//! The fuzz runner (contracts/fuzz-harness.md "Runner behaviour"): warm-up, baseline, the
//! per-iteration loop with every oracle, a hang watchdog, stop at the first failure.

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::mutate::{Generator, Input, Seed};
use crate::oracle::{
    Counted, Failure, FailureKind, Limits, Verdict, classify, coverage, read_status, run_caught,
    set_trace, settle_baseline,
};
use crate::report::{FuzzConfig, Render, TargetReport};
use crate::rng::Rng;

/// Default minimum number of executed inputs per target (FR-004).
pub const MIN_INPUTS: u64 = 10_000;
/// Extra room the mutator may add over the largest seed.
pub const CAP_SLACK: usize = 1024;

type SeedsFn = Box<dyn Fn() -> Vec<Seed>>;
type OneFn = Box<dyn Fn(&Input) -> Verdict>;

/// One fuzz target: its seeds, its oracle function and its limits.
pub struct Target {
    pub name: &'static str,
    pub min_inputs: u64,
    pub time_limit: Duration,
    /// The parser's documented allocation bound in bytes (the oracle adds 4 MiB slack).
    pub alloc_bound: u64,
    /// Largest mutated input; 0 means the largest seed plus [`CAP_SLACK`].
    pub input_cap: usize,
    pub render: Render,
    /// The closed list of error kinds `one` may reject with.
    pub error_kinds: &'static [&'static str],
    /// `(minimum derived inputs, maximum attempts)` for the full-unlock target.
    pub derived: Option<(u64, u64)>,
    /// Whether the deterministic truncation sweep runs (default true).
    pub sweep: bool,
    seeds: SeedsFn,
    one: OneFn,
}

impl Target {
    pub fn new(
        name: &'static str,
        seeds: impl Fn() -> Vec<Seed> + 'static,
        one: impl Fn(&Input) -> Verdict + 'static,
    ) -> Self {
        Self {
            name,
            min_inputs: MIN_INPUTS,
            time_limit: Duration::from_secs(1),
            alloc_bound: 1024 * 1024,
            input_cap: 0,
            render: Render::Hex,
            error_kinds: &[],
            derived: None,
            sweep: true,
            seeds: Box::new(seeds),
            one: Box::new(one),
        }
    }

    pub fn min_inputs(mut self, n: u64) -> Self {
        self.min_inputs = n;
        self
    }

    pub fn time_limit(mut self, limit: Duration) -> Self {
        self.time_limit = limit;
        self
    }

    pub fn alloc_bound(mut self, bytes: u64) -> Self {
        self.alloc_bound = bytes;
        self
    }

    pub fn input_cap(mut self, bytes: usize) -> Self {
        self.input_cap = bytes;
        self
    }

    pub fn render(mut self, render: Render) -> Self {
        self.render = render;
        self
    }

    pub fn error_kinds(mut self, kinds: &'static [&'static str]) -> Self {
        self.error_kinds = kinds;
        self
    }

    pub fn derived(mut self, minimum: u64, max_attempts: u64) -> Self {
        self.derived = Some((minimum, max_attempts));
        self
    }

    pub fn sweep(mut self, sweep: bool) -> Self {
        self.sweep = sweep;
        self
    }

    pub fn seeds(&self) -> Vec<Seed> {
        (self.seeds)()
    }

    pub fn one(&self, input: &Input) -> Verdict {
        (self.one)(input)
    }

    fn limits(&self) -> Limits {
        Limits {
            time_limit: self.time_limit,
            alloc_bound: self.alloc_bound,
            error_kinds: self.error_kinds,
        }
    }
}

/// Hang watchdog (research R5): threads cannot be killed, so a hang ends the process after
/// printing the failure line.
struct Watchdog {
    busy_since_us: Arc<AtomicU64>,
    iteration: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    start: Instant,
}

impl Watchdog {
    fn start(target: &Target, cfg: &FuzzConfig, seeds: &[Seed], cap: usize) -> Self {
        let busy_since_us = Arc::new(AtomicU64::new(0));
        let iteration = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let (busy, iter, halt) = (
            Arc::clone(&busy_since_us),
            Arc::clone(&iteration),
            Arc::clone(&stop),
        );
        let limit = target.time_limit.saturating_mul(5);
        let (name, seed, render, sweep) = (target.name, cfg.seed, target.render, target.sweep);
        let seeds = seeds.to_vec();
        let (ready, started) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            // Allocate once now, so glibc creates this thread's arena (a transient 128 MiB
            // mapping) before the allocation baseline is taken, not during an input.
            drop(std::hint::black_box(vec![0u8; 64]));
            let _ = ready.send(());
            while !halt.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
                let since = busy.load(Ordering::SeqCst);
                if since == 0 {
                    continue;
                }
                let now = start.elapsed().as_micros() as u64;
                if Duration::from_micros(now.saturating_sub(since)) > limit {
                    let number = iter.load(Ordering::SeqCst);
                    let mut rng = Rng::for_iteration(seed, name, number);
                    let input = Generator::with_sweep(&seeds, cap, sweep).input(number, &mut rng);
                    let failure = Failure {
                        target: name,
                        seed,
                        iteration: number,
                        kind: FailureKind::Hang,
                        detail: format!("input ran longer than {} ms", limit.as_millis()),
                        input: input.bytes,
                        render,
                    };
                    println!("{}", failure.line());
                    let _ = std::io::stdout().flush();
                    std::process::exit(101);
                }
            }
        });
        let _ = started.recv();
        Self {
            busy_since_us,
            iteration,
            stop,
            handle: Some(handle),
            start,
        }
    }

    fn enter(&self, iteration: u64) {
        self.iteration.store(iteration, Ordering::SeqCst);
        let now = (self.start.elapsed().as_micros() as u64).max(1);
        self.busy_since_us.store(now, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.busy_since_us.store(0, Ordering::SeqCst);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Runs `target` under `cfg`; returns its report or the first failure.
pub fn execute(target: &Target, cfg: &FuzzConfig) -> Result<TargetReport, Failure> {
    set_trace(cfg.trace);
    let started = Instant::now();
    let seeds = target.seeds();
    let cap = if target.input_cap == 0 {
        seeds.iter().map(|s| s.bytes.len()).max().unwrap_or(0) + CAP_SLACK
    } else {
        target.input_cap
    };
    let generator = Generator::with_sweep(&seeds, cap, target.sweep);
    let fail = |iteration: u64, kind: FailureKind, detail: String, input: Vec<u8>| Failure {
        target: target.name,
        seed: cfg.seed,
        iteration,
        kind,
        detail,
        input,
        render: target.render,
    };
    let watchdog = Watchdog::start(target, cfg, &seeds, cap);
    // Warm-up: every seed once (allocator arenas, lazy statics), then the baseline.
    for (index, seed) in seeds.iter().enumerate() {
        let input = Input {
            seed: index,
            bytes: seed.bytes.clone(),
            chunks: seed.chunks.clone(),
            mutations: Vec::new(),
            mutated: false,
        };
        let _ = run_caught(|| target.one(&input));
    }
    let (ballast, baseline) =
        settle_baseline().map_err(|detail| fail(0, FailureKind::AllocBound, detail, Vec::new()))?;
    let limits = target.limits();
    let (mut inputs, mut accepted, mut rejected, mut derived) = (0u64, 0u64, 0u64, 0u64);
    let (mut max_input_us, mut peak_growth) = (0u64, 0u64);
    let (want_derived, max_attempts) = match target.derived {
        Some((minimum, attempts)) => (Some(cfg.iterations(minimum)), attempts),
        None => (None, cfg.iterations(target.min_inputs)),
    };
    let mut iter = cfg.only.unwrap_or(0);
    loop {
        let done = match (cfg.only, want_derived) {
            (Some(_), _) => inputs == 1,
            (None, Some(want)) => derived >= want || inputs >= max_attempts,
            (None, None) => inputs >= max_attempts,
        };
        if done {
            break;
        }
        let mut rng = Rng::for_iteration(cfg.seed, target.name, iter);
        let input = generator.input(iter, &mut rng);
        if cfg.trace {
            eprintln!("FUZZ-TRACE target={} iteration={iter}", target.name);
        }
        watchdog.enter(iter);
        let at = Instant::now();
        let outcome = run_caught(|| target.one(&input));
        let elapsed = at.elapsed();
        watchdog.leave();
        let mem = read_status()
            .map_err(|detail| fail(iter, FailureKind::AllocBound, detail, input.bytes.clone()))?;
        let growth = mem.vm_peak.saturating_sub(baseline);
        max_input_us = max_input_us.max(elapsed.as_micros() as u64);
        peak_growth = peak_growth.max(growth);
        inputs += 1;
        match classify(outcome, elapsed, growth, &limits) {
            Ok(Counted::Accepted) => accepted += 1,
            Ok(Counted::Rejected) => rejected += 1,
            Ok(Counted::DerivedAccepted) => {
                accepted += 1;
                derived += 1;
            }
            Ok(Counted::DerivedRejected) => {
                rejected += 1;
                derived += 1;
            }
            Err((kind, detail)) => return Err(fail(iter, kind, detail, input.bytes)),
        }
        iter += 1;
    }
    drop(watchdog);
    drop(ballast);
    if cfg.only.is_none() {
        if let Some(want) = want_derived {
            if derived < want {
                return Err(fail(
                    iter,
                    FailureKind::Coverage,
                    format!("only {derived} derived inputs in {inputs} attempts, need {want}"),
                    Vec::new(),
                ));
            }
        }
        coverage(accepted, rejected)
            .map_err(|(kind, detail)| fail(iter, kind, detail, Vec::new()))?;
    }
    Ok(TargetReport {
        target: target.name,
        seed: cfg.seed,
        inputs,
        accepted,
        rejected,
        derived: target.derived.map(|_| derived),
        elapsed_ms: started.elapsed().as_millis() as u64,
        max_input_us,
        peak_over_baseline_kib: peak_growth / 1024,
    })
}

/// The test entry of every `fuzz_<target>.rs`: reads the environment, runs, prints the report
/// lines, and panics (failing the test) on a failure or a malformed setting.
pub fn run(target: Target) {
    let cfg = match FuzzConfig::from_env() {
        Ok(cfg) => cfg,
        Err(error) => panic!("{error}"),
    };
    match execute(&target, &cfg) {
        Ok(report) => {
            println!("{}", report.fuzz_line());
            println!("{}", report.time_line());
        }
        Err(failure) => {
            println!("{}", failure.line());
            panic!(
                "fuzz target {} failed at iteration {}",
                failure.target, failure.iteration
            );
        }
    }
}

/// The optional cargo-fuzz entry: raw bytes as seed `seed`'s input; panics on a violation.
pub fn check_bytes(target: &Target, seed: usize, bytes: &[u8]) {
    let input = Input::raw(seed, bytes);
    let outcome = run_caught(|| target.one(&input));
    if let Err((kind, detail)) = classify(outcome, Duration::ZERO, 0, &target.limits()) {
        panic!("{} violation: {} {}", target.name, kind.name(), detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutate::Seed;
    use crate::oracle::{FailureKind, Verdict};
    use crate::report::FuzzConfig;
    use std::time::Duration;

    fn config() -> FuzzConfig {
        FuzzConfig {
            seed: 9,
            iters: None,
            only: None,
            trace: false,
        }
    }

    /// Accepts inputs that start with byte 1, rejects the rest.
    fn toy(name: &'static str) -> Target {
        Target::new(
            name,
            || {
                vec![
                    Seed::new("one", vec![1, 2, 3]),
                    Seed::new("two", vec![2, 2]),
                ]
            },
            |input| {
                if input.bytes.first() == Some(&1) {
                    Verdict::Accepted
                } else {
                    Verdict::Rejected("Protocol")
                }
            },
        )
        .min_inputs(500)
        .alloc_bound(u64::MAX / 4)
        .error_kinds(&["Protocol"])
    }

    #[test]
    fn a_passing_target_reports_counts_and_pass() {
        let report = execute(&toy("toy_pass"), &config()).unwrap();
        assert_eq!(report.inputs, 500);
        assert_eq!(report.accepted + report.rejected, 500);
        assert!(report.accepted >= 1 && report.rejected >= 1);
        assert!(report.fuzz_line().ends_with("result=PASS"));
    }

    #[test]
    fn a_panicking_target_stops_at_the_first_failure() {
        let target = Target::new(
            "toy_panic",
            || vec![Seed::new("s", vec![0; 8])],
            |input| {
                if input.bytes.len() > 8 {
                    panic!("boom");
                }
                Verdict::Accepted
            },
        )
        .min_inputs(5000)
        .alloc_bound(u64::MAX / 4);
        let failure = execute(&target, &config()).unwrap_err();
        assert_eq!(failure.kind, FailureKind::Panic);
        assert_eq!(failure.target, "toy_panic");
        assert_eq!(failure.seed, 9);
        // The first failing iteration, not a later one.
        for iter in 0..failure.iteration {
            let mut only = config();
            only.only = Some(iter);
            assert!(execute(&target, &only).is_ok(), "iteration {iter}");
        }
        let line = failure.line();
        assert!(line.starts_with("FUZZ-FAIL target=toy_panic seed=0x0000000000000009 iteration="));
        assert!(line.contains("kind=Panic"));
    }

    #[test]
    fn rerunning_the_reported_iteration_reproduces_the_failure() {
        let target = Target::new(
            "toy_repro",
            || vec![Seed::new("s", vec![5; 4])],
            |input| {
                if input.bytes.contains(&0xFF) {
                    Verdict::Violation(FailureKind::ValueBound, "0xff seen".into())
                } else {
                    Verdict::Accepted
                }
            },
        )
        .min_inputs(5000)
        .alloc_bound(u64::MAX / 4);
        let failure = execute(&target, &config()).unwrap_err();
        let mut only = config();
        only.only = Some(failure.iteration);
        let again = execute(&target, &only).unwrap_err();
        assert_eq!(again.iteration, failure.iteration);
        assert_eq!(again.input, failure.input);
        assert_eq!(again.kind, FailureKind::ValueBound);
    }

    #[test]
    fn a_slow_target_is_a_time_overrun() {
        let target = Target::new(
            "toy_slow",
            || vec![Seed::new("s", vec![1])],
            |_| {
                std::thread::sleep(Duration::from_millis(30));
                Verdict::Accepted
            },
        )
        .min_inputs(3)
        .time_limit(Duration::from_millis(10))
        .alloc_bound(u64::MAX / 4);
        let failure = execute(&target, &config()).unwrap_err();
        assert_eq!(failure.kind, FailureKind::TimeOverrun);
    }

    #[test]
    fn a_target_without_rejections_fails_coverage() {
        let target = Target::new(
            "toy_cov",
            || vec![Seed::new("s", vec![1])],
            |_| Verdict::Accepted,
        )
        .min_inputs(50)
        .alloc_bound(u64::MAX / 4);
        assert_eq!(
            execute(&target, &config()).unwrap_err().kind,
            FailureKind::Coverage
        );
        let target = Target::new(
            "toy_cov2",
            || vec![Seed::new("s", vec![1])],
            |_| Verdict::Rejected("Protocol"),
        )
        .min_inputs(50)
        .alloc_bound(u64::MAX / 4)
        .error_kinds(&["Protocol"]);
        assert_eq!(
            execute(&target, &config()).unwrap_err().kind,
            FailureKind::Coverage
        );
    }

    #[test]
    fn only_runs_exactly_one_iteration() {
        let mut only = config();
        only.only = Some(42);
        let report = execute(&toy("toy_only"), &only).unwrap();
        assert_eq!(report.inputs, 1);
    }

    #[test]
    fn the_same_seed_gives_identical_fuzz_lines() {
        let a = execute(&toy("toy_det"), &config()).unwrap();
        let b = execute(&toy("toy_det"), &config()).unwrap();
        assert_eq!(a.fuzz_line(), b.fuzz_line());
        let mut other = config();
        other.seed = 10;
        let c = execute(&toy("toy_det"), &other).unwrap();
        assert!(c.fuzz_line().contains("seed=0x000000000000000a"));
    }

    #[test]
    fn derived_targets_run_until_the_derived_minimum() {
        let target = Target::new(
            "toy_derived",
            || vec![Seed::new("s", vec![1, 1])],
            |input| {
                let inner = if input.mutated {
                    Verdict::Rejected("Generic")
                } else {
                    Verdict::Accepted
                };
                if input.bytes.len() == 2 {
                    Verdict::Derived(Box::new(inner))
                } else {
                    Verdict::Rejected("Header")
                }
            },
        )
        .derived(16, 4096)
        .alloc_bound(u64::MAX / 4)
        .error_kinds(&["Generic", "Header"]);
        let report = execute(&target, &config()).unwrap();
        assert!(report.derived.unwrap() >= 16);
        assert!(report.inputs <= 4096);
    }

    #[test]
    fn derived_targets_fail_when_the_attempt_bound_is_reached() {
        let target = Target::new(
            "toy_never",
            || vec![Seed::new("s", vec![1])],
            |_| Verdict::Rejected("Header"),
        )
        .derived(16, 100)
        .alloc_bound(u64::MAX / 4)
        .error_kinds(&["Header"]);
        let failure = execute(&target, &config()).unwrap_err();
        assert_eq!(failure.kind, FailureKind::Coverage);
    }
}
