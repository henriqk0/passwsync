//! Oracles applied to every input (FR-005, research R4, R5): panic, per-input time, address
//! space growth read from `/proc/self/status`, closed error kinds, and the coverage rule
//! (FR-008). Std only, no `unsafe`.

use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::report::{Render, fail_line, render_input};

/// Allocation resolution of the `/proc` oracle (research R4).
pub const SLACK: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureKind {
    Panic,
    TimeOverrun,
    Hang,
    AllocBound,
    ValueBound,
    UnknownError,
    RoundTrip,
    StateLeak,
    GuardBypass,
    NotGeneric,
    Coverage,
}

impl FailureKind {
    pub const ALL: [Self; 11] = [
        Self::Panic,
        Self::TimeOverrun,
        Self::Hang,
        Self::AllocBound,
        Self::ValueBound,
        Self::UnknownError,
        Self::RoundTrip,
        Self::StateLeak,
        Self::GuardBypass,
        Self::NotGeneric,
        Self::Coverage,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Panic => "Panic",
            Self::TimeOverrun => "TimeOverrun",
            Self::Hang => "Hang",
            Self::AllocBound => "AllocBound",
            Self::ValueBound => "ValueBound",
            Self::UnknownError => "UnknownError",
            Self::RoundTrip => "RoundTrip",
            Self::StateLeak => "StateLeak",
            Self::GuardBypass => "GuardBypass",
            Self::NotGeneric => "NotGeneric",
            Self::Coverage => "Coverage",
        }
    }
}

/// What a target's `one` says about an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// Rejected with this error kind (must be in the target's closed list).
    Rejected(&'static str),
    /// A target-specific oracle failed. The detail is built from fixed rules only.
    Violation(FailureKind, String),
    /// The inner verdict of an input that reached the expensive path (key derivation).
    Derived(Box<Verdict>),
}

/// How a passing input is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counted {
    Accepted,
    Rejected,
    DerivedAccepted,
    DerivedRejected,
}

/// Per-target limits used by [`classify`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub time_limit: Duration,
    pub alloc_bound: u64,
    pub error_kinds: &'static [&'static str],
}

/// The first failure of a run, with everything needed to reproduce it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub target: &'static str,
    pub seed: u64,
    pub iteration: u64,
    pub kind: FailureKind,
    pub detail: String,
    pub input: Vec<u8>,
    pub render: Render,
}

impl Failure {
    pub fn line(&self) -> String {
        fail_line(
            self.target,
            self.seed,
            self.iteration,
            self.kind.name(),
            &self.detail,
            &render_input(&self.input, self.render),
        )
    }
}

/// Address-space figures in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mem {
    pub vm_peak: u64,
    pub vm_size: u64,
}

fn kib_field(text: &str, key: &str) -> Result<u64, String> {
    let line = text
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| format!("{key} missing in /proc/self/status"))?;
    let value = line[key.len()..].trim().trim_end_matches("kB").trim();
    value
        .parse::<u64>()
        .map(|kib| kib * 1024)
        .map_err(|_| format!("{key} unreadable in /proc/self/status"))
}

/// Parses `VmPeak` and `VmSize` from the text of `/proc/<pid>/status` (fails closed).
pub fn parse_status(text: &str) -> Result<Mem, String> {
    Ok(Mem {
        vm_peak: kib_field(text, "VmPeak:")?,
        vm_size: kib_field(text, "VmSize:")?,
    })
}

pub fn read_status_from(path: &Path) -> Result<Mem, String> {
    let text = std::fs::read_to_string(path).map_err(|_| "status file unreadable".to_owned())?;
    parse_status(&text)
}

pub fn read_status() -> Result<Mem, String> {
    read_status_from(Path::new("/proc/self/status"))
}

/// Measures the allocation baseline. `VmPeak` never decreases, and glibc briefly maps twice
/// a thread arena's 64 MiB when it creates one, so right after start-up the historical peak
/// sits well above the current size. An untouched reservation ("ballast", virtual only) of
/// that gap lifts the current size to the peak, so later growth of `VmPeak` measures new
/// allocations from the baseline at full resolution. Keep the ballast alive for the run.
pub fn settle_baseline() -> Result<(Vec<u8>, u64), String> {
    let mem = read_status()?;
    let gap = mem.vm_peak.saturating_sub(mem.vm_size);
    let ballast = Vec::with_capacity(usize::try_from(gap).unwrap_or(0));
    Ok((ballast, read_status()?.vm_size))
}

/// Classifies one input's outcome. `growth` is `VmPeak - baseline` in bytes.
pub fn classify(
    outcome: Result<Verdict, String>,
    elapsed: Duration,
    growth: u64,
    limits: &Limits,
) -> Result<Counted, (FailureKind, String)> {
    let verdict = outcome.map_err(|detail| (FailureKind::Panic, detail))?;
    if elapsed > limits.time_limit {
        return Err((
            FailureKind::TimeOverrun,
            format!(
                "input took {} us, limit {} us",
                elapsed.as_micros(),
                limits.time_limit.as_micros()
            ),
        ));
    }
    if growth > limits.alloc_bound.saturating_add(SLACK) {
        return Err((
            FailureKind::AllocBound,
            format!(
                "address space grew {} KiB, bound {} KiB + slack",
                growth / 1024,
                limits.alloc_bound / 1024
            ),
        ));
    }
    let (verdict, derived) = match verdict {
        Verdict::Derived(inner) => (*inner, true),
        other => (other, false),
    };
    match (verdict, derived) {
        (Verdict::Accepted, false) => Ok(Counted::Accepted),
        (Verdict::Accepted, true) => Ok(Counted::DerivedAccepted),
        (Verdict::Rejected(kind), derived) => {
            if !limits.error_kinds.contains(&kind) {
                return Err((
                    FailureKind::UnknownError,
                    format!("error kind {kind} is not in the closed list"),
                ));
            }
            Ok(if derived {
                Counted::DerivedRejected
            } else {
                Counted::Rejected
            })
        }
        (Verdict::Violation(kind, detail), _) => Err((kind, detail)),
        (Verdict::Derived(_), _) => Err((FailureKind::ValueBound, "nested derived verdict".into())),
    }
}

/// FR-008: at least one accepted and one rejected input.
pub fn coverage(accepted: u64, rejected: u64) -> Result<(), (FailureKind, String)> {
    if accepted >= 1 && rejected >= 1 {
        Ok(())
    } else {
        Err((
            FailureKind::Coverage,
            format!("accepted={accepted} rejected={rejected}, need at least one of each"),
        ))
    }
}

static HOOK: Once = Once::new();
static TRACE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static CATCHING: Cell<bool> = const { Cell::new(false) };
    static LOCATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// In trace mode a caught panic also prints its full message on stderr (local reproduction
/// only; the report lines never carry it, research R9).
pub fn set_trace(trace: bool) {
    TRACE.store(trace, Ordering::SeqCst);
}

fn install_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if CATCHING.with(Cell::get) {
                let location = info.location().map_or_else(
                    || "unknown".to_owned(),
                    |l| format!("{}:{}", l.file(), l.line()),
                );
                LOCATION.with(|slot| *slot.borrow_mut() = Some(location));
                if TRACE.load(Ordering::SeqCst) {
                    eprintln!("FUZZ-TRACE panic: {info}");
                }
            } else {
                previous(info);
            }
        }));
    });
}

/// Runs `f` and turns a panic into `Err("panic at <file>:<line>")`. The panic message is
/// withheld because it may quote input content.
pub fn run_caught(f: impl FnOnce() -> Verdict) -> Result<Verdict, String> {
    install_hook();
    CATCHING.with(|c| c.set(true));
    let result = catch_unwind(AssertUnwindSafe(f));
    CATCHING.with(|c| c.set(false));
    result.map_err(|_| {
        let location = LOCATION
            .with(|slot| slot.borrow_mut().take())
            .unwrap_or_else(|| "unknown".to_owned());
        format!("panic at {location} (message withheld; rerun with PASSWSYNC_FUZZ_TRACE=1)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const STATUS: &str = "Name:\tfuzz_frame\nUmask:\t0022\nState:\tR (running)\n\
VmPeak:\t  123456 kB\nVmSize:\t  120000 kB\nVmLck:\t       0 kB\nVmHWM:\t    9000 kB\n";

    fn limits() -> Limits {
        Limits {
            time_limit: Duration::from_secs(1),
            alloc_bound: 1024 * 1024,
            error_kinds: &["Protocol", "Malformed"],
        }
    }

    #[test]
    fn status_parser_reads_vmsize_and_vmpeak_in_bytes() {
        let mem = parse_status(STATUS).unwrap();
        assert_eq!(mem.vm_peak, 123_456 * 1024);
        assert_eq!(mem.vm_size, 120_000 * 1024);
    }

    #[test]
    fn status_parser_fails_closed() {
        assert!(parse_status("").is_err());
        assert!(parse_status("VmPeak:\t 1 kB\n").is_err());
        assert!(parse_status("VmPeak:\t x kB\nVmSize:\t 1 kB\n").is_err());
        assert!(read_status_from(std::path::Path::new("/nonexistent/status")).is_err());
    }

    #[test]
    fn the_live_status_file_is_readable() {
        let mem = read_status().unwrap();
        assert!(mem.vm_peak >= mem.vm_size);
    }

    #[test]
    fn ballast_lifts_the_current_size_to_the_historical_peak() {
        // Make a transient peak first (allocate and free 32 MiB untouched).
        drop(Vec::<u8>::with_capacity(32 * 1024 * 1024));
        let (ballast, baseline) = settle_baseline().unwrap();
        let after = read_status().unwrap();
        // Other test threads may allocate meanwhile; allow 8 MiB of noise.
        assert!(
            baseline + 8 * 1024 * 1024 >= after.vm_peak,
            "{baseline} {after:?}"
        );
        drop(ballast);
    }

    #[test]
    fn a_panic_is_classified_as_panic() {
        let out = classify(Err("panic at x.rs:1".into()), Duration::ZERO, 0, &limits());
        assert_eq!(out.unwrap_err().0, FailureKind::Panic);
    }

    #[test]
    fn a_slow_input_is_a_time_overrun() {
        let out = classify(
            Ok(Verdict::Accepted),
            Duration::from_millis(1001),
            0,
            &limits(),
        );
        assert_eq!(out.unwrap_err().0, FailureKind::TimeOverrun);
        let out = classify(
            Ok(Verdict::Accepted),
            Duration::from_millis(1000),
            0,
            &limits(),
        );
        assert!(out.is_ok());
    }

    #[test]
    fn growth_over_bound_plus_slack_is_an_allocation_violation() {
        let bound = limits().alloc_bound;
        let out = classify(
            Ok(Verdict::Accepted),
            Duration::ZERO,
            bound + SLACK,
            &limits(),
        );
        assert!(out.is_ok());
        let out = classify(
            Ok(Verdict::Accepted),
            Duration::ZERO,
            bound + SLACK + 1,
            &limits(),
        );
        assert_eq!(out.unwrap_err().0, FailureKind::AllocBound);
        assert_eq!(SLACK, 4 * 1024 * 1024);
    }

    #[test]
    fn an_error_kind_outside_the_closed_list_is_unknown() {
        let out = classify(
            Ok(Verdict::Rejected("Protocol")),
            Duration::ZERO,
            0,
            &limits(),
        );
        assert_eq!(out.unwrap(), Counted::Rejected);
        let out = classify(
            Ok(Verdict::Rejected("Storage")),
            Duration::ZERO,
            0,
            &limits(),
        );
        assert_eq!(out.unwrap_err().0, FailureKind::UnknownError);
    }

    #[test]
    fn a_violation_reported_by_the_target_keeps_its_kind() {
        let out = classify(
            Ok(Verdict::Violation(FailureKind::RoundTrip, "differs".into())),
            Duration::ZERO,
            0,
            &limits(),
        );
        assert_eq!(out.unwrap_err(), (FailureKind::RoundTrip, "differs".into()));
    }

    #[test]
    fn a_derived_verdict_is_counted_as_derived() {
        let out = classify(
            Ok(Verdict::Derived(Box::new(Verdict::Rejected("Protocol")))),
            Duration::ZERO,
            0,
            &limits(),
        );
        assert_eq!(out.unwrap(), Counted::DerivedRejected);
    }

    #[test]
    fn coverage_needs_one_accepted_and_one_rejected() {
        assert!(coverage(1, 1).is_ok());
        assert_eq!(coverage(0, 5).unwrap_err().0, FailureKind::Coverage);
        assert_eq!(coverage(5, 0).unwrap_err().0, FailureKind::Coverage);
    }

    #[test]
    fn caught_panics_report_only_the_location() {
        let out = run_caught(|| panic!("secret-ish text {}", 42));
        let detail = out.unwrap_err();
        assert!(detail.starts_with("panic at "), "{detail}");
        assert!(!detail.contains("secret-ish"), "{detail}");
        assert!(run_caught(|| Verdict::Accepted).is_ok());
    }

    #[test]
    fn kind_names_are_the_documented_ones() {
        let names: Vec<&str> = FailureKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(
            names,
            [
                "Panic",
                "TimeOverrun",
                "Hang",
                "AllocBound",
                "ValueBound",
                "UnknownError",
                "RoundTrip",
                "StateLeak",
                "GuardBypass",
                "NotGeneric",
                "Coverage"
            ]
        );
    }
}
