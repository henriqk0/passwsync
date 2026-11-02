//! Configuration from the environment and the report lines (contracts/fuzz-harness.md
//! "Output lines"). Lines carry labels, counts, hex of seed-derived bytes and details built
//! from fixed rules only (FR-038, research R9).

use std::fmt::Write as _;

pub const ENV_SEED: &str = "PASSWSYNC_FUZZ_SEED";
pub const ENV_ITERS: &str = "PASSWSYNC_FUZZ_ITERS";
pub const ENV_ONLY: &str = "PASSWSYNC_FUZZ_ONLY";
pub const ENV_TRACE: &str = "PASSWSYNC_FUZZ_TRACE";

/// How a failing input is printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Render {
    /// `hex:<lowercase hex>` (binary targets).
    Hex,
    /// `text:"<escaped>"` (HTTP requests, share text).
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    pub seed: u64,
    /// `PASSWSYNC_FUZZ_ITERS`: may raise the target minimum, never lower it.
    pub iters: Option<u64>,
    /// `PASSWSYNC_FUZZ_ONLY`: run exactly this iteration.
    pub only: Option<u64>,
    pub trace: bool,
}

/// Decimal, or hexadecimal with a `0x` prefix.
pub fn parse_u64(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl FuzzConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads the settings through `lookup`; a malformed value is an error naming the variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let number = |name: &str| -> Result<Option<u64>, String> {
            match lookup(name) {
                None => Ok(None),
                Some(value) => parse_u64(&value)
                    .map(Some)
                    .ok_or_else(|| format!("{name} must be a decimal or 0x-hex u64")),
            }
        };
        let trace = match lookup(ENV_TRACE).as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(format!("{ENV_TRACE} must be 0 or 1")),
        };
        Ok(Self {
            seed: number(ENV_SEED)?.unwrap_or(crate::DEFAULT_SEED),
            iters: number(ENV_ITERS)?,
            only: number(ENV_ONLY)?,
            trace,
        })
    }

    pub fn iterations(&self, minimum: u64) -> u64 {
        self.iters.map_or(minimum, |iters| iters.max(minimum))
    }
}

/// The deterministic and the timing figures of one target run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetReport {
    pub target: &'static str,
    pub seed: u64,
    pub inputs: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub derived: Option<u64>,
    pub elapsed_ms: u64,
    pub max_input_us: u64,
    pub peak_over_baseline_kib: u64,
}

impl TargetReport {
    /// Deterministic for a given seed and code (SC-002).
    pub fn fuzz_line(&self) -> String {
        let derived = self
            .derived
            .map_or_else(String::new, |d| format!(" derived={d}"));
        format!(
            "FUZZ target={} seed=0x{:016x} inputs={} accepted={} rejected={}{} result=PASS",
            self.target, self.seed, self.inputs, self.accepted, self.rejected, derived
        )
    }

    /// Not deterministic.
    pub fn time_line(&self) -> String {
        format!(
            "FUZZ-TIME target={} elapsed_ms={} max_input_us={} peak_over_baseline_kib={}",
            self.target, self.elapsed_ms, self.max_input_us, self.peak_over_baseline_kib
        )
    }
}

/// Escapes `\r \n \t \\ \"` and every non-printable byte as `\xNN`.
pub fn escape_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7E => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

pub fn render_input(bytes: &[u8], render: Render) -> String {
    match render {
        Render::Hex => {
            let mut out = String::with_capacity(4 + bytes.len() * 2);
            out.push_str("hex:");
            for byte in bytes {
                let _ = write!(out, "{byte:02x}");
            }
            out
        }
        Render::Text => format!("text:\"{}\"", escape_text(bytes)),
    }
}

pub fn fail_line(
    target: &str,
    seed: u64,
    iteration: u64,
    kind: &str,
    detail: &str,
    input: &str,
) -> String {
    format!(
        "FUZZ-FAIL target={target} seed=0x{seed:016x} iteration={iteration} kind={kind} detail=\"{}\" input={input}",
        escape_text(detail.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<FuzzConfig, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        FuzzConfig::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn defaults_without_environment() {
        let c = config(&[]).unwrap();
        assert_eq!(c.seed, crate::DEFAULT_SEED);
        assert_eq!(c.iters, None);
        assert_eq!(c.only, None);
        assert!(!c.trace);
    }

    #[test]
    fn seed_accepts_decimal_and_hex() {
        assert_eq!(
            config(&[("PASSWSYNC_FUZZ_SEED", "1234")]).unwrap().seed,
            1234
        );
        assert_eq!(
            config(&[("PASSWSYNC_FUZZ_SEED", "0x1234")]).unwrap().seed,
            0x1234
        );
        assert_eq!(
            config(&[("PASSWSYNC_FUZZ_SEED", "0XFFFFFFFFFFFFFFFF")])
                .unwrap()
                .seed,
            u64::MAX
        );
    }

    #[test]
    fn malformed_values_name_the_variable() {
        for (name, value) in [
            ("PASSWSYNC_FUZZ_SEED", "zz"),
            ("PASSWSYNC_FUZZ_SEED", ""),
            ("PASSWSYNC_FUZZ_SEED", "0x"),
            ("PASSWSYNC_FUZZ_ITERS", "-1"),
            ("PASSWSYNC_FUZZ_ONLY", "1.5"),
            ("PASSWSYNC_FUZZ_TRACE", "yes"),
        ] {
            let err = config(&[(name, value)]).unwrap_err();
            assert!(err.contains(name), "{err}");
        }
    }

    #[test]
    fn iterations_can_be_raised_but_never_lowered() {
        let c = config(&[("PASSWSYNC_FUZZ_ITERS", "50")]).unwrap();
        assert_eq!(c.iterations(10_000), 10_000);
        let c = config(&[("PASSWSYNC_FUZZ_ITERS", "20000")]).unwrap();
        assert_eq!(c.iterations(10_000), 20_000);
        assert_eq!(config(&[]).unwrap().iterations(64), 64);
    }

    #[test]
    fn only_and_trace_are_read() {
        let c = config(&[("PASSWSYNC_FUZZ_ONLY", "42"), ("PASSWSYNC_FUZZ_TRACE", "1")]).unwrap();
        assert_eq!(c.only, Some(42));
        assert!(c.trace);
        assert!(!config(&[("PASSWSYNC_FUZZ_TRACE", "0")]).unwrap().trace);
    }

    fn report() -> TargetReport {
        TargetReport {
            target: "sync_ctl",
            seed: 0x5057_5359_4E43_0008,
            inputs: 10_000,
            accepted: 120,
            rejected: 9_880,
            derived: None,
            elapsed_ms: 812,
            max_input_us: 95,
            peak_over_baseline_kib: 0,
        }
    }

    #[test]
    fn fuzz_line_format() {
        assert_eq!(
            report().fuzz_line(),
            "FUZZ target=sync_ctl seed=0x505753594e430008 inputs=10000 accepted=120 rejected=9880 result=PASS"
        );
        let mut r = report();
        r.derived = Some(64);
        assert_eq!(
            r.fuzz_line(),
            "FUZZ target=sync_ctl seed=0x505753594e430008 inputs=10000 accepted=120 rejected=9880 derived=64 result=PASS"
        );
    }

    #[test]
    fn time_line_format() {
        assert_eq!(
            report().time_line(),
            "FUZZ-TIME target=sync_ctl elapsed_ms=812 max_input_us=95 peak_over_baseline_kib=0"
        );
    }

    #[test]
    fn fail_line_format_with_hex_and_text_inputs() {
        assert_eq!(
            fail_line(
                "frame",
                0x1234,
                7,
                "Panic",
                "panic at a.rs:1",
                &render_input(&[0x00, 0xAB], Render::Hex)
            ),
            "FUZZ-FAIL target=frame seed=0x0000000000001234 iteration=7 kind=Panic detail=\"panic at a.rs:1\" input=hex:00ab"
        );
        assert_eq!(
            render_input(b"GET / HTTP/1.1\r\n\t\\\"\x01\xff", Render::Text),
            "text:\"GET / HTTP/1.1\\r\\n\\t\\\\\\\"\\x01\\xff\""
        );
    }

    #[test]
    fn detail_quotes_are_escaped() {
        let line = fail_line("t", 0, 0, "ValueBound", "a \"b\"", "hex:");
        assert!(line.contains("detail=\"a \\\"b\\\"\""), "{line}");
    }
}
