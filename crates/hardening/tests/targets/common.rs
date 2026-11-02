//! Helpers shared by several targets.

use hardening::oracle::{FailureKind, Verdict};

/// A target-specific oracle failure (`detail` from a fixed rule, never from input content).
pub fn violation(kind: FailureKind, detail: &str) -> Verdict {
    Verdict::Violation(kind, detail.to_owned())
}

/// Fails with `ValueBound` unless `ok`.
pub fn check(ok: bool, detail: &str) -> Result<(), Verdict> {
    if ok {
        Ok(())
    } else {
        Err(violation(FailureKind::ValueBound, detail))
    }
}

/// Fails with `RoundTrip` unless `ok`.
pub fn round_trip(ok: bool, detail: &str) -> Result<(), Verdict> {
    if ok {
        Ok(())
    } else {
        Err(violation(FailureKind::RoundTrip, detail))
    }
}

/// Runs an oracle body written with `?` on `Verdict` errors.
pub fn verdict(body: impl FnOnce() -> Result<Verdict, Verdict>) -> Verdict {
    body().unwrap_or_else(|v| v)
}

/// Transfers the edit `recorded -> input` onto `live` (research R10): every byte that the
/// mutation left unchanged keeps the live value, so an unmutated input reproduces the live
/// message exactly and a flipped byte flips the same live byte. Used by the handshake and
/// transfer targets, whose genuine messages differ between sessions (fresh randomness).
pub fn transfer_edit(recorded: &[u8], input: &[u8], live: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, byte)| match (recorded.get(i), live.get(i)) {
            (Some(r), Some(l)) => l ^ r ^ byte,
            _ => *byte,
        })
        .collect()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
