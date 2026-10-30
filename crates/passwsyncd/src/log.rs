//! Moved to `host-runtime` (007, FR-004); re-exported so paths stay stable.
pub use host_runtime::log::*;

use crate::app::StartError;

// --- 005 sharing events: the enum moved to `host_runtime::log::LogEvent`; the typed-field
// check now runs on it in `crates/host-runtime/tests/scans.rs`.
/// Why start-up failed (configuration, paths, instance, port). These messages name keys
/// and paths only, never request data or secrets.
pub trait FatalLog {
    fn fatal(&self, error: &StartError);
}

impl FatalLog for Log {
    fn fatal(&self, error: &StartError) {
        self.line(error);
    }
}
