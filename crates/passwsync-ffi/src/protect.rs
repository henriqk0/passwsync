#![forbid(unsafe_code)]
//! Process protections of the app (data-model.md section 2; FR-007, FR-008). Determined once at
//! `start`, in order: core dumps off, non-dumpable, memory-lock limit, then `mlockall` when the
//! limit allows it, else one probed page. A core-dump or non-dumpable failure blocks secret
//! operations; the memory-lock level is only reported.

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
};

use crate::error::Protection;
use crate::memprotect::{self, MemoryLevel, PageLocker};
use crate::records::{MemoryLockLevel, ProtectionStatus};

/// The four process controls, one call each. Real: [`OsProcess`]; tests: `FakeProcess`.
pub trait ProcessControls: Send + Sync {
    /// `setrlimit(RLIMIT_CORE, 0)`.
    fn disable_core_dumps(&self) -> bool;
    /// `prctl(PR_SET_DUMPABLE, 0)`.
    fn set_non_dumpable(&self) -> bool;
    /// The soft `RLIMIT_MEMLOCK`; `None` is unlimited.
    fn memlock_limit(&self) -> Option<u64>;
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)`.
    fn lock_all(&self) -> bool;
    /// Whether one page can be locked and unlocked again.
    fn probe_page_lock(&self) -> bool;
}

/// The real controls through `rustix`'s safe wrappers.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsProcess;

impl ProcessControls for OsProcess {
    fn disable_core_dumps(&self) -> bool {
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        setrlimit(Resource::Core, none).is_ok()
    }

    fn set_non_dumpable(&self) -> bool {
        set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok()
    }

    fn memlock_limit(&self) -> Option<u64> {
        getrlimit(Resource::Memlock).current
    }

    fn lock_all(&self) -> bool {
        mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).is_ok()
    }

    fn probe_page_lock(&self) -> bool {
        let page = vec![0u8; rustix::param::page_size()];
        let locker = PageLocker::system();
        let locked = locker.lock(&page);
        if locked {
            locker.unlock(&page);
        }
        locked
    }
}

/// Applies the protections in the normative order and computes the status.
pub fn determine(process: &dyn ProcessControls) -> ProtectionStatus {
    let core_dumps_disabled = process.disable_core_dumps();
    let non_dumpable = process.set_non_dumpable();
    let limit = process.memlock_limit();
    let mlockall_ok = memlock_allows_all(limit) && process.lock_all();
    let page_lock_ok = !mlockall_ok && process.probe_page_lock();
    let memory_lock = match memprotect::level(limit, mlockall_ok, page_lock_ok) {
        MemoryLevel::Full => MemoryLockLevel::Full,
        MemoryLevel::SecretsOnly => MemoryLockLevel::SecretsOnly,
        MemoryLevel::None => MemoryLockLevel::None,
    };
    let missing = if !core_dumps_disabled {
        Some(Protection::CoreDumps)
    } else if !non_dumpable {
        Some(Protection::NonDumpable)
    } else {
        None
    };
    ProtectionStatus {
        core_dumps_disabled,
        non_dumpable,
        memory_lock,
        can_unlock: missing.is_none(),
        missing,
    }
}

fn memlock_allows_all(limit: Option<u64>) -> bool {
    host_runtime::hardening::memlock_sufficient(limit)
}

/// The log word of a level (`ProtectionLevel` line).
pub fn log_level(level: MemoryLockLevel) -> host_runtime::log::MemoryProtection {
    use host_runtime::log::MemoryProtection;
    match level {
        MemoryLockLevel::Full => MemoryProtection::Full,
        MemoryLockLevel::SecretsOnly => MemoryProtection::SecretsOnly,
        MemoryLockLevel::None => MemoryProtection::None,
    }
}
