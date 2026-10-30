//! Process protections (FR-028–FR-031, research R4), applied before anything else and in a
//! fixed order. Any failure aborts start-up with exit code 3; no option skips them.

use std::sync::{Arc, Mutex, PoisonError};

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
};

use crate::log::{ErrorClass, Protection};

/// Required locked-memory limit (contracts/host-runtime.md).
pub const REQUIRED_MEMLOCK_BYTES: u64 = 256 * 1024 * 1024;

/// The four protections, one call each. Implemented by [`OsHardening`] and, for tests,
/// [`FakeHardening`].
pub trait Hardening: Send {
    fn disable_core_dumps(&self) -> Result<(), ErrorClass>;
    fn set_non_dumpable(&self) -> Result<(), ErrorClass>;
    fn check_memlock_limit(&self) -> Result<(), ErrorClass>;
    fn lock_all_memory(&self) -> Result<(), ErrorClass>;
}

/// Applies the protections in the normative order, stopping at the first failure.
pub fn apply(hardening: &dyn Hardening) -> Result<(), (Protection, ErrorClass)> {
    for which in [
        Protection::CoreDumps,
        Protection::NonDumpable,
        Protection::MemlockLimit,
        Protection::Mlockall,
    ] {
        let result = match which {
            Protection::CoreDumps => hardening.disable_core_dumps(),
            Protection::NonDumpable => hardening.set_non_dumpable(),
            Protection::MemlockLimit => hardening.check_memlock_limit(),
            Protection::Mlockall => hardening.lock_all_memory(),
        };
        result.map_err(|class| (which, class))?;
    }
    Ok(())
}

/// `None` means unlimited.
pub fn memlock_sufficient(soft_limit: Option<u64>) -> bool {
    soft_limit.is_none_or(|limit| limit >= REQUIRED_MEMLOCK_BYTES)
}

/// The real protections through `rustix`'s safe syscall wrappers.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsHardening;

impl Hardening for OsHardening {
    fn disable_core_dumps(&self) -> Result<(), ErrorClass> {
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        setrlimit(Resource::Core, none).map_err(ErrorClass::from_errno)
    }

    fn set_non_dumpable(&self) -> Result<(), ErrorClass> {
        set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(ErrorClass::from_errno)
    }

    fn check_memlock_limit(&self) -> Result<(), ErrorClass> {
        if memlock_sufficient(getrlimit(Resource::Memlock).current) {
            Ok(())
        } else {
            Err(ErrorClass::LimitTooLow)
        }
    }

    fn lock_all_memory(&self) -> Result<(), ErrorClass> {
        mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(ErrorClass::from_errno)
    }
}

/// Records the calls; optionally fails one protection with `ErrorClass::Permission`.
pub struct FakeHardening {
    fail: Option<Protection>,
    calls: Arc<Mutex<Vec<Protection>>>,
}

impl FakeHardening {
    pub fn ok() -> Self {
        Self {
            fail: None,
            calls: Arc::default(),
        }
    }

    pub fn failing(which: Protection) -> Self {
        Self {
            fail: Some(which),
            calls: Arc::default(),
        }
    }

    pub fn calls(&self) -> Arc<Mutex<Vec<Protection>>> {
        Arc::clone(&self.calls)
    }

    fn step(&self, which: Protection) -> Result<(), ErrorClass> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(which);
        if self.fail == Some(which) {
            Err(ErrorClass::Permission)
        } else {
            Ok(())
        }
    }
}

impl Hardening for FakeHardening {
    fn disable_core_dumps(&self) -> Result<(), ErrorClass> {
        self.step(Protection::CoreDumps)
    }

    fn set_non_dumpable(&self) -> Result<(), ErrorClass> {
        self.step(Protection::NonDumpable)
    }

    fn check_memlock_limit(&self) -> Result<(), ErrorClass> {
        self.step(Protection::MemlockLimit)
    }

    fn lock_all_memory(&self) -> Result<(), ErrorClass> {
        self.step(Protection::Mlockall)
    }
}
