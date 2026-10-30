//! FR-005, FR-008: wipe-on-free allocator and the reference-counted page locker. The unsafe
//! allocator calls stay inside `memprotect.rs`; these tests drive them through its safe
//! `testkit` harness.

use std::sync::{Arc, Mutex};

use passwsync_ffi::memprotect::testkit::{RecordingAlloc, exercise};
use passwsync_ffi::memprotect::{LockBackend, MemoryLevel, PageLocker, WipeOnFree, level};

#[test]
fn freed_blocks_are_zeroed_before_the_inner_dealloc() {
    let alloc = WipeOnFree::new(RecordingAlloc::default());
    exercise(&alloc, 64, None, 0xAA);
    exercise(&alloc, 4096, None, 0x55);
    let frees = alloc.inner().frees();
    assert_eq!(frees.len(), 2);
    assert!(frees.iter().all(|f| f.all_zero), "{frees:?}");
}

#[test]
fn realloc_wipes_the_old_block_and_keeps_the_content() {
    let alloc = WipeOnFree::new(RecordingAlloc::default());
    let kept = exercise(&alloc, 32, Some(4096), 0x77);
    assert!(kept, "content survives the move");
    let frees = alloc.inner().frees();
    // The old block (on realloc) and the new block (at the end).
    assert_eq!(frees.len(), 2);
    assert!(frees.iter().all(|f| f.all_zero), "{frees:?}");
    assert_eq!(frees[0].size, 32);
}

#[test]
fn zero_size_requests_never_reach_the_allocator_or_the_wipe() {
    // `GlobalAlloc` forbids zero-size layouts; the harness and the wipe treat length 0 as a
    // no-op instead of touching memory.
    let alloc = WipeOnFree::new(RecordingAlloc::default());
    assert!(exercise(&alloc, 0, None, 0x11));
    assert!(alloc.inner().frees().is_empty());
}

/// `(call, page address, length)` in order.
type Calls = Arc<Mutex<Vec<(&'static str, usize, usize)>>>;

/// Records lock/unlock calls per page; can be told to fail.
#[derive(Clone, Default)]
struct Backend {
    calls: Calls,
    fail: Arc<Mutex<bool>>,
}

impl LockBackend for Backend {
    fn lock(&self, addr: usize, len: usize) -> bool {
        if *self.fail.lock().unwrap() {
            return false;
        }
        self.calls.lock().unwrap().push(("lock", addr, len));
        true
    }
    fn unlock(&self, addr: usize, len: usize) {
        self.calls.lock().unwrap().push(("unlock", addr, len));
    }
}

const PAGE: usize = 4096;

#[test]
fn two_buffers_on_one_page_lock_it_once_and_unlock_after_the_last() {
    for first_released in [0, 1] {
        let backend = Backend::default();
        let locker = PageLocker::with_backend(backend.clone(), PAGE);
        let a = 10 * PAGE + 16;
        let b = 10 * PAGE + 512;
        assert!(locker.lock_range(a, 100));
        assert!(locker.lock_range(b, 100));
        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            &[("lock", 10 * PAGE, PAGE)]
        );
        let (x, y) = if first_released == 0 { (a, b) } else { (b, a) };
        locker.unlock_range(x, 100);
        assert_eq!(backend.calls.lock().unwrap().len(), 1, "still in use");
        locker.unlock_range(y, 100);
        assert_eq!(
            backend.calls.lock().unwrap().last().unwrap(),
            &("unlock", 10 * PAGE, PAGE)
        );
    }
}

#[test]
fn a_buffer_spanning_pages_locks_each_page() {
    let backend = Backend::default();
    let locker = PageLocker::with_backend(backend.clone(), PAGE);
    assert!(locker.lock_range(3 * PAGE - 8, 16));
    assert_eq!(backend.calls.lock().unwrap().len(), 2);
    locker.unlock_range(3 * PAGE - 8, 16);
    assert_eq!(backend.calls.lock().unwrap().len(), 4);
}

#[test]
fn an_exhausted_limit_yields_not_locked_gracefully() {
    let backend = Backend::default();
    *backend.fail.lock().unwrap() = true;
    let locker = PageLocker::with_backend(backend.clone(), PAGE);
    assert!(!locker.lock_range(5 * PAGE, 10));
    // Releasing an unlocked range is harmless.
    locker.unlock_range(5 * PAGE, 10);
    assert!(backend.calls.lock().unwrap().is_empty());
}

#[test]
fn the_level_follows_the_backend_results() {
    const MIB: u64 = 1024 * 1024;
    assert_eq!(level(None, true, true), MemoryLevel::Full, "unlimited");
    assert_eq!(level(Some(256 * MIB), true, true), MemoryLevel::Full);
    assert_eq!(
        level(Some(256 * MIB), false, true),
        MemoryLevel::SecretsOnly
    );
    assert_eq!(
        level(Some(64 * 1024), true, true),
        MemoryLevel::SecretsOnly,
        "too low"
    );
    assert_eq!(level(Some(64 * 1024), true, false), MemoryLevel::None);
    assert_eq!(level(None, false, false), MemoryLevel::None);
}
