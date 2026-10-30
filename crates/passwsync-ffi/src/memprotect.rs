//! Memory protection of the app process (FR-005, FR-008): a global allocator that wipes every
//! block before it is freed, and a reference-counted page locker for secret buffers.
//!
//! This is the ONLY module of the workspace allowed to use `unsafe` (FR-005,
//! `tests/unsafe_scope.rs`). Each block states the invariant it relies on.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroize;

pub use host_runtime::log::MemoryProtection as MemoryLevel;

/// Wraps an allocator so that every freed (or moved-from) block is zeroed before the inner
/// allocator gets it back.
pub struct WipeOnFree<A: GlobalAlloc> {
    inner: A,
}

impl<A: GlobalAlloc> WipeOnFree<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &A {
        &self.inner
    }
}

/// Zeroes `len` bytes at `ptr` with volatile writes (`zeroize`); `len == 0` touches nothing.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes when `len > 0`.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `ptr..ptr+len` is a live, writable allocation.
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }.zeroize();
}

// SAFETY: every method forwards to the inner allocator with the caller's layout; the only
// addition is zeroing memory the caller still owns (before `dealloc`, and the old block of a
// `realloc` after its content was copied).
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { self.inner.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was allocated with `layout` and is still owned by the caller.
        unsafe {
            wipe(ptr, layout.size());
            self.inner.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Never let the inner allocator move the block itself: it would free the old copy
        // without wiping it.
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `new_layout` is non-zero-size per the `realloc` contract.
        let new = unsafe { self.inner.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: both blocks are live and distinct; copy the smaller size, then wipe and
            // free the old block, which the caller gave up.
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}

/// Locks and unlocks page ranges (`mlock`/`munlock` in production).
pub trait LockBackend: Send + Sync {
    /// Locks `len` bytes at the page-aligned `addr`; `false` when the limit is exhausted.
    fn lock(&self, addr: usize, len: usize) -> bool;
    fn unlock(&self, addr: usize, len: usize);
}

/// The real backend: `mlock(2)`/`munlock(2)` through `rustix`.
pub struct Mlock;

impl LockBackend for Mlock {
    fn lock(&self, addr: usize, len: usize) -> bool {
        // SAFETY: `mlock` only changes residency of the given pages; the range comes from a
        // live buffer (`PageLocker::lock_range`) and an invalid range only returns an error.
        unsafe { rustix::mm::mlock(addr as *mut std::ffi::c_void, len) }.is_ok()
    }

    fn unlock(&self, addr: usize, len: usize) {
        // SAFETY: as for `lock`; unlocking never invalidates memory.
        let _ = unsafe { rustix::mm::munlock(addr as *mut std::ffi::c_void, len) };
    }
}

/// Reference-counted page locks: two buffers on one page lock it once, and the page is
/// unlocked only when the last of them is released (in any order).
pub struct PageLocker<B: LockBackend> {
    backend: B,
    page: usize,
    counts: Mutex<BTreeMap<usize, usize>>,
}

impl PageLocker<Mlock> {
    /// The production locker with the system page size.
    pub fn system() -> Self {
        Self::with_backend(Mlock, rustix::param::page_size())
    }
}

impl<B: LockBackend> PageLocker<B> {
    pub fn with_backend(backend: B, page: usize) -> Self {
        Self {
            backend,
            page: page.max(1),
            counts: Mutex::new(BTreeMap::new()),
        }
    }

    fn pages(&self, addr: usize, len: usize) -> impl Iterator<Item = usize> + use<B> {
        let page = self.page;
        let first = addr / page * page;
        let last = (addr + len.max(1) - 1) / page * page;
        (first..=last).step_by(page)
    }

    /// Locks every page of `addr..addr+len`. `false` (nothing left locked by this call) when
    /// a page cannot be locked.
    pub fn lock_range(&self, addr: usize, len: usize) -> bool {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let mut taken = Vec::new();
        for page in self.pages(addr, len) {
            let count = counts.entry(page).or_insert(0);
            if *count == 0 && !self.backend.lock(page, self.page) {
                counts.remove(&page);
                for done in taken {
                    Self::release(&self.backend, self.page, &mut counts, done);
                }
                return false;
            }
            *counts.get_mut(&page).unwrap_or_else(|| unreachable!()) += 1;
            taken.push(page);
        }
        true
    }

    /// Releases a range locked by [`Self::lock_range`]; pages not locked are ignored.
    pub fn unlock_range(&self, addr: usize, len: usize) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        for page in self.pages(addr, len) {
            Self::release(&self.backend, self.page, &mut counts, page);
        }
    }

    fn release(backend: &B, size: usize, counts: &mut BTreeMap<usize, usize>, page: usize) {
        if let Some(count) = counts.get_mut(&page) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&page);
                backend.unlock(page, size);
            }
        }
    }

    /// Locks `buf`'s pages (for a secret buffer that must not reach swap).
    pub fn lock(&self, buf: &[u8]) -> bool {
        self.lock_range(buf.as_ptr() as usize, buf.len())
    }

    pub fn unlock(&self, buf: &[u8]) {
        self.unlock_range(buf.as_ptr() as usize, buf.len());
    }
}

/// The achieved level (data-model.md section 2): `Full` when the memlock soft limit is
/// unlimited (`None`) or at least the desktop requirement and `mlockall` succeeded;
/// otherwise `SecretsOnly` when one page can be locked; otherwise `None`.
pub fn level(memlock_limit: Option<u64>, mlockall_ok: bool, page_lock_ok: bool) -> MemoryLevel {
    let sufficient =
        memlock_limit.is_none_or(|l| l >= host_runtime::hardening::REQUIRED_MEMLOCK_BYTES);
    if sufficient && mlockall_ok {
        MemoryLevel::Full
    } else if page_lock_ok {
        MemoryLevel::SecretsOnly
    } else {
        MemoryLevel::None
    }
}

/// Safe harness for the allocator tests (feature `testkit`).
#[cfg(feature = "testkit")]
pub mod testkit {
    use super::*;
    use std::alloc::System;

    /// One `dealloc` seen by [`RecordingAlloc`].
    #[derive(Clone, Debug)]
    pub struct Free {
        pub size: usize,
        /// Every byte was zero when the inner `dealloc` was called.
        pub all_zero: bool,
    }

    /// The system allocator, recording each free and whether the block was already wiped.
    #[derive(Default)]
    pub struct RecordingAlloc {
        frees: Mutex<Vec<Free>>,
    }

    impl RecordingAlloc {
        pub fn frees(&self) -> Vec<Free> {
            self.frees
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    // SAFETY: forwards to `System`; `dealloc` only reads the block it is handed.
    unsafe impl GlobalAlloc for RecordingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: caller's contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the block is live until `System.dealloc` below.
            let all_zero = unsafe { std::slice::from_raw_parts(ptr, layout.size()) }
                .iter()
                .all(|b| *b == 0);
            self.frees
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Free {
                    size: layout.size(),
                    all_zero,
                });
            // SAFETY: caller's contract.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    /// Allocates `size` bytes filled with `fill`, optionally reallocates to `grow_to`, then
    /// frees. Returns whether the content survived the reallocation. `size == 0` is a no-op
    /// (`GlobalAlloc` forbids zero-size layouts).
    pub fn exercise<A: GlobalAlloc>(
        alloc: &WipeOnFree<A>,
        size: usize,
        grow_to: Option<usize>,
        fill: u8,
    ) -> bool {
        if size == 0 || grow_to == Some(0) {
            return true;
        }
        let Ok(layout) = Layout::from_size_align(size, 8) else {
            return false;
        };
        // SAFETY: non-zero layout; every pointer is checked for null and used within its size.
        unsafe {
            let mut ptr = alloc.alloc(layout);
            if ptr.is_null() {
                return false;
            }
            std::ptr::write_bytes(ptr, fill, size);
            let mut current = layout;
            let mut kept = true;
            if let Some(new_size) = grow_to {
                ptr = alloc.realloc(ptr, layout, new_size);
                if ptr.is_null() {
                    return false;
                }
                kept = std::slice::from_raw_parts(ptr, size.min(new_size))
                    .iter()
                    .all(|b| *b == fill);
                current = Layout::from_size_align_unchecked(new_size, 8);
            }
            alloc.dealloc(ptr, current);
            kept
        }
    }
}
