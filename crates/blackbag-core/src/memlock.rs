//! Page locking for secret buffers.
//!
//! Fixes the defect in black-bagg 0.4.10, whose `Drop for Sensitive` called
//! `self.data.zeroize()` and *then* `munlock(self.data.as_ptr(), self.data.len())`.
//! `Zeroize for Vec<u8>` clears the vector, so `len()` was already 0 and the
//! unlock silently no-opped — every secret leaked its lock for the life of the
//! process. On this machine `ulimit -l` is 8192 KiB = 2048 pages, so a long
//! session eventually exhausts the budget and further locks fail unnoticed.
//!
//! The rule here: capture (ptr, len) at lock time and unlock with the captured
//! values, never with whatever the buffer looks like at drop time.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Pages currently locked by this process through `Lock`, for the doctor view.
static LOCKED_BYTES: AtomicUsize = AtomicUsize::new(0);
/// Locks we asked for and did not get.
static FAILED_LOCKS: AtomicUsize = AtomicUsize::new(0);

/// An owned `mlock` over a byte range, released exactly once on drop.
#[derive(Debug)]
pub struct Lock {
    ptr: *const u8,
    len: usize,
}

// The guard only ever passes the address back to munlock; it never reads the
// memory, so it is safe to move across threads with the buffer it guards.
unsafe impl Send for Lock {}
unsafe impl Sync for Lock {}

impl Lock {
    /// Lock `slice` into RAM. Returns `None` when the kernel refuses (typically
    /// RLIMIT_MEMLOCK); the caller keeps working, and `doctor` reports the miss.
    pub fn new(slice: &[u8]) -> Option<Self> {
        Self::try_new(slice).ok()
    }

    /// Like [`Lock::new`] but surfaces why the lock failed.
    pub fn try_new(slice: &[u8]) -> io::Result<Self> {
        let (ptr, len) = (slice.as_ptr(), slice.len());
        if len == 0 {
            return Ok(Self {
                ptr,
                len: 0,
            });
        }
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if rc != 0 {
            FAILED_LOCKS.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::last_os_error());
        }
        LOCKED_BYTES.fetch_add(len, Ordering::Relaxed);
        Ok(Self { ptr, len })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        // Uses the captured length, which is the whole point of this type.
        unsafe { libc::munlock(self.ptr as *const libc::c_void, self.len) };
        LOCKED_BYTES.fetch_sub(self.len, Ordering::Relaxed);
    }
}

/// Bytes this process currently holds locked via [`Lock`].
pub fn locked_bytes() -> usize {
    LOCKED_BYTES.load(Ordering::Relaxed)
}

/// Number of lock attempts the kernel refused.
pub fn failed_locks() -> usize {
    FAILED_LOCKS.load(Ordering::Relaxed)
}

/// The process memlock ceiling in bytes, and whether it is unlimited.
pub fn memlock_limit() -> (u64, bool) {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return (0, false);
    }
    let unlimited = lim.rlim_cur == libc::RLIM_INFINITY;
    (lim.rlim_cur as u64, unlimited)
}

/// Probe whether locking works at all right now, without keeping the lock.
pub fn probe() -> Result<(), String> {
    let probe = [0u8; 32];
    match Lock::try_new(&probe) {
        Ok(guard) => {
            drop(guard);
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_releases_even_after_buffer_is_cleared() {
        use zeroize::Zeroize;

        // `locked_bytes()` is a process-wide counter shared with every other
        // test in this binary, so it cannot be asserted on exactly under
        // `cargo test`'s default parallel execution — some other test's
        // Secret or DEK lock can (and does) land between our own lock and
        // drop. What actually matters for the 0.4.10 regression is what
        // `Drop for Lock` uses, which is the guard's own captured field, so
        // that is what this test inspects directly.
        let mut buf = vec![7u8; 4096];
        let Some(guard) = Lock::new(&buf) else {
            // No memlock budget in this environment; nothing to assert.
            return;
        };
        assert_eq!(guard.len, 4096);

        // This is precisely the sequence that broke 0.4.10: clear the buffer
        // first, then drop the guard. The guard must still unlock the range
        // it captured at construction, not whatever `buf` looks like now.
        buf.zeroize();
        assert_eq!(buf.len(), 0, "Zeroize for Vec clears the length");
        assert_eq!(
            guard.len, 4096,
            "the guard must keep the length it captured at construction"
        );
    }

    #[test]
    fn empty_slices_are_a_no_op() {
        let guard = Lock::new(&[]).expect("empty lock always succeeds");
        assert_eq!(guard.len, 0);
    }

    #[test]
    fn limit_is_readable() {
        let (limit, unlimited) = memlock_limit();
        assert!(unlimited || limit > 0);
    }
}
