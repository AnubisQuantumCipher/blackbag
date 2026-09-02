//! A locked arena for secret bytes.
//!
//! # Why `mlock` on a `Vec` was not enough
//!
//! The previous design page-locked each `Secret`'s `Vec<u8>` with its own
//! `mlock` call and released it with `munlock` on drop. That is correct for a
//! buffer that owns its pages and wrong for one that does not: `mlock` and
//! `munlock` are page-granular and **not reference counted**. Two secrets whose
//! heap allocations share a 4 KiB page — the common case for short passwords —
//! each lock the page; dropping the first *unlocks the page* while the second
//! still lives in it, believing itself locked. The lock was real at the moment
//! it was taken and silently gone a moment later, and nothing reported it.
//!
//! The only way to make "this secret is page-locked" true for the life of the
//! secret is to give secrets pages of their own. This module does that:
//!
//! * secrets are carved out of slabs that this module maps itself with
//!   `mmap`, so no ordinary allocation ever shares a page with one;
//! * each slab is `mlock`ed once, marked `MADV_DONTDUMP` (kept out of any
//!   core file, on top of the process-level `RLIMIT_CORE=0`) and
//!   `MADV_DONTFORK` (a forked child never inherits it);
//! * a slab is never unlocked while any secret lives in it — freed ranges are
//!   zeroed and reused, and the slab stays mapped and locked as a pool;
//! * when the kernel refuses the lock (`RLIMIT_MEMLOCK`, 8 MiB on a stock box),
//!   the slab is still used but recorded as unlocked, the failure is counted,
//!   and `Secret::is_locked` and `doctor` say so. Best-effort is fine; lying
//!   about it is not.
//!
//! [`SecretBuf`] is the one type that lives here. It is a growable byte buffer
//! with `Deref<Target = [u8]>` and `std::io::Write`, so the transient
//! plaintext of a whole payload — the decrypted CBOR before it is parsed, the
//! serialised CBOR before it is encrypted — can be built in locked memory too,
//! not just the parsed `Secret`s. Both were `Zeroizing<Vec<u8>>` before: wiped
//! on drop, but swappable while alive.
//!
//! # What this does not do
//!
//! Guard pages and canaries (the `sodium_malloc` design) are not implemented;
//! this is a locked arena, not a hardened allocator. The Argon2 working set,
//! the compositor's copy of a pasted value, and the QML surfaces remain in
//! ordinary memory, as the whitepaper's non-claims say.

use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Normal slab size. Large enough that a typical vault fits in one or two,
/// small enough that a failed lock costs little.
pub const SLAB_BYTES: usize = 256 * 1024;
/// Allocation granule inside a slab.
const ALIGN: usize = 16;

/// Bytes currently held in locked slabs.
static LOCKED_BYTES: AtomicUsize = AtomicUsize::new(0);
/// Bytes currently held in slabs the kernel refused to lock.
static UNLOCKED_BYTES: AtomicUsize = AtomicUsize::new(0);
/// Locks we asked for and did not get.
static FAILED_LOCKS: AtomicUsize = AtomicUsize::new(0);

static ARENA: Mutex<Arena> = Mutex::new(Arena { slabs: Vec::new() });

struct Arena {
    slabs: Vec<Slab>,
}

struct Slab {
    base: NonNull<u8>,
    size: usize,
    locked: bool,
    /// A slab mapped for one oversize allocation; released when it is freed.
    dedicated: bool,
    /// Free ranges as `(offset, len)`, sorted by offset, non-adjacent.
    free: Vec<(usize, usize)>,
    /// Live allocations, so a wholly-free slab can be recognised.
    live: usize,
}

// The arena hands out raw pointers into its own mappings; every access goes
// through a `SecretBuf` that owns its range exclusively.
unsafe impl Send for Slab {}

fn page_size() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 {
        4096
    } else {
        n as usize
    }
}

impl Slab {
    fn map(size: usize, dedicated: bool) -> Option<Slab> {
        let page = page_size();
        let size = size.div_ceil(page) * page;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        let base = NonNull::new(ptr as *mut u8)?;

        let locked = unsafe { libc::mlock(ptr, size) } == 0;
        if locked {
            LOCKED_BYTES.fetch_add(size, Ordering::Relaxed);
        } else {
            FAILED_LOCKS.fetch_add(1, Ordering::Relaxed);
            UNLOCKED_BYTES.fetch_add(size, Ordering::Relaxed);
        }
        // Advice, not policy: a kernel that ignores these is no worse off than
        // before this module existed.
        unsafe {
            libc::madvise(ptr, size, libc::MADV_DONTDUMP);
            libc::madvise(ptr, size, libc::MADV_DONTFORK);
        }

        Some(Slab {
            base,
            size,
            locked,
            dedicated,
            free: vec![(0, size)],
            live: 0,
        })
    }

    fn unmap(self) {
        // Belt and braces: the ranges were zeroed as they were freed, but the
        // whole mapping is scrubbed once more before it goes back to the kernel.
        unsafe {
            std::ptr::write_bytes(self.base.as_ptr(), 0, self.size);
            if self.locked {
                libc::munlock(self.base.as_ptr() as *const libc::c_void, self.size);
                LOCKED_BYTES.fetch_sub(self.size, Ordering::Relaxed);
            } else {
                UNLOCKED_BYTES.fetch_sub(self.size, Ordering::Relaxed);
            }
            libc::munmap(self.base.as_ptr() as *mut libc::c_void, self.size);
        }
    }

    /// First-fit allocation of `len` bytes (already rounded to `ALIGN`).
    fn alloc(&mut self, len: usize) -> Option<usize> {
        let idx = self.free.iter().position(|&(_, flen)| flen >= len)?;
        let (off, flen) = self.free[idx];
        if flen == len {
            self.free.remove(idx);
        } else {
            self.free[idx] = (off + len, flen - len);
        }
        self.live += 1;
        Some(off)
    }

    /// Return a range, zeroing it and coalescing with its neighbours.
    fn release(&mut self, off: usize, len: usize) {
        unsafe {
            // Volatile so the compiler cannot elide the wipe of memory it
            // believes is dead.
            let p = self.base.as_ptr().add(off);
            for i in 0..len {
                std::ptr::write_volatile(p.add(i), 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);

        let pos = self
            .free
            .iter()
            .position(|&(foff, _)| foff > off)
            .unwrap_or(self.free.len());
        self.free.insert(pos, (off, len));
        // Merge with the following range.
        if pos + 1 < self.free.len() && self.free[pos].0 + self.free[pos].1 == self.free[pos + 1].0 {
            let next = self.free.remove(pos + 1);
            self.free[pos].1 += next.1;
        }
        // Merge with the preceding range.
        if pos > 0 && self.free[pos - 1].0 + self.free[pos - 1].1 == self.free[pos].0 {
            let cur = self.free.remove(pos);
            self.free[pos - 1].1 += cur.1;
        }
        self.live = self.live.saturating_sub(1);
    }
}

fn round_up(len: usize) -> usize {
    len.max(1).div_ceil(ALIGN) * ALIGN
}

/// Where a buffer's bytes live.
#[derive(Clone, Copy)]
struct Place {
    slab: usize,
    off: usize,
    cap: usize,
}

fn arena_alloc(cap: usize) -> Option<(Place, NonNull<u8>, bool)> {
    let cap = round_up(cap);
    let mut arena = ARENA.lock().ok()?;

    if cap <= SLAB_BYTES {
        for (i, slab) in arena.slabs.iter_mut().enumerate() {
            if slab.dedicated {
                continue;
            }
            if let Some(off) = slab.alloc(cap) {
                let ptr = unsafe { NonNull::new_unchecked(slab.base.as_ptr().add(off)) };
                return Some((Place { slab: i, off, cap }, ptr, slab.locked));
            }
        }
        let mut slab = Slab::map(SLAB_BYTES, false)?;
        let off = slab.alloc(cap)?;
        let ptr = unsafe { NonNull::new_unchecked(slab.base.as_ptr().add(off)) };
        let locked = slab.locked;
        arena.slabs.push(slab);
        let idx = arena.slabs.len() - 1;
        return Some((Place { slab: idx, off, cap }, ptr, locked));
    }

    // Oversize: a slab of its own, released when it is freed.
    let mut slab = Slab::map(cap, true)?;
    let off = slab.alloc(cap)?;
    let ptr = unsafe { NonNull::new_unchecked(slab.base.as_ptr().add(off)) };
    let locked = slab.locked;
    // Reuse a vacated slot so indices of live buffers stay valid.
    if let Some(idx) = arena.slabs.iter().position(|s| s.size == 0) {
        arena.slabs[idx] = slab;
        return Some((Place { slab: idx, off, cap }, ptr, locked));
    }
    arena.slabs.push(slab);
    let idx = arena.slabs.len() - 1;
    Some((Place { slab: idx, off, cap }, ptr, locked))
}

fn arena_free(place: Place) {
    let Ok(mut arena) = ARENA.lock() else {
        return;
    };
    let Some(slab) = arena.slabs.get_mut(place.slab) else {
        return;
    };
    slab.release(place.off, place.cap);
    if slab.dedicated && slab.live == 0 {
        // Take it out without shifting the others: replace with a tombstone
        // whose size is zero so it is never chosen and its index can be reused.
        let tomb = Slab {
            base: NonNull::dangling(),
            size: 0,
            locked: false,
            dedicated: true,
            free: Vec::new(),
            live: 0,
        };
        let gone = std::mem::replace(slab, tomb);
        gone.unmap();
    }
}

fn arena_is_locked(slab: usize) -> bool {
    ARENA
        .lock()
        .ok()
        .and_then(|a| a.slabs.get(slab).map(|s| s.locked))
        .unwrap_or(false)
}

/// Bytes currently mapped in locked slabs.
pub fn locked_bytes() -> usize {
    LOCKED_BYTES.load(Ordering::Relaxed)
}

/// Bytes currently mapped in slabs the kernel refused to lock.
pub fn unlocked_bytes() -> usize {
    UNLOCKED_BYTES.load(Ordering::Relaxed)
}

/// Slab locks the kernel refused.
pub fn failed_locks() -> usize {
    FAILED_LOCKS.load(Ordering::Relaxed)
}

/// A growable byte buffer in the locked arena. Zeroed when it dies, and when
/// it grows out of a range, that range is zeroed on the way out too.
pub struct SecretBuf {
    ptr: NonNull<u8>,
    len: usize,
    place: Option<Place>,
}

unsafe impl Send for SecretBuf {}
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    /// An empty buffer that owns nothing yet.
    pub const fn empty() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            place: None,
        }
    }

    /// A buffer holding a copy of `bytes`.
    pub fn new(bytes: &[u8]) -> Self {
        let mut out = Self::with_capacity(bytes.len());
        out.extend_from_slice(bytes);
        out
    }

    /// A buffer of `len` zero bytes.
    pub fn zeroed(len: usize) -> Self {
        let mut out = Self::with_capacity(len);
        out.len = len;
        out
    }

    pub fn with_capacity(cap: usize) -> Self {
        if cap == 0 {
            return Self::empty();
        }
        match arena_alloc(cap) {
            Some((place, ptr, _)) => Self {
                ptr,
                len: 0,
                place: Some(place),
            },
            // The arena could not map memory at all. Rather than abort a
            // process that is mid-way through opening a vault, fall back to
            // an ordinary allocation that is still zeroed on drop; the miss
            // is visible through `failed_locks` because the slab map failed
            // before it could count a lock.
            None => {
                FAILED_LOCKS.fetch_add(1, Ordering::Relaxed);
                let mut v = Vec::<u8>::with_capacity(cap.max(1));
                let ptr = NonNull::new(v.as_mut_ptr()).unwrap_or(NonNull::dangling());
                std::mem::forget(v);
                Self {
                    ptr,
                    len: 0,
                    place: Some(Place {
                        slab: usize::MAX,
                        off: 0,
                        cap: cap.max(1),
                    }),
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.place.map(|p| p.cap).unwrap_or(0)
    }

    /// Whether the slab this buffer lives in is page-locked.
    pub fn is_locked(&self) -> bool {
        match self.place {
            Some(p) if p.slab != usize::MAX => arena_is_locked(p.slab),
            _ => false,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.as_ptr().add(self.len), bytes.len());
        }
        self.len += bytes.len();
    }

    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    /// Shrink to `len`, zeroing what is cut off.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        unsafe {
            let p = self.ptr.as_ptr().add(len);
            for i in 0..(self.len - len) {
                std::ptr::write_volatile(p.add(i), 0);
            }
        }
        self.len = len;
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Make room for `additional` more bytes, moving to a larger range if
    /// needed. The vacated range is zeroed.
    pub fn reserve(&mut self, additional: usize) {
        let needed = self.len.saturating_add(additional);
        if needed <= self.capacity() {
            return;
        }
        let new_cap = needed.max(self.capacity().saturating_mul(2)).max(ALIGN);
        let mut fresh = Self::with_capacity(new_cap);
        fresh.extend_from_slice(self.as_slice());
        *self = fresh;
    }

    /// Interpret as UTF-8, into a buffer that is wiped when dropped.
    pub fn to_zeroizing_string(&self) -> Result<zeroize::Zeroizing<String>, std::str::Utf8Error> {
        let s = std::str::from_utf8(self.as_slice())?;
        Ok(zeroize::Zeroizing::new(s.to_string()))
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        let Some(place) = self.place.take() else {
            return;
        };
        if place.slab == usize::MAX {
            // Fallback heap buffer.
            unsafe {
                for i in 0..place.cap {
                    std::ptr::write_volatile(self.ptr.as_ptr().add(i), 0);
                }
                drop(Vec::from_raw_parts(self.ptr.as_ptr(), 0, place.cap));
            }
            return;
        }
        arena_free(place);
    }
}

impl Clone for SecretBuf {
    fn clone(&self) -> Self {
        Self::new(self.as_slice())
    }
}

impl std::ops::Deref for SecretBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::ops::DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for SecretBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for SecretBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl io::Write for SecretBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PartialEq for SecretBuf {
    /// Constant-time over equal lengths.
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.len != other.len {
            return false;
        }
        self.as_slice().ct_eq(other.as_slice()).unwrap_u8() == 1
    }
}

impl Eq for SecretBuf {}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuf({} bytes, redacted)", self.len)
    }
}

impl Serialize for SecretBuf {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_slice())
    }
}

struct SecretVisitor;

impl<'de> Visitor<'de> for SecretVisitor {
    type Value = SecretBuf;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<SecretBuf, E> {
        Ok(SecretBuf::new(v))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<SecretBuf, E> {
        Ok(SecretBuf::new(v))
    }

    fn visit_byte_buf<E: de::Error>(self, mut v: Vec<u8>) -> Result<SecretBuf, E> {
        use zeroize::Zeroize;
        let out = SecretBuf::new(&v);
        v.zeroize();
        Ok(out)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretBuf, E> {
        Ok(SecretBuf::new(v.as_bytes()))
    }

    fn visit_string<E: de::Error>(self, mut v: String) -> Result<SecretBuf, E> {
        use zeroize::Zeroize;
        let out = SecretBuf::new(v.as_bytes());
        v.zeroize();
        Ok(out)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<SecretBuf, A::Error> {
        let mut out = SecretBuf::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element::<u8>()? {
            out.push(byte);
        }
        Ok(out)
    }
}

impl<'de> Deserialize<'de> for SecretBuf {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `deserialize_bytes`, not `deserialize_byte_buf`: ciborium serves the
        // former straight out of its scratch buffer, which the vault code
        // supplies from this arena, so no unlocked intermediate copy exists.
        // The byte_buf path would build an ordinary `Vec` first.
        deserializer.deserialize_bytes(SecretVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_bytes_and_reports_length() {
        let s = SecretBuf::new(b"correct horse");
        assert_eq!(s.len(), 13);
        assert_eq!(&*s, b"correct horse");
        assert!(!s.is_empty());
        assert!(SecretBuf::empty().is_empty());
    }

    #[test]
    fn growth_keeps_contents_and_zeroes_the_old_range() {
        let mut s = SecretBuf::with_capacity(4);
        let first_ptr = s.ptr.as_ptr();
        let first_cap = s.capacity();
        s.extend_from_slice(b"abcd");
        // Force a move to a larger range.
        s.extend_from_slice(&[b'x'; 1000]);
        assert_eq!(s.len(), 1004);
        assert_eq!(&s[..4], b"abcd");
        assert!(s[4..].iter().all(|&b| b == b'x'));
        assert!(s.capacity() >= 1004);
        // The vacated range must read back as zeros. It is still mapped
        // (slabs are pools), so this is safe to inspect.
        if first_ptr != s.ptr.as_ptr() && first_cap > 0 {
            let old = unsafe { std::slice::from_raw_parts(first_ptr, first_cap) };
            assert!(old.iter().all(|&b| b == 0), "vacated range was not wiped");
        }
    }

    #[test]
    fn freed_ranges_are_zeroed_and_reused() {
        let ptr;
        {
            let s = SecretBuf::new(&[0xAB; 64]);
            ptr = s.ptr.as_ptr();
        }
        // Dropped: the bytes at that address are zero now.
        let after = unsafe { std::slice::from_raw_parts(ptr, 64) };
        assert!(after.iter().all(|&b| b == 0), "freed secret was not wiped");
    }

    #[test]
    fn two_secrets_never_share_a_lock_they_can_lose() {
        // The defect this module exists for: with per-Vec mlock, dropping `a`
        // would munlock the page `b` lives in. Here `b` is locked iff its slab
        // is, and the slab stays locked until the whole arena is torn down.
        let a = SecretBuf::new(b"first");
        let b = SecretBuf::new(b"second");
        let b_locked_before = b.is_locked();
        drop(a);
        assert_eq!(b.is_locked(), b_locked_before);
        if b_locked_before {
            assert!(locked_bytes() >= SLAB_BYTES);
        }
    }

    #[test]
    fn oversize_allocations_get_their_own_slab_and_give_it_back() {
        let before = locked_bytes() + unlocked_bytes();
        {
            let big = SecretBuf::new(&vec![7u8; SLAB_BYTES * 2 + 5]);
            assert_eq!(big.len(), SLAB_BYTES * 2 + 5);
            assert!(locked_bytes() + unlocked_bytes() >= before + SLAB_BYTES * 2);
        }
        // Released on drop; the pool slabs stay.
        assert!(locked_bytes() + unlocked_bytes() < before + SLAB_BYTES * 2 + page_size() * 2);
    }

    #[test]
    fn constant_time_equality_is_length_then_content() {
        assert_eq!(SecretBuf::new(b"abc"), SecretBuf::new(b"abc"));
        assert_ne!(SecretBuf::new(b"abc"), SecretBuf::new(b"abd"));
        assert_ne!(SecretBuf::new(b"abc"), SecretBuf::new(b"abcd"));
    }

    #[test]
    fn debug_never_prints_bytes() {
        let s = SecretBuf::new(b"hunter2");
        let shown = format!("{s:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn serde_roundtrips_through_cbor_and_json() {
        let s = SecretBuf::new(b"bytes \x00\xff here");
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&s, &mut cbor).unwrap();
        let back: SecretBuf = ciborium::de::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(back, s);

        // JSON encodes bytes as an array of numbers; the seq path covers it.
        let json = serde_json::to_string(&SecretBuf::new(b"ab")).unwrap();
        let back: SecretBuf = serde_json::from_str(&json).unwrap();
        assert_eq!(&*back, b"ab");
    }

    #[test]
    fn many_small_secrets_pack_into_one_slab() {
        let before = locked_bytes() + unlocked_bytes();
        let held: Vec<SecretBuf> = (0..1000).map(|i| SecretBuf::new(&[i as u8; 24])).collect();
        assert_eq!(held.len(), 1000);
        // 1000 × 32 bytes = 32 KiB, well within one slab; at most one new slab
        // was mapped for them.
        assert!(locked_bytes() + unlocked_bytes() <= before + SLAB_BYTES + page_size());
        for (i, s) in held.iter().enumerate() {
            assert!(s.iter().all(|&b| b == i as u8));
        }
    }

    #[test]
    fn write_trait_appends() {
        use std::io::Write;
        let mut s = SecretBuf::empty();
        s.write_all(b"one ").unwrap();
        s.write_all(b"two").unwrap();
        assert_eq!(&*s, b"one two");
    }
}
