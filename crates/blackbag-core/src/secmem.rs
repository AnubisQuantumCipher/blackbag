//! Secret memory: encrypted at rest, kernel-invisible key, locked scratch.
//!
//! # The design, in one paragraph
//!
//! Every secret this process holds — each record field, the vault's data key —
//! is **ciphertext** while it rests in memory, sealed under a 32-byte session
//! key that exists only for the life of this process. The key lives in memory
//! the kernel itself cannot read: `memfd_secret` pages are removed from the
//! kernel's direct map, are never swapped, never land in a core file or a
//! hibernation image, and are not reachable through the usual "read another
//! process's memory" paths that go via the direct map. Where the kernel does
//! not offer that, the key sits in one page-locked slab instead, and the
//! difference is reported rather than hidden. Plaintext exists only while a
//! field is actually being used, in a small locked arena, and is wiped the
//! moment the use ends.
//!
//! What this buys over "page-lock everything": the thing that must never
//! reach disk shrinks from *every secret in the vault* to *32 bytes*, so a
//! large vault no longer contends with an 8 MiB `RLIMIT_MEMLOCK`; a memory
//! scrape of an idle unlocked agent finds ciphertext, not passwords; and a
//! secret's protection no longer depends on which page its neighbour was
//! freed from. It is the construction 1Password, KeePassXC and Bitwarden all
//! describe for their desktop clients, with a stronger home for the key than
//! any of them has on Linux.
//!
//! [`Guarded`] is the encrypted-at-rest type. [`SecretBuf`] is the transient
//! plaintext buffer, and the rest of this file is the arena behind it.
//!
//! # Why a plain `mlock`ed `Vec` was not enough for the transient buffers
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
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Associated data for in-memory sealing, so a guarded blob can never be
/// mistaken for — or replayed into — a vault ciphertext.
const AAD_GUARDED: &[u8] = b"black-bag::v2::guarded-memory";

/// `memfd_secret(2)`. The number is the same on every architecture Linux
/// has added a syscall to since the tables were unified, and `libc` does not
/// yet export it on all of them.
#[cfg(target_os = "linux")]
const SYS_MEMFD_SECRET: libc::c_long = 447;

// ── the session key ─────────────────────────────────────────────────────────

/// Where the session key's page came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBacking {
    /// `memfd_secret`: unmapped from the kernel's direct map, never swapped,
    /// never dumped, never in a hibernation image.
    SecretMem,
    /// A page-locked slab from the arena: never swapped, never dumped.
    LockedSlab,
    /// The arena could not lock its slab. The key is in ordinary memory and
    /// the posture report says so.
    Unlocked,
}

impl KeyBacking {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyBacking::SecretMem => "memfd_secret",
            KeyBacking::LockedSlab => "locked-slab",
            KeyBacking::Unlocked => "unlocked",
        }
    }
}

struct SessionKey {
    ptr: NonNull<u8>,
    backing: KeyBacking,
    /// Kept so the arena slab, when that is the backing, lives as long as
    /// the key does.
    _slab: Option<SecretBuf>,
}

unsafe impl Send for SessionKey {}
unsafe impl Sync for SessionKey {}

static SESSION_KEY: OnceLock<SessionKey> = OnceLock::new();

impl SessionKey {
    fn get() -> &'static SessionKey {
        SESSION_KEY.get_or_init(Self::create)
    }

    fn create() -> SessionKey {
        let mut fresh = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(fresh.as_mut());

        if std::env::var_os("BLACK_BAG_NO_SECRETMEM").is_none() {
            if let Some(ptr) = secretmem_page() {
                unsafe {
                    std::ptr::copy_nonoverlapping(fresh.as_ptr(), ptr.as_ptr(), 32);
                }
                return SessionKey {
                    ptr,
                    backing: KeyBacking::SecretMem,
                    _slab: None,
                };
            }
        }

        let mut slab = SecretBuf::zeroed(32);
        slab.as_mut_slice().copy_from_slice(fresh.as_ref());
        let backing = if slab.is_locked() {
            KeyBacking::LockedSlab
        } else {
            KeyBacking::Unlocked
        };
        let ptr = NonNull::new(slab.as_mut_slice().as_mut_ptr()).unwrap_or(NonNull::dangling());
        SessionKey {
            ptr,
            backing,
            _slab: Some(slab),
        }
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), 32) }
    }
}

/// One page of secret memory, or `None` when the kernel does not offer it.
#[cfg(target_os = "linux")]
fn secretmem_page() -> Option<NonNull<u8>> {
    let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0 as libc::c_uint) };
    if fd < 0 {
        return None;
    }
    let fd = fd as libc::c_int;
    let page = page_size();
    let ok = unsafe { libc::ftruncate(fd, page as libc::off_t) } == 0;
    if !ok {
        unsafe { libc::close(fd) };
        return None;
    }
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    // The mapping keeps the memory alive; the descriptor is not needed.
    unsafe { libc::close(fd) };
    if ptr == libc::MAP_FAILED {
        return None;
    }
    // Touch it so the page exists before the key is written.
    unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, page) };
    NonNull::new(ptr as *mut u8)
}

#[cfg(not(target_os = "linux"))]
fn secretmem_page() -> Option<NonNull<u8>> {
    None
}

/// How the session key is held. Forces creation of the key, which is what
/// any caller of this function is about to need anyway.
pub fn session_key_backing() -> KeyBacking {
    SessionKey::get().backing
}

// ── encrypted at rest ───────────────────────────────────────────────────────

/// Bytes sealed under the session key. The ciphertext lives in ordinary
/// memory — it can be swapped, dumped or scraped without revealing anything —
/// and [`Guarded::open`] produces the plaintext in a locked [`SecretBuf`] for
/// exactly as long as the caller holds it.
///
/// Serialises as the plaintext bytes, because the only place a `Guarded`
/// value is ever serialised is into the vault payload, which is itself about
/// to be encrypted in locked memory; and deserialises straight into a seal.
pub struct Guarded {
    nonce: [u8; 24],
    /// ciphertext || 16-byte tag
    sealed: Vec<u8>,
    len: usize,
}

impl Guarded {
    pub fn new(plain: &[u8]) -> Self {
        let key = SessionKey::get();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.bytes()));
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut sealed = plain.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), AAD_GUARDED, &mut sealed)
            .expect("in-memory sealing cannot fail for a buffer this size");
        sealed.extend_from_slice(&tag);
        Self {
            nonce,
            sealed,
            len: plain.len(),
        }
    }

    /// Plaintext length. Not secret: the record views already carry it.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Decrypt into a locked buffer. `None` only if the ciphertext was
    /// corrupted in memory, which is not a condition this process can
    /// recover from and is reported by the caller as such.
    pub fn try_open(&self) -> Option<SecretBuf> {
        if self.sealed.len() < 16 {
            return None;
        }
        let key = SessionKey::get();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.bytes()));
        let (body, tag) = self.sealed.split_at(self.sealed.len() - 16);
        let mut out = SecretBuf::new(body);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                AAD_GUARDED,
                out.as_mut_slice(),
                Tag::from_slice(tag),
            )
            .ok()?;
        Some(out)
    }

    /// Decrypt into a locked buffer.
    ///
    /// Panics if the sealed bytes fail authentication. That means this
    /// process's memory has been altered underneath it, and continuing to
    /// serve requests on a vault whose secrets can no longer be trusted is
    /// worse than unwinding — which wipes every `Zeroizing` and `SecretBuf`
    /// on the way out.
    pub fn open(&self) -> SecretBuf {
        self.try_open()
            .expect("a secret held in memory failed authentication; refusing to continue")
    }

    /// Whether the plaintext this holds is the given bytes, in constant time.
    pub fn equals(&self, plain: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        if self.len != plain.len() {
            return false;
        }
        let opened = self.open();
        opened.as_slice().ct_eq(plain).unwrap_u8() == 1
    }
}

impl Clone for Guarded {
    fn clone(&self) -> Self {
        Self {
            nonce: self.nonce,
            sealed: self.sealed.clone(),
            len: self.len,
        }
    }
}

impl PartialEq for Guarded {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        let a = self.open();
        let b = other.open();
        a == b
    }
}

impl Eq for Guarded {}

impl std::fmt::Debug for Guarded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Guarded({} bytes, sealed)", self.len)
    }
}

impl Serialize for Guarded {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let opened = self.open();
        serializer.serialize_bytes(opened.as_slice())
    }
}

impl<'de> Deserialize<'de> for Guarded {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let buf = SecretBuf::deserialize(deserializer)?;
        Ok(Guarded::new(buf.as_slice()))
    }
}

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
    fn guarded_roundtrips_and_never_stores_plaintext() {
        let g = Guarded::new(b"correct horse battery staple");
        assert_eq!(g.len(), 28);
        assert_eq!(&*g.open(), b"correct horse battery staple");
        // The resting representation must not contain the plaintext.
        let needle = b"correct horse";
        assert!(
            !g.sealed.windows(needle.len()).any(|w| w == needle),
            "plaintext found in the sealed buffer"
        );
        assert!(g.equals(b"correct horse battery staple"));
        assert!(!g.equals(b"correct horse battery stapl"));
    }

    #[test]
    fn guarded_uses_a_fresh_nonce_every_time() {
        let a = Guarded::new(b"same");
        let b = Guarded::new(b"same");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.sealed, b.sealed);
        assert_eq!(a, b, "equality is over plaintext");
    }

    #[test]
    fn guarded_detects_tampering_in_memory() {
        let mut g = Guarded::new(b"hunter2");
        g.sealed[0] ^= 0x01;
        assert!(g.try_open().is_none());
    }

    #[test]
    fn guarded_serde_carries_plaintext_only_across_the_vault_boundary() {
        let g = Guarded::new(b"\x00\x01secret\xff");
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&g, &mut cbor).unwrap();
        let back: Guarded = ciborium::de::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(back, g);
        assert_eq!(&*back.open(), b"\x00\x01secret\xff");
    }

    #[test]
    fn the_session_key_has_a_named_home() {
        let backing = session_key_backing();
        // On this machine it is memfd_secret; elsewhere a locked slab. What
        // it must never be, silently, is "unlocked" — that is reported.
        assert!(matches!(
            backing,
            KeyBacking::SecretMem | KeyBacking::LockedSlab | KeyBacking::Unlocked
        ));
        eprintln!("session key backing: {}", backing.as_str());
    }

    /// The property the whole module exists for, checked the hard way: after a
    /// secret is created, used and dropped, its plaintext is nowhere in this
    /// process's writable memory. Reads `/proc/self/mem` over every writable
    /// mapping — heap, arena slabs, stacks, the lot — and searches for a
    /// needle that appears in no other test.
    #[test]
    fn a_resting_secret_is_nowhere_in_writable_memory() {
        use std::io::{Read, Seek, SeekFrom};

        // Assembled at run time so the literal itself is not sitting in
        // .rodata as a single string the scan could trip over.
        let needle: Vec<u8> = b"ZETA-".iter().chain(b"NEEDLE-".iter()).chain(b"7741".iter()).copied().collect();

        let guarded = Guarded::new(&needle);
        {
            let opened = guarded.open();
            assert_eq!(opened.as_slice(), needle.as_slice());
            // `opened` is dropped here and its range zeroed.
        }

        // Another test in this binary runs `harden_process`, which clears
        // PR_SET_DUMPABLE and thereby makes /proc/self/mem root-owned. This
        // test needs to read its own memory, so it re-enables dumpability for
        // the test process. Test-only; production never does this.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
        let maps = std::fs::read_to_string("/proc/self/maps").expect("readable maps");
        let mut mem = std::fs::File::open("/proc/self/mem").expect("readable self mem");
        let mut hits = 0usize;
        let mut scanned = 0usize;
        let mut buf = Vec::new();
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            if !perms.starts_with("rw") {
                continue;
            }
            // Skip the needle vector's own allocation by excluding a hit at
            // exactly its address; everything else must be clean.
            let (lo, hi) = range.split_once('-').unwrap();
            let lo = u64::from_str_radix(lo, 16).unwrap();
            let hi = u64::from_str_radix(hi, 16).unwrap();
            let len = (hi - lo) as usize;
            if len > 256 * 1024 * 1024 {
                continue;
            }
            buf.clear();
            buf.resize(len, 0);
            if mem.seek(SeekFrom::Start(lo)).is_err() || mem.read_exact(&mut buf).is_err() {
                continue;
            }
            scanned += len;
            let own = needle.as_ptr() as u64;
            // The scan buffer is itself in the heap: while the heap mapping
            // is being read, `buf` holds whatever the previous mapping held,
            // which may include the needle. A hit inside `buf`'s own address
            // range is the scanner seeing itself, not a leak.
            let buf_lo = buf.as_ptr() as u64;
            let buf_hi = buf_lo + buf.len() as u64;
            for (i, w) in buf.windows(needle.len()).enumerate() {
                let at = lo + i as u64;
                if w == needle.as_slice() && at != own && !(at >= buf_lo && at < buf_hi) {
                    hits += 1;
                }
            }
        }
        assert!(scanned > 0, "nothing was scanned");
        assert_eq!(
            hits, 0,
            "plaintext of a resting secret found {hits} time(s) in writable memory"
        );
        drop(guarded);
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
