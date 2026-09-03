//! The SSH wire format — RFC 4251 §5.
//!
//! Length-prefixed everything: a `string` is a `uint32` byte count followed by
//! that many bytes, which may be binary. The agent protocol and the key and
//! signature blobs are all built from these few primitives, so this is the one
//! place that reads and writes them, and the one place bounds are checked.
//!
//! A reader over untrusted bytes — the agent socket carries whatever a client
//! sends — so every read is bounded against what remains, and a length that
//! runs past the buffer is an error rather than a panic or an allocation.

use anyhow::{Result, bail};

/// The most a single `string` may claim, so a hostile length cannot ask for a
/// gigabyte allocation. An SSH agent message is small; 256 KiB is generous.
const MAX_STRING: usize = 256 * 1024;

/// Reads SSH wire primitives, bounded against the end of the buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            bail!("truncated: expected a byte");
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            bail!("truncated: expected a uint32");
        }
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    /// A length-prefixed string, bounded by both the buffer and [`MAX_STRING`].
    pub fn string(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > MAX_STRING {
            bail!("an SSH string of {len} bytes exceeds the {MAX_STRING}-byte cap");
        }
        if self.remaining() < len {
            bail!("truncated: a string claims {len} bytes, {} remain", self.remaining());
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    /// A string that must be valid UTF-8 — a key type name, a comment.
    pub fn utf8(&mut self) -> Result<String> {
        String::from_utf8(self.string()?).map_err(|_| anyhow::anyhow!("a string was not UTF-8"))
    }
}

/// Builds SSH wire primitives.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, b: u8) -> &mut Self {
        self.buf.push(b);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn string(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Wrap the current contents as one length-prefixed frame: the agent
    /// protocol puts a `uint32` length in front of every message.
    pub fn into_frame(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len() + 4);
        out.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.buf);
        out
    }
}

/// The `ssh-ed25519` public-key blob: `string("ssh-ed25519") string(pubkey)`.
///
/// This is the byte string that appears, base64-encoded, in an
/// `authorized_keys` line and that a client matches a sign request against, so
/// it has to be exactly right.
pub fn ed25519_public_blob(public_key: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(b"ssh-ed25519").string(public_key);
    w.into_bytes()
}

/// The `ssh-ed25519` signature blob: `string("ssh-ed25519") string(sig)`.
pub fn ed25519_signature_blob(signature: &[u8; 64]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(b"ssh-ed25519").string(signature);
    w.into_bytes()
}

/// One `authorized_keys` / `.pub` line: `ssh-ed25519 <base64 blob> <comment>`.
pub fn authorized_key_line(public_key: &[u8; 32], comment: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(ed25519_public_blob(public_key));
    if comment.is_empty() {
        format!("ssh-ed25519 {b64}")
    } else {
        format!("ssh-ed25519 {b64} {comment}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip() {
        let mut w = Writer::new();
        w.u8(0x0c).u32(3).string(b"ssh-ed25519").string(&[0xab; 32]);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x0c);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.utf8().unwrap(), "ssh-ed25519");
        assert_eq!(r.string().unwrap(), vec![0xab; 32]);
        assert!(r.is_empty(), "everything was consumed");
    }

    /// The agent socket carries whatever a client sends. A length that runs
    /// past the buffer must be an error, never a panic and never a giant
    /// allocation.
    #[test]
    fn a_length_past_the_end_is_refused() {
        // Claims 1000 bytes, supplies none.
        let bytes = [0x00, 0x00, 0x03, 0xe8];
        let mut r = Reader::new(&bytes);
        assert!(r.string().is_err());
    }

    #[test]
    fn an_absurd_length_is_refused_before_allocating() {
        let bytes = [0xff, 0xff, 0xff, 0xff];
        let mut r = Reader::new(&bytes);
        let err = r.string().unwrap_err().to_string();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_a_panic() {
        let mut r = Reader::new(&[0x01]);
        assert!(r.u8().is_ok());
        assert!(r.u8().is_err());
        assert!(r.u32().is_err());
        assert!(r.string().is_err());
    }

    /// The public blob is what ends up in authorized_keys. Its exact bytes are
    /// the contract with every SSH server, so they are pinned here.
    #[test]
    fn the_ed25519_public_blob_has_the_documented_shape() {
        let pk = [0x11u8; 32];
        let blob = ed25519_public_blob(&pk);
        let mut r = Reader::new(&blob);
        assert_eq!(r.utf8().unwrap(), "ssh-ed25519");
        assert_eq!(r.string().unwrap(), pk.to_vec());
        assert!(r.is_empty());
        // 4 + 11 + 4 + 32
        assert_eq!(blob.len(), 51);
    }

    #[test]
    fn a_frame_is_length_prefixed() {
        let mut w = Writer::new();
        w.u8(6); // SSH_AGENT_SUCCESS
        let framed = w.into_frame();
        assert_eq!(&framed[..4], &[0, 0, 0, 1], "one byte of payload");
        assert_eq!(framed[4], 6);
        assert_eq!(framed.len(), 5);
    }

    /// An authorized_keys line has to be pasteable straight into a server.
    #[test]
    fn an_authorized_key_line_is_well_formed() {
        let line = authorized_key_line(&[0x22; 32], "black-bag");
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" black-bag"));
        let b64 = line.split(' ').nth(1).unwrap();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(decoded, ed25519_public_blob(&[0x22; 32]));

        // No trailing space when there is no comment.
        assert!(!authorized_key_line(&[0x22; 32], "").ends_with(' '));
    }
}
