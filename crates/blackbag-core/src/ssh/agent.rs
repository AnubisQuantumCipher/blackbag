//! The SSH agent protocol — draft-miller-ssh-agent.
//!
//! De-framed request bytes in, response payload bytes out. What signs and what
//! lists keys is a [`Signer`], so this whole module is tested without a vault
//! or a socket.
//!
//! Only two requests do anything: list the identities, and sign with one.
//! Everything else is answered with `SSH_AGENT_FAILURE`, which is what an agent
//! that does not implement a request is supposed to say. In particular:
//!
//! - **Adding and removing keys is refused.** The vault is where keys live, and
//!   a client must not be able to push one in over the socket or delete one out
//!   of it. `ssh-add` will report that it could not, which is correct.
//! - **Lock and unlock are refused.** Black-Bag has its own lock, with its own
//!   proof; a second one reachable without that proof would be a way around it.

use super::wire::{Reader, Writer};

/// Client → agent message numbers.
pub mod client {
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const SIGN_REQUEST: u8 = 13;
    pub const ADD_IDENTITY: u8 = 17;
    pub const REMOVE_IDENTITY: u8 = 18;
    pub const REMOVE_ALL_IDENTITIES: u8 = 19;
    pub const LOCK: u8 = 22;
    pub const UNLOCK: u8 = 23;
}

/// Agent → client message numbers.
pub mod reply {
    pub const FAILURE: u8 = 5;
    pub const SUCCESS: u8 = 6;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_RESPONSE: u8 = 14;
}

/// One key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The SSH public-key blob — see [`super::wire::ed25519_public_blob`].
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// What the agent asks the vault to do. A trait so the protocol is tested
/// against a signer that never opens a vault.
pub trait Signer {
    /// The keys to offer, in the order they should appear.
    fn identities(&mut self) -> Vec<Identity>;

    /// Sign `data` with the key named by `key_blob`.
    ///
    /// Returns the full SSH signature blob, or `None` for any reason at all —
    /// no such key, the human declined, the vault is locked. The protocol
    /// answer is the same `FAILURE` in every case, because which one it was is
    /// a fact about the vault that a client has no business distinguishing.
    fn sign(&mut self, key_blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>>;
}

/// Answer one de-framed request, returning the response payload (to be framed
/// by the caller). Never fails: an unparseable or unknown request is a
/// `FAILURE`, which is a valid answer.
pub fn respond(signer: &mut dyn Signer, request: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(request);
    let Ok(kind) = r.u8() else {
        return failure();
    };
    match kind {
        client::REQUEST_IDENTITIES => identities_answer(signer.identities()),
        client::SIGN_REQUEST => match parse_sign(&mut r) {
            Some((key_blob, data, flags)) => match signer.sign(&key_blob, &data, flags) {
                Some(sig) => sign_response(&sig),
                None => failure(),
            },
            None => failure(),
        },
        // Adding, removing, locking: not this agent's to do. See the module
        // comment. FAILURE is the correct answer for an unimplemented request.
        client::ADD_IDENTITY
        | client::REMOVE_IDENTITY
        | client::REMOVE_ALL_IDENTITIES
        | client::LOCK
        | client::UNLOCK => failure(),
        _ => failure(),
    }
}

fn parse_sign(r: &mut Reader) -> Option<(Vec<u8>, Vec<u8>, u32)> {
    let key_blob = r.string().ok()?;
    let data = r.string().ok()?;
    let flags = r.u32().ok()?;
    // A request with bytes left over is not one we understood. Ignoring the
    // tail would sign `data` for a message whose real shape we do not know —
    // and signing is the one thing here that cannot be taken back.
    if !r.is_empty() {
        return None;
    }
    Some((key_blob, data, flags))
}

fn failure() -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(reply::FAILURE);
    w.into_bytes()
}

fn identities_answer(ids: Vec<Identity>) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(reply::IDENTITIES_ANSWER).u32(ids.len() as u32);
    for id in &ids {
        w.string(&id.key_blob).string(id.comment.as_bytes());
    }
    w.into_bytes()
}

fn sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(reply::SIGN_RESPONSE).string(signature_blob);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::super::wire::{ed25519_public_blob, ed25519_signature_blob};
    use super::*;

    struct Fake {
        ids: Vec<Identity>,
        sign: Option<Vec<u8>>,
        last_signed: Option<(Vec<u8>, Vec<u8>, u32)>,
    }

    impl Signer for Fake {
        fn identities(&mut self) -> Vec<Identity> {
            self.ids.clone()
        }
        fn sign(&mut self, key_blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
            self.last_signed = Some((key_blob.to_vec(), data.to_vec(), flags));
            self.sign.clone()
        }
    }

    fn request_identities() -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(client::REQUEST_IDENTITIES);
        w.into_bytes()
    }

    /// A tiny deterministic PRNG (SplitMix64) so a fuzz failure reproduces.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// The agent request is untrusted: it arrives length-prefixed off the
    /// socket and is walked by the SSH wire reader. `respond` must always
    /// return a reply (a failure frame at worst) — never an index panic or an
    /// unwrap on a truncated length field. Requests are biased to start with a
    /// real message type so the sign/list decoders are reached, not just the
    /// unknown-type bail.
    #[test]
    fn arbitrary_requests_never_panic_respond() {
        let mut prng = SplitMix64::new(0x0055_1234_ABCD_5555);
        let types = [
            client::REQUEST_IDENTITIES,
            client::SIGN_REQUEST,
            0x11,
            0x00,
            0xff,
        ];
        let mut f = Fake {
            ids: vec![Identity {
                key_blob: ed25519_public_blob(&[9; 32]),
                comment: "k".into(),
            }],
            sign: Some(vec![1, 2, 3]),
            last_signed: None,
        };
        for _ in 0..50_000 {
            let n = (prng.next() % 300) as usize;
            let mut req: Vec<u8> = (0..n).map(|_| (prng.next() & 0xff) as u8).collect();
            if !req.is_empty() {
                req[0] = types[(prng.next() as usize) % types.len()];
            }
            // The whole contract: it returns a reply. A panic fails the test.
            let _ = respond(&mut f, &req);
        }
    }

    #[test]
    fn identities_are_listed_in_order_with_their_comments() {
        let mut f = Fake {
            ids: vec![
                Identity {
                    key_blob: ed25519_public_blob(&[1; 32]),
                    comment: "work".into(),
                },
                Identity {
                    key_blob: ed25519_public_blob(&[2; 32]),
                    comment: "personal".into(),
                },
            ],
            sign: None,
            last_signed: None,
        };
        let resp = respond(&mut f, &request_identities());
        let mut r = Reader::new(&resp);
        assert_eq!(r.u8().unwrap(), reply::IDENTITIES_ANSWER);
        assert_eq!(r.u32().unwrap(), 2);
        assert_eq!(r.string().unwrap(), ed25519_public_blob(&[1; 32]));
        assert_eq!(r.utf8().unwrap(), "work");
        assert_eq!(r.string().unwrap(), ed25519_public_blob(&[2; 32]));
        assert_eq!(r.utf8().unwrap(), "personal");
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_keyring_is_an_answer_with_zero_keys_not_a_failure() {
        let mut f = Fake {
            ids: vec![],
            sign: None,
            last_signed: None,
        };
        let resp = respond(&mut f, &request_identities());
        let mut r = Reader::new(&resp);
        assert_eq!(r.u8().unwrap(), reply::IDENTITIES_ANSWER);
        assert_eq!(r.u32().unwrap(), 0);
    }

    #[test]
    fn a_sign_request_reaches_the_signer_and_the_blob_comes_back() {
        let blob = ed25519_signature_blob(&[0x55; 64]);
        let mut f = Fake {
            ids: vec![],
            sign: Some(blob.clone()),
            last_signed: None,
        };
        let key = ed25519_public_blob(&[9; 32]);
        let mut w = Writer::new();
        w.u8(client::SIGN_REQUEST)
            .string(&key)
            .string(b"the challenge to sign")
            .u32(0);
        let req = w.into_bytes();
        let resp = respond(&mut f, &req);

        let mut r = Reader::new(&resp);
        assert_eq!(r.u8().unwrap(), reply::SIGN_RESPONSE);
        assert_eq!(r.string().unwrap(), blob);
        // The signer saw exactly what was asked.
        let (k, d, fl) = f.last_signed.unwrap();
        assert_eq!(k, key);
        assert_eq!(d, b"the challenge to sign");
        assert_eq!(fl, 0);
    }

    /// Declining, no-such-key and a locked vault are all one answer, because
    /// which one it was is a fact about the vault the client must not learn.
    #[test]
    fn a_refused_signature_is_an_indistinguishable_failure() {
        let mut f = Fake {
            ids: vec![],
            sign: None, // the signer declines
            last_signed: None,
        };
        let mut w = Writer::new();
        w.u8(client::SIGN_REQUEST)
            .string(&ed25519_public_blob(&[9; 32]))
            .string(b"data")
            .u32(0);
        let req = w.into_bytes();
        let resp = respond(&mut f, &req);
        assert_eq!(resp, vec![reply::FAILURE]);
    }

    /// The vault owns the keyring; nothing over the socket may change it.
    #[test]
    fn adding_removing_and_locking_are_all_refused() {
        let mut f = Fake {
            ids: vec![],
            sign: None,
            last_signed: None,
        };
        for kind in [
            client::ADD_IDENTITY,
            client::REMOVE_IDENTITY,
            client::REMOVE_ALL_IDENTITIES,
            client::LOCK,
            client::UNLOCK,
        ] {
            let mut w = Writer::new();
            w.u8(kind);
            let resp = respond(&mut f, &w.into_bytes());
            assert_eq!(resp, vec![reply::FAILURE], "message {kind} must be refused");
        }
    }

    #[test]
    fn a_truncated_or_empty_request_is_a_failure_not_a_panic() {
        let mut f = Fake {
            ids: vec![],
            sign: Some(vec![1, 2, 3]),
            last_signed: None,
        };
        assert_eq!(respond(&mut f, &[]), vec![reply::FAILURE]);
        // SIGN_REQUEST with no body.
        assert_eq!(
            respond(&mut f, &[client::SIGN_REQUEST]),
            vec![reply::FAILURE]
        );
        // SIGN_REQUEST with a key but no data.
        let mut w = Writer::new();
        w.u8(client::SIGN_REQUEST).string(b"key");
        let partial = w.into_bytes();
        assert_eq!(respond(&mut f, &partial), vec![reply::FAILURE]);
        assert!(f.last_signed.is_none(), "a malformed request never reaches the signer");
    }

    #[test]
    fn an_unknown_message_is_a_failure() {
        let mut f = Fake {
            ids: vec![],
            sign: None,
            last_signed: None,
        };
        assert_eq!(respond(&mut f, &[99]), vec![reply::FAILURE]);
    }

    /// A SIGN_REQUEST with bytes left over is not one we understood, and
    /// signing is the one thing here that cannot be taken back. The fuzz pass
    /// that hardened the other parsers guarded the framing reader and left
    /// this one, which is the parser that reaches a private key.
    #[test]
    fn a_sign_request_with_trailing_bytes_is_refused() {
        let mut w = Writer::new();
        w.u8(client::SIGN_REQUEST);
        w.string(&ed25519_public_blob(&[1; 32]));
        w.string(b"payload");
        w.u32(0);
        w.u8(0x41); // one byte we never asked for
        let framed = w.into_bytes();
        let mut r = Reader::new(&framed[1..]);
        assert!(
            parse_sign(&mut r).is_none(),
            "a request we did not fully understand must not be signed");
    }

    /// And the exact same request without the tail still signs, so the guard
    /// refuses the surprise rather than the shape.
    #[test]
    fn the_same_sign_request_without_the_tail_is_accepted() {
        let mut w = Writer::new();
        w.u8(client::SIGN_REQUEST);
        w.string(&ed25519_public_blob(&[1; 32]));
        w.string(b"payload");
        w.u32(0);
        let framed = w.into_bytes();
        let mut r = Reader::new(&framed[1..]);
        let parsed = parse_sign(&mut r).expect("a well-formed request parses");
        assert_eq!(parsed.1, b"payload");
        assert_eq!(parsed.2, 0);
    }
}
