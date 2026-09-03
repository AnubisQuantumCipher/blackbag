//! Human approval for passkey ceremonies.
//!
//! # Why this exists at all
//!
//! Every other secret this agent hands out is a *copy of something you already
//! have*. A passkey assertion is different: it is a **login**, performed on your
//! behalf, at a site you may not be looking at. Reveal a password and an
//! attacker has a password. Sign an assertion and an attacker is already inside.
//!
//! The agent's socket is `0600` in a `0700` directory and checks `SO_PEERCRED`,
//! which establishes that the peer runs as the same user. That is the right
//! check and it is not a security boundary here: everything in the user's
//! session runs as the same user. If "the agent is unlocked" were sufficient
//! authority to sign, any process in the session could silently authenticate as
//! you, to anything, for as long as the vault stayed open — with nothing on
//! screen.
//!
//! So the socket never authorizes a signature. An approval must carry something
//! a socket client cannot manufacture: **the vault passphrase, re-entered for
//! this ceremony**, checked against the vault itself. That is the same secret
//! the vault already rests on, so this adds no new thing to steal, and it is
//! the one thing a process running as you does not have.
//!
//! This is a bar, not a boundary. A keylogger at the same uid defeats it — as
//! it defeats every other use of that passphrase. What it stops is the silent
//! case: a process that can write one line to a socket and be logged in as you
//! at a bank, with nothing on screen and nothing typed.
//!
//! # Why it is two-phase
//!
//! The agent is deliberately single-threaded: it accepts a connection, serves it
//! to completion, and only then accepts the next. Blocking inside a request to
//! wait for approval would deadlock — the approval could never be accepted. So a
//! ceremony is *registered*, the caller is handed a nonce, and the answer is
//! collected later.
//!
//! # What the nonce is and is not
//!
//! It identifies a **frozen** ceremony. Everything that will be signed —
//! the origin, the relying party, the client data, the set of credentials that
//! may be used — is recorded when the ceremony is registered and cannot be
//! changed afterwards. Approval selects from that recorded set and nothing else.
//! Without that, a caller could show the user one site, wait for approval, and
//! then swap in another: the classic time-of-check-to-time-of-use swap, which on
//! this path would mean approving a login to your bank and signing one to
//! someone else's.
//!
//! The nonce is not a capability to be guarded. Anything that can reach the
//! socket can enumerate pending ceremonies, because the deck — which reaches the
//! socket the same way — has to display them. Its job is to bind an approval to
//! one specific frozen request, not to keep secrets.

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// How long a ceremony may sit unanswered.
///
/// Chromium abandons a WebAuthn request at 180 seconds and then calls
/// `onRequestCanceled`, after which a response is no longer accepted. Expiring
/// first means the user is never asked to approve something that can no longer
/// be delivered, and never sees an approval appear to succeed and do nothing.
pub const CEREMONY_TTL_SECS: i64 = 120;

/// The most ceremonies that may be awaiting an answer at once.
///
/// A caller that can register ceremonies can also register them in a loop. The
/// cap keeps that from growing agent memory without bound, and — more usefully —
/// keeps it from burying a real prompt under a hundred fake ones the user
/// dismisses without reading.
pub const MAX_PENDING: usize = 8;

/// Wrong passphrases allowed on one ceremony before it is refused outright.
///
/// A passkey prompt that accepted guesses without limit would be a passphrase
/// oracle that any local process could raise at will — and each guess costs the
/// attacker one Argon2id evaluation, which is a price worth making them pay
/// only three times.
pub const MAX_PROOF_ATTEMPTS: u8 = 3;

/// What the browser asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Register a new credential at a relying party.
    Create,
    /// Sign an assertion with a credential the vault already holds.
    Assert,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Create => "create",
            Operation::Assert => "assert",
        }
    }
}

/// One credential a ceremony may legitimately use.
///
/// For an assert this is what the user picks between. For a create there is
/// exactly one, minted after approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    /// The vault record's id, as a string, so the deck can name it.
    pub record_id: String,
    /// The credential id the relying party knows this by.
    #[serde(with = "hex_bytes")]
    pub credential_id: Vec<u8>,
    /// What to show the human: the account, or the relying party.
    pub label: String,
}

/// A ceremony waiting for a human.
#[derive(Debug, Clone)]
pub struct Ceremony {
    pub nonce: String,
    pub operation: Operation,
    /// The caller origin, exactly as the browser reported it. This is what the
    /// human is shown, and what the signature is bound to.
    pub origin: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// Credentials this ceremony may use. Frozen at registration.
    pub choices: Vec<Choice>,
    /// The relying party's challenge, base64url, exactly as the browser
    /// supplied it.
    ///
    /// The *bytes* that get signed are built by the agent from this plus the
    /// origin above — never handed in by a caller. A caller that could supply
    /// the signed bytes directly would have a signing oracle with 32
    /// attacker-chosen bytes in a fixed position, and the origin the human read
    /// would have no mechanical relationship to the origin the relying party
    /// verifies.
    pub challenge: String,
    /// Whether the caller was a cross-origin iframe, for `crossOrigin`.
    pub cross_origin: bool,
    /// Set when the signed bytes are a hash we were HANDED rather than bytes
    /// we built, which is the only thing CTAP ever supplies.
    ///
    /// This is the one place the two lanes genuinely differ, so it is a field
    /// rather than a convention. On the browser-extension lane the agent
    /// builds `clientDataJSON` from an origin the browser vouched for, and the
    /// origin a person approved is the origin the relying party verifies *by
    /// construction*. Over CTAP there is no origin on the wire at all: an
    /// authenticator gets a relying-party id and a 32-byte hash and cannot see
    /// what was hashed. The browser binds the origin there, exactly as it does
    /// for a hardware key — no worse than the plastic, and no better.
    ///
    /// `register` enforces that exactly one of the two bindings is present, so
    /// a ceremony can never be half of each, and the consent screen can tell
    /// which it is looking at instead of showing an origin it does not have.
    pub client_data_hash: Option<Vec<u8>>,
    /// Create-only: who the credential will be for.
    pub user_handle: Option<Vec<u8>>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Create-only: the relying party's requested COSE algorithms
    /// (`pubKeyCredParams`), most preferred first. Frozen with the rest of the
    /// ceremony; empty means ES256, and the first supported one is minted.
    pub algorithms: Vec<i32>,
    /// Whether the relying party asked for the PRF extension.
    pub want_prf: bool,
    /// PRF salts, exactly as the relying party supplied them. Frozen with the
    /// rest of the ceremony: a PRF output is key material for the relying
    /// party's own encryption, so which salt gets evaluated must not be
    /// changeable after the human has approved.
    pub prf_first_salt: Option<Vec<u8>>,
    pub prf_second_salt: Option<Vec<u8>>,
    /// Opaque identity of the process that registered this ceremony, if the
    /// agent could determine one. Only that process may collect the answer.
    ///
    /// The human approves a login *for the thing that asked*. Without this, a
    /// local process could sit polling and take the signature the browser was
    /// waiting for — the person would have approved one login and someone else
    /// would have received it. This is blast-radius reduction and not a
    /// boundary: anything that can reach the socket can also spawn a process.
    pub owner: Option<String>,
    /// The program that asked, for the person answering to read.
    ///
    /// A hostile process can name itself anything and may be unreadable
    /// entirely, so this is not a control — it is context. Its value is that a
    /// prompt substituted by something else no longer looks identical to the
    /// one the browser raised.
    pub requester: Option<String>,
    pub registered_at: DateTime<Utc>,
    /// Failed proofs so far. A ceremony is refused outright after
    /// [`MAX_PROOF_ATTEMPTS`], so this is not an oracle to guess against.
    pub attempts: u8,
    pub state: State,
}

/// Where a ceremony has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// On screen, or about to be.
    AwaitingHuman,
    /// A human approved it, naming which credential to use.
    Approved { credential_id: Vec<u8> },
    /// A human refused it, or it expired.
    Refused { reason: &'static str },
    /// A human wants the browser's own path instead — a hardware key, or a
    /// phone.
    ///
    /// Distinct from a refusal because the caller has to act on it: while an
    /// extension holds the proxy, nothing in Chromium can reach a security
    /// key, so the only way to let one through is to stand down for a moment.
    /// A refusal and "let something else handle it" would otherwise be one
    /// string that the extension had to pattern-match, and a security decision
    /// taken by string comparison is one that breaks the first time the
    /// wording is improved.
    Deferred,
}

impl Ceremony {
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.registered_at + Duration::seconds(CEREMONY_TTL_SECS)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at()
    }

    /// What the deck puts on screen.
    ///
    /// The origin leads, because the origin is the thing a human can actually
    /// check and the thing an attacker must lie about.
    pub fn summary(&self) -> Summary {
        Summary {
            nonce: self.nonce.clone(),
            operation: self.operation,
            origin: self.origin.clone(),
            // So the screen can say "a program on this machine, through the
            // virtual security key" instead of naming an origin nobody told
            // us. A prompt that invented one would be the exact lie this
            // project exists not to tell.
            via_security_key: self.client_data_hash.is_some(),
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            account: self
                .user_name
                .clone()
                .or_else(|| self.choices.first().map(|c| c.label.clone())),
            requester: self.requester.clone(),
            choices: self.choices.clone(),
            want_prf: self.want_prf,
            expires_at: self.expires_at(),
        }
    }
}

/// The non-secret description of a pending ceremony, safe to publish where the
/// deck can see it.
///
/// It carries an origin and an account name — metadata, not secrets, and no
/// worse than the record list the same socket already serves. It carries no key
/// material and no client data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub nonce: String,
    pub operation: Operation,
    /// The caller origin, when a browser vouched for one. Empty when the
    /// request arrived over CTAP, where no origin exists on the wire.
    pub origin: String,
    /// True when this came through the virtual security key rather than the
    /// browser extension.
    ///
    /// The screen must render the two differently. Over CTAP there is no
    /// origin to show, and inventing a plausible one — from the relying-party
    /// id, say — would put a string in front of somebody that nothing checked.
    #[serde(default)]
    pub via_security_key: bool,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub account: Option<String>,
    /// What asked. `None` means the agent could not tell, which is itself
    /// worth showing rather than hiding.
    #[serde(default)]
    pub requester: Option<String>,
    pub choices: Vec<Choice>,
    /// Whether the relying party also asked for a PRF value.
    ///
    /// Worth its own line on screen: a PRF output is a key this credential
    /// derives for that site, which the site uses to encrypt things. Approving
    /// it is a different act from approving a sign-in, and a prompt that said
    /// only "sign in" while handing one over would be describing half of what
    /// it did.
    #[serde(default)]
    pub want_prf: bool,
    pub expires_at: DateTime<Utc>,
}

/// Every ceremony currently awaiting a human.
#[derive(Debug, Default)]
pub struct Desk {
    pending: Vec<Ceremony>,
}

impl Desk {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a ceremony and return its nonce.
    ///
    /// `nonce` is supplied rather than generated here so the caller owns the
    /// randomness source, and so tests are deterministic.
    pub fn register(&mut self, mut ceremony: Ceremony, now: DateTime<Utc>) -> Result<String> {
        self.expire(now);
        if self.pending.len() >= MAX_PENDING {
            bail!(
                "too many passkey requests are already waiting for an answer \
                 ({MAX_PENDING}); answer or dismiss one first"
            );
        }
        if ceremony.nonce.len() < 32 {
            bail!("a ceremony nonce must be at least 128 bits");
        }
        if self.pending.iter().any(|c| c.nonce == ceremony.nonce) {
            bail!("that ceremony nonce is already in use");
        }
        if ceremony.operation == Operation::Assert && ceremony.choices.is_empty() {
            bail!("no credential in this vault matches that request");
        }
        // Exactly one binding, never both and never neither. Both would leave
        // it ambiguous which bytes get signed; neither would mean nothing
        // binds the signature to a request at all.
        match &ceremony.client_data_hash {
            Some(hash) => {
                if hash.len() != 32 {
                    bail!("a client data hash is 32 bytes");
                }
                if !ceremony.origin.is_empty() || !ceremony.challenge.is_empty() {
                    bail!(
                        "a ceremony bound by a client data hash carries no origin \
                         and no challenge: there is nothing here to build them from"
                    );
                }
            }
            None => {
                if ceremony.origin.is_empty() || ceremony.challenge.is_empty() {
                    bail!("a ceremony needs an origin and a challenge, or a client data hash");
                }
            }
        }
        ceremony.state = State::AwaitingHuman;
        ceremony.registered_at = now;
        ceremony.attempts = 0;
        let nonce = ceremony.nonce.clone();
        self.pending.push(ceremony);
        Ok(nonce)
    }

    /// Approve a ceremony, naming which of its recorded credentials to use.
    ///
    /// A credential that was not among the choices recorded at registration is
    /// refused. This is the check that stops an approval being redirected: the
    /// human agreed to one specific thing, and only that thing can happen.
    /// Approve a ceremony, naming which of its recorded credentials to use.
    ///
    /// `proof_ok` is whether the answerer proved they know the vault
    /// passphrase. It is a parameter rather than something checked here because
    /// the check costs an Argon2id derivation and belongs to the agent that
    /// owns the vault path; what belongs here is that a false proof cannot
    /// approve anything, and that guesses are counted and run out.
    pub fn approve(
        &mut self,
        nonce: &str,
        credential_id: Option<&[u8]>,
        proof_ok: bool,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.expire(now);
        let ceremony = self
            .pending
            .iter_mut()
            .find(|c| c.nonce == nonce)
            .ok_or_else(|| anyhow!("no passkey request is waiting with that id"))?;

        if ceremony.state != State::AwaitingHuman {
            bail!("that passkey request has already been answered");
        }

        if !proof_ok {
            ceremony.attempts = ceremony.attempts.saturating_add(1);
            if ceremony.attempts >= MAX_PROOF_ATTEMPTS {
                ceremony.state = State::Refused {
                    reason: "too many wrong passphrases; the request was refused",
                };
                bail!("that is not the vault passphrase; the request was refused");
            }
            bail!("that is not the vault passphrase");
        }

        let chosen = match credential_id {
            Some(id) => ceremony
                .choices
                .iter()
                .find(|c| c.credential_id == id)
                .ok_or_else(|| {
                    anyhow!(
                        "that credential was not one of the choices this request \
                         was registered with"
                    )
                })?
                .credential_id
                .clone(),
            // Unnamed approval is only unambiguous when there is one choice.
            None => match ceremony.choices.as_slice() {
                [only] => only.credential_id.clone(),
                [] => Vec::new(),
                _ => bail!("this request has several credentials; the approval must name one"),
            },
        };

        ceremony.state = State::Approved {
            credential_id: chosen,
        };
        Ok(())
    }

    /// Refuse a ceremony.
    pub fn refuse(&mut self, nonce: &str, reason: &'static str, now: DateTime<Utc>) -> Result<()> {
        self.set_state(nonce, State::Refused { reason }, now)
    }

    /// Stand aside so the browser's own path can run.
    ///
    /// Costs no passphrase, and must not: saying "not with this authenticator"
    /// on someone's behalf denies them nothing they had. The worst a hostile
    /// caller achieves is making a login take a second attempt, which is the
    /// same thing `refuse` already allows.
    pub fn defer(&mut self, nonce: &str, now: DateTime<Utc>) -> Result<()> {
        self.set_state(nonce, State::Deferred, now)
    }

    fn set_state(&mut self, nonce: &str, state: State, now: DateTime<Utc>) -> Result<()> {
        self.expire(now);
        let ceremony = self
            .pending
            .iter_mut()
            .find(|c| c.nonce == nonce)
            .ok_or_else(|| anyhow!("no passkey request is waiting with that id"))?;
        ceremony.state = state;
        Ok(())
    }

    /// Take a ceremony whose answer is in, removing it.
    ///
    /// Single use: the caller gets the frozen request and its verdict exactly
    /// once, so a completed approval cannot be replayed into a second signature.
    pub fn take_answered(
        &mut self,
        nonce: &str,
        collector: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<Ceremony> {
        self.expire(now);
        let idx = self.pending.iter().position(|c| {
            c.nonce == nonce
                && !matches!(c.state, State::AwaitingHuman)
                // A ceremony registered by an identified peer is collectable
                // only by that peer. One registered by a peer the agent could
                // not identify is collectable by anyone — refusing outright
                // would break the ceremony rather than protect it, and the
                // approval still cost a passphrase.
                && (c.owner.is_none() || c.owner.as_deref() == collector)
        })?;
        Some(self.pending.remove(idx))
    }

    /// Is this ceremony still waiting?
    pub fn is_waiting(&self, nonce: &str) -> bool {
        self.pending
            .iter()
            .any(|c| c.nonce == nonce && c.state == State::AwaitingHuman)
    }

    /// What the deck should show, oldest first.
    ///
    /// A pure read: it filters lapsed ceremonies out of the answer rather than
    /// marking them refused, so that publishing a status document never mutates
    /// the desk. Expiry proper happens on the paths that can act on it.
    pub fn summaries(&self, now: DateTime<Utc>) -> Vec<Summary> {
        self.pending
            .iter()
            .filter(|c| c.state == State::AwaitingHuman && !c.is_expired(now))
            .map(|c| c.summary())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Drop everything. Called when the vault locks: a ceremony outliving the
    /// session it was authorized in would let a lock be stepped over.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Mark anything past its deadline refused, and drop what has been answered
    /// and abandoned.
    fn expire(&mut self, now: DateTime<Utc>) {
        for c in &mut self.pending {
            if c.state == State::AwaitingHuman && c.is_expired(now) {
                c.state = State::Refused {
                    reason: "the request expired before it was answered",
                };
            }
        }
        // An answered ceremony nobody collected is dropped a full TTL past its
        // deadline, so a caller that dies mid-ceremony cannot wedge a slot.
        self.pending
            .retain(|c| now < c.expires_at() + Duration::seconds(CEREMONY_TTL_SECS));
    }
}

/// Hex for the byte strings that cross into JSON, so the deck and the
/// native-messaging host never have to agree on a base64 variant.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd-length hex"));
        }
        (0..text.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&text[i..i + 2], 16).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn choice(id: &[u8], label: &str) -> Choice {
        Choice {
            record_id: format!("record-{label}"),
            credential_id: id.to_vec(),
            label: label.into(),
        }
    }

    fn ceremony(nonce: &str, choices: Vec<Choice>) -> Ceremony {
        Ceremony {
            client_data_hash: None,
            nonce: nonce.into(),
            operation: Operation::Assert,
            origin: "https://bank.example".into(),
            rp_id: "bank.example".into(),
            rp_name: Some("Bank".into()),
            choices,
            challenge: "Y2hhbGxlbmdl".into(),
            cross_origin: false,
            user_handle: None,
            user_name: Some("ada".into()),
            user_display_name: None,
            algorithms: Vec::new(),
            want_prf: false,
            prf_first_salt: None,
            prf_second_salt: None,
            owner: None,
            requester: Some("brave".into()),
            registered_at: at(0),
            attempts: 0,
            state: State::AwaitingHuman,
        }
    }

    const N1: &str = "0123456789abcdef0123456789abcdef";
    const N2: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn an_approval_can_only_select_a_credential_the_request_was_registered_with() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();

        // The swap a hostile caller wants: approve the ceremony the human saw,
        // but sign with a credential it never mentioned.
        assert!(desk.approve(N1, Some(b"bbbb"), true, at(1)).is_err());
        assert!(desk.is_waiting(N1), "a refused swap must not answer it");

        desk.approve(N1, Some(b"aaaa"), true, at(1)).unwrap();
        let done = desk.take_answered(N1, None, at(1)).unwrap();
        assert_eq!(
            done.state,
            State::Approved {
                credential_id: b"aaaa".to_vec()
            }
        );
    }

    /// A human approves a login *for the thing that asked*. Another process
    /// must not be able to take the signature it was waiting for.
    #[test]
    fn only_the_peer_that_asked_can_collect_the_answer() {
        let mut desk = Desk::new();
        let mut c = ceremony(N1, vec![choice(b"aaaa", "ada")]);
        c.owner = Some("PeerId { pid: 42, started: 900 }".into());
        desk.register(c, at(0)).unwrap();
        desk.approve(N1, None, true, at(1)).unwrap();

        assert!(
            desk.take_answered(N1, Some("PeerId { pid: 99, started: 7 }"), at(1)).is_none(),
            "a different process must not receive it"
        );
        assert!(
            desk.take_answered(N1, None, at(1)).is_none(),
            "nor must an unidentified one"
        );
        assert!(
            desk.take_answered(N1, Some("PeerId { pid: 42, started: 900 }"), at(1)).is_some(),
            "the peer that asked still gets it"
        );
    }

    /// When the agent could not identify the registering peer, binding would
    /// break the ceremony rather than protect it.
    #[test]
    fn an_unidentified_ceremony_is_still_collectable() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();
        desk.approve(N1, None, true, at(1)).unwrap();
        assert!(desk.take_answered(N1, Some("anyone"), at(1)).is_some());
    }

    #[test]
    fn an_answer_is_delivered_exactly_once() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();
        desk.approve(N1, None, true, at(1)).unwrap();

        assert!(desk.take_answered(N1, None, at(1)).is_some());
        assert!(
            desk.take_answered(N1, None, at(1)).is_none(),
            "one approval must not yield two signatures"
        );
    }

    #[test]
    fn an_unanswered_ceremony_expires_rather_than_waiting_forever() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();

        assert!(desk.is_waiting(N1));

        // `summaries` is a pure read — publishing a status document must not
        // mutate the desk — so a lapsed ceremony is filtered out of what the
        // deck sees before anything has marked it refused.
        let after = at(CEREMONY_TTL_SECS + 1);
        assert!(desk.summaries(after).is_empty(), "expired ones leave the screen");

        // Expiry proper happens on a path that can act on it, and then it is
        // refused rather than answerable.
        let done = desk.take_answered(N1, None, after).unwrap();
        assert!(matches!(done.state, State::Refused { .. }));
        assert!(!desk.is_waiting(N1), "and it is gone from the desk");
    }

    #[test]
    fn approval_is_refused_after_the_deadline() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();
        // The human clicks approve a fraction after it lapsed.
        assert!(desk.approve(N1, None, true, at(CEREMONY_TTL_SECS + 1)).is_err());
    }

    #[test]
    fn an_ambiguous_approval_must_name_its_credential() {
        let mut desk = Desk::new();
        desk.register(
            ceremony(N1, vec![choice(b"aaaa", "ada"), choice(b"bbbb", "grace")]),
            at(0),
        )
        .unwrap();
        assert!(
            desk.approve(N1, None, true, at(1)).is_err(),
            "two accounts and no choice named is not consent to either"
        );
        desk.approve(N1, Some(b"bbbb"), true, at(1)).unwrap();
    }

    #[test]
    fn the_desk_will_not_grow_without_bound() {
        let mut desk = Desk::new();
        for i in 0..MAX_PENDING {
            let nonce = format!("{i:032}");
            desk.register(ceremony(&nonce, vec![choice(b"aaaa", "ada")]), at(0))
                .unwrap();
        }
        assert!(desk
            .register(ceremony(N2, vec![choice(b"aaaa", "ada")]), at(0))
            .is_err());

        // Once they lapse, the desk takes work again.
        let later = at(CEREMONY_TTL_SECS * 2 + 2);
        desk.register(ceremony(N2, vec![choice(b"aaaa", "ada")]), later)
            .unwrap();
    }

    #[test]
    fn a_weak_nonce_is_refused() {
        let mut desk = Desk::new();
        assert!(desk
            .register(ceremony("tooshort", vec![choice(b"aaaa", "ada")]), at(0))
            .is_err());
    }

    #[test]
    fn an_assert_with_no_matching_credential_never_reaches_a_human() {
        let mut desk = Desk::new();
        assert!(
            desk.register(ceremony(N1, vec![]), at(0)).is_err(),
            "there is nothing to approve, so do not ask"
        );
    }

    #[test]
    fn locking_the_vault_clears_everything_waiting() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();
        desk.approve(N1, None, true, at(1)).unwrap();
        desk.clear();
        assert!(desk.is_empty());
        assert!(
            desk.take_answered(N1, None, at(1)).is_none(),
            "an approval must not survive the lock it was given under"
        );
    }

    #[test]
    fn a_summary_carries_what_the_human_needs_and_no_client_data() {
        let mut desk = Desk::new();
        desk.register(ceremony(N1, vec![choice(b"aaaa", "ada")]), at(0))
            .unwrap();
        let s = &desk.summaries(at(1))[0];
        assert_eq!(s.origin, "https://bank.example");
        assert_eq!(s.rp_id, "bank.example");
        assert_eq!(s.account.as_deref(), Some("ada"));
        assert_eq!(s.expires_at, at(CEREMONY_TTL_SECS));

        // The published shape must not carry the bytes that get signed.
        let json = serde_json::to_string(s).unwrap();
        assert!(!json.contains("client_data"), "client data must not be published");
        assert!(json.contains("61616161"), "credential ids travel as hex");
    }

    #[test]
    fn a_nonce_that_was_never_registered_answers_nothing() {
        let mut desk = Desk::new();
        assert!(desk.approve(N1, None, true, at(0)).is_err());
        assert!(desk.refuse(N1, "no", at(0)).is_err());
        assert!(desk.take_answered(N1, None, at(0)).is_none());
    }
}
