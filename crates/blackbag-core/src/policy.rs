//! Who may read which secret, and what it costs to say yes.
//!
//! # The problem this exists for
//!
//! Until now, an unlocked vault answered every `Reveal` on the socket. The
//! socket checks `SO_PEERCRED` and requires the same uid — which is correct,
//! and is not a boundary, because everything in the session runs as that uid.
//! On a machine that runs coding agents all day, that means any of them could
//! read any secret for as long as the vault stayed open, silently.
//!
//! # What an approval is
//!
//! **The master passphrase, not a click.** A same-uid process can synthesise a
//! click with `wtype` or `hyprctl`, so a click proves nothing about who is at
//! the keyboard. It is the same reasoning as the passkey consent screen, and
//! the same proof.
//!
//! An approval is remembered for one **(client, item, capability)** triple
//! until the vault locks or it is revoked. First use costs the passphrase;
//! after that the same program reading the same item is allowed, and every use
//! is still recorded in the audit log.
//!
//! # What client identity is worth
//!
//! `SO_PEERCRED` gives a pid; `/proc/<pid>/exe` gives a program name. Both are
//! **context, not control**. A hostile process running as you can be named
//! anything, and — for the browser specifically — a headless Chromium loading
//! an unpacked copy of our extension, carrying our public key, is
//! indistinguishable from the real one.
//!
//! So per-program identity is used for two things only: telling a person what
//! is asking, and remembering an answer they already gave. It is never used to
//! *grant* anything that a passphrase did not.
//!
//! The real boundary is a different uid, or a sandbox with no path to the
//! socket. `SECURITY.md` says so plainly rather than implying this module is
//! more than it is.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// What a caller wants to do with an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read a secret field's value.
    Reveal,
    /// Put a secret on the clipboard. Distinct from `Reveal` because the
    /// clipboard is readable by everything else in the session.
    Copy,
    /// Use an SSH key to sign.
    SshSign,
    /// Serve an item through the freedesktop Secret Service.
    SecretService,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Reveal => "reveal",
            Capability::Copy => "copy",
            Capability::SshSign => "ssh-sign",
            Capability::SecretService => "secret-service",
        }
    }
}

/// How a caller is remembered between requests.
///
/// The program's name, not its pid: a pid changes on every invocation, and an
/// approval that had to be re-granted for each new process would train the
/// owner to type their passphrase without reading the prompt — which is worse
/// than not asking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientKey(String);

impl ClientKey {
    pub fn of(program: Option<&str>) -> Self {
        Self(program.unwrap_or("unidentified").to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One remembered "yes".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Grant {
    pub client: ClientKey,
    pub item: String,
    pub capability: Capability,
}

/// What the agent decided to do about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An approval is already in force. Proceed, and record it.
    Remembered,
    /// Nobody has approved this. Ask, with the passphrase.
    MustAsk,
    /// Refused without asking, because the owner turned agents off.
    Blocked(&'static str),
}

/// The approval state for one unlocked session.
///
/// Deliberately not persisted. An approval is scoped to the session it was
/// granted in, so locking the vault — by hand, by idle, by suspend — forgets
/// every one of them. A grant that outlived the session it was given under
/// would quietly widen every lock into a pause.
#[derive(Debug, Default)]
pub struct Approvals {
    granted: HashSet<Grant>,
    /// The blanket refusal. When set, nothing is asked and nothing is served,
    /// except to clients on the always-allowed list.
    lockdown: bool,
    /// Programs allowed to skip the prompt entirely, by the owner's choice.
    ///
    /// Only ever the interactive browser, and only because a person who must
    /// type a passphrase for every form fill will turn the whole thing off.
    /// This is the one place per-program identity grants something, and it is
    /// the one place `SECURITY.md` warns about by name.
    trusted: HashSet<ClientKey>,
}

impl Approvals {
    pub fn new() -> Self {
        Self::default()
    }

    /// What should happen to this request.
    pub fn consider(&self, client: &ClientKey, item: &str, capability: Capability) -> Verdict {
        if self.trusted.contains(client) {
            return Verdict::Remembered;
        }
        if self.lockdown {
            return Verdict::Blocked("every program is currently denied; lockdown is on");
        }
        let grant = Grant {
            client: client.clone(),
            item: item.to_string(),
            capability,
        };
        if self.granted.contains(&grant) {
            Verdict::Remembered
        } else {
            Verdict::MustAsk
        }
    }

    /// Remember a "yes". The caller has already checked the passphrase.
    pub fn grant(&mut self, client: &ClientKey, item: &str, capability: Capability) {
        self.granted.insert(Grant {
            client: client.clone(),
            item: item.to_string(),
            capability,
        });
    }

    /// Withdraw one approval.
    pub fn revoke(&mut self, client: &ClientKey, item: &str, capability: Capability) -> bool {
        self.granted.remove(&Grant {
            client: client.clone(),
            item: item.to_string(),
            capability,
        })
    }

    /// Withdraw everything for one program.
    pub fn revoke_client(&mut self, client: &ClientKey) -> usize {
        let before = self.granted.len();
        self.granted.retain(|g| &g.client != client);
        self.trusted.remove(client);
        before - self.granted.len()
    }

    /// Deny every program until told otherwise.
    ///
    /// Trusted programs are cleared too: "deny all" that quietly kept an
    /// exception would be a switch that lies about what it did.
    pub fn set_lockdown(&mut self, on: bool) {
        self.lockdown = on;
        if on {
            self.trusted.clear();
        }
    }

    pub fn is_locked_down(&self) -> bool {
        self.lockdown
    }

    /// Let one program through without a prompt, from now until lock.
    pub fn trust(&mut self, client: &ClientKey) {
        if !self.lockdown {
            self.trusted.insert(client.clone());
        }
    }

    pub fn is_trusted(&self, client: &ClientKey) -> bool {
        self.trusted.contains(client)
    }

    /// Everything currently remembered, for the deck to show and revoke.
    pub fn granted(&self) -> impl Iterator<Item = &Grant> {
        self.granted.iter()
    }

    pub fn len(&self) -> usize {
        self.granted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.granted.is_empty()
    }

    /// Forget everything. Called when the vault locks.
    pub fn clear(&mut self) {
        self.granted.clear();
        self.trusted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(name: &str) -> ClientKey {
        ClientKey::of(Some(name))
    }

    #[test]
    fn the_first_request_asks_and_the_second_does_not() {
        let mut a = Approvals::new();
        let brave = client("brave");

        assert_eq!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
        a.grant(&brave, "rec-1", Capability::Reveal);
        assert_eq!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::Remembered
        );
    }

    /// An approval is for one program, one item, one capability. Any other
    /// combination is a different question and gets asked again.
    #[test]
    fn an_approval_does_not_spread() {
        let mut a = Approvals::new();
        a.grant(&client("brave"), "rec-1", Capability::Reveal);

        for (who, item, cap) in [
            ("curl", "rec-1", Capability::Reveal),
            ("brave", "rec-2", Capability::Reveal),
            ("brave", "rec-1", Capability::Copy),
            ("brave", "rec-1", Capability::SshSign),
        ] {
            assert_eq!(
                a.consider(&client(who), item, cap),
                Verdict::MustAsk,
                "{who}/{item}/{} must be asked separately",
                cap.as_str()
            );
        }
    }

    #[test]
    fn a_program_that_could_not_be_identified_is_its_own_client() {
        let mut a = Approvals::new();
        let unknown = ClientKey::of(None);
        a.grant(&unknown, "rec-1", Capability::Reveal);
        assert_eq!(
            a.consider(&unknown, "rec-1", Capability::Reveal),
            Verdict::Remembered
        );
        // And approving one unidentified caller does not approve a named one.
        assert_eq!(
            a.consider(&client("brave"), "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
    }

    #[test]
    fn revoking_takes_it_back() {
        let mut a = Approvals::new();
        let brave = client("brave");
        a.grant(&brave, "rec-1", Capability::Reveal);
        assert!(a.revoke(&brave, "rec-1", Capability::Reveal));
        assert_eq!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
        assert!(!a.revoke(&brave, "rec-1", Capability::Reveal), "and only once");
    }

    #[test]
    fn revoking_a_client_takes_back_everything_it_had() {
        let mut a = Approvals::new();
        let agent = client("some-agent");
        a.grant(&agent, "rec-1", Capability::Reveal);
        a.grant(&agent, "rec-2", Capability::Reveal);
        a.grant(&client("brave"), "rec-1", Capability::Reveal);

        assert_eq!(a.revoke_client(&agent), 2);
        assert_eq!(
            a.consider(&agent, "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
        assert_eq!(
            a.consider(&client("brave"), "rec-1", Capability::Reveal),
            Verdict::Remembered,
            "and leaves other clients alone"
        );
    }

    /// "Deny all" that kept a quiet exception would be a switch that lies.
    #[test]
    fn lockdown_denies_everything_including_trusted_programs() {
        let mut a = Approvals::new();
        let brave = client("brave");
        a.trust(&brave);
        a.grant(&brave, "rec-1", Capability::Reveal);
        assert_eq!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::Remembered
        );

        a.set_lockdown(true);
        assert!(matches!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::Blocked(_)
        ));
        assert!(!a.is_trusted(&brave), "trust is cleared, not merely bypassed");

        // And trusting during lockdown does nothing.
        a.trust(&brave);
        assert!(!a.is_trusted(&brave));
    }

    #[test]
    fn lifting_lockdown_does_not_restore_trust_by_itself() {
        let mut a = Approvals::new();
        let brave = client("brave");
        a.trust(&brave);
        a.set_lockdown(true);
        a.set_lockdown(false);
        assert!(!a.is_trusted(&brave));
        // Grants survive, because they were the owner's answers to specific
        // questions; blanket trust has to be given again deliberately.
        assert_eq!(
            a.consider(&brave, "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
    }

    /// Locking the vault must forget every answer, or a lock is only a pause.
    #[test]
    fn locking_forgets_everything() {
        let mut a = Approvals::new();
        a.trust(&client("brave"));
        a.grant(&client("brave"), "rec-1", Capability::Reveal);
        a.grant(&client("curl"), "rec-2", Capability::Copy);
        assert_eq!(a.len(), 2);

        a.clear();
        assert!(a.is_empty());
        assert!(!a.is_trusted(&client("brave")));
        assert_eq!(
            a.consider(&client("brave"), "rec-1", Capability::Reveal),
            Verdict::MustAsk
        );
    }

    #[test]
    fn what_is_remembered_can_be_listed() {
        let mut a = Approvals::new();
        a.grant(&client("brave"), "rec-1", Capability::Reveal);
        a.grant(&client("brave"), "rec-2", Capability::Copy);
        let mut seen: Vec<_> = a
            .granted()
            .map(|g| (g.client.as_str().to_string(), g.item.clone(), g.capability))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("brave".to_string(), "rec-1".to_string(), Capability::Reveal),
                ("brave".to_string(), "rec-2".to_string(), Capability::Copy),
            ]
        );
    }
}
