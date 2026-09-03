//! The CTAP2 commands, answered.
//!
//! This module decides *what* to say. It does not touch a vault, a device or a
//! socket: everything vault-shaped goes through [`Backend`], so the whole
//! command surface — including every refusal — is tested here without any of
//! them.
//!
//! ## The user-verification model
//!
//! A hardware key proves a person is present by being touched, and proves
//! *which* person with a PIN or a fingerprint. This authenticator has neither
//! a button nor a PIN, and does not pretend to: it reports `uv: true` with no
//! `clientPin` option, which CTAP 2.1 §6.4 calls a **built-in user
//! verification method**. The built-in method here is Black-Bag's own consent
//! screen and the master passphrase, which is stronger than a touch — a touch
//! proves somebody is at the desk, not that they meant this.
//!
//! `clientPin` is therefore not implemented, and says so rather than
//! pretending: an authenticator that answered PIN commands badly would be
//! worse than one that answers them not at all.

use super::cbor::{self, GetAssertion, MakeCredential, Request, status};
use ciborium::value::Value;

/// The AAGUID this authenticator reports.
///
/// Sixteen zero bytes, the same as lane A. It is the identifier a relying
/// party uses to say "this was made by a YubiKey 5", and saying nothing is the
/// honest answer for a credential that lives in a file: there is no hardware
/// model to name, and no attestation certificate that would let anyone check
/// the claim if we made one. It also keeps the two lanes one authenticator
/// rather than two.
pub const AAGUID: [u8; 16] = [0u8; 16];

/// What a `makeCredential` produced.
pub struct Made {
    pub auth_data: Vec<u8>,
    /// The attestation object's `fmt`. Always `"none"` here.
    pub fmt: String,
}

/// What a `getAssertion` produced.
pub struct Asserted {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// How many credentials matched, when more than one did. CTAP wants this
    /// only on the first response of a series.
    pub total: usize,
}

/// Everything the commands need that this module refuses to know how to do.
///
/// A trait rather than a concrete type so the command surface can be tested
/// against a backend that says yes, one that says no, and one that is not
/// there — which is most of what there is to get wrong.
pub trait Backend {
    /// Credentials this authenticator holds for a relying party, most recent
    /// first. Used to answer `excludeList` and to size an assertion.
    fn count_for(&mut self, rp_id: &str) -> usize;

    /// Whether any of these credential ids is one of ours for this relying
    /// party. `excludeList` exists to stop a second credential for an account
    /// that already has one.
    fn holds_any(&mut self, rp_id: &str, ids: &[Vec<u8>]) -> bool;

    /// Ask a human, mint a credential, and return its authenticator data.
    fn make_credential(&mut self, req: &MakeCredential) -> Result<Made, u8>;

    /// Ask a human and sign.
    fn get_assertion(&mut self, req: &GetAssertion) -> Result<Asserted, u8>;
}

/// Answer one CTAP2 request. Always returns a complete CTAPHID_CBOR payload.
pub fn dispatch(backend: &mut dyn Backend, request: &Request) -> Vec<u8> {
    let result = match request {
        Request::GetInfo => cbor::response(status::OK, Some(get_info())),
        Request::MakeCredential(req) => make_credential(backend, req),
        Request::GetAssertion(req) => get_assertion(backend, req),

        // Refusals, each for its own reason and each saying which.
        //
        // A "series" of assertions only exists after one that reported more
        // than one credential, and this authenticator never does: a person
        // chooses on Black-Bag's own screen, before anything is signed, so
        // exactly one credential comes back.
        Request::GetNextAssertion => Ok(vec![status::NOT_ALLOWED]),

        // There is no PIN and there is no pretending there is. §6.4's built-in
        // user verification is the consent screen and the master passphrase.
        Request::ClientPin => Ok(vec![status::PIN_NOT_SET]),

        // Resetting a hardware key wipes it. Here it would mean deleting the
        // contents of somebody's vault because a web page asked, and no
        // ceremony on this device is going to be allowed to do that.
        Request::Reset => Ok(vec![status::OPERATION_DENIED]),

        // `authenticatorSelection` asks for a touch to pick this device out of
        // several. Answering OK without asking anybody would be claiming a
        // user-presence test that did not happen.
        Request::Selection => Ok(vec![status::OPERATION_DENIED]),

        Request::Unknown(_) => Ok(vec![status::INVALID_COMMAND]),
    };
    result.unwrap_or_else(|_| vec![status::OTHER])
}

/// `authenticatorGetInfo`, §6.4.
pub fn get_info() -> Value {
    let text = |s: &str| Value::Text(s.into());
    cbor::map(vec![
        // NOT "U2F_V2". The INIT capabilities set NMSG, which says CTAPHID_MSG
        // is not implemented, and it is not — claiming the U2F version as well
        // would invite a client to try the one command we refuse. Two places
        // saying different things about the same capability is how a client
        // ends up with no working path at all.
        (0x01, Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")])),
        (0x02, Value::Array(vec![text("credProtect")])),
        (0x03, Value::Bytes(AAGUID.to_vec())),
        (
            0x04,
            Value::Map(vec![
                // Not a platform authenticator: it is presented over HID, and
                // a browser that believed otherwise would offer it in the
                // wrong place in its own picker.
                (text("plat"), Value::Bool(false)),
                // Discoverable credentials: the vault is a list of them.
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                // Built-in user verification: the consent screen and the
                // master passphrase. Reported as available AND configured,
                // because it always is — there is nothing to enrol.
                (text("uv"), Value::Bool(true)),
                // No PIN, and `clientPin` absent rather than false: false
                // means "supported, not set up", which would invite a client
                // to walk somebody through setting one.
                (text("makeCredUvNotRqd"), Value::Bool(false)),
            ]),
        ),
        (0x05, Value::Integer((super::hid::MAX_MESSAGE as i64).into())),
        // How many ids a client may put in one allow- or exclude-list.
        (0x06, Value::Integer(0.into())),
        (0x07, Value::Integer(16.into())),
        (0x08, Value::Integer(64.into())),
        (0x09, Value::Array(vec![text("usb")])),
        (
            0x0a,
            Value::Array(vec![Value::Map(vec![
                (text("alg"), Value::Integer((-7).into())),
                (text("type"), text("public-key")),
            ])]),
        ),
    ])
}

fn make_credential(backend: &mut dyn Backend, req: &MakeCredential) -> anyhow::Result<Vec<u8>> {
    // A PIN protocol we do not implement. Refused before anything else,
    // because a client that sent one is expecting a different authenticator
    // and every later answer would be read in that light.
    if req.pin_uv_auth_param.is_some() {
        return Ok(vec![status::PIN_NOT_SET]);
    }
    // ES256 or nothing. Saying so here rather than minting something the
    // client cannot use.
    if !req.algorithms.contains(&-7) {
        return Ok(vec![status::UNSUPPORTED_ALGORITHM]);
    }
    if req.options.uv == Some(false) {
        // A client asking explicitly for no user verification is asking for
        // something this authenticator cannot do: the passphrase is not
        // optional.
        return Ok(vec![status::INVALID_OPTION]);
    }
    // §6.1.2: excludeList exists so a relying party can stop a second
    // credential for an account that already has one. Checked BEFORE a human
    // is asked, so nobody is prompted for a ceremony that was going to be
    // refused anyway.
    if !req.exclude_list.is_empty() {
        let ids: Vec<Vec<u8>> = req.exclude_list.iter().map(|c| c.id.clone()).collect();
        if backend.holds_any(&req.rp.id, &ids) {
            return Ok(vec![status::CREDENTIAL_EXCLUDED]);
        }
    }

    match backend.make_credential(req) {
        Ok(made) => cbor::response(
            status::OK,
            Some(cbor::map(vec![
                (0x01, Value::Text(made.fmt)),
                (0x02, Value::Bytes(made.auth_data)),
                // `fmt: "none"` takes an empty statement. A self-signature
                // here would be attestation that attests to nothing.
                (0x03, Value::Map(Vec::new())),
            ])),
        ),
        Err(code) => Ok(vec![code]),
    }
}

fn get_assertion(backend: &mut dyn Backend, req: &GetAssertion) -> anyhow::Result<Vec<u8>> {
    if req.pin_uv_auth_param.is_some() {
        return Ok(vec![status::PIN_NOT_SET]);
    }
    if req.options.uv == Some(false) {
        return Ok(vec![status::INVALID_OPTION]);
    }
    // Nothing to offer. Answered before a human is asked: prompting for a
    // relying party we hold nothing for would tell whoever asked that the
    // vault is open, and tell the person nothing they can act on.
    if backend.count_for(&req.rp_id) == 0 {
        return Ok(vec![status::NO_CREDENTIALS]);
    }

    match backend.get_assertion(req) {
        Ok(a) => {
            let mut entries = vec![
                (
                    0x01,
                    Value::Map(vec![
                        (Value::Text("id".into()), Value::Bytes(a.credential_id)),
                        (Value::Text("type".into()), Value::Text("public-key".into())),
                    ]),
                ),
                (0x02, Value::Bytes(a.auth_data)),
                (0x03, Value::Bytes(a.signature)),
                (
                    0x04,
                    Value::Map(vec![(
                        Value::Text("id".into()),
                        Value::Bytes(a.user_handle),
                    )]),
                ),
            ];
            // §6.2.2: numberOfCredentials is only sent when there was a
            // choice. We always answer with one, because the choice was made
            // on Black-Bag's screen — so this is 1 or absent, never a count
            // the client is invited to page through.
            if a.total > 1 {
                entries.push((0x05, Value::Integer(1.into())));
            }
            cbor::response(status::OK, Some(cbor::map(entries)))
        }
        Err(code) => Ok(vec![code]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap::cbor::{CredentialDescriptor, Options, RelyingParty, User};

    #[derive(Default)]
    struct Fake {
        held: usize,
        excluded: bool,
        made: Option<Made>,
        asserted: Option<Asserted>,
        refuse_with: Option<u8>,
        asked: usize,
    }

    impl Backend for Fake {
        fn count_for(&mut self, _rp: &str) -> usize {
            self.held
        }
        fn holds_any(&mut self, _rp: &str, _ids: &[Vec<u8>]) -> bool {
            self.excluded
        }
        fn make_credential(&mut self, _req: &MakeCredential) -> Result<Made, u8> {
            self.asked += 1;
            if let Some(code) = self.refuse_with {
                return Err(code);
            }
            Ok(self.made.take().unwrap_or(Made {
                auth_data: vec![0xaa; 37],
                fmt: "none".into(),
            }))
        }
        fn get_assertion(&mut self, _req: &GetAssertion) -> Result<Asserted, u8> {
            self.asked += 1;
            if let Some(code) = self.refuse_with {
                return Err(code);
            }
            Ok(self.asserted.take().unwrap_or(Asserted {
                credential_id: vec![1, 2, 3],
                auth_data: vec![0xbb; 37],
                signature: vec![0xcc; 70],
                user_handle: b"ada".to_vec(),
                total: 1,
            }))
        }
    }

    fn a_make(algorithms: Vec<i64>) -> Request {
        Request::MakeCredential(Box::new(MakeCredential {
            client_data_hash: vec![0x11; 32],
            rp: RelyingParty {
                id: "example.com".into(),
                name: None,
            },
            user: User {
                id: b"ada".to_vec(),
                name: None,
                display_name: None,
            },
            algorithms,
            exclude_list: Vec::new(),
            options: Options::default(),
            hmac_secret: false,
            pin_uv_auth_param: None,
        }))
    }

    fn an_assert() -> Request {
        Request::GetAssertion(Box::new(GetAssertion {
            rp_id: "example.com".into(),
            client_data_hash: vec![0x22; 32],
            allow_list: Vec::new(),
            options: Options::default(),
            pin_uv_auth_param: None,
        }))
    }

    fn body(bytes: &[u8]) -> Value {
        ciborium::de::from_reader(&bytes[1..]).expect("a CBOR body")
    }

    fn field(v: &Value, key: i128) -> Option<&Value> {
        let Value::Map(m) = v else { return None };
        m.iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
            .map(|(_, v)| v)
    }

    #[test]
    fn get_info_describes_an_authenticator_with_no_pin_and_built_in_verification() {
        let info = get_info();
        let Some(Value::Map(options)) = field(&info, 0x04) else {
            panic!("no options")
        };
        let flag = |name: &str| {
            options
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
                .map(|(_, v)| matches!(v, Value::Bool(true)))
        };
        assert_eq!(flag("uv"), Some(true), "built-in user verification");
        assert_eq!(flag("rk"), Some(true), "discoverable credentials");
        assert_eq!(flag("plat"), Some(false), "presented over HID, not platform");
        assert!(
            !options
                .iter()
                .any(|(k, _)| matches!(k, Value::Text(t) if t == "clientPin")),
            "clientPin must be ABSENT, not false: false invites a client to set one up"
        );
        assert!(
            field(&info, 0x06).is_none() || matches!(field(&info, 0x06), Some(Value::Integer(_))),
            "no pinUvAuthProtocols are advertised"
        );
        let Some(Value::Bytes(aaguid)) = field(&info, 0x03) else {
            panic!("no aaguid")
        };
        assert_eq!(aaguid.len(), 16);
        assert_eq!(aaguid, &vec![0u8; 16], "no hardware model to claim");
    }

    /// getInfo and the INIT capabilities must agree about U2F.
    ///
    /// They did not, first time: the version list claimed `U2F_V2` while the
    /// NMSG capability bit said CTAPHID_MSG is not implemented — which it is
    /// not. A client that believed the version list would try the one command
    /// that is refused.
    #[test]
    fn the_version_list_does_not_claim_a_protocol_we_refuse() {
        let info = get_info();
        let Some(Value::Array(versions)) = field(&info, 0x01) else {
            panic!("no versions")
        };
        assert!(
            !versions.iter().any(|v| matches!(v, Value::Text(t) if t.starts_with("U2F"))),
            "NMSG is set, so U2F must not be advertised: {versions:?}"
        );
        assert!(versions.iter().any(|v| matches!(v, Value::Text(t) if t == "FIDO_2_0")));
        assert!(versions.iter().any(|v| matches!(v, Value::Text(t) if t == "FIDO_2_1")));
    }

    #[test]
    fn a_credential_is_made_and_comes_back_as_fmt_none() {
        let mut f = Fake::default();
        let out = dispatch(&mut f, &a_make(vec![-7]));
        assert_eq!(out[0], status::OK);
        let b = body(&out);
        assert_eq!(field(&b, 0x01), Some(&Value::Text("none".into())));
        assert!(matches!(field(&b, 0x02), Some(Value::Bytes(_))));
        assert_eq!(
            field(&b, 0x03),
            Some(&Value::Map(Vec::new())),
            "fmt none takes an empty attestation statement"
        );
    }

    #[test]
    fn an_algorithm_we_cannot_mint_is_refused_rather_than_substituted() {
        let mut f = Fake::default();
        let out = dispatch(&mut f, &a_make(vec![-8, -257]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], status::UNSUPPORTED_ALGORITHM);
        assert_eq!(f.asked, 0, "and nobody was prompted for it");
    }

    /// The exclude list is what stops a second credential for an account that
    /// already has one. Checked before a human is asked, so nobody is prompted
    /// for a ceremony that was going to be refused.
    #[test]
    fn an_excluded_credential_is_refused_without_asking_anyone() {
        let mut f = Fake {
            excluded: true,
            ..Default::default()
        };
        let Request::MakeCredential(mut req) = a_make(vec![-7]) else {
            unreachable!()
        };
        req.exclude_list = vec![CredentialDescriptor {
            id: vec![9, 9, 9],
            kind: "public-key".into(),
        }];
        let out = dispatch(&mut f, &Request::MakeCredential(req));
        assert_eq!(out, vec![status::CREDENTIAL_EXCLUDED]);
        assert_eq!(f.asked, 0);
    }

    #[test]
    fn a_relying_party_we_hold_nothing_for_is_answered_without_a_prompt() {
        let mut f = Fake::default();
        let out = dispatch(&mut f, &an_assert());
        assert_eq!(out, vec![status::NO_CREDENTIALS]);
        assert_eq!(
            f.asked, 0,
            "prompting would tell the caller the vault is open and tell the person nothing"
        );
    }

    #[test]
    fn an_assertion_carries_the_credential_the_signature_and_the_user() {
        let mut f = Fake {
            held: 1,
            ..Default::default()
        };
        let out = dispatch(&mut f, &an_assert());
        assert_eq!(out[0], status::OK);
        let b = body(&out);
        assert!(matches!(field(&b, 0x01), Some(Value::Map(_))));
        assert!(matches!(field(&b, 0x02), Some(Value::Bytes(_))));
        assert!(matches!(field(&b, 0x03), Some(Value::Bytes(_))));
        assert!(matches!(field(&b, 0x04), Some(Value::Map(_))));
        assert!(
            field(&b, 0x05).is_none(),
            "one credential means no numberOfCredentials"
        );
    }

    /// Even when several matched, exactly one comes back: the choice was made
    /// on Black-Bag's own screen, so there is no series for a client to page
    /// through — and `getNextAssertion` says so.
    #[test]
    fn several_matches_still_yield_one_assertion_and_no_series() {
        let mut f = Fake {
            held: 3,
            asserted: Some(Asserted {
                credential_id: vec![1],
                auth_data: vec![0; 37],
                signature: vec![0; 70],
                user_handle: b"a".to_vec(),
                total: 3,
            }),
            ..Default::default()
        };
        let out = dispatch(&mut f, &an_assert());
        let b = body(&out);
        assert_eq!(
            field(&b, 0x05),
            Some(&Value::Integer(1.into())),
            "one is offered, however many matched"
        );
        assert_eq!(
            dispatch(&mut f, &Request::GetNextAssertion),
            vec![status::NOT_ALLOWED]
        );
    }

    #[test]
    fn a_refusal_from_the_backend_is_passed_through_verbatim() {
        for code in [
            status::OPERATION_DENIED,
            status::USER_ACTION_TIMEOUT,
            status::NO_CREDENTIALS,
        ] {
            let mut f = Fake {
                held: 1,
                refuse_with: Some(code),
                ..Default::default()
            };
            assert_eq!(dispatch(&mut f, &a_make(vec![-7])), vec![code]);
            assert_eq!(dispatch(&mut f, &an_assert()), vec![code]);
        }
    }

    /// Each of these is refused for its own reason, and none of them is
    /// answered by accident.
    #[test]
    fn the_commands_this_authenticator_does_not_implement_say_so() {
        let mut f = Fake::default();
        assert_eq!(
            dispatch(&mut f, &Request::ClientPin),
            vec![status::PIN_NOT_SET],
            "there is no PIN, and pretending there is would be worse"
        );
        assert_eq!(
            dispatch(&mut f, &Request::Reset),
            vec![status::OPERATION_DENIED],
            "reset would empty somebody's vault because a page asked"
        );
        assert_eq!(
            dispatch(&mut f, &Request::Selection),
            vec![status::OPERATION_DENIED],
            "answering would claim a user-presence test that did not happen"
        );
        assert_eq!(
            dispatch(&mut f, &Request::Unknown(0x99)),
            vec![status::INVALID_COMMAND]
        );
        assert_eq!(f.asked, 0);
    }

    /// A client that came with a PIN protocol is expecting a different
    /// authenticator, and is told before anything else happens.
    #[test]
    fn a_pin_protocol_is_refused_before_anything_else() {
        let mut f = Fake {
            held: 1,
            ..Default::default()
        };
        let Request::MakeCredential(mut make) = a_make(vec![-7]) else {
            unreachable!()
        };
        make.pin_uv_auth_param = Some(vec![1; 16]);
        assert_eq!(
            dispatch(&mut f, &Request::MakeCredential(make)),
            vec![status::PIN_NOT_SET]
        );

        let Request::GetAssertion(mut get) = an_assert() else {
            unreachable!()
        };
        get.pin_uv_auth_param = Some(vec![1; 16]);
        assert_eq!(
            dispatch(&mut f, &Request::GetAssertion(get)),
            vec![status::PIN_NOT_SET]
        );
        assert_eq!(f.asked, 0);
    }

    /// `uv: false` asks for a ceremony without user verification. There is no
    /// such ceremony here — the passphrase is not optional — so it is refused
    /// rather than quietly upgraded.
    #[test]
    fn a_request_for_no_user_verification_is_refused_not_upgraded() {
        let mut f = Fake {
            held: 1,
            ..Default::default()
        };
        let Request::MakeCredential(mut make) = a_make(vec![-7]) else {
            unreachable!()
        };
        make.options.uv = Some(false);
        assert_eq!(
            dispatch(&mut f, &Request::MakeCredential(make)),
            vec![status::INVALID_OPTION]
        );

        let Request::GetAssertion(mut get) = an_assert() else {
            unreachable!()
        };
        get.options.uv = Some(false);
        assert_eq!(
            dispatch(&mut f, &Request::GetAssertion(get)),
            vec![status::INVALID_OPTION]
        );
        assert_eq!(f.asked, 0);
    }
}
