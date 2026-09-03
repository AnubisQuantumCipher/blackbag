//! The CTAP2 request and response encodings — CTAP 2.1 §6.
//!
//! CTAP2 speaks CBOR with integer keys. This module turns bytes into typed
//! requests and typed responses back into bytes, and does no vault work: the
//! whole of it can be exercised against captured wire bytes.
//!
//! ## The canonical-form rule, and why it is enforced on the way in
//!
//! §6 requires *canonical* CBOR both ways. Being strict about what arrives is
//! not pedantry: a map with a duplicate key has two readings, and an
//! authenticator that takes the last while a relying party takes the first is
//! a place to hide a different request inside the one somebody approved.

use anyhow::{Result, anyhow, bail};
use ciborium::value::Value;

/// CTAP2 command bytes, §6.
pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const SELECTION: u8 = 0x0b;
}

/// CTAP2 status codes, §6.3. Only the ones this authenticator can return.
pub mod status {
    pub const OK: u8 = 0x00;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const INVALID_OPTION: u8 = 0x2c;
    pub const KEEPALIVE_CANCEL: u8 = 0x2d;
    pub const NO_CREDENTIALS: u8 = 0x2e;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2f;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const UNSUPPORTED_OPTION: u8 = 0x2b;
    pub const OPERATION_PENDING: u8 = 0x02;
    pub const UNSUPPORTED_EXTENSION: u8 = 0x2b;
    pub const NOT_ALLOWED_UV: u8 = 0x2b;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const OTHER: u8 = 0x7f;
}

/// A relying party as CTAP describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    pub id: String,
    pub name: Option<String>,
}

/// A user handle and the names that go with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

/// One entry of an allow- or exclude-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    pub id: Vec<u8>,
    pub kind: String,
}

/// What the caller asked for in `options`. Absent is not the same as false —
/// §6.1 gives each a different default — so each stays an `Option`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub rk: Option<bool>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredential {
    pub client_data_hash: Vec<u8>,
    pub rp: RelyingParty,
    pub user: User,
    pub algorithms: Vec<i64>,
    pub exclude_list: Vec<CredentialDescriptor>,
    pub options: Options,
    /// True when the caller asked for a PRF/hmac-secret seed.
    pub hmac_secret: bool,
    /// Present when the caller used a PIN protocol, which this authenticator
    /// does not implement. Kept so the refusal can be specific.
    pub pin_uv_auth_param: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertion {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Vec<CredentialDescriptor>,
    pub options: Options,
    pub pin_uv_auth_param: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    MakeCredential(Box<MakeCredential>),
    GetAssertion(Box<GetAssertion>),
    GetInfo,
    GetNextAssertion,
    Selection,
    ClientPin,
    Reset,
    Unknown(u8),
}

/// Parse a CTAPHID_CBOR payload: one command byte, then the parameter map.
pub fn parse_request(payload: &[u8]) -> Result<Request> {
    let (&cmd, rest) = payload
        .split_first()
        .ok_or_else(|| anyhow!("an empty CBOR command"))?;
    match cmd {
        command::GET_INFO => Ok(Request::GetInfo),
        command::GET_NEXT_ASSERTION => Ok(Request::GetNextAssertion),
        command::SELECTION => Ok(Request::Selection),
        command::CLIENT_PIN => Ok(Request::ClientPin),
        command::RESET => Ok(Request::Reset),
        command::MAKE_CREDENTIAL => Ok(Request::MakeCredential(Box::new(
            parse_make_credential(rest)?,
        ))),
        command::GET_ASSERTION => Ok(Request::GetAssertion(Box::new(parse_get_assertion(rest)?))),
        other => Ok(Request::Unknown(other)),
    }
}

/// The parameter map, with integer keys, checked for duplicates.
fn map_of(bytes: &[u8]) -> Result<Vec<(i128, Value)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = ciborium::de::from_reader(bytes).map_err(|e| anyhow!("{e}"))?;
    let Value::Map(entries) = value else {
        bail!("CTAP2 parameters are a map");
    };
    let mut out: Vec<(i128, Value)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let key = match k {
            Value::Integer(i) => i128::from(i),
            _ => bail!("CTAP2 parameter keys are integers"),
        };
        if out.iter().any(|(seen, _)| *seen == key) {
            // Two readings of one request is one reading too many.
            bail!("a duplicate parameter key ({key})");
        }
        out.push((key, v));
    }
    Ok(out)
}

fn take(map: &[(i128, Value)], key: i128) -> Option<&Value> {
    map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

fn as_bytes(v: &Value, what: &str) -> Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => bail!("{what} must be a byte string"),
    }
}

fn as_text(v: &Value, what: &str) -> Result<String> {
    match v {
        Value::Text(t) => Ok(t.clone()),
        _ => bail!("{what} must be a text string"),
    }
}

fn text_field(map: &[(Value, Value)], name: &str) -> Option<String> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
        .and_then(|(_, v)| match v {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        })
}

fn as_map<'a>(v: &'a Value, what: &str) -> Result<&'a Vec<(Value, Value)>> {
    match v {
        Value::Map(m) => Ok(m),
        _ => bail!("{what} must be a map"),
    }
}

fn parse_options(v: Option<&Value>) -> Result<Options> {
    let Some(v) = v else {
        return Ok(Options::default());
    };
    let m = as_map(v, "options")?;
    let flag = |name: &str| -> Option<bool> {
        m.iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .and_then(|(_, v)| match v {
                Value::Bool(b) => Some(*b),
                _ => None,
            })
    };
    Ok(Options {
        rk: flag("rk"),
        up: flag("up"),
        uv: flag("uv"),
    })
}

fn parse_descriptor_list(v: Option<&Value>, what: &str) -> Result<Vec<CredentialDescriptor>> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let Value::Array(items) = v else {
        bail!("{what} must be an array");
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let m = as_map(item, what)?;
        let id = m
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "id"))
            .map(|(_, v)| as_bytes(v, "a credential id"))
            .transpose()?
            .ok_or_else(|| anyhow!("an entry of {what} has no id"))?;
        let kind = text_field(m, "type").unwrap_or_else(|| "public-key".into());
        out.push(CredentialDescriptor { id, kind });
    }
    Ok(out)
}

/// Whether the caller asked for `hmac-secret`, without pretending to serve it.
fn wants_hmac_secret(v: Option<&Value>) -> bool {
    let Some(Value::Map(m)) = v else { return false };
    m.iter().any(|(k, val)| {
        matches!(k, Value::Text(t) if t == "hmac-secret")
            && !matches!(val, Value::Bool(false) | Value::Null)
    })
}

fn parse_make_credential(bytes: &[u8]) -> Result<MakeCredential> {
    let map = map_of(bytes)?;
    let client_data_hash = as_bytes(
        take(&map, 1).ok_or_else(|| anyhow!("no clientDataHash"))?,
        "clientDataHash",
    )?;
    if client_data_hash.len() != 32 {
        bail!("clientDataHash is 32 bytes");
    }
    let rp_map = as_map(take(&map, 2).ok_or_else(|| anyhow!("no rp"))?, "rp")?;
    let rp = RelyingParty {
        id: text_field(rp_map, "id").ok_or_else(|| anyhow!("the relying party has no id"))?,
        name: text_field(rp_map, "name"),
    };
    let user_map = as_map(take(&map, 3).ok_or_else(|| anyhow!("no user"))?, "user")?;
    let user = User {
        id: user_map
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "id"))
            .map(|(_, v)| as_bytes(v, "the user handle"))
            .transpose()?
            .ok_or_else(|| anyhow!("the user has no id"))?,
        name: text_field(user_map, "name"),
        display_name: text_field(user_map, "displayName"),
    };
    let Some(Value::Array(params)) = take(&map, 4) else {
        bail!("no pubKeyCredParams");
    };
    let mut algorithms = Vec::new();
    for p in params {
        let m = as_map(p, "pubKeyCredParams")?;
        if let Some((_, Value::Integer(alg))) = m
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == "alg"))
        {
            algorithms.push(i128::from(*alg) as i64);
        }
    }

    Ok(MakeCredential {
        client_data_hash,
        rp,
        user,
        algorithms,
        exclude_list: parse_descriptor_list(take(&map, 5), "excludeList")?,
        hmac_secret: wants_hmac_secret(take(&map, 6)),
        options: parse_options(take(&map, 7))?,
        pin_uv_auth_param: take(&map, 8)
            .map(|v| as_bytes(v, "pinUvAuthParam"))
            .transpose()?,
    })
}

fn parse_get_assertion(bytes: &[u8]) -> Result<GetAssertion> {
    let map = map_of(bytes)?;
    let rp_id = as_text(take(&map, 1).ok_or_else(|| anyhow!("no rpId"))?, "rpId")?;
    let client_data_hash = as_bytes(
        take(&map, 2).ok_or_else(|| anyhow!("no clientDataHash"))?,
        "clientDataHash",
    )?;
    if client_data_hash.len() != 32 {
        bail!("clientDataHash is 32 bytes");
    }
    Ok(GetAssertion {
        rp_id,
        client_data_hash,
        allow_list: parse_descriptor_list(take(&map, 3), "allowList")?,
        options: parse_options(take(&map, 5))?,
        pin_uv_auth_param: take(&map, 6)
            .map(|v| as_bytes(v, "pinUvAuthParam"))
            .transpose()?,
    })
}

/// A response: one status byte, then the CBOR body when the status is OK.
pub fn response(status: u8, body: Option<Value>) -> Result<Vec<u8>> {
    let mut out = vec![status];
    if status == self::status::OK {
        if let Some(value) = body {
            ciborium::ser::into_writer(&value, &mut out).map_err(|e| anyhow!("{e}"))?;
        }
    }
    Ok(out)
}

/// Build a CBOR map from integer-keyed entries, in ascending key order.
///
/// §6 requires canonical CBOR, and canonical ordering for integer keys is
/// ascending. Sorting here rather than at every call site means a new field
/// cannot be added in the wrong place.
pub fn map(entries: Vec<(i128, Value)>) -> Value {
    let mut entries = entries;
    entries.sort_by_key(|(k, _)| *k);
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.try_into().expect("CTAP keys are small")), v))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn make_credential_bytes() -> Vec<u8> {
        let params = Value::Array(vec![Value::Map(vec![
            (text("alg"), Value::Integer((-7).into())),
            (text("type"), text("public-key")),
        ])]);
        let body = Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0x42; 32])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![
                    (text("id"), text("example.com")),
                    (text("name"), text("Example")),
                ]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![
                    (text("id"), Value::Bytes(b"user-handle".to_vec())),
                    (text("name"), text("ada")),
                    (text("displayName"), text("Ada Lovelace")),
                ]),
            ),
            (Value::Integer(4.into()), params),
            (
                Value::Integer(7.into()),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("uv"), Value::Bool(true)),
                ]),
            ),
        ]);
        let mut out = vec![command::MAKE_CREDENTIAL];
        out.extend(encode(&body));
        out
    }

    #[test]
    fn a_make_credential_request_parses_into_its_parts() {
        let Request::MakeCredential(req) = parse_request(&make_credential_bytes()).unwrap() else {
            panic!("wrong command");
        };
        assert_eq!(req.rp.id, "example.com");
        assert_eq!(req.rp.name.as_deref(), Some("Example"));
        assert_eq!(req.user.id, b"user-handle");
        assert_eq!(req.user.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(req.algorithms, vec![-7]);
        assert_eq!(req.client_data_hash.len(), 32);
        assert_eq!(req.options.rk, Some(true));
        assert_eq!(req.options.uv, Some(true));
        assert_eq!(req.options.up, None, "absent is not false");
        assert!(!req.hmac_secret);
        assert!(req.pin_uv_auth_param.is_none());
    }

    /// One request with two readings is one too many. An authenticator that
    /// took the last value while the caller meant the first would be a place
    /// to hide a different ceremony inside an approved one.
    #[test]
    fn a_duplicate_parameter_key_is_refused() {
        let body = Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0x11; 32])),
            (Value::Integer(1.into()), Value::Bytes(vec![0x22; 32])),
        ]);
        let mut bytes = vec![command::MAKE_CREDENTIAL];
        bytes.extend(encode(&body));
        let err = parse_request(&bytes).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn a_client_data_hash_of_the_wrong_length_is_refused() {
        for len in [0usize, 16, 31, 33, 64] {
            let body = Value::Map(vec![
                (Value::Integer(1.into()), Value::Bytes(vec![0; len])),
                (
                    Value::Integer(2.into()),
                    Value::Map(vec![(text("id"), text("example.com"))]),
                ),
                (
                    Value::Integer(3.into()),
                    Value::Map(vec![(text("id"), Value::Bytes(b"u".to_vec()))]),
                ),
                (Value::Integer(4.into()), Value::Array(vec![])),
            ]);
            let mut bytes = vec![command::MAKE_CREDENTIAL];
            bytes.extend(encode(&body));
            assert!(
                parse_request(&bytes).is_err(),
                "a {len}-byte clientDataHash must not be accepted"
            );
        }
    }

    #[test]
    fn a_get_assertion_request_parses_and_keeps_its_allow_list() {
        let body = Value::Map(vec![
            (Value::Integer(1.into()), text("example.com")),
            (Value::Integer(2.into()), Value::Bytes(vec![7; 32])),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(vec![1, 2, 3])),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ]);
        let mut bytes = vec![command::GET_ASSERTION];
        bytes.extend(encode(&body));

        let Request::GetAssertion(req) = parse_request(&bytes).unwrap() else {
            panic!("wrong command");
        };
        assert_eq!(req.rp_id, "example.com");
        assert_eq!(req.allow_list.len(), 1);
        assert_eq!(req.allow_list[0].id, vec![1, 2, 3]);
        assert_eq!(req.allow_list[0].kind, "public-key");
    }

    #[test]
    fn the_simple_commands_need_no_parameters() {
        assert_eq!(parse_request(&[command::GET_INFO]).unwrap(), Request::GetInfo);
        assert_eq!(
            parse_request(&[command::GET_NEXT_ASSERTION]).unwrap(),
            Request::GetNextAssertion
        );
        assert_eq!(parse_request(&[command::RESET]).unwrap(), Request::Reset);
        assert_eq!(
            parse_request(&[command::SELECTION]).unwrap(),
            Request::Selection
        );
    }

    #[test]
    fn an_unknown_command_is_reported_rather_than_guessed() {
        assert_eq!(parse_request(&[0xee]).unwrap(), Request::Unknown(0xee));
        assert!(parse_request(&[]).is_err());
    }

    #[test]
    fn a_pin_protocol_parameter_survives_so_the_refusal_can_be_specific() {
        let mut body = vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0x42; 32])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(text("id"), text("example.com"))]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(text("id"), Value::Bytes(b"u".to_vec()))]),
            ),
            (Value::Integer(4.into()), Value::Array(vec![])),
        ];
        body.push((Value::Integer(8.into()), Value::Bytes(vec![9; 16])));
        let mut bytes = vec![command::MAKE_CREDENTIAL];
        bytes.extend(encode(&Value::Map(body)));

        let Request::MakeCredential(req) = parse_request(&bytes).unwrap() else {
            panic!("wrong command");
        };
        assert_eq!(req.pin_uv_auth_param, Some(vec![9; 16]));
    }

    #[test]
    fn hmac_secret_is_noticed_rather_than_ignored() {
        let mut body = vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0x42; 32])),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(text("id"), text("example.com"))]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(text("id"), Value::Bytes(b"u".to_vec()))]),
            ),
            (Value::Integer(4.into()), Value::Array(vec![])),
        ];
        body.push((
            Value::Integer(6.into()),
            Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
        ));
        let mut bytes = vec![command::MAKE_CREDENTIAL];
        bytes.extend(encode(&Value::Map(body)));

        let Request::MakeCredential(req) = parse_request(&bytes).unwrap() else {
            panic!("wrong command");
        };
        assert!(req.hmac_secret, "asking for it must be visible to the caller");
    }

    #[test]
    fn a_response_is_a_status_byte_then_the_body() {
        let ok = response(status::OK, Some(map(vec![(1, text("hello"))]))).unwrap();
        assert_eq!(ok[0], 0);
        let parsed: Value = ciborium::de::from_reader(&ok[1..]).unwrap();
        assert_eq!(parsed, Value::Map(vec![(Value::Integer(1.into()), text("hello"))]));

        // An error carries a status and nothing else: a body after a non-zero
        // status is not something a client is required to read.
        let refused = response(status::OPERATION_DENIED, Some(text("why"))).unwrap();
        assert_eq!(refused, vec![status::OPERATION_DENIED]);
    }

    /// Canonical CBOR wants integer keys in ascending order, and a map built
    /// by hand drifts out of order the first time somebody adds a field.
    #[test]
    fn integer_keys_come_out_in_order_however_they_went_in() {
        let Value::Map(entries) = map(vec![
            (0x14, Value::Integer(1.into())),
            (0x01, Value::Integer(2.into())),
            (0x09, Value::Integer(3.into())),
        ]) else {
            panic!("not a map");
        };
        let keys: Vec<i128> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Integer(i) => i128::from(*i),
                _ => panic!("not an integer key"),
            })
            .collect();
        assert_eq!(keys, vec![0x01, 0x09, 0x14]);
    }

    #[test]
    fn malformed_cbor_is_an_error_not_a_panic() {
        for bytes in [
            vec![command::MAKE_CREDENTIAL, 0xff],
            vec![command::MAKE_CREDENTIAL, 0xa1, 0x01],
            vec![command::GET_ASSERTION, 0x00],
            vec![command::GET_ASSERTION, 0xa1, 0x61, 0x78, 0x01],
        ] {
            assert!(parse_request(&bytes).is_err(), "{bytes:?} must be refused");
        }
    }
}
