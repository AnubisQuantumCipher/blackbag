//! The native-messaging host: a wire between the browser extension and the agent.
//!
//! Chromium launches this process for the extension and speaks Chrome's native
//! messaging framing over stdio — a 4-byte native-endian length prefix followed
//! by that many bytes of JSON, in both directions. This translates those
//! messages into agent requests and the replies back.
//!
//! # What this process is trusted with, and what it is not
//!
//! It is a **relay and nothing else**. It holds no key material, makes no
//! security decision, and its opinion about an origin is worth nothing: the
//! agent independently checks that the relying party is a registrable-domain
//! suffix of the origin, and a human is shown that origin before anything is
//! signed. If this process were replaced wholesale by a hostile one, the worst
//! it could do is what any other process in the session can already do — ask
//! the agent for a ceremony, and be refused by the human looking at the screen.
//!
//! That is the reason the consent prompt lives in the deck rather than here or
//! in the extension. The two components nearest the browser are the two most
//! exposed, so neither is allowed to be the thing that says yes.
//!
//! # Framing
//!
//! Chrome's own limit is 1 MB per message in each direction. A WebAuthn request
//! is a few hundred bytes; anything approaching a megabyte is a bug or an
//! attack, so the cap is enforced here rather than trusted to the peer.

use anyhow::{anyhow, bail, Context, Result};
use blackbag_core::session::{self, Request, Response};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Chrome's documented per-message ceiling, applied in both directions.
const MAX_MESSAGE: u32 = 1024 * 1024;

/// What the extension sends us.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Incoming {
    /// Liveness, and whether the vault is open — so the extension can tell the
    /// user to unlock rather than failing a ceremony for no visible reason.
    Status,
    /// Register a ceremony. Fields mirror `Request::PasskeyBegin`.
    Begin(Box<BeginArgs>),
    /// Poll for the answer.
    Collect { nonce: String },
    /// The browser gave up (timeout, or the page called abort).
    Cancel { nonce: String },
}

#[derive(Debug, Deserialize)]
struct BeginArgs {
    operation: String,
    origin: String,
    rp_id: String,
    #[serde(default)]
    rp_name: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<String>,
    client_data_json: String,
    #[serde(default)]
    user_handle: Option<String>,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    user_display_name: Option<String>,
    #[serde(default)]
    want_prf: bool,
    #[serde(default)]
    prf_first_salt: Option<String>,
    #[serde(default)]
    prf_second_salt: Option<String>,
}

/// What we send back. Deliberately flat and boring: the extension turns this
/// straight into the JSON Chromium wants.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Outgoing {
    Status {
        unlocked: bool,
    },
    Registered {
        nonce: String,
    },
    /// Still waiting for the human.
    Waiting,
    Result {
        credential_id: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_object: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        public_key_der: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prf_first: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prf_second: Option<String>,
    },
    /// Everything that went wrong, including a refusal. The extension turns
    /// this into a DOMException, and the page cannot tell "you said no" from
    /// "there was no such credential" — which is the correct amount for a web
    /// page to learn about the contents of your vault.
    Error {
        message: String,
    },
}

/// Read one framed message. `Ok(None)` at end of input.
fn read_message(input: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("failed to read the message length"),
    }
    // Chrome writes the length in the platform's native byte order.
    let len = u32::from_ne_bytes(len);
    if len > MAX_MESSAGE {
        bail!("refusing a {len}-byte native message; the ceiling is {MAX_MESSAGE}");
    }
    let mut body = vec![0u8; len as usize];
    input
        .read_exact(&mut body)
        .context("the message ended before its declared length")?;
    Ok(Some(body))
}

fn write_message(output: &mut impl Write, value: &Outgoing) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() as u64 > MAX_MESSAGE as u64 {
        // Not reachable with the shapes above, but a reply that silently
        // exceeded the limit would wedge the port rather than fail loudly.
        bail!("reply of {} bytes exceeds the native messaging ceiling", body.len());
    }
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}

/// Translate one message and answer it.
fn handle(incoming: Incoming) -> Outgoing {
    match handle_inner(incoming) {
        Ok(out) => out,
        Err(e) => Outgoing::Error {
            message: e.to_string(),
        },
    }
}

fn handle_inner(incoming: Incoming) -> Result<Outgoing> {
    match incoming {
        Incoming::Status => match session::ask(&Request::Status)? {
            Response::Status(s) => Ok(Outgoing::Status {
                unlocked: s.unlocked,
            }),
            other => bail!("unexpected reply to status: {other:?}"),
        },

        Incoming::Begin(args) => {
            let operation = match args.operation.as_str() {
                "create" => blackbag_core::consent::Operation::Create,
                "assert" => blackbag_core::consent::Operation::Assert,
                other => bail!("unknown passkey operation {other:?}"),
            };
            let reply = session::ask(&Request::PasskeyBegin {
                operation,
                origin: args.origin,
                rp_id: args.rp_id,
                rp_name: args.rp_name,
                allow_credentials: args.allow_credentials,
                client_data_json: args.client_data_json,
                user_handle: args.user_handle,
                user_name: args.user_name,
                user_display_name: args.user_display_name,
                want_prf: args.want_prf,
                prf_first_salt: args.prf_first_salt,
                prf_second_salt: args.prf_second_salt,
            })?;
            match reply {
                Response::PasskeyRegistered { nonce, .. } => Ok(Outgoing::Registered { nonce }),
                Response::Error { message } => Ok(Outgoing::Error { message }),
                other => bail!("unexpected reply to begin: {other:?}"),
            }
        }

        Incoming::Collect { nonce } => match session::ask(&Request::PasskeyCollect { nonce })? {
            Response::PasskeyWaiting => Ok(Outgoing::Waiting),
            Response::PasskeyResult {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
                attestation_object,
                public_key_der,
                prf_first,
                prf_second,
            } => Ok(Outgoing::Result {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
                attestation_object,
                public_key_der,
                prf_first,
                prf_second,
            }),
            Response::Error { message } => Ok(Outgoing::Error { message }),
            other => bail!("unexpected reply to collect: {other:?}"),
        },

        Incoming::Cancel { nonce } => {
            // The browser has stopped waiting, so take the prompt off the
            // user's screen rather than leaving them to answer something that
            // can no longer be delivered.
            match session::ask(&Request::PasskeyRefuse { nonce })? {
                Response::Ok | Response::Error { .. } => Ok(Outgoing::Waiting),
                other => bail!("unexpected reply to cancel: {other:?}"),
            }
        }
    }
}

/// Serve until the browser closes the port.
pub fn serve() -> Result<()> {
    // Nothing secret passes through this process, but it is spawned by the
    // browser and inherits whatever the browser had; a core dump would still
    // capture a client data blob and an origin.
    let _ = blackbag_core::harden::harden_process();

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    while let Some(body) = read_message(&mut input)? {
        let reply = match serde_json::from_slice::<Incoming>(&body) {
            Ok(incoming) => handle(incoming),
            Err(e) => Outgoing::Error {
                message: format!("unintelligible message: {e}"),
            },
        };
        write_message(&mut output, &reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &str) -> Vec<u8> {
        let mut out = (body.len() as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(body.as_bytes());
        out
    }

    #[test]
    fn a_framed_message_round_trips() {
        let msg = framed(r#"{"type":"status"}"#);
        let mut cursor = std::io::Cursor::new(msg);
        let body = read_message(&mut cursor).unwrap().unwrap();
        let parsed: Incoming = serde_json::from_slice(&body).unwrap();
        assert!(matches!(parsed, Incoming::Status));
        assert!(read_message(&mut cursor).unwrap().is_none(), "then EOF");
    }

    /// A hostile peer declaring a huge message must be refused before the
    /// allocation, not after.
    #[test]
    fn an_oversized_message_is_refused_without_allocating_it() {
        let mut msg = (MAX_MESSAGE + 1).to_ne_bytes().to_vec();
        msg.extend_from_slice(b"{}");
        let mut cursor = std::io::Cursor::new(msg);
        let err = read_message(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("ceiling"), "{err}");
    }

    #[test]
    fn a_truncated_message_is_an_error_not_a_short_read() {
        let mut msg = 64u32.to_ne_bytes().to_vec();
        msg.extend_from_slice(b"only a few bytes");
        let mut cursor = std::io::Cursor::new(msg);
        assert!(read_message(&mut cursor).is_err());
    }

    #[test]
    fn a_reply_is_framed_with_its_own_length() {
        let mut out = Vec::new();
        write_message(
            &mut out,
            &Outgoing::Registered {
                nonce: "abcd".into(),
            },
        )
        .unwrap();
        let len = u32::from_ne_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(len, out.len() - 4);
        let value: serde_json::Value = serde_json::from_slice(&out[4..]).unwrap();
        assert_eq!(value["type"], "registered");
        assert_eq!(value["nonce"], "abcd");
    }

    #[test]
    fn nonsense_is_answered_with_an_error_rather_than_a_crash() {
        let reply = match serde_json::from_slice::<Incoming>(b"{\"type\":\"nope\"}") {
            Ok(i) => handle(i),
            Err(e) => Outgoing::Error {
                message: format!("unintelligible message: {e}"),
            },
        };
        assert!(matches!(reply, Outgoing::Error { .. }));
    }

    /// An error reply must not describe the vault's contents. A page that asks
    /// for a credential must not learn whether one exists.
    #[test]
    fn an_unknown_operation_is_refused_by_name_only() {
        let args = BeginArgs {
            operation: "exfiltrate".into(),
            origin: "https://evil.example".into(),
            rp_id: "evil.example".into(),
            rp_name: None,
            allow_credentials: vec![],
            client_data_json: "00".into(),
            user_handle: None,
            user_name: None,
            user_display_name: None,
            want_prf: false,
            prf_first_salt: None,
            prf_second_salt: None,
        };
        let reply = handle(Incoming::Begin(Box::new(args)));
        let Outgoing::Error { message } = reply else {
            panic!("an unknown operation must be an error")
        };
        assert!(message.contains("exfiltrate"), "{message}");
    }
}
