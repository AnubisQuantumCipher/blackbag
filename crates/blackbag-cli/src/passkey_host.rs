//! The native-messaging host: a wire between the browser extension and the agent.
//!
//! Chromium launches this process for the extension and speaks Chrome's native
//! messaging framing over stdio — a 4-byte native-endian length prefix followed
//! by that many bytes of JSON, in both directions. This translates those
//! messages into agent requests and the replies back.
//!
//! # What this process is trusted with, and what it is not
//!
//! It is a **relay and nothing else**. It holds no key material and makes no
//! security decision.
//!
//! Be precise about what that buys, because the obvious sentence is wrong. The
//! agent checks that the relying party is a registrable-domain suffix of the
//! origin it was handed. It does **not**, and cannot, check that the origin is
//! *real* — nothing downstream of the browser can. What stands behind the
//! origin is two other things: Chromium authored it (`sw.js` takes it from
//! `remoteDesktopClientOverride`, which a web page cannot forge), and a human
//! is shown it and must type the vault passphrase before anything is signed.
//!
//! So a hostile replacement of this process cannot sign anything by itself. It
//! can ask for a ceremony naming any origin it likes — and that is the string
//! the person reads on Black-Bag's own screen before approving.
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

use anyhow::{bail, Context, Result};
use blackbag_core::session::{self, Request, Response};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Chrome's documented per-message ceiling, applied in both directions.
const MAX_MESSAGE: u32 = 1024 * 1024;

/// What the extension sends us.
/// Unknown fields are refused, as on the agent socket and for a sharper
/// reason: the extension lives in the browser profile and updates on its own
/// schedule, so extension-versus-binary skew is the likeliest kind here.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Incoming {
    /// Liveness, and whether the vault is open — so the extension can tell the
    /// user to unlock rather than failing a ceremony for no visible reason.
    Status,
    /// Register a ceremony. Fields mirror `Request::PasskeyBegin`.
    Begin(Box<BeginArgs>),
    /// Wait for the answer, and reply once.
    ///
    /// The waiting happens HERE, in a process the browser keeps alive for the
    /// life of the port, rather than in the extension. An MV3 service worker is
    /// torn down when it looks idle, and a poll loop inside one is torn down
    /// with it — measured: the loop stopped after four polls, twenty-five
    /// seconds before the human answered, and the page waited forever for a
    /// ceremony that had already completed. One outstanding request also keeps
    /// the worker alive, which polling did not.
    Collect { nonce: String },
    /// The browser gave up (timeout, or the page called abort).
    Cancel { nonce: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginArgs {
    operation: String,
    origin: String,
    rp_id: String,
    #[serde(default)]
    rp_name: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<String>,
    challenge: String,
    #[serde(default)]
    cross_origin: bool,
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
        /// The exact bytes the agent hashed; Chromium gets these verbatim.
        client_data_json: String,
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
    /// The human asked for the browser's own path — a hardware key, or a
    /// phone.
    ///
    /// Its own reply rather than an `Error` with distinguishing prose, because
    /// the extension has to *act* on it: while it holds the proxy nothing in
    /// Chromium can reach a security key, so it must stand down for long
    /// enough to plug one in. A security decision taken by comparing error
    /// strings breaks the first time the wording is improved.
    UseSecurityKey,
    /// Everything that went wrong, including a refusal. The extension turns
    /// this into a DOMException, and the page cannot tell "you said no" from
    /// "there was no such credential" — which is the correct amount for a web
    /// page to learn about the contents of your vault.
    Error {
        message: String,
    },
}

/// Did this fail only because the other end went away?
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
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
fn handle(incoming: Incoming, output: &mut impl Write) -> Outgoing {
    match handle_inner(incoming, output) {
        Ok(out) => out,
        Err(e) => Outgoing::Error {
            message: e.to_string(),
        },
    }
}

fn handle_inner(incoming: Incoming, output: &mut impl Write) -> Result<Outgoing> {
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
                // The browser lane always has an origin.
                client_data_hash: None,
                origin: args.origin,
                rp_id: args.rp_id,
                rp_name: args.rp_name,
                allow_credentials: args.allow_credentials,
                challenge: args.challenge,
                cross_origin: args.cross_origin,
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

        Incoming::Collect { nonce } => collect_until_answered(&nonce, output),

        Incoming::Cancel { nonce } => {
            // The browser has stopped waiting, so take the prompt off the
            // user's screen rather than leaving them to answer something that
            // can no longer be delivered.
            match session::ask(&Request::PasskeyAnswer {
                nonce,
                approve: false,
                defer: false,
                credential_id: None,
                passphrase: Default::default(),
            })? {
                Response::Ok | Response::Error { .. } => Ok(Outgoing::Waiting),
                other => bail!("unexpected reply to cancel: {other:?}"),
            }
        }
    }
}

/// How long to wait for a human, and how often to ask the agent.
///
/// The agent expires a ceremony at 120 s and Chromium abandons the request at
/// 180 s, so waiting a little under the agent's own ceiling means a lapsed
/// ceremony is reported as an error rather than as silence.
const WAIT_CEILING: Duration = Duration::from_secs(118);
const WAIT_STEP: Duration = Duration::from_millis(350);

/// How often to say "still waiting" while a human decides.
///
/// Not for the human's benefit — for the browser's. Chromium tears down an MV3
/// service worker that has been idle for about thirty seconds, and a worker
/// waiting on a native reply looks idle. Measured: the extension went silent
/// mid-ceremony and the page waited forever for a signature the vault had
/// already produced. A message on the port is activity, so one every twenty
/// seconds keeps the worker alive for as long as the person is deciding.
const HEARTBEAT: Duration = Duration::from_secs(20);

/// Ask until there is an answer, sending a heartbeat while waiting.
fn collect_until_answered(nonce: &str, output: &mut impl Write) -> Result<Outgoing> {
    let started = Instant::now();
    let mut last_beat = Instant::now();
    loop {
        match session::ask(&Request::PasskeyCollect {
            nonce: nonce.to_string(),
        })? {
            Response::PasskeyWaiting => {}
            Response::PasskeyResult {
                client_data_json,
                credential_id,
                authenticator_data,
                signature,
                user_handle,
                attestation_object,
                public_key_der,
                prf_first,
                prf_second,
            } => {
                return Ok(Outgoing::Result {
                    client_data_json,
                    credential_id,
                    authenticator_data,
                    signature,
                    user_handle,
                    attestation_object,
                    public_key_der,
                    prf_first,
                    prf_second,
                })
            }
            Response::PasskeyUseSecurityKey => return Ok(Outgoing::UseSecurityKey),
            Response::Error { message } => return Ok(Outgoing::Error { message }),
            other => bail!("unexpected reply to collect: {other:?}"),
        }
        if started.elapsed() >= WAIT_CEILING {
            return Ok(Outgoing::Error {
                message: "Black-Bag was not answered in time".into(),
            });
        }
        if last_beat.elapsed() >= HEARTBEAT {
            write_message(output, &Outgoing::Waiting)?;
            last_beat = Instant::now();
        }
        std::thread::sleep(WAIT_STEP);
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
            Ok(incoming) => handle(incoming, &mut output),
            Err(e) => Outgoing::Error {
                message: format!("unintelligible message: {e}"),
            },
        };
        // The browser closing the port mid-write is how a native messaging host
        // ends: the page navigated away, the ceremony window closed, the
        // browser quit. It is not a failure, and reporting it as one puts
        // "black-bag: Broken pipe" in the browser's log every time somebody
        // closes a tab.
        match write_message(&mut output, &reply) {
            Ok(()) => {}
            Err(e) if is_broken_pipe(&e) => return Ok(()),
            Err(e) => return Err(e),
        }
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
            Ok(i) => handle(i, &mut Vec::new()),
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
            challenge: "Y2hhbGxlbmdl".into(),
            cross_origin: false,
            user_handle: None,
            user_name: None,
            user_display_name: None,
            want_prf: false,
            prf_first_salt: None,
            prf_second_salt: None,
        };
        let reply = handle(Incoming::Begin(Box::new(args)), &mut Vec::new());
        let Outgoing::Error { message } = reply else {
            panic!("an unknown operation must be an error")
        };
        assert!(message.contains("exfiltrate"), "{message}");
    }
}
