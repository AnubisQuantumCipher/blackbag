//! The SSH agent daemon.
//!
//! Binds `$SSH_AUTH_SOCK`, speaks the ssh-agent protocol, and answers every
//! request by asking the vault agent. It holds no keys itself — the vault does
//! — so this process is a thin, replaceable front end, exactly like the
//! browser's native host and the virtual FIDO2 key.
//!
//! When `ssh` asks for a signature the vault has not approved yet, the request
//! blocks here while the deck shows the approval and the user answers it. `ssh`
//! is waiting on the socket the whole time, so from its side the key simply
//! takes a moment — the same as touching a hardware key.

use anyhow::{Context, Result, anyhow, bail};
use blackbag_core::session::{self, Request as AgentRequest, Response};
use blackbag_core::ssh::agent::{Identity, Signer, respond};
use blackbag_core::ssh::wire::Writer;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long to wait for a human to approve a first-time signature before giving
/// up on that one request. `ssh` itself waits on the socket, so this only bounds
/// the wait; it does not shorten anyone's decision.
const APPROVAL_WAIT: Duration = Duration::from_secs(90);
/// How often to re-ask the vault while an approval is pending.
const POLL_EVERY: Duration = Duration::from_millis(250);
/// The largest agent message we will read. The protocol's own cap is 256 KiB.
const MAX_MESSAGE: usize = 256 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        bail!("expected hex");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| anyhow!("{e}")))
        .collect()
}

/// A [`Signer`] backed by the vault agent over its socket.
struct VaultSigner;

impl Signer for VaultSigner {
    fn identities(&mut self) -> Vec<Identity> {
        match session::ask(&AgentRequest::SshIdentities) {
            Ok(Response::SshIdentities { keys }) => keys
                .into_iter()
                .filter_map(|k| {
                    Some(Identity {
                        key_blob: unhex(&k.key_blob).ok()?,
                        comment: k.comment,
                    })
                })
                .collect(),
            // A locked or unreachable vault simply offers no keys, which is a
            // valid — empty — answer. ssh moves on to its own key files.
            _ => Vec::new(),
        }
    }

    fn sign(&mut self, key_blob: &[u8], data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        let started = Instant::now();
        let mut announced = false;
        #[allow(unused_assignments)]
        let mut pending_fingerprint: Option<String> = None;
        loop {
            match session::ask(&AgentRequest::SshSign {
                key_blob: hex(key_blob),
                data: hex(data),
            }) {
                Ok(Response::SshSignature { blob }) => return unhex(&blob).ok(),
                Ok(Response::ApprovalRequired { title, item, .. }) => {
                    pending_fingerprint = Some(item);
                    // First use of this key. The deck is showing the prompt;
                    // wait for the person to answer it while ssh waits on us.
                    if !announced {
                        let what = title.unwrap_or_else(|| "an SSH key".into());
                        eprintln!(
                            "black-bag: approve the use of {what} in Black-Bag \
                             (waiting up to {}s)",
                            APPROVAL_WAIT.as_secs()
                        );
                        announced = true;
                    }
                    if started.elapsed() >= APPROVAL_WAIT {
                        eprintln!("black-bag: not approved in time");
                        // Take the prompt off the deck: ssh has stopped waiting
                        // for this, so nobody should be asked to approve it.
                        if let Some(fp) = &pending_fingerprint {
                            let _ = session::ask(&AgentRequest::SshDismiss {
                                fingerprint: fp.clone(),
                            });
                        }
                        return None;
                    }
                    std::thread::sleep(POLL_EVERY);
                }
                // Refused, locked, no such key: all one answer to ssh, which is
                // FAILURE. Which one it was is a fact about the vault.
                Ok(Response::Error { message }) => {
                    eprintln!("black-bag: {message}");
                    return None;
                }
                Ok(other) => {
                    eprintln!("black-bag: unexpected reply to a sign request: {other:?}");
                    return None;
                }
                Err(e) => {
                    eprintln!("black-bag: {e}");
                    return None;
                }
            }
        }
    }
}

/// Read one length-prefixed agent message.
fn read_message(stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        // A clean hang-up between requests is normal, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_MESSAGE {
        bail!("an agent message of {n} bytes is out of range");
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn serve_connection(mut stream: UnixStream, signer: &mut VaultSigner) -> Result<()> {
    while let Some(request) = read_message(&mut stream)? {
        let response = respond(signer, &request);
        let mut w = Writer::new();
        for b in response {
            w.u8(b);
        }
        stream.write_all(&w.into_frame())?;
        stream.flush()?;
    }
    Ok(())
}

/// Where the socket goes. Honours `$SSH_AUTH_SOCK` if the caller pre-set one,
/// otherwise a private path under the runtime directory.
fn socket_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let dir = blackbag_core::status::runtime_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("ssh-agent.sock"))
}

/// Bind the socket and serve until stopped.
pub fn serve(explicit: Option<PathBuf>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = socket_path(explicit)?;
    // A stale socket from a previous run would block the bind. Removing it is
    // safe: if another agent is live on it, the connect test below would have
    // to succeed, and we only remove after it fails.
    if path.exists() && UnixStream::connect(&path).is_err() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("failed to bind {}", path.display()))?;
    // Owner-only: the socket is a signing oracle for anyone who can reach it,
    // and same-user is the boundary the whole agent already draws.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    eprintln!("black-bag: ssh-agent listening at {}", path.display());
    eprintln!("black-bag: export SSH_AUTH_SOCK={}", path.display());

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let mut signer = VaultSigner;
                if let Err(e) = serve_connection(stream, &mut signer) {
                    // One client's error is not the agent's; keep serving.
                    eprintln!("black-bag: ssh connection ended: {e}");
                }
            }
            Err(e) => eprintln!("black-bag: accept failed: {e}"),
        }
    }
    Ok(())
}

/// `black-bag ssh generate` — mint a key and print its public line.
pub fn generate(comment: &str) -> Result<()> {
    match session::ask(&AgentRequest::SshGenerate {
        comment: comment.to_string(),
    })? {
        Response::SshIdentities { keys } => {
            let k = keys
                .first()
                .ok_or_else(|| anyhow!("the agent minted no key"))?;
            let blob = unhex(&k.key_blob)?;
            let line = authorized_key_line(&blob, comment)?;
            println!("{line}");
            eprintln!();
            eprintln!("black-bag: minted {}", k.fingerprint);
            eprintln!("black-bag: add the line above to a server's ~/.ssh/authorized_keys");
            Ok(())
        }
        Response::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// `black-bag ssh list` — the public keys the vault holds.
pub fn list() -> Result<()> {
    match session::ask(&AgentRequest::SshIdentities)? {
        Response::SshIdentities { keys } => {
            if keys.is_empty() {
                println!("No SSH keys in this vault. Mint one: black-bag ssh generate");
                return Ok(());
            }
            for k in &keys {
                let blob = unhex(&k.key_blob)?;
                println!("{}  {}", k.fingerprint, authorized_key_line(&blob, &k.comment)?);
            }
            Ok(())
        }
        Response::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// `black-bag ssh approve <fingerprint>` — grant a key for signing, reading the
/// passphrase on stdin. What the deck runs when a person answers the prompt;
/// there is no `--passphrase` flag anywhere in this project.
pub fn approve(fingerprint: &str) -> Result<()> {
    // read_passphrase returns a Zeroizing<String>, which is exactly the field
    // type; passed by move so it is never copied into a second buffer.
    let passphrase = crate::tty::read_passphrase("Master passphrase, to approve: ")?;
    match session::ask(&AgentRequest::SshApprove {
        fingerprint: fingerprint.to_string(),
        passphrase,
    })? {
        Response::Ok => {
            println!("Approved {fingerprint}.");
            Ok(())
        }
        Response::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// Rebuild the `ssh-ed25519 <base64> <comment>` line from a public blob.
fn authorized_key_line(blob: &[u8], comment: &str) -> Result<String> {
    use blackbag_core::ssh::wire::Reader;
    let mut r = Reader::new(blob);
    if r.utf8()? != "ssh-ed25519" {
        bail!("not an ssh-ed25519 key");
    }
    let pk: [u8; 32] = r
        .string()?
        .try_into()
        .map_err(|_| anyhow!("an ed25519 public key is 32 bytes"))?;
    Ok(blackbag_core::ssh::wire::authorized_key_line(&pk, comment))
}

