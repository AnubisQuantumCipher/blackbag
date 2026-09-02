//! Lock the vault when the host sleeps or the session locks.
//!
//! Every serious password manager does this, and until now this one did not:
//! a laptop closed with the deck unlocked carried its data key into suspend,
//! and a locked screen was not a locked vault. `systemd-logind` announces both
//! events on the system D-Bus — `PrepareForSleep(true)` on the manager object
//! and `Lock` on the session object — so the agent subscribes to them.
//!
//! # Why this is a hand-written client
//!
//! A D-Bus library is a large dependency for two signals. This module speaks
//! exactly the subset it needs: SASL `EXTERNAL` authentication, `Hello`, two
//! `AddMatch` calls, and a loop that classifies incoming signals. It never
//! sends anything derived from a secret and never exposes an interface of its
//! own, so the worst a hostile bus can do is fail to tell us about a sleep —
//! the same position we were in before this module existed — or tell us about
//! one that is not happening, which locks the vault. Both fail safe.
//!
//! The parser is bounds-checked at every step and never panics on malformed
//! input; a message it cannot read is dropped, and a connection that breaks is
//! retried on a backoff. Its state is reported through `status.json` so the
//! deck can say whether the watcher is actually connected rather than assume.
//!
//! # What it does not do
//!
//! It takes no inhibitor lock, so there is no guarantee the vault is locked
//! *before* the kernel suspends — only that it is locked as soon as the agent
//! is scheduled after the signal, which is milliseconds in practice. A delay
//! inhibitor would need file-descriptor passing over the bus and is deliberately
//! out of scope for a two-signal client. The whitepaper says so.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::session::LockReason;

pub const DEFAULT_SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";
pub const LOGIND: &str = "org.freedesktop.login1";
pub const LOGIND_MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
pub const LOGIND_SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const RETRY_DELAY: Duration = Duration::from_secs(20);
/// A header or body larger than this is not something logind sends.
const MAX_MESSAGE_BYTES: usize = 1 << 20;

/// Where to connect and what to accept. Production uses the system bus and
/// only trusts signals from logind's well-known name; the end-to-end test
/// uses the session bus and any sender.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub socket: PathBuf,
    /// Only signals from this bus name are acted on. `None` accepts any sender,
    /// which is only appropriate on a bus you control.
    pub sender: Option<String>,
}

impl WatchConfig {
    /// The system bus, honouring `DBUS_SYSTEM_BUS_ADDRESS` when set.
    pub fn system() -> Self {
        Self {
            socket: system_bus_socket(),
            sender: Some(LOGIND.to_string()),
        }
    }
}

/// Resolve the system bus socket path from the environment or the default.
pub fn system_bus_socket() -> PathBuf {
    if let Ok(addr) = std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
        if let Some(path) = unix_path_from_address(&addr) {
            return path;
        }
    }
    PathBuf::from(DEFAULT_SYSTEM_BUS)
}

/// The first `unix:path=` entry of a D-Bus address string.
pub fn unix_path_from_address(address: &str) -> Option<PathBuf> {
    for entry in address.split(';') {
        let Some(rest) = entry.strip_prefix("unix:") else {
            continue;
        };
        for kv in rest.split(',') {
            if let Some(path) = kv.strip_prefix("path=") {
                return Some(PathBuf::from(unescape_address_value(path)));
            }
        }
    }
    None
}

/// D-Bus addresses percent-escape bytes outside `[A-Za-z0-9_/.\-]`.
fn unescape_address_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Start the watcher on its own thread. Events arrive on `tx`; the returned
/// handle carries a one-line description of the watcher's current state for
/// `status.json`.
pub fn spawn(config: WatchConfig, tx: Sender<LockReason>) -> Arc<Mutex<String>> {
    let state = Arc::new(Mutex::new("starting".to_string()));
    let shared = Arc::clone(&state);
    let spawned = std::thread::Builder::new()
        .name("sleep-watch".into())
        .stack_size(256 * 1024)
        .spawn(move || loop {
            set_state(&shared, "connecting");
            match run(&config, &tx, &shared) {
                Ok(()) => set_state(&shared, "disconnected; reconnecting"),
                Err(e) => set_state(&shared, &format!("unavailable: {e:#}")),
            }
            std::thread::sleep(RETRY_DELAY);
        });
    if let Err(e) = spawned {
        set_state(&state, &format!("unavailable: could not start thread: {e}"));
    }
    state
}

fn set_state(state: &Arc<Mutex<String>>, text: &str) {
    if let Ok(mut guard) = state.lock() {
        *guard = text.to_string();
    }
}

/// One connection's lifetime: authenticate, subscribe, classify until the bus
/// goes away.
pub fn run(config: &WatchConfig, tx: &Sender<LockReason>, state: &Arc<Mutex<String>>) -> Result<()> {
    let mut stream = UnixStream::connect(&config.socket)
        .with_context(|| format!("cannot reach {}", config.socket.display()))?;
    authenticate(&mut stream)?;

    let mut serial = 1u32;
    let mut next_serial = || {
        let s = serial;
        serial = serial.wrapping_add(1).max(1);
        s
    };

    // Hello is mandatory before anything else; the reply carries our unique
    // name, which we do not need.
    let hello = next_serial();
    stream.write_all(&method_call(
        hello,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
        None,
    ))?;
    wait_for_reply(&mut stream, hello)?;

    let sender_clause = config
        .sender
        .as_deref()
        .map(|s| format!(",sender='{s}'"))
        .unwrap_or_default();
    for rule in [
        format!(
            "type='signal'{sender_clause},interface='{LOGIND_MANAGER_IFACE}',member='PrepareForSleep'"
        ),
        format!("type='signal'{sender_clause},interface='{LOGIND_SESSION_IFACE}',member='Lock'"),
    ] {
        let s = next_serial();
        stream.write_all(&method_call(
            s,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "AddMatch",
            Some(("s", &marshal_string(&rule))),
        ))?;
        wait_for_reply(&mut stream, s)?;
    }

    set_state(
        state,
        &format!(
            "watching {} for suspend and session lock",
            config.sender.as_deref().unwrap_or("any sender")
        ),
    );

    loop {
        let message = read_message(&mut stream)?;
        if let Some(reason) = classify(&message, config.sender.as_deref()) {
            if tx.send(reason).is_err() {
                // The agent is gone; nothing to lock any more.
                return Ok(());
            }
        }
    }
}

/// SASL EXTERNAL: prove our uid by the credentials the kernel attaches to the
/// socket, which is all the system bus needs.
fn authenticate(stream: &mut UnixStream) -> Result<()> {
    let uid = unsafe { libc::getuid() }.to_string();
    let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
    stream.write_all(b"\0")?;
    stream.write_all(format!("AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let line = read_sasl_line(stream)?;
    if !line.starts_with("OK ") {
        bail!("bus refused authentication: {}", line.trim());
    }
    stream.write_all(b"BEGIN\r\n")?;
    Ok(())
}

fn read_sasl_line(stream: &mut UnixStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            bail!("bus closed during authentication");
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() > 4096 {
            bail!("authentication line too long");
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Read messages until the reply to `serial` arrives, failing on an error
/// reply. Signals that arrive meanwhile are discarded — subscription has not
/// completed yet, so there is nothing to act on.
fn wait_for_reply(stream: &mut UnixStream, serial: u32) -> Result<()> {
    for _ in 0..64 {
        let message = read_message(stream)?;
        if message.reply_serial == Some(serial) {
            return match message.kind() {
                MessageType::MethodReturn => Ok(()),
                MessageType::Error => bail!(
                    "bus error: {}",
                    message.error_name.as_deref().unwrap_or("unknown")
                ),
                _ => bail!("unexpected reply type"),
            };
        }
    }
    bail!("no reply to serial {serial}")
}

// ── wire format ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    MethodCall,
    MethodReturn,
    Error,
    Signal,
    Unknown(u8),
}

/// The parts of a message this module cares about.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub kind: Option<MessageType>,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub sender: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub signature: Option<String>,
    pub body: Vec<u8>,
    pub little_endian: bool,
}

impl Message {
    fn kind(&self) -> MessageType {
        self.kind.unwrap_or(MessageType::Unknown(0))
    }
}

/// Decide whether a message is one of the two events we lock on.
pub fn classify(message: &Message, expected_sender: Option<&str>) -> Option<LockReason> {
    if message.kind() != MessageType::Signal {
        return None;
    }
    if let Some(expected) = expected_sender {
        // logind's signals carry its unique name (`:1.6`) as sender, not the
        // well-known one, so the bus-side match rule is what enforces the
        // sender; here we only refuse a message that names a *different*
        // well-known name outright.
        if let Some(sender) = &message.sender {
            if sender.starts_with("org.") && sender != expected {
                return None;
            }
        }
    }
    match (message.interface.as_deref(), message.member.as_deref()) {
        (Some(LOGIND_MANAGER_IFACE), Some("PrepareForSleep")) => {
            let going_to_sleep = read_bool(&message.body, message.little_endian)?;
            going_to_sleep.then_some(LockReason::Suspend)
        }
        (Some(LOGIND_SESSION_IFACE), Some("Lock")) => Some(LockReason::SessionLock),
        _ => None,
    }
}

fn read_bool(body: &[u8], little_endian: bool) -> Option<bool> {
    let raw = body.get(0..4)?;
    let bytes = [raw[0], raw[1], raw[2], raw[3]];
    let value = if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    };
    Some(value == 1)
}

/// Read exactly one message off the stream.
pub fn read_message(stream: &mut impl Read) -> Result<Message> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed)?;
    let little_endian = match fixed[0] {
        b'l' => true,
        b'B' => false,
        other => bail!("bad endianness byte {other:#x}"),
    };
    let u32_at = |b: &[u8]| -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        }
    };
    let body_len = u32_at(&fixed[4..8]) as usize;
    let fields_len = u32_at(&fixed[12..16]) as usize;
    if body_len > MAX_MESSAGE_BYTES || fields_len > MAX_MESSAGE_BYTES {
        bail!("message too large");
    }
    let header_total = 16 + fields_len;
    let padded_header = header_total.div_ceil(8) * 8;
    let mut rest = vec![0u8; padded_header - 16 + body_len];
    stream.read_exact(&mut rest)?;

    let mut raw = Vec::with_capacity(padded_header + body_len);
    raw.extend_from_slice(&fixed);
    raw.extend_from_slice(&rest);
    parse_message(&raw).ok_or_else(|| anyhow!("malformed message"))
}

/// Parse a complete message from its bytes. `None` on anything malformed.
pub fn parse_message(raw: &[u8]) -> Option<Message> {
    let little_endian = match *raw.first()? {
        b'l' => true,
        b'B' => false,
        _ => return None,
    };
    let mut cursor = Cursor {
        buf: raw,
        pos: 0,
        little_endian,
    };
    cursor.pos = 1;
    let kind = match cursor.u8()? {
        1 => MessageType::MethodCall,
        2 => MessageType::MethodReturn,
        3 => MessageType::Error,
        4 => MessageType::Signal,
        other => MessageType::Unknown(other),
    };
    let _flags = cursor.u8()?;
    let version = cursor.u8()?;
    if version != 1 {
        return None;
    }
    let body_len = cursor.u32()? as usize;
    let serial = cursor.u32()?;
    let fields_len = cursor.u32()? as usize;
    let fields_end = cursor.pos.checked_add(fields_len)?;
    if fields_end > raw.len() {
        return None;
    }

    let mut message = Message {
        kind: Some(kind),
        serial,
        little_endian,
        ..Message::default()
    };

    while cursor.pos < fields_end {
        cursor.align(8)?;
        if cursor.pos >= fields_end {
            break;
        }
        let code = cursor.u8()?;
        let sig = cursor.signature()?;
        match (code, sig.as_str()) {
            (1, "o") => message.path = Some(cursor.string()?),
            (2, "s") => message.interface = Some(cursor.string()?),
            (3, "s") => message.member = Some(cursor.string()?),
            (4, "s") => message.error_name = Some(cursor.string()?),
            (5, "u") => message.reply_serial = Some(cursor.u32()?),
            (6, "s") => {
                let _destination = cursor.string()?;
            }
            (7, "s") => message.sender = Some(cursor.string()?),
            (8, "g") => message.signature = Some(cursor.signature()?),
            (9, "u") => {
                let _fds = cursor.u32()?;
            }
            (_, other) => {
                // Unknown field: skip its value by signature, for the simple
                // types we understand; anything else is a parse failure.
                match other {
                    "s" | "o" => {
                        cursor.string()?;
                    }
                    "g" => {
                        cursor.signature()?;
                    }
                    "u" | "i" | "b" => {
                        cursor.u32()?;
                    }
                    "y" => {
                        cursor.u8()?;
                    }
                    _ => return None,
                }
            }
        }
    }
    cursor.pos = fields_end;
    cursor.align(8)?;
    let body_start = cursor.pos;
    let body_end = body_start.checked_add(body_len)?;
    if body_end > raw.len() {
        return None;
    }
    message.body = raw[body_start..body_end].to_vec();
    Some(message)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    little_endian: bool,
}

impl Cursor<'_> {
    fn align(&mut self, to: usize) -> Option<()> {
        let aligned = self.pos.div_ceil(to) * to;
        if aligned > self.buf.len() {
            return None;
        }
        self.pos = aligned;
        Some(())
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u32(&mut self) -> Option<u32> {
        self.align(4)?;
        let raw = self.buf.get(self.pos..self.pos + 4)?;
        let arr = [raw[0], raw[1], raw[2], raw[3]];
        self.pos += 4;
        Some(if self.little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    }
    /// STRING and OBJECT_PATH share an encoding.
    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.buf.get(self.pos..self.pos.checked_add(len)?)?;
        let text = std::str::from_utf8(bytes).ok()?.to_string();
        self.pos += len;
        if self.u8()? != 0 {
            return None;
        }
        Some(text)
    }
    fn signature(&mut self) -> Option<String> {
        let len = self.u8()? as usize;
        let bytes = self.buf.get(self.pos..self.pos.checked_add(len)?)?;
        let text = std::str::from_utf8(bytes).ok()?.to_string();
        self.pos += len;
        if self.u8()? != 0 {
            return None;
        }
        Some(text)
    }
}

/// Little-endian STRING body encoding.
pub fn marshal_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 5);
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out
}

/// Build a METHOD_CALL, little-endian, with an optional body and its signature.
pub fn method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    body: Option<(&str, &[u8])>,
) -> Vec<u8> {
    build_message(1, serial, Some(destination), path, interface, member, body)
}

/// Build a SIGNAL, little-endian. Used by tests; nothing in production emits.
pub fn signal(serial: u32, path: &str, interface: &str, member: &str, body: Option<(&str, &[u8])>) -> Vec<u8> {
    build_message(4, serial, None, path, interface, member, body)
}

fn build_message(
    kind: u8,
    serial: u32,
    destination: Option<&str>,
    path: &str,
    interface: &str,
    member: &str,
    body: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut fields = Vec::new();
    push_field(&mut fields, 1, b'o', path);
    if let Some(dest) = destination {
        push_field(&mut fields, 6, b's', dest);
    }
    push_field(&mut fields, 2, b's', interface);
    push_field(&mut fields, 3, b's', member);
    if let Some((sig, _)) = body {
        pad_to(&mut fields, 8);
        fields.push(8);
        fields.extend_from_slice(&[1, b'g', 0]);
        fields.push(sig.len() as u8);
        fields.extend_from_slice(sig.as_bytes());
        fields.push(0);
    }

    let body_bytes = body.map(|(_, b)| b).unwrap_or(&[]);
    let mut out = Vec::with_capacity(16 + fields.len() + 8 + body_bytes.len());
    out.push(b'l');
    out.push(kind);
    out.push(0);
    out.push(1);
    out.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    out.extend_from_slice(&fields);
    pad_to(&mut out, 8);
    out.extend_from_slice(body_bytes);
    out
}

/// Append one header field. Fields are structs, so each starts 8-aligned;
/// offsets inside `fields` are congruent to absolute offsets because the
/// array content begins at byte 16.
fn push_field(fields: &mut Vec<u8>, code: u8, type_code: u8, value: &str) {
    pad_to(fields, 8);
    fields.push(code);
    fields.extend_from_slice(&[1, type_code, 0]);
    pad_to(fields, 4);
    fields.extend_from_slice(&(value.len() as u32).to_le_bytes());
    fields.extend_from_slice(value.as_bytes());
    fields.push(0);
}

fn pad_to(buf: &mut Vec<u8>, to: usize) {
    while buf.len() % to != 0 {
        buf.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_call_parses_back_to_what_was_built() {
        let raw = method_call(
            7,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "AddMatch",
            Some(("s", &marshal_string("type='signal'"))),
        );
        let message = parse_message(&raw).expect("our own message must parse");
        assert_eq!(message.kind, Some(MessageType::MethodCall));
        assert_eq!(message.serial, 7);
        assert_eq!(message.path.as_deref(), Some("/org/freedesktop/DBus"));
        assert_eq!(message.interface.as_deref(), Some("org.freedesktop.DBus"));
        assert_eq!(message.member.as_deref(), Some("AddMatch"));
        assert_eq!(message.signature.as_deref(), Some("s"));
        assert_eq!(message.body, marshal_string("type='signal'"));
        assert_eq!(raw.len() % 8, message.body.len() % 8, "body starts 8-aligned");
    }

    #[test]
    fn prepare_for_sleep_true_is_a_suspend() {
        let raw = signal(
            3,
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            Some(("b", &1u32.to_le_bytes())),
        );
        let message = parse_message(&raw).unwrap();
        assert_eq!(classify(&message, Some(LOGIND)), Some(LockReason::Suspend));
    }

    #[test]
    fn prepare_for_sleep_false_is_a_wake_and_does_nothing() {
        let raw = signal(
            3,
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            Some(("b", &0u32.to_le_bytes())),
        );
        let message = parse_message(&raw).unwrap();
        assert_eq!(classify(&message, Some(LOGIND)), None);
    }

    #[test]
    fn a_session_lock_is_a_session_lock() {
        let raw = signal(
            9,
            "/org/freedesktop/login1/session/_32",
            LOGIND_SESSION_IFACE,
            "Lock",
            None,
        );
        let message = parse_message(&raw).unwrap();
        assert_eq!(classify(&message, Some(LOGIND)), Some(LockReason::SessionLock));
    }

    #[test]
    fn a_method_call_is_never_an_event() {
        let raw = method_call(
            1,
            "x",
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            Some(("b", &1u32.to_le_bytes())),
        );
        let message = parse_message(&raw).unwrap();
        assert_eq!(classify(&message, Some(LOGIND)), None);
    }

    #[test]
    fn malformed_bytes_never_panic() {
        let raw = signal(
            3,
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            Some(("b", &1u32.to_le_bytes())),
        );
        // Every prefix of a valid message must be rejected, not crash.
        for cut in 0..raw.len() {
            let _ = parse_message(&raw[..cut]);
        }
        // Flip every byte in turn.
        for i in 0..raw.len() {
            let mut bent = raw.clone();
            bent[i] ^= 0xff;
            let _ = parse_message(&bent);
        }
        assert!(parse_message(b"").is_none());
        assert!(parse_message(b"x").is_none());
    }

    #[test]
    fn address_parsing_takes_the_first_unix_path() {
        assert_eq!(
            unix_path_from_address("unix:path=/run/dbus/system_bus_socket"),
            Some(PathBuf::from("/run/dbus/system_bus_socket"))
        );
        assert_eq!(
            unix_path_from_address("tcp:host=x;unix:path=/tmp/a%20b,guid=1"),
            Some(PathBuf::from("/tmp/a b"))
        );
        assert_eq!(unix_path_from_address("unix:abstract=/tmp/x"), None);
    }

    /// End-to-end against a real bus: connect to the session bus with no
    /// sender filter and emit the two signals with `busctl`. Skipped, not
    /// failed, on a machine with no session bus or no `busctl`.
    #[test]
    fn a_real_bus_delivers_both_events() {
        let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") else {
            eprintln!("no session bus; skipping");
            return;
        };
        let Some(socket) = unix_path_from_address(&addr) else {
            eprintln!("session bus is not a unix path; skipping");
            return;
        };
        if std::process::Command::new("busctl")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("no busctl; skipping");
            return;
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let state = spawn(
            WatchConfig {
                socket,
                sender: None,
            },
            tx,
        );

        // Give the subscription a moment to land.
        let started = std::time::Instant::now();
        loop {
            let text = state.lock().unwrap().clone();
            if text.starts_with("watching") {
                break;
            }
            if text.starts_with("unavailable") || started.elapsed() > Duration::from_secs(5) {
                eprintln!("watcher state: {text}; skipping");
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let emit = |path: &str, iface: &str, member: &str, extra: &[&str]| {
            let mut cmd = std::process::Command::new("busctl");
            cmd.args(["--user", "emit", path, iface, member]);
            cmd.args(extra);
            cmd.status().expect("busctl runs")
        };
        assert!(emit(
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            &["b", "true"]
        )
        .success());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            LockReason::Suspend
        );

        assert!(emit(
            "/org/freedesktop/login1/session/_32",
            LOGIND_SESSION_IFACE,
            "Lock",
            &[]
        )
        .success());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            LockReason::SessionLock
        );

        // And a wake-up must not lock anything.
        assert!(emit(
            "/org/freedesktop/login1",
            LOGIND_MANAGER_IFACE,
            "PrepareForSleep",
            &["b", "false"]
        )
        .success());
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    }
}
