//! The virtual FIDO2 device: `/dev/uhid`, and the loop that talks CTAPHID.
//!
//! Everything about *what to say* lives in `blackbag_core::ctap`, which is
//! tested without a device. What lives here is the device: creating it,
//! reading reports off it, and answering through the agent.
//!
//! ## Why this is its own process
//!
//! The same shape as the browser lane's native host, for the same reason. The
//! agent is single-threaded on its socket, deliberately — that is what makes
//! its idle timer and its lock-on-suspend mean anything — and a device that
//! sits blocked on a read for hours has no business inside it. So the device
//! is a separate process that speaks the ordinary agent protocol, registers
//! ceremonies like any other caller, and gets refused like any other caller.
//!
//! ## What can talk to this device
//!
//! Anything that can open the HID node — with the udev rule this project
//! ships, that is whoever is logged in at the seat. A hardware key is in the
//! same position and answers with a touch; this answers with Black-Bag's own
//! consent screen and the master passphrase, which is a stricter test.

use anyhow::{Context, Result, anyhow, bail};
use blackbag_core::consent::Operation;
use blackbag_core::ctap::authenticator::{self, Asserted, Backend, Made};
use blackbag_core::ctap::cbor::{self, GetAssertion, MakeCredential, status};
use blackbag_core::ctap::hid::{self, Message, Reassembler, Step, cmd, err};
use blackbag_core::session::{self, Request as AgentRequest, Response};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// How long to wait for a human before giving up on a ceremony.
///
/// Matches the consent desk's own ceremony lifetime. A client is kept informed
/// with CTAPHID_KEEPALIVE the whole time, which is what stops a browser
/// deciding the device has died.
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
/// How often to send KEEPALIVE. The specification suggests 100ms; a browser
/// gives up somewhere north of a second, so this is comfortable and quiet.
const KEEPALIVE_EVERY: Duration = Duration::from_millis(500);

// ── the HID report descriptor ────────────────────────────────────────────────
//
// FIDO U2F HID, from the CTAP specification's own appendix: usage page
// 0xF1D0, usage 0x01, one 64-byte input report and one 64-byte output report.
// A browser recognises a device as a security key by exactly this.
const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (U2F HID Authenticator Device)
    0xa1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Var, Abs)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Var, Abs)
    0xc0, //             End Collection
];

// ── the uhid ABI ─────────────────────────────────────────────────────────────
//
// `struct uhid_event` from include/uapi/linux/uhid.h: a `__u32 type` followed
// by a PACKED union, so every field sits at a fixed byte offset with no
// alignment padding anywhere.
//
// The offsets below were MEASURED on this machine with `offsetof`, not
// remembered — the first attempt put `rd_size` after the descriptor instead of
// before it, and the kernel answered `EINVAL` with no further explanation
// because it read a zero-length descriptor. A layout written from memory is a
// layout that is wrong in exactly one place.
//
//   sizeof(struct uhid_event)  4380  (create2 ends at 4376; the union is
//                                      8-byte aligned because uhid_start_req
//                                      holds a __u64, so it rounds up)
//   create2.name                  4    create2.version   272
//   create2.phys                132    create2.country   276
//   create2.uniq                196    create2.rd_data   280
//   create2.rd_size             260    input2.size         4
//   create2.bus                 262    input2.data         6
//   create2.vendor              264    output.data         4
//   create2.product             268    output.size      4100
//
// `uhid_event_type` is an enum, so the numbers are positional and stable.

const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;

const UHID_DATA_MAX: usize = 4096;
/// The kernel reads at most this much; a longer write is truncated to it.
const UHID_EVENT_SIZE: usize = 4380;

// create2, measured.
const C2_NAME: usize = 4;
const C2_PHYS: usize = 132;
const C2_UNIQ: usize = 196;
const C2_RD_SIZE: usize = 260;
const C2_BUS: usize = 262;
const C2_VENDOR: usize = 264;
const C2_PRODUCT: usize = 268;
const C2_VERSION: usize = 272;
const C2_COUNTRY: usize = 276;
const C2_RD_DATA: usize = 280;

// input2 and output, measured.
const IN2_SIZE: usize = 4;
const IN2_DATA: usize = 6;
const OUT_DATA: usize = 4;
const OUT_SIZE: usize = 4100;

// Checked when this compiles, not when a test runs. Every one of these is a
// fact about a C structure; getting one wrong produces a device the kernel
// refuses with EINVAL and no further explanation, and a build failure is a far
// better place to find that out than a running system.
const _: () = {
    assert!(C2_NAME < C2_PHYS && C2_PHYS < C2_UNIQ && C2_UNIQ < C2_RD_SIZE);
    assert!(C2_RD_SIZE < C2_BUS && C2_BUS < C2_VENDOR);
    assert!(C2_VENDOR < C2_PRODUCT && C2_PRODUCT < C2_VERSION);
    assert!(C2_VERSION < C2_COUNTRY && C2_COUNTRY < C2_RD_DATA);
    // rd_size comes BEFORE rd_data. This is the one that was wrong.
    assert!(C2_RD_SIZE < C2_RD_DATA);
    // Nothing overruns the event the kernel reads.
    assert!(C2_RD_DATA + UHID_DATA_MAX <= UHID_EVENT_SIZE);
    assert!(IN2_DATA + UHID_DATA_MAX <= UHID_EVENT_SIZE);
    assert!(OUT_SIZE + 2 < UHID_EVENT_SIZE);
    // The descriptor has to fit in the field, with room for its own length.
    assert!(REPORT_DESCRIPTOR.len() < UHID_DATA_MAX);
    assert!(!REPORT_DESCRIPTOR.is_empty());
};

/// BUS_USB, from linux/input.h. A browser looks at the bus to decide whether
/// something is a plausible security key.
const BUS_USB: u16 = 0x03;

/// Copy a string into a fixed-width field, always NUL-terminated.
fn put_str(dst: &mut [u8], text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&bytes[..n]);
}

/// Build a UHID_CREATE2 event.
fn create_event(name: &str, serial: &str) -> Vec<u8> {
    let mut ev = vec![0u8; UHID_EVENT_SIZE];
    ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
    put_str(&mut ev[C2_NAME..C2_PHYS], name);
    put_str(&mut ev[C2_PHYS..C2_UNIQ], "blackbag");
    put_str(&mut ev[C2_UNIQ..C2_RD_SIZE], serial);

    let rd = REPORT_DESCRIPTOR.len();
    ev[C2_RD_SIZE..C2_BUS].copy_from_slice(&(rd as u16).to_ne_bytes());
    ev[C2_BUS..C2_VENDOR].copy_from_slice(&BUS_USB.to_ne_bytes());
    // A vendor or product id we do not own would be a lie told to every
    // relying party that logs one. Zero says "no registered vendor", which is
    // true, and is what other virtual authenticators report.
    ev[C2_VENDOR..C2_PRODUCT].copy_from_slice(&0u32.to_ne_bytes());
    ev[C2_PRODUCT..C2_VERSION].copy_from_slice(&0u32.to_ne_bytes());
    ev[C2_VERSION..C2_COUNTRY].copy_from_slice(&1u32.to_ne_bytes());
    ev[C2_COUNTRY..C2_RD_DATA].copy_from_slice(&0u32.to_ne_bytes());
    ev[C2_RD_DATA..C2_RD_DATA + rd].copy_from_slice(REPORT_DESCRIPTOR);
    ev
}

/// Build a UHID_INPUT2 event carrying one report.
fn input_event(report: &[u8]) -> Vec<u8> {
    let mut ev = vec![0u8; UHID_EVENT_SIZE];
    ev[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
    let n = report.len().min(UHID_DATA_MAX);
    ev[IN2_SIZE..IN2_DATA].copy_from_slice(&(n as u16).to_ne_bytes());
    ev[IN2_DATA..IN2_DATA + n].copy_from_slice(&report[..n]);
    ev
}

fn write_event_to(file: &mut File, event: &[u8]) -> Result<()> {
    file.write_all(event)?;
    file.flush()?;
    Ok(())
}

/// Send one report down a `/dev/uhid` handle.
///
/// A free function taking a plain `File`, NOT a method on [`Device`].
///
/// `Device` destroys the device when it is dropped, which is right for the one
/// value that owns it and catastrophic for a second one wrapped around a
/// cloned descriptor. That is not hypothetical: the keepalive path built a
/// throwaway `Device` around a clone, and the first keepalive of the first
/// ceremony destroyed the key mid-request — every write after it failed with
/// `EINVAL` and the process died. A clone of the descriptor is not a second
/// device, and nothing here should be able to say otherwise.
pub fn send_report(file: &mut File, report: &[u8]) -> Result<()> {
    write_event_to(file, &input_event(report))
}

/// The device, for as long as this value is alive.
pub struct Device {
    file: File,
}

impl Device {
    /// Create the virtual key.
    ///
    /// The failure this is most likely to hit is permission, and it says so in
    /// full rather than passing `EACCES` along: the fix is a udev rule, and a
    /// person who has just been told "permission denied" has no way to know
    /// that.
    pub fn create(name: &str, serial: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => anyhow!(
                    "no permission to open /dev/uhid.\n\n\
                     A virtual security key needs it, and by default only root has it. \
                     Install the rule this project ships:\n\n  \
                     sudo install -m644 packaging/70-blackbag-uhid.rules \
                     /etc/udev/rules.d/\n  \
                     sudo udevadm control --reload && sudo udevadm trigger\n\n\
                     It grants the device to whoever is logged in at the seat, with \
                     TAG+=\"uaccess\" — NOT by putting you in the input group, which \
                     would give every program you run raw access to your keyboard."
                ),
                std::io::ErrorKind::NotFound => anyhow!(
                    "/dev/uhid does not exist. The kernel needs CONFIG_UHID; \
                     try `sudo modprobe uhid`."
                ),
                _ => anyhow!("could not open /dev/uhid: {e}"),
            })?;

        let mut me = Self { file };
        me.write_event(&create_event(name, serial))
            .context("the kernel refused to create the device")?;
        Ok(me)
    }

    fn write_event(&mut self, event: &[u8]) -> Result<()> {
        write_event_to(&mut self.file, event)
    }

    /// Send one 64-byte report to whoever has the device open.
    pub fn send(&mut self, report: &[u8]) -> Result<()> {
        send_report(&mut self.file, report)
    }

    /// Read the next event, returning an output report when there is one.
    fn next_report(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; UHID_EVENT_SIZE];
        let n = self.file.read(&mut buf)?;
        if n < 4 {
            return Ok(None);
        }
        let kind = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        match kind {
            UHID_OUTPUT => {
                let size =
                    u16::from_ne_bytes([buf[OUT_SIZE], buf[OUT_SIZE + 1]]) as usize;
                let size = size.min(UHID_DATA_MAX);
                Ok(Some(buf[OUT_DATA..OUT_DATA + size].to_vec()))
            }
            UHID_START | UHID_STOP | UHID_OPEN | UHID_CLOSE => Ok(None),
            _ => Ok(None),
        }
    }
}

impl Drop for Device {
    /// Take the key away when this value goes.
    ///
    /// Which is why nothing else may be a `Device`. Only the value returned by
    /// [`Device::create`] owns the key; anything that merely needs to write a
    /// report uses [`send_report`] on a cloned descriptor.
    fn drop(&mut self) {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_DESTROY.to_ne_bytes());
        let _ = self.write_event(&ev);
    }
}

// ── the agent-facing backend ─────────────────────────────────────────────────

/// Answers CTAP commands by running an ordinary ceremony through the agent.
pub struct AgentBackend {
    /// Sends a keepalive to the client while a human is deciding. Without it a
    /// browser concludes the key is dead and gives up.
    beat: Box<dyn FnMut() -> Result<()>>,
}

impl AgentBackend {
    pub fn new(beat: Box<dyn FnMut() -> Result<()>>) -> Self {
        Self { beat }
    }

    fn ask(&mut self, request: &AgentRequest) -> Result<Response> {
        session::ask(request)
    }

    /// Register a ceremony, wait for a human, and collect the answer.
    ///
    /// The CTAP status codes are chosen so a client can tell the three cases
    /// apart the way it would for a hardware key: refused, timed out, or
    /// nothing to offer.
    fn ceremony(&mut self, begin: AgentRequest, credential: Option<String>) -> Result<Response, u8> {
        let nonce = match self.ask(&begin) {
            Ok(Response::PasskeyRegistered { nonce, .. }) => nonce,
            // The agent refused before anybody was asked: a locked vault, no
            // matching credential, a relying party it will not accept.
            Ok(Response::Error { message }) => {
                eprintln!("black-bag: {message}");
                return Err(status::NO_CREDENTIALS);
            }
            Ok(_) => return Err(status::OTHER),
            Err(e) => {
                eprintln!("black-bag: {e}");
                return Err(status::OTHER);
            }
        };

        let started = Instant::now();
        let mut last_beat = Instant::now();
        loop {
            match self.ask(&AgentRequest::PasskeyCollect {
                nonce: nonce.clone(),
            }) {
                Ok(Response::PasskeyWaiting) => {}
                Ok(Response::PasskeyUseSecurityKey) => {
                    // Somebody chose "use a security key" on a request that
                    // ARRIVED through the security key. There is nothing
                    // further to stand aside for, so it is a refusal.
                    return Err(status::OPERATION_DENIED);
                }
                Ok(result @ Response::PasskeyResult { .. }) => return Ok(result),
                Ok(Response::Error { message }) => {
                    eprintln!("black-bag: {message}");
                    return Err(status::OPERATION_DENIED);
                }
                Ok(_) => return Err(status::OTHER),
                Err(e) => {
                    eprintln!("black-bag: {e}");
                    return Err(status::OTHER);
                }
            }
            if started.elapsed() >= CEREMONY_TIMEOUT {
                let _ = self.ask(&AgentRequest::PasskeyAnswer {
                    nonce: nonce.clone(),
                    approve: false,
                    defer: false,
                    credential_id: credential.clone(),
                    passphrase: Default::default(),
                });
                return Err(status::USER_ACTION_TIMEOUT);
            }
            if last_beat.elapsed() >= KEEPALIVE_EVERY {
                if (self.beat)().is_err() {
                    // The client hung up. Take the prompt off the screen
                    // rather than leaving somebody to answer something that
                    // can no longer be delivered.
                    let _ = self.ask(&AgentRequest::PasskeyAnswer {
                        nonce,
                        approve: false,
                        defer: false,
                        credential_id: credential,
                        passphrase: Default::default(),
                    });
                    return Err(status::KEEPALIVE_CANCEL);
                }
                last_beat = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(60));
        }
    }
}

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

impl Backend for AgentBackend {
    fn count_for(&mut self, rp_id: &str) -> usize {
        // A registration that is going to fail should fail before a human is
        // asked, so this is a plain read rather than a ceremony.
        match self.ask(&AgentRequest::List {
            kind: Some("passkey".into()),
            query: None,
        }) {
            Ok(Response::Records { records }) => records
                .iter()
                .filter(|r| {
                    r.kind == "passkey"
                        && r.attributes.iter().any(|(k, v)| {
                            k == "relying_party" && v.eq_ignore_ascii_case(rp_id)
                        })
                })
                .count(),
            _ => 0,
        }
    }

    fn holds_any(&mut self, rp_id: &str, ids: &[Vec<u8>]) -> bool {
        let hexed: Vec<String> = ids.iter().map(|i| hex(i)).collect();
        match self.ask(&AgentRequest::List {
            kind: Some("passkey".into()),
            query: None,
        }) {
            Ok(Response::Records { records }) => records.iter().any(|r| {
                r.kind == "passkey"
                    && r.attributes
                        .iter()
                        .any(|(k, v)| k == "relying_party" && v.eq_ignore_ascii_case(rp_id))
                    && r.attributes.iter().any(|(k, v)| {
                        k == "credential_id" && hexed.iter().any(|h| h.eq_ignore_ascii_case(v))
                    })
            }),
            _ => false,
        }
    }

    fn make_credential(&mut self, req: &MakeCredential) -> Result<Made, u8> {
        let begin = AgentRequest::PasskeyBegin {
            operation: Operation::Create,
            client_data_hash: Some(hex(&req.client_data_hash)),
            origin: String::new(),
            rp_id: req.rp.id.clone(),
            rp_name: req.rp.name.clone(),
            allow_credentials: Vec::new(),
            challenge: String::new(),
            cross_origin: false,
            user_handle: Some(hex(&req.user.id)),
            user_name: req.user.name.clone(),
            user_display_name: req.user.display_name.clone(),
            // hmac-secret over CTAP needs the PIN protocol's shared secret,
            // which this authenticator does not implement. Asking for a seed
            // we could never hand back would leave a credential carrying one
            // that nothing can reach.
            want_prf: false,
            prf_first_salt: None,
            prf_second_salt: None,
        };
        match self.ceremony(begin, None)? {
            Response::PasskeyResult {
                authenticator_data, ..
            } => Ok(Made {
                auth_data: unhex(&authenticator_data).map_err(|_| status::OTHER)?,
                fmt: "none".into(),
            }),
            _ => Err(status::OTHER),
        }
    }

    fn get_assertion(&mut self, req: &GetAssertion) -> Result<Asserted, u8> {
        let allow: Vec<String> = req.allow_list.iter().map(|c| hex(&c.id)).collect();
        let begin = AgentRequest::PasskeyBegin {
            operation: Operation::Assert,
            client_data_hash: Some(hex(&req.client_data_hash)),
            origin: String::new(),
            rp_id: req.rp_id.clone(),
            rp_name: None,
            allow_credentials: allow,
            challenge: String::new(),
            cross_origin: false,
            user_handle: None,
            user_name: None,
            user_display_name: None,
            want_prf: false,
            prf_first_salt: None,
            prf_second_salt: None,
        };
        match self.ceremony(begin, None)? {
            Response::PasskeyResult {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
                ..
            } => Ok(Asserted {
                credential_id: unhex(&credential_id).map_err(|_| status::OTHER)?,
                auth_data: unhex(&authenticator_data).map_err(|_| status::OTHER)?,
                signature: unhex(&signature).map_err(|_| status::OTHER)?,
                user_handle: unhex(&user_handle).map_err(|_| status::OTHER)?,
                total: 1,
            }),
            _ => Err(status::OTHER),
        }
    }
}

// ── the loop ─────────────────────────────────────────────────────────────────

/// Somewhere 64-byte reports go and come from.
///
/// A trait so the CTAPHID loop can be driven without `/dev/uhid`. That matters
/// more than it sounds: the device needs a udev rule and a seat, so a loop
/// reachable only through it would be a loop nobody could test on a build
/// machine. With this, the only part that needs the real thing is the ABI
/// marshalling above, whose byte layout is checked directly.
pub trait Wire {
    /// Send one report.
    fn send(&mut self, report: &[u8]) -> Result<()>;
    /// Wait for the next report. `None` means "nothing this time, ask again";
    /// an error ends the loop.
    fn recv(&mut self) -> Result<Option<Vec<u8>>>;
}

impl Wire for Device {
    fn send(&mut self, report: &[u8]) -> Result<()> {
        Device::send(self, report)
    }
    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.next_report()
    }
}

/// Supplies what answers CTAP2 commands, one per channel.
///
/// A parameter so the loop can be tested against a backend that never talks
/// to an agent, and so the keepalive can be wired to the real device without
/// the loop knowing about devices.
pub trait Backends {
    fn for_channel(&mut self, cid: u32) -> Box<dyn Backend>;
}

/// Run CTAPHID over any wire, with any backend, until the wire ends.
pub fn run(wire: &mut dyn Wire, backends: &mut dyn Backends) -> Result<()> {
    let mut frames = Reassembler::new();
    loop {
        let report = match wire.recv() {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => return Err(e),
        };
        match frames.push(&report) {
            Step::Continue => {}
            Step::Error { cid, code } => {
                for p in Message::new(cid, cmd::ERROR, vec![code]).to_packets() {
                    wire.send(&p)?;
                }
            }
            Step::Done(message) => answer(wire, &mut frames, backends, message)?,
        }
    }
}

/// Answer one complete CTAPHID message.
fn answer(
    wire: &mut dyn Wire,
    frames: &mut Reassembler,
    backends: &mut dyn Backends,
    message: Message,
) -> Result<()> {
    let reply = match message.cmd {
        cmd::INIT => {
            if message.data.len() < 8 {
                Some(Message::new(message.cid, cmd::ERROR, vec![err::INVALID_LEN]))
            } else {
                let cid = frames.allocate();
                Some(Message::new(
                    message.cid,
                    cmd::INIT,
                    hid::init_response(
                        &message.data[..8],
                        cid,
                        hid::capability::CBOR | hid::capability::NMSG,
                    ),
                ))
            }
        }
        cmd::PING => Some(Message::new(message.cid, cmd::PING, message.data.clone())),
        // Already cleared by the reassembler; there is nothing to say back.
        cmd::CANCEL => None,
        // No light to blink. Answered rather than refused: a client that winks
        // is only saying hello.
        cmd::WINK => Some(Message::new(message.cid, cmd::WINK, Vec::new())),
        // U2F, which this authenticator does not speak — and says so in its
        // INIT capabilities with the NMSG bit, so a client should not ask.
        cmd::MSG => Some(Message::new(message.cid, cmd::ERROR, vec![err::INVALID_CMD])),
        cmd::CBOR => {
            let cid = message.cid;
            let out = match cbor::parse_request(&message.data) {
                Ok(request) => {
                    let mut backend = backends.for_channel(cid);
                    authenticator::dispatch(backend.as_mut(), &request)
                }
                Err(e) => {
                    eprintln!("black-bag: {e}");
                    vec![status::INVALID_CBOR]
                }
            };
            Some(Message::new(cid, cmd::CBOR, out))
        }
        _ => Some(Message::new(message.cid, cmd::ERROR, vec![err::INVALID_CMD])),
    };

    if let Some(reply) = reply {
        for p in reply.to_packets() {
            wire.send(&p)?;
        }
    }
    Ok(())
}


/// Can this machine present a virtual key at all, and what is stopping it?
///
/// Separate from `serve` because "it did not work" is not an answer. Each
/// branch says what to do about it.
pub fn doctor() -> Result<()> {
    let path = std::path::Path::new("/dev/uhid");
    if !path.exists() {
        println!("uhid device        MISSING");
        println!("  /dev/uhid does not exist at all. The kernel needs CONFIG_UHID.");
        println!("  Try: sudo modprobe uhid");
        return Ok(());
    }
    println!("uhid device        present");

    // The trap this machine actually fell into.
    //
    // /dev/uhid exists as a STATIC node whether or not the module is loaded,
    // and opening it is normally what pulls the module in. That does not work
    // here: the static node is root-only, so a non-root open fails with EACCES
    // before the kernel autoloads anything — and until the module is loaded
    // there is no real device for udev to apply the uaccess rule to. Installing
    // the rule and seeing nothing change is the confusing symptom, so it gets
    // its own line rather than being folded into "permission NO".
    let loaded = std::path::Path::new("/sys/class/misc/uhid").exists();
    println!(
        "uhid module        {}",
        if loaded { "loaded" } else { "NOT LOADED" }
    );
    if !loaded {
        println!();
        println!("The node above is a static one; the driver behind it is not loaded, so");
        println!("udev has no device to grant. Until it is, no rule can help.");
        println!();
        println!("  sudo modprobe uhid                       # now");
        println!("  sudo install -m644 packaging/blackbag-uhid.conf /etc/modules-load.d/");
        println!("                                           # and at every boot");
        println!();
    }

    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => {
            println!("permission         yes");
            println!();
            println!("Ready. `black-bag key serve` presents the virtual security key.");
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("permission         NO");
            println!();
            println!("Only root may open /dev/uhid by default. Install the rule this");
            println!("project ships, which grants it to whoever is logged in at the seat:");
            println!();
            println!("  sudo install -m644 packaging/70-blackbag-uhid.rules /etc/udev/rules.d/");
            println!("  sudo udevadm control --reload && sudo udevadm trigger");
            println!();
            println!("It uses TAG+=\"uaccess\", NOT the input group. Adding yourself to");
            println!("`input` would give every program you run raw access to your keyboard,");
            println!("which is a far larger grant than the one being asked for.");
        }
        Err(e) => println!("permission         unclear: {e}"),
    }
    Ok(())
}

/// Present the device and answer it until stopped.
pub fn serve(name: &str) -> Result<()> {
    let mut serial = [0u8; 8];
    getrandom::getrandom(&mut serial).map_err(|e| anyhow!("the system CSPRNG refused: {e}"))?;
    let mut device = Device::create(name, &hex(&serial))?;
    eprintln!("black-bag: {name} is present as a virtual security key");

    // The device is cloned once per channel so a keepalive can go out while
    // the main loop is blocked waiting for the agent.
    struct Agents {
        file: File,
    }
    impl Backends for Agents {
        fn for_channel(&mut self, cid: u32) -> Box<dyn Backend> {
            // A cloned DESCRIPTOR, deliberately not a second `Device`: see
            // `send_report`. Dropping a `Device` destroys the key.
            let cloned = self.file.try_clone();
            Box::new(AgentBackend::new(Box::new(move || {
                let Ok(file) = &cloned else {
                    return Ok(());
                };
                let mut file = file.try_clone()?;
                for p in Message::new(cid, cmd::KEEPALIVE, vec![hid::keepalive::UPNEEDED])
                    .to_packets()
                {
                    send_report(&mut file, &p)?;
                }
                Ok(())
            })))
        }
    }

    let mut backends = Agents {
        file: device.file.try_clone()?,
    };
    run(&mut device, &mut backends)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor a browser matches on to decide something is a security
    /// key. Getting a byte wrong here produces a device that exists, works at
    /// the HID layer, and is never offered to anybody.
    #[test]
    fn the_report_descriptor_is_the_fido_hid_one() {
        assert_eq!(
            &REPORT_DESCRIPTOR[..5],
            &[0x06, 0xd0, 0xf1, 0x09, 0x01],
            "usage page 0xF1D0, usage 0x01"
        );
        assert_eq!(REPORT_DESCRIPTOR.last(), Some(&0xc0), "end collection");
        // One 64-byte input report and one 64-byte output report.
        let counts: Vec<usize> = REPORT_DESCRIPTOR
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[0] == 0x95)
            .map(|(i, _)| REPORT_DESCRIPTOR[i + 1] as usize)
            .collect();
        assert_eq!(counts, vec![64, 64]);
        assert!(REPORT_DESCRIPTOR.windows(2).any(|w| w == [0x81, 0x02]), "input");
        assert!(REPORT_DESCRIPTOR.windows(2).any(|w| w == [0x91, 0x02]), "output");
    }

    /// The layout the kernel actually reads.
    ///
    /// Every offset here was measured with `offsetof` against
    /// `linux/uhid.h` on this machine. The first version of this code put
    /// `rd_size` after the descriptor instead of before it, and the kernel
    /// answered `EINVAL` and nothing else — because it read a zero-length
    /// descriptor from the wrong two bytes. That is the whole class of bug
    /// this test exists for, and it is invisible to anything but a byte check.
    #[test]
    fn a_create_event_matches_the_measured_kernel_layout() {
        let ev = create_event("Black-Bag", "abcd1234");
        assert_eq!(ev.len(), UHID_EVENT_SIZE, "sizeof(struct uhid_event)");
        assert_eq!(
            u32::from_ne_bytes([ev[0], ev[1], ev[2], ev[3]]),
            UHID_CREATE2
        );

        assert!(ev[C2_NAME..C2_PHYS].starts_with(b"Black-Bag\0"));
        assert!(ev[C2_PHYS..C2_UNIQ].starts_with(b"blackbag\0"));
        assert!(ev[C2_UNIQ..C2_RD_SIZE].starts_with(b"abcd1234\0"));

        assert_eq!(
            u16::from_ne_bytes([ev[C2_RD_SIZE], ev[C2_RD_SIZE + 1]]) as usize,
            REPORT_DESCRIPTOR.len(),
            "rd_size comes BEFORE rd_data, and a zero here is the EINVAL"
        );
        assert_ne!(REPORT_DESCRIPTOR.len(), 0, "and it is never zero");
        assert_eq!(u16::from_ne_bytes([ev[C2_BUS], ev[C2_BUS + 1]]), BUS_USB);
        assert_eq!(
            u32::from_ne_bytes(ev[C2_VENDOR..C2_PRODUCT].try_into().unwrap()),
            0,
            "a vendor id we do not own would be a lie told to every relying party"
        );
        assert_eq!(
            &ev[C2_RD_DATA..C2_RD_DATA + REPORT_DESCRIPTOR.len()],
            REPORT_DESCRIPTOR
        );
        // Nothing spills past the end of the descriptor field. Note the
        // inequality: `create2` ends at 4376 and the event is 4380, because
        // the union is 8-byte aligned — `uhid_start_req` holds a `__u64` — so
        // its size rounds up even though the outer struct is packed. Four
        // bytes of trailing padding, measured rather than assumed.
        assert_eq!(C2_RD_DATA + UHID_DATA_MAX, 4376, "create2 ends here");
    }

    #[test]
    fn an_input_event_carries_one_report_and_its_size() {
        let report = [0x42u8; 64];
        let ev = input_event(&report);
        assert_eq!(ev.len(), UHID_EVENT_SIZE);
        assert_eq!(u32::from_ne_bytes([ev[0], ev[1], ev[2], ev[3]]), UHID_INPUT2);
        assert_eq!(u16::from_ne_bytes([ev[IN2_SIZE], ev[IN2_SIZE + 1]]), 64);
        assert_eq!(&ev[IN2_DATA..IN2_DATA + 64], &report);
    }

    /// The output offsets, which is how a report gets back FROM the kernel.
    /// Wrong here and the device would look alive and answer nothing.
    #[test]
    fn the_output_offsets_are_where_the_kernel_puts_them() {
        assert_eq!(OUT_DATA, 4, "data comes first in uhid_output_req");
        assert_eq!(OUT_SIZE, OUT_DATA + UHID_DATA_MAX, "then its size");
    }

    /// A wire that plays a script of reports in and records what comes out.
    struct Tape {
        incoming: std::collections::VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Wire for Tape {
        fn send(&mut self, report: &[u8]) -> Result<()> {
            self.sent.push(report.to_vec());
            Ok(())
        }
        fn recv(&mut self) -> Result<Option<Vec<u8>>> {
            match self.incoming.pop_front() {
                Some(r) => Ok(Some(r)),
                // The script ran out. An error is how the loop is asked to
                // stop; a test that let it spin would simply hang.
                None => bail!("end of tape"),
            }
        }
    }

    struct Yes;
    impl Backend for Yes {
        fn count_for(&mut self, _rp: &str) -> usize {
            1
        }
        fn holds_any(&mut self, _rp: &str, _ids: &[Vec<u8>]) -> bool {
            false
        }
        fn make_credential(&mut self, _req: &MakeCredential) -> Result<Made, u8> {
            Ok(Made {
                auth_data: vec![0xaa; 37],
                fmt: "none".into(),
            })
        }
        fn get_assertion(&mut self, _req: &GetAssertion) -> Result<Asserted, u8> {
            Ok(Asserted {
                credential_id: vec![1, 2, 3],
                auth_data: vec![0xbb; 37],
                signature: vec![0xcc; 70],
                user_handle: b"ada".to_vec(),
                total: 1,
            })
        }
    }

    struct Always;
    impl Backends for Always {
        fn for_channel(&mut self, _cid: u32) -> Box<dyn Backend> {
            Box::new(Yes)
        }
    }

    /// Reassemble what the device SENT.
    ///
    /// Not `Reassembler`, which models what a device will accept from a host
    /// and so refuses anything but INIT on the broadcast channel. Replies
    /// travel the other way, and a malformed INIT is legitimately answered
    /// with an error on the broadcast channel — using the request-side rules
    /// here silently swallowed exactly that reply.
    fn decode_replies(packets: &[Vec<u8>]) -> Vec<Message> {
        let mut out: Vec<Message> = Vec::new();
        let mut open: std::collections::HashMap<u32, (u8, usize, Vec<u8>)> =
            std::collections::HashMap::new();
        for p in packets {
            let cid = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
            if p[4] & 0x80 != 0 {
                let cmd = p[4] & 0x7f;
                let len = ((p[5] as usize) << 8) | p[6] as usize;
                let have = len.min(p.len() - 7);
                let data = p[7..7 + have].to_vec();
                if have == len {
                    out.push(Message::new(cid, cmd, data));
                } else {
                    open.insert(cid, (cmd, len, data));
                }
            } else {
                let complete = match open.get_mut(&cid) {
                    Some((_, len, data)) => {
                        let want = *len - data.len();
                        let have = want.min(p.len() - 5);
                        data.extend_from_slice(&p[5..5 + have]);
                        data.len() == *len
                    }
                    None => false,
                };
                if complete {
                    let (cmd, _, data) = open.remove(&cid).expect("just completed");
                    out.push(Message::new(cid, cmd, data));
                }
            }
        }
        out
    }

    /// Play a script through the loop and collect the messages that came back.
    fn play(messages: Vec<Message>) -> Vec<Message> {
        let mut tape = Tape {
            incoming: messages
                .iter()
                .flat_map(|m| m.to_packets())
                .map(|p| p.to_vec())
                .collect(),
            sent: Vec::new(),
        };
        // Ends with "end of tape", which is how the script says stop.
        let _ = run(&mut tape, &mut Always);
        decode_replies(&tape.sent)
    }

    /// The handshake every client does first. Without a correct INIT nothing
    /// else is ever attempted, so this is the one that decides whether the
    /// device is usable at all.
    #[test]
    fn init_answers_with_the_nonce_a_new_channel_and_the_capabilities() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let out = play(vec![Message::new(
            hid::BROADCAST_CID,
            cmd::INIT,
            nonce.to_vec(),
        )]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cmd, cmd::INIT);
        assert_eq!(&out[0].data[..8], &nonce, "the nonce comes back unchanged");

        let cid = u32::from_be_bytes([out[0].data[8], out[0].data[9], out[0].data[10], out[0].data[11]]);
        assert_ne!(cid, 0);
        assert_ne!(cid, hid::BROADCAST_CID);

        let caps = out[0].data[16];
        assert_eq!(caps & hid::capability::CBOR, hid::capability::CBOR, "CTAP2");
        assert_eq!(
            caps & hid::capability::NMSG,
            hid::capability::NMSG,
            "and NOT U2F, which is what NMSG says"
        );
    }

    #[test]
    fn a_short_init_is_refused_rather_than_answered_with_rubbish() {
        let out = play(vec![Message::new(hid::BROADCAST_CID, cmd::INIT, vec![1, 2, 3])]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cmd, cmd::ERROR);
        assert_eq!(out[0].data, vec![err::INVALID_LEN]);
    }

    /// PING is what a client uses to size the transport. It has to come back
    /// byte for byte at every length, including the ones that span packets.
    #[test]
    fn ping_comes_back_unchanged_at_every_length() {
        for len in [0usize, 1, 57, 58, 64, 200, 1000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let out = play(vec![Message::new(4, cmd::PING, payload.clone())]);
            assert_eq!(out.len(), 1, "at length {len}");
            assert_eq!(out[0].cmd, cmd::PING);
            assert_eq!(out[0].data, payload, "ping altered the payload at {len}");
        }
    }

    #[test]
    fn get_info_comes_back_over_the_wire() {
        let out = play(vec![Message::new(
            4,
            cmd::CBOR,
            vec![cbor::command::GET_INFO],
        )]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cmd, cmd::CBOR);
        assert_eq!(out[0].data[0], status::OK);
        let parsed: ciborium::value::Value =
            ciborium::de::from_reader(&out[0].data[1..]).expect("a CBOR body");
        let ciborium::value::Value::Map(entries) = parsed else {
            panic!("getInfo is a map")
        };
        assert!(!entries.is_empty());
    }

    #[test]
    fn a_cbor_payload_that_does_not_parse_is_refused_not_ignored() {
        let out = play(vec![Message::new(
            4,
            cmd::CBOR,
            vec![cbor::command::MAKE_CREDENTIAL, 0xff],
        )]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, vec![status::INVALID_CBOR]);
    }

    /// U2F is not implemented, and the INIT capabilities say so. A client that
    /// asks anyway gets an answer rather than silence, so it can fall back.
    #[test]
    fn a_u2f_message_is_refused_and_the_capabilities_already_said_so() {
        let out = play(vec![Message::new(4, cmd::MSG, vec![0; 10])]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cmd, cmd::ERROR);
        assert_eq!(out[0].data, vec![err::INVALID_CMD]);
    }

    #[test]
    fn wink_is_answered_and_cancel_is_not() {
        let out = play(vec![
            Message::new(4, cmd::WINK, Vec::new()),
            Message::new(4, cmd::CANCEL, Vec::new()),
        ]);
        assert_eq!(out.len(), 1, "cancel gets no reply of its own");
        assert_eq!(out[0].cmd, cmd::WINK);
    }

    #[test]
    fn an_unknown_command_is_answered_with_an_error() {
        let out = play(vec![Message::new(4, 0x77, vec![1, 2, 3])]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cmd, cmd::ERROR);
        assert_eq!(out[0].data, vec![err::INVALID_CMD]);
    }

    /// Two clients on two channels, interleaved packet by packet. This is the
    /// case a single-channel implementation passes every other test without
    /// noticing it fails.
    #[test]
    fn two_channels_are_answered_on_their_own_channels() {
        let a = Message::new(11, cmd::PING, vec![0xaa; 200]);
        let b = Message::new(22, cmd::PING, vec![0xbb; 200]);
        let pa = a.to_packets();
        let pb = b.to_packets();

        let mut incoming = std::collections::VecDeque::new();
        for i in 0..pa.len() {
            incoming.push_back(pa[i].to_vec());
            incoming.push_back(pb[i].to_vec());
        }
        let mut tape = Tape {
            incoming,
            sent: Vec::new(),
        };
        let _ = run(&mut tape, &mut Always);

        let out = decode_replies(&tape.sent);
        assert_eq!(out.len(), 2);
        let first = out.iter().find(|m| m.cid == 11).expect("channel 11");
        let second = out.iter().find(|m| m.cid == 22).expect("channel 22");
        assert_eq!(first.data, vec![0xaa; 200]);
        assert_eq!(second.data, vec![0xbb; 200]);
    }

    /// A framing error is reported on the channel it happened on, and the loop
    /// keeps going rather than falling over.
    #[test]
    fn a_framing_error_is_reported_and_the_loop_survives_it() {
        let mut bad = [0u8; hid::PACKET];
        bad[..4].copy_from_slice(&9u32.to_be_bytes());
        bad[4] = cmd::CBOR | 0x80;
        bad[5] = 0xff;
        bad[6] = 0xff; // a length far over the ceiling

        let good = Message::new(9, cmd::PING, vec![7; 4]).to_packets();
        let mut tape = Tape {
            incoming: vec![bad.to_vec(), good[0].to_vec()].into(),
            sent: Vec::new(),
        };
        let _ = run(&mut tape, &mut Always);

        let out = decode_replies(&tape.sent);
        assert_eq!(out.len(), 2, "the error, and then the ping that followed it");
        assert_eq!(out[0].cmd, cmd::ERROR);
        assert_eq!(out[0].data, vec![err::INVALID_LEN]);
        assert_eq!(out[1].cmd, cmd::PING);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x00, 0x01, 0x7f, 0x80, 0xff];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_err(), "odd length is not hex");
        assert!(unhex("zz").is_err());
    }
}
