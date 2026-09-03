//! CTAPHID framing — CTAP 2.1 §11.2.
//!
//! A HID report is 64 bytes and a CTAP message is not, so messages are split
//! across an initialisation packet and as many continuation packets as it
//! takes. This module does that and nothing else: it never looks inside a
//! message, so it can be tested exhaustively without a vault, a device, or a
//! browser.
//!
//! ```text
//! init packet:  CID(4) | CMD(1, top bit set) | BCNTH(1) | BCNTL(1) | data(57)
//! cont packet:  CID(4) | SEQ(1, top bit clear)          | data(59)
//! ```
//!
//! The parts that bite, all of which have tests below:
//!
//! - **Sequence numbers are checked.** A continuation that arrives out of
//!   order aborts the transaction rather than assembling a message that was
//!   never sent.
//! - **A second init packet on a busy channel is an error**, not a restart.
//!   Silently restarting would let one caller cancel another's transaction by
//!   guessing its channel.
//! - **Length is bounded** before anything is allocated.
//! - **Channel 0 is never allocated**, and the broadcast channel is only ever
//!   valid for INIT.

use std::collections::HashMap;

/// One HID report. Fixed by the report descriptor and by the specification.
pub const PACKET: usize = 64;
/// The most a CTAPHID message may carry, per §11.2.4.
pub const MAX_MESSAGE: usize = 7609;

pub const BROADCAST_CID: u32 = 0xffff_ffff;

/// CTAPHID commands. The top bit marks an initialisation packet on the wire
/// and is not part of the command.
pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3b;
    pub const ERROR: u8 = 0x3f;
}

/// CTAPHID error codes, §11.2.9.1.6.
pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const INVALID_CHANNEL: u8 = 0x0b;
    pub const OTHER: u8 = 0x7f;
}

/// Keepalive status bytes, §11.2.9.1.5.
pub mod keepalive {
    pub const PROCESSING: u8 = 1;
    pub const UPNEEDED: u8 = 2;
}

/// Capability bits in an INIT response.
pub mod capability {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    /// Set when the authenticator does NOT implement the U2F message command.
    pub const NMSG: u8 = 0x08;
}

/// A complete message, reassembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub data: Vec<u8>,
}

impl Message {
    pub fn new(cid: u32, cmd: u8, data: Vec<u8>) -> Self {
        Self { cid, cmd, data }
    }

    /// Split into wire packets, padded to 64 bytes each.
    ///
    /// Padding is required: a HID report is a fixed size, and a short write is
    /// a protocol error rather than a short report.
    pub fn to_packets(&self) -> Vec<[u8; PACKET]> {
        let mut out = Vec::new();
        let mut p = [0u8; PACKET];
        p[..4].copy_from_slice(&self.cid.to_be_bytes());
        p[4] = self.cmd | 0x80;
        let len = self.data.len().min(MAX_MESSAGE);
        p[5] = (len >> 8) as u8;
        p[6] = (len & 0xff) as u8;
        let first = len.min(PACKET - 7);
        p[7..7 + first].copy_from_slice(&self.data[..first]);
        out.push(p);

        let mut sent = first;
        let mut seq: u8 = 0;
        while sent < len {
            let mut c = [0u8; PACKET];
            c[..4].copy_from_slice(&self.cid.to_be_bytes());
            c[4] = seq & 0x7f;
            let n = (len - sent).min(PACKET - 5);
            c[5..5 + n].copy_from_slice(&self.data[sent..sent + n]);
            out.push(c);
            sent += n;
            seq = seq.wrapping_add(1);
        }
        out
    }
}

/// What a packet meant.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing to do yet: more packets are expected.
    Continue,
    /// A whole message arrived.
    Done(Message),
    /// Refuse this, with a CTAPHID error on the given channel.
    Error { cid: u32, code: u8 },
}

#[derive(Debug)]
struct Partial {
    cmd: u8,
    expect: usize,
    data: Vec<u8>,
    next_seq: u8,
}

/// Reassembles packets into messages, one transaction per channel.
#[derive(Debug, Default)]
pub struct Reassembler {
    open: HashMap<u32, Partial>,
    next_cid: u32,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            open: HashMap::new(),
            next_cid: 0,
        }
    }

    /// Allocate a channel for an INIT.
    ///
    /// Never returns 0 (reserved) or the broadcast channel: §11.2.9.1.3 makes
    /// both invalid as a real channel id, and handing one out would produce a
    /// device that talks to itself.
    pub fn allocate(&mut self) -> u32 {
        loop {
            self.next_cid = self.next_cid.wrapping_add(1);
            if self.next_cid != 0 && self.next_cid != BROADCAST_CID {
                return self.next_cid;
            }
        }
    }

    /// Abandon a channel's transaction. CTAPHID_CANCEL, and the way a
    /// finished transaction is cleared.
    pub fn cancel(&mut self, cid: u32) {
        self.open.remove(&cid);
    }

    pub fn is_busy(&self, cid: u32) -> bool {
        self.open.contains_key(&cid)
    }

    /// Feed one 64-byte report.
    pub fn push(&mut self, packet: &[u8]) -> Step {
        if packet.len() < 7 {
            // Too short to carry a header. There is no channel to answer on,
            // so there is nothing to say.
            return Step::Continue;
        }
        let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        if cid == 0 {
            return Step::Error {
                cid,
                code: err::INVALID_CHANNEL,
            };
        }
        let byte = packet[4];

        if byte & 0x80 != 0 {
            let cmd = byte & 0x7f;
            // CANCEL and INIT are the two things allowed to interrupt.
            if cmd == cmd::CANCEL {
                self.open.remove(&cid);
                return Step::Done(Message::new(cid, cmd, Vec::new()));
            }
            if self.open.contains_key(&cid) && cmd != cmd::INIT {
                // §11.2.4: a channel with a transaction in flight is busy. NOT
                // a silent restart — that would let anyone who guessed a
                // channel id abandon somebody else's ceremony.
                return Step::Error {
                    cid,
                    code: err::CHANNEL_BUSY,
                };
            }
            let expect = ((packet[5] as usize) << 8) | packet[6] as usize;
            if expect > MAX_MESSAGE {
                return Step::Error {
                    cid,
                    code: err::INVALID_LEN,
                };
            }
            if cid == BROADCAST_CID && cmd != cmd::INIT {
                // The broadcast channel exists to ask for a channel. Nothing
                // else may be said on it.
                return Step::Error {
                    cid,
                    code: err::INVALID_CHANNEL,
                };
            }
            let have = expect.min(packet.len() - 7);
            let data = packet[7..7 + have].to_vec();
            if have == expect {
                self.open.remove(&cid);
                return Step::Done(Message::new(cid, cmd, data));
            }
            self.open.insert(
                cid,
                Partial {
                    cmd,
                    expect,
                    data,
                    next_seq: 0,
                },
            );
            Step::Continue
        } else {
            let seq = byte & 0x7f;
            let Some(part) = self.open.get_mut(&cid) else {
                // A continuation for a channel with nothing in flight. Ignored
                // rather than answered: it may well be the tail of a
                // transaction that was already cancelled, and replying would
                // turn stale traffic into errors.
                return Step::Continue;
            };
            if seq != part.next_seq {
                self.open.remove(&cid);
                return Step::Error {
                    cid,
                    code: err::INVALID_SEQ,
                };
            }
            part.next_seq = part.next_seq.wrapping_add(1) & 0x7f;
            let want = part.expect - part.data.len();
            let have = want.min(packet.len() - 5);
            part.data.extend_from_slice(&packet[5..5 + have]);
            if part.data.len() == part.expect {
                let done = self.open.remove(&cid).expect("just checked");
                return Step::Done(Message::new(cid, done.cmd, done.data));
            }
            Step::Continue
        }
    }
}

/// The INIT response body: nonce, new channel, versions, capabilities.
pub fn init_response(nonce: &[u8], cid: u32, capabilities: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&cid.to_be_bytes());
    out.push(2); // CTAPHID protocol version
    out.push(env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0));
    out.push(env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0));
    out.push(env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0));
    out.push(capabilities);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(len: usize) {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let msg = Message::new(0x1234_5678, cmd::CBOR, data.clone());
        let packets = msg.to_packets();
        for p in &packets {
            assert_eq!(p.len(), PACKET, "every report is exactly 64 bytes");
        }
        let mut r = Reassembler::new();
        let mut got = None;
        for p in &packets {
            match r.push(p) {
                Step::Continue => {}
                Step::Done(m) => got = Some(m),
                other => panic!("unexpected {other:?} at length {len}"),
            }
        }
        let got = got.unwrap_or_else(|| panic!("no message came back at length {len}"));
        assert_eq!(got.cid, 0x1234_5678);
        assert_eq!(got.cmd, cmd::CBOR);
        assert_eq!(got.data, data, "payload survived the split at length {len}");
    }

    /// Every length across both packet boundaries, one by one. Off-by-one in
    /// the split is the classic framing bug and it hides everywhere except at
    /// the boundary itself.
    #[test]
    fn a_message_of_any_length_survives_the_round_trip() {
        for len in 0..200 {
            round_trip(len);
        }
        for len in [PACKET - 7, PACKET - 6, 57, 58, 116, 117, 1024, MAX_MESSAGE] {
            round_trip(len);
        }
    }

    #[test]
    fn a_continuation_out_of_order_aborts_rather_than_assembling() {
        let msg = Message::new(7, cmd::CBOR, vec![0xab; 300]);
        let mut packets = msg.to_packets();
        assert!(packets.len() > 3);
        packets.swap(1, 2);

        let mut r = Reassembler::new();
        let mut saw_error = false;
        for p in &packets {
            if let Step::Error { code, .. } = r.push(p) {
                assert_eq!(code, err::INVALID_SEQ);
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "a shuffled continuation must not assemble");
    }

    #[test]
    fn a_second_init_packet_on_a_busy_channel_is_refused() {
        let msg = Message::new(9, cmd::CBOR, vec![1; 300]);
        let packets = msg.to_packets();
        let mut r = Reassembler::new();
        assert_eq!(r.push(&packets[0]), Step::Continue);

        // Somebody else's PING arriving mid-transaction.
        let intruder = Message::new(9, cmd::PING, vec![2; 4]).to_packets();
        assert_eq!(
            r.push(&intruder[0]),
            Step::Error {
                cid: 9,
                code: err::CHANNEL_BUSY
            },
            "a busy channel must not be silently restarted by whoever asks second"
        );
    }

    #[test]
    fn cancel_clears_the_channel_and_is_itself_delivered() {
        let msg = Message::new(11, cmd::CBOR, vec![1; 300]);
        let packets = msg.to_packets();
        let mut r = Reassembler::new();
        r.push(&packets[0]);
        assert!(r.is_busy(11));

        let cancel = Message::new(11, cmd::CANCEL, Vec::new()).to_packets();
        assert_eq!(
            r.push(&cancel[0]),
            Step::Done(Message::new(11, cmd::CANCEL, Vec::new()))
        );
        assert!(!r.is_busy(11), "cancel abandons the transaction");
    }

    #[test]
    fn an_overlong_message_is_refused_before_anything_is_allocated() {
        let mut p = [0u8; PACKET];
        p[..4].copy_from_slice(&5u32.to_be_bytes());
        p[4] = cmd::CBOR | 0x80;
        p[5] = 0xff;
        p[6] = 0xff; // 65535, far over the 7609 ceiling
        let mut r = Reassembler::new();
        assert_eq!(
            r.push(&p),
            Step::Error {
                cid: 5,
                code: err::INVALID_LEN
            }
        );
        assert!(!r.is_busy(5));
    }

    #[test]
    fn channel_zero_is_never_valid() {
        let mut r = Reassembler::new();
        let p = Message::new(0, cmd::PING, vec![1]).to_packets();
        assert_eq!(
            r.push(&p[0]),
            Step::Error {
                cid: 0,
                code: err::INVALID_CHANNEL
            }
        );
    }

    #[test]
    fn the_broadcast_channel_carries_nothing_but_init() {
        let mut r = Reassembler::new();
        let ping = Message::new(BROADCAST_CID, cmd::PING, vec![1]).to_packets();
        assert_eq!(
            r.push(&ping[0]),
            Step::Error {
                cid: BROADCAST_CID,
                code: err::INVALID_CHANNEL
            }
        );
        let init = Message::new(BROADCAST_CID, cmd::INIT, vec![9; 8]).to_packets();
        assert!(matches!(r.push(&init[0]), Step::Done(_)));
    }

    #[test]
    fn allocated_channels_are_never_zero_or_broadcast() {
        let mut r = Reassembler::new();
        r.next_cid = BROADCAST_CID - 1;
        let seen: Vec<u32> = (0..4).map(|_| r.allocate()).collect();
        for cid in &seen {
            assert_ne!(*cid, 0);
            assert_ne!(*cid, BROADCAST_CID);
        }
        // And it kept moving rather than sticking at the wrap.
        assert_eq!(seen.len(), 4);
        assert!(seen.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn a_stray_continuation_is_ignored_rather_than_answered() {
        let mut r = Reassembler::new();
        let mut c = [0u8; PACKET];
        c[..4].copy_from_slice(&3u32.to_be_bytes());
        c[4] = 0; // seq 0, no transaction open
        assert_eq!(r.push(&c), Step::Continue);
    }

    #[test]
    fn two_channels_interleave_without_mixing() {
        let a = Message::new(1, cmd::CBOR, vec![0xaa; 200]).to_packets();
        let b = Message::new(2, cmd::CBOR, vec![0xbb; 200]).to_packets();
        assert_eq!(a.len(), b.len());

        let mut r = Reassembler::new();
        let mut done: Vec<Message> = Vec::new();
        for i in 0..a.len() {
            for step in [r.push(&a[i]), r.push(&b[i])] {
                if let Step::Done(m) = step {
                    done.push(m);
                }
            }
        }
        assert_eq!(done.len(), 2);
        let one = done.iter().find(|m| m.cid == 1).expect("channel 1");
        let two = done.iter().find(|m| m.cid == 2).expect("channel 2");
        assert_eq!(one.data, vec![0xaa; 200]);
        assert_eq!(two.data, vec![0xbb; 200]);
    }

    #[test]
    fn an_init_response_says_what_it_can_do() {
        let body = init_response(&[1, 2, 3, 4, 5, 6, 7, 8], 0x0102_0304, capability::CBOR);
        assert_eq!(&body[..8], &[1, 2, 3, 4, 5, 6, 7, 8], "the nonce comes back");
        assert_eq!(&body[8..12], &[1, 2, 3, 4], "then the new channel");
        assert_eq!(body[12], 2, "CTAPHID protocol version 2");
        assert_eq!(body[16], capability::CBOR);
        assert_eq!(body.len(), 17);
    }
}
