//! A FIDO2 authenticator that is not a piece of plastic.
//!
//! Lane B of the passkey work: instead of asking a browser to route WebAuthn
//! through an extension, present a **virtual FIDO2 device** to the kernel and
//! let every browser and every application talk to it the way they already
//! talk to a security key. Nothing has to know Black-Bag exists.
//!
//! ## What this buys, and what it costs
//!
//! It works with no extension, in Electron applications, in Firefox, and with
//! `ssh -sk`. It is the widest reach available on Linux.
//!
//! It also changes who binds the origin, and that has to be said plainly.
//! On lane A the browser hands us the caller origin and **the agent builds
//! `clientDataJSON` itself**, so the origin a person approves and the origin
//! the relying party verifies are the same string by construction. CTAP has no
//! such field: an authenticator is given a relying-party id and a
//! *clientDataHash*, and cannot see what was hashed. So on this lane the
//! browser binds the origin, exactly as it does for a hardware key — no worse
//! than the plastic, and no better. The consent screen can name the relying
//! party and must not pretend to name an origin.
//!
//! ## Layering
//!
//! - [`hid`] — CTAPHID framing: 64-byte packets, channels, transactions.
//!   Knows nothing about credentials.
//! - [`cbor`] — the CTAP2 request and response encodings.
//! - [`authenticator`] — the commands, answered from the vault through the
//!   same consent desk every other surface uses.
//!
//! The device itself lives in the CLI, because `/dev/uhid` is a machine
//! resource rather than a vault one. Everything here is testable without it,
//! and is tested without it.

pub mod authenticator;
pub mod cbor;
pub mod hid;
