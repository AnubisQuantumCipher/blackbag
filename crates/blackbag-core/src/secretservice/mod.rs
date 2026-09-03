//! The freedesktop Secret Service, backed by the vault.
//!
//! `org.freedesktop.secrets` is the D-Bus API that applications — browsers,
//! mail clients, anything using libsecret — call to stash and fetch secrets.
//! This lets the vault BE that store, so those secrets live encrypted in
//! Black-Bag and are released through the same consent as everything else,
//! instead of sitting in whatever the desktop's default keyring is.
//!
//! ## Layering, and why the crypto is here and the bus is not
//!
//! The parts with no D-Bus in them — the session encryption a client
//! negotiates — live here and are tested here, without a bus. The D-Bus object
//! tree lives in the CLI daemon next to the other surfaces.
//!
//! ## One name, one owner
//!
//! Only one process may own `org.freedesktop.secrets` on a session bus. On a
//! desktop that already runs gnome-keyring or kwallet, going live means telling
//! that one to stop serving secrets first — a deliberate, stated step, the same
//! shape as "disable the other passkey extension". Nothing here does that to a
//! live bus; the daemon binds whatever bus it is pointed at.

/// The record tag that marks a vault record as a Secret Service item, so the
/// service only ever serves and mutates items it created — never your ordinary
/// logins, which an application must not be able to read or overwrite through
/// this door.
pub const SECRET_SERVICE_TAG: &str = "secret-service";

/// The secret field on such a record.
pub const SECRET_SERVICE_FIELD: &str = "secret";

/// The client identity every Secret Service read approval is keyed under — the
/// deck approves, the D-Bus daemon reads, two processes meeting at one grant.
pub const SECRET_SERVICE_CLIENT: &str = "secret-service";

pub mod session;
