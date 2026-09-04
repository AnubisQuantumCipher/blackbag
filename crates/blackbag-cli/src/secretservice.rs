//! The `org.freedesktop.secrets` D-Bus service, backed by the vault.
//!
//! Applications that use libsecret — `secret-tool`, browsers, mail clients —
//! talk to this instead of gnome-keyring, so the secrets they store live in the
//! vault and are released through Black-Bag's own consent.
//!
//! ## What it exposes, and what it does not
//!
//! A single collection, `default`, holding only items THIS service created.
//! Your ordinary logins and passkeys are never exposed here: an application
//! must not be able to read or overwrite your real passwords through a door
//! meant for its own scratch secrets. Reading an item costs a first-use
//! approval in the deck, remembered until the vault locks — the `Reveal` model.
//!
//! ## Sessions
//!
//! `OpenSession` supports both `plain` and
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`; the crypto is in
//! `blackbag_core::secretservice::session` and tested there.
//!
//! ## The daemon holds no keys
//!
//! Like the SSH agent and the FIDO2 key, this is a thin front end that asks the
//! vault agent over its socket. The vault does the storing, the signing-off,
//! and the consent.

use anyhow::{Context, Result, anyhow, bail};
use blackbag_core::secretservice::session::{Opened, Session};
use blackbag_core::session::{self, Request as AgentRequest, Response, SecretItemView};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{connection, interface};

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/default";
const ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";

/// How long a first-use read blocks while the deck shows the approval. Under
/// the D-Bus default method timeout (25s), so libsecret sees a normal return.
const APPROVAL_WAIT: Duration = Duration::from_secs(20);
const POLL_EVERY: Duration = Duration::from_millis(200);

/// A D-Bus Secret: `(session, parameters, value, content_type)`.
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// A vault item id (a UUID) as a D-Bus path element: hyphens are not allowed in
/// a path, so they become underscores. UUIDs contain no underscores, so it
/// reverses cleanly.
fn item_path(id: &str) -> String {
    format!("{COLLECTION_PATH}/{}", id.replace('-', "_"))
}
fn id_from_path(path: &str) -> Option<String> {
    path.strip_prefix(&format!("{COLLECTION_PATH}/"))
        .map(|e| e.replace('_', "-"))
}

/// Ask the vault agent, off the async runtime so a blocking socket read never
/// stalls the D-Bus connection.
async fn ask(request: AgentRequest) -> Result<Response> {
    tokio::task::spawn_blocking(move || session::ask(&request))
        .await
        .map_err(|e| anyhow!("agent call panicked: {e}"))?
}

fn list_items() -> Result<Vec<SecretItemView>> {
    match session::ask(&AgentRequest::SecretList)? {
        Response::SecretItems { items } => Ok(items),
        Response::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// Whether an item's attributes contain every (key,value) the query asks for.
fn matches(item: &SecretItemView, query: &HashMap<String, String>) -> bool {
    query.iter().all(|(k, v)| {
        item.attributes
            .iter()
            .any(|(ik, iv)| ik == k && iv == v)
    })
}

/// The item a `CreateItem(replace=true)` should overwrite, if any.
///
/// `matches`/`search` is a *subset* test — every query pair present on the item
/// — which is what SearchItems wants but is wrong for replace: an empty
/// attribute set matches every item, and a partial set matches any item that
/// merely has those attributes among more, so a client could overwrite an
/// unrelated app's secret. Replace is therefore gated on an EXACT attribute-set
/// match, and never fires on an empty set.
fn replacement_target<'a>(
    items: &'a [SecretItemView],
    attributes: &HashMap<String, String>,
) -> Option<&'a SecretItemView> {
    if attributes.is_empty() {
        return None;
    }
    items.iter().find(|it| {
        it.attributes.len() == attributes.len()
            && it
                .attributes
                .iter()
                .all(|(k, v)| attributes.get(k) == Some(v))
    })
}

// ── the live sessions ──────────────────────────────────────────────────────

/// Sessions opened by clients, by their object path. Encryption state lives
/// here; a `Secret` names its session so we know how to decrypt it.
#[derive(Default)]
struct Sessions {
    map: HashMap<String, Session>,
    next: AtomicU64,
}

static SESSIONS: Mutex<Option<Sessions>> = Mutex::new(None);

fn sessions() -> std::sync::MutexGuard<'static, Option<Sessions>> {
    let mut g = SESSIONS.lock().unwrap();
    if g.is_none() {
        *g = Some(Sessions::default());
    }
    g
}

// ── org.freedesktop.Secret.Service ───────────────────────────────────────────

struct ServiceIface;

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceIface {
    /// Negotiate a session. `plain` or `dh-...`; an unknown algorithm is an
    /// error so the client retries.
    async fn open_session(
        &self,
        algorithm: String,
        input: Value<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let input_bytes: Vec<u8> = match &input {
            Value::Array(_) => Vec::<u8>::try_from(input.try_clone().unwrap()).unwrap_or_default(),
            _ => Vec::new(),
        };
        let Opened { session, output } = Session::open(&algorithm, &input_bytes)
            .map_err(|e| zbus::fdo::Error::NotSupported(e.to_string()))?;

        let path = {
            let mut guard = sessions();
            let s = guard.as_mut().unwrap();
            let n = s.next.fetch_add(1, Ordering::Relaxed);
            let path = format!("{SERVICE_PATH}/session/s{n}");
            s.map.insert(path.clone(), session);
            path
        };
        // Serve a Session object so the client's Close() has something to reach.
        let _ = object_server
            .at(path.as_str(), SessionIface { path: path.clone() })
            .await;

        let out = OwnedValue::try_from(Value::from(output))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok((out, OwnedObjectPath::try_from(path).unwrap()))
    }

    /// One collection, always present, never created on demand.
    async fn create_collection(
        &self,
        _properties: HashMap<String, OwnedValue>,
        _alias: String,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        Ok((
            OwnedObjectPath::try_from(COLLECTION_PATH).unwrap(),
            OwnedObjectPath::try_from("/").unwrap(),
        ))
    }

    /// Items matching the attributes, split into unlocked and locked. An item
    /// is "locked" only when the vault is; the per-item read approval is not
    /// modelled as a lock, it is taken at GetSecret.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let (items, unlocked) = search(&attributes).await?;
        let paths: Vec<OwnedObjectPath> = items
            .iter()
            .map(|i| OwnedObjectPath::try_from(item_path(&i.id)).unwrap())
            .collect();
        if unlocked {
            Ok((paths, Vec::new()))
        } else {
            Ok((Vec::new(), paths))
        }
    }

    /// Unlock. The vault's lock is the deck's business, not an app's, so when
    /// the vault is locked this returns the objects as still-locked with no
    /// prompt; when it is unlocked, everything asked for is already usable.
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let unlocked = vault_unlocked().await;
        let no_prompt = OwnedObjectPath::try_from("/").unwrap();
        if unlocked {
            Ok((objects, no_prompt))
        } else {
            Ok((Vec::new(), no_prompt))
        }
    }

    async fn lock(
        &self,
        _objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        // Locking the vault is a deliberate act taken in the deck (or on
        // suspend), not something an application does. Report nothing locked.
        Ok((Vec::new(), OwnedObjectPath::try_from("/").unwrap()))
    }

    /// Read several secrets at once. Each read is consent-gated; a refusal drops
    /// that one item from the result rather than failing the whole call.
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let mut out = HashMap::new();
        for item in items {
            if let Some(id) = id_from_path(item.as_str()) {
                if let Ok(secret) = read_secret(&id, &session).await {
                    out.insert(item, secret);
                }
            }
        }
        Ok(out)
    }

    async fn read_alias(&self, name: String) -> zbus::fdo::Result<OwnedObjectPath> {
        if name == "default" {
            Ok(OwnedObjectPath::try_from(COLLECTION_PATH).unwrap())
        } else {
            Ok(OwnedObjectPath::try_from("/").unwrap())
        }
    }

    async fn set_alias(&self, _name: String, _collection: OwnedObjectPath) -> zbus::fdo::Result<()> {
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![OwnedObjectPath::try_from(COLLECTION_PATH).unwrap()]
    }
}

// ── org.freedesktop.Secret.Collection ────────────────────────────────────────


/// Read one `a{sv}` property, distinguishing "absent" from "unreadable".
///
/// An absent property is the caller declining to set it and yields the type's
/// default. A property that is present but cannot be converted to its declared
/// type is a caller error, and answering it with a default silently stores
/// something the caller did not ask for.
fn read_property<T>(
    properties: &HashMap<String, OwnedValue>,
    name: &str,
) -> zbus::fdo::Result<T>
where
    T: Default + TryFrom<OwnedValue>,
{
    match properties.get(name) {
        None => Ok(T::default()),
        Some(value) => value
            .try_clone()
            .ok()
            .and_then(|owned| T::try_from(owned).ok())
            .ok_or_else(|| {
                zbus::fdo::Error::InvalidArgs(format!(
                    "{name} was set but could not be read as its declared type"
                ))
            }),
    }
}

struct CollectionIface;

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionIface {
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let (items, _) = search(&attributes).await?;
        Ok(items
            .iter()
            .map(|i| OwnedObjectPath::try_from(item_path(&i.id)).unwrap())
            .collect())
    }

    /// Store a secret. `replace` true and a matching item exists → overwrite it,
    /// which is what libsecret's "store" does.
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        // `a{sv}` is the spec's own extension point, so a property a client
        // never set is legitimate and defaults. A property that IS set and
        // cannot be read as its declared type is not: silently defaulting it
        // stored an item under a label or an attribute set the caller never
        // asked for. Attributes matter most — `replace` below is gated on an
        // exact attribute-set match, so an emptied set changes which item a
        // store overwrites, and an item stored with no attributes is one
        // nothing can look up again.
        let label = read_property::<String>(
            &properties, "org.freedesktop.Secret.Item.Label")?;
        let attributes = read_property::<HashMap<String, String>>(
            &properties, "org.freedesktop.Secret.Item.Attributes")?;

        let value = decrypt_secret(&secret)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // Overwrite an existing item with the SAME attributes when asked. See
        // `replacement_target`: `search` is a subset match (right for
        // SearchItems, wrong for replace), so replace is gated on an exact
        // attribute-set match to keep one client from clobbering another's item.
        let mut existing_id = String::new();
        if replace {
            if let Ok((items, _)) = search(&attributes).await {
                if let Some(exact) = replacement_target(&items, &attributes) {
                    existing_id = exact.id.clone();
                }
            }
        }

        let attrs: Vec<(String, String)> = attributes.into_iter().collect();
        let saved = ask(AgentRequest::SecretPut {
            id: existing_id,
            label,
            attributes: attrs,
            secret: value,
        })
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let id = match saved {
            Response::Saved { id } => id,
            Response::Error { message } => return Err(zbus::fdo::Error::Failed(message)),
            other => return Err(zbus::fdo::Error::Failed(format!("{other:?}"))),
        };
        // Register the item object NOW, so the path we hand back resolves the
        // instant the client uses it — not after the background poll notices.
        let path = item_path(&id);
        let _ = object_server
            .at(path.as_str(), ItemIface { id: id.clone() })
            .await;
        Ok((
            OwnedObjectPath::try_from(path).unwrap(),
            OwnedObjectPath::try_from("/").unwrap(),
        ))
    }

    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        // Deleting the whole collection would empty the vault of its Secret
        // Service items; not something an app gets to do.
        Err(zbus::fdo::Error::NotSupported(
            "the Black-Bag collection cannot be deleted through the Secret Service".into(),
        ))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        list_items()
            .unwrap_or_default()
            .iter()
            .map(|i| OwnedObjectPath::try_from(item_path(&i.id)).unwrap())
            .collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        "Black-Bag".into()
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        !vault_unlocked().await
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }
}

// ── org.freedesktop.Secret.Item ──────────────────────────────────────────────

struct ItemIface {
    id: String,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemIface {
    async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<SecretStruct> {
        read_secret(&self.id, &session)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    async fn set_secret(&self, secret: SecretStruct) -> zbus::fdo::Result<()> {
        let value = decrypt_secret(&secret)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let item = current_item(&self.id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        ask(AgentRequest::SecretPut {
            id: self.id.clone(),
            label: item.label,
            attributes: item.attributes,
            secret: value,
        })
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        ask(AgentRequest::SecretDelete { id: self.id.clone() })
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        !vault_unlocked().await
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        current_item(&self.id)
            .await
            .map(|i| i.attributes.into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        current_item(&self.id).await.map(|i| i.label).unwrap_or_default()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        current_item(&self.id).await.map(|i| i.created.max(0) as u64).unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        current_item(&self.id).await.map(|i| i.modified.max(0) as u64).unwrap_or(0)
    }
}

// ── org.freedesktop.Secret.Session ───────────────────────────────────────────

struct SessionIface {
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionIface {
    async fn close(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<()> {
        if let Some(s) = sessions().as_mut() {
            s.map.remove(&self.path);
        }
        let _ = object_server
            .remove::<SessionIface, _>(self.path.as_str())
            .await;
        Ok(())
    }
}

// ── shared helpers ───────────────────────────────────────────────────────────

async fn vault_unlocked() -> bool {
    matches!(ask(AgentRequest::Status).await, Ok(Response::Status(s)) if s.unlocked)
}

async fn search(
    attributes: &HashMap<String, String>,
) -> zbus::fdo::Result<(Vec<SecretItemView>, bool)> {
    let query = attributes.clone();
    let items = tokio::task::spawn_blocking(list_items)
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    let matched = items.into_iter().filter(|i| matches(i, &query)).collect();
    Ok((matched, vault_unlocked().await))
}

async fn current_item(id: &str) -> Result<SecretItemView> {
    let items = tokio::task::spawn_blocking(list_items).await??;
    items
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| anyhow!("no such item"))
}

/// Read one item, gated by the deck approval, and encrypt it for the session.
async fn read_secret(id: &str, session_path: &str) -> Result<SecretStruct> {
    let value = read_with_approval(id).await?;

    // Encrypt for the negotiated session.
    let (params, ct) = {
        let guard = sessions();
        let s = guard
            .as_ref()
            .unwrap()
            .map
            .get(session_path)
            .ok_or_else(|| anyhow!("that session is not open"))?;
        s.encrypt(value.as_bytes())?
    };
    Ok((
        OwnedObjectPath::try_from(session_path.to_string())?,
        params,
        ct,
        "text/plain".to_string(),
    ))
}

/// Block-poll the vault read until the deck grants the first-use approval, or
/// time out. The deck shows the pending item and takes the passphrase.
async fn read_with_approval(id: &str) -> Result<zeroize::Zeroizing<String>> {
    let started = Instant::now();
    let mut announced = false;
    loop {
        match ask(AgentRequest::SecretGet {
            id: id.to_string(),
            passphrase: None,
        })
        .await?
        {
            Response::Secret { value } => return Ok(value),
            Response::ApprovalRequired { title, .. } => {
                if !announced {
                    eprintln!(
                        "black-bag: approve access to {} in Black-Bag",
                        title.unwrap_or_else(|| "a stored secret".into())
                    );
                    announced = true;
                }
                if started.elapsed() >= APPROVAL_WAIT {
                    let _ = ask(AgentRequest::SecretDismiss { id: id.to_string() }).await;
                    bail!("not approved in time");
                }
                tokio::time::sleep(POLL_EVERY).await;
            }
            Response::Error { message } => bail!("{message}"),
            other => bail!("unexpected reply: {other:?}"),
        }
    }
}

/// Decrypt a secret a client handed us, using its session.
async fn decrypt_secret(secret: &SecretStruct) -> Result<zeroize::Zeroizing<String>> {
    let (session_path, params, value, _content) = secret;
    let guard = sessions();
    let s = guard
        .as_ref()
        .unwrap()
        .map
        .get(session_path.as_str())
        .ok_or_else(|| anyhow!("that session is not open"))?;
    let bytes = s.decrypt(params, value)?;
    Ok(zeroize::Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
}

// ── the loop ─────────────────────────────────────────────────────────────────

/// Bind the name and serve until stopped. Runs its own tokio runtime.
pub fn serve() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve_async())
}

async fn serve_async() -> Result<()> {
    // Register every item that already exists, plus the fixed objects.
    let builder = connection::Builder::session()?
        .name(SERVICE_NAME)
        .with_context(|| {
            format!(
                "could not take {SERVICE_NAME}: another secret service (gnome-keyring, \
                 kwallet, KeePassXC) already owns it. See `black-bag secretservice doctor`."
            )
        })?
        .serve_at(SERVICE_PATH, ServiceIface)?
        .serve_at(COLLECTION_PATH, CollectionIface)?
        .serve_at(ALIAS_PATH, CollectionIface)?;

    let conn = builder.build().await?;

    // Register existing items as objects so their paths resolve.
    if let Ok(items) = list_items() {
        for item in items {
            let _ = conn
                .object_server()
                .at(item_path(&item.id), ItemIface { id: item.id.clone() })
                .await;
        }
    }

    eprintln!("black-bag: secret service listening as {SERVICE_NAME}");
    eprintln!("black-bag: items are stored in the vault and released with your approval");

    // Keep the item object tree roughly in step: register any newly-created
    // items. A light poll — CreateItem returns the path before this notices, so
    // this is only for items created out of band.
    let conn2 = conn.clone();
    tokio::spawn(async move {
        let mut known: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            if let Ok(items) = tokio::task::spawn_blocking(list_items).await.unwrap_or(Ok(vec![])) {
                for item in items {
                    if known.insert(item.id.clone()) {
                        let _ = conn2
                            .object_server()
                            .at(item_path(&item.id), ItemIface { id: item.id.clone() })
                            .await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    // Also register a Session object factory: sessions are created in
    // OpenSession, and their Close is served here. Register lazily on first use
    // is complex with zbus; instead serve a session interface per open session
    // by registering when opened. For simplicity the SessionIface Close removes
    // the crypto state; the object is registered in open_session via the server.
    std::future::pending::<()>().await;
    Ok(())
}

/// `black-bag secretservice approve <id>` — grant a read, passphrase on stdin.
pub fn approve(id: &str) -> Result<()> {
    let passphrase = crate::tty::read_passphrase("Master passphrase, to approve: ")?;
    match session::ask(&AgentRequest::SecretApprove {
        id: id.to_string(),
        passphrase,
    })? {
        Response::Ok => {
            println!("Approved.");
            Ok(())
        }
        Response::Error { message } => bail!("{message}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// `black-bag secretservice doctor` — can we host it, and what is in the way?
pub fn doctor() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match zbus::Connection::session().await {
            Ok(conn) => {
                let dbus = zbus::fdo::DBusProxy::new(&conn).await?;
                let owned = dbus
                    .name_has_owner(SERVICE_NAME.try_into().unwrap())
                    .await
                    .unwrap_or(false);
                if owned {
                    let owner = dbus
                        .get_name_owner(SERVICE_NAME.try_into().unwrap())
                        .await
                        .map(|o| o.to_string())
                        .unwrap_or_default();
                    println!("secret service     TAKEN (owner {owner})");
                    println!();
                    println!("Something already owns {SERVICE_NAME} — usually gnome-keyring.");
                    println!("On Omarchy it is only D-Bus-activated, not a chosen service. To");
                    println!("hand the name to Black-Bag:");
                    println!();
                    println!("  1. Stop the current owner's secrets component. For gnome-keyring,");
                    println!("     run it as  gnome-keyring-daemon --components=pkcs11,ssh  (drop");
                    println!("     `secrets`), or don't autostart it.");
                    println!("  2. Install the activation file so it starts on demand:");
                    println!("       install -Dm644 the packaging file to");
                    println!("       ~/.local/share/dbus-1/services/org.freedesktop.secrets.service");
                    println!("     (the user dir overrides /usr/share; set Exec to your black-bag path)");
                    println!("  3. Log out and back in, or `systemctl --user restart dbus`.");
                } else {
                    println!("secret service     free");
                    println!();
                    println!("Nothing owns {SERVICE_NAME}. `black-bag secretservice serve` will");
                    println!("take it. To start it on demand instead, install the activation file");
                    println!("at ~/.local/share/dbus-1/services/{SERVICE_NAME}.service pointing at");
                    println!("`black-bag secretservice serve`.");
                }
                Ok::<(), anyhow::Error>(())
            }
            Err(e) => {
                println!("session bus        unreachable: {e}");
                Ok(())
            }
        }
    })
}

#[cfg(test)]
mod replace_target_tests {
    use super::*;

    fn item(id: &str, attrs: &[(&str, &str)]) -> SecretItemView {
        SecretItemView {
            id: id.to_string(),
            label: String::new(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            created: 0,
            modified: 0,
        }
    }

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_exact_attribute_set_is_replaced() {
        let items = vec![item("a", &[("service", "mail"), ("user", "me")])];
        let target = replacement_target(&items, &query(&[("service", "mail"), ("user", "me")]));
        assert_eq!(target.map(|i| i.id.as_str()), Some("a"));
    }

    #[test]
    fn an_empty_query_replaces_nothing() {
        let items = vec![item("a", &[("service", "mail")])];
        // A subset test would match every item here; replace must not.
        assert!(replacement_target(&items, &query(&[])).is_none());
    }

    #[test]
    fn a_subset_query_does_not_overwrite_a_larger_item() {
        // App A's item has two attributes; App B asks to replace with only one
        // of them. That is a subset, not the same item, so it must not match.
        let items = vec![item("a", &[("service", "mail"), ("user", "me")])];
        assert!(replacement_target(&items, &query(&[("service", "mail")])).is_none());
    }

    #[test]
    fn a_superset_query_does_not_match_a_smaller_item() {
        let items = vec![item("a", &[("service", "mail")])];
        assert!(
            replacement_target(&items, &query(&[("service", "mail"), ("user", "me")])).is_none()
        );
    }

    #[test]
    fn the_exact_item_is_chosen_among_similar_ones() {
        let items = vec![
            item("a", &[("service", "mail")]),
            item("b", &[("service", "mail"), ("user", "me")]),
            item("c", &[("service", "chat"), ("user", "me")]),
        ];
        let target = replacement_target(&items, &query(&[("service", "mail"), ("user", "me")]));
        assert_eq!(target.map(|i| i.id.as_str()), Some("b"));
    }
}
