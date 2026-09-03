//! Import from other password managers, and export for leaving.
//!
//! A vault you cannot move into is a vault nobody switches to, and a vault
//! you cannot move out of is a trap. Both directions exist here, and both
//! are deliberately unglamorous: the formats are the ones the other tools
//! actually write, parsed by hand, with the mapping to Black-Bag's kinds
//! stated in one table per format so it can be read and argued with.
//!
//! Nothing here touches the network. Every parser reads a file the user named
//! on the command line.
//!
//! Be clear about what that costs. The caller's input buffer is `Zeroizing`
//! and the `Record`s these parsers build hold their secrets in the arena —
//! but between those two points every value passes through ordinary `String`s
//! belonging to `serde_json` and to the CSV reader, and those are freed
//! without being wiped. An import is a bulk plaintext operation over a
//! plaintext file that was already sitting on the disk; treating its
//! intermediates as though they were vault secrets would be theatre. Delete
//! the export when you are done, which is what the command tells you to do.
//!
//! Supported inputs:
//!
//! | `--format`        | What it is                                                |
//! |-------------------|-----------------------------------------------------------|
//! | `bitwarden`       | Bitwarden's unencrypted JSON export (`items[]`)           |
//! | `keepassxc`       | KeePassXC's CSV export (Group, Title, Username, …, TOTP)  |
//! | `firefox`         | Firefox's `logins.csv`                                    |
//! | `chrome`          | Chrome/Chromium/Brave `Chrome Passwords.csv`              |
//! | `csv`             | Any CSV with a header row naming title/username/password  |
//!
//! Outputs: `json` (Black-Bag's own record shape, plaintext) and `keepassxc`
//! (the CSV above, which KeePassXC, Bitwarden and 1Password all import).

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use blackbag_core::record::{Kind, Record, Secret, TotpConfig};
use blackbag_core::session::{decode_base32, parse_otpauth};
use zeroize::Zeroizing;

/// Formats this build reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ImportFormat {
    Bitwarden,
    Keepassxc,
    Firefox,
    Chrome,
    Csv,
    /// This program's own JSON export. An export you cannot import is a
    /// backup you cannot restore.
    BlackBag,
    /// FIDO Alliance Credential Exchange Format (CXF) v1.0 — the standard for
    /// moving credentials, passkeys included, between managers.
    Cxf,
}

/// Formats this build writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ExportFormat {
    Json,
    Keepassxc,
    /// FIDO Alliance Credential Exchange Format (CXF) v1.0.
    Cxf,
}

/// What an import produced, before it is committed.
#[derive(Debug, Default)]
pub struct Imported {
    pub records: Vec<Record>,
    /// Rows skipped, with a reason each. Never carries a secret.
    pub skipped: Vec<String>,
}

impl Imported {
    pub fn counts_by_kind(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for r in &self.records {
            *out.entry(r.kind.as_str()).or_insert(0) += 1;
        }
        out
    }
}

/// Parse `text` in `format`.
pub fn parse(format: ImportFormat, text: &str) -> Result<Imported> {
    match format {
        ImportFormat::Bitwarden => bitwarden(text),
        ImportFormat::Keepassxc => keepassxc(text),
        ImportFormat::Firefox => firefox(text),
        ImportFormat::Chrome => chrome(text),
        ImportFormat::Csv => generic_csv(text),
        ImportFormat::BlackBag => black_bag_json(text),
        ImportFormat::Cxf => cxf(text),
    }
}

/// This program's own JSON export, read back whole: kinds, tags, attributes,
/// every secret field with its declared encoding, notes and TOTP.
fn black_bag_json(text: &str) -> Result<Imported> {
    let doc: serde_json::Value =
        serde_json::from_str(text).context("not a Black-Bag JSON export")?;
    if doc.get("format").and_then(|f| f.as_str()) != Some("black-bag-export") {
        bail!("this is not a Black-Bag export; its `format` field does not say so");
    }
    let records = doc
        .get("records")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow!("no records array in this export"))?;

    let mut out = Imported::default();
    for (n, item) in records.iter().enumerate() {
        match record_from_export_item(item) {
            Ok(record) => out.records.push(record),
            Err(reason) => out.skipped.push(format!("record {n}: {reason}")),
        }
    }
    Ok(out)
}

/// Rebuild a record from one Black-Bag export object — the inverse of
/// [`export_item_json`]. Shared with the CXF importer, whose `_blackbag`
/// extension is exactly this object.
fn record_from_export_item(item: &serde_json::Value) -> std::result::Result<Record, String> {
    let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
    let kind: Kind = item
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("login")
        .parse()
        .map_err(|e| format!("({title}): {e}"))?;
    let mut record = Record::new(kind, (!title.is_empty()).then(|| title.to_string()));

    if let Some(tags) = item.get("tags").and_then(|t| t.as_array()) {
        record.tags = tags
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
    }
    if let Some(attrs) = item.get("attributes").and_then(|a| a.as_object()) {
        for (k, v) in attrs {
            if let Some(v) = v.as_str() {
                set_attr_if(&mut record, k, v);
            }
        }
    }
    if let Some(secrets) = item.get("secrets").and_then(|s| s.as_object()) {
        for (name, value) in secrets {
            match decode_export_secret(value) {
                Some(bytes) => record.set_field(name, Secret::new(&bytes)),
                None => return Err(format!("({title}): field '{name}' is not readable")),
            }
        }
    }
    if let Some(notes) = item.get("notes").and_then(|v| v.as_str()) {
        set_notes_if(&mut record, notes);
    }
    if let Some(totp) = item.get("totp").filter(|t| !t.is_null()) {
        let defaults = TotpConfig::default();
        record.totp = Some(TotpConfig {
            issuer: totp.get("issuer").and_then(|v| v.as_str()).map(str::to_string),
            account: totp.get("account").and_then(|v| v.as_str()).map(str::to_string),
            digits: totp
                .get("digits")
                .and_then(|v| v.as_u64())
                .map(|d| d as u8)
                .unwrap_or(defaults.digits),
            step: totp.get("step").and_then(|v| v.as_u64()).unwrap_or(defaults.step),
            algorithm: match totp.get("algorithm").and_then(|v| v.as_str()) {
                Some("sha256") => blackbag_core::record::TotpAlgorithm::Sha256,
                Some("sha512") => blackbag_core::record::TotpAlgorithm::Sha512,
                _ => blackbag_core::record::TotpAlgorithm::Sha1,
            },
            ..defaults
        });
    }
    if let Some(pk) = item.get("passkey").filter(|p| !p.is_null()) {
        record.passkey = serde_json::from_value(pk.clone())
            .map_err(|e| format!("({title}): passkey config: {e}"))?;
    }
    record.validate().map_err(|e| format!("({title}): {e}"))?;
    Ok(record)
}

/// A secret from the export: `{"encoding": "utf8"|"base64", "value": …}`.
fn decode_export_secret(value: &serde_json::Value) -> Option<Vec<u8>> {
    let text = value.get("value")?.as_str()?;
    match value.get("encoding").and_then(|e| e.as_str()) {
        Some("base64") => {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).ok()
        }
        Some("utf8") => Some(text.as_bytes().to_vec()),
        _ => None,
    }
}

// ── CXF: FIDO Alliance Credential Exchange Format v1.0 ───────────────────────
//
// CXF is the standard for moving credentials — passwords, TOTP, SSH keys, and
// crucially passkeys with their private keys — between managers. Two goals pull
// in slightly different directions: interoperability (another manager should be
// able to read what we write) and fidelity (a Black-Bag export re-imported into
// Black-Bag should be byte-for-byte the same records). We serve both: every
// item carries a standard CXF credential AND a `_blackbag` extension that is
// the exact Black-Bag export object. Our own importer prefers the extension;
// importing someone else's CXF falls back to the standard credentials.
//
// CXF v1.0 is newly finalized and no two implementations fully interoperate
// yet, so this maps the credential types the vault actually holds and preserves
// everything else through the extension rather than claiming coverage it cannot
// demonstrate.

use base64::Engine as _;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Base32 (RFC 4648, no padding) — TOTP secrets are carried this way in CXF.
fn base32_encode(bytes: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, bytes)
}

/// One CXF credential for a record, by kind. Best-effort and standard; the
/// `_blackbag` extension alongside it is what makes the round trip exact.
fn cxf_credential(r: &Record) -> serde_json::Value {
    use serde_json::json;
    let attr = |name: &str| r.attribute(name).unwrap_or("").to_string();
    let field_utf8 = |name: &str| {
        r.field(name)
            .and_then(|f| f.expose_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    match r.kind {
        Kind::Login | Kind::Api | Kind::Bank | Kind::Wifi | Kind::Contact | Kind::Id => json!({
            "type": "basic-auth",
            "urls": r.attribute("url").map(|u| vec![u.to_string()]).unwrap_or_default(),
            "username": { "fieldType": "string", "value": attr("username") },
            "password": {
                "fieldType": "concealed-string",
                "value": field_utf8(r.fields.first().map(|f| f.name.as_str()).unwrap_or("password")),
            },
        }),
        Kind::Totp => {
            let seed = r.field("totp").map(|f| f.open());
            let seed_bytes = seed.as_ref().map(|s| s.as_slice()).unwrap_or(&[]);
            let t = r.totp.clone().unwrap_or_default();
            json!({
                "type": "totp",
                "secret": base32_encode(seed_bytes),
                "period": t.step,
                "digits": t.digits,
                "algorithm": t.algorithm.as_str(),
                "username": t.account.unwrap_or_default(),
                "issuer": t.issuer.unwrap_or_default(),
            })
        }
        Kind::Note => json!({
            "type": "note",
            "content": r.notes.as_ref().and_then(|n| n.expose_str().ok()).map(|s| s.to_string()).unwrap_or_default(),
        }),
        Kind::Ssh => {
            let seed = r.field(blackbag_core::ssh::SSH_SEED_FIELD).map(|f| f.open());
            json!({
                "type": "ssh-key",
                "keyType": "ssh-ed25519",
                "privateKey": {
                    "fieldType": "concealed-string",
                    "value": seed.map(|s| b64url(s.as_slice())).unwrap_or_default(),
                },
                "keyComment": attr("comment"),
            })
        }
        Kind::Passkey => {
            let cfg = r.passkey.clone();
            let key = r.field(blackbag_core::passkey::PRIVATE_KEY_FIELD).map(|f| f.open());
            json!({
                "type": "passkey",
                "credentialId": cfg.as_ref().map(|c| b64url(&c.credential_id)).unwrap_or_default(),
                "rpId": cfg.as_ref().map(|c| c.rp_id.clone()).unwrap_or_default(),
                "userName": cfg.as_ref().and_then(|c| c.user_name.clone()).unwrap_or_default(),
                "userDisplayName": cfg.as_ref().and_then(|c| c.user_display_name.clone()).unwrap_or_default(),
                "userHandle": cfg.as_ref().map(|c| b64url(&c.user_handle)).unwrap_or_default(),
                "key": key.map(|k| b64url(k.as_slice())).unwrap_or_default(),
                "algorithm": "ES256",
            })
        }
        _ => json!({ "type": "note", "content": "" }),
    }
}

fn render_cxf(records: &[Record]) -> Result<Zeroizing<String>> {
    let items: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": b64url(r.id.as_bytes()),
                "creationAt": r.created_at.timestamp(),
                "modifiedAt": r.updated_at.timestamp(),
                "title": r.title.clone().unwrap_or_default(),
                "credentials": [cxf_credential(r)],
                // The exact Black-Bag record, so our own re-import is lossless.
                // Other managers ignore an unknown key; ours reads it.
                "_blackbag": export_item_json(r),
            })
        })
        .collect();

    let doc = serde_json::json!({
        "version": { "major": 1, "minor": 0 },
        "exporterDisplayName": "Black-Bag",
        "timestamp": chrono::Utc::now().timestamp(),
        "accounts": [{
            "id": b64url(b"black-bag"),
            "userName": "",
            "email": "",
            "collections": [],
            "items": items,
        }],
    });
    Ok(Zeroizing::new(serde_json::to_string_pretty(&doc)?))
}

/// Parse a CXF document. Prefers each item's `_blackbag` extension for an exact
/// round trip; otherwise maps the standard credential.
fn cxf(text: &str) -> Result<Imported> {
    let doc: serde_json::Value = serde_json::from_str(text).context("not a CXF document")?;
    if doc.get("version").and_then(|v| v.get("major")).and_then(|m| m.as_u64()) != Some(1) {
        bail!("this is not a CXF v1 document");
    }
    let mut out = Imported::default();
    let accounts = doc.get("accounts").and_then(|a| a.as_array());
    for account in accounts.into_iter().flatten() {
        let items = account.get("items").and_then(|i| i.as_array());
        for (n, item) in items.into_iter().flatten().enumerate() {
            // The exact path.
            if let Some(bb) = item.get("_blackbag") {
                match record_from_export_item(bb) {
                    Ok(record) => out.records.push(record),
                    Err(reason) => out.skipped.push(format!("item {n}: {reason}")),
                }
                continue;
            }
            // The interop path: map the first standard credential we understand.
            match record_from_cxf_item(item) {
                Ok(Some(record)) => out.records.push(record),
                Ok(None) => out
                    .skipped
                    .push(format!("item {n}: no credential type this build imports")),
                Err(reason) => out.skipped.push(format!("item {n}: {reason}")),
            }
        }
    }
    Ok(out)
}

/// Map a foreign CXF item's standard credential to a record. Covers the types
/// a person is most likely to be bringing in: basic-auth, totp, note.
fn record_from_cxf_item(item: &serde_json::Value) -> std::result::Result<Option<Record>, String> {
    let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
    let creds = item.get("credentials").and_then(|c| c.as_array());
    let Some(creds) = creds else { return Ok(None) };
    for cred in creds {
        let cty = cred.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let val = |path: &[&str]| -> String {
            let mut v = cred;
            for p in path {
                match v.get(p) {
                    Some(next) => v = next,
                    None => return String::new(),
                }
            }
            v.as_str().unwrap_or("").to_string()
        };
        match cty {
            "basic-auth" => {
                let mut r = Record::new(Kind::Login, (!title.is_empty()).then(|| title.to_string()));
                let user = val(&["username", "value"]);
                if !user.is_empty() {
                    set_attr_if(&mut r, "username", &user);
                }
                if let Some(urls) = cred.get("urls").and_then(|u| u.as_array()) {
                    if let Some(u) = urls.first().and_then(|u| u.as_str()) {
                        set_attr_if(&mut r, "url", u);
                    }
                }
                let pw = val(&["password", "value"]);
                if !pw.is_empty() {
                    r.set_field("password", Secret::new(pw.as_bytes()));
                }
                r.validate().map_err(|e| format!("({title}): {e}"))?;
                return Ok(Some(r));
            }
            "note" => {
                let mut r = Record::new(Kind::Note, (!title.is_empty()).then(|| title.to_string()));
                set_notes_if(&mut r, &val(&["content"]));
                r.validate().map_err(|e| format!("({title}): {e}"))?;
                return Ok(Some(r));
            }
            "totp" => {
                let secret_b32 = val(&["secret"]);
                let seed = base32::decode(
                    base32::Alphabet::Rfc4648 { padding: false },
                    &secret_b32.replace(' ', "").to_uppercase(),
                )
                .ok_or_else(|| format!("({title}): TOTP secret is not base32"))?;
                let mut r = Record::new(Kind::Totp, (!title.is_empty()).then(|| title.to_string()));
                r.set_field("totp", Secret::new(&seed));
                r.totp = Some(TotpConfig {
                    issuer: cred.get("issuer").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
                    account: cred.get("username").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
                    digits: cred.get("digits").and_then(|v| v.as_u64()).map(|d| d as u8).unwrap_or(6),
                    step: cred.get("period").and_then(|v| v.as_u64()).unwrap_or(30),
                    ..TotpConfig::default()
                });
                r.validate().map_err(|e| format!("({title}): {e}"))?;
                return Ok(Some(r));
            }
            _ => continue,
        }
    }
    Ok(None)
}

// ── CSV ─────────────────────────────────────────────────────────────────────

/// RFC 4180 with the usual tolerances: CRLF or LF, quoted fields with `""`
/// escapes and embedded newlines, a leading UTF-8 BOM, and a trailing
/// newline that is not a row. Returns rows of fields; the caller decides
/// what the first row means.
pub fn parse_csv(text: &str) -> Result<Vec<Vec<String>>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    let mut in_quotes = false;
    let mut field_started = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                other => field.push(other),
            }
            continue;
        }
        match c {
            '"' if !field_started || field.is_empty() => {
                in_quotes = true;
                field_started = true;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                field_started = false;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                field_started = false;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                field_started = false;
            }
            other => {
                field.push(other);
                field_started = true;
            }
        }
    }
    if in_quotes {
        bail!("CSV ends inside a quoted field");
    }
    if field_started || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    // A wholly empty trailing row is a trailing newline, not data.
    while rows
        .last()
        .is_some_and(|r| r.iter().all(|f| f.is_empty()))
    {
        rows.pop();
    }
    Ok(rows)
}

/// Quote a field for CSV output.
pub fn csv_quote(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A header-indexed row.
struct Row<'a> {
    header: &'a [String],
    cells: &'a [String],
}

impl Row<'_> {
    fn get(&self, name: &str) -> &str {
        self.header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(name))
            .and_then(|i| self.cells.get(i))
            .map(String::as_str)
            .unwrap_or("")
    }

    /// First non-empty of several candidate column names.
    fn first(&self, names: &[&str]) -> &str {
        for name in names {
            let v = self.get(name);
            if !v.trim().is_empty() {
                return v;
            }
        }
        ""
    }
}

fn header_and_rows(text: &str) -> Result<(Vec<String>, Vec<Vec<String>>)> {
    let mut rows = parse_csv(text)?;
    if rows.is_empty() {
        bail!("the file has no rows");
    }
    let header = rows.remove(0);
    // An interior blank line parses as a one-cell row and used to import as
    // an untitled record with no fields. A row with nothing in it is not a
    // record in any format.
    rows.retain(|r| r.iter().any(|c| !c.trim().is_empty()));
    Ok((header, rows))
}

/// Refuse a file whose header names none of the columns this format needs,
/// rather than importing every row as an untitled record with the password
/// sitting in a plain attribute.
fn require_columns(header: &[String], wanted: &[&[&str]], format: &str) -> Result<()> {
    let present = |names: &[&str]| {
        names.iter().any(|n| {
            header
                .iter()
                .any(|h| h.trim().eq_ignore_ascii_case(n))
        })
    };
    if wanted.iter().any(|names| present(names)) {
        return Ok(());
    }
    bail!(
        "this does not look like a {format} export: its header names none of the \
         columns one has ({})",
        wanted
            .iter()
            .flat_map(|n| n.iter())
            .copied()
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// ── record building ─────────────────────────────────────────────────────────

fn set_attr_if(record: &mut Record, name: &str, value: &str) {
    let v = value.trim();
    if !v.is_empty() {
        record.set_attribute(name, v);
    }
}

fn set_secret_if(record: &mut Record, name: &str, value: &str) {
    if !value.is_empty() {
        record.set_field(name, Secret::from_str(value));
    }
}

fn set_notes_if(record: &mut Record, value: &str) {
    let v = value.trim();
    if !v.is_empty() {
        record.notes = Some(Secret::from_str(v));
    }
}

/// Attach a TOTP from either an `otpauth://` URI or a bare base32 secret.
/// Failures are reported, not fatal: a login with a bad TOTP is still a
/// login worth having.
fn attach_totp(record: &mut Record, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let parsed = if value.starts_with("otpauth://") {
        parse_otpauth(value)
    } else {
        decode_base32(value).map(|bytes| {
            let config = TotpConfig {
                issuer: record.title.clone(),
                account: record.attribute("username").map(str::to_string),
                ..TotpConfig::default()
            };
            (bytes, config)
        })
    };
    match parsed {
        Ok((bytes, config)) => {
            record.set_field("totp", Secret::new(&bytes));
            record.totp = Some(config);
            None
        }
        Err(e) => Some(format!("TOTP not imported: {e}")),
    }
}

/// The field an export put a kind's main secret into; the inverse of the
/// preference order `render_keepassxc` uses.
fn primary_field_for(kind: Kind) -> &'static str {
    match kind {
        Kind::Login | Kind::Totp => "password",
        Kind::Wifi => "passphrase",
        Kind::Api => "secret_key",
        Kind::Ssh | Kind::Pgp => "private_key",
        Kind::Wallet => "seed",
        Kind::Bank => "account_number",
        Kind::Id => "number",
        Kind::Contact => "notes",
        Kind::Note => "body",
        Kind::Recovery => "payload",
        Kind::Passkey => "private_key",
    }
}

/// Marks the block this exporter appends to a Notes column. Anything after
/// it is ours; anything before it is the user's.
pub const META_MARKER: &str = "[black-bag]";

/// What our own export stashed in a Notes column.
#[derive(Debug, Default, PartialEq, Eq)]
struct NoteMeta {
    kind: Option<Kind>,
    attributes: Vec<(String, String)>,
    secrets: Vec<(String, String)>,
}

/// Encode a value for the line-oriented `[black-bag]` meta block.
///
/// The block is read back one physical line at a time by [`split_meta`], so a
/// raw newline in a value would split it across lines: the continuation lines
/// were silently dropped on re-import (losing secret material), and one that
/// happened to begin with a directive keyword could inject a spurious kind,
/// attribute or field. Backslash, newline and carriage return are the only
/// characters that need escaping; everything else rides through unchanged.
fn meta_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// The inverse of [`meta_escape`], tolerant of older exports that never
/// escaped: an unknown `\x` is left as its two literal characters, so a value
/// that genuinely held a lone backslash still round-trips unchanged.
fn meta_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Split a Notes column into the user's notes and whatever our exporter put
/// after the marker. A column with no marker is all notes, which is what
/// every other tool's export looks like.
fn split_meta(notes: &str) -> (NoteMeta, String) {
    let Some(at) = notes.find(META_MARKER) else {
        return (NoteMeta::default(), notes.to_string());
    };
    let (head, tail) = notes.split_at(at);
    let mut meta = NoteMeta::default();
    for line in tail.lines().skip(1) {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("kind: ") {
            meta.kind = rest.trim().parse::<Kind>().ok();
        } else if let Some(rest) = line.strip_prefix("attr ") {
            if let Some((k, v)) = rest.split_once(": ") {
                meta.attributes.push((k.to_string(), meta_unescape(v)));
            }
        } else if let Some(rest) = line.strip_prefix("secret ") {
            if let Some((k, v)) = rest.split_once(": ") {
                meta.secrets.push((k.to_string(), meta_unescape(v)));
            }
        }
    }
    (meta, head.trim_end().to_string())
}

/// Cells a spreadsheet would treat as a formula rather than as text.
///
/// A plaintext CSV is exactly the file someone opens in a spreadsheet "just
/// to check it", and a title of `=cmd|' /C calc'!A0` is a live payload there.
/// Quoting does not help — Excel and LibreOffice parse the formula either
/// way — so the leading character is escaped with the conventional
/// apostrophe, and [`undefang`] takes it off again on the way in.
fn defang(value: &str) -> String {
    match value.chars().next() {
        Some('=') | Some('+') | Some('-') | Some('@') | Some('\t') | Some('\r') => {
            format!("'{value}")
        }
        _ => value.to_string(),
    }
}

/// Reverse [`defang`]. Unambiguous: the apostrophe is only removed when what
/// follows it is itself dangerous, so a value that genuinely begins with one
/// survives untouched.
fn undefang(value: &str) -> String {
    if let Some(rest) = value.strip_prefix('\'') {
        if matches!(
            rest.chars().next(),
            Some('=') | Some('+') | Some('-') | Some('@') | Some('\t') | Some('\r')
        ) {
            return rest.to_string();
        }
    }
    value.to_string()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?.trim();
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

fn login(title: &str, username: &str, password: &str, url: &str, notes: &str) -> Record {
    let title = title.trim();
    let title = if title.is_empty() {
        host_of(url).unwrap_or_else(|| "(untitled)".to_string())
    } else {
        title.to_string()
    };
    let mut r = Record::new(Kind::Login, Some(title));
    set_attr_if(&mut r, "username", username);
    set_attr_if(&mut r, "url", url);
    set_secret_if(&mut r, "password", password);
    set_notes_if(&mut r, notes);
    r
}

// ── formats ─────────────────────────────────────────────────────────────────

/// Bitwarden unencrypted JSON: `{"folders":[{id,name}], "items":[…]}`.
/// Item types: 1 login, 2 secure note, 3 card, 4 identity.
fn bitwarden(text: &str) -> Result<Imported> {
    let doc: serde_json::Value =
        serde_json::from_str(text).context("not a Bitwarden JSON export")?;
    if doc.get("encrypted").and_then(|v| v.as_bool()) == Some(true) {
        bail!("this is an encrypted Bitwarden export; export it unencrypted (Bitwarden → Tools → Export → .json) and import that");
    }
    let folders: BTreeMap<String, String> = doc
        .get("folders")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    Some((
                        f.get("id")?.as_str()?.to_string(),
                        f.get("name")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let items = doc
        .get("items")
        .and_then(|i| i.as_array())
        .ok_or_else(|| anyhow!("no items array in this export"))?;

    let s = |v: Option<&serde_json::Value>| -> String {
        v.and_then(|x| x.as_str()).unwrap_or("").to_string()
    };

    let mut out = Imported::default();
    for (n, item) in items.iter().enumerate() {
        let name = s(item.get("name"));
        let notes = s(item.get("notes"));
        let kind = item.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
        let mut record = match kind {
            1 => {
                let l = item.get("login").cloned().unwrap_or_default();
                let uri = l
                    .get("uris")
                    .and_then(|u| u.as_array())
                    .and_then(|u| u.first())
                    .map(|u| s(u.get("uri")))
                    .unwrap_or_default();
                let mut r = login(&name, &s(l.get("username")), &s(l.get("password")), &uri, &notes);
                if let Some(warn) = attach_totp(&mut r, &s(l.get("totp"))) {
                    out.skipped.push(format!("item {n} ({name}): {warn}"));
                }
                r
            }
            2 => {
                let mut r = Record::new(Kind::Note, Some(name.clone()));
                set_secret_if(&mut r, "body", &notes);
                r
            }
            3 => {
                let c = item.get("card").cloned().unwrap_or_default();
                let mut r = Record::new(Kind::Bank, Some(name.clone()));
                set_attr_if(&mut r, "institution", &s(c.get("brand")));
                set_attr_if(&mut r, "account_name", &s(c.get("cardholderName")));
                let exp = format!("{}/{}", s(c.get("expMonth")), s(c.get("expYear")));
                if exp != "/" {
                    set_attr_if(&mut r, "expiry", &exp);
                }
                set_secret_if(&mut r, "account_number", &s(c.get("number")));
                set_secret_if(&mut r, "security_code", &s(c.get("code")));
                set_notes_if(&mut r, &notes);
                r
            }
            4 => {
                let i = item.get("identity").cloned().unwrap_or_default();
                let mut r = Record::new(Kind::Id, Some(name.clone()));
                let full = [s(i.get("firstName")), s(i.get("middleName")), s(i.get("lastName"))]
                    .iter()
                    .filter(|p| !p.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                set_attr_if(&mut r, "name_on_doc", &full);
                set_attr_if(&mut r, "issuing_country", &s(i.get("country")));
                let number = [s(i.get("passportNumber")), s(i.get("licenseNumber")), s(i.get("ssn"))]
                    .into_iter()
                    .find(|v| !v.is_empty())
                    .unwrap_or_default();
                if !s(i.get("passportNumber")).is_empty() {
                    set_attr_if(&mut r, "id_type", "passport");
                } else if !s(i.get("licenseNumber")).is_empty() {
                    set_attr_if(&mut r, "id_type", "driving licence");
                } else if !s(i.get("ssn")).is_empty() {
                    set_attr_if(&mut r, "id_type", "national id");
                }
                set_secret_if(&mut r, "number", &number);
                set_notes_if(&mut r, &notes);
                r
            }
            other => {
                out.skipped
                    .push(format!("item {n} ({name}): unknown Bitwarden type {other}"));
                continue;
            }
        };

        // Custom fields: hidden ones are secrets, the rest attributes.
        if let Some(fields) = item.get("fields").and_then(|f| f.as_array()) {
            for f in fields {
                let fname = s(f.get("name"));
                let fvalue = s(f.get("value"));
                if fname.trim().is_empty() {
                    continue;
                }
                let mut key = fname.trim().to_ascii_lowercase().replace(' ', "_");
                // A custom field may not overwrite what the item's own type
                // already put there. Bitwarden happily holds a custom field
                // called "password" beside a login password, and a text one
                // called "totp" would have replaced decoded secret bytes with
                // its own literal text.
                let collides = key == "totp"
                    || record.field(&key).is_some()
                    || record.attribute(&key).is_some();
                if collides {
                    let renamed = format!("custom_{key}");
                    out.skipped.push(format!(
                        "item {n} ({name}): custom field '{fname}' renamed to '{renamed}'; it \
                         collides with a field this item type already defines"
                    ));
                    key = renamed;
                }
                match f.get("type").and_then(|t| t.as_u64()) {
                    Some(1) => set_secret_if(&mut record, &key, &fvalue),
                    _ => set_attr_if(&mut record, &key, &fvalue),
                }
            }
        }
        if let Some(folder) = item.get("folderId").and_then(|f| f.as_str()) {
            if let Some(name) = folders.get(folder) {
                record.tags.push(name.clone());
            }
        }
        if item.get("favorite").and_then(|f| f.as_bool()) == Some(true) {
            record.tags.push("favorite".into());
        }
        if let Err(e) = record.validate() {
            out.skipped.push(format!("item {n} ({name}): {e}"));
            continue;
        }
        out.records.push(record);
    }
    Ok(out)
}

/// KeePassXC CSV: Group, Title, Username, Password, URL, Notes, TOTP, Icon,
/// Last Modified, Created.
fn keepassxc(text: &str) -> Result<Imported> {
    let (header, rows) = header_and_rows(text)?;
    require_columns(&header, &[&["Title"], &["Password"]], "KeePassXC")?;
    let mut out = Imported::default();
    for (n, cells) in rows.iter().enumerate() {
        let row = Row {
            header: &header,
            cells,
        };
        let title = undefang(row.get("Title"));
        let username = undefang(row.get("Username"));
        let password = row.get("Password");
        let url = undefang(row.get("URL"));
        let notes = undefang(row.get("Notes"));
        let group = row.get("Group");
        let (title, username, url) = (title.as_str(), username.as_str(), url.as_str());
        // Our own export appends a marked block to Notes, so a Black-Bag →
        // KeePassXC → Black-Bag round trip keeps the kind, every attribute
        // and every extra secret field rather than flattening them away.
        let (meta, notes) = split_meta(&notes);
        let mut record = match meta.kind {
            Some(kind) if kind != Kind::Login => {
                let mut r = Record::new(kind, Some(title.to_string()));
                set_attr_if(&mut r, "username", username);
                set_attr_if(&mut r, "url", url);
                set_secret_if(&mut r, primary_field_for(kind), password);
                set_notes_if(&mut r, &notes);
                r
            }
            _ if username.is_empty()
                && password.is_empty()
                && url.is_empty()
                && meta.secrets.is_empty() =>
            {
                let mut r = Record::new(Kind::Note, Some(title.to_string()));
                set_secret_if(&mut r, "body", &notes);
                r
            }
            _ => login(title, username, password, url, &notes),
        };
        for (k, v) in &meta.attributes {
            set_attr_if(&mut record, k, v);
        }
        for (k, v) in &meta.secrets {
            set_secret_if(&mut record, k, v);
        }
        for part in group.split('/') {
            let tag = part.trim();
            if !tag.is_empty() && tag != "Root" {
                record.tags.push(tag.to_string());
            }
        }
        if let Some(warn) = attach_totp(&mut record, row.get("TOTP")) {
            out.skipped.push(format!("row {}: {warn}", n + 2));
        }
        if let Err(e) = record.validate() {
            out.skipped.push(format!("row {}: {e}", n + 2));
            continue;
        }
        out.records.push(record);
    }
    Ok(out)
}

/// Firefox `logins.csv`: url, username, password, httpRealm,
/// formActionOrigin, guid, timeCreated, timeLastUsed, timePasswordChanged.
fn firefox(text: &str) -> Result<Imported> {
    let (header, rows) = header_and_rows(text)?;
    require_columns(&header, &[&["url"], &["password"]], "Firefox")?;
    let mut out = Imported::default();
    for (n, cells) in rows.iter().enumerate() {
        let row = Row {
            header: &header,
            cells,
        };
        let url = row.get("url");
        let record = login("", row.get("username"), row.get("password"), url, "");
        if let Err(e) = record.validate() {
            out.skipped.push(format!("row {}: {e}", n + 2));
            continue;
        }
        out.records.push(record);
    }
    Ok(out)
}

/// Chrome/Chromium/Brave: name, url, username, password, note.
fn chrome(text: &str) -> Result<Imported> {
    let (header, rows) = header_and_rows(text)?;
    require_columns(&header, &[&["name"], &["url"], &["password"]], "Chrome")?;
    let mut out = Imported::default();
    for (n, cells) in rows.iter().enumerate() {
        let row = Row {
            header: &header,
            cells,
        };
        let record = login(
            row.get("name"),
            row.get("username"),
            row.get("password"),
            row.get("url"),
            row.get("note"),
        );
        if let Err(e) = record.validate() {
            out.skipped.push(format!("row {}: {e}", n + 2));
            continue;
        }
        out.records.push(record);
    }
    Ok(out)
}

/// Any CSV with a header. Column names are matched case-insensitively
/// against a small set of synonyms; unrecognised columns become attributes.
fn generic_csv(text: &str) -> Result<Imported> {
    let (header, rows) = header_and_rows(text)?;
    const TITLE: &[&str] = &["title", "name", "account", "site", "service"];
    const USER: &[&str] = &["username", "user", "login", "email", "user name"];
    const PASS: &[&str] = &["password", "pass", "secret", "pwd"];
    const URL: &[&str] = &["url", "website", "web site", "login_uri", "uri"];
    const NOTES: &[&str] = &["notes", "note", "comment", "extra"];
    const TOTP: &[&str] = &["totp", "otp", "otpauth", "2fa"];
    let known: Vec<&str> = [TITLE, USER, PASS, URL, NOTES, TOTP].concat();
    require_columns(&header, &[TITLE, USER, PASS], "CSV")?;

    let mut out = Imported::default();
    for (n, cells) in rows.iter().enumerate() {
        let row = Row {
            header: &header,
            cells,
        };
        let mut record = login(
            row.first(TITLE),
            row.first(USER),
            row.first(PASS),
            row.first(URL),
            row.first(NOTES),
        );
        for (i, col) in header.iter().enumerate() {
            let key = col.trim().to_ascii_lowercase();
            if key.is_empty() || known.contains(&key.as_str()) {
                continue;
            }
            if let Some(v) = cells.get(i) {
                set_attr_if(&mut record, &key.replace(' ', "_"), v);
            }
        }
        if let Some(warn) = attach_totp(&mut record, row.first(TOTP)) {
            out.skipped.push(format!("row {}: {warn}", n + 2));
        }
        if let Err(e) = record.validate() {
            out.skipped.push(format!("row {}: {e}", n + 2));
            continue;
        }
        out.records.push(record);
    }
    Ok(out)
}

// ── export ──────────────────────────────────────────────────────────────────

/// Render `records` as plaintext in `format`. The caller owns the warning
/// and the file permissions; this only produces bytes, wiped by the caller.
pub fn render(records: &[Record], format: ExportFormat) -> Result<Zeroizing<String>> {
    match format {
        ExportFormat::Json => render_json(records),
        ExportFormat::Keepassxc => render_keepassxc(records),
        ExportFormat::Cxf => render_cxf(records),
    }
}

fn render_json(records: &[Record]) -> Result<Zeroizing<String>> {
    let items: Vec<serde_json::Value> = records.iter().map(export_item_json).collect();
    let doc = serde_json::json!({
        "format": "black-bag-export",
        "version": 1,
        "plaintext": true,
        "records": items,
    });
    Ok(Zeroizing::new(serde_json::to_string_pretty(&doc)?))
}

/// One record as the Black-Bag export object. The lossless representation, used
/// both by our own JSON export and, verbatim, as the `_blackbag` extension that
/// makes a CXF export round-trip exactly.
fn export_item_json(r: &Record) -> serde_json::Value {
    let mut secrets = serde_json::Map::new();
    for f in &r.fields {
        // A secret that is not UTF-8 — a raw TOTP seed, a binary key — is
        // base64, and says so. An untagged fallback was indistinguishable from
        // a value that merely looked like base64, so nothing could import this
        // file back without guessing.
        let value = match f.secret.expose_str() {
            Ok(text) => serde_json::json!({ "encoding": "utf8", "value": text.to_string() }),
            Err(_) => serde_json::json!({
                "encoding": "base64",
                "value": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    f.secret.open().as_slice(),
                ),
            }),
        };
        secrets.insert(f.name.clone(), value);
    }
    let notes = r
        .notes
        .as_ref()
        .and_then(|n| n.expose_str().ok())
        .map(|s| s.to_string());
    serde_json::json!({
        "id": r.id,
        "kind": r.kind.as_str(),
        "title": r.title,
        "tags": r.tags,
        "attributes": r.attributes.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "secrets": secrets,
        "notes": notes,
        "totp": r.totp.as_ref().map(|t| serde_json::json!({
            "issuer": t.issuer, "account": t.account, "digits": t.digits,
            "step": t.step, "algorithm": t.algorithm.as_str(),
        })),
        // The passkey configuration, when present. Without this a passkey does
        // not survive an export round trip: its private key rides in `secrets`,
        // but the relying party, credential id and user handle live here.
        "passkey": r.passkey.as_ref().map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null)),
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

fn render_keepassxc(records: &[Record]) -> Result<Zeroizing<String>> {
    let mut out = String::new();
    out.push_str("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n");
    for r in records {
        let group = if r.tags.is_empty() {
            "Root".to_string()
        } else {
            format!("Root/{}", r.tags.join("/"))
        };
        let title = r.title.clone().unwrap_or_default();
        let username = r
            .attribute("username")
            .or_else(|| r.attribute("account"))
            .unwrap_or("")
            .to_string();
        // The same field the importer will read back out of this column. A
        // global preference list stood here and disagreed with the importer's
        // per-kind choice, so an SSH key carrying both a `passphrase` and a
        // `private_key` came back with the passphrase in the key field and
        // the key demoted to a note.
        let primary_name = primary_field_for(r.kind);
        let primary = r
            .field(primary_name)
            .map(|s| (primary_name, s))
            .or_else(|| r.fields.first().map(|f| (f.name.as_str(), &f.secret)));
        let password = primary
            .and_then(|(_, s)| s.expose_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let url = r.attribute("url").unwrap_or("").to_string();
        // The user's own notes first, then everything with no column of its
        // own, in a block we can read back exactly. Marking the block is what
        // lets an attribute and a second secret be told apart on the way in,
        // which a bare `name: value` line could not manage.
        let mut notes = Vec::new();
        if let Some(n) = r.notes.as_ref().and_then(|n| n.expose_str().ok()) {
            notes.push(n.to_string());
        }
        let mut meta = Vec::new();
        if r.kind != Kind::Login {
            meta.push(format!("kind: {}", r.kind.as_str()));
        }
        for (k, v) in &r.attributes {
            if k != "username" && k != "url" && k != "account" {
                meta.push(format!("attr {k}: {}", meta_escape(v)));
            }
        }
        for f in &r.fields {
            if Some(f.name.as_str()) != primary.map(|(n, _)| n) && f.name != "totp" {
                if let Ok(v) = f.secret.expose_str() {
                    meta.push(format!("secret {}: {}", f.name, meta_escape(&v)));
                }
            }
        }
        if !meta.is_empty() {
            notes.push(format!("{}\n{}", META_MARKER, meta.join("\n")));
        }
        let totp = match (&r.totp, r.field("totp")) {
            (Some(cfg), Some(secret)) => {
                let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret.open().as_slice());
                format!(
                    "otpauth://totp/{}?secret={}&digits={}&period={}&algorithm={}{}",
                    percent_encode(&format!(
                        "{}:{}",
                        cfg.issuer.as_deref().unwrap_or(&title),
                        cfg.account.as_deref().unwrap_or(&username)
                    )),
                    b32,
                    cfg.digits,
                    cfg.step,
                    cfg.algorithm.as_str().to_ascii_uppercase(),
                    cfg.issuer
                        .as_deref()
                        .map(|i| format!("&issuer={}", percent_encode(i)))
                        .unwrap_or_default()
                )
            }
            _ => String::new(),
        };
        // Only the columns a spreadsheet would evaluate are defanged. The
        // Password column is left exactly as stored: a leading apostrophe
        // there would become part of the secret to any importer, ours
        // included.
        let line = [
            defang(&group),
            defang(&title),
            defang(&username),
            password,
            defang(&url),
            defang(&notes.join("\n")),
            totp,
            "0".to_string(),
            r.updated_at.to_rfc3339(),
            r.created_at.to_rfc3339(),
        ]
        .iter()
        .map(|f| csv_quote(f))
        .collect::<Vec<_>>()
        .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    Ok(Zeroizing::new(out))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' | b'@' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_handles_quotes_newlines_and_bom() {
        let text = "\u{feff}a,b,c\r\n1,\"two, with comma\",\"three \"\"quoted\"\"\"\n\"multi\nline\",,\n";
        let rows = parse_csv(text).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], vec!["a", "b", "c"]);
        assert_eq!(rows[1], vec!["1", "two, with comma", "three \"quoted\""]);
        assert_eq!(rows[2], vec!["multi\nline", "", ""]);
        assert!(parse_csv("a,\"unterminated").is_err());
        assert_eq!(csv_quote("plain"), "plain");
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn keepassxc_rows_become_logins_and_notes_with_tags_and_totp() {
        let text = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
                    \"Root/Work\",\"GitHub\",\"octocat\",\"hunter2\",\"https://github.com\",\"main account\",\"otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\",\"0\",\"2025-01-01T00:00:00Z\",\"2024-01-01T00:00:00Z\"\n\
                    \"Root\",\"Recipe\",\"\",\"\",\"\",\"two eggs\",\"\",\"0\",\"\",\"\"\n";
        let imported = parse(ImportFormat::Keepassxc, text).unwrap();
        assert_eq!(imported.records.len(), 2);
        assert!(imported.skipped.is_empty(), "{:?}", imported.skipped);
        let gh = &imported.records[0];
        assert_eq!(gh.kind, Kind::Login);
        assert_eq!(gh.attribute("username"), Some("octocat"));
        assert_eq!(gh.field("password").unwrap().expose_str().unwrap().as_str(), "hunter2");
        assert_eq!(gh.tags, vec!["Work"]);
        assert!(gh.totp.is_some());
        assert_eq!(gh.notes.as_ref().unwrap().expose_str().unwrap().as_str(), "main account");
        let note = &imported.records[1];
        assert_eq!(note.kind, Kind::Note);
        assert_eq!(note.field("body").unwrap().expose_str().unwrap().as_str(), "two eggs");
    }

    #[test]
    fn firefox_and_chrome_exports_import() {
        let ff = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                  \"https://accounts.example.com\",\"me@example.com\",\"p@ss\",\"\",\"https://accounts.example.com\",\"{1}\",\"1\",\"2\",\"3\"\n";
        let imported = parse(ImportFormat::Firefox, ff).unwrap();
        assert_eq!(imported.records.len(), 1);
        assert_eq!(imported.records[0].title.as_deref(), Some("accounts.example.com"));
        assert_eq!(imported.records[0].attribute("username"), Some("me@example.com"));

        let ch = "name,url,username,password,note\nExample,https://www.example.com/login,bob,secret!,remember\n";
        let imported = parse(ImportFormat::Chrome, ch).unwrap();
        assert_eq!(imported.records.len(), 1);
        assert_eq!(imported.records[0].title.as_deref(), Some("Example"));
        assert_eq!(
            imported.records[0].notes.as_ref().unwrap().expose_str().unwrap().as_str(),
            "remember"
        );
    }

    #[test]
    fn bitwarden_json_maps_every_item_type() {
        let text = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Work"}],
          "items": [
            {"type": 1, "name": "GitHub", "folderId": "f1", "favorite": true, "notes": "n",
             "login": {"username": "octocat", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP",
                       "uris": [{"uri": "https://github.com"}]},
             "fields": [{"name": "Recovery code", "value": "abc", "type": 1}, {"name": "Plan", "value": "pro", "type": 0}]},
            {"type": 2, "name": "Note", "notes": "the body"},
            {"type": 3, "name": "Visa", "card": {"cardholderName": "A B", "brand": "Visa", "number": "4111", "expMonth": "1", "expYear": "2030", "code": "123"}},
            {"type": 4, "name": "Passport", "identity": {"firstName": "A", "lastName": "B", "passportNumber": "P123", "country": "GB"}},
            {"type": 9, "name": "Unknown"}
          ]}"#;
        let imported = parse(ImportFormat::Bitwarden, text).unwrap();
        assert_eq!(imported.records.len(), 4);
        assert_eq!(imported.skipped.len(), 1);
        let gh = &imported.records[0];
        assert_eq!(gh.kind, Kind::Login);
        assert!(gh.tags.contains(&"Work".to_string()) && gh.tags.contains(&"favorite".to_string()));
        assert!(gh.totp.is_some());
        assert_eq!(gh.field("recovery_code").unwrap().expose_str().unwrap().as_str(), "abc");
        assert_eq!(gh.attribute("plan"), Some("pro"));
        assert_eq!(imported.records[1].kind, Kind::Note);
        assert_eq!(imported.records[2].kind, Kind::Bank);
        assert_eq!(imported.records[2].field("account_number").unwrap().expose_str().unwrap().as_str(), "4111");
        assert_eq!(imported.records[3].kind, Kind::Id);
        assert_eq!(imported.records[3].attribute("id_type"), Some("passport"));
        assert_eq!(imported.records[3].field("number").unwrap().expose_str().unwrap().as_str(), "P123");
    }

    #[test]
    fn an_encrypted_bitwarden_export_is_refused_with_advice() {
        let err = parse(ImportFormat::Bitwarden, r#"{"encrypted": true, "items": []}"#).unwrap_err();
        assert!(err.to_string().contains("unencrypted"));
    }

    #[test]
    fn generic_csv_uses_synonyms_and_keeps_extra_columns() {
        let text = "Site,Login,Pass,Website,Comment,Department\nExample,bob,pw,https://e.com,hi,Ops\n";
        let imported = parse(ImportFormat::Csv, text).unwrap();
        let r = &imported.records[0];
        assert_eq!(r.title.as_deref(), Some("Example"));
        assert_eq!(r.attribute("username"), Some("bob"));
        assert_eq!(r.attribute("url"), Some("https://e.com"));
        assert_eq!(r.attribute("department"), Some("Ops"));
        assert_eq!(r.field("password").unwrap().expose_str().unwrap().as_str(), "pw");
    }

    #[test]
    fn export_roundtrips_through_keepassxc_csv() {
        let mut r = Record::new(Kind::Login, Some("GitHub".into()));
        r.set_attribute("username", "octocat");
        r.set_attribute("url", "https://github.com");
        r.set_field("password", Secret::from_str("hun,ter\"2"));
        r.tags = vec!["Work".into()];
        let (bytes, mut cfg) = parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap();
        cfg.issuer = Some("GitHub".into());
        r.set_field("totp", Secret::new(&bytes));
        r.totp = Some(cfg);

        let csv = render(&[r], ExportFormat::Keepassxc).unwrap();
        let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
        assert_eq!(back.records.len(), 1, "{:?}", back.skipped);
        let b = &back.records[0];
        assert_eq!(b.title.as_deref(), Some("GitHub"));
        assert_eq!(b.attribute("username"), Some("octocat"));
        assert_eq!(b.field("password").unwrap().expose_str().unwrap().as_str(), "hun,ter\"2");
        assert_eq!(b.tags, vec!["Work"]);
        assert!(b.totp.is_some());
        assert_eq!(b.field("totp").unwrap().open().as_slice(), bytes.as_slice());
    }

    #[test]
    fn keepassxc_roundtrip_keeps_non_login_kinds() {
        let mut api = Record::new(Kind::Api, Some("prod".into()));
        api.set_attribute("service", "aws");
        api.set_field("secret_key", Secret::from_str("AKIA"));
        let mut note = Record::new(Kind::Note, Some("memo".into()));
        note.set_field("body", Secret::from_str("line one\nline two"));
        let csv = render(&[api, note], ExportFormat::Keepassxc).unwrap();
        let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
        assert_eq!(back.records.len(), 2, "{:?}", back.skipped);
        assert_eq!(back.records[0].kind, Kind::Api);
        assert_eq!(back.records[0].field("secret_key").unwrap().expose_str().unwrap().as_str(), "AKIA");
        // The attribute travels in the marked block, not smuggled into notes.
        assert_eq!(back.records[0].attribute("service"), Some("aws"));
        assert!(back.records[0].notes.is_none(), "the metadata block is not left in the notes");
        assert_eq!(back.records[1].kind, Kind::Note);
        assert_eq!(back.records[1].field("body").unwrap().expose_str().unwrap().as_str(), "line one\nline two");
    }

    /// A non-primary secret field whose value spans lines used to come back as
    /// only its first line: the meta block is line-oriented and the value's
    /// newlines split it. Escaping fixes the round trip.
    #[test]
    fn a_multi_line_secondary_secret_survives_the_keepassxc_round_trip() {
        let mut r = Record::new(Kind::Login, Some("Bank".into()));
        r.set_attribute("username", "me");
        r.set_field("password", Secret::from_str("primary"));
        let codes = "aaaa-bbbb\ncccc-dddd\neeee-ffff";
        r.set_field("backup_codes", Secret::from_str(codes));

        let csv = render(&[r], ExportFormat::Keepassxc).unwrap();
        let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
        assert_eq!(back.records.len(), 1, "{:?}", back.skipped);
        let b = &back.records[0];
        assert_eq!(b.field("password").unwrap().expose_str().unwrap().as_str(), "primary");
        assert_eq!(
            b.field("backup_codes").unwrap().expose_str().unwrap().as_str(),
            codes,
            "a multi-line secondary secret must not be truncated"
        );
    }

    /// And a value that begins with a directive keyword cannot inject one: the
    /// newline that would have started a fresh physical line is escaped away.
    #[test]
    fn a_secondary_secret_cannot_inject_a_meta_directive() {
        let mut r = Record::new(Kind::Login, Some("x".into()));
        r.set_attribute("username", "me");
        r.set_field("password", Secret::from_str("primary"));
        let payload = "real\nkind: note\nattr injected: yes";
        r.set_field("note", Secret::from_str(payload));

        let csv = render(&[r], ExportFormat::Keepassxc).unwrap();
        let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
        let b = &back.records[0];
        assert_eq!(b.kind, Kind::Login, "the injected kind must not take effect");
        assert_eq!(b.attribute("injected"), None, "no attribute may be injected");
        assert_eq!(
            b.field("note").unwrap().expose_str().unwrap().as_str(),
            payload,
            "the value must survive whole, keyword lines and all"
        );
    }

    #[test]
    fn cxf_round_trips_the_kinds_it_exports() {
        use blackbag_core::passkey::{Credential, NewCredential, PRIVATE_KEY_FIELD};

        let mut login = Record::new(Kind::Login, Some("GitHub".into()));
        login.set_attribute("username", "octocat");
        login.set_attribute("url", "https://github.com");
        login.set_field("password", Secret::from_str("hunter2"));

        let mut totp = Record::new(Kind::Totp, Some("Bank 2FA".into()));
        totp.set_field("totp", Secret::new(b"12345678901234567890"));
        totp.totp = Some(TotpConfig {
            issuer: Some("Bank".into()),
            account: Some("me".into()),
            digits: 6,
            step: 30,
            ..TotpConfig::default()
        });

        let mut note = Record::new(Kind::Note, Some("memo".into()));
        note.set_field("body", Secret::from_str("line one\nline two"));

        let mut ssh = Record::new(Kind::Ssh, Some("laptop".into()));
        ssh.set_attribute("comment", "me@laptop");
        ssh.set_field(blackbag_core::ssh::SSH_SEED_FIELD, Secret::new(&[7u8; 32]));

        // A real passkey, private key and all.
        let (created, _seed) = Credential::create(NewCredential {
            rp_id: "example.com".into(),
            rp_name: Some("Example".into()),
            user_handle: b"user-handle".to_vec(),
            user_name: Some("ada".into()),
            user_display_name: Some("Ada".into()),
            user_verified: true,
            with_prf: false,
            backed_up: false,
            algorithms: Vec::new(),
        })
        .unwrap();
        let mut passkey = Record::new(Kind::Passkey, Some(created.credential.config.describe()));
        passkey.passkey = Some(created.credential.config.clone());
        passkey.set_field(PRIVATE_KEY_FIELD, Secret::new(created.credential.private_key()));

        let originals = vec![login, totp, note, ssh, passkey];
        let cxf = render(&originals, ExportFormat::Cxf).unwrap();

        // It is valid CXF v1 with the standard shape a foreign reader expects.
        let doc: serde_json::Value = serde_json::from_str(&cxf).unwrap();
        assert_eq!(doc["version"]["major"], 1);
        let items = doc["accounts"][0]["items"].as_array().unwrap();
        assert_eq!(items.len(), 5);
        // The passkey item carries a standard passkey credential AND the key.
        let pk = items.iter().find(|i| i["credentials"][0]["type"] == "passkey").unwrap();
        assert_eq!(pk["credentials"][0]["rpId"], "example.com");
        assert!(!pk["credentials"][0]["key"].as_str().unwrap().is_empty());

        // And our own re-import is exact.
        let back = parse(ImportFormat::Cxf, &cxf).unwrap();
        assert_eq!(back.records.len(), 5, "{:?}", back.skipped);
        let by_kind = |k: Kind| back.records.iter().find(|r| r.kind == k).unwrap();

        let l = by_kind(Kind::Login);
        assert_eq!(l.attribute("username"), Some("octocat"));
        assert_eq!(l.field("password").unwrap().expose_str().unwrap().as_str(), "hunter2");

        let t = by_kind(Kind::Totp);
        assert_eq!(t.field("totp").unwrap().open().as_slice(), b"12345678901234567890");
        assert_eq!(t.totp.as_ref().unwrap().issuer.as_deref(), Some("Bank"));

        let s = by_kind(Kind::Ssh);
        assert_eq!(s.field(blackbag_core::ssh::SSH_SEED_FIELD).unwrap().open().as_slice(), &[7u8; 32]);

        let p = by_kind(Kind::Passkey);
        assert_eq!(p.passkey.as_ref().unwrap().rp_id, "example.com");
        assert_eq!(
            p.field(PRIVATE_KEY_FIELD).unwrap().open().as_slice(),
            created.credential.private_key(),
            "the passkey private key survives the CXF round trip"
        );
    }

    /// A foreign CXF (no `_blackbag` extension) still imports its common types.
    #[test]
    fn a_foreign_cxf_imports_by_its_standard_credentials() {
        let doc = r#"{
          "version": {"major":1,"minor":0},
          "exporterDisplayName": "SomeOtherManager",
          "accounts": [{
            "id":"eA","items":[
              {"title":"Mail","credentials":[
                {"type":"basic-auth",
                 "urls":["https://mail.example"],
                 "username":{"fieldType":"string","value":"alice"},
                 "password":{"fieldType":"concealed-string","value":"s3cret"}}]},
              {"title":"VPN 2FA","credentials":[
                {"type":"totp","secret":"GEZDGNBVGY3TQOJQ","period":30,"digits":6,"issuer":"VPN"}]},
              {"title":"scratch","credentials":[
                {"type":"note","content":"remember the milk"}]}
            ]}
          ]
        }"#;
        let back = parse(ImportFormat::Cxf, doc).unwrap();
        assert_eq!(back.records.len(), 3, "{:?}", back.skipped);
        let mail = back.records.iter().find(|r| r.title.as_deref() == Some("Mail")).unwrap();
        assert_eq!(mail.kind, Kind::Login);
        assert_eq!(mail.attribute("username"), Some("alice"));
        assert_eq!(mail.field("password").unwrap().expose_str().unwrap().as_str(), "s3cret");
        let vpn = back.records.iter().find(|r| r.title.as_deref() == Some("VPN 2FA")).unwrap();
        assert_eq!(vpn.kind, Kind::Totp);
        assert!(vpn.totp.is_some());
        let scratch = back.records.iter().find(|r| r.title.as_deref() == Some("scratch")).unwrap();
        assert_eq!(scratch.kind, Kind::Note);
    }

    /// The latent bug the CXF work surfaced: a passkey must survive the
    /// Black-Bag JSON export too, config and private key both.
    #[test]
    fn a_passkey_survives_the_json_round_trip() {
        use blackbag_core::passkey::{Credential, NewCredential, PRIVATE_KEY_FIELD};
        let (created, _) = Credential::create(NewCredential {
            rp_id: "example.com".into(),
            rp_name: None,
            user_handle: b"u".to_vec(),
            user_name: Some("ada".into()),
            user_display_name: None,
            user_verified: true,
            with_prf: false,
            backed_up: false,
            algorithms: Vec::new(),
        })
        .unwrap();
        let mut pk = Record::new(Kind::Passkey, Some("example.com".into()));
        pk.passkey = Some(created.credential.config.clone());
        pk.set_field(PRIVATE_KEY_FIELD, Secret::new(created.credential.private_key()));

        let json = render(&[pk], ExportFormat::Json).unwrap();
        let back = parse(ImportFormat::BlackBag, &json).unwrap();
        assert_eq!(back.records.len(), 1, "{:?}", back.skipped);
        let r = &back.records[0];
        assert_eq!(r.passkey.as_ref().unwrap().rp_id, "example.com");
        assert_eq!(
            r.field(PRIVATE_KEY_FIELD).unwrap().open().as_slice(),
            created.credential.private_key()
        );
    }

    #[test]
    fn cxf_refuses_a_non_cxf_document() {
        assert!(parse(ImportFormat::Cxf, r#"{"format":"black-bag-export"}"#).is_err());
        assert!(parse(ImportFormat::Cxf, "not json").is_err());
    }

    /// The shape the review found broken: an SSH key carrying both a
    /// private key and its passphrase came back with the passphrase in the
    /// key field and the key demoted to a note.
    #[test]
    fn a_record_with_two_secrets_survives_the_keepassxc_round_trip() {
        let mut ssh = Record::new(Kind::Ssh, Some("build box".into()));
        ssh.set_attribute("label", "ci");
        ssh.set_attribute("comment", "rotate yearly");
        ssh.set_field("private_key", Secret::from_str("-----BEGIN KEY-----\nabc\n"));
        ssh.set_field("passphrase", Secret::from_str("unlock me"));
        ssh.notes = Some(Secret::from_str("kept in the safe"));
        ssh.tags = vec!["infra".into()];

        let csv = render(&[ssh], ExportFormat::Keepassxc).unwrap();
        let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
        assert_eq!(back.records.len(), 1, "{:?}", back.skipped);
        let r = &back.records[0];

        assert_eq!(r.kind, Kind::Ssh);
        assert_eq!(r.title.as_deref(), Some("build box"));
        assert_eq!(
            r.field("private_key").unwrap().expose_str().unwrap().as_str(),
            "-----BEGIN KEY-----\nabc\n",
            "the key must come back as the key"
        );
        assert_eq!(
            r.field("passphrase").unwrap().expose_str().unwrap().as_str(),
            "unlock me",
            "and the passphrase as the passphrase"
        );
        assert_eq!(r.attribute("label"), Some("ci"));
        assert_eq!(r.attribute("comment"), Some("rotate yearly"));
        assert_eq!(r.notes.as_ref().unwrap().expose_str().unwrap().as_str(), "kept in the safe");
        assert_eq!(r.tags, vec!["infra"]);
    }

    /// A title that is a spreadsheet formula must not come out of the export
    /// as one, and must come back in unchanged.
    #[test]
    fn formula_shaped_cells_are_defanged_on_the_way_out_and_restored_on_the_way_in() {
        for hostile in ["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)"] {
            let mut r = Record::new(Kind::Login, Some(hostile.into()));
            r.set_attribute("username", hostile);
            r.set_field("password", Secret::from_str(hostile));

            let csv = render(&[r], ExportFormat::Keepassxc).unwrap();
            let title_cell = csv.lines().nth(1).unwrap();
            assert!(
                title_cell.contains(&format!("'{hostile}")),
                "the title column was not defanged: {title_cell}"
            );

            let back = parse(ImportFormat::Keepassxc, &csv).unwrap();
            let r = &back.records[0];
            assert_eq!(r.title.as_deref(), Some(hostile), "defang must be reversible");
            assert_eq!(r.attribute("username"), Some(hostile));
            // The password column is never defanged: an apostrophe there
            // would become part of the secret.
            assert_eq!(
                r.field("password").unwrap().expose_str().unwrap().as_str(),
                hostile
            );
        }

        // A value that genuinely starts with an apostrophe is left alone.
        assert_eq!(undefang("'tis"), "'tis");
        assert_eq!(undefang("'=1"), "=1");
        assert_eq!(defang("safe"), "safe");
    }

    /// A Bitwarden custom field may not quietly replace the item's own.
    #[test]
    fn a_colliding_custom_field_is_renamed_and_reported() {
        let text = r#"{
          "encrypted": false,
          "items": [
            {"type": 1, "name": "GitHub",
             "login": {"username": "octocat", "password": "real-password", "totp": "JBSWY3DPEHPK3PXP"},
             "fields": [
               {"name": "password", "value": "decoy", "type": 1},
               {"name": "TOTP", "value": "not-a-secret", "type": 0},
               {"name": "username", "value": "decoy-user", "type": 0}
             ]}
          ]}"#;
        let imported = parse(ImportFormat::Bitwarden, text).unwrap();
        let r = &imported.records[0];
        assert_eq!(
            r.field("password").unwrap().expose_str().unwrap().as_str(),
            "real-password",
            "the login password was overwritten by a custom field"
        );
        assert_eq!(r.attribute("username"), Some("octocat"));
        assert!(r.totp.is_some(), "the decoded TOTP config survived");
        assert_eq!(r.field("custom_password").unwrap().expose_str().unwrap().as_str(), "decoy");
        assert_eq!(r.attribute("custom_username"), Some("decoy-user"));
        assert_eq!(r.attribute("custom_totp"), Some("not-a-secret"));
        assert_eq!(imported.skipped.len(), 3, "each collision is reported: {:?}", imported.skipped);
    }

    #[test]
    fn json_export_carries_every_field_and_says_it_is_plaintext() {
        let mut r = Record::new(Kind::Api, Some("prod".into()));
        r.set_attribute("service", "aws");
        r.set_field("secret_key", Secret::from_str("AKIA..."));
        r.notes = Some(Secret::from_str("rotate quarterly"));
        let json = render(&[r], ExportFormat::Json).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["plaintext"], true);
        assert_eq!(doc["records"][0]["secrets"]["secret_key"]["value"], "AKIA...");
        assert_eq!(doc["records"][0]["secrets"]["secret_key"]["encoding"], "utf8");
        assert_eq!(doc["records"][0]["notes"], "rotate quarterly");
        assert_eq!(doc["records"][0]["attributes"]["service"], "aws");
    }

    /// Junk in must not become records out.
    /// An export you cannot import is a backup you cannot restore.
    #[test]
    fn the_json_export_imports_back_exactly() {
        let mut login = Record::new(Kind::Login, Some("GitHub".into()));
        login.set_attribute("username", "octocat");
        login.set_attribute("url", "https://github.com");
        login.set_field("password", Secret::from_str("hunter2"));
        login.tags = vec!["work".into()];
        login.notes = Some(Secret::from_str("the main one"));

        let mut totp = Record::new(Kind::Totp, Some("GitHub 2FA".into()));
        let (bytes, mut cfg) =
            parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .unwrap();
        cfg.issuer = Some("GitHub".into());
        cfg.digits = 8;
        cfg.step = 60;
        // A raw seed is not UTF-8, which is the case the untagged export
        // could not represent unambiguously.
        totp.set_field("totp", Secret::new(&bytes));
        totp.totp = Some(cfg);

        let json = render(&[login, totp], ExportFormat::Json).unwrap();
        let back = parse(ImportFormat::BlackBag, &json).unwrap();
        assert_eq!(back.records.len(), 2, "{:?}", back.skipped);
        assert!(back.skipped.is_empty(), "{:?}", back.skipped);

        let a = &back.records[0];
        assert_eq!(a.kind, Kind::Login);
        assert_eq!(a.title.as_deref(), Some("GitHub"));
        assert_eq!(a.attribute("username"), Some("octocat"));
        assert_eq!(a.field("password").unwrap().expose_str().unwrap().as_str(), "hunter2");
        assert_eq!(a.tags, vec!["work"]);
        assert_eq!(a.notes.as_ref().unwrap().expose_str().unwrap().as_str(), "the main one");

        let b = &back.records[1];
        assert_eq!(b.kind, Kind::Totp);
        assert_eq!(
            b.field("totp").unwrap().open().as_slice(),
            bytes.as_slice(),
            "a non-UTF-8 seed must survive the round trip byte for byte"
        );
        let cfg = b.totp.as_ref().unwrap();
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.step, 60);
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));

        // And something that is not one of our exports is refused by name.
        let err = parse(ImportFormat::BlackBag, r#"{"records": []}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a Black-Bag export"), "{err}");
    }

    #[test]
    fn blank_rows_are_dropped_and_an_unrecognisable_header_is_refused() {
        let with_blanks = "name,url,username,password,note\n\
                           Example,https://e.com,bob,pw,\n\
                           \n\
                           \n\
                           Other,https://o.com,ann,pw2,\n";
        let imported = parse(ImportFormat::Chrome, with_blanks).unwrap();
        assert_eq!(imported.records.len(), 2, "blank lines became records");

        // A header that names none of the columns the format has is a file
        // this parser has no business guessing at.
        let wrong = "alpha,beta,gamma\n1,2,3\n";
        let err = parse(ImportFormat::Chrome, wrong).unwrap_err().to_string();
        assert!(err.contains("does not look like a Chrome export"), "{err}");
        assert!(parse(ImportFormat::Csv, wrong).is_err());
        assert!(parse(ImportFormat::Keepassxc, wrong).is_err());

        // And a real header still works.
        assert!(parse(ImportFormat::Csv, "Site,Login,Pass\nA,b,c\n").is_ok());
    }

    #[test]
    fn host_extraction_is_forgiving() {
        assert_eq!(host_of("https://www.example.com/login?x=1"), Some("example.com".into()));
        assert_eq!(host_of("http://user:pw@host.tld:8443/"), Some("host.tld".into()));
        assert_eq!(host_of("example.org"), Some("example.org".into()));
        assert_eq!(host_of(""), None);
    }
}
