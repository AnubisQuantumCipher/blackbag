//! Import from other password managers, and export for leaving.
//!
//! A vault you cannot move into is a vault nobody switches to, and a vault
//! you cannot move out of is a trap. Both directions exist here, and both
//! are deliberately unglamorous: the formats are the ones the other tools
//! actually write, parsed by hand, with the mapping to Black-Bag's kinds
//! stated in one table per format so it can be read and argued with.
//!
//! Nothing here touches the network. Every parser reads a file the user
//! named on the command line; secrets inside it are handed to `Record`s and
//! then to the engine, and the input buffer is wiped on the way out.
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
}

/// Formats this build writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ExportFormat {
    Json,
    Keepassxc,
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
    }
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
    Ok((header, rows))
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
    }
}

/// Pull a trailing `kind: xxx` line out of a Notes column, returning the
/// kind and the notes without that line.
fn split_kind_hint(notes: &str) -> (Option<Kind>, String) {
    let mut kind = None;
    let mut kept = Vec::new();
    for line in notes.lines() {
        if let Some(rest) = line.strip_prefix("kind: ") {
            if let Ok(k) = rest.trim().parse::<Kind>() {
                kind = Some(k);
                continue;
            }
        }
        kept.push(line);
    }
    (kind, kept.join("\n"))
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
                let key = fname.trim().to_ascii_lowercase().replace(' ', "_");
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
    let mut out = Imported::default();
    for (n, cells) in rows.iter().enumerate() {
        let row = Row {
            header: &header,
            cells,
        };
        let title = row.get("Title");
        let username = row.get("Username");
        let password = row.get("Password");
        let url = row.get("URL");
        let notes = row.get("Notes");
        let group = row.get("Group");
        // Our own export writes non-login kinds into Notes as a "kind: …"
        // line, so a Black-Bag → KeePassXC → Black-Bag round trip keeps the
        // kind rather than flattening everything into logins.
        let (kind_hint, notes) = split_kind_hint(notes);
        let mut record = match kind_hint {
            Some(kind) if kind != Kind::Login => {
                let mut r = Record::new(kind, Some(title.to_string()));
                set_attr_if(&mut r, "username", username);
                set_attr_if(&mut r, "url", url);
                let primary = primary_field_for(kind);
                set_secret_if(&mut r, primary, password);
                set_notes_if(&mut r, &notes);
                r
            }
            _ if username.is_empty() && password.is_empty() && url.is_empty() => {
                let mut r = Record::new(Kind::Note, Some(title.to_string()));
                set_secret_if(&mut r, "body", &notes);
                r
            }
            _ => login(title, username, password, url, &notes),
        };
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
    }
}

fn render_json(records: &[Record]) -> Result<Zeroizing<String>> {
    let mut items = Vec::with_capacity(records.len());
    for r in records {
        let mut secrets = serde_json::Map::new();
        for f in &r.fields {
            let value = f
                .secret
                .expose_str()
                .map(|s| serde_json::Value::String(s.to_string()))
                .unwrap_or_else(|_| {
                    serde_json::Value::String(
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, f.secret.open().as_slice()),
                    )
                });
            secrets.insert(f.name.clone(), value);
        }
        let notes = r
            .notes
            .as_ref()
            .and_then(|n| n.expose_str().ok())
            .map(|s| s.to_string());
        items.push(serde_json::json!({
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
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }));
    }
    let doc = serde_json::json!({
        "format": "black-bag-export",
        "version": 1,
        "plaintext": true,
        "records": items,
    });
    Ok(Zeroizing::new(serde_json::to_string_pretty(&doc)?))
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
        let primary = ["password", "passphrase", "secret_key", "private_key", "seed",
                       "account_number", "number", "body", "notes", "payload"]
            .iter()
            .find_map(|name| r.field(name).map(|s| (name, s)));
        let password = primary
            .and_then(|(_, s)| s.expose_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let url = r.attribute("url").unwrap_or("").to_string();
        // Everything that does not fit a column goes into Notes as k=v
        // lines, so nothing is silently dropped on the way out.
        let mut notes = Vec::new();
        if let Some(n) = r.notes.as_ref().and_then(|n| n.expose_str().ok()) {
            notes.push(n.to_string());
        }
        for (k, v) in &r.attributes {
            if k != "username" && k != "url" && k != "account" {
                notes.push(format!("{k}: {v}"));
            }
        }
        for f in &r.fields {
            if Some(f.name.as_str()) != primary.map(|(n, _)| *n) && f.name != "totp" {
                if let Ok(v) = f.secret.expose_str() {
                    notes.push(format!("{}: {}", f.name, *v));
                }
            }
        }
        if r.kind != Kind::Login {
            notes.push(format!("kind: {}", r.kind.as_str()));
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
        let line = [
            group,
            title,
            username,
            password,
            url,
            notes.join("\n"),
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
        assert_eq!(back.records[0].notes.as_ref().unwrap().expose_str().unwrap().as_str(), "service: aws");
        assert_eq!(back.records[1].kind, Kind::Note);
        assert_eq!(back.records[1].field("body").unwrap().expose_str().unwrap().as_str(), "line one\nline two");
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
        assert_eq!(doc["records"][0]["secrets"]["secret_key"], "AKIA...");
        assert_eq!(doc["records"][0]["notes"], "rotate quarterly");
        assert_eq!(doc["records"][0]["attributes"]["service"], "aws");
    }

    #[test]
    fn host_extraction_is_forgiving() {
        assert_eq!(host_of("https://www.example.com/login?x=1"), Some("example.com".into()));
        assert_eq!(host_of("http://user:pw@host.tld:8443/"), Some("host.tld".into()));
        assert_eq!(host_of("example.org"), Some("example.org".into()));
        assert_eq!(host_of(""), None);
    }
}
