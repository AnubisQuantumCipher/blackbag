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
                meta.attributes.push((k.to_string(), v.to_string()));
            }
        } else if let Some(rest) = line.strip_prefix("secret ") {
            if let Some((k, v)) = rest.split_once(": ") {
                meta.secrets.push((k.to_string(), v.to_string()));
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
    }
}

fn render_json(records: &[Record]) -> Result<Zeroizing<String>> {
    let mut items = Vec::with_capacity(records.len());
    for r in records {
        let mut secrets = serde_json::Map::new();
        for f in &r.fields {
            // A secret that is not UTF-8 — a raw TOTP seed, a binary key —
            // is base64, and says so. An untagged fallback was
            // indistinguishable from a value that merely looked like base64,
            // so nothing could import this file back without guessing.
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
                meta.push(format!("attr {k}: {v}"));
            }
        }
        for f in &r.fields {
            if Some(f.name.as_str()) != primary.map(|(n, _)| n) && f.name != "totp" {
                if let Ok(v) = f.secret.expose_str() {
                    meta.push(format!("secret {}: {}", f.name, *v));
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
