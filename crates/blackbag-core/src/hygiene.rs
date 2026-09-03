//! Local credential hygiene analysis.
//!
//! Everything here is computed in this process, from records that are already
//! decrypted in memory. There is no network call in this module and there must
//! never be one: "nothing leaves the machine" is a property users are invited to
//! rely on, and one lookup would end it. The analysis reads secret bytes to
//! measure them — length, whether every byte is an ASCII digit — and emits only
//! those measurements, never the bytes.
//!
//! # How reuse is found without comparing secrets
//!
//! [`crate::record::Secret::handle`] is a BLAKE3 derive-key tag over a domain
//! string and the secret bytes, truncated to four bytes. This module passes the
//! *field name* as the domain, so two records whose `password` fields hold the
//! same bytes produce the same eight hex characters, and nothing else does. No
//! secret is compared against another, copied, or held outside its own
//! page-locked buffer.
//!
//! Three consequences follow. All three are reported rather than papered over:
//!
//! * **A handle is 32 bits.** Two unrelated secrets share one with probability
//!   about 2^-32 per pair. A [`ReuseCluster`] therefore states that its members
//!   *share a handle* — not that they provably hold the same bytes. The handle
//!   is deliberately short because it is shown in the interface; lengthening it
//!   here to buy certainty would break the thing it is for.
//! * **The domain is the field name verbatim.** A `password` field and a
//!   `Password` field occupy different lanes, and reuse between a `password` and
//!   a `passphrase` field is invisible to this analysis. An empty
//!   `reuse_clusters` is not evidence that nothing is reused.
//! * **Non-reversible is not the same as safe to publish.** A handle over a
//!   low-entropy secret — a four-digit PIN has ten thousand candidates — falls
//!   to an offline search immediately. A [`VaultReport`] carries handles and
//!   record titles, so it lives in the same trust domain as the open vault:
//!   never in `status.json`, never in a log, never on argv. [`summary_line`]
//!   carries counts alone and is safe to print.
//!
//! # What a clean report does not say
//!
//! * `Stale` is measured from `Record::updated_at`, which moves when *anything*
//!   on the record is edited — a tag, a URL. The vault stores no per-field
//!   change time. `age_days` is therefore a **lower bound** on the age of the
//!   credential, and the absence of a `Stale` issue does not mean the password
//!   is fresh.
//! * `NoTotp` means no second factor is stored *in this vault* for the record.
//!   It says nothing about whether the account has 2FA enabled elsewhere.
//! * Rules are applied per kind and per field name. A field this module has no
//!   defensible expectation for is left alone, and silence about it is silence,
//!   not a pass.
//!
//! # The figure
//!
//! There is no score out of a hundred. [`HygieneScore`] carries counts by
//! severity plus a demerit total, and the total is exactly
//!
//! ```text
//! demerits = 5 * (high issues) + 2 * (medium issues) + 1 * (low issues)
//! ```
//!
//! summed over every issue on every record. `contributions` lists what each
//! record cost, so a caller can show the arithmetic rather than assert it; the
//! contributions sum to `demerits`, and the tests assert both. Demerits rise as
//! the vault gets worse and have no ceiling, so there is no denominator to argue
//! about and no way for a large tidy vault to score worse than a small filthy
//! one by an accident of scaling.
//!
//! # Thresholds
//!
//! Every threshold is a named constant, reachable and overridable through
//! [`Policy`]. [`MIN_ALL_DIGIT_DIGITS`] is the only one derived rather than
//! chosen: it is the smallest `k` with `10^k >= 62^12`, so an all-numeric secret
//! at that length has at least as many candidates as a twelve-character
//! alphanumeric one. `62^12 = 3226266762397899821056`, which exceeds `10^21` and
//! falls short of `10^22`, giving `k = 22` (exact integer arithmetic).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::record::{Kind, Record};

/// Byte floor for a user-chosen passphrase that is not all digits.
pub const MIN_PASSPHRASE_BYTES: usize = 12;

/// Digit floor for a secret whose every byte is an ASCII digit. See the module
/// docs for the derivation; it is higher than [`MIN_PASSPHRASE_BYTES`] because a
/// ten-symbol alphabet buys far less per character.
pub const MIN_ALL_DIGIT_DIGITS: usize = 22;

/// Digit floor for a field named as a PIN, on kinds where the PIN is chosen by
/// the owner rather than issued to them.
pub const MIN_PIN_DIGITS: usize = 6;

/// Days after which a rotatable credential's record counts as stale.
pub const STALE_AFTER_DAYS: i64 = 365;

pub const WEIGHT_HIGH: u64 = 5;
pub const WEIGHT_MEDIUM: u64 = 2;
pub const WEIGHT_LOW: u64 = 1;

/// The thresholds an analysis run applies. `Default` is the documented policy;
/// the fields exist so a caller — or a test pinning a boundary — can state a
/// different one explicitly rather than patch a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub min_passphrase_bytes: usize,
    pub min_all_digit_digits: usize,
    pub min_pin_digits: usize,
    pub stale_after_days: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_passphrase_bytes: MIN_PASSPHRASE_BYTES,
            min_all_digit_digits: MIN_ALL_DIGIT_DIGITS,
            min_pin_digits: MIN_PIN_DIGITS,
            stale_after_days: STALE_AFTER_DAYS,
        }
    }
}

/// How much an issue costs. Declaration order is worst-first, so the derived
/// `Ord` sorts a list of issues the way a reader wants to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn weight(self) -> u64 {
        match self {
            Severity::High => WEIGHT_HIGH,
            Severity::Medium => WEIGHT_MEDIUM,
            Severity::Low => WEIGHT_LOW,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One finding about one record.
///
/// Every variant carries the threshold it was judged against, so a stored report
/// stays readable after the policy changes and no reader has to guess which
/// floor applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Issue {
    /// This field's secret produces the same handle as the same-named field on
    /// the listed records. A shared handle, not a proven shared secret.
    Reused {
        field: String,
        shared_with: Vec<Uuid>,
        handle: String,
    },
    /// A chosen passphrase below the byte floor.
    Short {
        field: String,
        bytes: usize,
        floor: usize,
    },
    /// The record has not been modified for at least `threshold_days`. This is a
    /// lower bound on the credential's age, never a measurement of it.
    Stale {
        last_modified: DateTime<Utc>,
        age_days: i64,
        threshold_days: i64,
    },
    /// No second factor is stored in this vault for a record of a kind where one
    /// would be meaningful. Says nothing about the account itself.
    NoTotp,
    /// A secret made entirely of ASCII digits, below the floor that applies to
    /// it. Raised instead of `Short`, never alongside it.
    WeakPin {
        field: String,
        digits: usize,
        floor: usize,
    },
    /// Another record of the same kind carries the same title, so the two cannot
    /// be told apart in a list. Titles are compared case-insensitively after
    /// trimming, and only within one kind: a `login` and a `totp` sharing a title
    /// are a deliberate pair, not a duplicate.
    DuplicateTitle { others: Vec<Uuid> },
    /// The value appears in the Pwned Passwords corpus. Only present after the
    /// user has run a breach check in this session — see `breach.rs` for what
    /// leaves the machine, and how little.
    Exposed { field: String, breaches: u64 },
}

impl Issue {
    pub fn severity(&self) -> Severity {
        match self {
            Issue::Reused { .. } | Issue::WeakPin { .. } | Issue::Exposed { .. } => Severity::High,
            Issue::Short { .. } => Severity::Medium,
            Issue::Stale { .. } | Issue::NoTotp | Issue::DuplicateTitle { .. } => Severity::Low,
        }
    }

    /// Stable identifier, in the style of `status::Finding::id`.
    pub fn code(&self) -> &'static str {
        match self {
            Issue::Reused { .. } => "REUSED",
            Issue::Short { .. } => "SHORT",
            Issue::Stale { .. } => "STALE",
            Issue::NoTotp => "NO_TOTP",
            Issue::WeakPin { .. } => "WEAK_PIN",
            Issue::DuplicateTitle { .. } => "DUPLICATE_TITLE",
            Issue::Exposed { .. } => "EXPOSED",
        }
    }

    /// A printable sentence. Carries counts, lengths, thresholds and handles —
    /// never secret bytes, and never a title.
    pub fn describe(&self) -> String {
        match self {
            Issue::Reused {
                field,
                shared_with,
                handle,
            } => format!(
                "{field} shares handle {handle} with {} other record(s)",
                shared_with.len()
            ),
            Issue::Short { field, bytes, floor } => {
                format!("{field} is {bytes} bytes, under the {floor}-byte floor")
            }
            Issue::Stale {
                age_days,
                threshold_days,
                ..
            } => format!(
                "not modified for {age_days} days, at or past the {threshold_days}-day mark"
            ),
            Issue::NoTotp => "no second factor stored in this vault for this record".to_string(),
            Issue::WeakPin {
                field,
                digits,
                floor,
            } => format!(
                "{field} is {digits} digits and nothing else, under the {floor}-digit floor"
            ),
            Issue::DuplicateTitle { others } => format!(
                "title is shared with {} other record(s) of the same kind",
                others.len()
            ),
            Issue::Exposed { field, breaches } => format!(
                "{field} appears {breaches} time(s) in known data breaches"
            ),
        }
    }
}

/// A record that has at least one issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordReport {
    pub id: Uuid,
    pub title: Option<String>,
    pub kind: Kind,
    /// Worst first.
    pub issues: Vec<Issue>,
}

impl RecordReport {
    /// What this record contributes to [`HygieneScore::demerits`].
    pub fn demerits(&self) -> u64 {
        self.issues.iter().map(|i| i.severity().weight()).sum()
    }

    /// The severity of the worst issue, or `None` when there are none.
    pub fn worst(&self) -> Option<Severity> {
        self.issues.iter().map(Issue::severity).min()
    }
}

/// The records whose same-named field produced one handle.
///
/// `members.len()` is always at least two. Membership means "shares a handle";
/// see the module docs on the 32-bit collision space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseCluster {
    pub field: String,
    pub handle: String,
    pub members: Vec<Uuid>,
}

/// What one record cost, so the total can be shown rather than asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreContribution {
    pub id: Uuid,
    pub demerits: u64,
}

/// Counts by severity plus a decomposable total. See the module docs for the
/// formula; nothing here is normalised, scaled, or capped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HygieneScore {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// `5 * high + 2 * medium + 1 * low`, equal to the sum of `contributions`.
    pub demerits: u64,
    pub records_with_issues: usize,
    pub clean_records: usize,
    /// Costliest first, then by id. Empty when the vault is clean.
    pub contributions: Vec<ScoreContribution>,
}

impl HygieneScore {
    pub fn total_issues(&self) -> usize {
        self.high + self.medium + self.low
    }
}

/// The result of one analysis run.
///
/// `records` holds an entry only for a record with at least one issue, so
/// `scanned - records.len() == score.clean_records` and a tidy vault yields an
/// empty vector rather than a wall of clean rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultReport {
    pub scanned: usize,
    pub records: Vec<RecordReport>,
    /// Sorted by field name then handle, so two runs over one vault agree.
    pub reuse_clusters: Vec<ReuseCluster>,
    pub score: HygieneScore,
}

impl VaultReport {
    pub fn is_clean(&self) -> bool {
        self.records.is_empty()
    }
}

/// Analyse `records` as of `now`, under the default [`Policy`].
///
/// `now` is a parameter rather than a call to `Utc::now`, so a run is a pure
/// function of its inputs and a test can pin a boundary exactly.
pub fn analyse(records: &[Record], now: DateTime<Utc>) -> VaultReport {
    analyse_with(records, now, Policy::default())
}

/// [`analyse`] under a stated policy.
pub fn analyse_with(records: &[Record], now: DateTime<Utc>, policy: Policy) -> VaultReport {
    analyse_with_exposure(records, now, policy, &crate::breach::ExposureMap::new())
}

/// [`analyse_with`], folding in the results of a breach check the user ran
/// earlier in this session. `exposure` maps `(record id, field name)` to the
/// number of breaches the value appears in.
pub fn analyse_with_exposure(
    records: &[Record],
    now: DateTime<Utc>,
    policy: Policy,
    exposure: &crate::breach::ExposureMap,
) -> VaultReport {
    let per_record_handles = handles_per_record(records);
    let clusters = cluster_map(records, &per_record_handles);
    let titles = title_map(records);
    let anchors = second_factor_anchors(records);

    let mut reports: Vec<RecordReport> = Vec::new();

    for (record, handles) in records.iter().zip(&per_record_handles) {
        let mut issues: Vec<Issue> = Vec::new();

        for (field, handle) in handles {
            let Some(members) = clusters.get(&(field.clone(), handle.clone())) else {
                continue;
            };
            let shared_with: Vec<Uuid> =
                members.iter().copied().filter(|id| *id != record.id).collect();
            if shared_with.is_empty() {
                continue;
            }
            issues.push(Issue::Reused {
                field: field.clone(),
                shared_with,
                handle: handle.clone(),
            });
        }

        for field in &record.fields {
            let opened = field.secret.open();
            let bytes = opened.as_slice();
            match field_role(&field.name) {
                FieldRole::Passphrase => {
                    if bytes.is_empty() {
                        issues.push(Issue::Short {
                            field: field.name.clone(),
                            bytes: 0,
                            floor: policy.min_passphrase_bytes,
                        });
                    } else if all_ascii_digits(bytes) {
                        if bytes.len() < policy.min_all_digit_digits {
                            issues.push(Issue::WeakPin {
                                field: field.name.clone(),
                                digits: bytes.len(),
                                floor: policy.min_all_digit_digits,
                            });
                        }
                    } else if bytes.len() < policy.min_passphrase_bytes {
                        issues.push(Issue::Short {
                            field: field.name.clone(),
                            bytes: bytes.len(),
                            floor: policy.min_passphrase_bytes,
                        });
                    }
                }
                FieldRole::Pin => {
                    if !numeric_pin_is_issued(record.kind)
                        && all_ascii_digits(bytes)
                        && bytes.len() < policy.min_pin_digits
                    {
                        issues.push(Issue::WeakPin {
                            field: field.name.clone(),
                            digits: bytes.len(),
                            floor: policy.min_pin_digits,
                        });
                    }
                }
                FieldRole::Opaque => {}
            }
        }

        if rotatable(record.kind) && !record.fields.is_empty() {
            let age_days = (now - record.updated_at).num_days();
            if age_days >= policy.stale_after_days {
                issues.push(Issue::Stale {
                    last_modified: record.updated_at,
                    age_days,
                    threshold_days: policy.stale_after_days,
                });
            }
        }

        if second_factor_expected(record.kind)
            && !record.fields.is_empty()
            && !carries_second_factor(record)
            && !identity_keys(record).iter().any(|key| anchors.contains(key))
        {
            issues.push(Issue::NoTotp);
        }

        if let Some(title) = normalised_title(record) {
            if let Some(members) = titles.get(&(record.kind.as_str(), title)) {
                let others: Vec<Uuid> =
                    members.iter().copied().filter(|id| *id != record.id).collect();
                if !others.is_empty() {
                    issues.push(Issue::DuplicateTitle { others });
                }
            }
        }

        for field in &record.fields {
            if let Some(breaches) = exposure.get(&(record.id, field.name.clone())) {
                issues.push(Issue::Exposed {
                    field: field.name.clone(),
                    breaches: *breaches,
                });
            }
        }

        if issues.is_empty() {
            continue;
        }
        issues.sort_by_key(Issue::severity);
        reports.push(RecordReport {
            id: record.id,
            title: record.title.clone(),
            kind: record.kind,
            issues,
        });
    }

    let reuse_clusters: Vec<ReuseCluster> = clusters
        .iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|((field, handle), members)| ReuseCluster {
            field: field.clone(),
            handle: handle.clone(),
            members: members.clone(),
        })
        .collect();

    let score = score(&reports, records.len());

    VaultReport {
        scanned: records.len(),
        records: reports,
        reuse_clusters,
        score,
    }
}

/// A one-line summary for the CLI.
///
/// Counts only: no titles, no handles, no lengths. Safe to print to a terminal
/// that may be logged.
pub fn summary_line(report: &VaultReport) -> String {
    if report.scanned == 0 {
        return "no records to scan".to_string();
    }
    if report.is_clean() {
        return format!(
            "{} record(s) scanned; no hygiene issues found",
            report.scanned
        );
    }
    format!(
        "{} record(s) scanned; {} with issues ({} high, {} medium, {} low); \
         {} reuse cluster(s); {} demerits",
        report.scanned,
        report.score.records_with_issues,
        report.score.high,
        report.score.medium,
        report.score.low,
        report.reuse_clusters.len(),
        report.score.demerits,
    )
}

fn score(reports: &[RecordReport], scanned: usize) -> HygieneScore {
    let mut score = HygieneScore {
        records_with_issues: reports.len(),
        clean_records: scanned.saturating_sub(reports.len()),
        ..HygieneScore::default()
    };

    for report in reports {
        for issue in &report.issues {
            match issue.severity() {
                Severity::High => score.high += 1,
                Severity::Medium => score.medium += 1,
                Severity::Low => score.low += 1,
            }
        }
        score.contributions.push(ScoreContribution {
            id: report.id,
            demerits: report.demerits(),
        });
    }

    score.demerits = WEIGHT_HIGH * score.high as u64
        + WEIGHT_MEDIUM * score.medium as u64
        + WEIGHT_LOW * score.low as u64;
    score
        .contributions
        .sort_by(|a, b| b.demerits.cmp(&a.demerits).then_with(|| a.id.cmp(&b.id)));
    score
}

/// `(field name, handle)` for every non-empty secret field, in record order.
///
/// `notes` is excluded on purpose: two records carrying the same boilerplate note
/// is not credential reuse. Empty secrets are excluded because every empty secret
/// shares one handle, which would manufacture a cluster out of nothing.
fn handles_per_record(records: &[Record]) -> Vec<Vec<(String, String)>> {
    records
        .iter()
        .map(|record| {
            let mut out: Vec<(String, String)> = Vec::new();
            for field in &record.fields {
                if field.secret.is_empty() {
                    continue;
                }
                let handle = field.secret.handle(&field.name);
                if out.iter().any(|(n, h)| n == &field.name && h == &handle) {
                    continue;
                }
                out.push((field.name.clone(), handle));
            }
            out
        })
        .collect()
}

/// `BTreeMap` rather than `HashMap` so cluster order is the same on every run.
fn cluster_map(
    records: &[Record],
    handles: &[Vec<(String, String)>],
) -> BTreeMap<(String, String), Vec<Uuid>> {
    let mut map: BTreeMap<(String, String), Vec<Uuid>> = BTreeMap::new();
    for (record, per_field) in records.iter().zip(handles) {
        for key in per_field {
            let members = map.entry(key.clone()).or_default();
            if !members.contains(&record.id) {
                members.push(record.id);
            }
        }
    }
    map
}

fn title_map(records: &[Record]) -> BTreeMap<(&'static str, String), Vec<Uuid>> {
    let mut map: BTreeMap<(&'static str, String), Vec<Uuid>> = BTreeMap::new();
    for record in records {
        if let Some(title) = normalised_title(record) {
            let members = map.entry((record.kind.as_str(), title)).or_default();
            if !members.contains(&record.id) {
                members.push(record.id);
            }
        }
    }
    map
}

/// Names under which some record in this vault holds a second factor.
fn second_factor_anchors(records: &[Record]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for record in records {
        if carries_second_factor(record) {
            out.extend(identity_keys(record));
        }
    }
    out
}

/// The strings by which a record might be paired with a separate TOTP record.
///
/// Deliberately excludes `username` and `account`: pairing on those would call a
/// login covered because some unrelated record shares the name `admin`.
fn identity_keys(record: &Record) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(title) = normalised_title(record) {
        out.push(title);
    }
    for name in ["issuer", "service", "site"] {
        if let Some(value) = record.attribute(name) {
            let value = value.trim();
            if !value.is_empty() {
                out.push(value.to_ascii_lowercase());
            }
        }
    }
    if let Some(issuer) = record.totp.as_ref().and_then(|c| c.issuer.as_deref()) {
        let issuer = issuer.trim();
        if !issuer.is_empty() {
            out.push(issuer.to_ascii_lowercase());
        }
    }
    out
}

fn carries_second_factor(record: &Record) -> bool {
    record.kind == Kind::Totp
        || record.totp.is_some()
        || record
            .fields
            .iter()
            .any(|f| f.name.trim().eq_ignore_ascii_case("totp"))
}

fn normalised_title(record: &Record) -> Option<String> {
    let title = record.title.as_deref()?.trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_ascii_lowercase())
    }
}

fn all_ascii_digits(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_digit)
}

enum FieldRole {
    /// Chosen by the owner, defended by its length.
    Passphrase,
    /// A short numeric code.
    Pin,
    /// Everything else: keys, seeds, tokens, account numbers, note bodies. Their
    /// length is fixed by whoever issued them, so a length rule here would be
    /// advice the owner cannot act on.
    Opaque,
}

/// The role follows the field NAME, not the record kind: an SSH key's
/// `passphrase` is chosen by the owner exactly as a login password is, while the
/// `private_key` beside it is not.
fn field_role(name: &str) -> FieldRole {
    match name.trim().to_ascii_lowercase().as_str() {
        "password" | "passphrase" | "pass" | "pw" => FieldRole::Passphrase,
        "pin" | "pin_code" | "passcode" => FieldRole::Pin,
        _ => FieldRole::Opaque,
    }
}

/// Kinds whose numeric PIN is issued rather than chosen. A bank card PIN is four
/// digits because the bank made it four; telling the owner to lengthen it is
/// advice they cannot take.
///
/// Matched exhaustively so a fourteenth [`Kind`] cannot inherit an answer here
/// by default.
fn numeric_pin_is_issued(kind: Kind) -> bool {
    match kind {
        Kind::Bank | Kind::Id => true,
        Kind::Login
        | Kind::Totp
        | Kind::Api
        | Kind::Ssh
        | Kind::Pgp
        | Kind::Wallet
        | Kind::Wifi
        | Kind::Contact
        | Kind::Note
        | Kind::Recovery
        | Kind::Passkey => false,
    }
}

/// Kinds whose secret can be rotated on request. A wallet seed is excluded
/// because rotating one means moving funds, and a bank account number and an ID
/// number because they are facts about the world, not credentials with an age.
fn rotatable(kind: Kind) -> bool {
    match kind {
        Kind::Login | Kind::Api | Kind::Ssh | Kind::Pgp | Kind::Wifi => true,
        Kind::Totp
        | Kind::Wallet
        | Kind::Bank
        | Kind::Id
        | Kind::Contact
        | Kind::Note
        | Kind::Recovery
        | Kind::Passkey => false,
    }
}

/// Kinds where a stored second factor is a thing the owner could reasonably
/// have. An API key or an SSH key is presented alone by construction.
fn second_factor_expected(kind: Kind) -> bool {
    match kind {
        Kind::Login | Kind::Bank => true,
        Kind::Totp
        | Kind::Api
        | Kind::Ssh
        | Kind::Pgp
        | Kind::Wallet
        | Kind::Wifi
        | Kind::Id
        | Kind::Contact
        | Kind::Note
        | Kind::Recovery
        | Kind::Passkey => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Secret, TotpConfig};
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Fields are set before `updated_at`, because `set_field` moves it.
    fn record(kind: Kind, title: Option<&str>, fields: &[(&str, &str)]) -> Record {
        let mut record = Record::new(kind, title.map(str::to_string));
        for (name, value) in fields {
            record.set_field(name, Secret::from_str(value));
        }
        record.updated_at = now();
        record
    }

    fn strong(kind: Kind, title: &str, field: &str) -> Record {
        record(kind, Some(title), &[(field, "correct-horse-battery-staple")])
    }

    fn issues_of(report: &VaultReport, id: Uuid) -> &[Issue] {
        report
            .records
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.issues.as_slice())
            .unwrap_or(&[])
    }

    fn has(report: &VaultReport, id: Uuid, code: &str) -> bool {
        issues_of(report, id).iter().any(|i| i.code() == code)
    }

    #[test]
    fn reuse_is_detected_across_records() {
        let a = record(Kind::Login, Some("GitHub"), &[("password", "shared-value-long")]);
        let b = record(Kind::Login, Some("GitLab"), &[("password", "shared-value-long")]);
        let c = record(Kind::Login, Some("Forgejo"), &[("password", "different-value-long")]);
        let (ida, idb, idc) = (a.id, b.id, c.id);

        let report = analyse(&[a, b, c], now());

        assert_eq!(report.reuse_clusters.len(), 1);
        let cluster = &report.reuse_clusters[0];
        assert_eq!(cluster.field, "password");
        assert_eq!(cluster.handle.len(), 8);
        assert_eq!(cluster.members, vec![ida, idb]);

        assert!(has(&report, ida, "REUSED"));
        assert!(has(&report, idb, "REUSED"));
        assert!(!has(&report, idc, "REUSED"));

        match issues_of(&report, ida).iter().find(|i| i.code() == "REUSED") {
            Some(Issue::Reused { shared_with, .. }) => assert_eq!(shared_with, &vec![idb]),
            other => panic!("expected a Reused issue, got {other:?}"),
        }
    }

    #[test]
    fn reuse_does_not_cross_field_names() {
        let a = record(Kind::Login, Some("Router"), &[("password", "shared-value-long")]);
        let b = record(Kind::Wifi, Some("Home"), &[("passphrase", "shared-value-long")]);
        let (ida, idb) = (a.id, b.id);

        let report = analyse(&[a, b], now());

        assert!(
            report.reuse_clusters.is_empty(),
            "handles are domain-separated by field name: {:?}",
            report.reuse_clusters
        );
        assert!(!has(&report, ida, "REUSED"));
        assert!(!has(&report, idb, "REUSED"));
    }

    #[test]
    fn empty_secrets_do_not_form_reuse_clusters() {
        let a = record(Kind::Note, Some("one"), &[("body", "")]);
        let b = record(Kind::Note, Some("two"), &[("body", "")]);
        let report = analyse(&[a, b], now());
        assert!(report.reuse_clusters.is_empty());
    }

    #[test]
    fn notes_are_not_part_of_reuse() {
        let mut a = record(Kind::Login, Some("One"), &[("password", "first-unique-value")]);
        let mut b = record(Kind::Login, Some("Two"), &[("password", "second-unique-value")]);
        a.notes = Some(Secret::from_str("same boilerplate note"));
        b.notes = Some(Secret::from_str("same boilerplate note"));
        a.totp = Some(TotpConfig::default());
        b.totp = Some(TotpConfig::default());
        a.updated_at = now();
        b.updated_at = now();

        let report = analyse(&[a, b], now());
        assert!(report.reuse_clusters.is_empty());
        assert!(report.is_clean());
    }

    #[test]
    fn a_tidy_vault_reports_nothing() {
        let mut login = strong(Kind::Login, "GitHub", "password");
        login.totp = Some(TotpConfig::default());
        login.updated_at = now();
        let note = record(Kind::Note, Some("Runbook"), &[("body", "short")]);
        let ssh = strong(Kind::Ssh, "bastion", "private_key");

        let report = analyse(&[login, note, ssh], now());

        assert!(report.is_clean(), "unexpected issues: {:?}", report.records);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.score.clean_records, 3);
        assert_eq!(report.score.total_issues(), 0);
        assert_eq!(report.score.demerits, 0);
        assert!(report.score.contributions.is_empty());
        assert_eq!(
            summary_line(&report),
            "3 record(s) scanned; no hygiene issues found"
        );
    }

    #[test]
    fn an_empty_vault_is_reported_as_empty() {
        let report = analyse(&[], now());
        assert_eq!(report.scanned, 0);
        assert!(report.is_clean());
        assert!(report.reuse_clusters.is_empty());
        assert_eq!(report.score, HygieneScore::default());
        assert_eq!(summary_line(&report), "no records to scan");
    }

    #[test]
    fn a_single_record_is_scanned() {
        let solo = record(Kind::Login, Some("Solo"), &[("password", "short")]);
        let id = solo.id;
        let report = analyse(&[solo], now());

        assert_eq!(report.scanned, 1);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.score.clean_records, 0);
        assert!(
            report.reuse_clusters.is_empty(),
            "one record cannot reuse anything"
        );
        assert!(has(&report, id, "SHORT"));
        assert!(has(&report, id, "NO_TOTP"));
        assert!(!has(&report, id, "DUPLICATE_TITLE"));
    }

    #[test]
    fn staleness_triggers_exactly_at_the_threshold() {
        let mut at_threshold = strong(Kind::Login, "At", "password");
        at_threshold.updated_at = now() - Duration::days(STALE_AFTER_DAYS);
        at_threshold.totp = Some(TotpConfig::default());

        let mut one_second_short = strong(Kind::Login, "Under", "password");
        one_second_short.updated_at =
            now() - Duration::days(STALE_AFTER_DAYS) + Duration::seconds(1);
        one_second_short.totp = Some(TotpConfig::default());

        let (stale_id, fresh_id) = (at_threshold.id, one_second_short.id);
        let report = analyse(&[at_threshold, one_second_short], now());

        assert!(has(&report, stale_id, "STALE"), "the boundary is inclusive");
        assert!(!has(&report, fresh_id, "STALE"));

        match issues_of(&report, stale_id).iter().find(|i| i.code() == "STALE") {
            Some(Issue::Stale {
                age_days,
                threshold_days,
                ..
            }) => {
                assert_eq!(*age_days, STALE_AFTER_DAYS);
                assert_eq!(*threshold_days, STALE_AFTER_DAYS);
            }
            other => panic!("expected a Stale issue, got {other:?}"),
        }
    }

    #[test]
    fn staleness_is_only_raised_for_rotatable_kinds() {
        let mut wallet = strong(Kind::Wallet, "Cold store", "seed");
        wallet.updated_at = now() - Duration::days(4000);
        let mut api = strong(Kind::Api, "prod", "secret_key");
        api.updated_at = now() - Duration::days(4000);
        let (wallet_id, api_id) = (wallet.id, api.id);

        let report = analyse(&[wallet, api], now());
        assert!(!has(&report, wallet_id, "STALE"));
        assert!(has(&report, api_id, "STALE"));
    }

    #[test]
    fn the_report_never_serialises_secret_bytes() {
        let mut a = record(
            Kind::Login,
            Some("VERY-DISTINCTIVE-TITLE"),
            &[("password", "DISTINCTIVE-SECRET"), ("pin", "1234")],
        );
        a.notes = Some(Secret::from_str("DISTINCTIVE-NOTE"));
        let b = record(
            Kind::Login,
            Some("OTHER-TITLE"),
            &[("password", "DISTINCTIVE-SECRET")],
        );

        let report = analyse(&[a, b], now());
        let json = serde_json::to_string(&report).unwrap();

        for forbidden in ["DISTINCTIVE-SECRET", "DISTINCTIVE-NOTE", "1234"] {
            assert!(
                !json.contains(forbidden),
                "hygiene report leaked {forbidden}:\n{json}"
            );
        }
        assert!(json.contains("VERY-DISTINCTIVE-TITLE"), "titles are intended");
        assert!(!summary_line(&report).contains("VERY-DISTINCTIVE-TITLE"));
        assert!(!report.reuse_clusters.is_empty());
    }

    #[test]
    fn score_contributions_sum_to_the_total() {
        let a = record(Kind::Login, Some("Dup"), &[("password", "shared-short")]);
        let b = record(Kind::Login, Some("Dup"), &[("password", "shared-short")]);
        let mut c = strong(Kind::Api, "prod", "secret_key");
        c.updated_at = now() - Duration::days(1000);

        let report = analyse(&[a, b, c], now());

        let summed: u64 = report.score.contributions.iter().map(|c| c.demerits).sum();
        assert_eq!(summed, report.score.demerits);

        let by_formula = WEIGHT_HIGH * report.score.high as u64
            + WEIGHT_MEDIUM * report.score.medium as u64
            + WEIGHT_LOW * report.score.low as u64;
        assert_eq!(by_formula, report.score.demerits);

        let by_record: u64 = report.records.iter().map(RecordReport::demerits).sum();
        assert_eq!(by_record, report.score.demerits);

        assert_eq!(report.score.records_with_issues, report.records.len());
        assert_eq!(
            report.score.clean_records,
            report.scanned - report.records.len()
        );
        assert_eq!(report.score.contributions.len(), report.records.len());

        let ordered: Vec<u64> = report.score.contributions.iter().map(|c| c.demerits).collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(ordered, sorted, "contributions are costliest first");
    }

    #[test]
    fn an_issued_bank_pin_is_left_alone_but_a_chosen_one_is_not() {
        let bank = record(Kind::Bank, Some("Current account"), &[("pin", "1234")]);
        let login = record(Kind::Login, Some("Door"), &[("pin", "1234")]);
        let (bank_id, login_id) = (bank.id, login.id);

        let report = analyse(&[bank, login], now());
        assert!(
            !has(&report, bank_id, "WEAK_PIN"),
            "a four-digit bank PIN is issued, not chosen"
        );
        assert!(has(&report, login_id, "WEAK_PIN"));
    }

    #[test]
    fn an_all_digit_password_is_flagged_past_the_byte_floor() {
        let long_digits = record(
            Kind::Login,
            Some("Numeric"),
            &[("password", "1234567890123456")],
        );
        let id = long_digits.id;
        let report = analyse(&[long_digits], now());

        assert!(
            !has(&report, id, "SHORT"),
            "sixteen bytes clears the byte floor"
        );
        match issues_of(&report, id).iter().find(|i| i.code() == "WEAK_PIN") {
            Some(Issue::WeakPin { digits, floor, .. }) => {
                assert_eq!(*digits, 16);
                assert_eq!(*floor, MIN_ALL_DIGIT_DIGITS);
            }
            other => panic!("expected a WeakPin issue, got {other:?}"),
        }
    }

    #[test]
    fn opaque_fields_get_no_length_rule() {
        let key = record(Kind::Ssh, Some("bastion"), &[("private_key", "tiny")]);
        let id_number = record(Kind::Id, Some("Passport"), &[("number", "12345")]);
        let (key_id, id_id) = (key.id, id_number.id);

        let report = analyse(&[key, id_number], now());
        assert!(!has(&report, key_id, "SHORT"));
        assert!(!has(&report, key_id, "WEAK_PIN"));
        assert!(!has(&report, id_id, "SHORT"));
        assert!(!has(&report, id_id, "WEAK_PIN"));
    }

    #[test]
    fn duplicate_titles_are_only_flagged_within_one_kind() {
        let login = strong(Kind::Login, "GitHub", "password");
        let mut totp = record(Kind::Totp, Some("GitHub"), &[("totp", "0123456789")]);
        totp.updated_at = now();
        let other_login = strong(Kind::Login, "  github  ", "password");
        let (login_id, totp_id, other_id) = (login.id, totp.id, other_login.id);

        let report = analyse(&[login, totp, other_login], now());

        assert!(has(&report, login_id, "DUPLICATE_TITLE"));
        assert!(has(&report, other_id, "DUPLICATE_TITLE"));
        assert!(
            !has(&report, totp_id, "DUPLICATE_TITLE"),
            "a login and its totp record sharing a title is the intended pairing"
        );
        match issues_of(&report, login_id)
            .iter()
            .find(|i| i.code() == "DUPLICATE_TITLE")
        {
            Some(Issue::DuplicateTitle { others }) => assert_eq!(others, &vec![other_id]),
            other => panic!("expected a DuplicateTitle issue, got {other:?}"),
        }
    }

    #[test]
    fn a_separate_totp_record_covers_a_login() {
        let paired = strong(Kind::Login, "GitHub", "password");
        let lonely = strong(Kind::Login, "GitLab", "password");
        let mut totp = record(Kind::Totp, Some("GitHub"), &[("totp", "0123456789")]);
        totp.updated_at = now();
        let (paired_id, lonely_id) = (paired.id, lonely.id);

        let report = analyse(&[paired, lonely, totp], now());
        assert!(!has(&report, paired_id, "NO_TOTP"));
        assert!(has(&report, lonely_id, "NO_TOTP"));
    }

    #[test]
    fn a_totp_issuer_attribute_also_pairs() {
        let mut login = strong(Kind::Login, "Work mail", "password");
        login.set_attribute("issuer", "Fastmail");
        login.updated_at = now();
        let mut totp = record(Kind::Totp, Some("mail second factor"), &[("totp", "01234567")]);
        totp.set_attribute("issuer", "fastmail");
        totp.updated_at = now();
        let login_id = login.id;

        let report = analyse(&[login, totp], now());
        assert!(!has(&report, login_id, "NO_TOTP"));
    }

    #[test]
    fn a_record_with_no_fields_is_not_told_to_add_a_factor() {
        let stub = record(Kind::Login, Some("Placeholder"), &[]);
        let id = stub.id;
        let report = analyse(&[stub], now());
        assert!(!has(&report, id, "NO_TOTP"));
        assert!(!has(&report, id, "STALE"));
    }

    #[test]
    fn analyse_with_honours_a_stated_policy() {
        let mut record = strong(Kind::Login, "GitHub", "password");
        record.totp = Some(TotpConfig::default());
        record.updated_at = now() - Duration::days(30);
        let id = record.id;
        let records = [record];

        let lenient = analyse(&records, now());
        assert!(!has(&lenient, id, "STALE"));

        let strict = analyse_with(
            &records,
            now(),
            Policy {
                stale_after_days: 30,
                ..Policy::default()
            },
        );
        assert!(has(&strict, id, "STALE"));

        let very_strict = analyse_with(
            &records,
            now(),
            Policy {
                min_passphrase_bytes: 64,
                ..Policy::default()
            },
        );
        assert!(has(&very_strict, id, "SHORT"));
    }

    #[test]
    fn issues_are_ordered_worst_first_and_carry_stable_codes() {
        let a = record(Kind::Login, Some("Dup"), &[("password", "shared-short")]);
        let b = record(Kind::Login, Some("Dup"), &[("password", "shared-short")]);
        let id = a.id;

        let report = analyse(&[a, b], now());
        let issues = issues_of(&report, id);
        assert!(issues.len() > 1);

        let severities: Vec<Severity> = issues.iter().map(Issue::severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_unstable();
        assert_eq!(severities, sorted);

        for issue in issues {
            assert!(!issue.code().is_empty());
            assert!(!issue.describe().is_empty());
            assert!(
                !issue.describe().contains("shared-short"),
                "describe leaked a secret"
            );
        }

        let report_row = report.records.iter().find(|r| r.id == id).unwrap();
        assert_eq!(report_row.worst(), Some(Severity::High));
        let expected: u64 = report_row
            .issues
            .iter()
            .map(|i| i.severity().weight())
            .sum();
        assert_eq!(report_row.demerits(), expected);
        assert!(report_row.demerits() >= WEIGHT_HIGH);
    }

    #[test]
    fn severity_weights_and_labels_are_the_documented_ones() {
        assert_eq!(Severity::High.weight(), WEIGHT_HIGH);
        assert_eq!(Severity::Medium.weight(), WEIGHT_MEDIUM);
        assert_eq!(Severity::Low.weight(), WEIGHT_LOW);
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::Low.to_string(), "low");
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
    }

    #[test]
    fn the_default_policy_is_the_documented_one() {
        let policy = Policy::default();
        assert_eq!(policy.min_passphrase_bytes, MIN_PASSPHRASE_BYTES);
        assert_eq!(policy.min_all_digit_digits, MIN_ALL_DIGIT_DIGITS);
        assert_eq!(policy.min_pin_digits, MIN_PIN_DIGITS);
        assert_eq!(policy.stale_after_days, STALE_AFTER_DAYS);
    }

    #[test]
    fn a_record_dated_after_now_is_never_stale() {
        let mut ahead = strong(Kind::Login, "Skewed clock", "password");
        ahead.totp = Some(TotpConfig::default());
        ahead.updated_at = now() + Duration::days(10);
        let id = ahead.id;

        let report = analyse(&[ahead], now());
        assert!(!has(&report, id, "STALE"));
    }

    #[test]
    fn summary_line_is_counts_only() {
        let a = record(
            Kind::Login,
            Some("SECRET-LOOKING-TITLE"),
            &[("password", "shared-short")],
        );
        let b = record(
            Kind::Login,
            Some("ANOTHER-TITLE"),
            &[("password", "shared-short")],
        );
        let report = analyse(&[a, b], now());
        let line = summary_line(&report);

        assert!(!line.contains('\n'));
        assert!(!line.contains("SECRET-LOOKING-TITLE"));
        assert!(!line.contains("shared-short"));
        for cluster in &report.reuse_clusters {
            assert!(!line.contains(&cluster.handle), "handles are not for printing");
        }
        assert!(line.starts_with("2 record(s) scanned;"));
        assert!(line.contains("1 reuse cluster(s)"));
    }
}
