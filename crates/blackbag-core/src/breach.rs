//! Breach exposure via the Pwned Passwords k-anonymity range protocol.
//!
//! # The one exception to "nothing leaves the machine"
//!
//! Every other analysis in this crate is local. This one is not, and it is
//! built so the exception is as small as it can be made:
//!
//! * The **agent** computes the SHA-1 of each password-like field and hands
//!   the caller only the first five hex characters — 20 bits. That prefix
//!   names a bucket of roughly a thousand real leaked hashes, and it is what
//!   the protocol is designed to reveal. Nothing else about the password is
//!   derivable from it.
//! * The **caller** (the CLI, through `curl`, so the agent needs no network
//!   capability at all) fetches the bucket for each prefix and hands the
//!   whole bucket back.
//! * The **agent** does the matching, in its own memory, against the full
//!   hash it never disclosed. The count of breaches each exposed field appears
//!   in is remembered for the rest of the session so the hygiene report can
//!   carry it, and forgotten on lock.
//!
//! The service sees: your IP address, the moment you asked, and up to one
//! five-character prefix per distinct password. It does not see which password
//! you hold, whether it matched, or how many you have — the prefixes are
//! deduplicated before they are sent, and the caller asks for padded
//! responses so bucket sizes carry no information either.
//!
//! What this cannot tell you: a password absent from the corpus is not a
//! password nobody has leaked, only one Pwned Passwords has not seen.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::record::Record;

/// Field names whose values are passwords in the sense the corpus means.
pub const CHECKED_FIELDS: &[&str] = &["password", "passphrase", "pin"];

/// The endpoint the caller queries, one request per prefix.
pub const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// The part of the SHA-1 that leaves the agent.
pub const PREFIX_LEN: usize = 5;

/// A field the agent is willing to check, identified without its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: Uuid,
    pub title: Option<String>,
    pub field: String,
    /// Uppercase hex, `PREFIX_LEN` characters.
    pub prefix: String,
}

/// One bucket as returned by the service: every 35-character suffix in it
/// with its breach count. Padding entries carry a count of zero and are
/// dropped by the caller before they get here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub prefix: String,
    pub suffixes: Vec<(String, u64)>,
}

/// A field that appears in the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    pub id: Uuid,
    pub title: Option<String>,
    pub field: String,
    /// Times the value appears in the corpus.
    pub breaches: u64,
}

/// The outcome of a matching pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Report {
    /// Fields whose prefix had a bucket to compare against.
    pub checked: usize,
    /// Fields skipped because no bucket was supplied for their prefix.
    pub unchecked: usize,
    pub exposed: Vec<Exposure>,
}

/// The map the agent keeps for the life of a session.
pub type ExposureMap = HashMap<(Uuid, String), u64>;

/// Uppercase hex SHA-1 of `bytes`.
pub fn sha1_hex(bytes: &[u8]) -> String {
    let digest = Sha1::digest(bytes);
    let mut out = String::with_capacity(40);
    for b in digest {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Every password-like field across `records`, with its prefix.
pub fn candidates(records: &[Record]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for record in records {
        for field in &record.fields {
            if !CHECKED_FIELDS.contains(&field.name.as_str()) {
                continue;
            }
            let hash = sha1_hex(field.secret.open().as_slice());
            out.push(Candidate {
                id: record.id,
                title: record.title.clone(),
                field: field.name.clone(),
                prefix: hash[..PREFIX_LEN].to_string(),
            });
        }
    }
    out
}

/// The distinct prefixes a caller has to fetch — deduplicated, sorted, so
/// the request pattern says nothing about how many records share a value.
pub fn distinct_prefixes(candidates: &[Candidate]) -> Vec<String> {
    candidates
        .iter()
        .map(|c| c.prefix.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Parse one bucket body — lines of `SUFFIX:COUNT` — dropping padding.
pub fn parse_range(prefix: &str, body: &str) -> Range {
    let mut suffixes = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some((suffix, count)) = line.split_once(':') else {
            continue;
        };
        let suffix = suffix.trim().to_ascii_uppercase();
        if suffix.len() != 40 - PREFIX_LEN || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(count) = count.trim().parse::<u64>() else {
            continue;
        };
        if count == 0 {
            continue;
        }
        suffixes.push((suffix, count));
    }
    Range {
        prefix: prefix.to_ascii_uppercase(),
        suffixes,
    }
}

/// Match every candidate field against the supplied buckets. Runs inside the
/// agent: the full hash is computed here and compared here.
pub fn match_ranges(records: &[Record], ranges: &[Range]) -> (Report, ExposureMap) {
    let buckets: BTreeMap<&str, &Range> = ranges.iter().map(|r| (r.prefix.as_str(), r)).collect();
    let mut report = Report::default();
    let mut map = ExposureMap::new();

    for record in records {
        for field in &record.fields {
            if !CHECKED_FIELDS.contains(&field.name.as_str()) {
                continue;
            }
            let hash = sha1_hex(field.secret.open().as_slice());
            let (prefix, suffix) = hash.split_at(PREFIX_LEN);
            let Some(bucket) = buckets.get(prefix) else {
                report.unchecked += 1;
                continue;
            };
            report.checked += 1;
            // Not constant-time, and it need not be: the comparison is
            // between a hash the agent holds and a public list, in the
            // agent's own process, with no observer.
            if let Some((_, count)) = bucket.suffixes.iter().find(|(s, _)| s == suffix) {
                report.exposed.push(Exposure {
                    id: record.id,
                    title: record.title.clone(),
                    field: field.name.clone(),
                    breaches: *count,
                });
                map.insert((record.id, field.name.clone()), *count);
            }
        }
    }
    (report, map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Kind, Secret};

    // RFC-standard test vector: SHA-1("password").
    const PASSWORD_SHA1: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_matches_the_known_vector() {
        assert_eq!(sha1_hex(b"password"), PASSWORD_SHA1);
    }

    fn vault() -> Vec<Record> {
        let mut a = Record::new(Kind::Login, Some("weak".into()));
        a.set_field("password", Secret::from_str("password"));
        let mut b = Record::new(Kind::Login, Some("strong".into()));
        b.set_field("password", Secret::from_str("correct horse battery staple 9!"));
        let mut c = Record::new(Kind::Api, Some("api".into()));
        c.set_field("secret_key", Secret::from_str("password"));
        vec![a, b, c]
    }

    #[test]
    fn only_password_like_fields_are_candidates() {
        let cands = candidates(&vault());
        assert_eq!(cands.len(), 2, "the api secret_key is not a password");
        assert!(cands.iter().all(|c| c.prefix.len() == PREFIX_LEN));
        assert_eq!(cands[0].prefix, &PASSWORD_SHA1[..5]);
    }

    #[test]
    fn prefixes_are_deduplicated_and_sorted() {
        let mut records = vault();
        let mut d = Record::new(Kind::Login, Some("weak twin".into()));
        d.set_field("password", Secret::from_str("password"));
        records.push(d);
        let cands = candidates(&records);
        let prefixes = distinct_prefixes(&cands);
        assert_eq!(cands.len(), 3);
        assert_eq!(prefixes.len(), 2, "two records sharing a value send one prefix");
        let mut sorted = prefixes.clone();
        sorted.sort();
        assert_eq!(prefixes, sorted);
    }

    #[test]
    fn a_bucket_parses_and_drops_padding() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                    0000000000000000000000000000000000A:0\r\n\
                    garbage line\r\n\
                    1e4c9b93f3f0682250b6cf8331b7ee68fd9:12\r\n";
        let range = parse_range("5baa6", body);
        assert_eq!(range.prefix, "5BAA6");
        assert_eq!(range.suffixes.len(), 2, "padding and garbage are dropped");
        assert_eq!(range.suffixes[0].1, 3_861_493);
        assert_eq!(range.suffixes[1].0, "1E4C9B93F3F0682250B6CF8331B7EE68FD9");
    }

    #[test]
    fn matching_finds_the_exposed_field_and_nothing_else() {
        let records = vault();
        let range = parse_range(
            &PASSWORD_SHA1[..5],
            &format!("{}:3861493\n", &PASSWORD_SHA1[5..]),
        );
        let (report, map) = match_ranges(&records, &[range]);
        assert_eq!(report.checked, 1, "only the bucket we supplied is checked");
        assert_eq!(report.unchecked, 1, "the strong password's prefix had no bucket");
        assert_eq!(report.exposed.len(), 1);
        assert_eq!(report.exposed[0].title.as_deref(), Some("weak"));
        assert_eq!(report.exposed[0].breaches, 3_861_493);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&(records[0].id, "password".to_string())], 3_861_493);
    }

    #[test]
    fn a_report_never_carries_a_hash_or_a_value() {
        let mut records = vault();
        let mut canary = Record::new(Kind::Login, Some("canary".into()));
        canary.set_field("password", Secret::from_str("LEAK-CANARY-VALUE"));
        records.push(canary);
        let canary_hash = sha1_hex(b"LEAK-CANARY-VALUE");
        let range = parse_range(
            &canary_hash[..5],
            &format!("{}:7\n", &canary_hash[5..]),
        );
        let (report, _) = match_ranges(&records, &[range]);
        assert_eq!(report.exposed.len(), 1);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("LEAK-CANARY-VALUE"), "value leaked: {json}");
        assert!(!json.contains(&canary_hash[5..]), "hash leaked: {json}");
        assert!(!json.contains(&canary_hash[..5]), "even the prefix is not in a report: {json}");
        let cands = serde_json::to_string(&candidates(&records)).unwrap();
        assert!(!cands.contains("LEAK-CANARY-VALUE"), "candidates carry a value: {cands}");
        assert!(!cands.contains(&canary_hash[5..]), "candidates carry the full hash: {cands}");
    }
}
