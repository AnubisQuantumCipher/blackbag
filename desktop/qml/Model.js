// Pure logic for the BLACK-BAG surfaces. No QML bindings, no engine access —
// colours arrive as stringified arguments so this stays a shared library.
//
// One rule governs this file: nothing here ever retains, formats, caches or
// logs a secret. Two functions (buildDraft, draftProblems) are handed the
// editor's secret values so they can be packed into a draft or counted as
// present; they pass them through and keep nothing. The cockpit asks the agent
// for a stored secret only at the moment of an explicit COPY or SHOW, and that
// value goes straight to the clipboard or to a self-clearing property.

.pragma library

// ── glyphs ───────────────────────────────────────────────────────────────────

// Restricted to glyphs the shell's monospace font actually carries — ⚿, ☏ and
// ⎈ were tried first and rendered as tofu boxes on this theme's font.
var KIND_GLYPH = {
  login:    "◉",
  totp:     "⟲",
  api:      "⊢",
  ssh:      "⋈",
  pgp:      "✉",
  wallet:   "◈",
  bank:     "⚖",
  wifi:     "≋",
  id:       "▣",
  contact:  "✦",
  note:     "▭",
  recovery: "✚",
  passkey:  "⚿"
}

var KIND_ORDER = ["login", "totp", "api", "ssh", "pgp", "wallet",
                  "bank", "wifi", "id", "contact", "note", "recovery", "passkey"]

function kindGlyph(kind) {
  return KIND_GLYPH[String(kind)] || "·"
}

function severityMark(severity) {
  if (severity === "alert") return "!!"
  if (severity === "warn")  return "!"
  if (severity === "note")  return "·"
  if (severity === "ok")    return "✓"
  return "?"
}

// ── record templates ─────────────────────────────────────────────────────────
//
// What each kind asks for. `attrs` are open metadata stored inside the
// encrypted payload; `secrets` are page-locked fields. The split is a judgement
// call per kind and this is the one place to change it — a document number and
// a contact's notes are treated as secret because in practice they are.
var KIND_TEMPLATE = {
  login:    { label: "Login",        attrs: ["username", "url"],
              secrets: ["password"] },
  totp:     { label: "2FA code",     attrs: ["issuer", "account"],
              secrets: [], totp: true },
  api:      { label: "API key",      attrs: ["service", "environment", "access_key", "scopes"],
              secrets: ["secret_key"] },
  ssh:      { label: "SSH key",      attrs: ["label", "comment"],
              secrets: ["private_key"], multiline: ["private_key"] },
  pgp:      { label: "PGP key",      attrs: ["label", "fingerprint"],
              secrets: ["private_key"], multiline: ["private_key"] },
  wallet:   { label: "Wallet",       attrs: ["asset", "address", "network"],
              secrets: ["seed"], multiline: ["seed"] },
  bank:     { label: "Bank",         attrs: ["institution", "account_name", "routing_number"],
              secrets: ["account_number"] },
  wifi:     { label: "Wi-Fi",        attrs: ["ssid", "security", "location"],
              secrets: ["passphrase"] },
  id:       { label: "ID document",  attrs: ["id_type", "name_on_doc", "issuing_country", "expiry"],
              secrets: ["number"] },
  contact:  { label: "Contact",      attrs: ["full_name", "emails", "phones", "address", "company"],
              secrets: ["notes"], multiline: ["notes"] },
  note:     { label: "Secure note",  attrs: [],
              secrets: ["body"], multiline: ["body"] },
  recovery: { label: "Recovery kit", attrs: ["description"],
              secrets: ["payload"], multiline: ["payload"] },
  // A passkey is never authored by hand: the browser mints it and the agent
  // stores it. `secrets` is empty not because it holds none, but because its
  // key material is not revealable — the engine refuses to hand it back, so
  // offering a COPY button for it would be offering something that cannot
  // happen.
  passkey:  { label: "Passkey",      attrs: ["relying_party", "username"],
              secrets: [], sealed: true }
}

/// Kinds whose secret fields are never revealed, copied or shown.
///
/// A passkey's private key has exactly one use and it happens inside the
/// agent. `Request::Reveal` refuses it; this is the deck agreeing rather than
/// drawing buttons that produce an error.
function kindIsSealed(kind) {
  var t = KIND_TEMPLATE[String(kind)]
  return !!(t && t.sealed)
}

function templateFor(kind) {
  return KIND_TEMPLATE[String(kind)] || { label: String(kind), attrs: [], secrets: [] }
}

function kindLabel(kind) {
  return templateFor(kind).label
}

function isMultiline(kind, field) {
  var t = templateFor(kind)
  var m = t.multiline || []
  for (var i = 0; i < m.length; i++) if (m[i] === field) return true
  return false
}

// Human wording for a field name, so the form does not read like a schema.
function fieldLabel(name) {
  var map = {
    username: "username", url: "URL", access_key: "access key",
    secret_key: "secret key", private_key: "private key",
    account_number: "account number", routing_number: "routing number",
    account_name: "account name", full_name: "full name",
    id_type: "document type", name_on_doc: "name on document",
    issuing_country: "issuing country", emails: "emails (comma separated)",
    phones: "phones (comma separated)", scopes: "scopes (comma separated)"
  }
  return map[String(name)] || String(name).replace(/_/g, " ")
}

/// The kinds a person can create by hand.
///
/// Not every kind: a passkey is minted by a browser ceremony and its private
/// key never passes through a human's hands, so offering "new passkey" in the
/// editor would offer a form nobody can fill in. The census still counts them,
/// because a zero there is a measured zero.
function kindChoices() {
  var out = []
  for (var i = 0; i < KIND_ORDER.length; i++) {
    var k = KIND_ORDER[i]
    if (kindIsSealed(k)) continue
    out.push({ kind: k, glyph: kindGlyph(k), label: kindLabel(k) })
  }
  return out
}

// Build the JSON draft the engine expects. Secret values pass through
// untouched and are never inspected, cached or reformatted here.
function buildDraft(kind, title, tagsText, attrValues, secretValues, totpInput) {
  var t = templateFor(kind)
  var attributes = []
  for (var i = 0; i < t.attrs.length; i++) {
    var name = t.attrs[i]
    var v = String(attrValues[name] === undefined ? "" : attrValues[name]).trim()
    if (v.length > 0) attributes.push([name, v])
  }

  var secrets = []
  for (var j = 0; j < t.secrets.length; j++) {
    var sname = t.secrets[j]
    var sv = secretValues[sname]
    secrets.push([sname, sv === undefined ? "" : String(sv)])
  }

  var tags = []
  var parts = String(tagsText || "").split(",")
  for (var k = 0; k < parts.length; k++) {
    var tag = parts[k].trim()
    if (tag.length > 0) tags.push(tag)
  }

  var draft = {
    kind: String(kind),
    title: String(title || "").trim(),
    tags: tags,
    attributes: attributes,
    secrets: secrets
  }

  if (t.totp) {
    var uri = String(totpInput && totpInput.uri ? totpInput.uri : "").trim()
    var b32 = String(totpInput && totpInput.secret ? totpInput.secret : "").trim()
    draft.totp = {}
    if (uri.length > 0) draft.totp.otpauth_uri = uri
    else if (b32.length > 0) draft.totp.secret_base32 = b32
    var issuer = String(attrValues["issuer"] || "").trim()
    var account = String(attrValues["account"] || "").trim()
    if (issuer.length > 0) draft.totp.issuer = issuer
    if (account.length > 0) draft.totp.account = account
  }

  return draft
}

// What is missing before this draft can be saved. Empty means ready.
function draftProblems(kind, title, secretValues, totpInput, isEdit) {
  var t = templateFor(kind)
  var out = []
  if (String(title || "").trim().length === 0) out.push("a title")

  if (t.totp) {
    var uri = String(totpInput && totpInput.uri ? totpInput.uri : "").trim()
    var b32 = String(totpInput && totpInput.secret ? totpInput.secret : "").trim()
    if (!isEdit && uri.length === 0 && b32.length === 0)
      out.push("an otpauth:// URI or a base32 secret")
    if (uri.length > 0 && uri.indexOf("otpauth://") !== 0)
      out.push("a URI starting with otpauth://")
  }

  // A new record must supply every secret its kind defines; on an edit a blank
  // means "keep what is stored".
  if (!isEdit) {
    for (var i = 0; i < t.secrets.length; i++) {
      var name = t.secrets[i]
      var v = secretValues[name]
      if (v === undefined || String(v).length === 0) out.push(fieldLabel(name))
    }
  }
  return out
}

// ── formatting ───────────────────────────────────────────────────────────────

// Absent renders as an em dash, never as a blank that could read as a pass.
function orDash(value) {
  if (value === undefined || value === null) return "—"
  var s = String(value)
  return s.length === 0 ? "—" : s
}

// Wall-clock time of day for an ISO timestamp, for "session ends at 03:12".
function fmtClock(iso) {
  if (!iso) return "—"
  var t = Date.parse(iso)
  if (!isFinite(t)) return "—"
  var d = new Date(t)
  function two(n) { return (n < 10 ? "0" : "") + n }
  return two(d.getHours()) + ":" + two(d.getMinutes())
}

function fmtAgo(iso, nowMs) {
  if (!iso) return "—"
  var t = Date.parse(iso)
  if (!isFinite(t)) return "—"
  var s = Math.max(0, Math.round((nowMs - t) / 1000))
  if (s < 60)    return s + "s ago"
  if (s < 3600)  return Math.floor(s / 60) + "m ago"
  if (s < 86400) return Math.floor(s / 3600) + "h ago"
  return Math.floor(s / 86400) + "d ago"
}

function fmtCountdown(secs) {
  if (secs === undefined || secs === null || !isFinite(secs) || secs < 0) return "—"
  var s = Math.round(secs)
  if (s < 60) return s + "s"
  var m = Math.floor(s / 60)
  if (m < 60) return m + "m " + (s % 60 < 10 ? "0" : "") + (s % 60) + "s"
  return Math.floor(m / 60) + "h " + (m % 60) + "m"
}

// Thousands-grouped integer. Qt's JS `toLocaleString` renders large numbers
// in scientific notation, which turned "52,372,427 breaches" into 5.2e+07.
function fmtInt(n) {
  var v = Math.round(Number(n) || 0)
  var neg = v < 0
  var s = String(Math.abs(v))
  var out = ""
  while (s.length > 3) { out = "," + s.slice(-3) + out; s = s.slice(0, -3) }
  return (neg ? "-" : "") + s + out
}

function fmtBytes(n) {
  var v = Number(n) || 0
  if (v < 1024) return v + " B"
  if (v < 1024 * 1024) return (v / 1024).toFixed(1) + " KiB"
  return (v / (1024 * 1024)).toFixed(1) + " MiB"
}

// Argon2 memory is quoted in KiB in the file; humans read MiB.
function fmtKdf(kdf) {
  if (!kdf) return "—"
  var mib = Math.round(Number(kdf.mem_cost_kib || 0) / 1024)
  return String(kdf.algorithm || "argon2id") + " · " + mib + " MiB · t="
       + String(kdf.time_cost) + " · p=" + String(kdf.lanes)
}

// ── state derivation ─────────────────────────────────────────────────────────

// Staleness outranks every other state: an old file cannot vouch for anything,
// so it is reported as UNKNOWN rather than as its last-known value.
function deckState(status, nowMs, staleAfterSec) {
  if (!status) return "NO SIGNAL"
  var age = statusAgeSecs(status, nowMs)
  if (age === null || age > staleAfterSec) return "UNKNOWN"
  if (status.error) return "UNREADABLE"
  if (!status.vault_present) return "NO VAULT"
  if (status.rollback_suspected) return "ROLLBACK"
  if (status.session && status.session.unlocked) return "UNLOCKED"
  return "LOCKED"
}

function statusAgeSecs(status, nowMs) {
  if (!status || !status.published_at) return null
  var t = Date.parse(status.published_at)
  if (!isFinite(t)) return null
  return Math.max(0, (nowMs - t) / 1000)
}

function isStale(status, nowMs, staleAfterSec) {
  var age = statusAgeSecs(status, nowMs)
  return age === null || age > staleAfterSec
}

// Seconds left on the unlock session, or null when locked / unknown.
function sessionRemaining(status, nowMs) {
  if (!status || !status.session || !status.session.unlocked) return null
  var iso = status.session.expires_at
  if (!iso) return null
  var t = Date.parse(iso)
  if (!isFinite(t)) return null
  return Math.max(0, (t - nowMs) / 1000)
}

// Why the agent last locked, in words a person would use.
function lockReasonLabel(reason) {
  var map = {
    "manual": "locked by hand",
    "idle": "locked after idling",
    "session-ceiling": "locked at the session ceiling",
    "suspend": "locked before suspend",
    "session-lock": "locked with the screen",
    "rekeyed": "locked: re-keyed elsewhere",
    "shutdown": "locked: agent stopped"
  }
  var r = String(reason || "")
  return map[r] || (r.length > 0 ? "locked (" + r + ")" : "")
}

// The rows the SESSION card draws under the buttons. Every value is a fact the
// status document carries; absence renders as a dash, never as a blank.
function sessionRows(status, nowMs) {
  var s = status && status.session ? status.session : null
  var rows = []
  rows.push({ k: "idle timeout", v: s ? fmtCountdown(s.idle_timeout_secs) : "—" })
  if (s && s.unlocked) {
    rows.push({ k: "unlocked by", v: orDash(s.method) })
    if (s.session_ends_at)
      rows.push({ k: "ends regardless", v: fmtClock(s.session_ends_at)
                  + " · " + fmtCountdown(Math.max(0, (Date.parse(s.session_ends_at) - nowMs) / 1000)) })
    else if (s.max_session_secs === 0)
      rows.push({ k: "session ceiling", v: "off" })
  } else if (s && s.last_lock_reason) {
    rows.push({ k: "last lock", v: lockReasonLabel(s.last_lock_reason) })
  }
  var watch = s ? String(s.sleep_watch || "") : ""
  rows.push({
    k: "suspend & screen lock",
    v: watch.indexOf("watching") === 0 ? "locks the vault"
     : (watch.length > 0 ? "not watched" : "—"),
    ok: watch.indexOf("watching") === 0 ? true : (watch.length > 0 ? false : null),
    detail: watch.indexOf("watching") === 0 ? "" : watch
  })
  return rows
}

// Worst finding severity present, for the bar widget's single-glyph verdict.
function worstSeverity(status) {
  var findings = asList(status ? status.findings : null)
  if (findings.length === 0) return "unknown"
  var rank = { alert: 0, warn: 1, note: 2, ok: 3 }
  var worst = "ok"
  for (var i = 0; i < findings.length; i++) {
    var s = String(findings[i].severity)
    if (rank[s] !== undefined && rank[s] < rank[worst]) worst = s
  }
  return worst
}

function countFindings(status, severity) {
  var findings = asList(status ? status.findings : null)
  var n = 0
  for (var i = 0; i < findings.length; i++)
    if (String(findings[i].severity) === severity) n++
  return n
}

// ── the unlock verdict ───────────────────────────────────────────────────────
//
// Everything the sealed screen renders comes from here, and it is deliberately
// NOT built on deckState().
//
// deckState() checks staleness first and returns UNKNOWN, which is right for a
// status chip and catastrophically wrong for a hazard: it would mask a rollback
// or an attached debugger behind a grey "unknown". Here staleness is a
// MODIFIER — it weakens an all-clear and never suppresses an alarm.
//
// Second rule: only conditions that should stop your fingers appear here.
// Swap being active, a tight memlock budget and a below-default KDF are real
// findings, but they are permanent facts of this machine — putting them here
// would mean the sealed screen is never quiet, and a screen that always shouts
// teaches you to stop reading it. They belong to the unlocked deck.

var HAZARD_NONE  = "none"
var HAZARD_ALERT = "alert"
var HAZARD_STALE = "stale"

function unlockVerdict(status, nowMs, staleAfterSec) {
  var v = {
    severity: HAZARD_NONE,
    headline: "",
    detail: "",
    blockInput: false,     // true only when typing itself is the danger
    hasVault: true,
    verb: "unlock",
    identity: "————  ————",
    witness: "",
    witnessTone: "quiet",  // quiet | good | bad
    stale: false,
    staleFor: ""
  }

  if (!status) {
    v.severity = HAZARD_ALERT
    v.headline = "NO STATUS PUBLISHED"
    v.detail = "the engine has not reported yet — run: black-bag status --publish"
    v.hasVault = false
    return v
  }

  v.stale = isStale(status, nowMs, staleAfterSec)
  if (v.stale) {
    var age = statusAgeSecs(status, nowMs)
    v.staleFor = age === null ? "never published" : fmtCountdown(age) + " old"
  }

  if (status.error) {
    v.severity = HAZARD_ALERT
    v.headline = "VAULT UNREADABLE"
    v.detail = String(status.error)
    v.hasVault = false
    return v
  }

  if (status.vault_present !== true) {
    v.severity = HAZARD_NONE
    v.headline = "NO VAULT AT THIS PATH"
    v.detail = "nothing here yet — the deck can create one"
    v.hasVault = false      // and therefore: no passphrase field at all
    return v
  }

  v.identity = fingerprint(status.vault_id)

  // Absence must never counterfeit a pass. An engine that published no host
  // section is not a healthy host, it is an unmeasured one.
  if (!status.host) {
    v.severity = HAZARD_ALERT
    v.headline = "HOST POSTURE UNKNOWN"
    v.detail = "this engine published no host section — nothing was measured"
    return v
  }

  // A live tracer reads the passphrase keystroke by keystroke, so the harm is
  // done before Enter is pressed. There is no honest "proceed anyway" here,
  // and offering one would launder a refusal into a speed bump.
  if (status.host.traced === true) {
    v.severity = HAZARD_ALERT
    v.headline = "A DEBUGGER IS ATTACHED TO THIS SESSION"
    v.detail = "it can read anything you type — detach it and this clears itself"
    v.blockInput = true
    return v
  }

  if (status.host.mlock_working === false) {
    v.severity = HAZARD_ALERT
    v.headline = "MEMORY LOCKING IS NOT WORKING"
    v.detail = orDash(status.host.mlock_error)
      + " — secrets may be paged to disk while unlocked"
    return v
  }

  // Rollback is loud but never blocking: restoring a legitimate backup must
  // not lock the owner out of his own vault.
  if (status.rollback_suspected === true) {
    v.severity = HAZARD_ALERT
    v.headline = "THIS FILE IS OLDER THAN THE LAST ONE SEEN HERE"
    v.detail = "witness recorded epoch " + orDash(status.witness_epoch)
             + "; this file says " + orDash(status.epoch)
    v.verb = "unlock anyway"
    v.witness = "ROLLED BACK"
    v.witnessTone = "bad"
    return v
  }

  // The epoch the file asserts is worth nothing on its own — a planted vault
  // picks its own. The witness is the half a forger cannot choose, so the
  // screen states the comparison rather than asking anyone to eye-match digits.
  if (status.witness_epoch === null || status.witness_epoch === undefined) {
    v.witness = "unwitnessed"
    v.witnessTone = "quiet"
  } else {
    v.witness = "epoch " + orDash(status.epoch) + " witnessed"
    v.witnessTone = "good"
  }

  if (v.stale) v.severity = HAZARD_STALE
  return v
}

// Short, stable, recognisable handle for a vault. Grouped 4+4 so the eye reads
// it as a shape rather than a string. Absence renders as em dashes in the SAME
// slot geometry, so a hole is visibly a hole and cannot be mistaken for a value.
function fingerprint(vaultId) {
  var hex = String(vaultId || "").replace(/[^0-9a-fA-F]/g, "")
  if (hex.length < 8) return "————  ————"
  return hex.substring(0, 4) + "  " + hex.substring(4, 8)
}

// ── bar widget text ──────────────────────────────────────────────────────────

function barText(status, nowMs, staleAfterSec) {
  var state = deckState(status, nowMs, staleAfterSec)
  if (state === "UNLOCKED") {
    var left = sessionRemaining(status, nowMs)
    return left === null ? "OPEN" : "OPEN " + fmtCountdown(left)
  }
  if (state === "LOCKED") return "LOCKED"
  return state
}

function barTooltip(status, nowMs, staleAfterSec) {
  if (!status) return "BLACK-BAG — no status published yet"
  var lines = []
  lines.push("BLACK-BAG — " + deckState(status, nowMs, staleAfterSec))
  lines.push("vault: " + orDash(status.vault_path))
  if (status.vault_present) {
    lines.push("format v" + orDash(status.vault_format) + " · epoch " + orDash(status.epoch))
    lines.push("kdf: " + fmtKdf(status.kdf))
    lines.push("recipients: " + recipientSummary(status))
  }
  var alerts = countFindings(status, "alert")
  var warns  = countFindings(status, "warn")
  if (alerts || warns) lines.push(alerts + " alert · " + warns + " warn")
  lines.push("published " + fmtAgo(status.published_at, nowMs))
  return lines.join("\n")
}

function recipientSummary(status) {
  if (!status || asList(status.recipients).length === 0)
    return "none"
  var recips = asList(status.recipients)
  var external = 0
  for (var i = 0; i < recips.length; i++)
    if (recips[i].key_held_externally) external++
  return recips.length + " (" + external + " with keys held offline)"
}

// ── census ───────────────────────────────────────────────────────────────────

// Always returns all twelve kinds, so a zero reads as a measured zero rather
// than as a row that happened not to be rendered.
function census(countsByKind) {
  var map = {}
  var pairs = asList(countsByKind)
  for (var i = 0; i < pairs.length; i++)
    map[String(pairs[i][0])] = Number(pairs[i][1]) || 0

  var out = []
  for (var k = 0; k < KIND_ORDER.length; k++) {
    var kind = KIND_ORDER[k]
    out.push({ kind: kind, glyph: kindGlyph(kind), count: map[kind] || 0 })
  }
  return out
}

function totalRecords(countsByKind) {
  var n = 0
  var pairs = asList(countsByKind)
  for (var i = 0; i < pairs.length; i++) n += Number(pairs[i][1]) || 0
  return n
}

// ── record list ──────────────────────────────────────────────────────────────

function recordLabel(record) {
  if (!record) return "—"
  if (record.title && String(record.title).length > 0) return String(record.title)
  var attrs = attrMap(record)
  return attrs.username || attrs.service || attrs.ssid || attrs.full_name
      || attrs.label || attrs.account || ("(untitled " + String(record.kind) + ")")
}

// Duck-typed on `length` rather than Array.isArray: values marshalled from a
// QML `var` property into this library are not always recognised as native
// Arrays, and an isArray check silently yields an empty map instead of failing.
function attrMap(record) {
  var out = {}
  var attrs = record ? record.attributes : null
  if (!attrs || typeof attrs.length !== "number") return out
  for (var i = 0; i < attrs.length; i++) {
    var pair = attrs[i]
    if (!pair || typeof pair.length !== "number" || pair.length < 2) continue
    out[String(pair[0])] = String(pair[1])
  }
  return out
}

// Same reason as attrMap: never gate on Array.isArray for QML-supplied values.
function asList(value) {
  if (!value || typeof value.length !== "number") return []
  var out = []
  for (var i = 0; i < value.length; i++) out.push(value[i])
  return out
}

function recordSubtitle(record) {
  if (!record) return ""
  var attrs = attrMap(record)
  var bits = []
  if (attrs.username) bits.push(attrs.username)
  if (attrs.service)  bits.push(attrs.service)
  if (attrs.url)      bits.push(attrs.url)
  if (attrs.ssid)     bits.push(attrs.ssid)
  if (attrs.account && bits.indexOf(attrs.account) < 0) bits.push(attrs.account)

  // Kinds whose useful attribute is not in the list above (ssh label, wallet
  // asset, bank institution) would otherwise show a blank second line, so fall
  // back to whatever the record actually carries rather than rendering nothing.
  if (bits.length === 0) {
    var attrList = asList(record.attributes)
    for (var i = 0; i < attrList.length && bits.length < 2; i++) {
      var pair = attrList[i]
      if (!pair || typeof pair.length !== "number" || pair.length < 2) continue
      var val = String(pair[1])
      if (val.length > 0) bits.push(val)
    }
  }
  if (bits.length === 0) {
    var tags = asList(record.tags)
    if (tags.length > 0) bits.push(tags.join(" "))
  }
  return bits.join(" · ")
}

// Local filter over the metadata the agent already sent. Deliberately never
// looks at secret_fields values, because there are none to look at.
function filterRecords(records, kind, query) {
  records = asList(records)
  var needle = String(query || "").toLowerCase().trim()
  var out = []
  for (var i = 0; i < records.length; i++) {
    var r = records[i]
    if (kind && String(r.kind) !== String(kind)) continue
    if (needle.length > 0) {
      var hay = [
        String(r.title || ""),
        String(r.kind || ""),
        asList(r.tags).join(" "),
        recordSubtitle(r)
      ].join(" ").toLowerCase()
      if (hay.indexOf(needle) < 0) continue
    }
    out.push(r)
  }
  return out
}

function sortRecords(records) {
  var copy = asList(records)
  copy.sort(function (a, b) {
    var ka = KIND_ORDER.indexOf(String(a.kind))
    var kb = KIND_ORDER.indexOf(String(b.kind))
    if (ka !== kb) return ka - kb
    return recordLabel(a).toLowerCase().localeCompare(recordLabel(b).toLowerCase())
  })
  return copy
}

// The secret field Enter acts on. Preference order is what a person most
// often wants copied for that kind; the first listed field otherwise.
var PRIMARY_FIELD_ORDER = ["password", "secret_key", "private_key", "passphrase",
                           "account_number", "seed", "body", "totp", "number", "payload"]

function primaryField(record) {
  var fields = record ? asList(record.secret_fields) : []
  if (fields.length === 0) return ""
  for (var p = 0; p < PRIMARY_FIELD_ORDER.length; p++)
    for (var i = 0; i < fields.length; i++)
      if (fields[i] && String(fields[i].name) === PRIMARY_FIELD_ORDER[p]) return PRIMARY_FIELD_ORDER[p]
  return String(fields[0].name)
}

// The largest deck scale at which the three rails still fit the window. The
// rails want about 900 logical pixels at scale 1; past that the centre column
// goes negative and the table vanishes.
function maxScaleFor(widthPx) {
  var w = Number(widthPx)
  if (!isFinite(w) || w <= 0) return 3.0
  return Math.max(0.7, Math.min(3.0, Math.floor((w / 900) * 20) / 20))
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

// Fraction of the current step already elapsed, for the countdown arc.
function totpProgress(ttlSecs, stepSecs) {
  var step = Number(stepSecs) || 30
  var ttl = Number(ttlSecs)
  if (!isFinite(ttl) || step <= 0) return 0
  return Math.max(0, Math.min(1, 1 - (ttl / step)))
}

function totpUrgent(ttlSecs) {
  return (Number(ttlSecs) || 0) <= 5
}

// ── recipients ───────────────────────────────────────────────────────────────

function recipientRows(status) {
  var recips = asList(status ? status.recipients : null)
  var out = []
  for (var i = 0; i < recips.length; i++) {
    var r = recips[i]
    out.push({
      label: String(r.label),
      kind: String(r.kind),
      external: r.key_held_externally === true,
      // The distinction the 0.4.x design got wrong: a KEM only protects
      // anything when its private half is not sitting in the same file.
      note: r.key_held_externally
        ? "private key held outside the vault"
        : "derived from your passphrase"
    })
  }
  return out
}

// The labels of recipients whose private key is held outside the vault. A
// vault with none of these cannot be opened without its passphrase, and the
// deck must not offer a way back in that does not exist.
function recoverableLabels(status) {
  var out = []
  var recips = asList(status ? status.recipients : null)
  for (var i = 0; i < recips.length; i++)
    if (recips[i] && recips[i].key_held_externally === true)
      out.push(String(recips[i].label))
  return out
}

function canRecover(status) {
  return recoverableLabels(status).length > 0
}

// Recipients that may be revoked. The passphrase recipient may not: a vault
// only a key file can open is a lockout waiting to happen, and the engine
// refuses it anyway.
function revocableRecipients(status) {
  return recipientRows(status).filter(function (r) { return r.external })
}

// A short, sortable stamp for a default recovery-key label, so two keys minted
// on the same machine do not collide by name.
function shortStamp() {
  var d = new Date()
  function two(n) { return (n < 10 ? "0" : "") + n }
  return String(d.getFullYear()) + two(d.getMonth() + 1) + two(d.getDate())
}

// What `crypto::DEFAULT_MEM_KIB` is in the engine. Restated rather than read
// because status.json reports what the VAULT uses, not what a fresh one would
// choose; if the engine's default changes this must change with it.
var DEFAULT_MEM_KIB = 262144

function kdfMeetsDefault(status) {
  var kdf = status ? status.kdf : null
  if (!kdf) return true          // nothing to complain about yet
  return kdf.meets_current_defaults === true
}

var IMPORT_FORMATS = [
  { key: "bitwarden", label: "Bitwarden" },
  { key: "keepassxc", label: "KeePassXC" },
  { key: "firefox",   label: "Firefox" },
  { key: "chrome",    label: "Chrome" },
  { key: "csv",       label: "Any CSV" },
  { key: "black-bag", label: "Black-Bag" }
]

var EXPORT_FORMATS = [
  { key: "json",      label: "Black-Bag JSON" },
  { key: "keepassxc", label: "KeePassXC CSV" }
]

var GEN_KINDS = [
  { key: "password",   label: "Password" },
  { key: "passphrase", label: "Passphrase" },
  { key: "pin",        label: "PIN" }
]

// The settings a person may change from the deck, with the same bounds
// clampSettings enforces — so the stepper cannot even offer an out-of-range
// value, rather than offering it and having it silently corrected.
var SETTING_ROWS = [
  { key: "revealSeconds", label: "reveal timeout",
    hint: "how long SHOW, the editor's eye and a generated value stay readable",
    fallback: 10, from: 3, to: 120, step: 1 },
  { key: "clipboardClearSec", label: "clipboard clears after",
    hint: "seconds before a copied secret is taken back off the clipboard",
    fallback: 30, from: 5, to: 600, step: 5 },
  { key: "staleAfterSec", label: "treat status as stale after",
    hint: "older than this and the deck desaturates rather than asserting a state",
    fallback: 120, from: 10, to: 3600, step: 10 },
  { key: "pollIntervalSec", label: "status poll interval",
    hint: "the file is watched anyway; this is the safety net",
    fallback: 15, from: 2, to: 120, step: 1 }
]

// ── hygiene ──────────────────────────────────────────────────────────────────
//
// The engine serialises `Issue` externally tagged, which is two shapes:
//   struct variants -> { "reused": { field, shared_with, handle } }
//   unit variants   -> "no_totp"
// Severity is a method on the Rust side and is NOT in the JSON, so it is
// mirrored here. Keep this table in step with `Issue::severity` in hygiene.rs.
var HYGIENE_SEVERITY = {
  reused: "alert",
  weak_pin: "alert",
  exposed: "alert",
  short: "warn",
  stale: "warn",
  duplicate_title: "note",
  no_totp: "note"
}

function hygieneKind(issue) {
  if (typeof issue === "string") return issue
  if (!issue || typeof issue !== "object") return ""
  for (var k in issue) return k
  return ""
}

function hygieneBody(issue) {
  if (typeof issue === "string") return {}
  var k = hygieneKind(issue)
  return (k && issue[k] && typeof issue[k] === "object") ? issue[k] : {}
}

function hygieneSeverity(issue) {
  var s = HYGIENE_SEVERITY[hygieneKind(issue)]
  // An issue kind this build does not recognise must still be shown, and must
  // not be quietly demoted to the mildest bucket.
  return s === undefined ? "warn" : s
}

function hygieneLine(issue) {
  var kind = hygieneKind(issue)
  var b = hygieneBody(issue)
  if (kind === "reused")
    return "same " + String(b.field) + " as "
         + asList(b.shared_with).length + " other record(s)"
  if (kind === "short")
    return String(b.field) + " is " + b.bytes + " bytes · floor " + b.floor
  if (kind === "stale")
    return "unchanged for " + b.age_days + " days"
  if (kind === "no_totp")
    return "no second factor stored here"
  if (kind === "weak_pin")
    return String(b.field) + " is " + b.digits + " digits · floor " + b.floor
  if (kind === "duplicate_title")
    return "shares a title with " + asList(b.others).length + " other record(s)"
  if (kind === "exposed")
    return String(b.field) + " seen in " + fmtInt(b.breaches) + " known breaches"
  if (kind.length === 0) return "unrecognised finding"
  return kind.replace(/_/g, " ")
}

// Records worst-first, issues worst-first within each; stable otherwise, so
// the engine's own order still shows through among equals.
function sortHygiene(report) {
  var rank = { alert: 0, warn: 1, note: 2 }
  function worst(issues) {
    var w = 3
    for (var i = 0; i < issues.length; i++) {
      var r = rank[hygieneSeverity(issues[i])]
      if (r !== undefined && r < w) w = r
    }
    return w
  }
  var records = asList(report ? report.records : null)
  var indexed = []
  for (var i = 0; i < records.length; i++) {
    var issues = asList(records[i].issues)
    var sortedIssues = []
    for (var j = 0; j < issues.length; j++) sortedIssues.push([j, issues[j]])
    sortedIssues.sort(function (a, b) {
      var ra = rank[hygieneSeverity(a[1])], rb = rank[hygieneSeverity(b[1])]
      if (ra === undefined) ra = 1
      if (rb === undefined) rb = 1
      return ra !== rb ? ra - rb : a[0] - b[0]
    })
    var copy = {}
    for (var k in records[i]) copy[k] = records[i][k]
    copy.issues = sortedIssues.map(function (x) { return x[1] })
    indexed.push([i, worst(copy.issues), copy])
  }
  indexed.sort(function (a, b) { return a[1] !== b[1] ? a[1] - b[1] : a[0] - b[0] })
  return indexed.map(function (x) { return x[2] })
}

// How many fields the breach check found in the corpus, from a hygiene report.
function exposedCount(report) {
  var records = asList(report ? report.records : null)
  var n = 0
  for (var i = 0; i < records.length; i++) {
    var issues = asList(records[i].issues)
    for (var j = 0; j < issues.length; j++) if (hygieneKind(issues[j]) === "exposed") n++
  }
  return n
}

function hygieneCount(report) {
  if (!report || !report.score) return 0
  var s = report.score
  return (s.high || 0) + (s.medium || 0) + (s.low || 0)
}

// ── posture ──────────────────────────────────────────────────────────────────

// Tri-state: true = measured good, false = measured bad, null = not measured.
// `null` must never render like `true` — an unmeasured host is not a healthy one.
// Each row also carries its own severity so a note (swap active) cannot borrow
// the same red as a failure (mlock broken); red that fires for everything
// teaches the eye to skip it.
function postureRows(status) {
  var h = (status && status.host) ? status.host : null
  if (!h) {
    var unknown = []
    var labels = ["mlock", "core dumps", "swap", "memlock", "tracer"]
    for (var i = 0; i < labels.length; i++)
      unknown.push({ label: labels[i], ok: null, value: "UNKNOWN",
                     severity: "alert", detail: "not measured" })
    return unknown
  }

  var swaps = asList(h.swap_devices)
  var swapOn = swaps.length > 0
  var memlockOk = h.memlock_unlimited === true
                  || Number(h.memlock_limit_bytes) >= 67108864

  return [
    { label: "mlock",
      ok: h.mlock_working === undefined ? null : h.mlock_working === true,
      value: h.mlock_working === true ? "working"
           : h.mlock_working === false ? "FAILED" : "UNKNOWN",
      severity: "alert",
      detail: h.mlock_working === false ? orDash(h.mlock_error) : "" },

    { label: "core dumps",
      ok: h.core_dumps_disabled === undefined ? null : h.core_dumps_disabled === true,
      value: h.core_dumps_disabled === true ? "disabled"
           : h.core_dumps_disabled === false ? "ENABLED" : "UNKNOWN",
      severity: "warn",
      detail: h.core_dumps_disabled === true ? "" : orDash(h.core_pattern) },

    { label: "swap",
      ok: h.swap_devices === undefined ? null : !swapOn,
      value: swapOn ? swaps.join(", ") : "none",
      severity: "note",
      detail: swapOn ? "mlock is load-bearing" : "" },

    { label: "memlock",
      ok: h.memlock_limit_bytes === undefined ? null : memlockOk,
      value: h.memlock_unlimited === true ? "unlimited" : fmtBytes(h.memlock_limit_bytes),
      severity: "note",
      detail: memlockOk ? "" : "large secrets may fail to lock" },

    { label: "tracer",
      ok: h.traced === undefined ? null : h.traced !== true,
      value: h.traced === true ? "ATTACHED" : (h.traced === false ? "none" : "UNKNOWN"),
      severity: "alert",
      detail: h.traced === true ? "a debugger can read this process" : "" },

    // Every resting secret is ciphertext under a per-process key; this row
    // says where that key lives, which is the thing that actually matters.
    { label: "session key",
      ok: h.session_key_backing === undefined ? null
        : h.session_key_backing !== "unlocked",
      value: h.session_key_backing === "memfd_secret" ? "kernel-invisible"
           : h.session_key_backing === "locked-slab" ? "locked page"
           : h.session_key_backing === "unlocked" ? "UNLOCKED"
           : "UNKNOWN",
      severity: "warn",
      detail: h.session_key_backing === "memfd_secret"
        ? "memfd_secret · secrets rest encrypted"
        : h.session_key_backing === "locked-slab" ? "secrets rest encrypted"
        : h.session_key_backing === "unlocked" ? "the key may be swapped" : "" }
  ]
}

// Worst first, stable within a rank so the file's own order still shows through.
function sortFindings(status) {
  var findings = asList(status ? status.findings : null)
  var rank = { alert: 0, warn: 1, note: 2, ok: 3 }
  var indexed = []
  for (var i = 0; i < findings.length; i++) indexed.push([i, findings[i]])
  indexed.sort(function (a, b) {
    var ra = rank[String(a[1].severity)]
    var rb = rank[String(b[1].severity)]
    if (ra === undefined) ra = 2
    if (rb === undefined) rb = 2
    return ra !== rb ? ra - rb : a[0] - b[0]
  })
  var out = []
  for (var j = 0; j < indexed.length; j++) out.push(indexed[j][1])
  return out
}

// ── plugin settings ─────────────────────────────────────────────────────────
//
// The shell injects `settings` into bar widgets only. Overlays and services get
// `shell` and `manifest` but NOT `settings`, and `shell.serviceFor()` does not
// hand an overlay its own service either — verified on this box, where the
// overlay saw `service === null`. So a manifest can declare a whole settings
// schema that nothing ever reads.
//
// What IS reachable from every surface is `shell.shellConfig`, so the merge
// happens here as a pure function: manifest defaults first, then whatever the
// user's shell.json carries for this plugin's bar entry.
// Bounds a settings file cannot push past. A reveal timeout of 0 would leave
// a secret on screen forever, a clear delay of 0 would never clear, and a
// stale threshold of 0 would call every status stale. These mirror the
// manifest schema's min/max and apply to both hosts.
var SETTING_BOUNDS = {
  pollIntervalSec:   [2, 120],
  staleAfterSec:     [10, 3600],
  clipboardClearSec: [5, 600],
  revealSeconds:     [3, 120],
  uiScale:           [0, 3.0]     // 0 is "from the viewport"; else 0.7..3.0
}

function clampSettings(settings) {
  var out = {}
  for (var k in settings) out[k] = settings[k]
  for (var key in SETTING_BOUNDS) {
    if (out[key] === undefined || out[key] === null) continue
    var n = Number(out[key])
    var lo = SETTING_BOUNDS[key][0], hi = SETTING_BOUNDS[key][1]
    if (!isFinite(n)) { delete out[key]; continue }
    if (key === "uiScale") out[key] = n <= 0 ? 0 : Math.max(0.7, Math.min(hi, n))
    else out[key] = Math.max(lo, Math.min(hi, Math.round(n)))
  }
  if (out.motionEnabled !== undefined && typeof out.motionEnabled !== "boolean")
    out.motionEnabled = String(out.motionEnabled) === "true"
  return out
}

function resolvePluginSettings(shellConfig, manifest, pluginId) {
  var merged = {}

  if (manifest && manifest.barWidget && manifest.barWidget.defaults) {
    var d = manifest.barWidget.defaults
    for (var k in d) merged[k] = d[k]
  }

  var layout = (shellConfig && shellConfig.bar && shellConfig.bar.layout)
    ? shellConfig.bar.layout : null
  if (layout) {
    var sections = ["left", "center", "right"]
    for (var n = 0; n < sections.length; n++) {
      var list = asList(layout[sections[n]])
      for (var i = 0; i < list.length; i++) {
        var e = list[i]
        if (!e || e.id !== pluginId) continue
        for (var key in e) if (key !== "id") merged[key] = e[key]
      }
    }
  }

  // Top-level plugin entries carry settings too, for non-bar plugins.
  var plugins = asList(shellConfig ? shellConfig.plugins : null)
  for (var p = 0; p < plugins.length; p++) {
    var pe = plugins[p]
    if (!pe || pe.id !== pluginId) continue
    for (var pk in pe) if (pk !== "id") merged[pk] = pe[pk]
  }

  return clampSettings(merged)
}

// The application's equivalent of resolvePluginSettings, for a surface with no
// shell to ask.
//
// The defaults are the plugin manifest's defaults, restated. They are restated
// rather than read because the application does not ship a manifest, and a
// deck that silently disagreed with the plugin about how long a revealed
// secret stays on screen would be worse than one that states its numbers where
// they can be diffed. If the manifest changes, this changes with it.
//
// Only keys that are already known are taken from the file. An unrecognised
// key in ~/.config/black-bag/desktop.json is ignored rather than surfaced,
// because a typo that silently becomes a setting is a setting nobody can find
// again; `theme` and `window` are the application's own and are handled in
// C++, not here.
var DESKTOP_DEFAULTS = {
  // 0 is the sentinel for "size from the viewport"; any positive number is an
  // operator-chosen scale. Listed here because desktopSettings copies ONLY
  // known keys — leaving it out meant the saved scale was written faithfully
  // and then filtered out on every read, so ⌘+/⌘- never survived a restart.
  uiScale: 0,
  staleAfterSec: 120,
  clipboardClearSec: 30,
  revealSeconds: 10,
  motionEnabled: true
}

function desktopSettings(fileSettings) {
  var merged = {}
  for (var k in DESKTOP_DEFAULTS) merged[k] = DESKTOP_DEFAULTS[k]
  if (!fileSettings) return merged
  for (var key in DESKTOP_DEFAULTS) {
    var v = fileSettings[key]
    if (v === undefined || v === null) continue
    // Type-guarded: a string "10" where a number is expected would otherwise
    // reach arithmetic and produce a countdown that concatenates.
    if (typeof DESKTOP_DEFAULTS[key] === "boolean") {
      if (typeof v === "boolean") merged[key] = v
    } else {
      var n = Number(v)
      if (isFinite(n)) merged[key] = n
    }
  }
  return clampSettings(merged)
}

function settingOf(settings, name, fallback) {
  var v = settings ? settings[name] : undefined
  return v === undefined || v === null ? fallback : v
}


/// Render an origin so a lookalike is visible at a glance.
///
/// The registrable domain — approximated as the last two labels — is drawn in
/// `bright`; the scheme, any leading subdomains, the port and the path are
/// drawn in `dim`. `https://bank.example.evil.test` therefore reads as
/// **evil.test**, which is what it actually is, rather than as "bank.example"
/// with noise around it.
///
/// The approximation is deliberate and its limit is worth stating: without a
/// Public Suffix List, `shop.co.uk` highlights `co.uk`. That under-emphasises a
/// legitimate site; it never over-emphasises a hostile one, because the last
/// two labels of an attacker's origin always belong to the attacker.
function originMarkup(origin, dim, bright) {
  var text = String(origin || "")
  if (text.length === 0) return ""

  var esc = function (s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
  }
  // `<font color=...>`, not a CSS style attribute: Qt's StyledText supports a
  // small fixed tag set and silently ignores `style=`, which renders the whole
  // origin in one undifferentiated colour — exactly the failure this function
  // exists to prevent.
  var span = function (s, colour) {
    return s.length === 0 ? "" : '<font color="' + colour + '">' + esc(s) + "</font>"
  }

  var schemeEnd = text.indexOf("://")
  if (schemeEnd < 0) return span(text, bright)
  var scheme = text.slice(0, schemeEnd + 3)
  var rest = text.slice(schemeEnd + 3)

  var cut = rest.length
  var slash = rest.indexOf("/")
  if (slash >= 0) cut = Math.min(cut, slash)
  var hostAndPort = rest.slice(0, cut)
  var tail = rest.slice(cut)

  var host = hostAndPort
  var port = ""
  var colon = hostAndPort.lastIndexOf(":")
  // Only a trailing :port, never part of an IPv6 literal.
  if (colon > 0 && hostAndPort.indexOf("]") < colon) {
    port = hostAndPort.slice(colon)
    host = hostAndPort.slice(0, colon)
  }

  var labels = host.split(".")
  var lead = "", core = host
  if (labels.length > 2) {
    core = labels.slice(labels.length - 2).join(".")
    lead = labels.slice(0, labels.length - 2).join(".") + "."
  }
  return span(scheme, dim) + span(lead, dim) + span(core, bright)
       + span(port, dim) + span(tail, dim)
}

// ── access: approvals and the record of them ─────────────────────────────────

/// What a capability lets a program do, in words rather than in its wire name.
///
/// The distinction between REVEAL and COPY is the one that matters and is the
/// one a bare enum name hides: a value on screen goes away when you look away,
/// and a value on the clipboard is readable by everything else in the session
/// until it is cleared.
function capabilityPhrase(capability) {
  switch (String(capability)) {
    case "reveal":         return "may read it"
    case "copy":           return "may put it on the clipboard"
    case "ssh-sign":       return "may sign with the key"
    case "secret-service": return "may serve it over the Secret Service"
    default:               return String(capability)
  }
}

/// True for a decision that is worth noticing — a refusal, a block, or a
/// withdrawal. Used only to colour a line, never to decide anything.
function decisionIsAdverse(decision) {
  var d = String(decision)
  return d === "refused" || d === "blocked" || d === "revoked" || d === "lapsed"
}

/// `2026-09-03T21:04:07.123456Z` as `21:04:07`.
///
/// The date is dropped deliberately: this list is the last fourteen decisions,
/// which on a machine in use are all from the last few minutes, and a date on
/// every line would crowd out the part that is read.
function auditStamp(at) {
  var text = String(at === undefined || at === null ? "" : at)
  var t = text.indexOf("T")
  if (t < 0) return text
  var rest = text.slice(t + 1)
  // Trim the zone and any fractional seconds: HH:MM:SS is what is left.
  var cut = rest.length
  for (var i = 0; i < rest.length; i++) {
    var c = rest.charAt(i)
    if (c === "." || c === "Z" || c === "+" || (c === "-" && i > 0)) { cut = i; break }
  }
  return rest.slice(0, cut)
}

/// How a backup's state was decided: by reading it, or by looking at it.
///
/// These are different claims and the panel must not blur them. A file that is
/// there at the right size has not been checked; a file whose every byte was
/// read has.
function backupCheckPhrase(checked) {
  return String(checked) === "digest" ? "read in full" : "size checked"
}
