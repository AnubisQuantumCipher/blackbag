// ---- assertions ----
let fails = 0
function eq(actual, expected, label) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected)
  if (a !== e) { console.log(`FAIL ${label}: got ${a}, want ${e}`); fails++ }
  else console.log(`ok   ${label}`)
}

const NOW = Date.parse("2026-08-30T12:00:00Z")
function status(over) {
  return Object.assign({
    schema_version: 1,
    published_at: "2026-08-30T11:59:58Z",
    vault_present: true, error: null, rollback_suspected: false,
    session: { unlocked: false }, findings: [], recipients: [],
  }, over || {})
}

eq(deckState(null, NOW, 120), "NO SIGNAL", "null status")
eq(deckState(status(), NOW, 120), "LOCKED", "fresh + sealed")
eq(deckState(status({ session: { unlocked: true } }), NOW, 120), "UNLOCKED", "unlocked")
eq(deckState(status({ rollback_suspected: true }), NOW, 120), "ROLLBACK", "rollback wins over locked")
eq(deckState(status({ published_at: "2026-08-30T11:00:00Z" }), NOW, 120), "UNKNOWN", "stale outranks all")
eq(deckState(status({ vault_present: false }), NOW, 120), "NO VAULT", "absent vault")
eq(deckState(status({ error: "boom" }), NOW, 120), "UNREADABLE", "parse error")

// stale must outrank even an alert-worthy rollback
eq(deckState(status({ published_at: "2026-01-01T00:00:00Z", rollback_suspected: true }), NOW, 120),
   "UNKNOWN", "stale beats rollback")

eq(fmtCountdown(0), "0s", "countdown zero")
eq(fmtCountdown(59), "59s", "countdown secs")
eq(fmtCountdown(90), "1m 30s", "countdown mins")
eq(fmtCountdown(3700), "1h 1m", "countdown hours")
eq(fmtCountdown(undefined), "—", "countdown absent")

// ── settings clamping ────────────────────────────────────────────────────────
eq(clampSettings({ revealSeconds: 0 }).revealSeconds, 3, "reveal 0 clamps up")
eq(clampSettings({ revealSeconds: -5 }).revealSeconds, 3, "negative reveal clamps up")
eq(clampSettings({ revealSeconds: 9999 }).revealSeconds, 120, "reveal clamps down")
eq(clampSettings({ clipboardClearSec: 0 }).clipboardClearSec, 5, "clear 0 clamps up")
eq(clampSettings({ staleAfterSec: 0 }).staleAfterSec, 10, "stale 0 clamps up")
eq(clampSettings({ uiScale: 0 }).uiScale, 0, "scale 0 stays auto")
eq(clampSettings({ uiScale: 0.2 }).uiScale, 0.7, "tiny scale clamps to floor")
eq(clampSettings({ uiScale: 9 }).uiScale, 3, "huge scale clamps to ceiling")
eq(clampSettings({ revealSeconds: "abc" }).revealSeconds, undefined, "non-numeric dropped")
eq(clampSettings({ motionEnabled: "false" }).motionEnabled, false, "string boolean coerced")
eq(resolvePluginSettings({ bar: { layout: { right: [{ id: "khephri.blackbag", revealSeconds: 0 }] } } },
                         { barWidget: { defaults: { revealSeconds: 10 } } }, "khephri.blackbag").revealSeconds,
   3, "plugin settings are clamped")
eq(desktopSettings({ revealSeconds: 0, uiScale: 1.4 }).revealSeconds, 3, "desktop settings are clamped")
eq(desktopSettings({ uiScale: 1.4 }).uiScale, 1.4, "desktop uiScale survives the read")
eq(desktopSettings({ uiScale: "1.5" }).uiScale, 1.5, "desktop numeric string accepted")
eq(desktopSettings({ bogus: 1 }).bogus, undefined, "unknown desktop keys ignored")

// ── primary field ────────────────────────────────────────────────────────────
eq(primaryField({ secret_fields: [{ name: "notes" }, { name: "password" }] }), "password", "password preferred")
eq(primaryField({ secret_fields: [{ name: "custom" }] }), "custom", "first field otherwise")
eq(primaryField({ secret_fields: [] }), "", "no fields")
eq(primaryField(null), "", "no record")
eq(primaryField({ secret_fields: { length: 1, 0: { name: "seed" } } }), "seed", "array-like from QML")

// ── scale ceiling ────────────────────────────────────────────────────────────
eq(maxScaleFor(1920), 2.1, "1920 wide allows 2.1")
eq(maxScaleFor(1100), 1.2, "1100 wide allows 1.2")
eq(maxScaleFor(0), 3.0, "unknown width allows all")

// ── lock reasons + session rows ──────────────────────────────────────────────
eq(lockReasonLabel("suspend"), "locked before suspend", "suspend reason")
eq(lockReasonLabel("session-lock"), "locked with the screen", "session-lock reason")
eq(lockReasonLabel("weird"), "locked (weird)", "unknown reason shown raw")
eq(lockReasonLabel(""), "", "no reason")
{
  const rows = sessionRows(status({ session: { unlocked: true, method: "passphrase", idle_timeout_secs: 900,
    session_ends_at: "2026-08-30T20:00:00Z", max_session_secs: 43200, sleep_watch: "watching org.freedesktop.login1 for suspend and session lock" } }), NOW)
  eq(rows[0], { k: "idle timeout", v: "15m 00s" }, "session row idle")
  eq(rows[1], { k: "unlocked by", v: "passphrase" }, "session row method")
  eq(rows[2].k, "ends regardless", "session row ceiling")
  eq(rows[2].v.indexOf("8h 0m") > 0, true, "ceiling countdown")
  eq(rows[3].v, "locks the vault", "sleep watch active")
  eq(rows[3].ok, true, "sleep watch ok")
  const locked = sessionRows(status({ session: { unlocked: false, idle_timeout_secs: 900, last_lock_reason: "suspend", sleep_watch: "unavailable: no bus" } }), NOW)
  eq(locked[1], { k: "last lock", v: "locked before suspend" }, "last lock row")
  eq(locked[2].ok, false, "sleep watch unavailable is bad")
  eq(locked[2].detail, "unavailable: no bus", "sleep watch detail carries the reason")
  eq(sessionRows(null, NOW)[0], { k: "idle timeout", v: "—" }, "no status")
}

// ── hygiene sort + exposure ──────────────────────────────────────────────────
{
  const report = { records: [
    { id: "a", title: "A", issues: ["no_totp"] },
    { id: "b", title: "B", issues: ["no_totp", { reused: { field: "password", shared_with: ["a"], handle: "x" } }] },
    { id: "c", title: "C", issues: [{ short: { field: "password", bytes: 4, floor: 12 } }] },
    { id: "d", title: "D", issues: [{ exposed: { field: "password", breaches: 52372427 } }] }
  ], score: { high: 2, medium: 1, low: 2 } }
  const sorted = sortHygiene(report)
  eq(sorted.map(r => r.id), ["b", "d", "c", "a"], "records worst-first, stable among equals")
  eq(hygieneKind(sorted[0].issues[0]), "reused", "issues worst-first within a record")
  eq(exposedCount(report), 1, "exposed count")
  eq(hygieneSeverity({ exposed: { field: "password", breaches: 3 } }), "alert", "exposed is an alert")
  eq(hygieneLine({ exposed: { field: "password", breaches: 3 } }), "password seen in 3 known breaches", "exposed line")
  eq(hygieneLine({ exposed: { field: "password", breaches: 52372427 } }), "password seen in 52,372,427 known breaches", "exposed line groups thousands")
  eq(fmtInt(0), "0", "fmtInt zero")
  eq(fmtInt(999), "999", "fmtInt small")
  eq(fmtInt(1000), "1,000", "fmtInt thousand")
  eq(fmtInt("1234567"), "1,234,567", "fmtInt string input")
  eq(sortHygiene(null), [], "no report sorts to nothing")
}

// ── the way back in ──────────────────────────────────────────────────────────
{
  const withKey = status({ recipients: [
    { label: "passphrase", kind: "passphrase", key_held_externally: false },
    { label: "offsite", kind: "hybrid-x25519-mlkem1024", key_held_externally: true }
  ] })
  eq(recoverableLabels(withKey), ["offsite"], "only externally-held keys count")
  eq(canRecover(withKey), true, "a vault with a recovery recipient can be recovered")

  const passphraseOnly = status({ recipients: [
    { label: "passphrase", kind: "passphrase", key_held_externally: false }
  ] })
  eq(recoverableLabels(passphraseOnly), [], "a passphrase recipient is not a way back in")
  eq(canRecover(passphraseOnly), false, "and the deck must not offer one")
  eq(canRecover(status()), false, "no recipients at all")
  eq(canRecover(null), false, "no status at all")
  // Array-like from QML, the marshalling case asList exists for.
  eq(recoverableLabels({ recipients: { length: 1, 0: { label: "usb", key_held_externally: true } } }),
     ["usb"], "array-like recipients from QML")
}

// ── vault management ─────────────────────────────────────────────────────────
{
  const two = status({ recipients: [
    { label: "passphrase", kind: "passphrase", key_held_externally: false },
    { label: "offsite", kind: "hybrid-x25519-mlkem1024", key_held_externally: true },
    { label: "usb", kind: "hybrid-x25519-mlkem1024", key_held_externally: true }
  ] })
  eq(revocableRecipients(two).map(r => r.label), ["offsite", "usb"], "only offline keys are revocable")
  eq(revocableRecipients(status()).length, 0, "nothing to revoke without recipients")

  eq(kdfMeetsDefault(status({ kdf: { meets_current_defaults: true } })), true, "kdf at default")
  eq(kdfMeetsDefault(status({ kdf: { meets_current_defaults: false } })), false, "kdf below default")
  eq(kdfMeetsDefault(status()), true, "no kdf reported is not a complaint")
  eq(kdfMeetsDefault(null), true, "no status is not a complaint")

  eq(shortStamp().length, 8, "stamp is YYYYMMDD")
  eq(/^\d{8}$/.test(shortStamp()), true, "stamp is all digits")

  eq(IMPORT_FORMATS.length, 7, "every import format the engine has is offered")
  eq(EXPORT_FORMATS.length, 3, "and every export format")
  eq(GEN_KINDS.length, 3, "and every generator kind")

  // The steppers must not be able to offer a value the clamp would reject.
  for (const row of SETTING_ROWS) {
    const lo = clampSettings({ [row.key]: row.from })[row.key]
    const hi = clampSettings({ [row.key]: row.to })[row.key]
    eq(lo, row.from, `${row.key} lower bound survives the clamp`)
    eq(hi, row.to, `${row.key} upper bound survives the clamp`)
  }
}

// ── posture: session key ─────────────────────────────────────────────────────
{
  const rows = postureRows(status({ host: { mlock_working: true, core_dumps_disabled: true, swap_devices: [],
    memlock_limit_bytes: 8388608, traced: false, session_key_backing: "memfd_secret" } }))
  const key = rows.find(r => r.label === "session key")
  eq(key.ok, true, "memfd_secret is good")
  eq(key.value, "kernel-invisible", "memfd_secret label")
  const bad = postureRows(status({ host: { session_key_backing: "unlocked" } })).find(r => r.label === "session key")
  eq(bad.ok, false, "unlocked key is bad")
  const unk = postureRows(status({ host: {} })).find(r => r.label === "session key")
  eq(unk.ok, null, "unmeasured key is null")
}

// ── formatting helpers that carry the list ───────────────────────────────────
eq(fmtAgo("2026-08-30T11:59:30Z", NOW), "30s ago", "ago seconds")
eq(fmtAgo("2026-08-30T11:30:00Z", NOW), "30m ago", "ago minutes")
eq(fmtAgo("2026-08-29T12:00:00Z", NOW), "1d ago", "ago days")
eq(fmtAgo("garbage", NOW), "—", "ago garbage")
eq(asList(null), [], "asList null")
eq(asList({ length: 2, 0: "a", 1: "b" }), ["a", "b"], "asList array-like")
eq(isStale(status(), NOW, 120), false, "fresh is not stale")
eq(isStale(status({ published_at: "2026-08-30T11:00:00Z" }), NOW, 120), true, "old is stale")
eq(isStale(status({ published_at: "2026-08-30T11:58:00Z" }), NOW, 120), false, "exactly at threshold is fresh")
eq(sessionRemaining(status({ session: { unlocked: true, expires_at: "2026-08-30T12:05:00Z" } }), NOW), 300, "remaining seconds")
eq(sessionRemaining(status(), NOW), null, "remaining when locked")
eq(totpUrgent(5), true, "5s is urgent")
eq(totpUrgent(6), false, "6s is not")
eq(fmtClock("2026-08-30T12:34:56Z").length, 5, "clock is HH:MM")

eq(orDash(""), "—", "empty is dash")
eq(orDash(0), "0", "zero is not dash")
eq(orDash(null), "—", "null is dash")

// census must always return all twelve kinds so a zero is a measured zero
const c = census([["login", 3], ["totp", 2]])
eq(c.length, 13, "census covers every kind")
eq(c[0], { kind: "login", glyph: "◉", count: 3 }, "census login")
eq(c.find(r => r.kind === "wifi").count, 0, "census absent kind is 0")
eq(totalRecords([["login", 3], ["totp", 2]]), 5, "total records")

const recs = [
  { id: "1", kind: "login", title: "GitHub", tags: ["dev"],
    attributes: [["username", "octocat"]], secret_fields: [{ name: "password" }] },
  { id: "2", kind: "note", title: "Ops", tags: [], attributes: [], secret_fields: [] },
  { id: "3", kind: "totp", title: "Bank", tags: [], attributes: [], secret_fields: [] },
]
eq(filterRecords(recs, "", "github").length, 1, "search by title")
eq(filterRecords(recs, "", "octocat").length, 1, "search by attribute")
eq(filterRecords(recs, "login", "").length, 1, "filter by kind")
eq(filterRecords(recs, "", "").length, 3, "empty filter keeps all")
eq(sortRecords(recs).map(r => r.kind), ["login", "totp", "note"], "sort by kind order")

eq(totpProgress(30, 30), 0, "totp fresh")
eq(totpProgress(15, 30), 0.5, "totp half")
eq(totpProgress(0, 30), 1, "totp expired")
eq(totpUrgent(5), true, "totp urgent at 5s")
eq(totpUrgent(6), false, "totp not urgent at 6s")

eq(worstSeverity(status({ findings: [{ severity: "ok" }, { severity: "alert" }] })), "alert", "worst severity")
eq(countFindings(status({ findings: [{ severity: "warn" }, { severity: "warn" }] }), "warn"), 2, "count warns")

eq(fmtKdf({ algorithm: "argon2id", mem_cost_kib: 262144, time_cost: 10, lanes: 4 }),
   "argon2id · 256 MiB · t=10 · p=4", "kdf format")

const posture = postureRows(status({ host: {
  mlock_working: true, core_dumps_disabled: false, core_pattern: "|/usr/lib/systemd/systemd-coredump",
  swap_devices: ["/dev/zram0"], memlock_limit_bytes: 8388608, memlock_unlimited: false, traced: false } }))
eq(posture.find(r => r.label === "core dumps").ok, false, "coredumps flagged when host handler set")
eq(posture.find(r => r.label === "swap").ok, false, "active swap flagged")
eq(posture.find(r => r.label === "mlock").ok, true, "working mlock is ok")

eq(barText(status({ session: { unlocked: false } }), NOW, 120), "LOCKED", "bar locked")
eq(barText(status({ published_at: "2020-01-01T00:00:00Z" }), NOW, 120), "UNKNOWN", "bar stale")



// Regression: values arriving from a QML `var` property are not always native
// Arrays. Guarding on Array.isArray made attrMap return {} and silently blanked
// every record subtitle in the cockpit. Simulate that with an array-like.
function arrayLike(items) {
  const o = { length: items.length }
  items.forEach((v, i) => { o[i] = v })
  return o   // no Array.prototype — Array.isArray(o) === false
}
const marshalled = {
  id: "1", kind: "login", title: "GitHub",
  tags: arrayLike(["dev"]),
  attributes: arrayLike([arrayLike(["username", "octocat"]),
                         arrayLike(["url", "https://github.com"])]),
  secret_fields: arrayLike([])
}
eq(attrMap(marshalled), { username: "octocat", url: "https://github.com" },
   "attrMap survives QML array marshalling")
eq(recordSubtitle(marshalled), "octocat · https://github.com",
   "recordSubtitle survives QML array marshalling")
eq(filterRecords(arrayLike([marshalled]), "", "octocat").length, 1,
   "filterRecords survives QML array marshalling")
eq(census(arrayLike([arrayLike(["login", 2])]))[0].count, 2,
   "census survives QML array marshalling")


// ── unlockVerdict: hazards must survive staleness ────────────────────────────
const NOW2 = Date.parse("2026-08-30T12:00:00Z")
function st(over) {
  return Object.assign({
    schema_version: 1, published_at: "2026-08-30T11:59:58Z",
    vault_present: true, error: null, rollback_suspected: false,
    vault_id: "a4ef5118-1234-5678-9abc-def012345678",
    epoch: 9, witness_epoch: 9,
    session: { unlocked: false }, findings: [], recipients: [],
    host: { mlock_working: true, core_dumps_disabled: true, swap_devices: [],
            memlock_limit_bytes: 8388608, memlock_unlimited: false, traced: false,
            core_pattern: "|/usr/lib/systemd/systemd-coredump" }
  }, over || {})
}
const V = (o, now) => unlockVerdict(st(o), now === undefined ? NOW2 : now, 120)

eq(V({}).severity, "none", "healthy vault is quiet")
eq(V({}).headline, "", "healthy vault says nothing")
eq(V({}).witness, "epoch 9 witnessed", "witness verdict is stated, not left to the eye")
eq(V({}).blockInput, false, "healthy vault accepts typing")

// The whole point: staleness must MODIFY, never MASK.
const STALE = Date.parse("2026-08-30T13:00:00Z")
eq(V({ rollback_suspected: true }, STALE).severity, "alert",
   "a STALE rollback still alarms (staleness must not mask a hazard)")
eq(V({ host: { traced: true } }, STALE).blockInput, true,
   "a STALE tracer still blocks (fail closed on the alarm)")
eq(V({}, STALE).severity, "stale", "a stale all-clear is downgraded, not trusted")
eq(V({}, STALE).stale, true, "staleness is reported")

// A tracer reads keystrokes, so there is no honest "proceed anyway".
eq(V({ host: { traced: true } }).blockInput, true, "tracer blocks input")
eq(V({ host: { traced: true } }).severity, "alert", "tracer is an alert")

// Rollback is loud but never blocking — a legitimate restore must not lock you out.
eq(V({ rollback_suspected: true, witness_epoch: 11 }).blockInput, false,
   "rollback warns but never blocks")
eq(V({ rollback_suspected: true }).verb, "unlock anyway", "rollback changes the verb")
eq(V({ rollback_suspected: true }).witnessTone, "bad", "rollback marks the witness bad")

// Absence must never counterfeit a pass.
eq(V({ host: undefined }).severity, "alert", "a missing host section is an alert")
eq(V({ host: undefined }).headline, "HOST POSTURE UNKNOWN", "missing host says so")
eq(unlockVerdict(null, NOW2, 120).severity, "alert", "no status at all is an alert")
eq(V({ witness_epoch: null }).witness, "unwitnessed", "no witness says unwitnessed")
eq(V({ witness_epoch: null }).witnessTone, "quiet", "unwitnessed is quiet, not good")

// Two absences, two renderings: no vault means no field at all.
eq(V({ vault_present: false }).hasVault, false, "absent vault offers no field")
eq(V({ error: "bad cbor" }).hasVault, false, "unreadable vault offers no field")
eq(V({ error: "bad cbor" }).severity, "alert", "unreadable vault is an alert")

// mlock failure is an alert, not a note.
eq(V({ host: { mlock_working: false, mlock_error: "ENOMEM", traced: false } }).severity,
   "alert", "broken mlock is an alert")

// Notes that are permanent on this machine must NOT reach the sealed screen,
// or it would never be quiet and the quiet would stop meaning anything.
eq(V({ host: { mlock_working: true, core_dumps_disabled: true, traced: false,
               swap_devices: ["/dev/zram0"], memlock_limit_bytes: 8388608 } }).severity,
   "none", "active swap does not shout on the sealed screen")

// Fingerprint: absence has the shape of the thing that is missing.
eq(fingerprint("a4ef5118-1234-5678-9abc-def012345678"), "a4ef  5118", "fingerprint groups 4+4")
eq(fingerprint(null), "————  ————", "absent fingerprint is a hole, not a blank")
eq(fingerprint("abc"), "————  ————", "too-short id is a hole")

// postureRows tri-state
const pr = postureRows(st({}))
eq(pr.find(r => r.label === "mlock").ok, true, "measured-good is true")
eq(postureRows(st({ host: undefined })).every(r => r.ok === null), true,
   "no host section means every row is unmeasured, not passing")
eq(postureRows(st({ host: undefined }))[0].value, "UNKNOWN", "unmeasured renders UNKNOWN")
eq(pr.find(r => r.label === "swap").severity, "note", "swap is a note")
eq(pr.find(r => r.label === "mlock").severity, "alert", "mlock is an alert")

// findings sorted worst-first, stable within a rank
const sorted = sortFindings(st({ findings: [
  { severity: "note", id: "N1" }, { severity: "alert", id: "A" },
  { severity: "note", id: "N2" }, { severity: "warn", id: "W" }] }))
eq(sorted.map(f => f.id), ["A", "W", "N1", "N2"], "findings sort worst-first, stable")

eq(severityMark("unknown-value"), "?", "unknown severity does not borrow the pass tick")


// ── plugin settings resolution ───────────────────────────────────────────────
const MANIFEST = { barWidget: { defaults: {
  pollIntervalSec: 5, staleAfterSec: 120, clipboardClearSec: 30,
  revealSeconds: 10, motionEnabled: true } } }
const CFG = { bar: { layout: {
  left: [{ id: "omarchy.menu" }],
  center: [],
  right: [{ id: "khephri.jackal" }, { id: "khephri.blackbag", revealSeconds: 4 }] } } }

eq(resolvePluginSettings(CFG, MANIFEST, "khephri.blackbag").revealSeconds, 4,
   "a shell.json override wins over the manifest default")
eq(resolvePluginSettings(CFG, MANIFEST, "khephri.blackbag").staleAfterSec, 120,
   "untouched keys still resolve to the manifest default")
eq(resolvePluginSettings(null, MANIFEST, "khephri.blackbag").revealSeconds, 10,
   "no shell config falls back to the manifest")
eq(resolvePluginSettings(CFG, null, "khephri.blackbag").revealSeconds, 4,
   "no manifest still picks up the override")
eq(Object.keys(resolvePluginSettings(null, null, "khephri.blackbag")).length, 0,
   "nothing in, nothing invented")
eq(resolvePluginSettings(CFG, MANIFEST, "khephri.other").revealSeconds, 10,
   "another plugin's entry is not read")
eq(settingOf({ a: 0 }, "a", 9), 0, "a zero setting is not treated as absent")
eq(settingOf({ a: null }, "a", 9), 9, "an explicit null falls back")
eq(settingOf(null, "a", 9), 9, "no settings object falls back")

// top-level plugin entries (non-bar plugins) resolve too
eq(resolvePluginSettings({ plugins: [{ id: "khephri.blackbag", revealSeconds: 7 }] },
                         MANIFEST, "khephri.blackbag").revealSeconds, 7,
   "a top-level plugin entry is honoured")


// ── hygiene rendering, against the shapes the engine really emits ────────────
// serde tags Issue externally: struct variants nest, unit variants are bare
// strings, and severity is a Rust method that never reaches the JSON.
const H_REUSED = { reused: { field: "totp", shared_with: ["a54a"], handle: "66808bcc" } }
const H_SHORT  = { short: { field: "password", bytes: 6, floor: 12 } }
const H_STALE  = { stale: { last_modified: "2024-01-01T00:00:00Z", age_days: 600, threshold_days: 365 } }
const H_PIN    = { weak_pin: { field: "password", digits: 4, floor: 22 } }
const H_DUP    = { duplicate_title: { others: ["x", "y"] } }

eq(hygieneKind(H_REUSED), "reused", "kind of a struct variant")
eq(hygieneKind("no_totp"), "no_totp", "kind of a unit variant")
eq(hygieneSeverity(H_REUSED), "alert", "reuse is an alert")
eq(hygieneSeverity(H_PIN), "alert", "a weak pin is an alert")
eq(hygieneSeverity("no_totp"), "note", "a missing second factor is a note")
eq(hygieneSeverity({ brand_new_rule: {} }), "warn",
   "a finding this build does not know must not be demoted to the mildest bucket")
eq(hygieneLine(H_REUSED), "same totp as 1 other record(s)", "reuse line")
eq(hygieneLine("no_totp"), "no second factor stored here", "no_totp line")
eq(hygieneLine(H_SHORT), "password is 6 bytes · floor 12", "short line")
eq(hygieneLine(H_STALE), "unchanged for 600 days", "stale line")
eq(hygieneLine(H_PIN), "password is 4 digits · floor 22", "weak pin line")
eq(hygieneLine(H_DUP), "shares a title with 2 other record(s)", "duplicate line")
eq(hygieneCount({ score: { high: 2, medium: 0, low: 1 } }), 3, "issue count")
eq(hygieneCount(null), 0, "no report counts zero rather than crashing")

// ── record templates and draft building ──────────────────────────────────────
eq(templateFor("login").secrets, ["password"], "login asks for a password")
eq(templateFor("contact").attrs.indexOf("phones") >= 0, true, "contact takes phone numbers")
eq(templateFor("totp").totp, true, "totp is flagged as a 2FA kind")
eq(kindChoices().length, 12, "every authorable kind is offered in the picker")
eq(kindChoices().some(c => c.kind === "passkey"), false,
   "a passkey is not authorable by hand and is not offered")
eq(kindIsSealed("passkey"), true, "a passkey's key material is sealed")
eq(kindIsSealed("login"), false, "an ordinary password is not")
eq(isMultiline("note", "body"), true, "a note body is multiline")
eq(isMultiline("login", "password"), false, "a password is not")

const d = buildDraft("login", " GitHub ", "dev, code ,",
                     { username: "octocat", url: "" },
                     { password: "s3cret" }, null)
eq(d.kind, "login", "draft kind")
eq(d.title, "GitHub", "draft title is trimmed")
eq(d.tags, ["dev", "code"], "tags split and trimmed, empties dropped")
eq(d.attributes, [["username", "octocat"]], "empty attributes are omitted")
eq(d.secrets, [["password", "s3cret"]], "secret carried through untouched")

const dt = buildDraft("totp", "GitHub 2FA", "",
                      { issuer: "GitHub", account: "octocat" }, {},
                      { uri: "otpauth://totp/GitHub:octocat?secret=ABC" })
eq(dt.totp.otpauth_uri, "otpauth://totp/GitHub:octocat?secret=ABC", "otpauth URI carried")
eq(dt.totp.issuer, "GitHub", "issuer rides along for code labelling")

eq(draftProblems("login", "", {}, null, false).indexOf("a title") >= 0, true,
   "a new record needs a title")
eq(draftProblems("login", "x", {}, null, false).length > 0, true,
   "a new login needs its password")
eq(draftProblems("login", "x", {}, null, true).length, 0,
   "an edit may leave the password blank to keep the stored one")
eq(draftProblems("totp", "x", {}, { uri: "" }, false).length > 0, true,
   "a new 2FA record needs a secret or a URI")
eq(draftProblems("totp", "x", {}, { uri: "https://nope" }, false)
     .indexOf("a URI starting with otpauth://") >= 0, true,
   "a non-otpauth URI is rejected before it reaches the engine")


// ── the origin, rendered so a lookalike is visible ─────────────────────────
//
// This is the only defence a human has on the consent screen, so its edges are
// tested rather than eyeballed.

const DIM = "#555", BRIGHT = "#0f0";
const core = (s) => {
  // The text inside the BRIGHT span: what the eye is being told to trust.
  const m = originMarkup(s, DIM, BRIGHT).match(
    new RegExp('<font color="' + BRIGHT + '">([^<]*)</font>'));
  return m ? m[1] : "";
};

eq(core("https://bank.example"), "bank.example", "a bare origin highlights itself");
eq(core("https://login.bank.example"), "bank.example", "a subdomain highlights the domain");
eq(core("https://a.b.c.bank.example"), "bank.example", "deep subdomains still highlight it");
eq(core("https://bank.example.evil.test"), "evil.test",
   "a lookalike highlights the attacker's domain, not the bait");
eq(core("https://bank.example:8443"), "bank.example", "a port is not part of the domain");
eq(core("https://bank.example/login?next=/x"), "bank.example", "nor is a path");
eq(core("http://localhost:3000"), "localhost", "localhost has no second label");
eq(originMarkup("", DIM, BRIGHT), "", "nothing in, nothing out");

// StyledText renders markup, so anything that arrives from a browser must be
// escaped or an origin could inject styling into this screen.
eq(originMarkup("https://<b>evil</b>.test", DIM, BRIGHT).indexOf("&lt;b&gt;") > 0, true,
   "markup in an origin is escaped, not rendered");
eq(core("https://x&y.test"), "x&amp;y.test", "an ampersand is escaped");


// ── access: approvals, and reading the record of them ────────────────────────

// The wire names come from Rust's `Capability::as_str`, and a mismatch here
// would silently render a raw enum name in the one panel a person consults
// before deciding whether to withdraw an approval.
eq(capabilityPhrase("reveal"), "may read it", "reveal reads plainly");
eq(capabilityPhrase("copy"), "may put it on the clipboard",
   "copy names the clipboard, which is the whole reason it is separate");
eq(capabilityPhrase("ssh-sign"), "may sign with the key", "ssh-sign reads plainly");
eq(capabilityPhrase("secret-service"), "may serve it over the Secret Service",
   "secret-service reads plainly");
eq(capabilityPhrase("something-new"), "something-new",
   "an unknown capability shows its own name rather than vanishing");

eq(decisionIsAdverse("refused"), true, "a refusal is worth noticing");
eq(decisionIsAdverse("blocked"), true, "so is a block");
eq(decisionIsAdverse("revoked"), true, "so is a withdrawal");
eq(decisionIsAdverse("lapsed"), true, "so is an expiry");
eq(decisionIsAdverse("approved"), false, "an approval is not");
eq(decisionIsAdverse("remembered"), false, "nor is one already given");

eq(auditStamp("2026-09-03T21:04:07Z"), "21:04:07", "a plain UTC stamp");
eq(auditStamp("2026-09-03T21:04:07.123456Z"), "21:04:07", "fractional seconds are dropped");
eq(auditStamp("2026-09-03T21:04:07+01:00"), "21:04:07", "so is a positive offset");
eq(auditStamp("2026-09-03T21:04:07-05:00"), "21:04:07", "and a negative one");
eq(auditStamp(""), "", "nothing in, nothing out");
eq(auditStamp(undefined), "", "and an absent field does not print 'undefined'");

eq(backupCheckPhrase("digest"), "read in full", "a verified copy says so");
eq(backupCheckPhrase("size"), "size checked", "an unverified one does not overclaim");
eq(backupCheckPhrase(undefined), "size checked",
   "an absent field is the weaker claim, never the stronger one");

console.log(fails === 0 ? "\nALL PASS" : `\n${fails} FAILURES`)
process.exit(fails === 0 ? 0 : 1)
