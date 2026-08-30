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

eq(orDash(""), "—", "empty is dash")
eq(orDash(0), "0", "zero is not dash")
eq(orDash(null), "—", "null is dash")

// census must always return all twelve kinds so a zero is a measured zero
const c = census([["login", 3], ["totp", 2]])
eq(c.length, 12, "census covers every kind")
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
eq(kindChoices().length, 12, "every kind is offered in the picker")
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

console.log(fails === 0 ? "\nALL PASS" : `\n${fails} FAILURES`)
process.exit(fails === 0 ? 0 : 1)
