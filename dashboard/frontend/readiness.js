/* DPDP readiness score: a 0-100 score and grade built from nine areas, each scored from what the
   dashboard already measures (breach detectors and the anomaly model, the breach register and its
   clocks, consent coverage, retention deadlines, access policies, log coverage). Every finding cites
   the law and gives a fix. Areas the person may not read are "not assessed", not failed.
   Results are saved with a score history. The "Public exposure" area comes from the server's exposure
   test (reads the customer database with the shop's public key); its own tab shows table-by-table results.
   "Records & evidence" comes from the server's hash-chained ledger; the Evidence & audit tab verifies it,
   shows the daily seals and log retention, and exports / checks evidence packs for an auditor.
   Uses Breach / Consent / Retention / Dashboard modules and session / can / ME from app.js. */
const Readiness = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const dt = (v) => { if (!v) return "–"; const d = new Date(v); return isNaN(d) ? String(v) : F.format(d).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase()); };
  const grade = (s) => (s >= 85 ? "A" : s >= 70 ? "B" : s >= 55 ? "C" : s >= 40 ? "D" : "E");
  const clamp = (x) => Math.max(0, Math.min(1, x));

  const S = { result: null, history: [], busy: false, err: "", started: false, step: "", tab: "score", exp: null, expBusy: false, expErr: "", ev: null, evBusy: "", evErr: "", check: null };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r = await go();
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  const f = (level, text, ref, fix) => ({ level, text, ref, fix });

  /* ---------- the six areas ---------- */
  async function monitoring(w) {
    if (!w.logs) return { score: null, why: "Connect your logs to assess security monitoring." };
    if (!can("breach:ReadSignals")) return { score: null, why: "Needs permission to read breach signals." };
    const ctx = await Breach.context();
    if (!ctx) return { score: null, why: "Breach detection didn't answer." };
    const dets = ctx.detectors, on = dets.filter((d) => d.enabled).length, model = ctx.anomaly_model || {};
    const fresh = ctx.signals.filter((s) => s.state === "new").length;
    const pii = dets.filter((d) => /personal data written to application logs/i.test(d.name)).reduce((n, d) => n + (d.signals || 0), 0);
    const out = [];
    out.push(on === dets.length ? f("ok", `All ${on} breach detectors are on.`, "s.8(5)") : f("warn", `${dets.length - on} of ${dets.length} breach detectors are off.`, "s.8(5)", "Turn them on in Breach Response → Detectors & settings."));
    out.push(model.enabled ? f("ok", `The ML anomaly model is on (${model.sensitivity} sensitivity).`, "Rule 6(1)(c)") : f("warn", "The anomaly model is off, so only fixed rules watch the logs.", "Rule 6(1)(c)", "Turn it on in Breach Response → Anomaly model."));
    out.push(!fresh ? f("ok", "Every breach signal has been reviewed.", "s.8(6)") : f(fresh > 10 ? "bad" : "warn", `${fresh} breach signals are waiting for review.`, "s.8(6)", "Review them in Breach Response → Signals: open an incident or dismiss with a reason."));
    out.push(!pii ? f("ok", "No personal data patterns caught in application logs.", "s.8(5)") : f("warn", `${pii} groups of personal data patterns were caught in application logs.`, "s.8(5) reasonable security safeguards", "Stop logging personal data at the source, and check the masker's false positives."));
    const score = 35 * (dets.length ? on / dets.length : 0) + (model.enabled ? 15 : 0) + 25 * clamp(1 - fresh / 20) + 25 * clamp(1 - pii / 10);
    return { score, findings: out };
  }
  async function breach() {
    if (!can("breach:ReadSignals")) return { score: null, why: "Needs permission to read Breach Response." };
    const s = await Breach.summary(), ctx = await Breach.context();
    if (!s || !ctx) return { score: null, why: "Breach Response didn't answer." };
    const c = ctx.clocks_hours || {}, out = [];
    out.push(!s.contactMissing ? f("ok", "A contact person is set for customer notices.", "Rule 7(1)(e)") : f("bad", "No contact person is set for breach notices.", "Rule 7(1)(e)", "Add one in Breach Response → Detectors & settings, or in Workspace settings → Company profile."));
    out.push(!s.overdue ? f("ok", "No breach notification is overdue.", "Rule 7(1)–(2)") : f("bad", `${s.overdue} breach notification deadline(s) are overdue.`, "Rule 7(2)(b) · 72 hours", "Open the incident and send the notice, or record that it was sent."));
    out.push((c.board_report_hours || 99) <= 72 ? f("ok", `The Board's detailed report is due within ${c.board_report_hours} h.`, "Rule 7(2)(b)") : f("bad", `The Board report clock is ${c.board_report_hours} h, longer than the 72 h the Rules allow.`, "Rule 7(2)(b)", "Set it to 72 hours or less."));
    out.push((c.cert_in_hours || 99) <= 6 ? f("ok", "CERT-In reporting is set to 6 hours.", "CERT-In Directions 2022") : f("warn", `CERT-In reporting is set to ${c.cert_in_hours} h; the Directions require 6 h.`, "CERT-In Directions 2022", "Set the CERT-In clock to 6 hours."));
    const score = (s.contactMissing ? 0 : 35) + (s.overdue ? 0 : 35) + ((c.board_report_hours || 99) <= 72 ? 15 : 0) + ((c.cert_in_hours || 99) <= 6 ? 15 : 0);
    return { score, findings: out };
  }
  async function consent(w) {
    if (!w.shop) return { score: null, why: "Connect your customer database to assess consent." };
    if (!can("consent:ReadFindings")) return { score: null, why: "Needs permission to read Consent & Purpose." };
    const s = await Consent.summary().catch(() => null);
    if (!s || !s.customers) return { score: null, why: "No customers found yet. Map your tables in Consent & Purpose → Data inventory." };
    const out = [], g = s.gate;
    // With mandatory acceptance at sign-up, existing accounts waiting to re-accept count half: they're on track, not in breach.
    const ratio = (s.valid + 0.5 * (s.legacy || 0)) / s.customers;
    if (g) out.push(!g.failures ? f("ok", `The sign-up gate works: ${g.accepted} of ${g.after} accounts created since acceptance became mandatory accepted at sign-up.`, "s.5, s.6")
      : f("bad", `${g.failures} account(s) created since acceptance became mandatory have no acceptance recorded.`, "s.5, s.6", "Check the website's sign-up flow: the acceptance must be saved before the account is created."));
    out.push(s.attention === 0 ? f("ok", `${s.valid} of ${num(s.customers)} customers accepted${s.legacy ? `; ${s.legacy} existing account(s) will be asked at their next sign-in` : ""}.`, "s.6")
      : f(s.attention <= 2 ? "warn" : "bad", `${s.attention} customer(s) need action (not saved, old version, or active without re-accepting); ${s.valid} accepted${s.legacy ? `, ${s.legacy} existing account(s) to re-accept` : ""}.`, "s.6 · consent must be free, specific, informed", "Open Consent & Purpose → Customers → Needs action."));
    out.push(!s.high ? f("ok", "No high-severity consent issues.", "ss.5–7") : f("bad", `${s.high} high-severity consent issue(s), ${s.issues} in all.`, "ss.5–7", "Open Consent & Purpose → Overview and work through the issues."));
    return { score: 60 * ratio + 40 * clamp(1 - s.high / 5) * (s.issues > 20 ? 0.7 : 1), findings: out };
  }
  async function retention(w) {
    if (!w.shop) return { score: null, why: "Connect your customer database to assess retention." };
    if (!can("retention:ReadSchedule")) return { score: null, why: "Needs permission to read Retention." };
    const s = await Retention.summary().catch(() => null);
    if (!s) return { score: null, why: "Retention didn't answer." };
    const out = [];
    out.push(!s.past ? f("ok", "No personal data is kept past its retention deadline.", "s.8(7)") : f(s.past > 100 ? "bad" : "warn", `${num(s.past)} records are kept past their retention deadline.`, "s.8(7) · erase when the purpose is served", "Export the deletion worklist in Retention and have the owning service delete them."));
    out.push(!s.erasureOverdue ? f("ok", "Every erasure request is within its deadline.", "s.12(3)") : f("bad", `${num(s.erasureOverdue)} erasure request(s) are overdue.`, "s.12(3)", "Complete them and record the date."));
    out.push(!s.conflicts ? f("ok", "No conflict between legal minimums and deletion rules.", "Rule 8") : f("warn", `${s.conflicts} retention rule conflict(s).`, "Rule 8", "Resolve them in Retention → Rules."));
    return { score: 50 * clamp(1 - s.past / 200) + 35 * (s.erasureOverdue ? 0 : 1) + 15 * (s.conflicts ? 0 : 1), findings: out };
  }
  async function access() {
    if (!can("iam:ListUsers")) return { score: null, why: "Needs permission to list users and policies." };
    const st = await api("/api/iam");
    const users = st.users || [], others = users.filter((u) => !u.root), total = Object.keys(st.catalog).reduce((n, k) => n + Object.keys(st.catalog[k].actions).length, 0);
    const broad = others.filter((u) => u.allowed >= total * 0.8), stale = others.filter((u) => !u.last_sign_in_at || Date.now() - new Date(u.last_sign_in_at) > 90 * 864e5), out = [];
    out.push(f("ok", "Access is denied by default; nothing is allowed unless a policy grants it.", "s.8(5)"));
    out.push(!broad.length ? f("ok", others.length ? "No one besides root has near-full access." : "Only root has access so far.", "s.8(5) · least privilege") : f("warn", `${broad.length} person(s) have near-full access.`, "s.8(5) · least privilege", "Give people only the actions they need in Access management."));
    out.push(!stale.length ? f("ok", "No unused accounts.", "s.8(5)") : f("warn", `${stale.length} account(s) haven't signed in for 90 days or never.`, "s.8(5)", "Deactivate accounts that aren't needed."));
    return { score: 20 + 45 * (broad.length ? clamp(1 - broad.length / Math.max(1, others.length)) : 1) + 35 * (stale.length ? clamp(1 - stale.length / Math.max(1, others.length)) : 1), findings: out };
  }
  async function logging(w) {
    if (!w.logs) return { score: null, why: "Connect your logs to assess logging coverage." };
    if (!can("dashboard:View") && !can("telemetry:ReadLogs")) return { score: null, why: "Needs permission to read logs." };
    const c = await Dashboard.context().catch(() => null);
    if (!c) return { score: null, why: "The logs didn't answer." };
    const services = (c.lines_by_service || []).length, lines = c.lines, errs = (c.lines_by_level?.ERROR || 0), out = [];
    out.push(services ? f("ok", `${services} services are writing logs.`, "Rule 6(1)(e) · logs for detection") : f("bad", "No service wrote logs in the last 7 days.", "Rule 6(1)(e)", "Check that your services send logs to the connected project."));
    out.push(lines ? f("ok", `${num(lines)} log lines in the last 7 days.`, "Rule 6(1)(e)") : f("bad", "No log lines in the last 7 days.", "Rule 6(1)(e)", "Logs must be kept so breaches can be detected and investigated (and kept for at least a year)."));
    out.push(c.all_time?.lines_with_pii_masked ? f("ok", "Personal data in log lines is masked before it is stored.", "s.8(5)") : f("warn", "No sign that personal data in log lines is masked.", "s.8(5)", "Mask emails, phones and card numbers in your log pipeline."));
    out.push(lines && errs / lines < 0.05 ? f("ok", `${((errs / Math.max(1, lines)) * 100).toFixed(1)}% of log lines are errors.`, "Rule 6(1)(c)") : f("warn", `${num(errs)} error lines (${((errs / Math.max(1, lines)) * 100).toFixed(1)}%).`, "Rule 6(1)(c)", "Look at the busiest error sources in the Dashboard."));
    return { score: 30 * (services ? 1 : 0) + 30 * (lines ? 1 : 0) + 20 * (c.all_time?.lines_with_pii_masked ? 1 : 0) + 20 * (lines && errs / lines < 0.05 ? 1 : 0), findings: out };
  }
  async function exposure() {
    const v = can("readiness:Run") ? { last: await api("/api/readiness/exposure", { method: "POST" }) } : await api("/api/readiness/exposure");
    S.exp = { ...(S.exp || {}), configured: true, ...v, history: S.exp?.history || [] };
    const x = v.last;
    if (!x) return { score: null, why: "The exposure test hasn't run yet. Someone with permission to run the readiness score can start it." };
    const out = [], leak = x.tables.filter((t) => t.state === "exposed" && t.personal?.length);
    out.push(!leak.length ? f("ok", `None of ${x.counts.tables} tables gives personal data to the public key.`, "Rule 6(1)(b) · access control")
      : f("bad", `${leak.length} table(s) give personal data to anyone with the public key: ${leak.slice(0, 4).map((t) => t.table).join(", ")}${leak.length > 4 ? "…" : ""}.`, "Rule 6(1)(b) · access control", "Open the Public exposure tab and apply the fix for each table."));
    const open = x.tables.filter((t) => t.state === "exposed" && !t.personal?.length);
    if (open.length) out.push(f("warn", `${open.length} table(s) are readable by the public but hold no personal data: ${open.slice(0, 4).map((t) => t.table).join(", ")}.`, "s.8(5)", "Fine for a public catalogue; otherwise lock them down too."));
    for (const c of x.checks.filter((c) => !["ok", "info"].includes(c.severity))) out.push(f(c.severity === "high" ? "bad" : "warn", c.text, "Rule 6(1)", c.fix || ""));
    if (x.checks.every((c) => ["ok", "info"].includes(c.severity))) out.push(f("ok", "Storage, sign-up and API settings show no public leaks.", "Rule 6(1)"));
    return { score: x.score, findings: out };
  }
  async function evidence() {
    if (!can("readiness:VerifyIntegrity") && !can("readiness:Read")) return { score: null, why: "Needs permission to see the evidence ledger." };
    const v = await api("/api/evidence"); S.ev = v;
    const out = [], lr = v.log_retention || {}, d = (x) => (x ? dt(x) : "–");
    out.push(v.ok ? f("ok", `Records are intact: ${num(v.entries)} ledger entries, ${num(v.audit_records)} activity records and ${v.files_tracked} record files check out since ${d(v.since)}.`, "s.8(5) · Rule 6(1)(e)")
      : f("bad", `${v.problem_count} record(s) were changed outside the system: ${v.problems[0]?.text || ""}`, "s.8(5) · Rule 6(1)(e)", "Open Evidence & audit to see what changed, find out who had access to the server, and treat it as a possible breach."));
    out.push(lr.ok ? f("ok", `No retention rule deletes logs before one year${lr.rules?.length ? ` (${lr.rules.map((r) => `${r.id}: ${Math.round(r.keep_days)} days`).join(", ")})` : ""}.`, "Rule 6(1)(e) · keep logs ≥ 1 year")
      : f("bad", lr.findings?.[0] || "A rule deletes logs too early.", "Rule 6(1)(e) · keep logs ≥ 1 year", "Change the rule in Retention → Rules to keep logs at least 365 days."));
    if (lr.days != null) out.push(f("ok", `Logs go back ${lr.days >= 365 ? "over a year" : `${Math.floor(lr.days)} days`} (oldest ${d(lr.oldest)}).`, "Rule 6(1)(e)"));
    const lastSeal = v.seals?.slice(-1)[0], age = v.since ? (Date.now() - new Date(v.since)) / 864e5 : 0;
    out.push(lastSeal ? (lastSeal.intact === false ? f("warn", `The last daily seal (${lastSeal.day}) was made while records were broken.`, "s.8(5)", "Resolve the integrity problems.") : f("ok", `Sealed daily; last seal ${lastSeal.day}.`, "s.8(5)"))
      : age > 2 ? f("warn", "No daily seal has been made.", "s.8(5)", "Check that the service is running past midnight IST.") : f("ok", "The first daily seal is made after midnight IST.", "s.8(5)"));
    const sealOk = lastSeal ? lastSeal.intact !== false : age <= 2;
    return { score: (v.ok ? 60 : 0) + (lr.ok ? 30 : 0) + (sealOk ? 10 : 0), findings: out };
  }
  async function inventory() {
    if (!can("datamap:Read") && !can("readiness:Read")) return { score: null, why: "Needs permission to read the data map." };
    const d = (await api("/api/datamap")).last;
    if (!d) return { score: null, why: "The data map hasn't been built yet. Open Data map to run the first scan." };
    const st = d.stats, out = [];
    out.push(f("ok", `${st.personal_tables} tables hold personal data (${st.personal_columns} fields), used by ${st.personal_services} services; ${st.processors} recipients recorded. Scanned ${dt(d.at)}.`, "s.8(1) · accountability"));
    const top = d.gaps.filter((g) => ["critical", "high"].includes(g.severity));
    top.slice(0, 3).forEach((g) => out.push(f("bad", g.title, g.ref, g.fix)));
    const med = d.gaps.filter((g) => g.severity === "medium");
    if (med.length) out.push(f("warn", `${med.length} medium gap(s): ${[...new Set(med.map((g) => g.title.replace(/^.*?: /, "")))].slice(0, 2).join("; ")}${med.length > 2 ? "…" : ""}`, "DPDP Act ss.5, 8", "Open Data map → Gaps."));
    if (!d.gaps.length) out.push(f("ok", "Every personal data store has a purpose, a retention rule and no public access; every recipient has a contract.", "ss.5–8"));
    return { score: d.score, findings: out };
  }
  const AREAS = [["monitoring", "Security monitoring", monitoring], ["breach", "Breach readiness", breach], ["consent", "Consent & purpose", consent],
    ["retention", "Retention", retention], ["access", "Access control", access], ["logging", "Logging coverage", logging],
    ["exposure", "Public exposure", exposure], ["evidence", "Records & evidence", evidence], ["inventory", "Data inventory", inventory]];

  async function run() {
    S.busy = true; S.err = ""; render();
    const areas = [];
    for (const [key, label, fn] of AREAS) {
      S.step = label; render();
      try { const r = await fn({ logs: true, shop: true }); areas.push({ key, label, score: r.score == null ? null : Math.round(r.score), findings: r.findings || [], why: r.why }); }
      catch (e) { areas.push({ key, label, score: null, findings: [], why: `Couldn't assess: ${e.message}` }); }
    }
    const scored = areas.filter((a) => a.score != null), score = scored.length ? Math.round(scored.reduce((n, a) => n + a.score, 0) / scored.length) : 0;
    S.result = { score, grade: scored.length ? grade(score) : "–", areas, at: new Date().toISOString(), assessed: scored.length };
    S.busy = false; S.step = "";
    if (scored.length && can("readiness:Run")) {
      try { await api("/api/readiness", { method: "POST", body: JSON.stringify(S.result) }); } catch (e) { S.err = `Not saved: ${e.message}`; }
    }
    await loadHistory();
    render();
  }
  async function loadHistory() { try { S.history = (await api("/api/readiness")).history || []; } catch { S.history = []; } }

  function ring(score, g) {
    const r = 54, c = 2 * Math.PI * r, off = c * (1 - score / 100);
    return `<svg class="rd-ring g-${esc(g)}" viewBox="0 0 140 140" role="img" aria-label="Readiness ${score} out of 100, grade ${esc(g)}"><circle cx="70" cy="70" r="${r}" class="rd-track"/><circle cx="70" cy="70" r="${r}" class="rd-val" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 70 70)"/><text x="70" y="68" text-anchor="middle" class="rd-num">${score}</text><text x="70" y="90" text-anchor="middle" class="rd-of">of 100</text></svg>`;
  }
  function trend() {
    const h = S.history.slice(-12);
    if (h.length < 2) return "";
    const W = 260, H = 60, X = (i) => 6 + (i * (W - 12)) / (h.length - 1), Y = (v) => H - 6 - (v / 100) * (H - 12);
    return `<div class="rd-trend"><span class="muted">Score history</span><svg viewBox="0 0 ${W} ${H}"><path d="${h.map((e, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(e.score).toFixed(1)}`).join("")}" class="rd-tline"/>${h.map((e, i) => `<circle cx="${X(i)}" cy="${Y(e.score)}" r="3" class="rd-tdot"><title>${esc(dt(e.at))}: ${e.score} (${esc(e.grade)})</title></circle>`).join("")}</svg></div>`;
  }
  const tabs = () => `<div class="cp-tabs us-tabs" role="tablist">${[["score", "Readiness score"], ["exposure", "Public exposure"], ...(can("readiness:VerifyIntegrity") || can("readiness:ExportEvidence") ? [["evidence", "Evidence & audit"]] : [])].map(([k, l]) => `<button role="tab" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}" data-rtab="${k}">${esc(l)}</button>`).join("")}</div>`;
  const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", ok: "OK" };
  const KIND_LVL = { critical: "bad", high: "bad", medium: "warn", low: "warn", info: "ok", ok: "ok" };
  async function loadExposure() { try { S.exp = await api("/api/readiness/exposure"); } catch (e) { S.expErr = e.message; } }
  async function runExposure() {
    S.expBusy = true; S.expErr = ""; render();
    try { const last = await api("/api/readiness/exposure", { method: "POST" }); await loadExposure(); S.exp.last = last; }
    catch (e) { S.expErr = e.message; }
    S.expBusy = false; render();
  }
  function exposureHtml() {
    const v = S.exp || {}, x = v.last;
    const runBtn = can("readiness:Run") ? `<button class="btn primary" data-act="exp-run" ${S.expBusy ? "disabled" : ""}>${S.expBusy ? "Testing…" : x ? "Run the test again" : "Run the exposure test"}</button>` : "";
    const how = `<p class="muted">The test reads ${esc(ME?.client?.name ? ME.client.name + "’s" : "your")} customer database the way anyone on the internet can: with the public key the website already ships. It only reads, at most one row per table, and keeps only table and column names, never the values. It runs by itself once a day after the first run.</p>`;
    if (v.configured === false) return `<div class="panel cp-empty"><h3>Public exposure test</h3><p>Add the shop's public (anon) key to the server's settings as <code>SHOP_SUPABASE_ANON_KEY</code> to turn this on.</p></div>`;
    if (S.expBusy && !x) return `<div class="panel cp-empty"><h3>Testing what the public can read…</h3><p>Trying every table with the public key.</p></div>`;
    if (!x) return `<div class="panel cp-empty rd-empty"><h3>What can anyone on the internet read?</h3>${how}${S.expErr ? `<p class="cp-red">${esc(S.expErr)}</p>` : ""}${runBtn}</div>`;
    const c = x.counts, g = grade(x.score), leak = x.tables.filter((t) => t.state === "exposed"), safe = x.tables.filter((t) => t.state !== "exposed");
    const sevRank = { critical: 3, high: 2, medium: 1, info: 0 };
    leak.sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0));
    const state = (t) => t.state === "blocked" ? "Blocked for the public" : t.state === "protected" ? "Protected (rows hidden by policy)" : t.state === "empty" ? "Readable, but empty now" : t.state === "error" ? `Couldn't test (${esc(t.detail || "")})` : "";
    const hist = (v.history || []).slice(-12);
    return `
      <section class="panel rd-hero">
        ${ring(x.score, g)}
        <div class="rd-sum">
          <span class="us-plan">Rule 6 · reasonable security safeguards</span>
          <h3>${c.personal ? `${c.personal} table(s) leak personal data to the public` : c.exposed ? "No personal data is public; some tables are readable" : "Nothing in the customer database is readable by the public"}</h3>
          <p class="muted">Tested ${esc(dt(x.at))} by ${esc(x.by)} · ${c.tables} tables in ${x.seconds}s.</p>
          ${S.expErr ? `<p class="cp-red">${esc(S.expErr)}</p>` : ""}
          ${x.new_exposures?.length ? `<p class="cp-red"><b>New since the last test:</b> ${x.new_exposures.map(esc).join(", ")}</p>` : ""}
          <div class="rd-acts">${runBtn}<button class="btn ghost ai-ask" data-ask-ai="readiness">✦ Ask AI</button></div>
        </div>
        ${hist.length > 1 ? `<div class="rd-trend"><span class="muted">Exposure score history</span><svg viewBox="0 0 260 60">${(() => { const X = (i) => 6 + (i * 248) / (hist.length - 1), Y = (s) => 54 - (s / 100) * 48; return `<path class="rd-tline" d="${hist.map((e, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(e.score).toFixed(1)}`).join("")}"/>${hist.map((e, i) => `<circle class="rd-tdot" cx="${X(i)}" cy="${Y(e.score)}" r="3"><title>${esc(dt(e.at))}: ${e.score}</title></circle>`).join("")}`; })()}</svg></div>` : ""}
      </section>
      <div class="us-cards">
        <div class="panel us-card ex-card"><span class="us-clabel">Tables tested</span><b>${c.tables}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">Readable by the public</span><b class="${c.exposed ? "us-amber" : ""}">${c.exposed}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">With personal data</span><b class="${c.personal ? "us-red" : ""}">${c.personal}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">Blocked or protected</span><b>${c.blocked}</b></div>
      </div>
      ${leak.length ? `<section class="panel ex-sec"><h3>Readable with the public key</h3><div class="ex-list">${leak.map((t) => `
        <div class="ex-row">
          <div class="ex-head"><b class="ex-t">${esc(t.table)}</b><span class="ex-sev s-${esc(t.personal?.length ? t.severity : "info")}">${t.personal?.length ? SEV[t.severity] : "No personal data"}</span>
            <span class="muted">${t.rows_visible == null ? "rows readable" : `${num(t.rows_visible)} row(s) readable`} · ${t.columns} columns</span></div>
          ${t.personal?.length ? `<div class="ex-cols">${t.personal.map((p) => `<span class="ex-chip s-${esc(p.sensitivity)}" title="${esc(p.kind)}">${esc(p.column)} <small>${esc(p.kind)}</small></span>`).join("")}</div>` : ""}
          ${t.fix ? `<details class="ex-fix"><summary>How to fix (SQL for the shop's developer)</summary><pre>${esc(t.fix)}</pre><button class="btn ghost sm" data-act="exp-copy" data-sql="${esc(t.fix)}">Copy SQL</button></details>` : ""}
        </div>`).join("")}</div></section>` : ""}
      <section class="panel ex-sec"><h3>Settings checks</h3><ul class="rd-finds">${x.checks.map((k) => `<li class="${KIND_LVL[k.severity] || "ok"}"><i>${KIND_LVL[k.severity] === "ok" ? (k.severity === "info" ? "i" : "✓") : KIND_LVL[k.severity] === "warn" ? "!" : "✕"}</i><div><b>${esc(k.text)}</b>${k.fix ? (k.fix.includes("\n") || /^revoke|^update/.test(k.fix) ? `<details class="ex-fix"><summary>How to fix</summary><pre>${esc(k.fix)}</pre></details>` : `<span>${esc(k.fix)}</span>`) : ""}<small>${esc(SEV[k.severity] || "")}</small></div></li>`).join("")}</ul></section>
      <section class="panel ex-sec"><h3>Tables that passed <span class="muted">(${safe.length})</span></h3><div class="ex-pass">${safe.map((t) => `<span class="ex-chip s-ok" title="${esc(state(t))}">${esc(t.table)} <small>${esc(state(t))}</small></span>`).join("")}</div></section>
      <section class="panel ex-sec ex-note"><h3>How this works</h3>${how}<p class="muted">Not tested, on purpose: writing to tables and running database functions, because a test must never change the shop's data. It also can't see what one signed-in customer can read of another's data; that needs a test account. Fixes are shown for the shop's developer and never run from here.</p></section>`;
  }
  /* ---------- evidence & audit ---------- */
  const isoDay = (d) => new Date(d.getTime() + 330 * 6e4).toISOString().slice(0, 10);
  async function loadEvidence() { S.evErr = ""; try { S.ev = await api("/api/evidence"); } catch (e) { S.evErr = e.message; } }
  async function verifyNow() {
    S.evBusy = "verify"; render();
    try { const r = await api("/api/evidence/verify", { method: "POST" }); S.ev = { ...(S.ev || {}), ...r }; S.evErr = ""; } catch (e) { S.evErr = e.message; }
    S.evBusy = ""; render();
  }
  async function makePack() {
    const from = $("evFrom")?.value, to = $("evTo")?.value;
    const w = window.open("", "_blank");
    S.evBusy = "pack"; render();
    try {
      const pk = await api("/api/evidence/pack", { method: "POST", body: JSON.stringify({ from, to }) });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(pk, null, 1)], { type: "application/json" }));
      a.download = `evidence-pack-${(pk.client?.id || "client")}-${pk.from}-to-${pk.to}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      if (w) { w.document.open(); w.document.write(packReport(pk)); w.document.close(); }
      await loadEvidence();
    } catch (e) { S.evErr = e.message; if (w) w.close(); }
    S.evBusy = ""; render();
  }
  async function checkPack(file) {
    S.evBusy = "check"; S.check = null; render();
    try {
      let pk; try { pk = JSON.parse(await file.text()); } catch { throw new Error("That file isn't valid JSON."); }
      S.check = await api("/api/evidence/check", { method: "POST", body: JSON.stringify(pk) }); S.check.name = file.name;
    } catch (e) { S.check = { error: e.message, name: file.name }; }
    S.evBusy = ""; render();
  }
  function packReport(pk) {
    const t = (rows, head) => `<table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c ?? "–")}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${head.length}">None in this period.</td></tr>`}</tbody></table>`;
    const i = pk.integrity, lr = pk.log_retention || {}, ex = pk.exposure || {};
    return `<!doctype html><html><head><meta charset="utf-8"><title>DPDP evidence pack · ${esc(pk.client?.name)} · ${esc(pk.from)} to ${esc(pk.to)}</title><style>
      body{font:13px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#111;background:#fff;margin:32px auto;max-width:960px;padding:0 16px}
      h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:26px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
      table{width:100%;border-collapse:collapse;margin:6px 0}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #eee;vertical-align:top}th{background:#f6f6f6;font-weight:600}
      .mono{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all}.ok{color:#15803d}.bad{color:#b91c1c}.muted{color:#666}
      .box{border:1px solid #ddd;border-radius:8px;padding:10px 14px;margin:10px 0}@media print{body{margin:0}}</style></head><body>
      <h1>DPDP evidence pack: ${esc(pk.client?.name)}</h1>
      <p class="muted">Period ${esc(pk.from)} to ${esc(pk.to)} · generated ${esc(dt(pk.generated_at))} by ${esc(pk.generated_by)}</p>
      <div class="box"><b>Pack fingerprint (SHA-256)</b><div class="mono">${esc(pk.fingerprint)}</div><span class="muted">Recorded in the system's ledger. Anyone can check this pack later in Readiness → Evidence &amp; audit → Check a pack; any edit to the file changes the fingerprint.</span></div>
      <h2>Record integrity</h2>
      <p class="${i.ok ? "ok" : "bad"}"><b>${i.ok ? "Intact" : `${i.problem_count} problem(s) found`}</b> · checked ${esc(dt(i.checked_at))} · ledger since ${esc(dt(i.since))}: ${num(i.entries)} entries, ${num(i.audit_records)} activity records, ${i.files_tracked} record files.</p>
      ${i.problems?.length ? `<ul>${i.problems.map((p) => `<li class="bad">${esc(p.text)}</li>`).join("")}</ul>` : ""}
      <p>Ledger head: <span class="mono">${esc(i.head)}</span></p>
      ${t((pk.seals || []).map((x) => [x.day, x.head, x.intact === false ? "broken" : "intact"]), ["Daily seal", "Chain fingerprint", "State"])}
      <h2>Log retention (DPDP Rules 2025, Rule 6(1)(e))</h2>
      <p>Oldest log line: ${esc(lr.oldest ? dt(lr.oldest) : "–")}${lr.days != null ? ` (${Math.floor(lr.days)} days)` : ""}. ${lr.ok ? `<span class="ok">No rule deletes logs before one year.</span>` : `<span class="bad">${esc((lr.findings || []).join(" "))}</span>`}</p>
      ${t((lr.rules || []).map((r) => [r.id, r.name, `${Math.round(r.keep_days)} days`, r.action || "minimum (legal hold)", r.enabled ? "on" : "off"]), ["Rule", "Name", "Keep", "Action", "State"])}
      <h2>DPDP readiness score</h2>
      ${t((pk.readiness || []).map((r) => [dt(r.at), r.by, `${r.score} (${r.grade})`, (r.areas || []).map((a) => `${a.label}: ${a.score ?? "n/a"}`).join(" · ")]), ["When", "By", "Score", "Areas"])}
      <h2>Public exposure test (Rule 6(1)(b))</h2>
      ${ex.last ? `<p>Last test ${esc(dt(ex.last.at))}: score <b>${ex.last.score}</b>; ${ex.last.counts?.tables} tables tested, ${ex.last.counts?.exposed} readable by the public, ${ex.last.counts?.personal} with personal data.</p>
        ${t((ex.exposed_tables || []).map((x) => [x.table, x.severity, (x.personal || []).map((c) => c.column).join(", ") || "none", x.rows_visible]), ["Readable table", "Severity", "Personal columns", "Rows visible"])}` : "<p>Not run.</p>"}
      <h2>Breach register (s.8(6), Rule 7)</h2>
      <p class="muted">Clocks: ${esc(Object.entries(pk.breach?.clocks_hours || {}).map(([k, v]) => `${k.replace(/_/g, " ")} ${v} h`).join(" · "))}</p>
      ${t((pk.breach?.incidents || []).map((x) => [x.id, x.title, x.status, x.severity, dt(x.aware_at), Object.entries(x.obligations || {}).filter(([, v]) => v).map(([k, v]) => `${k}: ${dt(v?.at || v)}`).join("; ") || "–"]), ["Incident", "Title", "Status", "Severity", "Aware at", "Notifications"])}
      <h2>Policy records and their versions</h2>
      ${t(Object.entries(pk.records || {}).map(([k, r]) => [k, `v${r.current_version}`, `${dt(r.updated_at)} by ${r.updated_by}`, (r.versions_in_range || []).map((v) => `v${v.version} ${dt(v.updated_at)} ${v.updated_by}: ${v.change_note}`).join(" | ") || "no changes"]), ["Record", "Current", "Last change", "Changes in this period"])}
      <h2>Access control (s.8(5))</h2>
      ${t((pk.access?.users || []).map((u) => [u.email, u.root ? "root" : (u.policies || []).join(", ") || "none", u.active ? "active" : "disabled", dt(u.last_sign_in_at)]), ["User", "Policies", "State", "Last sign-in"])}
      ${t((pk.access?.policies || []).map((p) => [p.id, p.name, `v${p.version}`, (p.document?.Statement || []).map((st) => `${st.Effect} ${[].concat(st.Action).join(", ")}`).join(" · ")]), ["Policy", "Name", "Version", "Statements"])}
      <h2>Activity log</h2>
      <p>${num(pk.activity?.count)} events in this period${pk.activity?.count > 300 ? "; the latest 300 are listed here, all are in the JSON file" : ""}.</p>
      ${t((pk.activity?.events || []).slice(-300).reverse().map((e) => [dt(e.at), e.user, e.action, e.detail]), ["When", "Who", "Action", "Detail"])}
      <p class="muted" style="margin-top:28px">${esc(pk.about)} This report is an aid for review, not legal advice.</p>
      <script>setTimeout(()=>window.print(),400)<\/script></body></html>`;
  }
  const ruleText = (r) => `${r.id} ${r.name}: ${Math.round(r.keep_days)} days` + (r.action === "delete" ? ", then delete" : r.action ? `, then ${r.action}` : " minimum");
  function evidenceHtml() {
    const v = S.ev;
    if (!v) return S.evErr ? `<div class="panel cp-empty"><h3>Evidence & audit</h3><p class="cp-red">${esc(S.evErr)}</p></div>` : `<div class="panel cp-empty"><h3>Checking your records…</h3></div>`;
    const lr = v.log_retention || {}, seals = (v.seals || []).slice(-14).reverse(), lastSeal = (v.seals || []).slice(-1)[0];
    const today = new Date(), from = new Date(today.getTime() - 90 * 864e5);
    const c = S.check;
    return `
      <section class="panel rd-hero ev-hero">
        <div class="ev-badge ${v.ok ? "ok" : "bad"}" aria-hidden="true">${v.ok ? "✓" : "✕"}</div>
        <div class="rd-sum">
          <span class="us-plan">s.8(5) · Rule 6(1)(e) · tamper-evident records</span>
          <h3>${v.ok ? "Records are intact" : `${v.problem_count} record(s) were changed outside the system`}</h3>
          <p class="muted">Every activity record and every change to policies, retention rules, breach detectors and incidents, access, plan, billing, readiness and exposure results is fingerprinted into a hash chain since ${esc(dt(v.since))}. Checked ${esc(dt(v.checked_at))}.</p>
          ${S.evErr ? `<p class="cp-red">${esc(S.evErr)}</p>` : ""}
          <div class="ev-head"><span class="muted">Chain fingerprint</span><code title="${esc(v.head)}">${esc(v.head)}</code><button class="btn ghost sm" data-act="ev-copy" data-sql="${esc(v.head)}">Copy</button></div>
          <div class="rd-acts">${can("readiness:VerifyIntegrity") ? `<button class="btn primary" data-act="ev-verify" ${S.evBusy ? "disabled" : ""}>${S.evBusy === "verify" ? "Verifying…" : "Verify now"}</button>` : ""}</div>
        </div>
      </section>
      ${v.problems?.length ? `<section class="panel ex-sec"><h3>What changed</h3><ul class="rd-finds">${v.problems.map((p) => `<li class="bad"><i>✕</i><div><b>${esc(p.text)}</b>${p.at ? `<small>${esc(dt(p.at))}</small>` : ""}</div></li>`).join("")}</ul><p class="muted">Changes made outside the dashboard (by hand on the server) show up here. Find out who had access, and treat it as a possible breach.</p></section>` : ""}
      <div class="us-cards">
        <div class="panel us-card ex-card"><span class="us-clabel">Ledger entries</span><b>${num(v.entries)}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">Activity records</span><b>${num(v.audit_records)}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">Record files tracked</span><b>${num(v.files_tracked)}</b></div>
        <div class="panel us-card ex-card"><span class="us-clabel">Last daily seal</span><b class="ev-small">${lastSeal ? esc(lastSeal.day) : "after midnight IST"}</b></div>
      </div>
      <section class="panel ex-sec"><h3>Log retention <span class="muted">· Rule 6(1)(e): keep logs at least one year</span></h3>
        <ul class="rd-finds">
          <li class="${lr.ok ? "ok" : "bad"}"><i>${lr.ok ? "✓" : "✕"}</i><div><b>${lr.ok ? "No retention rule deletes logs before one year." : esc((lr.findings || []).join(" "))}</b>${!lr.ok ? `<span>Change it in Retention → Rules.</span>` : ""}<small>${esc((lr.rules || []).map(ruleText).join(" · ") || "No rule covers the logs.")}</small></div></li>
          <li class="ok"><i>i</i><div><b>${lr.oldest ? `Oldest log line: ${esc(dt(lr.oldest))} (${Math.floor(lr.days)} days back).` : esc(lr.error || "No log lines yet.")}</b>${lr.days != null && lr.days < 365 ? `<span>Logging began less than a year ago, so a full year can't be shown yet; nothing is set to delete them early.</span>` : ""}</div></li>
        </ul></section>
      ${can("readiness:ExportEvidence") ? `<section class="panel ex-sec"><h3>Evidence pack</h3>
        <p class="muted">One file for an auditor or the Data Protection Board: integrity and seals, log retention, readiness scores, the exposure test, the breach register, policy versions, access, and the activity log for the period. It downloads as JSON and opens as a printable report (save it as PDF). Its fingerprint is recorded in the ledger.</p>
        <div class="ev-form"><label>From <input type="date" id="evFrom" value="${isoDay(from)}" max="${isoDay(today)}"></label><label>To <input type="date" id="evTo" value="${isoDay(today)}" max="${isoDay(today)}"></label>
          <button class="btn primary" data-act="ev-pack" ${S.evBusy ? "disabled" : ""}>${S.evBusy === "pack" ? "Building…" : "Create evidence pack"}</button></div>
        ${(v.exports || []).length ? `<details class="ex-fix"><summary>Packs created (${v.exports.length})</summary><table class="ev-table"><thead><tr><th>When</th><th>By</th><th>Period</th><th>Fingerprint</th></tr></thead><tbody>${v.exports.slice().reverse().map((x) => `<tr><td>${esc(dt(x.at))}</td><td>${esc(x.by)}</td><td>${esc(x.from)} → ${esc(x.to)}</td><td><code>${esc(x.sha.slice(0, 16))}…</code></td></tr>`).join("")}</tbody></table></details>` : ""}
      </section>` : ""}
      ${can("readiness:VerifyIntegrity") ? `<section class="panel ex-sec"><h3>Check a pack</h3>
        <p class="muted">Received a pack and want to know it's genuine and unedited? Choose the JSON file.</p>
        <label class="btn ghost ev-file">${S.evBusy === "check" ? "Checking…" : "Choose a pack file"}<input type="file" id="evCheck" accept=".json,application/json" hidden></label>
        ${c ? (c.error ? `<p class="cp-red">${esc(c.name)}: ${esc(c.error)}</p>` : `<ul class="rd-finds ev-check">
          <li class="${c.unchanged ? "ok" : "bad"}"><i>${c.unchanged ? "✓" : "✕"}</i><div><b>${c.unchanged ? "Unchanged since it was created." : "The file was edited after it was created."}</b><small>${esc(c.name)} · ${esc(c.client || "")} · ${esc(c.from)} → ${esc(c.to)}</small></div></li>
          <li class="${c.recorded ? "ok" : "bad"}"><i>${c.recorded ? "✓" : "✕"}</i><div><b>${c.recorded ? `Issued by this system on ${esc(dt(c.recorded_at))} by ${esc(c.recorded_by)}.` : "This system has no record of issuing this pack."}</b></div></li></ul>`) : ""}
      </section>` : ""}
      <section class="panel ex-sec"><h3>Daily seals</h3>
        ${seals.length ? `<table class="ev-table"><thead><tr><th>Day</th><th>Chain fingerprint at the end of the day</th><th>State</th></tr></thead><tbody>${seals.map((x) => `<tr><td>${esc(x.day)}</td><td><code>${esc(x.head)}</code></td><td>${x.intact === false ? `<span class="cp-red">broken</span>` : "intact"}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">The first seal is made after midnight IST. Each seal fixes the day's records; a later rewrite of that day no longer matches.</p>`}
      </section>
      <section class="panel ex-sec ex-note"><h3>How this works</h3>
        <p class="muted">Each record gets a SHA-256 fingerprint, and each ledger entry includes the previous entry's fingerprint, so changing, deleting or reordering any past record breaks the chain from that point. Verification re-reads the activity log and the record files and compares them with the ledger. It also runs every day before the seal, and a break is written to the activity log.</p>
        <p class="muted">To guard against someone rewriting the whole ledger, keep a copy of the chain fingerprint outside this server: it's printed in every evidence pack, or copy it above once a month. Meter totals (usage) aren't part of the chain, because they change every few seconds.</p></section>`;
  }
  function render() {
    const body = $("rdBody"); if (!body) return;
    if (S.tab === "evidence") { body.innerHTML = tabs() + evidenceHtml(); return; }
    if (S.tab === "exposure") { body.innerHTML = tabs() + exposureHtml(); return; }
    const r = S.result;
    if (S.busy) { body.innerHTML = tabs() + `<div class="panel cp-empty"><h3>Checking your compliance…</h3><p>${esc(S.step)}</p></div>`; return; }
    if (!r) {
      const last = S.history.slice(-1)[0];
      body.innerHTML = tabs() + `<div class="panel cp-empty rd-empty"><h3>DPDP readiness score</h3><p>${last ? `Last score <b>${last.score}</b> (${esc(last.grade)}) on ${esc(dt(last.at))}. Run it again to see the findings.` : "See where your company stands on the DPDP Act in about a minute."}</p>
        ${can("readiness:Run") ? `<button class="btn primary" data-act="run">${last ? "Run again" : "Run my readiness check"}</button>` : ""}${trend()}</div>`;
      return;
    }
    body.innerHTML = tabs() + `
      <section class="panel rd-hero">
        ${r.assessed ? ring(r.score, r.grade) : `<div class="rd-na">Not enough data to score yet.</div>`}
        <div class="rd-sum">
          <span class="us-plan">${esc(ME?.client?.name || "")}</span>
          <h3>${r.assessed ? `Grade ${esc(r.grade)}: ${r.score >= 85 ? "well prepared" : r.score >= 70 ? "mostly ready, a few gaps" : r.score >= 55 ? "real gaps to close" : "significant work needed"}` : "Not enough data to score yet"}</h3>
          <p class="muted">${esc(dt(r.at))} · ${r.assessed} of ${r.areas.length} areas assessed. Each finding cites the DPDP Act 2023 or the DPDP Rules 2025. This is an aid for your review, not legal advice.</p>
          ${S.err ? `<p class="cp-red">${esc(S.err)}</p>` : ""}
          <div class="rd-acts"><button class="btn primary" data-act="run">Run again</button><button class="btn ghost" data-act="print">Print / save as PDF</button><button class="btn ghost ai-ask" data-ask-ai="readiness">✦ Ask AI</button></div>
        </div>
        ${trend()}
      </section>
      <div class="rd-areas">${r.areas.map((a) => `<section class="panel rd-area ${a.score == null ? "na" : `g-${grade(a.score)}`}">
        <div class="rd-ahead"><h3>${esc(a.label)}</h3>${a.score == null ? `<span class="rd-pill na">Not assessed</span>` : `<span class="rd-pill g-${grade(a.score)}">${a.score}</span>`}</div>
        ${a.score != null ? `<span class="rd-bar"><i style="width:${a.score}%"></i></span>` : ""}
        ${a.score == null ? `<p class="muted">${esc(a.why || "")}</p>` : `<ul class="rd-finds">${a.findings.map((x) => `<li class="${x.level}"><i>${x.level === "ok" ? "✓" : x.level === "warn" ? "!" : "✕"}</i><div><b>${esc(x.text)}</b>${x.fix ? `<span>${esc(x.fix)}</span>` : ""}<small>${esc(x.ref)}</small></div></li>`).join("")}</ul>`}
      </section>`).join("")}</div>`;
  }
  function bind() {
    $("rdBody").addEventListener("change", (e) => { if (e.target.id === "evCheck" && e.target.files[0]) checkPack(e.target.files[0]); });
    $("rdBody").addEventListener("click", (e) => {
      const t = e.target.closest("[data-rtab]");
      if (t) { S.tab = t.dataset.rtab; render(); if (S.tab === "exposure" && !S.exp) loadExposure().then(render); if (S.tab === "evidence") loadEvidence().then(render); return; }
      const b = e.target.closest("[data-act]"); if (!b) return;
      if (b.dataset.act === "exp-run") return runExposure();
      if (b.dataset.act === "ev-verify") return verifyNow();
      if (b.dataset.act === "ev-pack") return makePack();
      if (b.dataset.act === "ev-copy") { navigator.clipboard?.writeText(b.dataset.sql).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500); }); return; }
      if (b.dataset.act === "exp-copy") { navigator.clipboard?.writeText(b.dataset.sql).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy SQL"), 1500); }); return; }
      if (b.dataset.act === "run") return run();
      if (b.dataset.act === "print") return window.print();
    });
  }
  return {
    async show() { if (!S.started) { S.started = true; bind(); } if (!S.history.length) await loadHistory(); render(); },
    async runAndOpen() { show("readiness"); await run(); },
    aiItem() {
      const r = S.result, x = S.exp?.last;
      if (!r && x) return { name: `Public exposure test ${x.score}/100`, question: "Explain my public exposure test: what is at risk, what to fix first, and how.",
        text: JSON.stringify({ score: x.score, at: x.at, counts: x.counts, readable_tables: x.tables.filter((t) => t.state === "exposed").map((t) => ({ table: t.table, severity: t.severity, personal_columns: (t.personal || []).map((p) => `${p.column} (${p.kind})`) })), checks: x.checks.map((c) => `${c.severity}: ${c.text}`) }, null, 1) };
      if (!r) return null;
      return { name: `DPDP readiness ${r.score}/100 (${r.grade})`, question: "Explain my DPDP readiness score: what matters most, what to fix first, and how to raise the score.",
        text: JSON.stringify({ public_exposure_test: S.exp?.last ? { score: S.exp.last.score, at: S.exp.last.at, readable_tables: S.exp.last.tables.filter((t) => t.state === "exposed").map((t) => ({ table: t.table, severity: t.severity, personal_columns: (t.personal || []).map((p) => `${p.column} (${p.kind})`) })), checks: S.exp.last.checks.map((c) => `${c.severity}: ${c.text}`) } : "not run",
          score: r.score, grade: r.grade, areas: r.areas.map((a) => ({ area: a.label, score: a.score, not_assessed_because: a.why, findings: a.findings.map((x) => `${x.level}: ${x.text} [${x.ref}]${x.fix ? ` Fix: ${x.fix}` : ""}`) })) }, null, 1) };
    },
  };
})();
