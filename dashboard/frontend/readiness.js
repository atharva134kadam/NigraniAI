/* DPDP readiness score: a 0-100 score and grade built from eight areas, each scored from what the
   dashboard already measures (breach detectors and the anomaly model, the breach register and its
   clocks, consent coverage, retention deadlines, access policies, log coverage, the evidence ledger,
   the data map). Every finding cites the law and gives a fix. Areas the person may not read are
   "not assessed", not failed. Results are saved with a score history. The page ranks open findings
   by how much each could raise the score ("Fix these first") and links each area to its section.
   "Records & evidence" comes from the server's hash-chained ledger; the Evidence & audit section
   (evidence.js) verifies it, shows the chain and the daily seals, and builds / checks evidence packs.
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

  const S = { result: null, history: [], busy: false, err: "", started: false, step: "", done: [], open: new Set() };

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
    if (!d.gaps.length) out.push(f("ok", "Every personal data store has a purpose and a retention rule; every recipient has a contract.", "ss.5–8"));
    return { score: d.score, findings: out };
  }
  // key, label, scoring function, law, the section that fixes it, its icon
  const AREAS = [
    ["monitoring", "Security monitoring", monitoring, "s.8(5) · Rule 6(1)(c)", "breach", "i-shield"],
    ["breach", "Breach readiness", breach, "s.8(6) · Rule 7", "breach", "i-breach"],
    ["consent", "Consent & purpose", consent, "ss.5–7", "consent", "i-consent"],
    ["retention", "Retention", retention, "s.8(7) · Rule 8", "retention", "i-retention"],
    ["access", "Access control", access, "s.8(5) · least privilege", "iam", "i-key"],
    ["logging", "Logging coverage", logging, "Rule 6(1)(e)", "telemetry", "i-logs"],
    ["evidence", "Records & evidence", evidence, "s.8(5) · Rule 6(1)(e)", "evidence", "i-ledger"],
    ["inventory", "Data inventory", inventory, "s.8(1) · accountability", "datamap", "i-map"],
  ];
  const META = Object.fromEntries(AREAS.map(([k, l, , law, view, icon]) => [k, { label: l, law, view, icon }]));
  const VIEW_NAME = { breach: "Breach Response", consent: "Consent & Purpose", retention: "Retention", iam: "Access (IAM)", telemetry: "Log Telemetry", evidence: "Evidence & audit", datamap: "Data map" };
  const VERDICT = (s) => (s >= 85 ? "Well prepared" : s >= 70 ? "Mostly ready, a few gaps" : s >= 55 ? "Real gaps to close" : s >= 40 ? "Significant work needed" : "Not ready yet");

  async function run() {
    S.busy = true; S.err = ""; S.done = []; render();
    const areas = [];
    for (const [key, label, fn] of AREAS) {
      S.step = key; render();
      try { const r = await fn({ logs: true, shop: true }); areas.push({ key, label, score: r.score == null ? null : Math.round(r.score), findings: r.findings || [], why: r.why }); }
      catch (e) { areas.push({ key, label, score: null, findings: [], why: `Couldn't assess: ${e.message}` }); }
      S.done.push(key);
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

  /* ---------- drawing ---------- */
  function ring(score, g, size = "lg") {
    const big = size === "lg", r = big ? 58 : 20, w = big ? 12 : 5, box = big ? 140 : 52, c = 2 * Math.PI * r, off = c * (1 - (score || 0) / 100), mid = box / 2;
    return `<svg class="rd2-ring ${size} g-${esc(g)}" viewBox="0 0 ${box} ${box}" role="img" aria-label="${score} out of 100"><circle cx="${mid}" cy="${mid}" r="${r}" class="rd2-track" stroke-width="${w}"/>
      <circle cx="${mid}" cy="${mid}" r="${r}" class="rd2-val" stroke-width="${w}" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 ${mid} ${mid})" style="--c:${c.toFixed(1)}"/>
      ${big ? `<text x="${mid}" y="${mid + 4}" text-anchor="middle" class="rd2-num">${score}</text><text x="${mid}" y="${mid + 26}" text-anchor="middle" class="rd2-of">of 100</text>` : `<text x="${mid}" y="${mid + 5}" text-anchor="middle" class="rd2-snum">${score}</text>`}</svg>`;
  }
  // Score history with the grade bands behind it.
  function history() {
    const h = S.history.slice(-20);
    if (h.length < 2) return "";
    const W = 640, H = 170, L = 34, R = 10, T = 10, B = 24, X = (i) => L + (i * (W - L - R)) / (h.length - 1), Y = (v) => T + (1 - v / 100) * (H - T - B);
    const bands = [[85, 100, "A"], [70, 85, "B"], [55, 70, "C"], [40, 55, "D"], [0, 40, "E"]];
    const line = h.map((e, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(e.score).toFixed(1)}`).join("");
    const area = `${line}L${X(h.length - 1).toFixed(1)},${Y(0)}L${X(0).toFixed(1)},${Y(0)}Z`;
    const lab = (e) => new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short" }).format(new Date(e.at));
    return `<section class="panel rd2-card"><div class="rd2-ch"><h3>Score history</h3><span class="muted">last ${h.length} runs · shaded by grade</span></div>
      <svg class="rd2-hist" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
        ${bands.map(([lo, hi, g]) => `<rect x="${L}" y="${Y(hi)}" width="${W - L - R}" height="${Y(lo) - Y(hi)}" class="rd2-band g-${g}"/><text x="${L - 8}" y="${(Y(hi) + Y(lo)) / 2 + 4}" text-anchor="end" class="rd2-bl">${g}</text>`).join("")}
        <path d="${area}" class="rd2-harea"/><path d="${line}" class="rd2-hline"/>
        ${h.map((e, i) => `<circle cx="${X(i)}" cy="${Y(e.score)}" r="4" class="rd2-hdot"><title>${esc(dt(e.at))}: ${e.score} (${esc(e.grade)}) by ${esc(e.by || "")}</title></circle>`).join("")}
        <text x="${X(0)}" y="${H - 6}" class="rd2-bl">${esc(lab(h[0]))}</text><text x="${X(h.length - 1)}" y="${H - 6}" text-anchor="end" class="rd2-bl">${esc(lab(h[h.length - 1]))}</text>
      </svg></section>`;
  }

  /* ---------- page parts ---------- */
  // Every open finding, with the most the overall score could rise if it were fixed.
  function fixes(r) {
    const n = r.assessed || 1, out = [];
    for (const a of r.areas) {
      if (a.score == null) continue;
      const open = a.findings.filter((x) => x.level !== "ok");
      open.forEach((x) => out.push({ ...x, area: a.key, gain: (100 - a.score) / n / open.length }));
    }
    return out.sort((p, q) => (q.level === "bad") - (p.level === "bad") || q.gain - p.gain);   // problems first, then the biggest gain
  }
  const pts = (g) => (g >= 0.95 ? `+${Math.round(g)}` : g > 0.05 ? `+${g.toFixed(1)}` : "");

  function hero(r, prev) {
    const delta = prev && r.assessed ? r.score - prev.score : null, counts = { bad: 0, warn: 0, ok: 0 };
    r.areas.forEach((a) => (Array.isArray(a.findings) ? a.findings : []).forEach((x) => (counts[x.level] = (counts[x.level] || 0) + 1)));
    return `<section class="panel dm-hero rd2-hero g-${esc(r.grade)}">
      <div class="dm-htext">
        <div class="dm-erow"><span class="dm-eyebrow">DPDP Act 2023 · DPDP Rules 2025</span><span class="rd2-gpill g-${esc(r.grade)}">Grade ${esc(r.grade)}</span></div>
        <h2>${r.assessed ? esc(VERDICT(r.score)) : "Not enough data to score yet"}</h2>
        <p class="muted">${r.assessed} of ${r.areas.length} areas assessed ${r.at ? `· checked ${esc(dt(r.at))}` : ""}. Each finding cites the Act or the Rules and says how to fix it. An aid for your review, not legal advice.</p>
        ${S.err ? `<p class="cp-red">${esc(S.err)}</p>` : ""}
        ${r.findings !== false ? `<div class="rd2-counts"><span class="bad"><i>✕</i>${counts.bad} to fix</span><span class="warn"><i>!</i>${counts.warn} to improve</span><span class="ok"><i>✓</i>${counts.ok} passing</span></div>` : ""}
        <div class="dm-hacts">
          ${can("readiness:Run") ? `<button class="btn primary" data-act="run">${r.findings === false ? "Run the check" : "Run again"}</button>` : ""}
          ${r.findings !== false ? `<button class="btn ghost" data-act="print">Print / save as PDF</button><button class="btn ghost ai-ask" data-ask-ai="readiness">✦ Ask AI</button>` : ""}
        </div>
      </div>
      <div class="rd2-score">
        ${r.assessed ? ring(r.score, r.grade) : `<div class="rd-na">–</div>`}
        ${delta != null ? `<span class="rd2-delta ${delta > 0 ? "up" : delta < 0 ? "down" : ""}">${delta > 0 ? "▲" : delta < 0 ? "▼" : "•"} ${delta > 0 ? "+" : ""}${delta} since ${esc(dt(prev.at))}</span>` : `<span class="muted rd2-delta">first run</span>`}
      </div>
    </section>`;
  }

  function fixFirst(r) {
    const list = fixes(r).slice(0, 6);
    if (!list.length) return `<section class="panel rd2-card rd2-clear"><span class="rd2-big">✓</span><div><h3>Nothing to fix</h3><p class="muted">Every check passed. Run it again after big changes, or monthly.</p></div></section>`;
    return `<section class="panel rd2-card"><div class="rd2-ch"><h3>Fix these first</h3><span class="muted">ordered by severity and by how much each could raise your score</span></div>
      <ol class="rd2-fixes">${list.map((x, i) => { const m = META[x.area]; return `<li class="${x.level}">
        <span class="rd2-fi"><svg><use href="#${m.icon}"/></svg></span>
        <div class="rd2-ft"><b>${esc(x.text)}</b>${x.fix ? `<span>${esc(x.fix)}</span>` : ""}<small>${esc(m.label)} · ${esc(x.ref)}</small></div>
        <div class="rd2-fa">${pts(x.gain) ? `<span class="rd2-gain" title="Most the overall score could rise">${pts(x.gain)} pts</span>` : ""}
          <button class="btn ghost sm" data-act="go" data-view="${m.view}">Open ${esc(VIEW_NAME[m.view])}</button>
          <button class="btn ghost sm ai-ask" data-ask-ai="readiness:fix:${i}">✦ Ask AI</button></div></li>`; }).join("")}</ol></section>`;
  }

  function areaCard(a) {
    const m = META[a.key] || { label: a.label, law: "", view: null, icon: "i-gauge" }, g = a.score == null ? "na" : grade(a.score);
    const list = Array.isArray(a.findings) ? a.findings : [], bad = list.filter((x) => x.level !== "ok"), good = list.filter((x) => x.level === "ok");
    const li = (x) => `<li class="${x.level}"><i>${x.level === "ok" ? "✓" : x.level === "warn" ? "!" : "✕"}</i><div><b>${esc(x.text)}</b>${x.fix ? `<span>${esc(x.fix)}</span>` : ""}<small>${esc(x.ref)}</small></div></li>`;
    const open = S.open.has(a.key);
    return `<section class="panel rd2-area g-${g}">
      <div class="rd2-ahead">
        <span class="rd2-aicon"><svg><use href="#${m.icon}"/></svg></span>
        <div class="rd2-at"><h3>${esc(m.label)}</h3><small class="muted">${esc(m.law)}</small></div>
        ${a.score == null ? `<span class="rd-pill na">Not assessed</span>` : ring(a.score, g, "sm")}
      </div>
      ${a.score == null ? `<p class="muted rd2-why">${esc(a.why || "")}</p>` : Array.isArray(a.findings) ? `
        <div class="rd2-astat">${bad.length ? `<span class="${bad.some((x) => x.level === "bad") ? "bad" : "warn"}">${bad.length} to work on</span>` : `<span class="ok">All checks passed</span>`}<span class="muted">${good.length} passed</span></div>
        ${bad.length ? `<ul class="rd-finds">${bad.map(li).join("")}</ul>` : ""}
        ${good.length ? `<button class="rd2-more" data-act="toggle" data-area="${esc(a.key)}">${open ? "Hide" : "Show"} ${good.length} passed check${good.length > 1 ? "s" : ""}</button>${open ? `<ul class="rd-finds rd2-passed">${good.map(li).join("")}</ul>` : ""}` : ""}`
        : `<p class="muted rd2-why">${num(a.findings || 0)} finding(s) last time. Run again to see them.</p>`}
      ${m.view ? `<button class="rd2-link" data-act="go" data-view="${m.view}">Open ${esc(VIEW_NAME[m.view])} →</button>` : ""}
    </section>`;
  }

  function running() {
    return `<section class="panel dm-hero rd2-hero"><div class="dm-htext"><div class="dm-erow"><span class="dm-eyebrow">DPDP Act 2023 · DPDP Rules 2025</span><span class="dm-live">Checking</span></div>
      <h2>Checking your compliance…</h2><p class="muted">Each area reads live data from its own section. This takes a few seconds.</p>
      <ol class="rd2-steps">${AREAS.map(([k, l, , , , icon]) => `<li class="${S.done.includes(k) ? "done" : S.step === k ? "now" : ""}"><span><svg><use href="#${icon}"/></svg></span>${esc(l)}<i>${S.done.includes(k) ? "✓" : S.step === k ? "…" : ""}</i></li>`).join("")}</ol></div></section>`;
  }

  function render() {
    const body = $("rdBody"); if (!body) return;
    if (S.busy) { body.innerHTML = running(); return; }
    let r = S.result, prev = S.history.length > 1 ? S.history[S.history.length - 2] : null;
    if (!r) {
      const last = S.history.slice(-1)[0];
      prev = S.history.length > 1 ? S.history[S.history.length - 2] : null;
      if (!last) {
        body.innerHTML = `<section class="panel dm-hero rd2-hero"><div class="dm-htext"><div class="dm-erow"><span class="dm-eyebrow">DPDP Act 2023 · DPDP Rules 2025</span></div>
          <h2>How ready are you for a DPDP audit?</h2><p class="muted">One score across ${AREAS.length} areas, built from what NigraniAI already measures. Every finding cites the law and says how to fix it.</p>
          <div class="rd2-chips">${AREAS.map(([, l, , , , icon]) => `<span><svg><use href="#${icon}"/></svg>${esc(l)}</span>`).join("")}</div>
          <div class="dm-hacts">${can("readiness:Run") ? `<button class="btn primary" data-act="run">Run my readiness check</button>` : `<p class="muted">Ask someone with permission to run it.</p>`}</div></div></section>`;
        return;
      }
      // The last saved result: scores only (findings are not stored), until it is run again.
      r = { ...last, findings: false, assessed: (last.areas || []).filter((a) => a.score != null).length,
        areas: AREAS.map(([k, l]) => { const a = (last.areas || []).find((x) => x.key === k); return { key: k, label: l, score: a ? a.score : null, findings: a ? a.findings : 0, why: a ? "" : "Not part of that run." }; }) };
      body.innerHTML = hero(r, prev) + `<p class="rd2-note muted">Showing the last saved score. Run it again to see every finding and what to fix first.</p><div class="rd2-areas">${r.areas.map(areaCard).join("")}</div>${history()}`;
      return;
    }
    body.innerHTML = hero(r, prev) + fixFirst(r) + `<div class="rd2-ch rd2-sect"><h3>All areas</h3><span class="muted">${r.assessed} assessed · the overall score is their average</span></div><div class="rd2-areas">${r.areas.map(areaCard).join("")}</div>` + history();
  }
  function bind() {
    $("rdBody").addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      if (b.dataset.act === "run") return run();
      if (b.dataset.act === "print") return window.print();
      if (b.dataset.act === "go") return show(b.dataset.view);
      if (b.dataset.act === "toggle") { const k = b.dataset.area; S.open.has(k) ? S.open.delete(k) : S.open.add(k); render(); }
    });
  }
  return {
    async show() { if (!S.started) { S.started = true; bind(); } if (!S.history.length) await loadHistory(); render(); },
    async runAndOpen() { show("readiness"); await run(); },
    aiItem(arg = "") {
      const r = S.result; if (!r) return null;
      const all = { score: r.score, grade: r.grade, areas: r.areas.map((a) => ({ area: a.label, score: a.score, not_assessed_because: a.why, findings: a.findings.map((x) => `${x.level}: ${x.text} [${x.ref}]${x.fix ? ` Fix: ${x.fix}` : ""}`) })) };
      const [what, i] = arg.split(":");
      if (what === "fix") {
        const x = fixes(r).slice(0, 6)[Number(i)]; if (!x) return null;
        return { name: `Readiness fix: ${META[x.area].label}`, question: `How exactly do I fix this, step by step, and why does the DPDP law require it? "${x.text}"`,
          text: JSON.stringify({ finding: { area: META[x.area].label, level: x.level, text: x.text, law: x.ref, suggested_fix: x.fix, could_raise_score_by: Number(x.gain.toFixed(1)) }, readiness: all }, null, 1) };
      }
      return { name: `DPDP readiness ${r.score}/100 (${r.grade})`, question: "Explain my DPDP readiness score: what matters most, what to fix first, and how to raise the score.", text: JSON.stringify(all, null, 1) };
    },
  };
})();
