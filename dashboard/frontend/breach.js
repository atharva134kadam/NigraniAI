/* Breach Response — DPDP Act s.8(6) and DPDP Rules 2025, Rule 7.
   Detectors (versioned, editable) scan the NigraniAI logs → signals to triage →
   incidents in a breach register with the response clocks (CERT-In 6 h, Board
   "without delay", customers "without delay", Board detailed report 72 h) →
   notices drafted from the incident record → audit trail of every change.
   Incidents can also be reported by hand (lost laptop, email to the wrong person…).
   Detection runs in consent_service with the signed-in user's own token; evidence
   log lines are read directly from NigraniAI. Nothing in either database changes.
   Uses session / refreshSession / authedFetch / DASH_URL / DB_SCHEMA from app.js. */
const Breach = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const IST = "Asia/Kolkata";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const plural = (n, one, many = one + "s") => `${num(n)} ${n === 1 ? one : many}`;
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
  const fmt = (o) => new Intl.DateTimeFormat("en-IN", { timeZone: IST, ...o });
  const F_DT = fmt({ day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const F_SHORT = fmt({ day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  const F_TIME = fmt({ hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const up = (s) => s.replace(/\b(am|pm)\b/i, (m) => m.toUpperCase());
  const ist = (v) => (v ? up(F_DT.format(new Date(v))) : "–");
  const short = (v) => (v ? up(F_SHORT.format(new Date(v))) : "–");
  // <input type="datetime-local"> works in local wall time; the dashboard shows IST.
  const toLocalInput = (v) => {
    if (!v) return "";
    const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone: IST, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(v)).map((x) => [x.type, x.value]));
    return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
  };
  const fromLocalInput = (s) => (s ? new Date(`${s}:00+05:30`).toISOString() : null);
  function span(ms) {
    const a = Math.abs(ms), d = Math.floor(a / 864e5), h = Math.floor((a % 864e5) / 36e5), m = Math.floor((a % 36e5) / 6e4);
    if (d >= 1) return `${d} d${h ? ` ${h} h` : ""}`;
    if (h >= 1) return `${h} h${m ? ` ${m} min` : ""}`;
    return `${Math.max(1, m)} min`;
  }

  /* ---------- vocabulary ---------- */
  const CATS = {
    confidentiality: { label: "Confidentiality", desc: "Disclosed, accessed or copied without authorisation" },
    integrity: { label: "Integrity", desc: "Altered or destroyed without authorisation" },
    availability: { label: "Availability", desc: "Lost, or customers lost access to it" },
  };
  const SEVS = ["low", "medium", "high", "critical"];
  const STATUS = {
    suspected: ["warn", "Suspected", "Assess quickly: is personal data involved?"],
    confirmed: ["bad", "Confirmed", "Personal data breach confirmed. Notify and contain."],
    contained: ["hold", "Contained", "The breach is stopped. Finish notices and the report."],
    closed: ["ok", "Closed", "All obligations met and lessons recorded."],
    not_breach: ["off", "Not a breach", "Assessed: no personal data breach."],
  };
  const FLOW = ["suspected", "confirmed", "contained", "closed"];
  const OPEN = (i) => i.status !== "closed" && i.status !== "not_breach";
  const DATA_CATS = { identity: "Identity (name, account)", contact: "Contact (email, phone)", address: "Addresses", financial: "Payment / financial", orders: "Order history", credentials: "Passwords, tokens", usage: "Usage and device data", consent: "Consent records", other: "Other" };
  const OBL = {
    cert_in: { label: "CERT-In report", law: "CERT-In Directions 2022 · within 6 hours", hours: "cert_in_hours", who: "CERT-In (incident@cert-in.org.in)" },
    board_initial: { label: "Initial intimation to the Board", law: "Rule 7(2)(a) · without delay", hours: "board_initial_hours", who: "Data Protection Board of India" },
    principals: { label: "Notice to affected customers", law: "Rule 7(1) · without delay", hours: "principals_hours", who: "each affected Data Principal" },
    board_report: { label: "Detailed report to the Board", law: "Rule 7(2)(b) · within 72 hours", hours: "board_report_hours", who: "Data Protection Board of India" },
  };
  const OPS = { eq: "is", neq: "is not", gt: "is above", gte: "is at least", lt: "is below", lte: "is at most", in: "is one of", is: "is", has: "contains" };
  const FIELDS = {
    activity_logs: { service: "text", level: "text", kind: "text", event: "text", route: "text", http_method: "text", http_status: "int", actor_type: "text", actor_ref: "text", data_category: "text", severity: "text", purpose: "text", consent_status: "text", risk_indicators: "array", masked_pii_types: "array" },
    database_logs: { service: "text", level: "text", event: "text", operation: "text", db_table: "text", data_category: "text", personal_data: "bool", row_count: "int", status: "text", sql_state: "text", slow: "bool", duration_ms: "int" },
  };
  const FIELD_LABEL = { http_status: "HTTP status", risk_indicators: "risk indicators", masked_pii_types: "masked PII types", actor_ref: "actor", actor_type: "actor type", db_table: "table", personal_data: "personal data", row_count: "rows read", sql_state: "SQL state", duration_ms: "duration (ms)", data_category: "data category", consent_status: "consent status", http_method: "HTTP method" };
  const fl = (f) => FIELD_LABEL[f] || f.replace(/_/g, " ");
  const SOURCE_LABEL = { activity_logs: "application logs", database_logs: "database logs" };
  const TEMPLATES = {
    failed_logins: { label: "Failed sign-ins", desc: "Bursts of rejected sign-ins (password guessing).", d: { name: "Burst of failed sign-ins", category: "confidentiality", severity: "high", source: "activity_logs", match: [{ field: "http_status", op: "eq", value: "401" }], measure: "count", threshold: 20, window: { n: 10, unit: "minutes" }, group_by: "service" } },
    errors: { label: "Errors and outages", desc: "Server errors that may cut off access to personal data.", d: { name: "Service errors", category: "availability", severity: "medium", source: "activity_logs", match: [{ field: "http_status", op: "gte", value: "500" }], measure: "count", threshold: 5, window: { n: 15, unit: "minutes" }, group_by: "service" } },
    pii_logs: { label: "Personal data in logs", desc: "PII patterns caught by the log masker.", d: { name: "Personal data in logs", category: "confidentiality", severity: "medium", source: "activity_logs", match: [{ field: "risk_indicators", op: "has", value: "pii_pattern_masked" }], measure: "count", threshold: 1, window: { n: 1, unit: "days" }, group_by: "service" } },
    bulk_read: { label: "Bulk read", desc: "Many personal-data rows read in a short time.", d: { name: "Bulk read of personal data", category: "confidentiality", severity: "critical", source: "database_logs", match: [{ field: "personal_data", op: "is", value: "true" }], measure: "sum", sum_field: "row_count", threshold: 500, window: { n: 5, unit: "minutes" }, group_by: "service" } },
    event: { label: "A specific event", desc: "Any named log event, e.g. an admin export.", d: { name: "Sensitive event", category: "confidentiality", severity: "low", source: "activity_logs", match: [{ field: "event", op: "eq", value: "" }], measure: "count", threshold: 1, window: { n: 1, unit: "hours" }, group_by: "actor_ref" } },
    custom: { label: "Custom", desc: "Build the conditions yourself.", d: { name: "New detector", category: "confidentiality", severity: "medium", source: "activity_logs", match: [], measure: "count", threshold: 10, window: { n: 15, unit: "minutes" }, group_by: "service" } },
  };
  // The anomaly model (server-side Isolation Forest) reports its signals as detector "ML".
  const ML = "ML";
  const ML_DET = { id: ML, name: "Unusual activity (ML model)", source: "activity_logs", group_by: "service", category: "confidentiality", severity: "medium", enabled: true,
    why: "The anomaly model learned what normal looks like for each service from the logs, and this stretch is far outside it. Nobody wrote a rule for it, so it can catch patterns the detectors miss: a quiet scrape of customer records, unusual sign-in failures, or a service misbehaving.",
    steps: ["Read the reasons: which measures are above normal, and by how much", "Open the log lines and check who or what caused them", "If personal data may have been accessed, lost or exposed, open an incident; otherwise dismiss with a reason"],
    ref: "DPDP Act 2023 · s.8(5) reasonable security safeguards" };
  // PII detection v2 reports unmasked personal data found in stored log lines as detector "PII".
  const PII = "PII";
  const PII_DET = { id: PII, name: "Unmasked personal data in logs", source: "activity_logs", group_by: "service", category: "confidentiality", severity: "high", enabled: true,
    why: "Log lines were stored with personal data the log masker didn't catch: validated emails, phone numbers, card or Aadhaar numbers (checksums pass), access tokens, or people's names found by the language model. Anyone who can read the logs can see them.",
    steps: ["Open the log lines (Log Telemetry → Unmasked personal data) and check what was written", "Fix the service so it stops logging the value, or extend the masker", "Decide whether stored logs need purging; if the data was exposed, open an incident"],
    ref: "DPDP Act 2023 · s.8(5) reasonable security safeguards · DPDP Rules Rule 6(1)(a)" };
  const ANOM_DEFAULT = { enabled: true, sensitivity: "medium", bucket_minutes: 10, min_history: 12, auto_open: false };
  const SENS = { low: ["Low", "Only the most extreme slices", 0.72], medium: ["Medium", "Balanced (recommended)", 0.67], high: ["High", "Flags more, expect false alarms", 0.62] };
  const DISMISS_REASONS = ["False positive: not personal data", "Expected behaviour (deploy, test, maintenance)", "Already handled in another incident", "Below our risk threshold"];

  const S = {
    started: false, tab: "overview", policy: null, draft: null, scan: null, incidents: [], error: "", busy: false, loadedAt: null, gen: 0,
    sigFilter: "new", sigDetector: "", openSig: null, evidence: {}, incFilter: "open", incQuery: "", sel: null, dirty: null,
    notice: "board_initial", oblEdit: null, editDet: null, newDet: null, picking: false, history: null, preview: {},
    model: null, modelAt: 0, modelBusy: false, modelPreview: null, modelSvc: "",
  };
  const P = () => S.draft || S.policy;
  const det = (id) => (id === ML ? ML_DET : id === PII ? PII_DET : P()?.detectors.find((d) => d.id === id) || S.policy?.detectors.find((d) => d.id === id));
  // Model signals carry their own severity and breach type.
  const sdet = (s) => { const d = det(s.detector); return d && (s.detector === ML || s.detector === PII) ? { ...d, severity: s.severity || d.severity, category: s.category || d.category } : d; };
  const AN = () => ({ ...ANOM_DEFAULT, ...(P()?.anomaly || {}) });

  /* ---------- API ---------- */
  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r;
    try { r = await go(); } catch { throw Object.assign(new Error("offline"), { offline: true }); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), { status: r.status, body: j });
    return j;
  }

  /* ---------- signals ---------- */
  function allSignals() {
    const out = [];
    for (const [did, res] of Object.entries(S.scan?.results || {})) for (const s of res.signals) out.push({ ...s, triage: S.scan.triage[s.id] || null });
    return out.sort((a, b) => (b.end > a.end ? 1 : -1));
  }
  const sigState = (s) => s.triage?.state || "new";
  const sevRank = (s) => SEVS.indexOf(s);

  /* ---------- clocks ---------- */
  function clocks(inc) {
    const c = P().clocks, now = Date.now(), base = new Date(inc.aware_at).getTime();
    return Object.entries(OBL).map(([key, o]) => {
      const applicable = key !== "cert_in" || inc.cyber_incident;
      let due = base + c[o.hours] * 36e5;
      if (key === "board_report" && inc.extension_until) due = new Date(inc.extension_until).getTime();
      const done = inc.obligations?.[key];
      const doneAt = done?.done_at ? new Date(done.done_at).getTime() : null;
      let state;
      if (inc.status === "not_breach" || !applicable) state = "na";
      else if (doneAt) state = doneAt <= due ? "done" : "late";
      else if (now > due) state = "overdue";
      else if (due - now < c.warn_hours * 36e5) state = "soon";
      else state = "running";
      return { key, ...o, applicable, due, total: due - base, done, doneAt, state, left: due - now };
    });
  }
  const pending = (cl) => cl.filter((x) => x.state === "overdue" || x.state === "soon" || x.state === "running");
  function nextDeadline(inc) {
    if (!OPEN(inc)) return null;
    return pending(clocks(inc)).sort((a, b) => a.due - b.due)[0] || null;
  }
  function clockText(x) {
    if (x.state === "na") return x.applicable ? "Not required" : "Not a cyber incident";
    if (x.state === "done") return `Done ${short(x.doneAt)} · on time`;
    if (x.state === "late") return `Done ${short(x.doneAt)} · ${span(x.doneAt - x.due)} late`;
    if (x.state === "overdue") return `Overdue by ${span(-x.left)}`;
    return `${span(x.left)} left`;
  }

  /* ---------- loading ---------- */
  async function loadAll({ withPolicy = true } = {}) {
    const gen = S.gen;
    S.busy = true; renderMeta();
    try {
      // The scan returns the register too, so incidents it auto-opens show up at once.
      const [pol, scan] = await Promise.all([withPolicy || !S.policy ? api("/api/breach-policy") : null, api("/api/breach/scan")]);
      if (gen !== S.gen) return;
      if (pol) S.policy = pol;
      S.scan = scan; S.incidents = scan.incidents; S.error = ""; S.loadedAt = new Date();
    } catch (e) { if (gen === S.gen) S.error = e.offline ? "offline" : e.message; }
    finally { S.busy = false; if (gen === S.gen) render(); else renderMeta(); }
  }
  function putIncident(inc) {
    const i = S.incidents.findIndex((x) => x.id === inc.id);
    if (i >= 0) S.incidents[i] = inc; else S.incidents.push(inc);
  }
  async function patch(inc, changes, okMsg) {
    try {
      const r = await api(`/api/incidents/${inc.id}`, { method: "PUT", body: JSON.stringify({ rev: inc.rev, changes }) });
      putIncident(r); render(); if (okMsg) toast(okMsg, true);
      return r;
    } catch (e) {
      if (e.status === 409 && e.body?.current) { putIncident(e.body.current); S.dirty = null; render(); }
      toast(e.message);
      return null;
    }
  }

  /* ---------- render shell ---------- */
  const pill = (cls, label) => `<span class="rt-pill ${cls}">${esc(label)}</span>`;
  const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(cap(s))}</span>`;
  const statusPill = (st) => pill(STATUS[st][0], STATUS[st][1]);
  function render() {
    renderMeta();
    const body = $("brBody");
    if (!body) return;
    if (S.error === "offline") { body.innerHTML = `<div class="panel cp-empty"><h3>The consent service isn't running</h3><p>Breach detection and the breach register run in it. Start it from the project folder, then click Check now.</p><pre class="logline">python3 consent_service/server.py</pre></div>`; return; }
    if (S.error && !S.policy) { body.innerHTML = `<div class="panel cp-empty"><h3>Could not load breach data</h3><p>${esc(S.error)}</p></div>`; return; }
    if (!S.policy || !S.scan) { body.innerHTML = `<div class="panel cp-empty"><p>Scanning the logs…</p></div>`; return; }
    document.querySelectorAll("#brTabs [data-tab]").forEach((b) => { const on = b.dataset.tab === S.tab; b.classList.toggle("on", on); b.setAttribute("aria-selected", on); });
    const fresh = allSignals().filter((s) => sigState(s) === "new").length, open = S.incidents.filter(OPEN).length;
    $("brSigCount").textContent = num(fresh); $("brSigCount").hidden = !fresh;
    $("brIncCount").textContent = num(open); $("brIncCount").hidden = !open;
    const errs = Object.entries(S.scan.results).filter(([, r]) => r.error);
    const mdot = $("brModelDot"); if (mdot) { const r = S.scan.results[ML]; mdot.className = `br-mdot ${!AN().enabled ? "off" : r?.status === "training" ? "busy" : r?.error ? "bad" : "on"}`; }
    const banner = (S.error ? `<div class="cp-warn" role="alert"><b>Showing the last good results.</b><span>${esc(S.error)}</span></div>` : "")
      + (errs.length ? `<div class="cp-warn" role="alert"><b>Some detectors could not run, so results may be incomplete.</b><span>${errs.map(([id, r]) => `${esc(det(id)?.name || id)}: ${esc(r.error)}`).join(" · ")}</span></div>` : "");
    const view = S.tab === "incidents" && S.sel ? incidentHtml : { overview: overviewHtml, signals: signalsHtml, incidents: registerHtml, model: modelHtml, detectors: detectorsHtml }[S.tab];
    body.innerHTML = banner + view();
    renderDraftBar();
  }
  function renderMeta() {
    const m = $("brMeta"); if (!m) return;
    m.textContent = S.busy ? "Scanning…" : S.policy ? `Scanned ${S.loadedAt ? up(F_TIME.format(S.loadedAt)) + " IST" : "–"} · last ${plural(S.policy.lookback_days, "day")} of logs · Detectors v${S.policy.version}` : "";
  }

  /* ---------- Overview ---------- */
  function overviewHtml() {
    const sigs = allSignals(), fresh = sigs.filter((s) => sigState(s) === "new");
    const open = S.incidents.filter(OPEN).sort((a, b) => (nextDeadline(a)?.due || Infinity) - (nextDeadline(b)?.due || Infinity));
    const overdue = open.reduce((n, i) => n + clocks(i).filter((x) => x.state === "overdue").length, 0);
    const dets = P().detectors, on = dets.filter((d) => d.enabled), scanned = Object.entries(S.scan.results).reduce((n, [k, r]) => n + (k === ML || k === PII ? 0 : r.scanned || 0), 0);
    const kpi = (cls, label, value, sub, go) => `<button class="panel rt-kpi br-kpi ${cls}" ${go}><span>${esc(label)}</span><b>${value}</b><small>${sub}</small></button>`;
    const next = open.map((i) => ({ i, n: nextDeadline(i) })).filter((x) => x.n)[0];
    return `
      ${!P().contact?.email && !P().contact?.phone ? `<div class="cp-warn" role="alert"><b>Add a contact person before you need one.</b><span>Rule 7(1)(e) requires every customer notice to name someone who can answer questions. <button class="link" data-goto="detectors">Add contact in Detectors &amp; settings</button></span></div>` : ""}
      <div class="rt-kpis">
        ${kpi(open.length ? "bad" : "ok", "Open incidents", num(open.length), open.length ? `${num(open.filter((i) => i.status === "suspected").length)} suspected · ${num(open.filter((i) => i.status !== "suspected").length)} confirmed or contained` : "no breach being handled", `data-goto="incidents"`)}
        ${kpi(overdue ? "bad" : next ? "warn" : "", "Next deadline", next ? esc(next.n.state === "overdue" ? "Overdue" : span(next.n.left)) : "–", next ? `${esc(next.n.label)} · ${esc(next.i.id)}` : "no clock running", next ? `data-inc="${esc(next.i.id)}"` : "")}
        ${kpi(fresh.length ? "warn" : "ok", "Signals to review", num(fresh.length), fresh.length ? `from ${plural(new Set(fresh.map((s) => s.detector)).size, "detector")}` : "every signal is triaged", `data-goto="signals"`)}
        ${kpi("", "Detectors on", `${num(on.length)}<small class="br-of"> of ${num(dets.length)}</small>`, `${num(scanned)} log lines checked${AN().enabled ? " · ML model on" : ""}`, `data-goto="detectors"`)}
      </div>
      ${open.length ? `<section class="panel cp-list" aria-labelledby="brClocks">
        <div class="cp-list-head"><h3 id="brClocks">Response clocks</h3><span class="muted">Clocks start when you became aware of the breach</span></div>
        ${open.slice(0, 4).map((i) => `<article class="br-clockrow">
          <div class="br-clockhead"><button class="link strong" data-inc="${esc(i.id)}">${esc(i.id)} · ${esc(i.title)}</button><span>${statusPill(i.status)} ${sev(i.severity)}</span></div>
          <div class="br-clocks">${clocks(i).map(clockCard).join("")}</div>
        </article>`).join("")}
      </section>` : `<section class="panel br-calm"><div><b>No breach is being handled right now.</b><p>Detectors watch the logs continuously. You can also <button class="link" data-act="report">report a breach by hand</button>, for example a lost laptop or an email sent to the wrong customer.</p></div></section>`}
      <div class="br-two">
        <section class="panel cp-list" aria-labelledby="brNew">
          <div class="cp-list-head"><h3 id="brNew">Signals to review</h3><button class="link" data-goto="signals">All signals</button></div>
          ${fresh.length ? fresh.sort((a, b) => sevRank(sdet(b)?.severity) - sevRank(sdet(a)?.severity)).slice(0, 5).map((s) => {
            const d = sdet(s) || {};
            return `<button class="cp-row" data-sig-go="${esc(s.id)}">${sev(d.severity || "medium")}<span class="cp-row-main"><b>${esc(d.name || s.detector)}</b><span>${esc(groupLabel(d, s))} · ${esc(measureText(d, s))} · ${esc(short(s.end))}</span></span></button>`;
          }).join("") : `<p class="cp-none">Nothing new. Every signal has been dismissed or linked to an incident.</p>`}
        </section>
        <section class="panel cp-list" aria-labelledby="brDet">
          <div class="cp-list-head"><h3 id="brDet">Detectors</h3><button class="link" data-goto="detectors">Edit</button></div>
          ${modelRow()}
          ${dets.map((d) => {
            const r = S.scan.results[d.id], n = r?.signals.length || 0, nNew = (r?.signals || []).filter((s) => !S.scan.triage[s.id]).length;
            return `<div class="br-detrow${d.enabled ? "" : " off"}"><span class="br-cat ${esc(d.category)}" title="${esc(CATS[d.category]?.label)}"></span><span class="cp-row-main"><b>${esc(d.name)}</b><span>${d.enabled ? r?.error ? `<span class="cp-red">${esc(r.error)}</span>` : `${plural(r?.scanned || 0, "line")} checked` : "Off"}</span></span>
              <span class="br-detn ${nNew ? "warn" : n ? "" : "ok"}">${d.enabled ? (n ? `${num(n)} signal${n === 1 ? "" : "s"}${nNew ? ` · ${num(nNew)} new` : ""}` : "Quiet") : ""}</span></div>`;
          }).join("")}
        </section>
      </div>
      <p class="rt-note">A personal data breach is any unauthorised processing, accidental disclosure, sharing, alteration, destruction or loss of access that compromises the confidentiality, integrity or availability of personal data (DPDP Act s.2(u)). Rule 7 applies from 13 May 2027; the clocks run now so the process is ready.</p>`;
  }
  function modelRow() {
    const a = AN(), r = S.scan.results[ML], n = r?.signals.length || 0, nNew = (r?.signals || []).filter((s) => !S.scan.triage[s.id]).length;
    const sub = !a.enabled ? "Off" : r?.error ? `<span class="cp-red">${esc(r.error)}</span>` : r?.status === "training" ? "Learning from the logs…" : `Learns normal per service · ${esc(SENS[a.sensitivity][0])} sensitivity`;
    return `<button class="br-detrow br-mlrow${a.enabled ? "" : " off"}" data-goto="model"><span class="br-mlico" aria-hidden="true">ML</span><span class="cp-row-main"><b>Unusual activity (ML model)</b><span>${sub}</span></span>
      <span class="br-detn ${nNew ? "warn" : n ? "" : "ok"}">${a.enabled && r?.status !== "training" ? (n ? `${num(n)} anomal${n === 1 ? "y" : "ies"}${nNew ? ` · ${num(nNew)} new` : ""}` : "Quiet") : ""}</span></button>`;
  }
  function clockCard(x) {
    const pct = x.state === "na" ? 0 : x.doneAt ? 100 : Math.min(100, Math.max(0, ((x.total - x.left) / x.total) * 100));
    return `<div class="br-clock ${x.state}"><span class="br-clabel">${esc(x.label)}</span><b>${esc(clockText(x))}</b>
      <span class="br-bar"><i style="width:${pct.toFixed(1)}%"></i></span><small>${x.state === "na" ? esc(x.law) : `Due ${esc(short(x.due))} · ${esc(x.law)}`}</small></div>`;
  }

  /* ---------- Signals ---------- */
  const groupLabel = (d, s) => (d.group_by ? `${fl(d.group_by)} ${s.group}` : "all services");
  const winText = (w) => (w ? plural(w.n, w.unit.replace(/s$/, ""), w.unit) : "");
  const measureText = (d, s) => (s.detector === PII ? `${(s.reasons || []).map((r) => `${num(r.count)} × ${r.label.toLowerCase()}`).join(", ")} in ${plural(s.events, "log line")}` : s.detector === ML ? `${(s.reasons || []).slice(0, 2).map((r) => `${num(r.value)} ${r.label} (usually ${num(r.usual)})`).join(", ")} · score ${Number(s.score).toFixed(2)}` : d.measure === "sum" ? `${num(s.peak)} ${fl(d.sum_field)} in ${winText(d.window)}` : `${plural(s.events, "event")}${s.peak !== s.events ? `, up to ${num(s.peak)} in ${winText(d.window)}` : ` in ${s.start === s.end ? "one moment" : span(new Date(s.end) - new Date(s.start))}`}`);
  function signalsHtml() {
    const sigs = allSignals().filter((s) => !S.sigDetector || s.detector === S.sigDetector);
    const counts = { new: 0, linked: 0, dismissed: 0, all: sigs.length };
    sigs.forEach((s) => counts[sigState(s)]++);
    const shown = S.sigFilter === "all" ? sigs : sigs.filter((s) => sigState(s) === S.sigFilter);
    const open = S.incidents.filter(OPEN);
    return `<section class="panel cp-cpanel">
      <div class="cp-ctools">
        <div class="cp-chips">${[["new", "To review"], ["linked", "Linked"], ["dismissed", "Dismissed"], ["all", "All"]].map(([k, l]) => `<button class="cp-chip${S.sigFilter === k ? " on" : ""}" data-sig-filter="${k}" aria-pressed="${S.sigFilter === k}">${l} · ${num(counts[k])}</button>`).join("")}</div>
        <label class="cp-select br-push"><span class="sr-only">Detector</span><select data-sig-det><option value="">All detectors</option>${AN().enabled ? `<option value="${ML}" ${S.sigDetector === ML ? "selected" : ""}>${esc(ML_DET.name)}</option>` : ""}<option value="${PII}" ${S.sigDetector === PII ? "selected" : ""}>${esc(PII_DET.name)}</option>${P().detectors.map((d) => `<option value="${esc(d.id)}" ${S.sigDetector === d.id ? "selected" : ""}>${esc(d.name)}</option>`).join("")}</select></label>
      </div>
      ${shown.length ? shown.map((s) => signalRow(s, open)).join("") : `<p class="cp-none br-padx">${S.sigFilter === "new" ? "Nothing to review. New signals appear here as the detectors find them." : "No signals in this view."}</p>`}
    </section>
    <p class="rt-note">A signal is a stretch of log activity that crossed a detector's threshold. Review it: open an incident if personal data may be affected, add it to an incident you already have, or dismiss it with a reason. Every choice is recorded.</p>`;
  }
  function signalRow(s, open) {
    const d = sdet(s) || { name: s.detector, severity: "medium", category: "confidentiality" }, st = sigState(s), isOpen = S.openSig === s.id;
    const tri = s.triage;
    return `<article class="br-sig${isOpen ? " open" : ""}" id="sig-${esc(s.id)}">
      <div class="br-sigrow">
        ${sev(d.severity)}
        <div class="br-sigmain"><h4>${s.detector === PII ? `<span class="br-mltag">PII v2</span> ` : ""}${s.detector === ML ? `<span class="br-mltag">ML</span> ${s.live ? `<span class="ml-live sm"><i></i>Happening now</span> ` : ""}` : ""}${esc(d.name)} <small>${esc(groupLabel(d, s))}</small></h4>
          <p>${esc(measureText(d, s))} · ${esc(ist(s.start))}${s.start !== s.end ? ` – ${esc(short(s.end))}` : ""} · <span class="br-cat-t ${esc(d.category)}">${esc(CATS[d.category]?.label || "")}</span></p>
          ${st === "dismissed" ? `<p class="br-tri">Dismissed by ${esc(tri.by)} ${esc(short(tri.at))}: “${esc(tri.reason)}” <button class="link" data-sig-reopen="${esc(s.id)}">Undo</button></p>` : ""}
          ${st === "linked" ? `<p class="br-tri">In incident <button class="link strong" data-inc="${esc(tri.incident)}">${esc(tri.incident)}</button> · ${esc(tri.by)} ${esc(short(tri.at))}</p>` : ""}
        </div>
        <div class="br-sigact">
          <button class="btn ghost sm" data-sig-toggle="${esc(s.id)}" aria-expanded="${isOpen}">${isOpen ? "Hide" : "Review"}</button>
          <button class="btn ghost sm ai-ask" data-ask-ai="breach:signal:${esc(s.id)}">✦ Ask AI</button>
          ${st === "new" ? `<button class="btn primary sm" data-sig-open="${esc(s.id)}">Open incident</button>` : ""}
        </div>
      </div>
      ${isOpen ? `<div class="br-sigbody">
        <div class="cp-whywhat"><div><h5>Why this matters</h5><p>${esc(d.why || "")}</p><p class="br-ref">${esc(d.ref || "")}</p></div>
          ${(d.steps || []).length ? `<div><h5>First checks</h5><ol class="cp-steps">${d.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></div>` : ""}</div>
        ${s.detector === ML ? mlWhy(s) : ""}${s.detector === PII ? `<p class="muted br-piiwhy">Validated by PII detection v2 (checksums and context; names by the local language model). <button class="link" data-go-telemetry-unmasked>Open these lines in Log Telemetry</button></p>` : ""}
        ${evidenceHtml(s, d)}
        ${st === "new" ? `<div class="br-triage">
          <div class="br-tgroup"><h5>Add to an open incident</h5>${open.length ? `<div class="br-inline"><select data-sig-target="${esc(s.id)}">${open.map((i) => `<option value="${esc(i.id)}">${esc(i.id)} · ${esc(i.title.slice(0, 60))}</option>`).join("")}</select><button class="btn ghost sm" data-sig-add="${esc(s.id)}">Add</button></div>` : `<p class="muted">No open incident.</p>`}</div>
          <div class="br-tgroup"><h5>Dismiss</h5><div class="br-inline"><select data-sig-reason="${esc(s.id)}">${DISMISS_REASONS.map((r) => `<option>${esc(r)}</option>`).join("")}<option value="">Other (type below)…</option></select><button class="btn ghost sm danger" data-sig-dismiss="${esc(s.id)}">Dismiss</button></div>
            <input type="text" class="br-other" data-sig-other="${esc(s.id)}" placeholder="Reason (required for Other)" maxlength="300"></div>
        </div>` : ""}
      </div>` : ""}
    </article>`;
  }
  // Why the model flagged a stretch: each measure against the service's usual level (log scale).
  function mlWhy(s) {
    const rs = s.reasons || [], cut = SENS[AN().sensitivity][2];
    const top = Math.max(...rs.map((r) => Math.log1p(r.value)), Math.log1p(1), ...rs.map((r) => Math.log1p(r.p95))) * 1.08;
    const pos = (v) => `${((Math.log1p(v) / top) * 100).toFixed(1)}%`;
    const gauge = Math.min(100, Math.max(0, ((s.score - 0.3) / 0.55) * 100));
    return `<div class="ml-why">
      <div class="ml-whyhead"><h5>Why the model flagged this</h5>
        <div class="ml-score" title="Isolation Forest anomaly score: 0.5 is ordinary, close to 1 is very unusual. Cut-off at this sensitivity: ${cut}">
          <span>Anomaly score</span><b>${Number(s.score).toFixed(2)}</b><span class="ml-gauge"><i style="width:${gauge.toFixed(0)}%"></i><em style="left:${(((cut - 0.3) / 0.55) * 100).toFixed(0)}%"></em></span></div></div>
      <div class="ml-reasons">${rs.map((r) => `<div class="ml-reason">
        <div class="ml-rtext"><b>${esc(cap(r.label))}</b><span>${num(r.value)} in one ${esc(AN().bucket_minutes)}-minute slice · usually ${num(r.usual)}, 95% of slices ≤ ${num(r.p95)}</span></div>
        <div class="ml-bar" aria-hidden="true"><span class="ml-normal" style="width:${pos(r.p95)}"></span><span class="ml-med" style="left:${pos(r.usual)}"></span><span class="ml-obs" style="left:${pos(r.value)}"></span></div>
        <span class="ml-times">${r.times >= 10 ? Math.round(r.times) : r.times}× usual</span></div>`).join("")}</div>
      <p class="ml-legend"><span><i class="ml-k normal"></i>usual range (95% of slices)</span><span><i class="ml-k obs"></i>this stretch</span><span>${plural(s.slices || 1, "slice")} of ${esc(AN().bucket_minutes)} min · ${plural(s.events, "log line")}</span></p>
      ${(s.together || []).length ? `<p class="ml-together"><b>Also unusual at the same time:</b> ${s.together.map(esc).join(", ")}. Several services changing together usually means a deploy, restart or shared outage, not an attack on one service.</p>` : ""}
    </div>`;
  }
  function evidenceHtml(s, d) {
    const ev = S.evidence[s.id];
    if (!ev) { loadEvidence(s, d); return `<p class="muted">Loading log lines…</p>`; }
    if (ev.error) return `<p class="cp-red">Could not load log lines: ${esc(ev.error)}</p>`;
    const db = (d.source || s.source) === "database_logs";
    return `<div><h5>Log lines <span class="muted">(${num(Math.min(ev.rows.length, s.sample_ids.length))} of ${num(s.events)} shown)</span></h5>
      <div class="cp-tablewrap"><table class="cp-evidence"><thead><tr><th>Time (IST)</th><th>Service</th><th>Level</th>${db ? "<th>Operation</th><th>Table</th><th>Rows</th>" : "<th>Event</th><th>Status</th><th>Route</th>"}</tr></thead>
      <tbody>${ev.rows.map((r) => `<tr><td class="nowrap">${esc(up(F_TIME.format(new Date(r.logged_at))))} · ${esc(short(r.logged_at).split(",")[0])}</td><td>${esc(r.service)}</td><td>${esc(r.level || "")}</td>
        ${db ? `<td>${esc(r.operation || r.event || "")}</td><td>${esc(r.db_table || "")}</td><td>${esc(r.row_count ?? "")}</td>` : `<td>${esc(r.event || r.kind || "")}</td><td>${esc(r.http_status ?? "")}</td><td><code>${esc(r.route || "")}</code></td>`}</tr>`).join("")}</tbody></table></div>
      <p class="br-ref">Open Log Telemetry and search a trace or service for the full lines. Personal data in them is masked there.</p></div>`;
  }
  async function loadEvidence(s, d) {
    S.evidence[s.id] = { rows: [], loading: true };
    const src = d.source || s.source || "activity_logs";
    const cols = src === "database_logs" ? "id,logged_at,service,level,event,operation,db_table,row_count" : "id,logged_at,service,level,event,kind,http_status,route";
    try {
      const u = new URL(`${DASH_URL}/rest/v1/${src}`);
      u.searchParams.set("select", cols); u.searchParams.set("id", `in.(${s.sample_ids.join(",")})`); u.searchParams.set("order", "logged_at.asc");
      const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      S.evidence[s.id] = { rows: await r.json() };
    } catch (e) { S.evidence[s.id] = { error: e.message }; }
    render();
  }
  async function triage(sid, action, body, msg) {
    try {
      const r = await api(`/api/breach/signals/${sid}/${action}`, { method: "POST", body: JSON.stringify(body || {}) });
      S.scan.triage = r.triage;
      if (r.incident) putIncident(r.incident);
      render(); toast(msg, true);
      return r;
    } catch (e) { toast(e.message); return null; }
  }
  const sigById = (id) => allSignals().find((s) => s.id === id);
  const snapshot = (s) => ({ ...s, triage: undefined, detector_name: det(s.detector)?.name, source: det(s.detector)?.source || s.source });

  /* ---------- Incidents: register ---------- */
  function registerHtml() {
    const q = S.incQuery.trim().toLowerCase();
    const all = [...S.incidents].sort((a, b) => (b.created_at > a.created_at ? 1 : -1));
    const counts = { open: all.filter(OPEN).length, closed: all.filter((i) => !OPEN(i)).length, all: all.length };
    const shown = all.filter((i) => (S.incFilter === "all" || (S.incFilter === "open" ? OPEN(i) : !OPEN(i))) && (!q || `${i.id} ${i.title} ${i.services.join(" ")}`.toLowerCase().includes(q)));
    const dots = (i) => clocks(i).map((x) => `<span class="br-odot ${x.state}" title="${esc(x.label)}: ${esc(clockText(x))}"></span>`).join("");
    return `<section class="panel cp-cpanel">
      <div class="cp-ctools">
        <div class="cp-chips">${[["open", "Open"], ["closed", "Closed"], ["all", "All"]].map(([k, l]) => `<button class="cp-chip${S.incFilter === k ? " on" : ""}" data-inc-filter="${k}">${l} · ${num(counts[k])}</button>`).join("")}</div>
        <input type="search" class="br-push br-search" data-inc-q placeholder="Search id, title or system" value="${esc(S.incQuery)}" aria-label="Search incidents">
        <button class="btn ghost" data-act="csv-register" ${all.length ? "" : "disabled"}>Export register (CSV)</button>
      </div>
      ${shown.length ? `<div class="cp-tablewrap"><table class="cp-ctable">
        <thead><tr><th>Incident</th><th>Status</th><th>Severity</th><th>Became aware (IST)</th><th>Next deadline</th><th>Obligations</th><th class="num">Customers</th></tr></thead>
        <tbody>${shown.map((i) => { const n = nextDeadline(i); return `<tr data-inc="${esc(i.id)}" tabindex="0">
          <td><b>${esc(i.id)}</b><div class="br-ttl">${esc(i.title)}</div></td><td>${statusPill(i.status)}</td><td>${sev(i.severity)}</td><td>${esc(ist(i.aware_at))}</td>
          <td>${n ? `<span class="br-due ${n.state}">${esc(clockText(n))}</span><div class="br-ttl">${esc(n.label)}</div>` : `<span class="muted">${OPEN(i) ? "All done" : "–"}</span>`}</td>
          <td><span class="br-odots">${dots(i)}</span></td><td class="num">${i.principals_affected == null ? "–" : num(i.principals_affected)}</td></tr>`; }).join("")}</tbody></table></div>`
        : `<div class="br-calm br-padx"><div><b>${all.length ? "No incidents in this view." : "The breach register is empty."}</b><p>Incidents are opened from signals, by auto-open detectors, or by hand with <button class="link" data-act="report">Report a breach</button>.</p></div></div>`}
    </section>
    <p class="rt-note">The register is the record you show the Board: every incident, its timeline, the notices sent and who did what. Incidents ruled “Not a breach” stay in it with the reason.</p>`;
  }

  /* ---------- Incident detail ---------- */
  function incidentHtml() {
    const i = S.incidents.find((x) => x.id === S.sel);
    if (!i) { S.sel = null; return registerHtml(); }
    const v = { ...i, ...(S.dirty?.id === i.id ? S.dirty.changes : {}) };
    const cl = clocks(i), idx = FLOW.indexOf(i.status);
    const list = [...S.incidents].sort((a, b) => (b.created_at > a.created_at ? 1 : -1)), pos = list.findIndex((x) => x.id === i.id);
    const txt = (k, label, rows, help) => `<label class="field br-f wide"><span>${esc(label)}${help ? ` <small>${esc(help)}</small>` : ""}</span><textarea name="${k}" rows="${rows}">${esc(v[k] || "")}</textarea></label>`;
    const dt = (k, label, help) => `<label class="field br-f"><span>${esc(label)}${help ? ` <small>${esc(help)}</small>` : ""}</span><input type="datetime-local" name="${k}" value="${esc(toLocalInput(v[k]))}"></label>`;
    return `
      <div class="cp-crumbs"><button class="link" data-act="inc-back">← Breach register</button>
        <span class="cp-pager"><button class="btn ghost sm" data-inc="${esc(list[pos - 1]?.id || "")}" ${pos > 0 ? "" : "disabled"}>Newer</button><span>${num(pos + 1)} of ${num(list.length)}</span><button class="btn ghost sm" data-inc="${esc(list[pos + 1]?.id || "")}" ${pos < list.length - 1 ? "" : "disabled"}>Older</button></span></div>
      <article class="panel br-ihead">
        <div class="cp-titlerow">${statusPill(i.status)} ${sev(i.severity)}<span class="cp-ref">${esc(i.id)} · ${i.source === "manual" ? "Reported by hand" : "From detector signals"} by ${esc(i.created_by)} · ${esc(ist(i.created_at))}</span><button class="btn ghost sm ai-ask" data-ask-ai="breach:incident:${esc(i.id)}">✦ Ask AI</button></div>
        <h2>${esc(i.title)}</h2>
        <p class="muted">${esc(STATUS[i.status][2])}</p>
        <div class="br-flow" role="group" aria-label="Status">
          ${FLOW.map((st, k) => `<button class="br-step${st === i.status ? " on" : ""}${idx > k && i.status !== "not_breach" ? " past" : ""}" data-status="${st}" ${st === i.status ? 'aria-current="step"' : ""}><i>${idx > k && i.status !== "not_breach" ? "✓" : k + 1}</i>${esc(STATUS[st][1])}</button>`).join("")}
          <button class="br-step nb${i.status === "not_breach" ? " on" : ""}" data-status="not_breach"><i>✕</i>Not a breach</button>
        </div>
      </article>
      <section class="panel br-sec" aria-labelledby="brObl">
        <div class="cp-list-head flat"><h3 id="brObl">Obligations</h3><label class="switch"><span>Cyber incident (CERT-In applies)</span><input type="checkbox" data-cyber ${i.cyber_incident ? "checked" : ""}><i></i></label></div>
        <div class="br-obls">${cl.map((x) => oblCard(i, x)).join("")}</div>
        <div class="br-ext"><span>Board allowed more time for the detailed report?</span><input type="datetime-local" data-ext value="${esc(toLocalInput(i.extension_until))}" aria-label="Extended deadline (IST)"><small>Rule 7(2)(b): only on a written request to the Board.</small></div>
      </section>
      <form class="panel br-sec br-form" data-inc-form="${esc(i.id)}">
        <div class="cp-list-head flat"><h3>What happened</h3><span class="br-ref">Rule 7(2)(a): nature, extent, timing, location, likely impact</span></div>
        <div class="br-grid">
          <label class="field br-f wide"><span>Title</span><input type="text" name="title" value="${esc(v.title)}" maxlength="200"></label>
          <label class="field br-f"><span>Severity</span><select name="severity">${SEVS.map((s) => `<option value="${s}" ${v.severity === s ? "selected" : ""}>${cap(s)}</option>`).join("")}</select></label>
          <label class="field br-f"><span>Owner</span><input type="text" name="owner" value="${esc(v.owner || "")}" maxlength="120" placeholder="Who is handling it"></label>
          ${dt("aware_at", "Became aware (IST)", "the clocks start here")}
          ${dt("occurred_from", "Breach started (IST)")}
          ${dt("occurred_to", "Breach ended (IST)", "empty if ongoing")}
          <label class="field br-f"><span>Customers affected <small>best estimate</small></span><input type="number" min="0" name="principals_affected" value="${esc(v.principals_affected ?? "")}"></label>
          <fieldset class="br-checks wide"><legend>Type of breach</legend>${Object.entries(CATS).map(([k, c]) => `<label title="${esc(c.desc)}"><input type="checkbox" name="categories" value="${k}" ${v.categories.includes(k) ? "checked" : ""}> ${esc(c.label)} <small>${esc(c.desc)}</small></label>`).join("")}</fieldset>
          <fieldset class="br-checks wide"><legend>Personal data involved</legend>${Object.entries(DATA_CATS).map(([k, l]) => `<label><input type="checkbox" name="data_categories" value="${k}" ${v.data_categories.includes(k) ? "checked" : ""}> ${esc(l)}</label>`).join("")}</fieldset>
          <label class="field br-f wide"><span>Systems affected <small>comma separated</small></span><input type="text" name="services" value="${esc(v.services.join(", "))}"></label>
          <label class="field br-f wide"><span>Location <small>where it happened: system, region, vendor</small></span><input type="text" name="location" value="${esc(v.location)}" maxlength="500"></label>
          ${txt("description", "Nature and extent", 3, "what happened and how much data")}
          ${txt("impact", "Likely impact on customers", 2)}
        </div>
        <div class="cp-list-head flat br-gap"><h3>Investigation and response</h3><span class="br-ref">Rule 7(2)(b)(ii)–(v) and 7(1)(c)–(d)</span></div>
        <div class="br-grid">
          ${txt("cause", "Events, circumstances and reasons", 3)}
          ${txt("mitigation", "Measures taken or proposed to reduce the risk", 2)}
          ${txt("remedial", "Remedial measures to prevent it happening again", 2)}
          ${txt("person_findings", "Findings about who caused it", 2)}
          ${txt("safety_advice", "What customers can do to protect themselves", 2, "shown in the customer notice")}
          ${txt("principal_note", "How customers were notified", 1, "e.g. email to registered address and in-app message")}
          ${i.status === "closed" || i.status === "not_breach" || v.status === "closed" ? txt("closure_note", i.status === "not_breach" ? "Why this is not a personal data breach" : "Closure note and lessons learned", 2) : ""}
        </div>
        <div class="br-formfoot"><span class="muted" data-dirty-note>${S.dirty?.id === i.id ? "Unsaved changes" : `Last saved ${esc(ist(i.updated_at))}`}</span>
          <div class="cp-rbtns"><button type="button" class="btn ghost" data-act="form-reset" ${S.dirty?.id === i.id ? "" : "disabled"}>Undo changes</button><button type="submit" class="btn primary" ${S.dirty?.id === i.id ? "" : "disabled"}>Save changes</button></div></div>
      </form>
      ${noticesHtml(i)}
      ${i.signals.length ? `<section class="panel br-sec"><div class="cp-list-head flat"><h3>Evidence from the logs</h3><span class="muted">${plural(i.signals.length, "linked signal")}</span></div>
        ${i.signals.map((s) => { const d = det(s.detector) || { name: s.detector_name, source: s.source }; const k = `inc-${s.id}`;
          return `<div class="br-evrow"><div><b>${esc(d.name || s.detector_name)}</b> <span class="muted">· ${esc(groupLabel(d, s))} · ${esc(measureText(d, s))} · ${esc(ist(s.start))}</span></div>
            <button class="btn ghost sm" data-ev-toggle="${esc(s.id)}">${S.openSig === k ? "Hide log lines" : "Show log lines"}</button></div>${S.openSig === k ? evidenceHtml(s, d) : ""}`; }).join("")}</section>` : ""}
      <section class="panel br-sec" aria-labelledby="brLog"><div class="cp-list-head flat"><h3 id="brLog">Activity</h3><span class="muted">Every change, with who made it</span></div>
        <ol class="br-log">${[...i.log].reverse().map((l) => `<li><span>${esc(ist(l.at))}</span><b>${esc(l.text)}</b><small>${esc(l.by)}</small></li>`).join("")}</ol></section>`;
  }
  function oblCard(i, x) {
    const editing = S.oblEdit === x.key;
    const d = x.done || {};
    return `<div class="br-obl ${x.state}">
      <div class="br-obltop"><div><b>${esc(x.label)}</b><span>${esc(x.law)}</span></div><span class="br-due ${x.state}">${esc(clockText(x))}</span></div>
      ${x.state === "na" ? `<p class="muted">${x.applicable ? "Not required: assessed as not a breach." : "Switch on “Cyber incident” if this was an attack or intrusion. CERT-In then requires a report within 6 hours."}</p>`
      : `<span class="br-bar"><i style="width:${(x.doneAt ? 100 : Math.min(100, Math.max(0, ((x.total - x.left) / x.total) * 100))).toFixed(1)}%"></i></span>
        <p class="br-oblmeta">${x.doneAt ? `Sent ${esc(ist(x.doneAt))} by ${esc(d.by || "")}${d.ref ? ` · ref ${esc(d.ref)}` : ""}${d.count != null ? ` · ${plural(d.count, "customer")} notified` : ""}${d.note ? ` · ${esc(d.note)}` : ""}` : `Due ${esc(ist(x.due))} · to ${esc(x.who)}`}</p>
        ${editing ? `<form class="br-oblform" data-obl-form="${x.key}">
            <label class="field"><span>Sent at (IST)</span><input type="datetime-local" name="done_at" value="${esc(toLocalInput(d.done_at || new Date().toISOString()))}" required></label>
            <label class="field"><span>Reference / acknowledgement no.</span><input type="text" name="ref" value="${esc(d.ref || "")}" maxlength="120"></label>
            ${x.key === "principals" ? `<label class="field"><span>Customers notified</span><input type="number" min="0" name="count" value="${esc(d.count ?? i.principals_affected ?? "")}"></label>` : ""}
            <label class="field"><span>Note</span><input type="text" name="note" value="${esc(d.note || "")}" maxlength="1000"></label>
            <div class="cp-rbtns"><button type="button" class="btn ghost sm" data-act="obl-cancel">Cancel</button><button class="btn primary sm">Save</button></div></form>`
          : `<div class="cp-rbtns">${x.doneAt ? `<button class="btn ghost sm" data-obl-edit="${x.key}">Edit</button><button class="btn ghost sm" data-obl-undo="${x.key}">Mark not done</button>` : `<button class="btn ghost sm" data-notice-go="${x.key}">Draft notice</button><button class="btn primary sm" data-obl-edit="${x.key}">Mark as sent</button>`}</div>`}`}
    </div>`;
  }

  /* ---------- Notices (drafted from the incident record) ---------- */
  function noticeText(i, kind) {
    const pol = P(), c = pol.contact || {}, org = pol.organisation || "the Data Fiduciary", missing = [];
    const need = (v, label) => { if (v === null || v === undefined || String(v).trim() === "") { missing.push(label); return `[add: ${label}]`; } return v; };
    const cats = i.categories.map((k) => `${CATS[k].label} (${CATS[k].desc.toLowerCase()})`).join("; ");
    const data = i.data_categories.map((k) => DATA_CATS[k]).join(", ");
    const when = `${i.occurred_from ? ist(i.occurred_from) : need("", "when it started")} to ${i.occurred_to ? ist(i.occurred_to) : "ongoing / not yet known"} (IST)`;
    const contact = [c.name && `${c.name}${c.role ? `, ${c.role}` : ""}`, c.email, c.phone].filter(Boolean).join(" · ") || need("", "contact person (Detectors & settings)");
    const affected = i.principals_affected == null ? need("", "number of customers affected") : `${num(i.principals_affected)} (best estimate)`;
    const today = ist(new Date());
    let text = "";
    if (kind === "board_initial") text =
`To: Data Protection Board of India
Subject: Intimation of personal data breach (${i.id}), ${org}

Under Rule 7(2)(a) of the Digital Personal Data Protection Rules, 2025, ${org} intimates the following personal data breach. A detailed report will follow within 72 hours of becoming aware.

1. Description of the breach
   Nature: ${need(cats, "type of breach")}
   ${need(i.description, "nature and extent")}
   Extent: ${affected} Data Principals affected; personal data involved: ${need(data, "personal data involved")}
   Timing: ${when}; became aware ${ist(i.aware_at)} (IST)
   Location: ${need(i.location || i.services.join(", "), "location")}${i.services.length ? `; systems: ${i.services.join(", ")}` : ""}

2. Likely impact
   ${need(i.impact, "likely impact")}

Contact: ${contact}
Date: ${today} (IST)`;
    else if (kind === "board_report") {
      const pn = i.obligations?.principals;
      text =
`To: Data Protection Board of India
Subject: Detailed report on personal data breach (${i.id}), ${org}

Under Rule 7(2)(b) of the Digital Personal Data Protection Rules, 2025.${i.obligations?.board_initial?.done_at ? ` Initial intimation sent ${ist(i.obligations.board_initial.done_at)}${i.obligations.board_initial.ref ? `, reference ${i.obligations.board_initial.ref}` : ""}.` : ""}

(i) Updated and detailed description
   Nature: ${need(cats, "type of breach")}
   ${need(i.description, "nature and extent")}
   Extent: ${affected} Data Principals; personal data involved: ${need(data, "personal data involved")}
   Timing: ${when}; became aware ${ist(i.aware_at)}; location: ${need(i.location || i.services.join(", "), "location")}
   Likely impact: ${need(i.impact, "likely impact")}

(ii) Events, circumstances and reasons leading to the breach
   ${need(i.cause, "cause")}

(iii) Measures implemented or proposed to mitigate risk
   ${need(i.mitigation, "mitigation")}

(iv) Findings regarding the person who caused the breach
   ${need(i.person_findings, "findings about who caused it")}

(v) Remedial measures taken to prevent recurrence
   ${need(i.remedial, "remedial measures")}

(vi) Intimations given to affected Data Principals
   ${pn?.done_at ? `Sent ${ist(pn.done_at)}${pn.count != null ? ` to ${num(pn.count)} Data Principals` : ""}${i.principal_note ? ` via ${i.principal_note}` : ""}.` : need("", "customer notices (mark them as sent)")}
${i.signals.length ? `\nEvidence: ${i.signals.map((s) => `${s.detector_name || s.detector} (${s.group || "all"}, ${s.events} log events, ${ist(s.start)} to ${ist(s.end)})`).join("; ")}.\n` : ""}
Contact: ${contact}
Date: ${today} (IST)`;
    }
    else if (kind === "principals") text =
`Subject: Important: a security incident involving your ${org} account

Dear customer,

We are writing to tell you about an incident that affected some of your personal data.

What happened
${need(i.description, "nature and extent")} It happened ${i.occurred_from ? `between ${ist(i.occurred_from)} and ${i.occurred_to ? ist(i.occurred_to) : "now"}` : need("", "when it started")} (IST). The information involved: ${need(data, "personal data involved")}.

What this may mean for you
${need(i.impact, "likely impact")}

What we are doing
${need(i.mitigation, "mitigation")}

What you can do
${need(i.safety_advice, "advice to customers")}

If you have questions, contact ${contact}.

${org}`;
    else if (kind === "cert_in") text =
`To: CERT-In, incident@cert-in.org.in
Subject: Cyber security incident report: ${i.title} (${i.id})

Reported under the CERT-In Directions of 28 April 2022 (section 70B(6), IT Act 2000).

Organisation: ${org} (e-commerce)
Point of contact: ${contact}
Incident type: ${need(i.categories.length ? i.title : "", "incident type")}
Detected: ${ist(i.aware_at)} (IST); occurred ${when}
Systems affected: ${need(i.services.join(", ") || i.location, "systems affected")}
Description: ${need(i.description, "nature and extent")}
Impact: ${need(i.impact, "likely impact")}
Actions taken: ${need(i.mitigation, "mitigation")}
${i.signals.length ? `Indicators (log evidence): ${i.signals.map((s) => `${s.detector_name || s.detector}: ${s.events} events from ${s.services.join(", ") || s.group}, ${ist(s.start)} to ${ist(s.end)}`).join("; ")}` : ""}

Date: ${today} (IST)`;
    return { text, missing: [...new Set(missing)] };
  }
  function noticesHtml(i) {
    const tabs = Object.entries(OBL).filter(([k]) => k !== "cert_in" || i.cyber_incident);
    if (!tabs.some(([k]) => k === S.notice)) S.notice = tabs[0][0];
    const n = noticeText(i, S.notice), done = i.obligations?.[S.notice]?.done_at;
    return `<section class="panel br-sec" id="brNotices" aria-labelledby="brNoticeH">
      <div class="cp-list-head flat"><h3 id="brNoticeH">Notices</h3><span class="muted">Drafted from this incident record. Save changes above to update them.</span></div>
      <div class="cp-chips">${tabs.map(([k, o]) => `<button class="cp-chip${S.notice === k ? " on" : ""}" data-notice="${k}">${esc(o.label)}${i.obligations?.[k]?.done_at ? " ✓" : ""}</button>`).join("")}</div>
      ${n.missing.length ? `<div class="cp-warn"><b>${plural(n.missing.length, "detail")} still missing</b><span>${n.missing.map(esc).join(" · ")}</span></div>` : `<p class="br-ready">Every detail this notice needs is filled in.</p>`}
      <pre class="logline br-notice" tabindex="0">${esc(n.text)}</pre>
      <div class="cp-rbtns"><button class="btn ghost" data-act="notice-copy">Copy</button><button class="btn ghost" data-act="notice-download">Download .txt</button>
        ${done ? `<span class="br-ready">Sent ${esc(ist(done))}</span>` : `<button class="btn primary" data-obl-edit="${S.notice}">Mark as sent</button>`}</div>
    </section>`;
  }

  /* ---------- report a breach (manual) ---------- */
  function openReport() {
    const dlg = $("brDialog");
    $("brDialogBody").innerHTML = `
      <label class="field"><span>What happened?</span><input type="text" name="title" required maxlength="200" placeholder="e.g. Order export emailed to the wrong vendor"></label>
      <div class="br-grid two">
        <label class="field"><span>Became aware (IST)</span><input type="datetime-local" name="aware_at" value="${esc(toLocalInput(new Date().toISOString()))}" required></label>
        <label class="field"><span>Severity</span><select name="severity">${SEVS.map((s) => `<option value="${s}" ${s === "medium" ? "selected" : ""}>${cap(s)}</option>`).join("")}</select></label>
      </div>
      <fieldset class="br-checks"><legend>Type of breach</legend>${Object.entries(CATS).map(([k, c]) => `<label><input type="checkbox" name="categories" value="${k}"> ${esc(c.label)} <small>${esc(c.desc)}</small></label>`).join("")}</fieldset>
      <label class="field"><span>Short description <small>you can add detail later</small></span><textarea name="description" rows="3"></textarea></label>
      <label class="switch"><span>Cyber incident: attack, intrusion or malware (CERT-In 6-hour report)</span><input type="checkbox" name="cyber_incident"><i></i></label>`;
    $("brDialogErr").textContent = "";
    dlg.showModal();
    dlg.querySelector('[name="title"]').focus();
  }
  async function submitReport(form) {
    const f = (n) => form.querySelector(`[name="${n}"]`);
    const title = f("title").value.trim();
    if (!title) { $("brDialogErr").textContent = "Describe what happened in a few words."; return false; }
    try {
      const inc = await api("/api/incidents", { method: "POST", body: JSON.stringify({ incident: { title, aware_at: fromLocalInput(f("aware_at").value), severity: f("severity").value, description: f("description").value.trim(), cyber_incident: f("cyber_incident").checked, categories: [...form.querySelectorAll('[name="categories"]:checked')].map((x) => x.value) } }) });
      putIncident(inc); S.tab = "incidents"; S.sel = inc.id; S.dirty = null; render(); window.scrollTo(0, 0);
      toast(`${inc.id} opened. The response clocks are running.`, true);
      return true;
    } catch (e) { $("brDialogErr").textContent = e.message; return false; }
  }

  /* ---------- Anomaly model ---------- */
  async function loadModel(force, quiet) {
    if (S.modelBusy) return;
    S.modelBusy = true; if (S.tab === "model" && !quiet) render();
    try {
      S.model = force ? await api("/api/breach/model/retrain", { method: "POST", body: "{}" }) : await api("/api/breach/model");
      S.modelAt = Date.now();
      if (force) { toast(`Model retrained on ${num(S.model.lines)} log lines: ${plural(S.model.signals.length, "anomaly", "anomalies")}.`, true); S.modelBusy = false; return loadAll({ withPolicy: false }); }
    } catch (e) { toast(e.message); }
    finally { S.modelBusy = false; if (S.tab === "model") render(); }
  }
  // Draft settings: train on the cached log window without saving, to show what would change.
  let previewTimer = null;
  function previewModel() {
    const a = AN(), key = JSON.stringify(a);
    if (!S.draft || JSON.stringify({ ...ANOM_DEFAULT, ...(S.policy.anomaly || {}) }) === key || !a.enabled) { S.modelPreview = null; return; }
    if (S.modelPreview?.key === key) return;
    S.modelPreview = { key, busy: true };
    clearTimeout(previewTimer);
    previewTimer = setTimeout(async () => {
      try { const m = await api("/api/breach/model/retrain", { method: "POST", body: JSON.stringify({ preview: a }) }); if (S.modelPreview?.key === key) S.modelPreview = { key, n: m.signals.length, services: new Set(m.signals.map((x) => x.group)).size, note: m.note }; }
      catch (e) { if (S.modelPreview?.key === key) S.modelPreview = { key, error: e.message }; }
      if (S.tab === "model") render();
    }, 350);
  }
  function scoreChart(m, cut) {
    const W = 1000, H = 230, L = 40, R = 12, T = 12, B = 28, lo = 0.3, hi = 0.85;
    const pts = m.series.flatMap((x) => x.points.map((p) => ({ svc: x.service, t: new Date(p[0]).getTime(), s: p[1], f: p[2], live: p[3] })));
    if (!pts.length) return "";
    const t0 = Math.min(...pts.map((p) => p.t)), t1 = Math.max(...pts.map((p) => p.t)) + m.bucket_minutes * 6e4;
    const X = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * (W - L - R), Y = (v) => T + (1 - (Math.min(hi, Math.max(lo, v)) - lo) / (hi - lo)) * (H - T - B);
    const grid = [0.4, 0.5, 0.6, 0.7, 0.8].map((v) => `<line class="ch-grid" x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="ch-ax" x="${L - 8}" y="${Y(v) + 4}" text-anchor="end">${v.toFixed(1)}</text>`).join("");
    const day = 864e5, ist0 = Math.ceil((t0 + 330 * 6e4) / (day / 2)) * (day / 2) - 330 * 6e4, ticks = [];
    for (let t = ist0; t < t1; t += day / 2) ticks.push(t);
    const step = Math.max(1, Math.ceil(ticks.length / 8));
    const xt = ticks.filter((_, i) => i % step === 0).map((t) => `<line class="ch-grid" x1="${X(t)}" x2="${X(t)}" y1="${T}" y2="${H - B}" stroke-dasharray="2 4"/><text class="ch-ax" x="${X(t)}" y="${H - 8}" text-anchor="middle">${esc(up(fmt({ day: "numeric", month: "short", hour: "numeric", hour12: true }).format(new Date(t))))}</text>`).join("");
    const sel = S.modelSvc;
    const dots = pts.sort((a, b) => a.f - b.f || a.s - b.s).map((p) => {
      const dim = sel && p.svc !== sel, cls = p.f ? "ml-pt bad" : p.s >= cut ? "ml-pt warn" : "ml-pt";
      if (p.live) return `<circle class="${cls} live${dim ? " dim" : ""}" cx="${X(p.t).toFixed(1)}" cy="${Y(p.s).toFixed(1)}" r="5"><title>${esc(p.svc)} · slice in progress · score ${p.s.toFixed(2)} so far</title></circle>`;
      return `<circle class="${cls}${dim ? " dim" : ""}" cx="${X(p.t).toFixed(1)}" cy="${Y(p.s).toFixed(1)}" r="${p.f ? 4.5 : 2.4}">${p.f || p.s >= cut ? `<title>${esc(p.svc)} · ${esc(short(p.t))} · score ${p.s.toFixed(2)}${p.f ? " · anomaly" : " · above cut-off but no measure clearly above normal"}</title>` : ""}</circle>`;
    }).join("");
    return `<svg class="ml-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Anomaly score of every time slice; ${m.signals.length} anomalies above the cut-off ${cut}">
      ${grid}${xt}<line class="ml-cut" x1="${L}" x2="${W - R}" y1="${Y(cut)}" y2="${Y(cut)}"/><text class="ml-cutlabel" x="${W - R}" y="${Y(cut) - 6}" text-anchor="end">cut-off ${cut.toFixed(2)}</text>${dots}</svg>`;
  }
  function modelHtml() {
    const a = AN(), r = S.scan.results[ML] || {}, m = S.model, cut = SENS[a.sensitivity][2];
    if (a.enabled && (!m || Date.now() - S.modelAt > 20000) && !S.modelBusy) setTimeout(() => loadModel(false));
    previewModel();
    const state = !a.enabled ? ["off", "Off"] : r.error || m?.error ? ["bad", "Error"] : r.status === "training" || (!m && S.modelBusy) ? ["warn", "Learning…"] : m?.note ? ["warn", "Needs more data"] : ["ok", "Live"];
    const ago = m?.scored_at ? Math.max(0, Math.round((Date.now() - new Date(m.scored_at)) / 1000)) : null;
    const stat = (label, v, sub) => `<div class="ml-stat"><span>${esc(label)}</span><b>${v}</b>${sub ? `<small>${sub}</small>` : ""}</div>`;
    const sigs = allSignals().filter((x) => x.detector === ML), fresh = (m?.signals || sigs).filter((x) => !S.scan.triage[x.id]).length;
    const pv = S.modelPreview;
    const svcs = m?.services || [];
    return `
      <section class="panel ml-hero">
        <div class="ml-herohead">
          <span class="ml-ico" aria-hidden="true">ML</span>
          <div class="ml-title"><h3>Unusual activity model ${state[1] === "Live" ? `<span class="ml-live"><i></i>Live</span>` : pill(state[0], state[1])}</h3>
            <p>Learns what normal looks like for each service from the logs, then flags stretches that are far outside it. No rules to write, no labels needed.</p></div>
          <div class="ml-heroact">
            <button class="btn ghost sm ai-ask" data-ask-ai="breach:model">✦ Ask AI</button>
            <button class="btn ghost" data-act="model-retrain" ${!a.enabled || S.modelBusy ? "disabled" : ""}>${S.modelBusy ? "Training…" : "Retrain now"}</button>
            <button class="btn primary" data-act="model-signals" ${sigs.length || m?.signals?.length ? "" : "disabled"}>Review anomalies${fresh ? ` · ${num(fresh)}` : ""}</button>
          </div>
        </div>
        ${m && !m.error ? `<div class="ml-stats">
          ${stat("Log lines learned from", num(m.lines), `last ${plural(P().lookback_days, "day")}${m.truncated ? " (capped)" : ""}`)}
          ${stat("Time slices", num(m.slices), `${esc(m.bucket_minutes)} min each, ${plural(svcs.length, "service")}`)}
          ${stat("Anomalies", num(m.signals.length), `${num(fresh)} to review`)}
          ${stat("Last scored", ago == null ? "–" : ago < 60 ? `${ago} s ago` : esc(up(F_TIME.format(new Date(m.scored_at)))), `new lines scored every ${esc(m.rescore_every_s || 10)} s · this slice: ${plural(m.live_lines || 0, "line")} so far`)}
          ${stat("Normal learned", esc(up(F_TIME.format(new Date(m.fitted_at || m.trained_at)))), `from ${num(m.fit_slices || m.slices)} finished slices · re-learned every ${Math.round((m.refit_every_s || 600) / 60)} min`)}
        </div>` : m?.error || r.error ? `<p class="cp-red ml-pad">${esc(m?.error || r.error)}</p>` : a.enabled ? `<p class="muted ml-pad">Reading the logs and training the model…</p>` : `<p class="muted ml-pad">The model is off. Turn it on in the settings on the right.</p>`}
        ${m?.note ? `<p class="cp-warn ml-pad">${esc(m.note)}</p>` : ""}
      </section>
      <div class="cp-rlayout">
        <div class="cp-rmain">
          <section class="panel ml-sec">
            <div class="cp-list-head flat"><h3>Anomaly score of every time slice</h3><span class="muted">Each dot is one service in one ${esc(a.bucket_minutes)}-minute slice. Red dots became signals.</span></div>
            ${m?.series?.length ? `<div class="cp-chips ml-svcs"><button class="cp-chip${!S.modelSvc ? " on" : ""}" data-model-svc="">All services</button>${svcs.map((x) => `<button class="cp-chip${S.modelSvc === x.service ? " on" : ""}" data-model-svc="${esc(x.service)}">${esc(x.service)}${x.flagged ? ` · ${num(x.flagged)}` : ""}</button>`).join("")}</div>
              ${scoreChart(m, cut)}
              <p class="ml-legend"><span><i class="ml-k dot"></i>ordinary slice</span><span><i class="ml-k dot warn"></i>above the cut-off, but nothing clearly above normal</span><span><i class="ml-k dot bad"></i>anomaly (became a signal)</span><span><i class="ml-k dot live"></i>slice in progress (scored live)</span><span><i class="ml-k cut"></i>cut-off for ${esc(SENS[a.sensitivity][0].toLowerCase())} sensitivity</span></p>`
            : `<p class="muted">${a.enabled ? "The chart appears once the model has trained." : "Turn the model on to see scores."}</p>`}
          </section>
          <section class="panel ml-sec">
            <div class="cp-list-head flat"><h3>What the model learned per service</h3><span class="muted">Usual level in one slice (median) → the busiest 5% of slices</span></div>
            ${svcs.length ? `<div class="cp-tablewrap"><table class="cp-ctable ml-table"><thead><tr><th>Service</th><th class="num">Slices</th><th>Requests</th><th>Data ops</th><th>Personal data</th><th>Errors</th><th>Top score</th><th class="num">Anomalies</th></tr></thead>
              <tbody>${svcs.map((x) => { const t = x.typical, cell = (k) => `${num(t[k][0])} <span class="muted">→ ${num(t[k][1])}</span>`; return `<tr>
                <td><b>${esc(x.service)}</b>${x.learning ? ` <span class="cp-tag">learning</span>` : ""}</td><td class="num">${num(x.slices)}</td><td>${cell("requests")}</td><td>${cell("operations")}</td><td>${cell("personal_data")}</td><td>${cell("errors")}</td>
                <td><span class="ml-mini"><i style="width:${Math.min(100, Math.max(0, ((x.max_score - 0.3) / 0.55) * 100)).toFixed(0)}%" class="${x.max_score >= cut ? "hot" : ""}"></i></span> ${x.max_score.toFixed(2)}</td>
                <td class="num">${x.flagged ? `<b class="cp-red">${num(x.flagged)}</b>` : `<span class="muted">0</span>`}</td></tr>`; }).join("")}</tbody></table></div>` : `<p class="muted">Nothing learned yet.</p>`}
          </section>
          <section class="panel ml-sec">
            <div class="cp-list-head flat"><h3>How it works</h3><span class="muted">${esc(m?.algorithm || "Isolation Forest with per-service robust scaling")}</span></div>
            <ol class="ml-steps">
              <li><b>Slice</b><span>Each service's log lines are cut into ${esc(a.bucket_minutes)}-minute slices. Each slice gets 10 measures: requests, data operations, personal-data and credential events, rejected sign-ins, PII caught in log text, errors, warnings, server errors and response time.</span></li>
              <li><b>Learn normal</b><span>For every service separately, the model learns the usual level of each measure (median and spread), so a busy service and a quiet one are each judged against themselves. Only slices with activity count, so downtime isn't treated as normal.</span></li>
              <li><b>Score</b><span>An Isolation Forest of 150 random trees tries to separate each slice from the rest. Unusual slices are cut off in few steps and score close to 1; ordinary ones score about 0.5 or less.</span></li>
              <li><b>Score live</b><span>Every 10 seconds the newest log lines are scored against the learned normal, including the slice still in progress, so a spike shows up while it is happening. Normal is re-learned every 10 minutes from finished slices.</span></li>
              <li><b>Explain</b><span>A slice becomes a signal only if its score passes the cut-off <i>and</i> at least one measure is clearly above that service's normal (more than 3 spreads, and a meaningful amount). The signal lists those measures, so you can check it.</span></li>
            </ol>
            <p class="rt-note">The model runs inside the consent service in plain Python, on the same read-only log window as the detectors. Nothing is sent outside and nothing in the database changes. It is unsupervised: it finds what is <i>unusual</i>, not what is <i>malicious</i>. Your triage decides.</p>
          </section>
        </div>
        <aside class="cp-rside-col">
          <div class="panel cp-scard ml-set">
            <div class="cp-list-head flat"><h3>Model settings</h3><button class="cp-switch" role="switch" aria-checked="${a.enabled}" aria-label="Anomaly model ${a.enabled ? "on" : "off"}" data-anom-toggle><i></i></button></div>
            <fieldset class="ml-sens" ${a.enabled ? "" : "disabled"}><legend>Sensitivity</legend>
              ${Object.entries(SENS).map(([k, [l, d, c]]) => `<label class="ml-opt${a.sensitivity === k ? " on" : ""}"><input type="radio" name="ml-sens" value="${k}" ${a.sensitivity === k ? "checked" : ""} data-anom="sensitivity"><span><b>${l}</b><small>${esc(d)} · cut-off ${c}</small></span></label>`).join("")}
            </fieldset>
            <label class="br-kvin"><span>Time slice</span><span><select data-anom="bucket_minutes" ${a.enabled ? "" : "disabled"}>${[5, 10, 15, 30, 60].map((n) => `<option value="${n}" ${a.bucket_minutes === n ? "selected" : ""}>${n} min</option>`).join("")}</select></span></label>
            <label class="br-kvin"><span>Learn first for</span><span><input type="number" min="4" max="1000" value="${esc(a.min_history)}" data-anom="min_history" ${a.enabled ? "" : "disabled"}> slices</span></label>
            <p class="rt-help">A service is only judged once the model has seen this many active slices of it.</p>
            <label class="ml-check"><input type="checkbox" data-anom="auto_open" ${a.auto_open ? "checked" : ""} ${a.enabled ? "" : "disabled"}><span>Open an incident automatically for each anomaly</span></label>
            <p class="rt-help">Off by default: anomalies are unusual, not proven breaches, so they wait in Signals for review.</p>
            ${pv ? `<div class="ml-preview">${pv.busy ? "Testing these settings on the current logs…" : pv.error ? `<span class="cp-red">${esc(pv.error)}</span>` : pv.note ? esc(pv.note) : `With these settings: <b>${plural(pv.n, "anomaly", "anomalies")}</b> across ${plural(pv.services, "service")} (now ${num(m?.signals.length || 0)}). Save to apply.`}</div>` : ""}
          </div>
        </aside>
      </div>`;
  }

  /* ---------- Detectors & settings ---------- */
  function sentence(d) {
    const tok = (s) => `<span class="cp-tok">${esc(s)}</span>`;
    const conds = (d.match || []).map((m) => `${esc(fl(m.field))} ${esc(OPS[m.op] || m.op)} ${tok(m.value)}`).join(" and ") || "any line";
    const what = d.measure === "sum" ? `the total ${esc(fl(d.sum_field))} reaches ${tok(num(d.threshold))}` : `${tok(plural(d.threshold, "line"))} or more`;
    return `Signal when ${what} in ${esc(SOURCE_LABEL[d.source])} where ${conds}, within ${tok(winText(d.window))}${d.group_by ? ` for the same ${esc(fl(d.group_by))}` : ""}.`;
  }
  function detectorsHtml() {
    const pol = P(), c = pol.clocks, ct = pol.contact || {};
    const group = (cat) => {
      const list = pol.detectors.map((d, i) => ({ d, i })).filter(({ d }) => d.category === cat);
      const fresh = S.newDet && S.newDet.category === cat ? [S.newDet] : [];
      if (!list.length && !fresh.length) return "";
      return `<div class="panel cp-rgroup"><h3>${esc(CATS[cat].label)} <small class="br-gsub">${esc(CATS[cat].desc)}</small></h3>
        ${fresh.map((d) => `<div class="cp-rule editing new">${detForm(d, true)}</div>`).join("")}
        ${list.map(({ d, i }) => { const r = S.scan.results[d.id]; return `<div class="cp-rule${d.enabled ? "" : " off"}${S.editDet === d.id ? " editing" : ""}">
          <div class="cp-rrow">
            <button class="cp-switch" role="switch" aria-checked="${d.enabled}" aria-label="Detector ${esc(d.id)} ${d.enabled ? "on" : "off"}" data-toggle-det="${i}"><i></i></button>
            <div class="cp-rtext"><p><b>${esc(d.name)}</b></p><p class="br-sent">${sentence(d)}</p><span>${esc(d.id)} · ${esc(d.ref || "")}${d.auto_open ? ` · <b class="br-auto">Opens an incident automatically</b>` : ""}</span></div>
            <div class="cp-rside">${sev(d.severity)}<span class="cp-rcount ${!d.enabled ? "off" : r?.signals.length ? "bad" : "ok"}">${!d.enabled ? "Off" : S.draft ? "" : r ? (r.signals.length ? plural(r.signals.length, "signal") : "Quiet") : ""}</span><button class="btn ghost" data-edit-det="${esc(d.id)}" ${S.editDet === d.id ? "disabled" : ""}>Edit</button></div>
          </div>
          ${S.editDet === d.id ? detForm(d, false) : ""}
        </div>`; }).join("")}</div>`;
    };
    return `
      <div class="cp-rtop">
        <p>Detectors <b>v${esc(S.policy.version)}</b>, saved ${esc(ist(S.policy.updated_at))} by ${esc(S.policy.updated_by)}</p>
        <div class="cp-rbtns"><button class="btn ghost" data-act="export">Export</button><button class="btn primary" data-act="pick-det" ${S.newDet ? "disabled" : ""}>Add detector</button></div>
      </div>
      ${S.picking ? `<div class="panel cp-picker"><div class="cp-list-head"><h3>Start from a template</h3><button class="link" data-act="pick-cancel">Cancel</button></div>
        <div class="cp-pickgrid">${Object.entries(TEMPLATES).map(([k, t]) => `<button class="cp-pick" data-new-det="${k}"><b>${esc(t.label)}</b><span>${esc(t.desc)}</span></button>`).join("")}</div></div>` : ""}
      <div class="cp-rlayout">
        <div class="cp-rmain">${Object.keys(CATS).map(group).join("")}</div>
        <aside class="cp-rside-col">
          <div class="panel cp-scard"><h3>Response clocks</h3>
            <p class="rt-help">Hours from becoming aware. The law fixes 72 h for the Board's detailed report and 6 h for CERT-In; “without delay” targets are yours to set.</p>
            ${[["cert_in_hours", "CERT-In report"], ["board_initial_hours", "Initial intimation to the Board"], ["principals_hours", "Notice to customers"], ["board_report_hours", "Detailed report to the Board"], ["warn_hours", "Warn when this close"]].map(([k, l]) => `<label class="br-kvin"><span>${esc(l)}</span><span><input type="number" min="1" max="720" value="${esc(c[k])}" data-clock="${k}"> h</span></label>`).join("")}
          </div>
          <div class="panel cp-scard"><h3>Contact for notices</h3>
            <p class="rt-help">Named in every customer notice (Rule 7(1)(e)) and Board intimation.</p>
            <label class="field"><span>Organisation</span><input type="text" value="${esc(pol.organisation || "")}" data-org maxlength="120"></label>
            ${[["name", "Name", "text"], ["role", "Role", "text"], ["email", "Email", "email"], ["phone", "Phone", "tel"]].map(([k, l, t]) => `<label class="field"><span>${l}</span><input type="${t}" value="${esc(ct[k] || "")}" data-contact="${k}" maxlength="120"></label>`).join("")}
          </div>
          <div class="panel cp-scard"><h3>Scanning</h3>
            <label class="br-kvin"><span>Look back over</span><span><input type="number" min="1" max="90" value="${esc(pol.lookback_days)}" data-lookback> days</span></label>
            <p class="rt-help">Detectors re-scan this window every 30 seconds while this page is open. Signals older than the window drop off the list; triage decisions and incidents are kept.</p>
          </div>
          <div class="panel cp-scard"><div class="cp-list-head flat"><h3>Version history</h3></div>${historyHtml()}</div>
        </aside>
      </div>`;
  }
  function historyHtml() {
    if (!S.history) { loadHistory(); return `<p class="muted">Loading…</p>`; }
    return S.history.slice(0, 8).map((h) => `<div class="rt-hist"><div><b>v${h.version}</b>${h.version === S.policy.version ? ' <span class="cp-tag ok">Current</span>' : ""}<span>${esc(ist(h.updated_at))} · ${esc(h.updated_by)}</span><small>${esc(h.change_note)}</small></div>
      ${h.version === S.policy.version ? "" : `<button class="btn ghost sm" data-restore="${h.version}">Restore</button>`}</div>`).join("");
  }
  async function loadHistory() {
    try { S.history = await api("/api/breach-policy/history"); } catch { S.history = []; }
    if (S.tab === "detectors") render();
  }
  function detForm(d, isNew) {
    const fields = FIELDS[d.source] || {};
    const opsFor = (f) => (fields[f] === "array" ? ["has"] : fields[f] === "bool" ? ["is"] : fields[f] === "int" ? ["eq", "neq", "gt", "gte", "lt", "lte", "in"] : ["eq", "neq", "in"]);
    const cond = (m, k) => `<div class="br-cond" data-cond>
      <select name="c_field" aria-label="Field">${Object.keys(fields).map((f) => `<option value="${f}" ${m.field === f ? "selected" : ""}>${esc(fl(f))}</option>`).join("")}</select>
      <select name="c_op" aria-label="Condition">${opsFor(m.field).map((o) => `<option value="${o}" ${m.op === o ? "selected" : ""}>${esc(OPS[o])}</option>`).join("")}</select>
      ${fields[m.field] === "bool" ? `<select name="c_value" aria-label="Value">${["true", "false"].map((x) => `<option ${String(m.value) === x ? "selected" : ""}>${x}</option>`).join("")}</select>` : `<input type="text" name="c_value" value="${esc(m.value)}" aria-label="Value" placeholder="${m.op === "in" ? "a, b, c" : "value"}">`}
      <button type="button" class="icon-btn" data-act="cond-del" aria-label="Remove condition">×</button></div>`;
    return `<form class="cp-redit" data-det="${esc(d.id)}" data-new="${isNew ? 1 : 0}">
      ${isNew ? `<p class="cp-newlabel">New detector · ${esc(d.id)}</p>` : ""}
      <div class="cp-rfields">
        <label class="field wide"><span>Name</span><input type="text" name="name" value="${esc(d.name)}" maxlength="120"></label>
        <label class="field"><span>Logs</span><select name="source" data-det-source>${Object.keys(FIELDS).map((s) => `<option value="${s}" ${d.source === s ? "selected" : ""}>${esc(cap(SOURCE_LABEL[s]))}</option>`).join("")}</select></label>
      </div>
      <fieldset class="br-conds"><legend>Count log lines where</legend>${(d.match || []).map(cond).join("") || `<p class="muted">No conditions: every line counts.</p>`}<button type="button" class="link" data-act="cond-add">+ Add condition</button></fieldset>
      <div class="cp-rfields">
        <label class="field"><span>Measure</span><select name="measure" data-det-measure><option value="count" ${d.measure !== "sum" ? "selected" : ""}>Number of lines</option>${Object.entries(fields).filter(([, t]) => t === "int").map(([f]) => `<option value="sum:${f}" ${d.measure === "sum" && d.sum_field === f ? "selected" : ""}>Total ${esc(fl(f))}</option>`).join("")}</select></label>
        <label class="field"><span>Signal at</span><input type="number" name="threshold" min="1" value="${esc(d.threshold)}"></label>
        <label class="field"><span>Within</span><span class="rt-period"><input type="number" name="win_n" min="1" value="${esc(d.window.n)}" aria-label="Window amount"><select name="win_unit" aria-label="Window unit">${["minutes", "hours", "days"].map((u) => `<option ${d.window.unit === u ? "selected" : ""}>${u}</option>`).join("")}</select></span></label>
        <label class="field"><span>Per</span><select name="group_by"><option value="">All lines together</option>${Object.entries(fields).filter(([, t]) => t === "text").map(([f]) => `<option value="${f}" ${d.group_by === f ? "selected" : ""}>Same ${esc(fl(f))}</option>`).join("")}</select></label>
      </div>
      <div class="cp-rfields">
        <label class="field"><span>Type of breach</span><select name="category">${Object.entries(CATS).map(([k, c]) => `<option value="${k}" ${d.category === k ? "selected" : ""}>${esc(c.label)}</option>`).join("")}</select></label>
        <label class="field"><span>Severity</span><select name="severity">${SEVS.map((s) => `<option value="${s}" ${d.severity === s ? "selected" : ""}>${cap(s)}</option>`).join("")}</select></label>
        <label class="field br-chk"><input type="checkbox" name="auto_open" ${d.auto_open ? "checked" : ""}><span>Open an incident automatically <small>the clocks start as soon as it fires</small></span></label>
      </div>
      <label class="field"><span>Why it matters (shown when reviewing a signal)</span><textarea name="why" rows="2">${esc(d.why || "")}</textarea></label>
      <label class="field"><span>First checks, one per line</span><textarea name="steps" rows="3">${esc((d.steps || []).join("\n"))}</textarea></label>
      <label class="field"><span>Legal reference</span><input type="text" name="ref" value="${esc(d.ref || "")}" maxlength="200"></label>
      <div class="cp-rfoot"><span class="cp-preview" aria-live="polite"></span>
        <div class="cp-rbtns">${isNew ? "" : `<button type="button" class="btn ghost danger" data-act="delete-det">Delete detector</button>`}
          <button type="button" class="btn ghost" data-act="cancel-det">Cancel</button><button type="submit" class="btn primary">Apply</button></div></div>
    </form>`;
  }
  function readDet(form) {
    const isNew = form.dataset.new === "1", base = isNew ? S.newDet : P().detectors.find((x) => x.id === form.dataset.det);
    if (!base) return null;
    const v = (n) => form.querySelector(`[name="${n}"]`)?.value;
    const [measure, sumField] = (v("measure") || "count").split(":");
    const out = { ...base, name: (v("name") || "").trim(), source: v("source"), measure, threshold: Math.max(1, Number(v("threshold")) || 1),
      window: { n: Math.max(1, Number(v("win_n")) || 1), unit: v("win_unit") }, group_by: v("group_by") || "", category: v("category"), severity: v("severity"),
      auto_open: form.querySelector('[name="auto_open"]').checked, why: v("why").trim(), steps: v("steps").split("\n").map((x) => x.trim()).filter(Boolean), ref: v("ref").trim(),
      match: [...form.querySelectorAll("[data-cond]")].map((row) => ({ field: row.querySelector('[name="c_field"]').value, op: row.querySelector('[name="c_op"]').value, value: row.querySelector('[name="c_value"]').value.trim() })) };
    if (measure === "sum") out.sum_field = sumField; else delete out.sum_field;
    return { det: out, isNew };
  }
  let previewT;
  function preview(form) {
    clearTimeout(previewT);
    previewT = setTimeout(async () => {
      if (!form.isConnected || !readDet(form)) return;
      const { det: d } = readDet(form), el = form.querySelector(".cp-preview");
      if (d.match.some((m) => !m.value)) { el.textContent = "Fill in every condition value."; return; }
      el.textContent = "Checking the logs…";
      try {
        const r = await api("/api/breach/preview", { method: "POST", body: JSON.stringify({ lookback_days: P().lookback_days, detectors: [{ ...d, enabled: true }] }) });
        if (!form.isConnected) return;
        const res = r.results[d.id];
        el.textContent = res.error ? `Couldn't check: ${res.error}` : `With these settings: ${plural(res.signals.length, "signal")} in the last ${plural(P().lookback_days, "day")} (${num(res.scanned)} matching lines${res.truncated ? ", capped" : ""})`;
      } catch (e) { if (form.isConnected) el.textContent = `Couldn't check: ${e.message}`; }
    }, 450);
  }
  function applyDet(form) {
    const read = readDet(form);
    if (!read) return;
    clearTimeout(previewT);
    const { det: d, isNew } = read;
    if (!d.name) return toast("Give the detector a name.");
    if (d.match.some((m) => !m.value)) return toast("Fill in every condition value, or remove the condition.");
    S.editDet = null; S.newDet = null;
    edit((p) => { if (isNew) p.detectors.push(d); else p.detectors[p.detectors.findIndex((x) => x.id === d.id)] = d; });
  }

  /* ---------- drafts (detectors + settings) ---------- */
  function edit(fn) {
    if (!S.draft) S.draft = clone(S.policy);
    fn(S.draft);
    render();
  }
  function renderDraftBar() {
    const bar = $("brDraft");
    if (!S.draft) { bar.hidden = true; return; }
    bar.hidden = false;
    const on = S.draft.detectors.filter((d) => d.enabled).length;
    $("brDraftImpact").innerHTML = `Unsaved changes · <b>${num(on)}</b> of ${num(S.draft.detectors.length)} detectors on. Signals update after saving.`;
  }
  async function save() {
    const note = $("brNote").value.trim();
    if (!note) { $("brNote").focus(); return toast("Describe the change before saving."); }
    $("brSave").disabled = true;
    try {
      const saved = await api("/api/breach-policy", { method: "PUT", body: JSON.stringify({ policy: S.draft, base_version: S.policy.version, change_note: note }) });
      S.gen++; S.policy = saved; S.draft = null; S.history = null; $("brNote").value = "";
      toast(`Saved as version ${saved.version}. Re-scanning…`, true);
      await loadAll({ withPolicy: false });
    } catch (e) {
      if (e.status === 409 && e.body?.current) { S.gen++; S.policy = e.body.current; render(); toast(`${e.body.current.updated_by} saved version ${e.body.current.version} meanwhile. Your draft is kept; saving again replaces it.`); }
      else toast(e.message);
    } finally { $("brSave").disabled = false; }
  }
  async function restore(v) {
    if (S.draft && !window.confirm("You have unsaved changes. Restore anyway and discard them?")) return;
    if (!window.confirm(`Restore detectors version ${v}? It will be saved as a new version.`)) return;
    try {
      const r = await api(`/api/breach-policy/restore/v${v}`, { method: "POST", body: JSON.stringify({ base_version: S.policy.version }) });
      S.gen++; S.policy = r; S.draft = null; S.history = null;
      toast(`Version ${v} restored as version ${r.version}.`, true);
      await loadAll({ withPolicy: false });
    } catch (e) { toast(e.message); }
  }

  /* ---------- incident form ---------- */
  // The datetime inputs hold minutes only; compare at that precision so seconds don't count as an edit.
  const minute = (v) => (v ? Math.floor(new Date(v).getTime() / 6e4) : null);
  function readIncForm(form, inc) {
    const v = (n) => form.querySelector(`[name="${n}"]`)?.value;
    const out = {};
    for (const k of ["title", "owner", "location", "description", "impact", "cause", "mitigation", "remedial", "person_findings", "safety_advice", "principal_note", "closure_note", "severity"]) if (form.querySelector(`[name="${k}"]`)) out[k] = v(k).trim();
    for (const k of ["aware_at", "occurred_from", "occurred_to"]) out[k] = fromLocalInput(v(k));
    out.principals_affected = v("principals_affected") === "" ? null : Math.max(0, Number(v("principals_affected")) || 0);
    out.categories = [...form.querySelectorAll('[name="categories"]:checked')].map((x) => x.value);
    out.data_categories = [...form.querySelectorAll('[name="data_categories"]:checked')].map((x) => x.value);
    out.services = v("services").split(",").map((x) => x.trim()).filter(Boolean);
    const changes = {};
    for (const [k, val] of Object.entries(out)) {
      const cur = inc[k];
      const same = Array.isArray(val) ? JSON.stringify(val) === JSON.stringify(cur || []) : k.endsWith("_at") || k.startsWith("occurred") ? minute(val) === minute(cur) : (val ?? "") === (cur ?? "");
      if (!same) changes[k] = val;
    }
    return changes;
  }
  function markDirty(form) {
    const inc = S.incidents.find((x) => x.id === form.dataset.incForm);
    const changes = readIncForm(form, inc);
    const has = Object.keys(changes).length > 0;
    S.dirty = has ? { id: inc.id, changes } : null;
    form.querySelector("[data-dirty-note]").textContent = has ? "Unsaved changes" : `Last saved ${ist(inc.updated_at)}`;
    form.querySelectorAll('[data-act="form-reset"], [type="submit"]').forEach((b) => (b.disabled = !has));
  }
  async function setStatus(inc, st) {
    if (st === inc.status) return;
    if (S.dirty?.id === inc.id && !window.confirm("You have unsaved changes in the form. Change the status anyway? Your edits are kept.")) return;
    if (st === "closed") {
      const open = clocks(inc).filter((x) => x.state === "overdue" || x.state === "running" || x.state === "soon");
      if (open.length && !window.confirm(`${plural(open.length, "obligation")} not marked as sent: ${open.map((x) => x.label).join(", ")}. Close anyway?`)) return;
    }
    let extra = {};
    if (st === "not_breach") {
      const why = window.prompt("Why is this not a personal data breach? (kept in the register)", inc.closure_note || "");
      if (why === null) return;
      if (!why.trim()) return toast("A reason is required to rule out a breach.");
      extra.closure_note = why.trim();
    }
    const keep = S.dirty?.id === inc.id ? S.dirty : null;
    const r = await patch(inc, { status: st, ...extra }, `Status: ${STATUS[st][1]}.`);
    if (r && keep) { S.dirty = keep; render(); }
  }

  let toastT;
  function toast(m, ok = false) { const t = $("brToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }
  function download(name, text, type = "text/plain") {
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function registerCsv() {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const head = ["Incident", "Title", "Status", "Severity", "Type", "Became aware (IST)", "Started (IST)", "Ended (IST)", "Customers affected", "Systems", ...Object.values(OBL).map((o) => `${o.label} (IST)`), "Owner", "Source"];
    const rows = S.incidents.map((i) => [i.id, i.title, STATUS[i.status][1], i.severity, i.categories.join(" "), ist(i.aware_at), ist(i.occurred_from), ist(i.occurred_to), i.principals_affected ?? "", i.services.join(" "),
      ...Object.keys(OBL).map((k) => (i.obligations?.[k]?.done_at ? ist(i.obligations[k].done_at) : "")), i.owner, i.source].map(q).join(","));
    download("breach-register.csv", [head.map(q).join(","), ...rows].join("\n"), "text/csv");
  }

  /* ---------- AI context helpers ---------- */
  function incSig(s) {
    const d = sdet(s) || {};
    return { id: s.id, detector: s.detector, detector_name: d.name, category: d.category, severity: d.severity, group: s.group, start: s.start, end: s.end, events: s.events, peak: s.peak, measure: measureText(d, s),
      ...(s.detector === ML ? { anomaly_score: s.score, reasons: (s.reasons || []).map((r) => `${r.label}: ${r.value} (usual ${r.usual}, 95% of slices <= ${r.p95})`), also_unusual_at_same_time: s.together } : {}),
      state: sigState(s), dismissed_reason: s.triage?.reason, incident: s.triage?.incident };
  }
  function modelCtx() {
    const a = AN(), m = S.model, r = S.scan?.results[ML];
    return { enabled: a.enabled, sensitivity: a.sensitivity, score_cutoff: SENS[a.sensitivity][2], slice_minutes: a.bucket_minutes, auto_open: a.auto_open,
      algorithm: "Isolation Forest (150 trees) on 10 per-slice measures, scaled per service by median/MAD; a slice is an anomaly if score >= cut-off and a measure is > 3 MAD above that service's median",
      status: r?.status, anomalies: r?.signals.length, lines_learned: m?.lines, slices: m?.slices,
      services: (m?.services || []).map((x) => ({ service: x.service, slices: x.slices, anomalies: x.flagged, highest_score: x.max_score })) };
  }
  function incCtx(i) {
    return { id: i.id, title: i.title, status: i.status, severity: i.severity, source: i.source, breach_type: i.categories, cyber_incident: i.cyber_incident,
      became_aware: i.aware_at, started: i.occurred_from, ended: i.occurred_to, customers_affected: i.principals_affected, systems: i.services, data_involved: i.data_categories,
      description: i.description, likely_impact: i.impact, cause: i.cause, mitigation: i.mitigation, remedial: i.remedial, advice_to_customers: i.safety_advice,
      obligations: clocks(i).map((x) => ({ obligation: x.label, law: x.law, state: x.state, due: new Date(x.due).toISOString(), done_at: x.done?.done_at || null, status: clockText(x) })),
      missing_for_board_report: noticeText(i, "board_report").missing, missing_for_customer_notice: noticeText(i, "principals").missing,
      linked_signals: i.signals.map((s) => ({ detector: s.detector_name || s.detector, group: s.group, events: s.events, start: s.start, end: s.end })), activity: i.log.slice(-15) };
  }

  /* ---------- events ---------- */
  function onClick(e) {
    const t = (s) => e.target.closest(s);
    let b;
    if (t("[data-go-telemetry-unmasked]")) return Telemetry.openUnmasked();
    if ((b = t("[data-goto]"))) { S.tab = b.dataset.goto; S.sel = null; return render(); }
    if ((b = t("[data-inc]"))) { if (!b.dataset.inc) return; S.tab = "incidents"; S.sel = b.dataset.inc; S.oblEdit = null; if (S.dirty?.id !== S.sel) S.dirty = null; render(); return window.scrollTo(0, 0); }
    if ((b = t("[data-sig-go]"))) { S.tab = "signals"; S.sigFilter = "new"; S.openSig = b.dataset.sigGo; render(); return $(`sig-${b.dataset.sigGo}`)?.scrollIntoView({ block: "center" }); }
    if ((b = t("[data-inc-filter]"))) { S.incFilter = b.dataset.incFilter; return render(); }
    if ((b = t("[data-sig-filter]"))) { S.sigFilter = b.dataset.sigFilter; return render(); }
    if ((b = t("[data-sig-toggle]"))) { S.openSig = S.openSig === b.dataset.sigToggle ? null : b.dataset.sigToggle; return render(); }
    if ((b = t("[data-ev-toggle]"))) { const k = `inc-${b.dataset.evToggle}`; S.openSig = S.openSig === k ? null : k; return render(); }
    if ((b = t("[data-sig-open]"))) { const s = sigById(b.dataset.sigOpen); return s && triage(s.id, "link", { signal: snapshot(s) }, "Incident opened. The response clocks are running.").then((r) => { if (r?.incident) { S.tab = "incidents"; S.sel = r.incident.id; render(); window.scrollTo(0, 0); } }); }
    if ((b = t("[data-sig-add]"))) { const s = sigById(b.dataset.sigAdd), target = document.querySelector(`[data-sig-target="${b.dataset.sigAdd}"]`)?.value; return s && target && triage(s.id, "link", { signal: snapshot(s), incident: target }, `Added to ${target}.`); }
    if ((b = t("[data-sig-dismiss]"))) {
      const id = b.dataset.sigDismiss, sel = document.querySelector(`[data-sig-reason="${id}"]`).value, other = document.querySelector(`[data-sig-other="${id}"]`).value.trim();
      const reason = sel || other;
      if (!reason) { document.querySelector(`[data-sig-other="${id}"]`).focus(); return toast("Type a reason for dismissing."); }
      S.openSig = null;
      return triage(id, "dismiss", { reason: other && sel ? `${sel}: ${other}` : reason }, "Signal dismissed. You can undo it from the Dismissed filter.");
    }
    if ((b = t("[data-sig-reopen]"))) return triage(b.dataset.sigReopen, "reopen", {}, "Signal back in the review list.");
    const inc = S.incidents.find((x) => x.id === S.sel);
    if ((b = t("[data-status]")) && inc) return setStatus(inc, b.dataset.status);
    if ((b = t("[data-obl-edit]")) && inc) { S.oblEdit = b.dataset.oblEdit; render(); return document.querySelector(`[data-obl-form="${S.oblEdit}"]`)?.scrollIntoView({ block: "center" }); }
    if ((b = t("[data-obl-undo]")) && inc) { if (!window.confirm(`Mark “${OBL[b.dataset.oblUndo].label}” as not done? The change is recorded.`)) return; return patch(inc, { obligations: { [b.dataset.oblUndo]: null } }, "Marked as not done."); }
    if ((b = t("[data-notice-go]"))) { S.notice = b.dataset.noticeGo; render(); return $("brNotices")?.scrollIntoView({ block: "start" }); }
    if ((b = t("[data-notice]"))) { S.notice = b.dataset.notice; return render(); }
    if ((b = t("[data-toggle-det]"))) { const i = +b.dataset.toggleDet; return edit((d) => (d.detectors[i].enabled = !d.detectors[i].enabled)); }
    if ((b = t("[data-edit-det]"))) { S.editDet = b.dataset.editDet; S.newDet = null; S.picking = false; render(); const f = document.querySelector("#brBody .cp-redit"); f?.scrollIntoView({ block: "center" }); return f && preview(f); }
    if ((b = t("[data-new-det]"))) {
      let n = 1; while (P().detectors.some((d) => d.id === `D${n}`)) n++;
      S.newDet = { id: `D${n}`, enabled: true, auto_open: false, why: "", steps: [], ref: "", ...clone(TEMPLATES[b.dataset.newDet].d) };
      S.picking = false; S.editDet = null; render();
      const f = document.querySelector("#brBody .cp-redit"); f?.scrollIntoView({ block: "center" }); return f && preview(f);
    }
    if ((b = t("[data-restore]"))) return restore(+b.dataset.restore);
    if ((b = t("[data-model-svc]"))) { S.modelSvc = b.dataset.modelSvc; return render(); }
    if (t("[data-anom-toggle]")) return edit((d) => (d.anomaly = { ...AN(), enabled: !AN().enabled }));
    b = t("[data-act]"); if (!b) return;
    const form = b.closest("form");
    switch (b.dataset.act) {
      case "report": return openReport();
      case "inc-back": S.sel = null; S.oblEdit = null; return render();
      case "obl-cancel": S.oblEdit = null; return render();
      case "form-reset": S.dirty = null; return render();
      case "csv-register": return registerCsv();
      case "notice-copy": { const i = S.incidents.find((x) => x.id === S.sel); return navigator.clipboard?.writeText(noticeText(i, S.notice).text).then(() => toast("Notice copied.", true), () => toast("Copy failed: select the text and copy it.")); }
      case "notice-download": { const i = S.incidents.find((x) => x.id === S.sel); return download(`${i.id}-${S.notice.replace("_", "-")}.txt`, noticeText(i, S.notice).text); }
      case "pick-det": S.picking = true; S.editDet = null; return render();
      case "model-retrain": return loadModel(true);
      case "model-signals": S.tab = "signals"; S.sigDetector = ML; S.sigFilter = "new"; return render();
      case "pick-cancel": S.picking = false; return render();
      case "cancel-det": S.editDet = null; S.newDet = null; return render();
      case "delete-det": { const id = form.dataset.det; if (!window.confirm(`Delete detector ${id}? Nothing is saved until you click Save.`)) return; S.editDet = null; return edit((d) => d.detectors.splice(d.detectors.findIndex((x) => x.id === id), 1)); }
      case "cond-add": { const read = readDet(form); if (!read) return; read.det.match.push({ field: Object.keys(FIELDS[read.det.source])[0], op: "eq", value: "" }); return redrawForm(form, read); }
      case "cond-del": { b.closest("[data-cond]").remove(); return preview(form); }
      case "export": return download(`breach-detectors-v${S.policy.version}${S.draft ? "-draft" : ""}.json`, JSON.stringify(P(), null, 2), "application/json");
    }
  }
  // Re-render one detector form in place; unsaved edits travel in read.det.
  function redrawForm(form, read) {
    if (read.isNew) S.newDet = read.det;
    const tmp = document.createElement("div");
    tmp.innerHTML = detForm(read.det, read.isNew);
    const f = tmp.firstElementChild;
    form.replaceWith(f);
    preview(f);
  }
  function onChange(e) {
    const t = e.target;
    const detf = t.closest(".cp-redit");
    if (detf) {
      if (t.matches("[data-det-source]") || t.matches('[name="c_field"]')) {
        const read = readDet(detf);
        if (t.matches("[data-det-source]")) { read.det.match = []; read.det.group_by = "service"; read.det.measure = "count"; delete read.det.sum_field; }
        else { const row = t.closest("[data-cond]"), k = [...detf.querySelectorAll("[data-cond]")].indexOf(row), ty = FIELDS[read.det.source][t.value]; read.det.match[k].op = ty === "array" ? "has" : ty === "bool" ? "is" : "eq"; read.det.match[k].value = ty === "bool" ? "true" : ""; }
        return redrawForm(detf, read);
      }
      return preview(detf);
    }
    const inc = S.incidents.find((x) => x.id === S.sel);
    if (t.closest("[data-inc-form]")) return markDirty(t.closest("[data-inc-form]"));
    if (t.matches("[data-cyber]") && inc) return patch(inc, { cyber_incident: t.checked }, t.checked ? "CERT-In report added to the obligations." : "CERT-In report marked as not applicable.");
    if (t.matches("[data-ext]") && inc) return patch(inc, { extension_until: fromLocalInput(t.value) }, t.value ? "Detailed report deadline extended." : "Extension removed.");
    if (t.matches("[data-sig-det]")) { S.sigDetector = t.value; return render(); }
    if (t.matches("[data-anom]")) {
      const k = t.dataset.anom, v = k === "auto_open" ? t.checked : k === "sensitivity" ? t.value : Math.round(Number(t.value)) || ANOM_DEFAULT[k];
      return edit((d) => (d.anomaly = { ...AN(), [k]: k === "min_history" ? Math.min(1000, Math.max(4, v)) : v }));
    }
    if (t.matches("[data-clock]")) { const n = Math.min(720, Math.max(1, Math.round(Number(t.value)) || 1)); return edit((d) => (d.clocks[t.dataset.clock] = n)); }
    if (t.matches("[data-contact]")) return edit((d) => { d.contact = { ...(d.contact || {}), [t.dataset.contact]: t.value.trim() }; });
    if (t.matches("[data-org]")) return edit((d) => (d.organisation = t.value.trim()));
    if (t.matches("[data-lookback]")) { const n = Math.min(90, Math.max(1, Math.round(Number(t.value)) || 7)); return edit((d) => (d.lookback_days = n)); }
  }
  function onInput(e) {
    const t = e.target;
    if (t.closest("[data-inc-form]")) return markDirty(t.closest("[data-inc-form]"));
    if (t.matches("[data-inc-q]")) { S.incQuery = t.value; const pos = t.selectionStart; render(); const q = document.querySelector("[data-inc-q]"); q?.focus(); q?.setSelectionRange(pos, pos); return; }
    const f = t.closest(".cp-redit"); if (f) preview(f);
  }
  async function onSubmit(e) {
    const form = e.target;
    if (form.matches(".cp-redit")) { e.preventDefault(); return applyDet(form); }
    if (form.matches("[data-inc-form]")) {
      e.preventDefault();
      const inc = S.incidents.find((x) => x.id === form.dataset.incForm), changes = readIncForm(form, inc);
      if (!Object.keys(changes).length) return;
      if ("title" in changes && !changes.title) return toast("The incident needs a title.");
      if (changes.aware_at === null) return toast("“Became aware” is required: the clocks start there.");
      const r = await patch(inc, changes, "Saved. The change is recorded in Activity.");
      if (r) { S.dirty = null; render(); }
      return;
    }
    if (form.matches("[data-obl-form]")) {
      e.preventDefault();
      const inc = S.incidents.find((x) => x.id === S.sel), key = form.dataset.oblForm, v = (n) => form.querySelector(`[name="${n}"]`)?.value;
      const doneAt = fromLocalInput(v("done_at"));
      if (!doneAt) return toast("Enter when it was sent.");
      if (new Date(doneAt) > Date.now() + 6e4) return toast("The sent time can't be in the future.");
      S.oblEdit = null;
      return patch(inc, { obligations: { [key]: { done_at: doneAt, ref: v("ref")?.trim(), note: v("note")?.trim(), count: v("count") === undefined || v("count") === "" ? null : Number(v("count")) } } }, `${OBL[key].label}: marked as sent.`);
    }
  }
  function bind() {
    $("brTabs").onclick = (e) => { const b = e.target.closest("[data-tab]"); if (b) { S.tab = b.dataset.tab; S.sel = null; render(); } };
    $("brRefresh").onclick = () => loadAll({ withPolicy: !S.draft });
    $("brReport").onclick = openReport;
    $("brSave").onclick = save;
    $("brDiscard").onclick = () => { if (!window.confirm("Discard all unsaved detector and settings changes?")) return; S.draft = null; S.editDet = null; S.newDet = null; render(); };
    $("brDialogForm").addEventListener("submit", async (e) => {
      if (e.submitter?.value !== "ok") return;
      e.preventDefault();
      if (await submitReport(e.target)) $("brDialog").close();
    });
    const body = $("brBody");
    body.addEventListener("click", onClick);
    body.addEventListener("change", onChange);
    body.addEventListener("input", onInput);
    body.addEventListener("submit", onSubmit);
    body.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches("tr[data-inc]")) e.target.click(); });
  }

  return {
    show() { if (!S.started) { S.started = true; bind(); } if (!S.policy || S.error) loadAll(); else render(); },
    tick(ticks) {
      const a = document.activeElement;
      const editing = S.editDet || S.newDet || S.picking || S.oblEdit || S.dirty || $("brDialog").open || ($("view-breach").contains(a) && /SELECT|INPUT|TEXTAREA/.test(a.tagName));
      if (ticks % 8 === 0 && S.started && !S.busy && !editing) loadAll({ withPolicy: !S.draft }); // every ~15 s
      else if (S.tab === "model" && ticks % 5 === 0 && S.started && !S.modelBusy && !editing && AN().enabled && $("view-breach").offsetParent) loadModel(false, true); // live scores every 10 s
    },
    // For the main dashboard: loads once if needed, then reuses the last scan for 60 s.
    async summary() {
      if (!S.busy && (!S.scan || !S.loadedAt || Date.now() - S.loadedAt > 60000)) await loadAll({ withPolicy: !S.draft });
      if (!S.scan) return null;
      const open = S.incidents.filter(OPEN);
      const next = open.map((i) => ({ i, n: nextDeadline(i) })).filter((x) => x.n).sort((a, b) => a.n.due - b.n.due)[0];
      return { open: open.length, suspected: open.filter((i) => i.status === "suspected").length, total: S.incidents.length,
        signalsNew: allSignals().filter((s) => sigState(s) === "new").length, signals: allSignals().length,
        overdue: open.reduce((n, i) => n + clocks(i).filter((x) => x.state === "overdue").length, 0),
        next: next ? { id: next.i.id, label: next.n.label, text: clockText(next.n), state: next.n.state } : null,
        byDetector: [...(AN().enabled ? [ML_DET] : []), ...P().detectors.filter((d) => d.enabled)].map((d) => { const sg = S.scan.results[d.id]?.signals || []; return { name: d.name, category: d.category, signals: sg.length, fresh: sg.filter((x) => !S.scan.triage[x.id]).length }; }),
        detectorsOn: P().detectors.filter((d) => d.enabled).length, detectors: P().detectors.length, contactMissing: !P().contact?.email && !P().contact?.phone };
    },
    // For the AI assistant: detectors, signals and the register (no personal data is held here).
    async context() {
      await this.summary();
      if (!S.scan) return null;
      const txt = (h) => String(h).replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&#39;/g, "'");
      return {
        detectors_version: S.policy.version, scanned_at: S.loadedAt, lookback_days: P().lookback_days, clocks_hours: P().clocks,
        notice_contact_set: !!(P().contact?.email || P().contact?.phone), organisation: P().organisation,
        detectors: P().detectors.map((d) => ({ id: d.id, name: d.name, enabled: d.enabled, category: d.category, severity: d.severity, auto_open: d.auto_open, rule: txt(sentence(d)), ref: d.ref,
          lines_checked: S.scan.results[d.id]?.scanned, signals: S.scan.results[d.id]?.signals.length, error: S.scan.results[d.id]?.error })),
        anomaly_model: modelCtx(),
        signals: allSignals().slice(0, 60).map(incSig),
        incidents: S.incidents.map(incCtx),
      };
    },
    aiItem(ref) {
      const [kind, id] = ref.split(":");
      if (kind === "signal") { const s = sigById(id); if (!s) return null; const d = sdet(s) || {};
        return { name: `Breach signal: ${d.name} · ${s.group}`, question: "Is this signal a personal data breach? Explain what it means, what to check first, and whether I should open an incident.", text: JSON.stringify({ ...incSig(s), why: d.why, first_checks: d.steps, ref: d.ref, evidence_rows: (S.evidence[s.id]?.rows || []).slice(0, 25) }, null, 1) }; }
      if (kind === "model") return { name: "Breach anomaly model", question: "Explain how the anomaly model works, what it found in our logs, and whether the current sensitivity is right for us.", text: JSON.stringify({ model: modelCtx(), anomalies: allSignals().filter((x) => x.detector === ML).slice(0, 20).map(incSig) }, null, 1) };
      if (kind === "incident") { const i = S.incidents.find((x) => x.id === id); if (!i) return null;
        return { name: `Incident ${i.id}: ${i.title}`, question: "Review this incident: what is still missing, which deadlines are at risk, and what should I do next?", text: JSON.stringify(incCtx(i), null, 1) }; }
      return null;
    },
    _clocks: clocks, _notice: noticeText,
  };
})();
