/* Evidence & audit: NigraniAI's tamper-evident records as their own section.
   Every change to the system's records (policies, retention, breach detectors and incidents, access,
   plan, billing, readiness, exposure, data map, PII verdicts) and every activity record is fingerprinted
   (SHA-256) into a hash chain on the server (data/ledger.jsonl), sealed daily after midnight IST.
   This page verifies the chain, shows it as a timeline, lists what is protected, builds evidence packs
   for an auditor, checks a pack someone sends back, and hands any of it to the AI assistant.
   Server: GET /api/evidence, POST /api/evidence/verify | /pack | /check. Only names, times and
   fingerprints reach the browser, never record contents. Uses session / can / ME / show from app.js. */
const Evidence = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const FD = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short" });
  const dt = (v) => { if (!v) return "–"; const d = new Date(v); return isNaN(d) ? String(v) : F.format(d).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase()); };
  const dday = (iso) => { const d = new Date(`${iso}T00:00:00+05:30`); return isNaN(d) ? iso : FD.format(d); };
  const ago = (v) => {
    const s = (Date.now() - new Date(v)) / 1000;
    if (!v || isNaN(s)) return "–";
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  };
  const short = (h, n = 10) => (h ? `${h.slice(0, n)}…` : "–");
  const isoDay = (d) => new Date(d.getTime() + 330 * 6e4).toISOString().slice(0, 10);
  const canSee = () => can("readiness:Read") || can("readiness:VerifyIntegrity") || can("readiness:ExportEvidence");

  // Friendly names for the record files the ledger protects.
  const FILE_NAMES = { "policy.json": "Consent & purpose policy", "retention.json": "Retention schedule", "breach.json": "Breach detectors & clocks",
    "incidents.json": "Breach register", "iam.json": "Access policies & users", "plan.json": "Plan", "billing.json": "Billing & invoices",
    "readiness.json": "Readiness scores", "exposure.json": "Public exposure tests", "datamap.json": "Data map & declarations", "pii.json": "PII detection verdicts" };
  const HIST_NAMES = { history: "Consent policy", retention_history: "Retention schedule", breach_history: "Breach detectors" };
  function fileName(f) {
    if (FILE_NAMES[f]) return FILE_NAMES[f];
    const m = /^([a-z_]+)\/v(\d+)\.json$/.exec(f || "");
    return m && HIST_NAMES[m[1]] ? `${HIST_NAMES[m[1]]} · version ${m[2]}` : f || "record";
  }
  // Activity actions in plain words (the rest fall back to the raw action name).
  const ACTIONS = { "datamap.scan": "Data map scanned", "datamap.declare": "Data map declarations saved", "pii.scan": "PII detection scan", "pii.feedback": "PII verdict reviewed",
    "readiness.run": "Readiness score run", "exposure.run": "Public exposure test", "policy.update": "Consent policy changed", "retention.update": "Retention schedule changed",
    "breach.update": "Breach detectors changed", "incident.create": "Breach incident opened", "incident.update": "Breach incident updated", "iam.user.create": "User added",
    "iam.policy.save": "Access policy saved", "evidence.pack": "Evidence pack created", "integrity.verify": "Records verified", "integrity.broken": "Integrity problem found" };
  const actionText = (a) => ACTIONS[a] || (a || "Activity").replace(/[._]/g, " ").replace(/^\w/, (c) => c.toUpperCase());

  const KIND = {
    genesis: { icon: "★", label: "Ledger started", cls: "k-gen" },
    write: { icon: "✎", label: "Record saved", cls: "k-write" },
    audit: { icon: "•", label: "Activity", cls: "k-audit" },
    seal: { icon: "◆", label: "Daily seal", cls: "k-seal" },
    export: { icon: "⇩", label: "Evidence pack issued", cls: "k-export" },
    declared: { icon: "＋", label: "Record added", cls: "k-write" },
  };
  function entryTitle(e) {
    if (e.type === "write" || e.type === "declared") return fileName(e.file);
    if (e.type === "audit") return actionText(e.action);
    if (e.type === "seal") return `Seal for ${dday(e.day)}${e.entries != null ? ` · ${num(e.entries)} entries` : ""}`;
    if (e.type === "export") return `Pack ${e.from || "?"} → ${e.to || "?"}`;
    if (e.type === "genesis") return "Chain started";
    return e.type;
  }

  const S = { started: false, ev: null, err: "", busy: "", tab: "overview", filter: "all", check: null, drag: false, more: false };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r = await go();
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }

  async function load() { S.err = ""; try { S.ev = await api("/api/evidence"); } catch (e) { S.err = e.message; } }
  async function verifyNow() {
    S.busy = "verify"; render();
    try { const r = await api("/api/evidence/verify", { method: "POST" }); await load(); S.ev = { ...(S.ev || {}), ...r }; S.err = ""; toast(r.ok ? "Verified: every record matches the chain." : `${r.problem_count} problem(s) found.`); }
    catch (e) { S.err = e.message; }
    S.busy = ""; render();
  }
  async function makePack() {
    const from = $("evFrom")?.value, to = $("evTo")?.value;
    if (!from || !to || from > to) { S.err = "Choose a start date on or before the end date."; render(); return; }
    const w = window.open("", "_blank");
    S.busy = "pack"; render();
    try {
      const pk = await api("/api/evidence/pack", { method: "POST", body: JSON.stringify({ from, to }) });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(pk, null, 1)], { type: "application/json" }));
      a.download = `evidence-pack-${(pk.client?.id || "client")}-${pk.from}-to-${pk.to}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      if (w) { w.document.open(); w.document.write(packReport(pk)); w.document.close(); }
      await load(); toast("Evidence pack created and recorded in the chain.");
    } catch (e) { S.err = e.message; if (w) w.close(); }
    S.busy = ""; render();
  }
  async function checkPack(file) {
    S.busy = "check"; S.check = null; render();
    try {
      let pk; try { pk = JSON.parse(await file.text()); } catch { throw new Error("That file isn't valid JSON."); }
      S.check = await api("/api/evidence/check", { method: "POST", body: JSON.stringify(pk) }); S.check.name = file.name;
    } catch (e) { S.check = { error: e.message, name: file.name }; }
    S.busy = ""; render();
  }
  function toast(msg) {
    const t = $("evToast"); if (!t) return;
    t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 3200);
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
      <div class="box"><b>Pack fingerprint (SHA-256)</b><div class="mono">${esc(pk.fingerprint)}</div><span class="muted">Recorded in the system's ledger. Anyone can check this pack later in Evidence &amp; audit → Check a pack; any edit to the file changes the fingerprint.</span></div>
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

  /* ---------- page parts ---------- */
  const ruleText = (r) => `${r.id} ${r.name}: ${Math.round(r.keep_days)} days` + (r.action === "delete" ? ", then delete" : r.action ? `, then ${r.action}` : " minimum");
  const kindsBroken = (v) => new Set((v.problems || []).map((p) => p.kind));

  function hero(v) {
    const ok = v.ok, b = kindsBroken(v);
    return `<section class="panel dm-hero ev2-hero ${ok ? "is-ok" : "is-bad"}">
      <div class="dm-htext">
        <div class="dm-erow"><span class="dm-eyebrow">DPDP Act s.8(5) · Rule 6(1)(e) · tamper-evident records</span>
          <span class="dm-live ${ok ? "" : "bad"}">${ok ? "Intact" : "Attention"}</span></div>
        <h2>${ok ? "Every record matches its fingerprint" : `${num(v.problem_count)} record(s) were changed outside the system`}</h2>
        <p class="muted">Each change to NigraniAI’s records and every activity entry is fingerprinted into a tamper-evident chain, sealed every night. Last verified ${esc(ago(v.checked_at))}.</p>
        ${S.err ? `<p class="cp-red">${esc(S.err)}</p>` : ""}
        <div class="dm-hacts">
          ${can("readiness:VerifyIntegrity") ? `<button class="btn primary${S.busy === "verify" ? " loading" : ""}" data-act="verify" ${S.busy ? "disabled" : ""}>${S.busy === "verify" ? "Verifying…" : "Verify now"}</button>` : ""}
          ${can("readiness:ExportEvidence") ? `<button class="btn ghost" data-act="tab" data-tab="packs">Create evidence pack</button>` : ""}
          <button class="btn ghost ai-ask" data-ask-ai="evidence">✦ Ask AI</button>
        </div>
      </div>
      <div class="ev2-seal">
        <div class="ev2-shield ${ok ? "ok" : "bad"}" aria-hidden="true">
          <svg viewBox="0 0 64 64"><path d="M32 5 9 14v16c0 15 10 26 23 30 13-4 23-15 23-30V14L32 5Z" class="ev2-sh"/>${ok ? `<path d="m21 32 8 8 15-16" class="ev2-tick"/>` : `<path d="m23 23 18 18M41 23 23 41" class="ev2-tick"/>`}</svg>
        </div>
        <ul class="ev2-checks">
          ${[["ledger", "Chain links"], ["file", "Record files"], ["audit", "Activity log"]].map(([k, l]) => `<li class="${b.has(k) ? "bad" : "ok"}"><i>${b.has(k) ? "✕" : "✓"}</i>${l}</li>`).join("")}
        </ul>
        <div class="ev2-fp"><span>Chain fingerprint</span><code title="${esc(v.head)}">${esc(short(v.head, 14))}</code><button class="btn ghost sm" data-act="copy" data-copy="${esc(v.head)}">Copy</button></div>
      </div>
    </section>`;
  }

  function tiles(v) {
    const lastSeal = (v.seals || []).slice(-1)[0];
    const t = [
      ["Chain entries", num(v.entries), `since ${v.since ? dday(isoDay(new Date(v.since))) : "–"}`],
      ["Activity records", num(v.audit_records), "who did what, and when"],
      ["Protected records", num(v.files_tracked), "files fingerprinted"],
      ["Daily seals", num((v.seals || []).length), lastSeal ? `last ${dday(lastSeal.day)}` : "first after midnight"],
      ["Evidence packs", num((v.exports || []).length), "issued to auditors"],
    ];
    return `<div class="dm-tiles ev2-tiles">${t.map(([l, b, s]) => `<div class="panel dm-tile"><span>${esc(l)}</span><b>${b}</b><small class="muted">${esc(s)}</small></div>`).join("")}</div>`;
  }

  function tabs() {
    const T = [["overview", "Overview"], ["chain", "Chain timeline"], ...(can("readiness:ExportEvidence") || can("readiness:VerifyIntegrity") ? [["packs", "Evidence packs"]] : []), ["seals", "Daily seals"], ["how", "How it works"]];
    return `<div class="cp-tabs dm-tabs" role="tablist">${T.map(([k, l]) => `<button role="tab" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}" data-act="tab" data-tab="${k}">${esc(l)}${k === "overview" && S.ev?.problem_count ? ` <span class="count">${S.ev.problem_count}</span>` : ""}</button>`).join("")}</div>`;
  }

  function activityChart(v) {
    const days = v.per_day || [];
    if (!days.length) return "";
    const max = Math.max(...days.map((d) => d.entries), 1);
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>Chain activity</h3><span class="muted">entries per day, last ${days.length} day(s)</span></div>
      <div class="ev2-bars">${days.map((d) => `<div class="ev2-bar" title="${esc(dday(d.day))}: ${num(d.entries)} entries"><i style="height:${Math.max(6, Math.round((d.entries / max) * 100))}%"></i><span>${esc(dday(d.day).split(" ")[0])}</span></div>`).join("")}</div></section>`;
  }

  function overview(v) {
    const lr = v.log_retention || {}, prot = v.protected || [];
    const problems = (v.problems || []).map((p, i) => `<li class="bad"><i>✕</i><div><b>${esc(p.text)}</b>${p.at ? `<small>${esc(dt(p.at))}</small>` : ""}</div><button class="btn ghost sm ai-ask" data-ask-ai="evidence:problem:${i}">✦ Ask AI</button></li>`).join("");
    return `
      ${problems ? `<section class="panel ev2-card ev2-alert"><h3>What changed outside the system</h3><ul class="rd-finds">${problems}</ul>
        <p class="muted">Changes made by hand on the server show up here. Find out who had server access, restore the record from its last version, and treat it as a possible breach (Breach Response).</p></section>` : ""}
      <div class="ev2-grid">
        <section class="panel ev2-card"><div class="ev2-ch"><h3>Protected records</h3><span class="muted">last change to each record</span></div>
          ${prot.length ? `<ul class="ev2-files">${prot.map((f) => `<li><span class="ev2-fi">✎</span><div><b>${esc(fileName(f.file))}</b><small>${esc(ago(f.at))} · ${num(f.writes)} change(s) · <code>${esc(short(f.sha, 8))}</code></small></div></li>`).join("")}</ul>` : `<p class="muted">No record has changed since the chain started.</p>`}
        </section>
        <div class="ev2-col">
          <section class="panel ev2-card"><div class="ev2-ch"><h3>Log retention</h3><span class="muted">Rule 6(1)(e): keep logs ≥ 1 year</span></div>
            <ul class="rd-finds">
              <li class="${lr.ok ? "ok" : "bad"}"><i>${lr.ok ? "✓" : "✕"}</i><div><b>${lr.ok ? "No rule deletes logs before one year." : esc((lr.findings || []).join(" "))}</b>${!lr.ok ? `<span>Change it in Retention → Rules.</span>` : ""}<small>${esc((lr.rules || []).map(ruleText).join(" · ") || "No rule covers the logs.")}</small></div></li>
              <li class="ok"><i>i</i><div><b>${lr.oldest ? `Logs go back to ${esc(dt(lr.oldest))}.` : esc(lr.error || "No log lines yet.")}</b>${lr.days != null && lr.days < 365 ? `<span>Logging began less than a year ago, so a full year can’t be shown yet; nothing is set to delete them early.</span>` : ""}</div></li>
            </ul>
          </section>
          ${activityChart(v)}
        </div>
      </div>`;
  }

  function chain(v) {
    const all = v.chain || [], F2 = [["all", "All"], ["write", "Records"], ["audit", "Activity"], ["seal", "Seals"], ["export", "Packs"]];
    const full = S.filter === "all" ? all : all.filter((e) => e.type === S.filter || (S.filter === "write" && e.type === "declared"));
    const list = S.more ? full : full.slice(0, 12);
    return `<section class="panel ev2-card">
      <div class="ev2-ch"><h3>Chain timeline</h3><span class="muted">latest ${num(all.length)} of ${num(v.entries)} entries · each one holds the fingerprint of the one before</span></div>
      <div class="ev2-filters">${F2.map(([k, l]) => `<button class="chip${S.filter === k ? " on" : ""}" data-act="filter" data-f="${k}">${l}</button>`).join("")}</div>
      ${list.length ? `<ol class="ev2-chain">${list.map((e, i) => {
        const K = KIND[e.type] || { icon: "•", label: e.type, cls: "" }, next = full[i + 1];
        const linked = !next || S.filter !== "all" || next.hash === e.prev;
        return `<li class="${K.cls}">
          <span class="ev2-node" aria-hidden="true">${K.icon}</span>
          <div class="ev2-block">
            <div class="ev2-bh"><b>${esc(entryTitle(e))}</b><span class="ev2-k">${esc(K.label)}</span><span class="muted ev2-at" title="${esc(dt(e.at))}">#${num(e.seq)} · ${esc(ago(e.at))}</span></div>
            <div class="ev2-hash"><span>hash <code>${esc(short(e.hash, 12))}</code></span><span class="${linked ? "ok" : "bad"}">${linked ? "↳ links to" : "✕ broken link to"} <code>${esc(short(e.prev, 12))}</code></span>${e.by ? `<span class="muted">by ${esc(e.by)}</span>` : ""}</div>
          </div></li>`;
      }).join("")}</ol>${full.length > list.length ? `<button class="btn ghost sm ev2-more" data-act="more">Show ${num(full.length - list.length)} more</button>` : ""}` : `<p class="muted">Nothing of this kind in the latest entries.</p>`}
    </section>`;
  }

  function packs(v) {
    const today = new Date(), c = S.check, ex = (v.exports || []).slice().reverse();
    const preset = (d, l) => `<button class="chip" data-act="preset" data-days="${d}">${l}</button>`;
    return `<div class="ev2-grid">
      ${can("readiness:ExportEvidence") ? `<section class="panel ev2-card"><div class="ev2-ch"><h3>Create an evidence pack</h3><span class="muted">for an auditor or the Data Protection Board</span></div>
        <p class="muted">One file with integrity and seals, log retention, readiness scores, the exposure test, the breach register, policy versions, access and the activity log for the period. It downloads as JSON and opens as a printable report (save it as PDF). Its fingerprint is recorded in the chain.</p>
        <div class="ev2-presets">${preset(30, "Last 30 days")}${preset(90, "Last 90 days")}${preset(365, "Last year")}</div>
        <div class="ev-form"><label>From <input type="date" id="evFrom" value="${isoDay(new Date(today.getTime() - 90 * 864e5))}" max="${isoDay(today)}"></label><label>To <input type="date" id="evTo" value="${isoDay(today)}" max="${isoDay(today)}"></label>
          <button class="btn primary" data-act="pack" ${S.busy ? "disabled" : ""}>${S.busy === "pack" ? "Building…" : "Create pack"}</button></div>
      </section>` : ""}
      ${can("readiness:VerifyIntegrity") ? `<section class="panel ev2-card"><div class="ev2-ch"><h3>Check a pack</h3><span class="muted">is it genuine and unedited?</span></div>
        <label class="ev2-drop${S.drag ? " drag" : ""}" id="evDrop"><input type="file" id="evCheck" accept=".json,application/json" hidden>
          <span class="ev2-dicon">⇪</span><b>${S.busy === "check" ? "Checking…" : "Drop a pack file here"}</b><small class="muted">or click to choose the JSON file</small></label>
        ${c ? (c.error ? `<p class="cp-red">${esc(c.name)}: ${esc(c.error)}</p>` : `<ul class="rd-finds ev-check">
          <li class="${c.unchanged ? "ok" : "bad"}"><i>${c.unchanged ? "✓" : "✕"}</i><div><b>${c.unchanged ? "Unchanged since it was created." : "The file was edited after it was created."}</b><small>${esc(c.name)} · ${esc(c.client || "")} · ${esc(c.from)} → ${esc(c.to)}</small></div></li>
          <li class="${c.recorded ? "ok" : "bad"}"><i>${c.recorded ? "✓" : "✕"}</i><div><b>${c.recorded ? `Issued by this system on ${esc(dt(c.recorded_at))} by ${esc(c.recorded_by)}.` : "This system has no record of issuing this pack."}</b></div></li></ul>
          <button class="btn ghost sm ai-ask" data-ask-ai="evidence:check">✦ Ask AI about this result</button>`) : ""}
      </section>` : ""}
    </div>
    <section class="panel ev2-card"><div class="ev2-ch"><h3>Packs issued</h3><span class="muted">${num(ex.length)} recorded in the chain</span></div>
      ${ex.length ? `<table class="ev-table"><thead><tr><th>When</th><th>By</th><th>Period</th><th>Fingerprint</th></tr></thead><tbody>${ex.map((x) => `<tr><td>${esc(dt(x.at))}</td><td>${esc(x.by)}</td><td>${esc(x.from)} → ${esc(x.to)}</td><td><code title="${esc(x.sha)}">${esc(short(x.sha, 16))}</code></td></tr>`).join("")}</tbody></table>` : `<p class="muted">No pack has been created yet.</p>`}
    </section>`;
  }

  function seals(v) {
    const by = Object.fromEntries((v.seals || []).map((s) => [s.day, s])), cells = [], today = new Date();
    for (let i = 29; i >= 0; i--) {
      const d = isoDay(new Date(today.getTime() - i * 864e5)), s = by[d];
      cells.push(`<div class="ev2-day ${s ? (s.intact === false ? "bad" : "ok") : i === 0 ? "today" : "none"}" title="${esc(dday(d))}: ${s ? (s.intact === false ? "sealed while broken" : "sealed, intact") : i === 0 ? "sealed after midnight" : "no seal"}"><span>${esc(dday(d).split(" ")[0])}</span></div>`);
    }
    const list = (v.seals || []).slice().reverse();
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>Last 30 days</h3><span class="muted">each night after midnight IST the day’s records are sealed with one fingerprint</span></div>
      <div class="ev2-cal">${cells.join("")}</div>
      <div class="ev2-legend"><span><i class="ok"></i>Sealed, intact</span><span><i class="bad"></i>Sealed while broken</span><span><i class="none"></i>No seal (service off or before the chain)</span></div></section>
    <section class="panel ev2-card"><div class="ev2-ch"><h3>Seals</h3><span class="muted">${num(list.length)} recorded</span></div>
      ${list.length ? `<table class="ev-table"><thead><tr><th>Day</th><th>Chain fingerprint at the end of the day</th><th>Entries</th><th>State</th></tr></thead><tbody>${list.map((x) => `<tr><td>${esc(dday(x.day))}</td><td><code title="${esc(x.head)}">${esc(short(x.head, 24))}</code></td><td>${num(x.entries)}</td><td>${x.intact === false ? `<span class="cp-red">broken</span>` : `<span class="dm-good">intact</span>`}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">The first seal is made after midnight IST.</p>`}
    </section>`;
  }

  function how() {
    const steps = [["✎", "Fingerprint", "Every saved record and activity entry gets a SHA-256 fingerprint: change one character and the fingerprint changes completely."],
      ["⛓", "Chain", "Each entry also holds the fingerprint of the entry before it, so editing, deleting or reordering any past entry breaks every link after it."],
      ["◆", "Seal", "After midnight IST the whole day is sealed with one fingerprint. A later rewrite of that day no longer matches its seal."],
      ["✓", "Verify", "Verify re-reads every record file and the activity log and compares them with the chain. It also runs on its own every day."]];
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>How the records are protected</h3><span class="muted">DPDP Act s.8(1) accountability · s.8(5) safeguards</span></div>
      <ol class="ev2-steps">${steps.map(([i, t, d], n) => `<li><span class="ev2-si">${i}</span><b>${n + 1}. ${t}</b><p class="muted">${d}</p></li>`).join("")}</ol></section>
    <section class="panel ev2-card ex-note"><h3>Good practice</h3>
      <p class="muted">The chain lives on the same server as the records. Someone with full server access could in theory rewrite everything consistently, so keep a copy of the chain fingerprint somewhere else: it is printed in every evidence pack, or copy it from the top of this page once a month. A pack an auditor already holds would no longer match a rewritten history.</p>
      <p class="muted">Changes made through the dashboard are always fine: they are saved with a new version and a new chain entry. Usage meter totals are not part of the chain because they change every few seconds.</p>
      <button class="btn ghost sm ai-ask" data-ask-ai="evidence:how">✦ Ask AI how to strengthen this</button></section>`;
  }

  function render() {
    const body = $("evBody"); if (!body) return;
    if (!canSee()) { body.innerHTML = `<div class="panel cp-empty"><h3>Evidence & audit</h3><p>You don’t have access to the evidence records. Ask the root user.</p></div>`; return; }
    const v = S.ev;
    if (!v) { body.innerHTML = S.err ? `<div class="panel cp-empty"><h3>Evidence & audit</h3><p class="cp-red">${esc(S.err)}</p><button class="btn ghost" data-act="reload">Try again</button></div>` : `<div class="panel cp-empty"><h3>Checking your records…</h3><p class="muted">Re-reading every record file against the chain.</p></div>`; return; }
    const part = S.tab === "chain" ? chain(v) : S.tab === "packs" ? packs(v) : S.tab === "seals" ? seals(v) : S.tab === "how" ? how() : overview(v);
    body.innerHTML = hero(v) + tiles(v) + tabs() + `<div class="ev2-part">${part}</div>`;
  }

  function bind() {
    const body = $("evBody");
    body.addEventListener("change", (e) => { if (e.target.id === "evCheck" && e.target.files[0]) checkPack(e.target.files[0]); });
    body.addEventListener("dragover", (e) => { if (e.target.closest("#evDrop")) { e.preventDefault(); if (!S.drag) { S.drag = true; e.target.closest("#evDrop").classList.add("drag"); } } });
    body.addEventListener("dragleave", (e) => { if (e.target.closest("#evDrop")) { S.drag = false; e.target.closest("#evDrop").classList.remove("drag"); } });
    body.addEventListener("drop", (e) => { if (!e.target.closest("#evDrop")) return; e.preventDefault(); S.drag = false; const f = e.dataTransfer.files[0]; if (f) checkPack(f); });
    body.addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      const a = b.dataset.act;
      if (a === "tab") { S.tab = b.dataset.tab; render(); return; }
      if (a === "filter") { S.filter = b.dataset.f; S.more = false; render(); return; }
      if (a === "more") { S.more = true; render(); return; }
      if (a === "verify") return verifyNow();
      if (a === "pack") return makePack();
      if (a === "reload") { load().then(render); return; }
      if (a === "preset") { const t = new Date(); $("evFrom").value = isoDay(new Date(t.getTime() - Number(b.dataset.days) * 864e5)); $("evTo").value = isoDay(t); return; }
      if (a === "copy") { navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500); }); }
    });
  }

  // What the AI may see: status, counts, problem texts, names, times and short fingerprints. No record contents.
  function context() {
    const v = S.ev; if (!v) return null;
    return {
      records_intact: v.ok, problems: (v.problems || []).map((p) => ({ kind: p.kind, text: p.text, at: p.at })), checked_at: v.checked_at, chain_started: v.since,
      chain_entries: v.entries, entries_by_type: v.by_type, activity_records: v.audit_records, protected_records: v.files_tracked,
      protected: (v.protected || []).map((f) => ({ record: fileName(f.file), last_change: f.at, changes: f.writes })),
      daily_seals: (v.seals || []).slice(-14).map((s) => ({ day: s.day, intact: s.intact !== false, entries: s.entries })),
      evidence_packs: (v.exports || []).map((x) => ({ at: x.at, by: x.by, period: `${x.from} to ${x.to}` })),
      log_retention: { ok: v.log_retention?.ok, oldest_log: v.log_retention?.oldest, days_of_logs: v.log_retention?.days != null ? Math.floor(v.log_retention.days) : null, findings: v.log_retention?.findings, rules: (v.log_retention?.rules || []).map(ruleText) },
      recent_chain: (v.chain || []).slice(0, 15).map((e) => `#${e.seq} ${e.type}: ${entryTitle(e)} (${e.at})`),
    };
  }

  return {
    async show() {
      if (!S.started) { S.started = true; bind(); }
      render();
      if (canSee()) { await load(); render(); }
    },
    context: async () => { if (!S.ev && canSee()) await load(); return context(); },
    aiItem(arg = "") {
      const ctx = context(); if (!ctx) return null;
      const [what, i] = arg.split(":");
      if (what === "problem") {
        const p = S.ev.problems?.[Number(i)]; if (!p) return null;
        return { name: "Evidence integrity problem", question: "A record was changed outside NigraniAI. What does this mean, how serious is it under the DPDP Act, and exactly what should I do now?", text: JSON.stringify({ problem: p, ...ctx }, null, 1) };
      }
      if (what === "check" && S.check && !S.check.error) {
        const c = S.check;
        return { name: `Evidence pack check: ${c.name}`, question: "Explain this evidence pack check result: can I rely on this pack, and what should I tell the auditor?", text: JSON.stringify({ pack_check: { file: c.name, unchanged: c.unchanged, issued_by_this_system: c.recorded, issued_at: c.recorded_at, issued_by: c.recorded_by, period: `${c.from} to ${c.to}` }, ...ctx }, null, 1) };
      }
      if (what === "how") return { name: "Evidence & audit setup", question: "How can we make our evidence ledger stronger against someone with full server access, and what should our monthly evidence routine be?", text: JSON.stringify(ctx, null, 1) };
      return { name: `Evidence & audit · ${ctx.records_intact ? "records intact" : `${ctx.problems.length} problem(s)`}`, question: "Explain my evidence and audit status: are my records trustworthy, am I ready to show an auditor, and what should I do next?", text: JSON.stringify(ctx, null, 1) };
    },
    access() { if (S.started) render(); },
  };
})();
