/* Usage & plan: what the company (or this person) has used in the billing cycle, against the plan.
   Meters are counted by consent_service (the browser can't change them): log lines analysed,
   detector and model runs, AI questions / tokens / files, customer lookups, incidents, API
   requests and seats. The plan (set by whoever has usage:ManagePlan) gives each billed meter an
   allowance, an overage price and, for AI, lookups and seats only, a hard limit. Monitoring is
   never blocked. Uses session / refreshSession / can / show / ME from app.js. */
const Usage = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const inr = (n) => `₹${Number(n || 0).toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;
  const compact = (n) => { n = Number(n || 0); return n >= 1e7 ? `${+(n / 1e7).toFixed(2)} Cr` : n >= 1e5 ? `${+(n / 1e5).toFixed(2)} L` : n >= 1e3 ? `${+(n / 1e3).toFixed(1)}k` : num(n); };
  const F_DAY = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short" });
  const F_FULL = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric" });
  const F_DT = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  const dt = (v) => F_DT.format(new Date(v)).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase());
  const BLOCK = { 1: "", 1000: "per 1,000", 10000: "per 10,000", 100000: "per 1 lakh" };
  const unitPrice = (m) => (m.unit_size === 1 ? `per ${m.unit.replace(/s$/, "")}` : `${BLOCK[m.unit_size] || `per ${num(m.unit_size)}`} ${m.unit}`);

  const S = { r: null, scope: null, tab: "overview", meter: "logs.analysed", draft: null, busy: false, err: "", loadedAt: 0, started: false };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r;
    try { r = await go(); } catch { throw new Error("The consent service isn't running."); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), { status: r.status, body: j });
    return j;
  }
  async function load() {
    if (S.scope === null) S.scope = can("usage:ViewAllUsage") ? "all" : "me";
    S.busy = true;
    try { S.r = await api(`/api/usage?scope=${S.scope}`); S.err = ""; S.loadedAt = Date.now(); }
    catch (e) { S.err = e.message; }
    S.busy = false;
    render();
  }
  let toastT;
  function toast(m, ok = false) { const t = $("usToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }
  const level = (pct) => (pct == null ? "" : pct >= 100 ? "bad" : pct >= 80 ? "warn" : "ok");

  /* ---------- shell ---------- */
  function render() {
    const body = $("usBody");
    if (!body) return;
    if (S.err && !S.r) { body.innerHTML = `<div class="panel cp-empty"><h3>Usage isn't available</h3><p>${esc(S.err)}</p></div>`; return; }
    if (!S.r) { body.innerHTML = `<div class="panel cp-empty"><p>Loading usage…</p></div>`; return; }
    const r = S.r, tabs = [["overview", "Overview"], ...(r.scope === "all" ? [["users", "By user"]] : []), ...(can("usage:ManagePlan") ? [["plan", "Plan & limits"]] : []), ...(can("billing:ViewInvoices") ? [["billing", "Billing"]] : [])];
    if (!tabs.some((t) => t[0] === S.tab)) S.tab = "overview";
    body.innerHTML = heroHtml(r) + alertsHtml(r)
      + `<div class="cp-tabs us-tabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}" data-utab="${k}">${esc(l)}</button>`).join("")}</div>`
      + ({ overview: overviewHtml, users: usersHtml, plan: planHtml, billing: () => `<div id="billBox"></div>` }[S.tab])(r);
    if (S.tab === "billing" && typeof Billing !== "undefined") Billing.mount($("billBox"));
  }
  function heroHtml(r) {
    const c = r.cycle, end = new Date(new Date(c.end).getTime() - 1);
    return `<section class="panel us-hero">
      <div class="us-hhead">
        <div><span class="us-plan">${esc(r.plan.name)} plan</span>
          <h3>${esc(F_DAY.format(new Date(c.start)))} – ${esc(F_FULL.format(end))}</h3>
          <p class="muted">${c.days_left === 0 ? "Last day of this billing cycle" : `${num(c.days_left)} day${c.days_left === 1 ? "" : "s"} left in this billing cycle`}${r.scope === "me" ? " · showing your own usage; allowances are for the whole company" : ""}</p></div>
        <div class="us-hact">
          ${can("usage:ViewAllUsage") ? `<div class="seg us-scope" role="radiogroup" aria-label="Whose usage"><button role="radio" aria-checked="${S.scope === "all"}" class="${S.scope === "all" ? "on" : ""}" data-scope="all">Everyone</button><button role="radio" aria-checked="${S.scope === "me"}" class="${S.scope === "me" ? "on" : ""}" data-scope="me">Just me</button></div>` : ""}
          <button class="btn ghost" data-act="csv">Export CSV</button>
          ${can("usage:ManagePlan") ? `<button class="btn primary" data-utab="plan">Change plan</button>` : ""}
        </div>
      </div>
      <div class="us-cycle" title="${Math.round(c.elapsed * 100)}% of the cycle has passed"><i style="width:${(c.elapsed * 100).toFixed(1)}%"></i></div>
      ${r.scope === "all" || can("usage:ViewAllUsage") ? `<div class="us-bill">
        <div><span>Monthly fee</span><b>${inr(r.estimate.base_fee)}</b></div>
        <div><span>Overage so far</span><b class="${r.estimate.overage ? "us-red" : ""}">${inr(r.estimate.overage)}</b></div>
        <div><span>Bill so far</span><b>${inr(r.estimate.total)}</b><small>before GST</small></div>
        <div><span>Forecast for the cycle</span><b class="${r.estimate.forecast_total > r.estimate.total ? "us-amber" : ""}">${inr(r.estimate.forecast_total)}</b><small>if usage continues at this rate</small></div>
      </div>` : ""}
    </section>`;
  }
  function alertsHtml(r) {
    const hot = r.meters.filter((m) => m.billed && m.pct != null && m.pct >= 80);
    if (!hot.length) return "";
    return `<div class="cp-warn us-alert" role="alert"><b>${hot.some((m) => m.pct >= 100) ? "A plan allowance is used up." : "Close to a plan allowance."}</b>
      <span>${hot.map((m) => `${esc(m.label)}: ${num(m.org_used)} of ${num(m.included)} (${Math.round(m.pct)}%)${m.pct >= 100 ? (m.hard ? " · blocked until the cycle resets" : ` · overage ${inr(m.overage_cost)} so far`) : ""}`).join(" · ")}${can("usage:ManagePlan") ? ` <button class="link" data-utab="plan">Change the plan</button>` : " Ask the workspace owner to raise the limit."}</span></div>`;
  }

  /* ---------- overview ---------- */
  function card(m) {
    const pct = m.pct, cls = level(pct), sel = S.meter === m.key, mine = S.r.scope === "me";
    const used = mine ? m.mine : m.org_used;
    return `<button class="panel us-card ${cls}${sel ? " sel" : ""}" data-meter="${esc(m.key)}" aria-pressed="${sel}" title="${esc(m.desc)}">
      <span class="us-clabel">${esc(m.label)}${m.hard ? ` <span class="us-tag hard" title="Requests are refused at the limit">hard limit</span>` : m.included != null ? ` <span class="us-tag" title="Usage continues; extra is billed">soft</span>` : ""}</span>
      <b>${compact(used)}</b>
      <span class="us-of">${m.included == null ? "Unlimited" : `of ${compact(m.included)} ${esc(m.unit)}${mine ? " for the company" : ""}`}</span>
      ${m.included != null ? `<span class="us-bar"><i style="width:${Math.min(100, pct || 0).toFixed(1)}%"></i><em></em></span>` : `<span class="us-bar none"></span>`}
      <small>${m.kind === "gauge" ? `${num(m.org_used)} now` : `${mine ? `company ${compact(m.org_used)} · ` : ""}on track for ${compact(m.forecast)}`}${m.overage_cost ? ` · <span class="us-red">overage ${inr(m.overage_cost)}</span>` : m.forecast_cost ? ` · <span class="us-amber">forecast overage ${inr(m.forecast_cost)}</span>` : ""}${m.my_cap != null ? ` · your cap ${num(m.my_cap)}` : ""}</small>
    </button>`;
  }
  function overviewHtml(r) {
    const billed = r.meters.filter((m) => m.billed), info = r.meters.filter((m) => !m.billed);
    const m = r.meters.find((x) => x.key === S.meter) || billed[0];
    return `<div class="us-cards">${billed.map(card).join("")}</div>
      <section class="panel us-sec">
        <div class="cp-list-head flat"><h3>${esc(m.label)} this cycle</h3><span class="muted">${esc(m.desc)}</span></div>
        <div class="cp-chips us-mchips">${r.meters.filter((x) => x.kind === "meter").map((x) => `<button class="cp-chip${x.key === m.key ? " on" : ""}" data-meter="${esc(x.key)}">${esc(x.label)}</button>`).join("")}</div>
        ${m.kind === "gauge" ? `<p class="muted">Users are counted as they are now: ${num(m.org_used)} of ${m.included == null ? "unlimited" : num(m.included)}.</p>` : chartHtml(r, m)}
      </section>
      <section class="panel us-sec">
        <div class="cp-list-head flat"><h3>Activity</h3><span class="muted">Counted for transparency; not billed</span></div>
        <div class="us-info">${info.map((x) => `<button class="us-irow${x.key === m.key ? " on" : ""}" data-meter="${esc(x.key)}"><span><b>${esc(x.label)}</b><small>${esc(x.desc)}</small></span><b>${num(r.scope === "me" ? x.mine : x.org_used)}</b></button>`).join("")}</div>
      </section>
      <p class="rt-note">Meters are counted by the consent service and can't be changed from the browser. “Log lines analysed” counts each log line once, the first time it is read. Breach monitoring is never blocked by a limit: extra lines are billed as overage. Prices exclude GST.</p>`;
  }
  // Daily columns plus the running total against the allowance, with the forecast to the cycle end.
  function chartHtml(r, m) {
    const c = r.cycle, start = new Date(c.start), end = new Date(c.end), days = [];
    for (let d = new Date(start); d < end; d = new Date(d.getTime() + 864e5)) days.push(new Date(d.getTime() + 330 * 6e4).toISOString().slice(0, 10));
    const vals = days.map((d) => r.daily[d]?.[m.key] || 0);
    const today = new Date(Date.now() + 330 * 6e4).toISOString().slice(0, 10), ti = Math.max(0, days.indexOf(today));
    let run = 0; const cum = vals.map((v, i) => (i <= ti ? (run += v) : null));
    const total = run, forecast = r.scope === "all" ? m.forecast : Math.round(total / Math.max(c.elapsed, 1e-6));
    const inc = r.scope === "all" ? m.included : null;
    const W = 1000, H = 250, L = 56, R = 16, T = 14, B = 30;
    // Keep the running total readable: the allowance only sets the scale when it is in reach.
    const reach = Math.max(1, forecast, total), showInc = inc != null && inc <= reach * 3;
    const top = Math.max(reach, showInc ? inc : 0) * 1.12, maxDay = Math.max(1, ...vals);
    const X = (i) => L + (i + 0.5) * ((W - L - R) / days.length), Y = (v) => T + (1 - v / top) * (H - T - B), YD = (v) => H - B - (v / maxDay) * (H - T - B) * 0.45;
    const bw = Math.max(3, ((W - L - R) / days.length) * 0.6);
    const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => top * f);
    const grid = ticks.map((v) => `<line class="ch-grid" x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="ch-ax" x="${L - 8}" y="${Y(v) + 4}" text-anchor="end">${esc(compact(Math.round(v)))}</text>`).join("");
    const step = Math.ceil(days.length / 8);
    const xl = days.map((d, i) => (i % step === 0 ? `<text class="ch-ax" x="${X(i)}" y="${H - 9}" text-anchor="middle">${esc(F_DAY.format(new Date(`${d}T12:00:00+05:30`)))}</text>` : "")).join("");
    const bars = vals.map((v, i) => (v ? `<rect class="us-day" x="${X(i) - bw / 2}" y="${YD(v)}" width="${bw}" height="${H - B - YD(v)}" rx="2"><title>${esc(days[i])}: ${num(v)} ${esc(m.unit)}</title></rect>` : "")).join("");
    const line = cum.map((v, i) => (v == null ? "" : `${i === 0 || cum[i - 1] == null ? "M" : "L"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`)).join("");
    const area = `${line}L${X(ti).toFixed(1)},${H - B}L${X(0).toFixed(1)},${H - B}Z`;
    const fc = ti < days.length - 1 ? `<path class="us-fc" d="M${X(ti).toFixed(1)},${Y(total).toFixed(1)}L${X(days.length - 1).toFixed(1)},${Y(forecast).toFixed(1)}"/>` : "";
    const incLine = inc != null && !showInc ? `<text class="us-inclabel" x="${W - R}" y="${T + 4}" text-anchor="end">allowance ${esc(compact(inc))}: far above this scale</text>` : inc != null ? `<line class="us-inc" x1="${L}" x2="${W - R}" y1="${Y(inc)}" y2="${Y(inc)}"/><text class="us-inclabel" x="${W - R}" y="${Y(inc) - 6}" text-anchor="end">allowance ${esc(compact(inc))}</text>` : "";
    return `<svg class="us-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(m.label)}: ${num(total)} so far this cycle, forecast ${num(forecast)}">
        ${grid}${xl}${bars}<path class="us-area" d="${area}"/><path class="us-line" d="${line}"/>${fc}${incLine}
        <circle class="us-now" cx="${X(ti)}" cy="${Y(total)}" r="4.5"><title>Today: ${num(total)} so far</title></circle></svg>
      <p class="ml-legend"><span><i class="us-k line"></i>running total: ${num(total)}</span><span><i class="us-k fc"></i>forecast to cycle end: ${num(forecast)}</span>${inc != null ? `<span><i class="us-k inc"></i>allowance: ${num(inc)}</span>` : ""}<span><i class="us-k day"></i>per day (own scale)</span></p>`;
  }

  /* ---------- by user ---------- */
  function usersHtml(r) {
    const cols = r.meters.filter((m) => m.kind === "meter" && (m.billed || m.key === "api.requests" || m.key === "incidents"));
    const rows = Object.entries(r.by_user).sort((a, b) => (b[1]["ai.tokens"] || 0) - (a[1]["ai.tokens"] || 0) || (b[1]["api.requests"] || 0) - (a[1]["api.requests"] || 0));
    const caps = r.plan.user_caps || {};
    return `<section class="panel cp-cpanel"><div class="cp-tablewrap"><table class="cp-ctable us-table">
      <thead><tr><th>User</th>${cols.map((m) => `<th class="num">${esc(m.label)}</th>`).join("")}</tr></thead>
      <tbody>${rows.length ? rows.map(([email, ms]) => `<tr><td><b>${esc(email)}</b>${caps[email] ? `<div class="muted us-capnote">caps: ${Object.entries(caps[email]).map(([k, v]) => `${esc(r.meters.find((m) => m.key === k)?.label || k)} ${num(v)}`).join(", ")}</div>` : ""}</td>${cols.map((m) => `<td class="num">${ms[m.key] ? num(ms[m.key]) : `<span class="muted">0</span>`}${caps[email]?.[m.key] != null ? `<small class="muted"> / ${num(caps[email][m.key])}</small>` : ""}</td>`).join("")}</tr>`).join("")
        : `<tr><td colspan="${cols.length + 1}" class="muted">No usage yet this cycle.</td></tr>`}</tbody></table></div></section>
      <p class="rt-note">Background work (detector scans and the anomaly model) is counted for the person whose open page triggered it. “system” and “detector (auto-open)” are the service itself.</p>`;
  }

  /* ---------- plan & limits ---------- */
  function planHtml(r) {
    const ro = true, dis = "disabled";   // prices and allowances come from the chosen plan (Billing)
    const p = S.draft || r.plan, rows = r.meters.filter((m) => p.meters[m.key] || r.plan.meters[m.key]);
    const caps = Object.entries(p.user_caps || {}).flatMap(([email, cs]) => Object.entries(cs).map(([k, v]) => ({ email, k, v })));
    const capMeters = r.meters.filter((m) => m.hardable && m.kind === "meter");
    return `<div class="cp-warn us-alert" role="status"><b>Your allowances and prices come from your plan.</b><span>Change plan in the <button class="link" data-utab="billing">Billing</button> tab. Here you can set per-person caps and alert levels.</span></div>
      <form class="panel us-sec us-form" data-plan-form data-ro="${ro ? 1 : 0}">
        <div class="cp-list-head flat"><h3>Plan</h3><span class="muted">Revision ${num(r.plan.rev)} · saved ${esc(dt(r.plan.updated_at))} by ${esc(r.plan.updated_by)}</span></div>
        <div class="us-fgrid">
          <label class="field"><span>Plan name</span><input name="name" maxlength="60" value="${esc(p.name)}" required ${dis}></label>
          <label class="field"><span>Monthly fee (₹, before GST)</span><input name="base_fee" type="number" min="0" step="1" value="${esc(p.base_fee)}" ${dis}></label>
          <label class="field"><span>Billing cycle starts on day</span><input name="cycle_day" type="number" min="1" max="28" value="${esc(p.cycle_day)}" ${dis}></label>
          <label class="field"><span>Alert at (% of allowance)</span><input name="alert_at" value="${esc((p.alert_at || []).join(", "))}" placeholder="80, 100"></label>
        </div>
        <div class="cp-tablewrap"><table class="cp-ctable us-ptable">
          <thead><tr><th>Meter</th><th>Allowance per cycle</th><th>Overage price (₹)</th><th>At the allowance</th><th class="num">Used now</th></tr></thead>
          <tbody>${rows.map((m) => { const pm = p.meters[m.key] || { included: null, overage: 0 }, unl = pm.included == null, hard = (p.hard || []).includes(m.key); return `<tr data-prow="${esc(m.key)}">
            <td><b>${esc(m.label)}</b><div class="muted us-mdesc">${esc(m.desc)}</div></td>
            <td><div class="us-allow"><input type="number" min="0" step="1" name="inc" value="${unl ? "" : esc(pm.included)}" ${unl || ro ? "disabled" : ""} aria-label="${esc(m.label)} allowance"><label class="ml-check"><input type="checkbox" name="unl" ${unl ? "checked" : ""} ${dis}><span>Unlimited</span></label></div></td>
            <td><div class="us-price"><input type="number" min="0" step="0.5" name="price" value="${esc(pm.overage || 0)}" ${dis} aria-label="${esc(m.label)} overage price"><small>${esc(unitPrice(m))}</small></div></td>
            <td>${m.hardable ? `<select name="mode" aria-label="${esc(m.label)} limit" ${dis}><option value="soft" ${hard ? "" : "selected"}>Keep going, bill overage</option><option value="hard" ${hard ? "selected" : ""}>Block (hard limit)</option></select>` : `<span class="us-lock" title="Breach monitoring must not stop because a quota ran out">Keep going, bill overage <small>(monitoring is never blocked)</small></span>`}</td>
            <td class="num">${num(m.org_used)}</td></tr>`; }).join("")}</tbody></table></div>
        <div class="cp-list-head flat us-gap"><h3>Per-user caps</h3><span class="muted">Optional. A cap blocks that person only, even on an unlimited plan</span></div>
        <div class="us-caps">${caps.length ? caps.map((c, i) => `<div class="us-cap" data-cap="${i}"><span class="us-capwho">${esc(c.email)}</span><span>${esc(r.meters.find((m) => m.key === c.k)?.label || c.k)}</span><input type="number" min="0" step="1" name="capv" value="${esc(c.v)}" aria-label="Cap"><button type="button" class="btn ghost sm danger" data-act="cap-del" data-email="${esc(c.email)}" data-k="${esc(c.k)}">Remove</button></div>`).join("") : `<p class="muted">No caps. Everyone shares the workspace allowance.</p>`}
          <div class="us-cap new"><input type="email" name="cap_email" placeholder="person@company.com" list="usPeople" aria-label="Email"><datalist id="usPeople">${Object.keys(r.by_user).filter((e) => e.includes("@")).map((e) => `<option value="${esc(e)}">`).join("")}</datalist>
            <select name="cap_meter" aria-label="Meter">${capMeters.map((m) => `<option value="${esc(m.key)}">${esc(m.label)}</option>`).join("")}</select>
            <input type="number" min="0" step="1" name="cap_value" placeholder="Cap" aria-label="Cap value"><button type="button" class="btn ghost sm" data-act="cap-add">Add cap</button></div>
        </div>
        <div class="us-save"><span class="muted">${S.draft ? "Unsaved changes." : "No changes."} The estimate and limits update as soon as you save.</span>
          ${S.draft ? `<button type="button" class="btn ghost" data-act="discard">Discard</button>` : ""}<button type="submit" class="btn primary" ${S.draft ? "" : "disabled"}>Save plan</button></div>
      </form>
      <p class="rt-note">Hard limits apply to AI, customer lookups and seats only; breach monitoring is never blocked.</p>`;
  }
  function readPlanForm(form) {
    const p = JSON.parse(JSON.stringify(S.draft || S.r.plan)); p.user_caps = p.user_caps || {};
    const v = (n) => form.querySelector(`[name="${n}"]`).value;
    p.name = v("name").trim(); p.base_fee = Math.max(0, Number(v("base_fee")) || 0); p.cycle_day = Math.min(28, Math.max(1, Math.round(Number(v("cycle_day")) || 1)));
    p.alert_at = v("alert_at").split(/[,\s]+/).map(Number).filter((x) => x > 0 && x <= 200).slice(0, 4);
    p.hard = [];
    form.querySelectorAll("[data-prow]").forEach((row) => {
      const k = row.dataset.prow, unl = row.querySelector('[name="unl"]').checked, inc = row.querySelector('[name="inc"]');
      inc.disabled = unl || form.dataset.ro === "1";
      p.meters[k] = { included: unl ? null : Math.max(0, Math.round(Number(inc.value) || 0)), overage: Math.max(0, Number(row.querySelector('[name="price"]').value) || 0) };
      if (row.querySelector('[name="mode"]')?.value === "hard") p.hard.push(k);
    });
    form.querySelectorAll("[data-cap]").forEach((row) => { const b = row.querySelector("[data-act]"); p.user_caps[b.dataset.email][b.dataset.k] = Math.max(0, Math.round(Number(row.querySelector('[name="capv"]').value) || 0)); });
    return p;
  }
  async function savePlan(body, msg) {
    try {
      const plan = await api("/api/usage/plan", { method: "PUT", body: JSON.stringify(body) });
      S.draft = null; toast(msg || `Plan saved (revision ${plan.rev}).`, true);
      await load(); if (typeof Account !== "undefined") Account.refreshMe();
    } catch (e) {
      if (e.status === 409 && e.body?.current) { S.r.plan = e.body.current; S.draft = null; render(); }
      toast(e.message);
    }
  }

  /* ---------- CSV ---------- */
  function csv() {
    const r = S.r, q = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
    const lines = [["date", "meter", "label", "value"].join(",")];
    for (const [d, ms] of Object.entries(r.daily).sort()) for (const [k, v] of Object.entries(ms)) lines.push([d, k, q(r.meters.find((m) => m.key === k)?.label || k), v].join(","));
    if (r.scope === "all") { lines.push("", ["user", "meter", "label", "cycle_total"].join(",")); for (const [e, ms] of Object.entries(r.by_user)) for (const [k, v] of Object.entries(ms)) lines.push([q(e), k, q(r.meters.find((m) => m.key === k)?.label || k), v].join(",")); }
    lines.push("", ["meter", "label", "used", "included", "overage_cost_inr"].join(","));
    for (const m of r.meters) lines.push([m.key, q(m.label), r.scope === "me" ? m.mine : m.org_used, m.included ?? "unlimited", m.overage_cost].join(","));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
    a.download = `usage-${r.cycle.start.slice(0, 10)}-${r.scope}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* ---------- events ---------- */
  function bind() {
    const body = $("usBody");
    body.addEventListener("click", (e) => {
      const t = (s) => e.target.closest(s);
      let b;
      if ((b = t("[data-utab]"))) { S.tab = b.dataset.utab; return render(); }
      if ((b = t("[data-scope]"))) { S.scope = b.dataset.scope; S.r = null; render(); return load(); }
      if ((b = t("[data-meter]"))) { S.meter = b.dataset.meter; return render(); }
      if ((b = t("[data-act]"))) {
        const form = body.querySelector("[data-plan-form]");
        if (b.dataset.act === "csv") return csv();
        if (b.dataset.act === "discard") { S.draft = null; return render(); }
        if (b.dataset.act === "cap-del") { const p = readPlanForm(form); delete p.user_caps[b.dataset.email][b.dataset.k]; if (!Object.keys(p.user_caps[b.dataset.email]).length) delete p.user_caps[b.dataset.email]; S.draft = p; return render(); }
        if (b.dataset.act === "cap-add") {
          const email = form.querySelector('[name="cap_email"]').value.trim().toLowerCase(), k = form.querySelector('[name="cap_meter"]').value, v = form.querySelector('[name="cap_value"]').value;
          if (!/^[^@\s]+@[^@\s]+$/.test(email)) return toast("Enter the person's email.");
          if (v === "" || Number(v) < 0) return toast("Enter a cap of 0 or more.");
          const p = readPlanForm(form); p.user_caps[email] = { ...(p.user_caps[email] || {}), [k]: Math.round(Number(v)) }; S.draft = p; return render();
        }
      }
    });
    body.addEventListener("input", (e) => { const f = e.target.closest("[data-plan-form]"); if (f && !e.target.closest(".us-cap.new")) { S.draft = readPlanForm(f); const s = f.querySelector('[type="submit"]'); s.disabled = false; f.querySelector(".us-save .muted").textContent = "Unsaved changes. The estimate and limits update as soon as you save."; } });
    body.addEventListener("change", (e) => { const f = e.target.closest("[data-plan-form]"); if (f && e.target.name === "unl") { S.draft = readPlanForm(f); render(); } });
    body.addEventListener("submit", (e) => {
      if (!e.target.matches("[data-plan-form]")) return;
      e.preventDefault();
      const p = readPlanForm(e.target);
      if (!p.name) return toast("Give the plan a name.");
      savePlan({ rev: S.r.plan.rev, plan: p });
    });
  }

  // Top-of-page banner when the company is at 80%+ of an allowance (from /api/me).
  function banner() {
    const el = $("usageBanner"); if (!el) return;
    const hot = (ME?.usage_alerts || []).filter((a) => a.pct >= 80);
    if (!hot.length || currentView === "usage") { el.hidden = true; return; }
    const full = hot.filter((a) => a.pct >= 100);
    el.className = `us-banner ${full.length ? "bad" : "warn"}`;
    el.innerHTML = `<span>${full.length ? "Plan allowance used up:" : "Close to a plan allowance:"} ${hot.map((a) => `<b>${esc(a.label)}</b> ${Math.round(a.pct)}%${a.pct >= 100 && a.hard ? " (blocked)" : ""}`).join(" · ")}</span><button class="link" data-goto-usage>View usage</button>`;
    el.hidden = false;
    el.querySelector("[data-goto-usage]").onclick = () => show("usage");
  }

  return {
    show() { if (!S.started) { S.started = true; bind(); } if ($("usageBanner")) $("usageBanner").hidden = true; if (!S.r || Date.now() - S.loadedAt > 15000) load(); else render(); },
    tick(ticks) { const a = document.activeElement; if (ticks % 10 === 0 && !S.busy && !S.draft && !$("view-usage").contains(a?.matches?.("input,select,textarea") ? a : null)) load(); }, // every 20 s
    banner,
    openBilling() { S.tab = "billing"; show("usage"); render(); },
    reset() { S.r = null; S.scope = null; S.draft = null; S.tab = "overview"; },
  };
})();
