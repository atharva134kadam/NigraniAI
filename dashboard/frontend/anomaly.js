/* Anomaly detection: the unsupervised ML model as its own section.
   The model (consent_service/server.py, ml_*) cuts each service's logs into time slices, measures 13
   things per slice, learns each service's normal by time of day (median / MAD), scores every slice with
   an Isolation Forest and raises an anomaly only when the score passes the cut-off AND a measure is
   clearly above normal. Every anomaly comes with a plain-words summary, the measures behind it, which
   ones made the forest isolate it, the checks it passed, a likely cause, a timeline and sample lines.
   Dismissed anomalies teach it which patterns are expected (held back next time unless stronger).
   Tabs: Overview (live status, services × time heatmap), Anomalies (list + full report), Model (how it
   works, what it learned, quality from your reviews, backtest by sensitivity), Settings.
   Server: GET /api/breach/model, POST /api/breach/model/retrain ({preview} = test settings),
   GET/PUT /api/breach-policy (the anomaly settings live in the breach policy). Reviews (dismiss / open an
   incident) go through Breach Response, so Signals stays the one place where triage happens. */
const Anomaly = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN", { maximumFractionDigits: 1 });
  const IST = { timeZone: "Asia/Kolkata" };
  const FT = new Intl.DateTimeFormat("en-IN", { ...IST, day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  const FH = new Intl.DateTimeFormat("en-IN", { ...IST, hour: "numeric", hour12: true });
  const FD = new Intl.DateTimeFormat("en-IN", { ...IST, day: "numeric", month: "short" });
  const up = (s) => s.replace(/\b(am|pm)\b/gi, (m) => m.toUpperCase());
  const when = (v) => (v ? up(FT.format(new Date(v))) : "–");
  const ago = (v) => { const s = (Date.now() - new Date(v)) / 1000; return !v || isNaN(s) ? "–" : s < 60 ? `${Math.max(1, Math.round(s))} s ago` : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : "");
  const SEV = { high: "High", medium: "Medium", low: "Low" };
  const SENS = { low: ["Low", "Fewest alerts: only the clearest outliers"], medium: ["Medium", "Balanced (recommended)"], high: ["High", "Most alerts: catches subtler changes"] };

  const A = { started: false, m: null, err: "", busy: false, tab: "overview", sel: null, filter: "review", policy: null, draft: null, pv: null, pvBusy: false, saving: false, note: "", dismissing: null, lines: {}, at: 0 };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r = await go();
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  function toast(msg, ok = true) { const t = $("anToast"); if (!t) return; t.textContent = msg; t.className = `ttoast${ok ? " ok" : ""}`; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 3500); }

  async function load(force = false) {
    if (A.busy) return;
    A.busy = true; if (force) render();
    try {
      const [m] = await Promise.all([force ? api("/api/breach/model/retrain", { method: "POST", body: "{}" }) : api("/api/breach/model"), Breach.ensure().catch(() => {})]);
      A.m = m; A.err = m.error || ""; A.at = Date.now();
      if (force) toast(`Retrained on ${num(m.lines)} log lines: ${num((m.signals || []).length)} anomalies.`);
    } catch (e) { A.err = e.message; }
    A.busy = false; render();
  }
  async function loadPolicy() { try { A.policy = await api("/api/breach-policy"); } catch (e) { A.err = e.message; } }

  /* ---------- helpers ---------- */
  const cfg = () => ({ enabled: true, sensitivity: "medium", bucket_minutes: 10, min_history: 12, auto_open: false, ...(A.policy?.anomaly || {}) });
  const triage = () => (typeof Breach !== "undefined" ? Breach.triageOf() : {});
  const stateOf = (s) => { const t = triage()[s.id]; return t ? t.state : "new"; };
  const all = () => [...(A.m?.signals || []), ...(A.m?.held || [])];
  const byId = (id) => all().find((s) => s.id === id);
  const status = () => { const m = A.m; return !m ? ["warn", "Loading"] : m.error ? ["bad", "Error"] : m.status === "training" ? ["warn", "Learning…"] : m.note ? ["warn", "Needs more data"] : !cfg().enabled ? ["off", "Off"] : ["ok", "Live"]; };
  const gauge = (score, cut) => { const p = (v) => Math.min(100, Math.max(0, ((v - 0.3) / 0.55) * 100)).toFixed(0); return `<span class="an-gauge"><i style="width:${p(score)}%"></i><em style="left:${p(cut)}%" title="cut-off ${cut}"></em></span>`; };
  const sevPill = (s) => `<span class="an-sev s-${esc(s)}">${esc(SEV[s] || s)}</span>`;
  const statePill = (s) => { const st = s.held ? "held" : stateOf(s); return `<span class="an-st st-${st}">${st === "new" ? "To review" : st === "dismissed" ? "Dismissed" : st === "linked" ? "Incident opened" : "Held back"}</span>`; };

  /* ---------- hero + tiles ---------- */
  function hero() {
    const m = A.m || {}, st = status(), sigs = m.signals || [], fresh = sigs.filter((s) => stateOf(s) === "new").length;
    const svcs = m.services || [], liveTop = svcs.filter((x) => x.live != null).sort((a, b) => b.live - a.live)[0];
    return `<section class="panel dm-hero an-hero">
      <div class="dm-htext">
        <div class="dm-erow"><span class="dm-eyebrow">DPDP Act s.8(5) · Rule 6(1)(c)–(e) · monitoring & detection</span><span class="dm-live ${st[0] === "ok" ? "" : st[0] === "bad" ? "bad" : "off"}">${esc(st[1])}</span></div>
        <h2>${!A.m ? "Loading the model…" : m.error ? "The model couldn’t run" : fresh ? `${num(fresh)} anomal${fresh === 1 ? "y" : "ies"} to review` : "Nothing unusual waiting for review"}</h2>
        <p class="muted">${m.lines ? `Learned what normal looks like for ${num(svcs.length)} services, by day and by night, from ${num(m.lines)} log lines over the last ${num(Math.round((Date.now() - new Date(m.since)) / 864e5))} days. Scored ${esc(ago(m.scored_at))}; each anomaly explains which measures, how far from normal, and why.` : m.error ? esc(m.error) : "Reading the logs and learning normal for each service. The first run takes a few seconds."}</p>
        <div class="dm-hacts">
          <button class="btn primary" data-act="tab" data-tab="anomalies" ${sigs.length ? "" : "disabled"}>Review anomalies${fresh ? ` · ${num(fresh)}` : ""}</button>
          <button class="btn ghost" data-act="retrain" ${A.busy ? "disabled" : ""}>${A.busy ? "Training…" : "Retrain now"}</button>
          <button class="btn ghost ai-ask" data-ask-ai="anomaly">✦ Ask AI</button>
        </div>
      </div>
      <div class="an-now">
        <span class="an-nowl">Right now</span>
        ${liveTop ? `<b>${esc(liveTop.service)}</b><small class="muted">highest score in the current ${esc(m.bucket_minutes)}-min slice</small>${gauge(liveTop.live, m.cutoff)}<span class="an-nowv ${liveTop.live >= m.cutoff ? "hot" : ""}">${liveTop.live.toFixed(2)} <small>/ cut-off ${m.cutoff}</small></span>`
          : `<b>Quiet</b><small class="muted">no log lines in the current slice yet</small>`}
      </div>
    </section>`;
  }
  function tiles() {
    const m = A.m || {}, sigs = m.signals || [], bt = m.backtest?.[m.sensitivity];
    const t = [
      ["Anomalies", num(sigs.length), `in the last ${num(Math.round((Date.now() - new Date(m.since || Date.now())) / 864e5))} days`],
      ["To review", num(sigs.filter((s) => stateOf(s) === "new").length), "waiting in Signals"],
      ["Held back", num((m.held || []).length), "like ones you dismissed"],
      ["Services watched", num((m.services || []).length), `${num((m.services || []).filter((x) => x.learning).length)} still learning`],
      ["Alerts per day", bt ? num(bt.per_day) : "–", `at ${esc(m.sensitivity || "medium")} sensitivity`],
    ];
    return `<div class="dm-tiles ev2-tiles">${t.map(([l, b, s]) => `<div class="panel dm-tile"><span>${esc(l)}</span><b>${b}</b><small class="muted">${esc(s)}</small></div>`).join("")}</div>`;
  }
  function tabs() {
    const n = (A.m?.signals || []).filter((s) => stateOf(s) === "new").length;
    return `<div class="cp-tabs dm-tabs" role="tablist">${[["overview", "Overview"], ["anomalies", "Anomalies"], ["model", "How the model works"], ["settings", "Settings"]].map(([k, l]) => `<button role="tab" class="${A.tab === k ? "on" : ""}" aria-selected="${A.tab === k}" data-act="tab" data-tab="${k}">${l}${k === "anomalies" && n ? ` <span class="count">${n}</span>` : ""}</button>`).join("")}</div>`;
  }

  /* ---------- overview ---------- */
  // Services × hours: each cell is the highest slice score in that hour; flagged hours are outlined.
  function heatmap() {
    const m = A.m; if (!m?.series?.length) return `<p class="muted">The map appears once the model has scored the logs.</p>`;
    const H = 72, now = Math.floor(Date.now() / 36e5), start = now - H + 1, cut = m.cutoff;
    const sigAt = {};
    for (const s of all()) for (let h = Math.floor(new Date(s.start) / 36e5); h <= Math.floor((new Date(s.end) - 1) / 36e5); h++) sigAt[`${s.group}|${h}`] = s.id;
    const rows = m.series.map((sv) => {
      const cells = new Array(H).fill(null);
      for (const [t, sc, fl] of sv.points) { const h = Math.floor(new Date(t) / 36e5) - start; if (h >= 0 && h < H) cells[h] = Math.max(cells[h] ?? 0, sc) + (fl ? 10 : 0); }
      return `<div class="an-hrow"><span class="an-hsvc" title="${esc(sv.service)}">${esc(sv.service.replace(/-service$/, ""))}</span><div class="an-hcells">${cells.map((v, i) => {
        if (v == null) return `<i class="an-c none"></i>`;
        const fl = v >= 10, sc = fl ? v - 10 : v, lvl = sc >= cut ? 4 : sc >= cut - 0.05 ? 3 : sc >= 0.55 ? 2 : 1, id = sigAt[`${sv.service}|${start + i}`];
        return `<i class="an-c l${lvl}${fl ? " fl" : ""}" title="${esc(sv.service)} · ${esc(up(FT.format(new Date((start + i) * 36e5))))} · score ${sc.toFixed(2)}${fl ? " · anomaly" : ""}"${fl && id ? ` data-act="open" data-id="${id}"` : ""}></i>`;
      }).join("")}</div></div>`;
    }).join("");
    const ticks = [0, 24, 48, H - 1].map((i) => `<span style="left:${(i / (H - 1)) * 100}%">${esc(up(i === H - 1 ? "now" : FD.format(new Date((start + i) * 36e5)) + " " + FH.format(new Date((start + i) * 36e5))))}</span>`).join("");
    return `<div class="an-heat">${rows}<div class="an-haxis"><span class="an-hsvc"></span><div>${ticks}</div></div></div>
      <div class="an-hleg"><span><i class="an-c l1"></i>ordinary</span><span><i class="an-c l2"></i>a little unusual</span><span><i class="an-c l3"></i>close to the cut-off</span><span><i class="an-c l4"></i>above the cut-off</span><span><i class="an-c l4 fl"></i>anomaly (click it)</span><span><i class="an-c none"></i>no activity</span></div>`;
  }
  function card(s) {
    return `<button class="panel an-card s-${esc(s.severity)}" data-act="open" data-id="${esc(s.id)}">
      <div class="an-ch">${sevPill(s.severity)}<b>${esc(s.cause?.label || "Unusual activity")}</b>${statePill(s)}</div>
      <p>${esc(s.summary || "")}</p>
      <div class="an-cf"><span>${esc(s.group)}</span><span>${esc(when(s.start))}</span><span>score ${Number(s.score).toFixed(2)}</span>${s.live ? `<span class="an-livetag">happening now</span>` : ""}</div>
    </button>`;
  }
  function overview() {
    const sigs = (A.m?.signals || []).slice(0, 4);
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>Every service, hour by hour</h3><span class="muted">last 72 hours · darker = more unusual · outlined = anomaly</span></div>${heatmap()}</section>
      <section class="panel ev2-card"><div class="ev2-ch"><h3>Latest anomalies</h3><button class="btn ghost sm" data-act="tab" data-tab="anomalies">See all</button></div>
        ${sigs.length ? `<div class="an-cards">${sigs.map(card).join("")}</div>` : `<p class="muted">No anomalies in this window.</p>`}</section>`;
  }

  /* ---------- anomalies list + report ---------- */
  function list() {
    const F = [["review", "To review"], ["all", "All"], ["high", "High"], ["dismissed", "Dismissed"], ["held", "Held back"]];
    const sigs = A.filter === "held" ? A.m?.held || [] : (A.m?.signals || []).filter((s) => A.filter === "all" || (A.filter === "review" && stateOf(s) === "new") || (A.filter === "high" && s.severity === "high") || (A.filter === "dismissed" && stateOf(s) === "dismissed"));
    return `<section class="panel ev2-card"><div class="ev2-filters">${F.map(([k, l]) => `<button class="chip${A.filter === k ? " on" : ""}" data-act="filter" data-f="${k}">${l}</button>`).join("")}</div>
      ${A.filter === "held" ? `<p class="muted an-note">These looked like anomalies you dismissed before (same service, same measure, same time of day) and weren’t much stronger, so they weren’t raised. A stronger one still alerts.</p>` : ""}
      ${sigs.length ? `<div class="an-cards">${sigs.map(card).join("")}</div>` : `<p class="muted">Nothing here.</p>`}</section>`;
  }
  function timeline(s) {
    const pts = s.timeline || [], bm = (A.m?.bucket_minutes || 10) * 6e4;
    if (!pts.length) return "";
    // The whole stretch around the anomaly, slice by slice; quiet slices (no log lines) count as zero.
    const by = Object.fromEntries(pts.map((p) => [new Date(p[0]).getTime(), p]));
    const r0 = new Date(s.start).getTime(), r1 = new Date(s.end).getTime() - bm, t0 = r0 - 18 * bm, t1 = Math.min(r1 + 18 * bm, Math.floor(Date.now() / bm) * bm), grid = [];
    for (let t = t0; t <= t1; t += bm) grid.push(by[t] || [new Date(t).toISOString(), 0, 0, null, t >= r0 && t <= r1 ? 1 : 0, 0]);
    const W = 640, Ht = 150, T = 8, n = grid.length, bw = W / Math.max(n, 1);
    const maxL = Math.max(1, ...grid.map((p) => p[1])), maxF = Math.max(1, ...grid.map((p) => p[2]), s.reasons[0].p95);
    const X = (i) => i * bw, Yl = (v) => T + (1 - v / maxL) * (Ht - T), Yf = (v) => T + (1 - v / maxF) * (Ht - T);
    const fline = grid.map((p, i) => `${i ? "L" : "M"}${(X(i) + bw / 2).toFixed(1)},${Yf(p[2]).toFixed(1)}`).join("");
    const band = Yf(s.reasons[0].p95), ri = grid.findIndex((p) => p[4]);
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>Timeline around it</h3><span class="muted">${esc(s.group)} · bars = log lines per ${esc(A.m?.bucket_minutes)} min · line = ${esc(s.reasons[0].label)}</span></div>
      <svg class="an-tl" viewBox="0 0 ${W} ${Ht}" preserveAspectRatio="none">
        <rect x="0" y="${band}" width="${W}" height="${Ht - band}" class="an-band"/>
        ${ri >= 0 ? `<rect x="${X(ri)}" y="0" width="${bw * grid.filter((p) => p[4]).length}" height="${Ht}" class="an-span"/>` : ""}
        ${grid.map((p, i) => `<rect x="${(X(i) + 1).toFixed(1)}" y="${Yl(p[1]).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(Ht - Yl(p[1])).toFixed(1)}" class="an-bar${p[4] ? " in" : ""}"><title>${esc(when(p[0]))}: ${num(p[1])} lines, ${num(p[2])} ${esc(s.reasons[0].label)}${p[3] != null ? `, score ${p[3]}` : ""}</title></rect>`).join("")}
        <path d="${fline}" class="an-fline"/>
      </svg>
      <div class="an-tlx"><span>${esc(when(grid[0][0]))}</span><span>${esc(when(s.start))}</span><span>${esc(when(grid[n - 1][0]))}</span></div>
      <p class="an-leg2"><span><i class="an-k bar"></i>log lines</span><span><i class="an-k bar in"></i>the anomaly</span><span><i class="an-k line"></i>${esc(s.reasons[0].label)}</span><span><i class="an-k band"></i>its usual range (95% of slices)</span></p></section>`;
  }
  async function loadLines(s) {
    A.lines[s.id] = { loading: true }; render();
    try {
      const u = new URL(`${DASH_URL}/rest/v1/activity_logs`);
      u.searchParams.set("select", "id,logged_at,service,level,event,kind,http_status,route"); u.searchParams.set("id", `in.(${s.sample_ids.slice(0, 15).join(",")})`); u.searchParams.set("order", "logged_at.asc");
      const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      A.lines[s.id] = { rows: await r.json() };
    } catch (e) { A.lines[s.id] = { error: e.message }; }
    render();
  }
  function report(s) {
    const cut = A.m.cutoff, st = s.held ? "held" : stateOf(s), cz = s.cause || {};
    const top = Math.max(...s.reasons.map((r) => Math.log1p(Math.max(r.value, r.p95))), 1) * 1.08, pos = (v) => `${((Math.log1p(v) / top) * 100).toFixed(1)}%`;
    const ev = A.lines[s.id];
    if (!ev && s.sample_ids?.length) setTimeout(() => loadLines(s));
    return `<button class="btn ghost sm an-back" data-act="back">← All anomalies</button>
      <section class="panel dm-hero an-rhero s-${esc(s.severity)}">
        <div class="dm-htext">
          <div class="dm-erow">${sevPill(s.severity)}${statePill(s)}<span class="an-conf c-${esc(cz.confidence)}">${esc(cap(cz.confidence || ""))} confidence</span></div>
          <h2>${esc(cz.label || "Unusual activity")}</h2>
          <p class="an-sum">${esc(s.summary)}</p>
          <div class="an-meta"><span><b>${esc(s.group)}</b></span><span>${esc(when(s.start))} → ${esc(up(FH.format(new Date(s.end))))}</span><span>${num(s.slices)} slice(s) · ${num(s.events)} log lines</span>${s.live ? `<span class="an-livetag">happening now</span>` : ""}</div>
          <div class="dm-hacts">
            ${st === "new" && can("breach:TriageSignal") ? `<button class="btn primary" data-act="breach" data-id="${esc(s.id)}">Open an incident or review in Breach Response</button><button class="btn ghost" data-act="dismiss-start" data-id="${esc(s.id)}">Dismiss…</button>` : ""}
            ${st === "dismissed" && can("breach:TriageSignal") ? `<button class="btn ghost" data-act="reopen" data-id="${esc(s.id)}">Back to review</button>` : ""}
            ${st === "linked" ? `<button class="btn ghost" data-act="breach" data-id="${esc(s.id)}">Open in Breach Response</button>` : ""}
            <button class="btn ghost ai-ask" data-ask-ai="anomaly:sig:${esc(s.id)}">✦ Ask AI about this anomaly</button>
          </div>
          ${A.dismissing === s.id ? `<div class="an-dismiss"><input id="anReason" type="text" maxlength="300" placeholder="Why is this expected? e.g. planned load test, nightly batch job" aria-label="Reason"><button class="btn primary sm" data-act="dismiss" data-id="${esc(s.id)}">Dismiss</button><button class="btn ghost sm" data-act="dismiss-cancel">Cancel</button>
            <small class="muted">The model remembers this pattern (${esc(s.group)} · ${esc(s.reasons[0].label)} · ${esc(s.part)}time) and holds back similar ones unless they’re stronger.</small></div>` : ""}
        </div>
        <div class="an-scorebox"><span>Anomaly score</span><b>${Number(s.score).toFixed(2)}</b>${gauge(s.score, cut)}<small class="muted">0.5 is ordinary · cut-off ${cut}</small><span class="an-cnf">model confidence ${Math.round((s.confidence || 0) * 100)}%</span></div>
      </section>
      <div class="an-grid">
        <section class="panel ev2-card"><div class="ev2-ch"><h3>What was unusual</h3><span class="muted">each measure against ${esc(s.group)}’s normal${s.baseline === "time_of_day" ? ` ${esc(s.part)}time` : ""}</span></div>
          <div class="an-reasons">${s.reasons.map((r) => `<div class="an-reason">
            <div class="an-rt"><b>${esc(cap(r.label))}</b><span>${num(r.value)} in one slice · usually ${num(r.usual)} · 95% of slices ≤ ${num(r.p95)}</span></div>
            <div class="ml-bar" aria-hidden="true"><span class="ml-normal" style="width:${pos(r.p95)}"></span><span class="ml-med" style="left:${pos(r.usual)}"></span><span class="ml-obs" style="left:${pos(r.value)}"></span></div>
            <span class="an-times">${r.times >= 10 ? Math.round(r.times) : r.times}×<small>${num(r.z)} spreads</small></span></div>`).join("")}</div>
          <p class="ml-legend"><span><i class="ml-k normal"></i>usual range</span><span><i class="ml-k obs"></i>this anomaly</span></p></section>
        <section class="panel ev2-card"><div class="ev2-ch"><h3>What made the model isolate it</h3><span class="muted">share of the forest’s splits, weighted by distance from normal</span></div>
          <div class="an-contrib">${(s.contributions || []).map((c) => `<div class="an-crow"><span>${esc(cap(c.label))}</span><span class="an-cbar"><i style="width:${Math.round(c.share * 100)}%"></i></span><b>${Math.round(c.share * 100)}%</b></div>`).join("") || `<p class="muted">Not available for this anomaly.</p>`}</div>
          <p class="muted an-note">The Isolation Forest cuts the data at random until each slice stands alone. Unusual slices stand alone after very few cuts; this shows which measures those early cuts used.</p></section>
      </div>
      <div class="an-grid">
        <section class="panel ev2-card"><div class="ev2-ch"><h3>How it was detected</h3><span class="muted">every check an anomaly must pass</span></div>
          <ul class="an-checks">${(s.checks || []).map((c) => `<li class="${c.ok ? "ok" : "info"}"><i>${c.ok ? "✓" : "i"}</i><div><b>${esc(c.label)}</b><span>${esc(c.text)}</span></div></li>`).join("")}</ul></section>
        <section class="panel ev2-card"><div class="ev2-ch"><h3>Likely cause</h3><span class="muted">${esc(cap(cz.category || ""))}</span></div>
          <p class="an-cause"><b>${esc(cz.label || "")}</b> ${esc(cz.why || "")}</p>
          <h4 class="an-h4">What to check</h4><ol class="an-todo">${(cz.check || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol>
          ${(s.together || []).length ? `<p class="ml-together"><b>Also unusual at the same time:</b> ${s.together.map(esc).join(", ")}. Several services changing together usually means a deploy, restart or shared outage rather than an attack.</p>` : ""}</section>
      </div>
      ${timeline(s)}
      <section class="panel ev2-card"><div class="ev2-ch"><h3>Sample log lines</h3><span class="muted">up to 15 of the lines behind the leading measures</span></div>
        ${!s.sample_ids?.length ? `<p class="muted">No sample lines.</p>` : !ev || ev.loading ? `<p class="muted">Loading log lines…</p>` : ev.error ? `<p class="cp-red">Couldn’t load the lines: ${esc(ev.error)}</p>` :
          `<div class="cp-tablewrap"><table class="ev-table an-lines"><thead><tr><th>When</th><th>Level</th><th>Event</th><th>Route</th><th>Status</th></tr></thead><tbody>${ev.rows.map((r) => `<tr><td class="nowrap">${esc(when(r.logged_at))}</td><td><span class="an-lvl l-${esc(r.level)}">${esc(r.level || "")}</span></td><td>${esc(r.event || r.kind || "")}</td><td><code>${esc(r.route || "")}</code></td><td>${esc(r.http_status ?? "")}</td></tr>`).join("")}</tbody></table></div>`}
      </section>`;
  }

  /* ---------- model ---------- */
  function model() {
    const m = A.m || {}, svcs = m.services || [], bt = m.backtest || {}, sc = m.scores || {}, cut = m.cutoff;
    const tri = triage(), ml = (m.signals || []).map((s) => tri[s.id]?.state).filter(Boolean);
    const linked = ml.filter((x) => x === "linked").length, dis = ml.filter((x) => x === "dismissed").length;
    const steps = [["◫", "Slice", `Each service's log lines are cut into ${esc(m.bucket_minutes || 10)}-minute slices.`],
      ["▦", `Measure ${(m.features || []).length || 13} things`, "Requests, data operations, personal-data and credential events, rejected sign-ins, PII in log text, errors, warnings, 5xx, response time, and three rates: error rate, rejection rate, share touching personal data."],
      ["◐", "Learn normal, by time of day", "For every service separately, day (8 AM–8 PM IST) and night: the usual level (median) and spread (MAD) of each measure. A busy service and a quiet one, or 3 AM and noon, are each judged against themselves."],
      ["⌥", "Score", "An Isolation Forest of 150 random trees tries to separate each slice from the rest. Unusual slices stand alone after few cuts and score near 1; ordinary ones about 0.5."],
      ["✓", "Gate and explain", `A slice alerts only if its score passes the cut-off (${cut ?? "–"}) and a measure is clearly above normal (≥ ${m.z_threshold || 3} spreads and a meaningful amount). Neighbouring slices merge into one anomaly with its explanation.`],
      ["↺", "Learn from your reviews", "Dismiss an anomaly and the model remembers the pattern (service, measure, time of day). Similar ones are held back unless they are clearly stronger."]];
    const bmax = Math.max(1, ...Object.values(bt).map((b) => b.per_day));
    const dist = (v) => `${Math.min(100, Math.max(0, ((v - 0.3) / 0.55) * 100)).toFixed(1)}%`;
    return `<section class="panel ev2-card"><div class="ev2-ch"><h3>How it works</h3><span class="muted">${esc(m.algorithm || "")}</span></div>
        <ol class="an-steps">${steps.map(([i, t, d], n) => `<li><span class="an-si">${i}</span><b>${n + 1}. ${esc(t)}</b><p class="muted">${d}</p></li>`).join("")}</ol></section>
      <div class="an-grid">
        <section class="panel ev2-card"><div class="ev2-ch"><h3>How often it would alert</h3><span class="muted">backtest on the same ${esc(num(Math.round((Date.now() - new Date(m.since || Date.now())) / 864e5)))}-day window</span></div>
          <div class="an-bt">${Object.entries(bt).map(([k, b]) => `<div class="an-btrow${k === m.sensitivity ? " on" : ""}"><span>${esc(SENS[k]?.[0] || k)}${k === m.sensitivity ? " <small>(current)</small>" : ""}</span><span class="an-cbar"><i style="width:${((b.per_day / bmax) * 100).toFixed(0)}%"></i></span><b>${num(b.per_day)}/day</b><small class="muted">${num(b.anomalies)} in all · cut-off ${b.cutoff}</small></div>`).join("") || `<p class="muted">Appears once the model has scored the logs.</p>`}</div>
          <p class="muted an-note">Before your reviews hold any back. Change the sensitivity in Settings.</p></section>
        <section class="panel ev2-card"><div class="ev2-ch"><h3>Quality from your reviews</h3><span class="muted">anomalies in this window</span></div>
          <div class="an-q"><div><b>${num(linked + dis)}</b><span>reviewed</span></div><div><b>${num(linked)}</b><span>became incidents</span></div><div><b>${num(dis)}</b><span>dismissed</span></div><div><b>${linked + dis ? `${Math.round((linked / (linked + dis)) * 100)}%` : "–"}</b><span>were worth an incident</span></div><div><b>${num((m.held || []).length)}</b><span>held back</span></div></div>
          <p class="muted an-note">${linked + dis ? "Dismissed patterns are remembered, so expected activity stops alerting." : "No anomaly has been reviewed yet. Each review makes the model more precise: dismissed patterns are held back next time."}</p></section>
      </div>
      <section class="panel ev2-card"><div class="ev2-ch"><h3>Score distribution</h3><span class="muted">all ${num(m.slices)} slices · where the cut-off sits</span></div>
        <div class="an-dist"><span class="an-dtrack"></span>${[["p50", "median"], ["p90", "90%"], ["p99", "99%"], ["max", "max"]].map(([k, l]) => sc[k] != null ? `<span class="an-dmark" style="left:${dist(sc[k])}"><b>${sc[k].toFixed(2)}</b><small>${l}</small></span>` : "").join("")}${cut ? `<span class="an-dcut" style="left:${dist(cut)}"><small>cut-off ${cut}</small></span>` : ""}</div></section>
      <section class="panel ev2-card"><div class="ev2-ch"><h3>What it learned per service</h3><span class="muted">usual level in one slice (median) by day and by night → the busiest 5%</span></div>
        ${svcs.length ? `<div class="cp-tablewrap"><table class="ev-table an-svc"><thead><tr><th>Service</th><th>Slices day / night</th><th>Requests day</th><th>Requests night</th><th>Errors</th><th>Top score</th><th>Anomalous slices</th></tr></thead><tbody>${svcs.map((x) => {
          const d = x.typical_day || x.typical, n = x.typical_night || x.typical, c = (t, k) => t?.[k] ? `${num(t[k][0])} <span class="muted">→ ${num(t[k][1])}</span>` : "–";
          return `<tr><td><b>${esc(x.service)}</b>${x.learning ? ` <span class="cp-tag">learning</span>` : ""}</td><td>${num(x.day_slices)} / ${num(x.night_slices)}</td><td>${c(d, "requests")}</td><td>${c(n, "requests")}</td><td>${c(x.typical, "errors")}</td><td>${gauge(x.max_score, cut)} ${x.max_score.toFixed(2)}</td><td>${x.flagged ? `<b class="cp-red">${num(x.flagged)}</b>` : `<span class="muted">0</span>`}</td></tr>`; }).join("")}</tbody></table></div>` : `<p class="muted">Nothing learned yet.</p>`}</section>
      <section class="panel ev2-card"><div class="ev2-ch"><h3>Performance</h3><span class="muted">runs inside NigraniAI in plain Python; nothing leaves the server</span></div>
        <div class="an-q an-perf"><div><b>${num(m.lines)}</b><span>log lines in the window${m.truncated ? " (newest kept)" : ""}</span></div><div><b>${num(m.slices)}</b><span>slices scored</span></div><div><b>${m.seconds != null ? `${Math.round(m.seconds * 1000)} ms` : "–"}</b><span>last scoring run</span></div><div><b>${num(m.cached)}</b><span>slices reused unchanged</span></div><div><b>${esc(m.rescore_every_s || 10)} s</b><span>new lines scored every</span></div><div><b>${Math.round((m.refit_every_s || 600) / 60)} min</b><span>normal re-learned every</span></div></div></section>`;
  }

  /* ---------- settings ---------- */
  function settings() {
    if (!A.policy) { loadPolicy().then(render); return `<section class="panel ev2-card"><p class="muted">Loading settings…</p></section>`; }
    const c = { ...cfg(), ...(A.draft || {}) }, edit = can("breach:EditDetectors"), dis = edit ? "" : "disabled", bt = A.m?.backtest || {}, pv = A.pv;
    return `<div class="an-grid"><section class="panel ev2-card an-set">
        <div class="ev2-ch"><h3>Model settings</h3><label class="an-tog"><input type="checkbox" data-set="enabled" ${c.enabled ? "checked" : ""} ${dis}><span>${c.enabled ? "On" : "Off"}</span></label></div>
        <fieldset class="an-sens" ${dis}><legend>Sensitivity</legend>${Object.entries(SENS).map(([k, [l, d]]) => `<label class="an-opt${c.sensitivity === k ? " on" : ""}"><input type="radio" name="an-sens" value="${k}" data-set="sensitivity" ${c.sensitivity === k ? "checked" : ""}><b>${l}</b><span>${d}</span>${bt[k] ? `<small>${num(bt[k].per_day)} alerts/day on recent logs</small>` : ""}</label>`).join("")}</fieldset>
        <label class="an-field"><span>Time slice</span><select data-set="bucket_minutes" ${dis}>${[5, 10, 15, 30, 60].map((n) => `<option value="${n}" ${c.bucket_minutes === n ? "selected" : ""}>${n} minutes</option>`).join("")}</select></label>
        <label class="an-field"><span>Learn first for</span><span><input type="number" min="4" max="1000" value="${esc(c.min_history)}" data-set="min_history" ${dis}> slices</span></label>
        <p class="muted an-note">A service is only judged once the model has seen this many active slices of it.</p>
        <label class="an-check"><input type="checkbox" data-set="auto_open" ${c.auto_open ? "checked" : ""} ${dis}><span>Open an incident automatically for each anomaly</span></label>
        <p class="muted an-note">Off by default: anomalies are unusual, not proven breaches, so they wait in Signals for review.</p>
        ${A.draft ? `<div class="an-save"><input id="anNote" type="text" maxlength="300" placeholder="Why the change (saved with the breach policy version)" value="${esc(A.note)}"><button class="btn ghost" data-act="preview" ${A.pvBusy ? "disabled" : ""}>${A.pvBusy ? "Testing…" : "Test on recent logs"}</button><button class="btn primary" data-act="save" ${A.saving ? "disabled" : ""}>${A.saving ? "Saving…" : "Save"}</button><button class="btn ghost" data-act="discard">Discard</button></div>` : ""}
        ${pv ? `<p class="an-pv">${pv.error ? `<span class="cp-red">${esc(pv.error)}</span>` : pv.note ? esc(pv.note) : `With these settings the model would raise <b>${num((pv.signals || []).length)}</b> anomalies on the current window (now ${num((A.m?.signals || []).length)}).`}</p>` : ""}
        ${edit ? "" : `<p class="muted">You can see the settings; changing them needs the breach:EditDetectors permission.</p>`}
      </section>
      <section class="panel ev2-card"><div class="ev2-ch"><h3>What each setting does</h3></div>
        <ul class="an-checks"><li class="info"><i>i</i><div><b>Sensitivity</b><span>Moves the score cut-off (low 0.72 · medium 0.67 · high 0.62). Higher catches more, with more false alarms.</span></div></li>
          <li class="info"><i>i</i><div><b>Time slice</b><span>Shorter slices react faster to short bursts; longer ones smooth out noise for quiet services.</span></div></li>
          <li class="info"><i>i</i><div><b>Learn first for</b><span>How much history a service needs before it can alert. New services wait instead of alerting on everything.</span></div></li>
          <li class="info"><i>i</i><div><b>Auto-open incidents</b><span>Turns every anomaly into a suspected incident with its legal clocks. Best kept off until the model has been tuned with reviews.</span></div></li></ul></section></div>`;
  }
  async function preview() {
    A.pvBusy = true; A.pv = null; render();
    try { A.pv = await api("/api/breach/model/retrain", { method: "POST", body: JSON.stringify({ preview: { ...cfg(), ...A.draft } }) }); } catch (e) { A.pv = { error: e.message }; }
    A.pvBusy = false; render();
  }
  async function save() {
    const note = $("anNote")?.value.trim();
    if (!note) { toast("Describe the change first.", false); $("anNote")?.focus(); return; }
    A.saving = true; render();
    try {
      const pol = await api("/api/breach-policy");
      const { version, updated_at, updated_by, change_note, ...doc } = pol;
      await api("/api/breach-policy", { method: "PUT", body: JSON.stringify({ policy: { ...doc, anomaly: { ...cfg(), ...doc.anomaly, ...A.draft } }, base_version: version, change_note: note }) });
      A.draft = null; A.pv = null; A.note = ""; await loadPolicy(); toast("Saved. The model re-learns with the new settings."); load(true);
    } catch (e) { toast(e.message, false); }
    A.saving = false; render();
  }

  /* ---------- render + events ---------- */
  function render() {
    const body = $("anBody"); if (!body) return;
    if (!can("breach:ReadSignals")) { body.innerHTML = `<div class="panel cp-empty"><h3>Anomaly detection</h3><p>You need permission to read breach signals. Ask the root user.</p></div>`; return; }
    const keep = document.activeElement?.id, val = keep && $(keep)?.value;
    if (A.tab === "anomalies" && A.sel) {
      const s = byId(A.sel);
      body.innerHTML = s ? report(s) : `<button class="btn ghost sm an-back" data-act="back">← All anomalies</button><div class="panel cp-empty"><p>That anomaly is no longer in the window.</p></div>`;
    } else {
      const part = A.tab === "anomalies" ? list() : A.tab === "model" ? model() : A.tab === "settings" ? settings() : overview();
      body.innerHTML = hero() + tiles() + tabs() + `<div class="ev2-part">${part}</div>`;
    }
    if (keep && $(keep)) { $(keep).value = val; $(keep).focus(); }
  }
  function bind() {
    const body = $("anBody");
    body.addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]"); if (!b) return;
      const a = b.dataset.act, s = b.dataset.id && byId(b.dataset.id);
      if (a === "tab") { A.tab = b.dataset.tab; A.sel = null; render(); window.scrollTo(0, 0); return; }
      if (a === "filter") { A.filter = b.dataset.f; render(); return; }
      if (a === "open") { A.tab = "anomalies"; A.sel = b.dataset.id; A.dismissing = null; render(); window.scrollTo(0, 0); return; }
      if (a === "back") { A.sel = null; render(); return; }
      if (a === "retrain") return load(true);
      if (a === "breach" && s) return Breach.openSignal(s.id);
      if (a === "dismiss-start") { A.dismissing = b.dataset.id; render(); setTimeout(() => $("anReason")?.focus()); return; }
      if (a === "dismiss-cancel") { A.dismissing = null; render(); return; }
      if (a === "dismiss" && s) {
        const reason = $("anReason")?.value.trim();
        if (!reason) { toast("Give a reason, so the review is on record.", false); $("anReason")?.focus(); return; }
        Breach.dismiss(s.id, reason).then((r) => { if (r) { A.dismissing = null; toast("Dismissed. The model will remember this pattern."); load(); } });
        return;
      }
      if (a === "reopen" && s) { Breach.reopen(s.id).then(() => load()); return; }
      if (a === "preview") return preview();
      if (a === "save") return save();
      if (a === "discard") { A.draft = null; A.pv = null; render(); return; }
    });
    body.addEventListener("change", (e) => {
      const k = e.target.dataset.set; if (!k) return;
      const v = e.target.type === "checkbox" ? e.target.checked : k === "bucket_minutes" || k === "min_history" ? Number(e.target.value) : e.target.value;
      A.draft = { ...(A.draft || {}), [k]: v }; A.pv = null; render();
    });
    body.addEventListener("input", (e) => { if (e.target.id === "anNote") A.note = e.target.value; });
  }

  return {
    show() { if (!A.started) { A.started = true; bind(); } render(); if (!A.policy) loadPolicy().then(render); load(); },
    tick(ticks) {
      const a = document.activeElement, editing = A.draft || A.dismissing || ($("view-anomaly").contains(a) && /SELECT|INPUT|TEXTAREA/.test(a?.tagName));
      if (ticks % 5 === 0 && !A.busy && !editing) load();   // live: new log lines are scored every 10 s
    },
    open(id) { A.tab = "anomalies"; A.sel = id; show("anomaly"); },
    aiItem(arg = "") {
      const m = A.m; if (!m) return null;
      const [what, id] = arg.split(":");
      const brief = (s) => ({ service: s.group, from: s.start, to: s.end, severity: s.severity, score: s.score, cut_off: m.cutoff, likely_cause: s.cause, summary: s.summary,
        reasons: s.reasons.map((r) => `${r.label}: ${r.value} (usual ${r.usual}, 95% ≤ ${r.p95}, ${r.z} spreads, ${r.times}× usual)`),
        isolated_by: (s.contributions || []).map((c) => `${c.label} ${Math.round(c.share * 100)}%`), checks: (s.checks || []).map((c) => `${c.label}: ${c.text}`),
        also_unusual: s.together, time_of_day: s.part, review: s.held ? "held back (similar to dismissed)" : stateOf(s) });
      if (what === "sig") {
        const s = byId(id); if (!s) return null;
        return { name: `Anomaly · ${s.group} · ${when(s.start)}`, question: "Explain this anomaly in plain language: what happened, is it likely a personal data breach under the DPDP Act, and exactly what should I check and do next?", text: JSON.stringify(brief(s), null, 1) };
      }
      return { name: `Anomaly model · ${num((m.signals || []).length)} anomalies`, question: "Explain what the anomaly model found: which anomalies matter most, which are probably harmless, and how should I tune it?",
        text: JSON.stringify({ sensitivity: m.sensitivity, cut_off: m.cutoff, lines: m.lines, services: (m.services || []).map((x) => ({ service: x.service, flagged_slices: x.flagged, top_score: x.max_score, learning: x.learning })), backtest: m.backtest,
          held_back: (m.held || []).length, anomalies: (m.signals || []).slice(0, 12).map(brief) }, null, 1) };
    },
  };
})();
