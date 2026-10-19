/* Main dashboard: one view of every module, with live charts.
   Log charts come from a compact copy of the last 7 days of guardrail.activity_logs
   (time, level, service, status, data category), loaded once and then topped up every
   10 s with lines ingested since the last check. NigraniAI has no aggregate queries,
   so bucketing happens here. Module numbers come from Consent / Retention / Breach
   .summary() (each cached for 60 s). Inline SVG, themed with the CSS tokens.
   Uses authedFetch / rest / show / TITLES / DASH_URL / DB_SCHEMA from app.js. */
const Dashboard = (() => {
  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtN = (n) => Number(n || 0).toLocaleString("en-IN");
  const nOf = (n, one, many = one + "s") => `${fmtN(n)} ${n === 1 ? one : many}`;
  const pct = (a, b) => (b ? `${((a / b) * 100).toFixed(a / b < 0.1 ? 1 : 0)}%` : "–");
  const up = (s) => s.replace(/\b(am|pm)\b/gi, (m) => m.toUpperCase());
  const fmt = (o) => new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", ...o });
  const F_LAST = fmt({ day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  const F_TIME = fmt({ hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const F_HOUR = fmt({ hour: "numeric", hour12: true });
  const F_DAY = fmt({ day: "numeric", month: "short" });
  const F_TIP = fmt({ day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  function ago(ms) {
    const m = Math.round(ms / 6e4);
    if (m < 1) return "just now";
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`;
  }

  const RANGES = { "24h": { label: "24 hours", hours: 24, step: 1 }, "3d": { label: "3 days", hours: 72, step: 2 }, "7d": { label: "7 days", hours: 168, step: 6 } };
  const WINDOW_MS = 7 * 864e5;
  const COLS = "logged_at,ingested_at,level,service,http_status,data_category";
  const D = { range: "3d", rows: [], mark: "", loading: false, loadedAt: null, fullAt: 0, error: "", mods: { logs: null, breach: null, consent: null, retention: null }, modsAt: null, busy: false, started: false };
  try { const r = localStorage.getItem("dbRange"); if (RANGES[r]) D.range = r; } catch {}

  /* ---------- data: compact log window ---------- */
  async function page(params) {
    const u = new URL(`${DASH_URL}/rest/v1/activity_logs`);
    Object.entries(params).forEach(([k, v]) => u.searchParams.set(k, v));
    const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA, Prefer: "count=exact" } });
    if (!r.ok) throw new Error(`activity_logs → ${r.status}`);
    return { rows: await r.json(), total: Number((r.headers.get("content-range") || "").split("/")[1]) || 0 };
  }
  async function loadWindow() {
    const since = new Date(Date.now() - WINDOW_MS).toISOString();
    const base = { select: COLS, logged_at: `gte.${since}`, order: "logged_at.asc", limit: "1000" };
    const first = await page({ ...base, offset: "0" });
    const pages = Math.min(60, Math.ceil(first.total / 1000));   // cap: 60k lines per 7 days
    const rest = [];
    for (let i = 1; i < pages; i += 6) {                          // 6 requests at a time
      const batch = await Promise.all(Array.from({ length: Math.min(6, pages - i) }, (_, k) => page({ ...base, offset: String((i + k) * 1000) })));
      rest.push(...batch);
    }
    D.rows = [first, ...rest].flatMap((p) => p.rows);
    D.mark = D.rows.reduce((m, r) => (r.ingested_at > m ? r.ingested_at : m), "");
    D.fullAt = Date.now();
  }
  async function loadNew() {
    // Lines ingested since the last check (they may carry older logged_at values).
    for (let i = 0; i < 10; i++) {
      const p = await page({ select: COLS, ingested_at: `gt.${D.mark || "1970-01-01"}`, order: "ingested_at.asc", limit: "1000" });
      if (!p.rows.length) break;
      D.rows.push(...p.rows);
      D.mark = p.rows[p.rows.length - 1].ingested_at;
      if (p.rows.length < 1000) break;
    }
    const cut = new Date(Date.now() - WINDOW_MS).toISOString();
    if (D.rows.length && D.rows[0].logged_at < cut) D.rows = D.rows.filter((r) => r.logged_at >= cut);
  }
  async function refreshLogs() {
    if (D.loading) return;
    D.loading = true;
    try {
      // Full reload every 10 minutes keeps the window exact; otherwise only new lines.
      if (!D.fullAt || Date.now() - D.fullAt > 6e5) await loadWindow(); else await loadNew();
      D.loadedAt = new Date(); D.error = "";
    } catch (e) { D.error = e.message; }
    finally { D.loading = false; paintCharts(); }
  }

  /* ---------- data: module summaries + all-time log facts ---------- */
  async function countRows(table, params = {}, select = "id") {
    const u = new URL(`${DASH_URL}/rest/v1/${table}`);
    u.searchParams.set("select", select); u.searchParams.set("limit", "1");
    Object.entries(params).forEach(([k, v]) => u.searchParams.set(k, v));
    const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA, Prefer: "count=exact" } });
    if (!r.ok) throw new Error(`${table} → ${r.status}`);
    return { total: Number((r.headers.get("content-range") || "").split("/")[1]) || 0, rows: await r.json() };
  }
  async function loadLogFacts() {
    const [svcs, act, db, pii, err, last] = await Promise.all([
      rest("/service_registry", { select: "service,display_name", active: "is.true" }),
      countRows("activity_logs"), countRows("database_logs"), countRows("rule_pii_in_logs", {}, "event_ref"),
      countRows("activity_logs", { level: "eq.ERROR" }), countRows("activity_logs", { order: "logged_at.desc" }, "logged_at"),
    ]);
    return { services: svcs.length, names: Object.fromEntries(svcs.map((s) => [s.service, s.display_name || s.service])), act: act.total, db: db.total, pii: pii.total, errors: err.total, last: last.rows[0]?.logged_at || null };
  }
  function mod(key, action, load) {
    const M = D.mods;
    if (!ME) return Promise.resolve();
    if (!can(action)) return Promise.resolve((M[key] = { error: true, noaccess: true }));
    return load().then((v) => (M[key] = v || { error: true }), () => (M[key] = { error: true }));
  }
  async function refreshModules() {
    if (D.busy) { D.again = true; return; }
    D.again = false;
    D.busy = true;
    const M = D.mods;
    const jobs = [
      loadLogFacts().then((v) => (M.logs = v), () => (M.logs ??= { error: true })),
      // Sections the user has no permission for show "No access" instead of being queried. Until the
      // permissions have loaded (ME is null) the cards stay "loading"; applyAccess() refreshes them.
      mod("breach", "breach:ReadSignals", () => Breach.summary()),
      mod("consent", "consent:ReadFindings", () => Consent.summary()),
      mod("retention", "retention:ReadSchedule", () => Retention.summary()),
    ].map((p) => p.then(paintModules));
    await Promise.allSettled(jobs);
    D.modsAt = new Date(); paintModules();
    D.busy = false;
    if (D.again) refreshModules();   // permissions arrived while this pass ran
  }

  /* ---------- chart helpers (SVG) ---------- */
  // Round axis step: 1, 2 or 5 × 10^k (so labels read 2k, 4k, 6k).
  function niceStep(v) {
    if (v <= 1) return 1;
    const p = 10 ** Math.floor(Math.log10(v)), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
  }
  const short = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));

  // Stacked columns + optional line. series: [{key,label,cls}], buckets: [{t0,t1,v:{key:n},line}]
  function columns(el, buckets, series, line) {
    const W = Math.max(280, el.clientWidth), H = 230, L = 40, R = 10, T = 12, B = 28;
    const iw = W - L - R, ih = H - T - B, n = buckets.length, bw = iw / n, gap = Math.min(6, bw * 0.28);
    const tot = (b) => series.reduce((s, x) => s + (b.v[x.key] || 0), 0);
    const top = Math.max(1, ...buckets.map(tot), ...(line ? buckets.map((b) => b.line || 0) : []));
    const step = niceStep(top / 4), ticks = Math.max(1, Math.ceil(top / step)), max = step * ticks;
    const y = (v) => T + ih - (v / max) * ih;
    let g = "";
    for (let i = 0; i <= ticks; i++) { const v = step * i; g += `<line class="ch-grid" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text class="ch-ax" x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${short(v)}</text>`; }
    const every = Math.ceil(n / Math.max(2, Math.floor(iw / 70)));
    buckets.forEach((b, i) => {
      const x = L + i * bw;
      let acc = 0;
      for (const s of series) {
        const v = b.v[s.key] || 0;
        if (!v) continue;
        const y1 = y(acc + v), y0 = y(acc);
        g += `<rect class="ch-${s.cls}" x="${(x + gap / 2).toFixed(1)}" y="${y1.toFixed(1)}" width="${Math.max(1, bw - gap).toFixed(1)}" height="${Math.max(0.5, y0 - y1).toFixed(1)}" rx="2"/>`;
        acc += v;
      }
      if (i % every === 0) {
        const newDay = i === 0 || F_DAY.format(b.t0) !== F_DAY.format(buckets[i - every]?.t0 || b.t0);
        g += `<text class="ch-ax" x="${x + bw / 2}" y="${H - 8}" text-anchor="middle">${esc(up(newDay ? `${F_DAY.format(b.t0)}` : F_HOUR.format(b.t0)))}</text>`;
      }
    });
    if (line) {
      const pts = buckets.map((b, i) => `${(L + i * bw + bw / 2).toFixed(1)},${y(b.line || 0).toFixed(1)}`).join(" ");
      g += `<polyline class="ch-line" points="${pts}"/>`;
    }
    g += buckets.map((b, i) => `<rect class="ch-hit" data-i="${i}" x="${L + i * bw}" y="${T}" width="${bw}" height="${ih}"/>`).join("");
    el.innerHTML = `<svg class="ch-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Log lines over time">${g}</svg><div class="ch-tip" hidden></div>`;
    const tip = el.querySelector(".ch-tip"), svg = el.querySelector("svg");
    svg.onmousemove = (e) => {
      const r = e.target.closest(".ch-hit");
      svg.querySelectorAll(".ch-hit.on").forEach((x) => x.classList.remove("on"));
      if (!r) { tip.hidden = true; return; }
      r.classList.add("on");
      const b = buckets[+r.dataset.i];
      tip.innerHTML = `<b>${esc(up(F_TIP.format(b.t0)))} – ${esc(up(F_HOUR.format(b.t1)))}</b>` + series.map((s) => `<span><i class="ch-key ch-${s.cls}"></i>${esc(s.label)}<b>${fmtN(b.v[s.key] || 0)}</b></span>`).join("")
        + (line ? `<span><i class="ch-key ch-line-key"></i>${esc(line)}<b>${fmtN(b.line || 0)}</b></span>` : "");
      tip.hidden = false;
      const bx = el.getBoundingClientRect(), x = e.clientX - bx.left;
      tip.style.left = `${Math.min(Math.max(8, x + 14), bx.width - tip.offsetWidth - 8)}px`;
      tip.style.top = "8px";
    };
    svg.onmouseleave = () => { tip.hidden = true; svg.querySelectorAll(".ch-hit.on").forEach((x) => x.classList.remove("on")); };
  }

  // Donut. segs: [{label, value, cls}]
  function donut(el, segs, center, sub) {
    const total = segs.reduce((s, x) => s + x.value, 0), R = 52, C = 2 * Math.PI * R;
    let off = 0;
    const arcs = total ? segs.filter((s) => s.value).map((s) => {
      const len = (s.value / total) * C, a = `<circle class="dn-seg ch-${s.cls}" r="${R}" cx="70" cy="70" stroke-dasharray="${Math.max(0, len - (segs.filter((x) => x.value).length > 1 ? 2 : 0)).toFixed(2)} ${C.toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"><title>${esc(s.label)}: ${fmtN(s.value)}</title></circle>`;
      off += len; return a;
    }).join("") : "";
    el.innerHTML = `<div class="dn"><svg viewBox="0 0 140 140" width="140" height="140" role="img" aria-label="${esc(sub)}"><circle class="dn-track" r="${R}" cx="70" cy="70"/><g transform="rotate(-90 70 70)">${arcs}</g>
      <text x="70" y="68" text-anchor="middle" class="dn-big">${esc(center)}</text><text x="70" y="86" text-anchor="middle" class="dn-sub">${esc(sub)}</text></svg>
      <ul class="dn-legend">${segs.map((s) => `<li><i class="ch-key ch-${s.cls}"></i><span>${esc(s.label)}</span><b>${fmtN(s.value)}</b><small>${pct(s.value, total)}</small></li>`).join("")}</ul></div>`;
  }

  // Horizontal bars. rows: [{label, parts:[{value, cls, title}], note}]; share = each row is its own 100%.
  function hbars(el, rows, empty, share = false) {
    if (!rows.length) { el.innerHTML = `<p class="ch-empty">${esc(empty)}</p>`; return; }
    const top = Math.max(1, ...rows.map((r) => r.parts.reduce((s, p) => s + p.value, 0)));
    el.innerHTML = `<div class="hb">${rows.map((r) => { const t = r.parts.reduce((s, p) => s + p.value, 0), max = share ? Math.max(1, t) : top; return `<div class="hb-row"><span class="hb-label" title="${esc(r.label)}">${esc(r.label)}</span>
      <span class="hb-track">${r.parts.filter((p) => p.value).map((p) => `<i class="ch-${p.cls}" style="width:${((p.value / max) * 100).toFixed(2)}%" title="${esc(p.title || "")}: ${fmtN(p.value)}"></i>`).join("")}</span><b>${esc(r.note ?? short(t))}</b></div>`; }).join("")}</div>`;
  }

  /* ---------- paint: charts from the log window ---------- */
  const LEVELS = [{ key: "INFO", label: "Info", cls: "info" }, { key: "WARN", label: "Warning", cls: "warn" }, { key: "ERROR", label: "Error", cls: "err" }];
  const SVC_CLS = ["c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10"];
  function paintCharts() {
    const el = $("dbTimeline");
    if (!el) return;
    document.querySelectorAll("[data-range]").forEach((b) => { const on = b.dataset.range === D.range; b.classList.toggle("on", on); b.setAttribute("aria-pressed", on); });
    const live = $("dbLive");
    if (D.error && !D.rows.length) { el.innerHTML = `<p class="ch-empty">Could not read the logs: ${esc(D.error)}</p>`; live.textContent = "Offline"; live.className = "db-live off"; return; }
    if (!D.loadedAt) { el.innerHTML = `<p class="ch-empty">Loading log activity…</p>`; return; }
    const rg = RANGES[D.range], stepMs = rg.step * 36e5;
    const IST_MS = 330 * 6e4;   // align buckets to IST clock hours (UTC+5:30)
    const end = Math.ceil((Date.now() + IST_MS) / stepMs) * stepMs - IST_MS, start = end - rg.hours * 36e5;
    const n = rg.hours / rg.step;
    const buckets = Array.from({ length: n }, (_, i) => ({ t0: new Date(start + i * stepMs), t1: new Date(start + (i + 1) * stepMs), v: {}, line: 0 }));
    const svc = {}, http = { ok: 0, redirect: 0, client: 0, auth: 0, server: 0 };
    let inRange = 0, personal = 0, errors = 0, lastAt = 0, last15 = 0;
    const now = Date.now();
    for (const r of D.rows) {
      const t = Date.parse(r.logged_at);
      if (t > lastAt) lastAt = t;
      if (now - t <= 9e5) last15++;
      if (t < start || t >= end) continue;
      const b = buckets[Math.floor((t - start) / stepMs)];
      const lv = r.level === "ERROR" || r.level === "WARN" ? r.level : "INFO";
      b.v[lv] = (b.v[lv] || 0) + 1;
      inRange++;
      if (lv === "ERROR") errors++;
      if (r.data_category === "personal_data") { b.line++; personal++; }
      svc[r.service] = (svc[r.service] || 0) + 1;
      const s = r.http_status;
      if (s) { if (s < 300) http.ok++; else if (s < 400) http.redirect++; else if (s === 401 || s === 403) http.auth++; else if (s < 500) http.client++; else http.server++; }
    }
    columns(el, buckets, LEVELS, "Personal-data events");
    const peak = buckets.reduce((m, b) => { const t = LEVELS.reduce((s, x) => s + (b.v[x.key] || 0), 0); return t > m.t ? { t, b } : m; }, { t: 0, b: null });
    $("dbStrip").innerHTML = [
      ["Log lines", fmtN(inRange), `last ${rg.label}`],
      ["Peak", peak.b ? fmtN(peak.t) : "–", peak.b ? `${up(F_TIP.format(peak.b.t0))} (${rg.step} h)` : "no activity"],
      ["Error rate", pct(errors, inRange), `${fmtN(errors)} errors`],
      ["Personal-data events", fmtN(personal), `${pct(personal, inRange)} of lines`],
    ].map(([l, v, s]) => `<div class="db-m"><span>${esc(l)}</span><b>${v}</b><small>${esc(s)}</small></div>`).join("");
    const stale = lastAt && now - lastAt > 9e5;
    live.innerHTML = D.loading ? "Updating…" : stale ? `No new logs · last ${esc(ago(now - lastAt))}` : `<i></i>Live · ${fmtN(last15)} lines in 15 min`;
    live.className = `db-live${stale ? " idle" : ""}`;
    $("dbLiveAt").textContent = D.loadedAt ? `Checked ${up(F_TIME.format(D.loadedAt))} IST` : "";

    const names = D.mods.logs?.names || {};
    const svcRows = Object.entries(svc).sort((a, b) => b[1] - a[1]);
    const top = svcRows.slice(0, 7), other = svcRows.slice(7).reduce((s, [, v]) => s + v, 0);
    donut($("dbSvc"), [...top.map(([k, v], i) => ({ label: names[k] || k, value: v, cls: SVC_CLS[i] })), ...(other ? [{ label: "Others", value: other, cls: "c10" }] : [])], short(inRange), `lines · ${rg.label}`);
    const httpTotal = Object.values(http).reduce((a, b) => a + b, 0);
    donut($("dbHttp"), [
      { label: "Success (2xx)", value: http.ok, cls: "ok" }, { label: "Redirect (3xx)", value: http.redirect, cls: "c4" },
      { label: "Sign-in rejected (401/403)", value: http.auth, cls: "warn" }, { label: "Other client errors (4xx)", value: http.client, cls: "c6" },
      { label: "Server errors (5xx)", value: http.server, cls: "err" },
    ], httpTotal ? pct(http.ok, httpTotal) : "–", "requests OK");
    const spark = $("dbSpark");
    if (spark) {
      const vals = buckets.slice(-24).map((b) => LEVELS.reduce((s, x) => s + (b.v[x.key] || 0), 0)), mx = Math.max(1, ...vals);
      spark.innerHTML = `<polyline points="${vals.map((v, i) => `${(i / Math.max(1, vals.length - 1)) * 100},${28 - (v / mx) * 26}`).join(" ")}"/>`;
    }
  }

  /* ---------- paint: module numbers ---------- */
  function paintModules() {
    if (!$("dbAttn")) return;
    const { logs: L, breach: B, consent: C, retention: R } = D.mods;
    const big = (id, v, cls = "") => { const el = $(id); el.innerHTML = v; el.className = cls; };
    const offOf = (x) => (x?.noaccess ? "No access (ask the root user)" : "Consent service not running");
    if (L && !L.error) {
      big("dbLogBig", fmtN(L.act + L.db));
      $("dbLogSub").textContent = `log lines from ${nOf(L.services, "service")} · ${nOf(L.pii, "line")} with personal data masked`;
      $("metricServices").textContent = fmtN(L.services); $("dbAct").textContent = fmtN(L.act); $("dbDb").textContent = fmtN(L.db);
      $("dbPii").textContent = fmtN(L.pii); $("dbErr").textContent = fmtN(L.errors);
      $("dbLast").textContent = L.last ? up(F_LAST.format(new Date(L.last))) + " IST" : "–";
    } else if (L) $("dbLogSub").textContent = "Could not read the logs";
    if (B && !B.error) {
      big("dbBreachBig", fmtN(B.open), B.overdue ? "bad" : B.open ? "warn" : "ok");
      $("dbBreachSub").textContent = B.next ? `${B.overdue ? `${nOf(B.overdue, "obligation")} overdue · ` : ""}next: ${B.next.label} (${B.next.text})` : `open incidents · ${nOf(B.signalsNew, "signal")} to review`;
    } else if (B) $("dbBreachSub").textContent = offOf(B);
    if (C && !C.error) {
      big("dbConsentBig", `${fmtN(C.valid)}<small> / ${fmtN(C.customers)}</small>`, C.issues ? "warn" : "ok");
      $("dbConsentSub").textContent = `customers accepted${C.legacy ? ` · ${fmtN(C.legacy)} existing to re-accept` : ""} · ${nOf(C.issues, "open issue")}`;
    } else if (C) $("dbConsentSub").textContent = offOf(C);
    if (R && !R.error) {
      big("dbRetBig", fmtN(R.past), R.past ? "bad" : "ok");
      $("dbRetSub").textContent = `past their deadline · ${fmtN(R.soon)} due soon · ${fmtN(R.held)} on legal hold`;
    } else if (R) $("dbRetSub").textContent = offOf(R);

    // Module charts
    if (C && !C.error) donut($("dbConsent"), [{ label: "Accepted", value: C.valid, cls: "c1" }, ...(C.legacy != null ? [{ label: "Existing · to re-accept", value: C.legacy, cls: "c10" }] : []), { label: "Needs action", value: C.partial, cls: "warn" }, { label: C.gate ? "Signed up without accepting" : "Never accepted", value: C.none, cls: "err" }], pct(C.valid, C.customers), "accepted");
    else $("dbConsent").innerHTML = `<p class="ch-empty">${C ? offOf(C) : "Checking…"}</p>`;
    if (B && !B.error) hbars($("dbSignals"), B.byDetector.filter((d) => d.signals).map((d) => ({ label: d.name, parts: [{ value: d.fresh, cls: `cat-${d.category}`, title: "To review" }, { value: d.signals - d.fresh, cls: `cat-${d.category} dim`, title: "Reviewed" }], note: d.fresh ? `${d.fresh} new` : `${d.signals}` })), "No detector has fired in the look-back window.");
    else $("dbSignals").innerHTML = `<p class="ch-empty">${B ? offOf(B) : "Checking…"}</p>`;
    if (R && !R.error) hbars($("dbRet"), R.rules.filter((r) => r.total).map((r) => ({ label: r.type === "legal_minimum" ? `${r.name} (legal minimum)` : r.name, parts: r.type === "legal_minimum" ? [{ value: r.held, cls: "hold", title: "On legal hold" }] : [{ value: r.past, cls: "err", title: "Past deadline" }, { value: r.soon, cls: "warn", title: "Due soon" }, { value: Math.max(0, r.total - r.past - r.soon), cls: "okdim", title: "On track" }], note: r.type === "legal_minimum" ? `${short(r.held)} held` : r.past ? `${short(r.past)} past` : r.soon ? `${short(r.soon)} soon` : "On track" })), "No records are covered by the schedule.", true);
    else $("dbRet").innerHTML = `<p class="ch-empty">${R ? offOf(R) : "Checking…"}</p>`;

    // Needs attention: the most urgent items across modules, worst first.
    const items = [];
    const add = (lvl, text, sub, view) => items.push({ lvl, text, sub, view });
    if (B && !B.error) {
      if (B.overdue) add(0, `${nOf(B.overdue, "breach obligation")} overdue`, "Notices to the Board, customers or CERT-In are past their deadline", "breach");
      if (B.next && !B.overdue) add(1, `${B.next.id}: ${B.next.label}`, `${B.next.text} · Rule 7 response clock`, "breach");
      if (B.suspected) add(1, `${nOf(B.suspected, "suspected breach", "suspected breaches")} to assess`, "Confirm or rule out each one so the right clocks apply", "breach");
      if (B.signalsNew) add(2, `${nOf(B.signalsNew, "breach signal")} to review`, "Log activity that crossed a detector threshold", "breach");
      if (B.contactMissing) add(3, "Add the contact person for breach notices", "Rule 7(1)(e): every customer notice must name one", "breach");
    }
    if (C && !C.error) {
      for (const x of C.top) add(x.severity === "critical" || x.severity === "high" ? 0 : 1, x.title, `Consent & purpose · ${x.impact}`, "consent");
      if (C.issues > C.top.length) add(2, `${nOf(C.issues - C.top.length, "more consent issue")}`, `${nOf(C.findings, "finding")} in total`, "consent");
    }
    if (R && !R.error) {
      if (R.conflicts) add(0, `${nOf(R.conflicts, "retention conflict")}`, "A delete rule would remove records before their legal minimum", "retention");
      if (R.erasureOverdue) add(0, `${nOf(R.erasureOverdue, "erasure request")} overdue`, "DPDP Act s.12(3)", "retention");
      if (R.past) add(1, `${nOf(R.past, "record")} past their retention deadline`, "Delete, anonymise or review them", "retention");
      if (R.soon) add(2, `${nOf(R.soon, "record")} reach their deadline within ${R.soonDays} days`, "Retention schedule", "retention");
      if (R.notify) add(1, `${nOf(R.notify, "inactive customer")} to notify before erasure`, "DPDP Rules 2025, Rule 8(2)", "retention");
    }
    if (L && !L.error && L.pii) add(2, `${nOf(L.pii, "log line")} contained personal data patterns`, "Masked in Log Telemetry; check the source code that logged them", "telemetry");
    items.sort((a, b) => a.lvl - b.lvl);
    const ready = [L, B, C, R].every(Boolean), lvlCls = ["bad", "warn", "info", "info"];
    $("dbAttn").innerHTML = items.length ? items.slice(0, 7).map((x) => `<button class="db-item" data-open="${x.view}"><span class="db-dot ${lvlCls[x.lvl]}"></span><span class="cp-row-main"><b>${esc(x.text)}</b><span>${esc(x.sub)}</span></span><span class="db-go">${esc(TITLES[x.view])} →</span></button>`).join("")
      + (items.length > 7 ? `<p class="cp-none">${nOf(items.length - 7, "more item")} in the sections.</p>` : "")
      : `<p class="cp-none">${ready ? "Nothing needs attention right now." : "Checking every module…"}</p>`;
    $("dbAttnCount").textContent = items.length ? fmtN(items.length) : "";
    $("dbAttnCount").hidden = !items.length;

    // Compliance at a glance: one card per area, with its law and status.
    const stat = (label, v, cls = "") => `<div class="db-stat"><span>${esc(label)}</span><b class="${cls}">${v}</b></div>`;
    const card = (view, title, law, data, status, stats, raw) => `<button class="db-mod" data-open="${view}"><div class="db-modhead"><b>${esc(title)}</b>${status}</div><span class="db-law">${esc(law)}</span>
      <div class="db-stats">${data ? stats : `<p class="muted">${data === null ? "Checking…" : offOf(raw)}</p>`}</div></button>`;
    const pill = (cls, t) => `<span class="rt-pill ${cls}">${esc(t)}</span>`;
    const st = (bad, warn) => (bad ? pill("bad", "Action needed") : warn ? pill("warn", "Watch") : pill("ok", "On track"));
    const ok = (x) => (x && !x.error ? x : x ? undefined : null);
    const b = ok(B), c = ok(C), r = ok(R), l = ok(L);
    $("dbMods").innerHTML = [
      card("breach", "Breach response", "DPDP Act s.8(6) · Rules 2025 Rule 7", b, b ? st(b.overdue, b.open || b.signalsNew) : "",
        b && stat("Open incidents", fmtN(b.open), b.open ? "cp-red" : "") + stat("Signals to review", fmtN(b.signalsNew)) + stat("Detectors on", `${fmtN(b.detectorsOn)} / ${fmtN(b.detectors)}`), B),
      card("consent", "Consent & purpose", "DPDP Act s.4–s.6 · Rules 2025 Rule 3", c, c ? st(c.high, c.issues) : "",
        c && stat("Valid consent", `${fmtN(c.valid)} / ${fmtN(c.customers)}`) + stat("Open issues", fmtN(c.issues), c.issues ? "cp-red" : "") + stat("Findings", fmtN(c.findings)), C),
      card("retention", "Retention & erasure", "DPDP Act s.8(7), s.12(3) · Rule 8", r, r ? st(r.past || r.conflicts || r.erasureOverdue, r.soon || r.notify) : "",
        r && stat("Past deadline", fmtN(r.past), r.past ? "cp-red" : "") + stat("Due soon", fmtN(r.soon)) + stat("Legal hold", fmtN(r.held)), R),
      card("telemetry", "Logs & personal data", "DPDP Act s.8(5) · Rule 6 · Rule 8(3)", l, l ? st(false, l.pii) : "",
        l && stat("Services", fmtN(l.services)) + stat("PII lines masked", fmtN(l.pii), l.pii ? "cp-red" : "") + stat("Errors", fmtN(l.errors)), L),
    ].join("");
    if (D.rows.length) paintCharts();   // service names may have arrived
  }

  function bind() {
    $("view-dashboard").addEventListener("click", (e) => {
      const r = e.target.closest("[data-range]");
      if (r) { D.range = r.dataset.range; try { localStorage.setItem("dbRange", D.range); } catch {} return paintCharts(); }
      const b = e.target.closest("[data-open]"); if (b) show(b.dataset.open);
    });
    let t;
    window.addEventListener("resize", () => { clearTimeout(t); t = setTimeout(() => { if (!$("view-dashboard").hidden) paintCharts(); }, 150); });
  }

  // For the AI assistant: log aggregates from the 7-day window, pre-ranked so the model reads
  // numbers instead of adding them up; plus all-time counts. No log messages are included.
  async function context() {
    if (!D.loadedAt) await refreshLogs();
    if (!D.mods.logs) await loadLogFacts().then((v) => (D.mods.logs = v)).catch(() => {});
    const names = D.mods.logs?.names || {}, H = fmt({ day: "numeric", month: "short", hour: "numeric", hour12: true });
    const tally = (keyFn, pred) => { const m = {}; for (const r of D.rows) if (!pred || pred(r)) { const k = keyFn(r); m[k] = (m[k] || 0) + 1; } return m; };
    const rank = (m, n = 9) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ name: names[k] ? `${k} (${names[k]})` : k, count: v }));
    const svc = (r) => r.service, hour = (r) => `${up(H.format(new Date(r.logged_at)))} IST`;
    const is5xx = (r) => r.http_status >= 500, isErr = (r) => r.level === "ERROR", is401 = (r) => r.http_status === 401 || r.http_status === 403;
    const L = D.mods.logs && !D.mods.logs.error ? D.mods.logs : null;
    const times = D.rows.map((r) => r.logged_at).sort();
    return {
      window: "last 7 days of activity_logs", lines: D.rows.length, first_line: times[0] || null, last_line: times[times.length - 1] || null,
      lines_by_level: tally((r) => r.level || "none"), lines_by_service: rank(tally(svc), 12),
      http_responses: { total: D.rows.filter((r) => r.http_status).length, "2xx": D.rows.filter((r) => r.http_status >= 200 && r.http_status < 300).length, "401_403": D.rows.filter(is401).length, other_4xx: D.rows.filter((r) => r.http_status >= 400 && r.http_status < 500 && !is401(r)).length, "5xx": D.rows.filter(is5xx).length },
      server_errors_5xx_by_service: rank(tally(svc, is5xx)), server_errors_5xx_peak_hours: rank(tally(hour, is5xx), 6),
      error_level_lines_by_service: rank(tally(svc, isErr)), error_level_lines_peak_hours: rank(tally(hour, isErr), 6),
      rejected_signins_401_403_by_service: rank(tally(svc, is401)), rejected_signins_peak_hours: rank(tally(hour, is401), 6),
      personal_data_events: D.rows.filter((r) => r.data_category === "personal_data").length, personal_data_by_service: rank(tally(svc, (r) => r.data_category === "personal_data")),
      busiest_hours: rank(tally(hour), 6),
      all_time: L ? { services: L.services, application_lines: L.act, database_lines: L.db, lines_with_pii_masked: L.pii, error_level_lines: L.errors, latest_log_at: L.last } : null,
    };
  }

  return {
    context,
    show() {
      if (!D.started) { D.started = true; bind(); }
      paintCharts(); paintModules();
      refreshLogs(); refreshModules();
    },
    // Called by applyAccess() once the permissions are known (or change).
    access() { if (D.started) refreshModules(); },
    tick(ticks) {
      if (ticks % 5 === 0) { refreshLogs(); refreshModules(); }   // every 10 s; module checks are cached for 60 s
    },
  };
})();
