/* Data map: where the client's personal data lives, which services use it, for which purposes, and
   who receives it, built by the service from the shop schema, NigraniAI's database logs, the consent
   policy, the retention rules and the declarations kept here. Tabs: an interactive flow map, the
   data inventory, the record of processing (CSV / print), the gaps, and the declarations editor.
   Only names and counts reach the browser, never data values. While Live is on (the switch at the top)
   the map updates every 4 s from the log rows that arrived since the last update: links that just
   carried traffic pulse, a live feed lists the accesses, and new or closed gaps are announced.
   Uses session / refreshSession / can / ME / show from app.js. */
const DataMap = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => (n == null ? "–" : Number(n).toLocaleString("en-IN"));
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const dt = (v) => { if (!v) return "–"; const d = new Date(v); return isNaN(d) ? String(v) : F.format(d).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase()); };
  const ago = (v) => { if (!v) return "never"; const s = (Date.now() - new Date(v)) / 1000; return s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`; };
  const plural = (n, w) => `${num(n)} ${w}${n === 1 ? "" : "s"}`;

  const CAT = {
    contact: { label: "Contact", color: "#0ea5e9" }, address: { label: "Address", color: "#10b981" }, identity: { label: "Identity", color: "#8b5cf6" },
    financial: { label: "Financial", color: "#f59e0b" }, credentials: { label: "Credentials", color: "#ef4444" }, "customer content": { label: "Customer content", color: "#ec4899" },
    device: { label: "Device / network", color: "#64748b" }, "government ID": { label: "Government ID", color: "#dc2626" }, transaction: { label: "Transaction", color: "#14b8a6" }, "linked to a person": { label: "Linked to a person", color: "#94a3b8" },
  };
  const catOf = (c) => CAT[c] || { label: c, color: "#94a3b8" };
  const PURPOSE_HUES = ["#6366f1", "#0ea5e9", "#10b981", "#f59e0b", "#ec4899", "#14b8a6", "#8b5cf6", "#ef4444"];
  const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const BASIS = { consent: "Consent", legitimate_use: "Legitimate use", legal: "Legal obligation" };
  const COLS = [["s", "Services", "who uses the data"], ["t", "Data stores", "where it lives"], ["p", "Purposes", "why it's used"], ["r", "Recipients", "who else gets it"]];

  const S = {
    started: false, loading: false, scanning: false, err: "", last: null, config: null, history: [], tab: "map",
    personalOnly: true, cat: "", q: "", hover: null, sel: null, invFilter: "personal", invQ: "", gapSev: "", draft: null, dirty: false, saving: false, saveErr: "", toast: "",
    ticking: false, feed: [], pulse: new Set(), pulseUntil: 0, liveErr: "",
    pii: null, piiBusy: false, piiErr: "", detFilter: "personal", detQ: "",
  };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r = await go();
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `HTTP ${r.status}`); e.status = r.status; throw e; }
    return j;
  }
  async function load() {
    S.loading = true; S.err = ""; render();
    try {
      const [v, pv] = await Promise.all([api("/api/datamap"), api("/api/pii").catch(() => null)]);
      S.last = v.last; S.config = v.config; S.history = v.history || []; S.pii = pv;
      if (!S.dirty) S.draft = null;
    } catch (e) { S.err = e.message; }
    S.loading = false;
    const stale = !S.last || Date.now() - new Date(S.last.at) > 6 * 3600e3;
    if (!S.err && stale && can("datamap:Scan")) return scan();
    render();
  }
  async function scan() {
    if (S.scanning) return;
    S.scanning = true; S.err = ""; render();
    try {
      S.last = await api("/api/datamap/scan", { method: "POST" });
      const [v, pv] = await Promise.all([api("/api/datamap"), api("/api/pii").catch(() => null)]); S.config = v.config; S.history = v.history || []; S.pii = pv;
      flash("Data map updated");
    } catch (e) { S.err = e.message; }
    S.scanning = false; render();
  }
  function flash(t, kind = "ok") { S.toast = t; const el = $("dmToast"); if (el) { el.textContent = t; el.className = `ttoast dm-toast ${kind}`; el.hidden = false; clearTimeout(flash.t); flash.t = setTimeout(() => (el.hidden = true), kind === "bad" ? 6000 : 2600); } }

  /* ---------- lookups ---------- */
  const L = () => S.last;
  const purposeIdx = () => Object.fromEntries((L()?.purposes || []).map((p, i) => [p.id, i]));
  const purposeColor = (pid) => PURPOSE_HUES[(purposeIdx()[pid] ?? 0) % PURPOSE_HUES.length];
  const purposeName = (pid) => (L()?.purposes || []).find((p) => p.id === pid)?.name || pid;
  const gapsFor = (node) => (L()?.gaps || []).filter((g) => g.node === node);
  const worst = (gs) => gs.reduce((w, g) => (SEV_ORDER.indexOf(g.severity) < SEV_ORDER.indexOf(w) ? g.severity : w), "info");
  const nodeGaps = gapsFor;

  /* ---------- graph model ---------- */
  function model() {
    const d = L(); if (!d) return null;
    const cat = S.cat, po = S.personalOnly;
    const tableOk = (t) => (!po || t.is_personal) && (!cat || t.categories.includes(cat));
    const tables = d.tables.filter(tableOk);
    const tset = new Set(tables.map((t) => t.table));
    const flows = d.flows.filter((f) => tset.has(f.table) && (!po || f.personal));
    const svcUsed = new Set(flows.map((f) => f.service));
    const services = d.services.filter((s) => svcUsed.has(s.service));
    const purposes = d.purposes;
    const procs = d.processors;
    // order to reduce crossings: purposes fixed; tables by mean purpose index; services by mean table index; recipients by mean purpose index
    const pi = purposeIdx();
    const mean = (xs, dflt) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : dflt);
    tables.sort((a, b) => mean(a.purposes.map((p) => pi[p] ?? 99), 99) - mean(b.purposes.map((p) => pi[p] ?? 99), 99) || b.accesses - a.accesses);
    const ti = Object.fromEntries(tables.map((t, i) => [t.table, i]));
    services.sort((a, b) => {
      const ma = mean(flows.filter((f) => f.service === a.service).map((f) => ti[f.table]), 99), mb = mean(flows.filter((f) => f.service === b.service).map((f) => ti[f.table]), 99);
      return ma - mb;
    });
    procs.sort((a, b) => mean((a.purposes || []).map((p) => pi[p] ?? 99), 99) - mean((b.purposes || []).map((p) => pi[p] ?? 99), 99));
    const nodes = [
      ...services.map((s) => ({ id: `s:${s.service}`, col: 0, label: s.service, sub: `${num(s.personal_accesses || s.accesses)} accesses · ${plural(s.tables.filter((t) => tset.has(t)).length, "store")}`, ref: s })),
      ...tables.map((t) => ({ id: `t:${t.table}`, col: 1, label: t.table, sub: `${t.rows == null ? "?" : num(t.rows)} rows · ${plural(t.personal.length, "field")}`, ref: t, cats: t.categories })),
      ...purposes.map((p) => ({ id: `p:${p.id}`, col: 2, label: p.name, sub: `${BASIS[p.legal_basis] || p.legal_basis || "–"}${p.consent_type === "opt_in" ? " · opt-in" : ""}`, ref: p, color: purposeColor(p.id) })),
      ...procs.map((r) => ({ id: `r:${r.id}`, col: 3, label: r.name, sub: `${r.dpa === true ? "DPA signed" : r.dpa === false ? "No DPA" : "DPA not recorded"} · ${r.role || "Processor"}`, ref: r })),
    ];
    const links = [
      ...flows.map((f) => ({ id: `f:${f.service}>${f.table}`, a: `s:${f.service}`, b: `t:${f.table}`, kind: "flow", count: f.count, bad: f.personal && !f.in_purpose, personal: f.personal, ref: f })),
      ...tables.flatMap((t) => t.purposes.map((p) => ({ id: `tp:${t.table}>${p}`, a: `t:${t.table}`, b: `p:${p}`, kind: "purpose", color: purposeColor(p), ref: t }))),
      ...procs.flatMap((r) => (r.purposes || []).map((p) => ({ id: `pr:${p}>${r.id}`, a: `p:${p}`, b: `r:${r.id}`, kind: "recipient", color: purposeColor(p), ref: r }))),
    ];
    return { nodes, links, flows, maxCount: Math.max(1, ...flows.map((f) => f.count)) };
  }
  function connected(m, id) {
    if (!id) return null;
    const adj = {};
    m.links.forEach((l) => { (adj[l.a] ||= []).push([l.b, l]); (adj[l.b] ||= []).push([l.a, l]); });
    const nodes = new Set([id]), links = new Set();
    const col = (x) => "stpr".indexOf(x[0]);
    // walk outward in both directions, only moving away from the start column, so the highlight is the path through the node
    const walk = (start, dir) => {
      let frontier = [start];
      while (frontier.length) {
        const next = [];
        for (const n of frontier) for (const [o, l] of adj[n] || []) {
          if ((col(o) - col(n)) * dir <= 0) continue;
          links.add(l.id); if (!nodes.has(o)) { nodes.add(o); next.push(o); }
        }
        frontier = next;
      }
    };
    walk(id, 1); walk(id, -1);
    return { nodes, links };
  }

  /* ---------- the map ---------- */
  function mapSvg(m, W) {
    const NW = Math.min(232, Math.max(176, (W - 3 * 96) / 4)), NH = 50, GAP = 14, TOP = 58;
    const colX = [0, 1, 2, 3].map((c) => Math.round(c * (W - NW) / 3));
    const byCol = [0, 1, 2, 3].map((c) => m.nodes.filter((n) => n.col === c));
    const H = TOP + Math.max(...byCol.map((c) => c.length)) * (NH + GAP) + 10;
    const pos = {};
    byCol.forEach((list, c) => {
      const h = list.length * (NH + GAP) - GAP, y0 = TOP + Math.max(0, (H - TOP - 10 - h) / 2);
      list.forEach((n, i) => (pos[n.id] = { x: colX[c], y: y0 + i * (NH + GAP), w: NW, h: NH }));
    });
    // spread link ends along each node's side, ordered by the other end, so they don't stack on one point
    const ends = {};
    m.links.forEach((l) => { (ends[`${l.a}|out`] ||= []).push(l); (ends[`${l.b}|in`] ||= []).push(l); });
    const off = {};
    Object.entries(ends).forEach(([k, ls]) => {
      const out = k.endsWith("|out");
      ls.sort((x, y) => (pos[out ? x.b : x.a]?.y || 0) - (pos[out ? y.b : y.a]?.y || 0));
      const step = Math.min(7, (NH - 16) / Math.max(1, ls.length - 1));
      ls.forEach((l, i) => (off[`${l.id}|${out ? "a" : "b"}`] = (i - (ls.length - 1) / 2) * step));
    });
    const focus = [S.hover, S.sel].find((x) => x && pos[x]);
    const hl = connected(m, focus);
    const q = S.q.trim().toLowerCase();
    const match = (n) => !q || n.label.toLowerCase().includes(q) || (n.ref?.display_name || "").toLowerCase().includes(q);
    const lw = (l) => (l.kind === "flow" ? 1.6 + 8 * Math.log10(l.count + 1) / Math.log10(m.maxCount + 1) : 1.6);
    const linkSvg = m.links.map((l) => {
      const A = pos[l.a], B = pos[l.b]; if (!A || !B) return "";
      const x1 = A.x + A.w, y1 = A.y + A.h / 2 + (off[`${l.id}|a`] || 0), x2 = B.x, y2 = B.y + B.h / 2 + (off[`${l.id}|b`] || 0), dx = (x2 - x1) * 0.5;
      const on = hl ? hl.links.has(l.id) : true, dim = hl && !on;
      const pulse = l.kind === "flow" && Date.now() < S.pulseUntil && S.pulse.has(l.id);
      const cls = ["dm-link", l.kind, l.bad ? "bad" : "", l.kind === "flow" && !l.personal ? "np" : "", on && hl ? "on" : "", dim ? "dim" : "", pulse ? "pulse" : ""].join(" ");
      const stroke = l.kind === "flow" ? "" : ` style="stroke:${l.color}"`;
      return `<path class="${cls}" d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}" stroke-width="${lw(l).toFixed(1)}"${stroke} data-link="${esc(l.id)}"/>`;
    }).join("");
    const nodeSvg = m.nodes.map((n) => {
      const P = pos[n.id], g = nodeGaps(n.id), w = g.length ? worst(g) : null;
      const dim = (hl && !hl.nodes.has(n.id)) || (q && !match(n)), sel = S.sel === n.id;
      const accent = n.col === 2 ? n.color : n.col === 1 ? catOf(n.cats?.[0] || "").color : n.col === 0 ? "var(--primary)" : (n.ref.dpa === true ? "var(--ok)" : "var(--warn)");
      const cats = n.col === 1 ? (n.cats || []).slice(0, 5) : [];
      const right = (w ? 24 : 6) + cats.length * 10;
      const fit = (t, px, cw) => { const m = Math.max(6, Math.floor((P.w - px) / cw)); return t.length > m ? t.slice(0, m - 1) + "…" : t; };
      const label = fit(n.label, 22 + right, 7.4);
      const dots = cats.map((c, i) => `<circle cx="${P.w - (w ? 30 : 12) - i * 10}" cy="17" r="3.6" fill="${catOf(c).color}"><title>${esc(catOf(c).label)}</title></circle>`).join("");
      const badge = w ? `<g class="dm-badge s-${w}" transform="translate(${P.w - 13},16)"><circle r="8"/><text y="3.5" text-anchor="middle">${g.length}</text></g>` : "";
      const recip = "";
      const hot = Date.now() < S.pulseUntil && (n.col === 0 || n.col === 1) && [...S.pulse].some((x) => (n.col === 0 ? x.startsWith(`f:${n.label}>`) : x.endsWith(`>${n.label}`)));
      return `<g class="dm-node c${n.col}${dim ? " dim" : ""}${sel ? " sel" : ""}${w ? ` has-${w}` : ""}${hot ? " hot" : ""}" transform="translate(${P.x},${P.y})" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(`${COLS[n.col][1]}: ${n.label}. ${n.sub}${g.length ? `. ${g.length} gap(s)` : ""}`)}">
        <rect class="dm-nbox" width="${P.w}" height="${P.h}" rx="10"/><rect class="dm-nacc" width="4" height="${P.h - 16}" x="0" y="8" rx="2" style="fill:${accent}"/>
        <text class="dm-nlabel" x="14" y="21">${esc(label)}</text><text class="dm-nsub" x="14" y="38">${esc(fit(n.sub, 24, 6.3))}</text>${dots}${badge}${recip}</g>`;
    }).join("");
    const heads = COLS.map(([, t, s], c) => `<text class="dm-colh" x="${colX[c] + 2}" y="20">${t}</text><text class="dm-cols" x="${colX[c] + 2}" y="38">${s}</text>`).join("");
    return `<svg class="dm-svg${hl ? " hl" : ""}" viewBox="0 0 ${W} ${H}" style="width:${W}px;height:${H}px" role="img" aria-label="Personal data flow map">${heads}<g>${linkSvg}</g><g>${nodeSvg}</g></svg>`;
  }

  function detail(id) {
    const d = L(); if (!d || !id) return "";
    const [k, key] = [id[0], id.slice(2)];
    const gl = gapsFor(id);
    const gapsHtml = gl.length ? `<h4>Gaps</h4>${gl.map(gapCard).join("")}` : `<p class="dm-okline">✓ No gaps here.</p>`;
    const row = (l, v) => `<div class="dm-kv"><span>${l}</span><div>${v}</div></div>`;
    const chips = (xs, f) => (xs.length ? `<div class="dm-chips">${xs.map(f).join("")}</div>` : `<span class="muted">none</span>`);
    const pchip = (p) => `<span class="dm-pchip" style="--c:${purposeColor(p)}">${esc(purposeName(p))}</span>`;
    const cchip = (c) => `<span class="dm-cchip" style="--c:${catOf(c).color}">${esc(catOf(c).label)}</span>`;
    let head = "", body = "";
    if (k === "s") {
      const s = d.services.find((x) => x.service === key); if (!s) return "";
      const fl = d.flows.filter((f) => f.service === key);
      head = `<span class="dm-kind">Service</span><h3>${esc(s.service)}</h3><p class="muted">${esc(s.display_name)}${s.note ? ` · ${esc(s.note)}` : ""}</p>`;
      body = row("Declared purposes", chips(s.purposes, pchip)) + row("Accesses (30 days)", `${num(s.accesses)} <span class="muted">· ${num(s.personal_accesses)} to personal data</span>`)
        + `<h4>Data it uses</h4><div class="dm-flows">${fl.map((f) => `<div class="dm-flow${f.personal && !f.in_purpose ? " bad" : ""}"><b>${esc(f.table)}</b><span>${num(f.count)} · ${esc(Object.entries(f.ops).map(([o, n]) => `${o} ${num(n)}`).join(", "))}</span>${f.personal && !f.in_purpose ? `<em>outside its purposes</em>` : f.purposes.length ? `<small>${f.purposes.map((p) => esc(purposeName(p))).join(", ")}</small>` : ""}</div>`).join("") || `<p class="muted">No database access in the window.</p>`}</div>`
        + (Object.keys(s.log_pii || {}).length ? row("Personal data in its logs", Object.entries(s.log_pii).map(([t, n]) => `${esc(t.replace(/_/g, " ").toLowerCase())}: ${num(n)} line(s), masked`).join("<br>")) : "");
    } else if (k === "t") {
      const t = d.tables.find((x) => x.table === key); if (!t) return "";
      head = `<span class="dm-kind">Data store</span><h3>${esc(t.table)}</h3><p class="muted">${t.rows == null ? "Row count unavailable" : `${num(t.rows)} rows`} · ${t.columns} columns · last used ${esc(ago(t.last_access))}</p>`;
      body = row("Categories", chips(t.categories, cchip)) + row("Purposes", chips(t.purposes, pchip))
        + row("Retention", t.retention.length ? t.retention.map((r) => `<div>${esc(r.id)} · ${esc(r.rule)}</div>`).join("") : `<span class="dm-warn">No retention rule</span>`)
        + `<h4>Personal fields</h4><div class="dm-cols">${t.personal.map((c) => `<span class="dm-col" style="--c:${catOf(c.category).color}"><code>${esc(c.column)}</code><small>${esc(c.kind)}</small></span>`).join("") || `<span class="muted">none</span>`}</div>`
        + `<h4>Used by</h4>${Object.keys(t.services).length ? Object.entries(t.services).sort((a, b) => b[1] - a[1]).map(([s, n]) => `<div class="dm-bar"><span>${esc(s)}</span><i style="width:${Math.max(4, (100 * n) / Math.max(...Object.values(t.services)))}%"></i><b>${num(n)}</b></div>`).join("") : `<p class="muted">No service used it in the last ${d.window_days} days.</p>`}`;
    } else if (k === "p") {
      const p = d.purposes.find((x) => x.id === key); if (!p) return "";
      const r = d.ropa.find((x) => x.purpose === key) || {};
      head = `<span class="dm-kind" style="color:${purposeColor(key)}">Purpose</span><h3>${esc(p.name)}</h3><p class="muted">${esc(p.description)}</p>`;
      body = row("Legal basis", `${esc(BASIS[p.legal_basis] || p.legal_basis || "–")}${p.consent_type ? ` <span class="muted">· ${esc(p.consent_type === "opt_in" ? "opt-in consent" : "notice")}</span>` : ""}`)
        + row("Declared data", chips(p.data_categories, cchip)) + row("Data found", chips(r.found_categories || [], (c) => `<span class="dm-cchip${(p.data_categories || []).includes(c) ? "" : " extra"}" style="--c:${catOf(c).color}" title="${(p.data_categories || []).includes(c) ? "" : "Not stated in the notice"}">${esc(catOf(c).label)}</span>`))
        + row("Data stores", chips(r.tables || [], (t) => `<code class="dm-code">${esc(t)}</code>`)) + row("Services", chips(r.services || [], (s) => `<code class="dm-code">${esc(s)}</code>`))
        + row("Recipients", chips(r.recipients || [], (x) => `<span class="dm-cchip" style="--c:var(--muted)">${esc(x.name)}</span>`));
    } else if (k === "r") {
      const r = d.processors.find((x) => x.id === key); if (!r) return "";
      head = `<span class="dm-kind">Recipient</span><h3>${esc(r.name)}</h3><p class="muted">${esc(r.role || "Processor")}</p>`;
      body = row("Contract (DPA)", r.dpa === true ? `<span class="dm-good">Signed</span>` : r.dpa === false ? `<span class="dm-bad">Not signed</span>` : `<span class="dm-warn">Not recorded</span>`)
        + row("Location", r.country ? esc(r.country) : `<span class="dm-warn">Not recorded</span>`) + row("Purposes", chips(r.purposes || [], pchip)) + row("Data it receives", chips(r.data_categories || [], cchip))
        + (r.detected ? row("Detected", esc(r.detected)) : row("Source", "Declared by your team")) + (r.notes ? row("Notes", esc(r.notes)) : "");
    }
    const edit = can("datamap:Edit") ? `<button class="btn ghost sm" data-act="to-decl">Edit declarations</button>` : "";
    return `<div class="dm-dhead"><div class="dm-dtitle">${head}</div><button class="icon-btn" data-act="close" aria-label="Close details">✕</button></div><div class="dm-dbody">${body}${gapsHtml}<div class="dm-dacts">${edit}</div></div>`;
  }

  /* ---------- sections ---------- */
  function ring(score) {
    const r = 30, c = 2 * Math.PI * r, g = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "E";
    return `<svg class="dm-ring g-${g}" viewBox="0 0 76 76" role="img" aria-label="Data map health ${score} of 100"><circle cx="38" cy="38" r="${r}" class="dm-rtrack"/><circle cx="38" cy="38" r="${r}" class="dm-rval" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c * (1 - score / 100)).toFixed(1)}" transform="rotate(-90 38 38)"/><text x="38" y="43" text-anchor="middle">${score}</text></svg>`;
  }
  function hero() {
    const d = L(), st = d.stats;
    const sevChips = SEV_ORDER.filter((s) => st[`gaps_${s}`]).map((s) => `<button class="dm-sev s-${s}" data-gsev="${s}">${st[`gaps_${s}`]} ${SEV[s].toLowerCase()}</button>`).join("");
    const tiles = [
      ["Personal data stores", `${st.personal_tables}<small>of ${st.tables} tables</small>`, "t"],
      ["Personal fields", `${st.personal_columns}`, "t"],
      ["Services using it", `${st.personal_services}<small>of ${st.services}</small>`, "s"],
      [`Data flows · ${d.window_days} days`, `${st.personal_flows}<small>${num(st.accesses)} accesses</small>`, "s"],
      ["Recipients", `${st.processors}`, "r"],
      ["Gaps to close", `${st.gaps}`, "g"],
    ];
    return `<section class="panel dm-hero">
        <div class="dm-htext">
          <div class="dm-erow"><span class="dm-eyebrow">DPDP Act s.8(1) · accountability</span><span id="dmLive">${livePill()}</span></div>
          <h2>Where ${esc(ME?.client?.name || "your")}${ME?.client?.name ? "’s" : ""} personal data lives, who uses it, and why</h2>
          <p class="muted">Built from the shop’s database schema, its database logs, the consent policy, the retention rules and your declarations.</p>
          <div class="dm-hacts">
            ${can("datamap:Scan") ? `<button class="btn primary${S.scanning ? " loading" : ""}" data-act="scan" ${S.scanning ? "disabled" : ""}>${S.scanning ? "Scanning…" : "Rescan now"}</button>` : ""}
            <button class="btn ghost" data-act="tab" data-tab="ropa">Record of processing</button>
            <button class="btn ghost ai-ask" data-ask-ai="datamap">✦ Ask AI</button>
          </div>
        </div>
        <div class="dm-health">${ring(d.score)}<div><b>Data map health</b><div class="dm-sevs">${sevChips || `<span class="dm-good">No gaps</span>`}</div></div></div>
      </section>
      <div class="dm-tiles">${tiles.map(([l, v, t]) => `<button class="panel dm-tile k-${t}" data-act="tile" data-tile="${t}"><span>${l}</span><b>${v}</b></button>`).join("")}</div>`;
  }
  const liveOn = () => !!document.getElementById("live")?.checked;
  function livePill() {
    const lv = L()?.live, minute = S.feed.filter((e) => Date.now() - e.t < 60000).reduce((n, e) => n + e.n, 0);
    if (!liveOn()) return `<span class="dm-live off" title="Turn on Live at the top of the page">Live paused</span>`;
    if (S.liveErr) return `<span class="dm-live err" title="${esc(S.liveErr)}">Live: retrying</span>`;
    return `<span class="dm-live" title="Updates every 4 seconds from new database log rows">Live · ${lv?.at ? esc(ago(lv.at)) : "starting"}${minute ? ` · +${num(minute)} in the last minute` : ""}</span>`;
  }
  function feedHtml() {
    if (!liveOn()) return `<div class="dm-feed off"><b>Live activity</b><span class="muted">Paused. Turn on Live at the top of the page to watch accesses as they happen.</span></div>`;
    const items = S.feed.slice(0, 8);
    return `<div class="dm-feed"><b><i class="dm-dot"></i>Live activity</b>${items.length ? items.map((e) => `<button class="dm-fitem${e.bad ? " bad" : ""}${Date.now() - e.t < 5000 ? " fresh" : ""}" data-node="f:${esc(e.service)}>${esc(e.table)}" data-feed="t:${esc(e.table)}" title="${esc(Object.entries(e.ops).map(([o, n]) => `${o} ${n}`).join(", "))}"><time>${esc(new Date(e.t).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }))}</time><code>${esc(e.service)}</code><span>→</span><code>${esc(e.table)}</code><em>+${num(e.n)}</em>${e.isNew ? `<i class="dm-new">new flow</i>` : ""}</button>`).join("") : `<span class="muted">Waiting for database activity…</span>`}</div>`;
  }
  function tabs() {
    const n = L()?.gaps.length || 0;
    const list = [["map", "Map"], ["inventory", "Inventory"], ["ropa", "Record of processing"], ["gaps", `Gaps${n ? ` <i class="dm-count">${n}</i>` : ""}`], ["detect", "Detection"], ["decl", "Declarations"]];
    return `<div class="cp-tabs dm-tabs" role="tablist">${list.map(([k, l]) => `<button role="tab" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}" data-tab="${k}" data-act="tab">${l}</button>`).join("")}</div>`;
  }
  function mapTab() {
    const d = L(), cats = [...new Set(d.tables.flatMap((t) => t.categories))].sort((a, b) => Object.keys(CAT).indexOf(a) - Object.keys(CAT).indexOf(b));
    return `<section class="panel dm-mapp">
      <div class="dm-tools">
        <div class="dm-cats" role="group" aria-label="Filter by data category"><button class="dm-cf${!S.cat ? " on" : ""}" data-cat="">All data</button>${cats.map((c) => `<button class="dm-cf${S.cat === c ? " on" : ""}" data-cat="${esc(c)}" style="--c:${catOf(c).color}"><i></i>${esc(catOf(c).label)}</button>`).join("")}</div>
        <div class="dm-tright">
          <label class="switch"><input type="checkbox" id="dmPersonal" ${S.personalOnly ? "checked" : ""}><i></i>Personal data only</label>
          <input type="search" id="dmSearch" placeholder="Find a service, table…" value="${esc(S.q)}" aria-label="Find on the map">
        </div>
      </div>
      <div id="dmFeed">${feedHtml()}</div>
      <div class="dm-legend"><span><i class="lg-in"></i>Within its purposes</span><span><i class="lg-out"></i>Outside its purposes</span><span><i class="lg-np"></i>Not personal data</span><span><i class="lg-w"></i>Thicker = more accesses</span><span class="muted">Hover to trace a path · click for details</span></div>
      <div class="dm-wrap" id="dmWrap"><div class="dm-canvas" id="dmCanvas"></div><aside class="dm-drawer${S.sel ? " open" : ""}" id="dmDrawer" aria-live="polite">${S.sel ? detail(S.sel) : ""}</aside><div class="dm-tip" id="dmTip" hidden></div></div>
    </section>`;
  }
  function drawMap() {
    const c = $("dmCanvas"); if (!c) return;
    const m = model();
    if (!m.nodes.length) { c.innerHTML = `<div class="cp-empty">Nothing matches this filter.</div>`; return; }
    const cs = getComputedStyle(c), W = Math.max(980, Math.floor((c.clientWidth || 1012) - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - 1));
    c.innerHTML = mapSvg(m, W);
    c._m = m;
  }
  function inventoryTab() {
    const d = L(), q = S.invQ.trim().toLowerCase();
    const list = d.tables.filter((t) => (S.invFilter === "all" || (S.invFilter === "personal" ? t.is_personal : !t.is_personal)) && (!q || t.table.includes(q) || t.personal.some((c) => c.column.includes(q))));
    const card = (t) => {
      const g = gapsFor(`t:${t.table}`), w = g.length ? worst(g) : null, maxS = Math.max(1, ...Object.values(t.services));
      return `<article class="panel dm-inv${w ? ` has-${w}` : ""}" data-node="t:${esc(t.table)}">
        <header><div><code class="dm-tname">${esc(t.table)}</code><span class="muted">${t.rows == null ? "?" : num(t.rows)} rows · ${t.columns} columns</span></div>${w ? `<span class="dm-sev s-${w}">${g.length} gap${g.length > 1 ? "s" : ""}</span>` : t.is_personal ? `<span class="dm-sev s-ok">OK</span>` : `<span class="dm-sev s-np">Not personal</span>`}</header>
        ${t.categories.length ? `<div class="dm-chips">${t.categories.map((c) => `<span class="dm-cchip" style="--c:${catOf(c).color}">${esc(catOf(c).label)}</span>`).join("")}</div>` : ""}
        ${t.personal.length ? `<div class="dm-cols">${t.personal.map((c) => `<span class="dm-col" style="--c:${catOf(c.category).color}" title="${esc(c.v2 ? `${c.verdict} ${c.confidence}% · ${(c.evidence || []).join("; ")}` : c.kind)}"><code>${esc(c.column)}</code><small>${esc(c.kind)}${c.v2 ? ` · ${c.confidence}%` : ""}</small></span>`).join("")}</div>` : ""}
        <dl class="dm-dl">
          <div><dt>Purposes</dt><dd>${t.purposes.length ? t.purposes.map((p) => `<span class="dm-pchip" style="--c:${purposeColor(p)}">${esc(purposeName(p))}</span>`).join("") : t.is_personal ? `<span class="dm-bad">None declared</span>` : `<span class="muted">–</span>`}</dd></div>
          <div><dt>Retention</dt><dd>${t.retention.length ? t.retention.map((r) => esc(r.rule)).join("<br>") : t.is_personal ? `<span class="dm-warn">No rule</span>` : `<span class="muted">–</span>`}</dd></div>
          <div><dt>Last used</dt><dd>${esc(ago(t.last_access))}</dd></div>
        </dl>
        <div class="dm-used">${Object.entries(t.services).sort((a, b) => b[1] - a[1]).map(([s, n]) => {
          const bad = d.flows.find((f) => f.service === s && f.table === t.table && f.personal && !f.in_purpose);
          return `<div class="dm-bar${bad ? " bad" : ""}"><span>${esc(s)}</span><i style="width:${Math.max(4, (100 * n) / maxS)}%"></i><b>${num(n)}</b></div>`;
        }).join("") || `<p class="muted">No service used it in the last ${d.window_days} days.</p>`}</div>
      </article>`;
    };
    return `<div class="dm-invtools"><div class="dm-seg" role="group">${[["personal", "Personal data"], ["all", "All tables"], ["np", "Not personal"]].map(([k, l]) => `<button class="${S.invFilter === k ? "on" : ""}" data-inv="${k}">${l}</button>`).join("")}</div>
      <input type="search" id="dmInvQ" placeholder="Find a table or column…" value="${esc(S.invQ)}" aria-label="Find a table or column"></div>
      <div class="dm-invgrid">${list.map(card).join("") || `<div class="panel cp-empty">No tables match.</div>`}</div>`;
  }
  function ropaTab() {
    const d = L();
    const cell = (xs, f = esc) => (xs && xs.length ? xs.map(f).join(", ") : `<span class="muted">–</span>`);
    return `<section class="panel dm-ropa-head"><div><h3>Record of processing activities</h3><p class="muted">One entry per purpose, generated from the live data map: what personal data is processed, why, on what basis, where it's kept, who uses and receives it, how long it's kept, and how it's protected. ${esc(ME?.client?.name || "")} · data fiduciary · ${esc(dt(d.at))}.</p></div>
        <div class="dm-hacts"><button class="btn ghost" data-act="csv">Export CSV</button><button class="btn primary" data-act="print">Print / save as PDF</button></div></section>
      <div class="dm-ropa">${d.ropa.map((r) => {
        const extra = (r.found_categories || []).filter((c) => !(r.declared_categories || []).includes(c) && !["customer content", "linked to a person", "device"].includes(c));
        return `<article class="panel dm-ropa-card${r.purpose ? "" : " orphan"}" style="--c:${r.purpose ? purposeColor(r.purpose) : "var(--err)"}">
          <header><h3>${esc(r.name)}</h3>${r.purpose ? `<span class="dm-basis">${esc(BASIS[r.legal_basis] || r.legal_basis || "–")}${r.consent_type === "opt_in" ? " · opt-in" : ""}</span>` : `<span class="dm-sev s-high">Needs a purpose</span>`}${r.gaps.length ? `<button class="dm-sev s-${worst((d.gaps || []).filter((g) => r.gaps.includes(g.id)))}" data-act="tab" data-tab="gaps">${r.gaps.length} gap${r.gaps.length > 1 ? "s" : ""}</button>` : ""}</header>
          <p class="muted">${esc(r.description || "")}</p>
          <dl class="dm-rgrid">
            <div><dt>Data principals</dt><dd>${esc(r.principals)}</dd></div>
            <div><dt>Personal data (notice)</dt><dd>${cell(r.declared_categories, (c) => esc(catOf(c).label))}</dd></div>
            <div><dt>Personal data (found)</dt><dd>${cell(r.found_categories, (c) => `<span class="${extra.includes(c) ? "dm-warn" : ""}" title="${extra.includes(c) ? "Not stated in the notice" : ""}">${esc(catOf(c).label)}</span>`)}</dd></div>
            <div><dt>Data stores</dt><dd>${cell(r.tables, (t) => `<code class="dm-code">${esc(t)}</code>`)}</dd></div>
            <div><dt>Systems / services</dt><dd>${cell(r.services, (s) => `<code class="dm-code">${esc(s)}</code>`)}</dd></div>
            <div><dt>Recipients</dt><dd>${cell(r.recipients, (x) => `${esc(x.name)}${x.country ? ` (${esc(x.country)})` : ""}${x.dpa === true ? " · DPA ✓" : ` · <span class="dm-warn">DPA ${x.dpa === false ? "missing" : "?"}</span>`}`)}</dd></div>
            <div><dt>Retention</dt><dd>${r.retention.length ? r.retention.map((x) => `<code class="dm-code">${esc(x.table)}</code> ${x.rules.length ? esc(x.rules.join("; ")) : `<span class="dm-warn">no rule</span>`}`).join("<br>") : `<span class="muted">–</span>`}</dd></div>
            <div><dt>Safeguards</dt><dd>${cell(r.safeguards)}</dd></div>
          </dl></article>`;
      }).join("")}</div>`;
  }
  function gapCard(g) {
    return `<div class="dm-gap s-${g.severity}"><div class="dm-gtop"><span class="dm-sev s-${g.severity}">${SEV[g.severity]}</span><b>${esc(g.title)}</b></div>
      <p>${esc(g.detail)}</p><div class="dm-gfix"><span>Fix</span>${esc(g.fix)}</div>
      <div class="dm-gfoot"><small>${esc(g.ref)}</small>${g.node && S.tab !== "map" ? `<button class="btn ghost sm" data-act="locate" data-node="${esc(g.node)}">Show on map</button>` : ""}</div></div>`;
  }
  function gapsTab() {
    const d = L(), gs = d.gaps.filter((g) => !S.gapSev || g.severity === S.gapSev);
    const bar = SEV_ORDER.filter((s) => d.stats[`gaps_${s}`]).map((s) => `<i class="s-${s}" style="flex:${d.stats[`gaps_${s}`]}" title="${d.stats[`gaps_${s}`]} ${SEV[s]}"></i>`).join("");
    return `<section class="panel dm-gsum"><div><h3>${d.gaps.length ? `${d.gaps.length} gap${d.gaps.length > 1 ? "s" : ""} to close` : "No gaps"}</h3><p class="muted">Each gap cites the DPDP Act or Rules and says how to close it. Closing a gap and rescanning raises the health score (now ${d.score}).</p></div>
        ${d.gaps.length ? `<div class="dm-gbar">${bar}</div><div class="dm-sevs"><button class="dm-sev${!S.gapSev ? " on" : ""}" data-gsev="">All ${d.gaps.length}</button>${SEV_ORDER.filter((s) => d.stats[`gaps_${s}`]).map((s) => `<button class="dm-sev s-${s}${S.gapSev === s ? " on" : ""}" data-gsev="${s}">${d.stats[`gaps_${s}`]} ${SEV[s].toLowerCase()}</button>`).join("")}</div>` : ""}</section>
      <div class="dm-glist">${gs.map(gapCard).join("") || `<div class="panel cp-empty">Nothing at this level.</div>`}</div>`;
  }

  /* ---------- detection (PII detection v2) ---------- */
  const VERDICT = { confirmed: "Confirmed", likely: "Likely", possible: "Possible", not_personal: "Not personal" };
  function v1Badge(r) {
    const personal = r.verdict === "confirmed" || r.verdict === "likely";
    if (r.feedback) return `<span class="dt-v1 fb">${r.feedback.verdict === "not_personal" ? "rejected" : "confirmed"} by ${esc(r.feedback.by)}</span>`;
    if (personal && !r.v1) return `<span class="dt-v1 new" title="Name-only detection (v1) missed this">new in v2</span>`;
    if (!personal && r.v1) return `<span class="dt-v1 drop" title="v1 flagged it by name (${esc(r.v1)})">v1 false alarm${r.verdict === "possible" ? "?" : ""}</span>`;
    if (personal && r.v1) return `<span class="dt-v1 same" title="v1: ${esc(r.v1)}">v1 agreed</span>`;
    return "";
  }
  function detectTab() {
    const v = S.pii, cols = v?.columns, edit = can("datamap:Edit");
    if (!cols) return `<section class="panel cp-empty dm-empty"><h3>PII detection v2</h3><p>Checks every column four ways: its name, sampled values with checksums, links to people, and a local language model for free text.</p>${can("datamap:Scan") ? `<button class="btn primary${S.piiBusy ? " loading" : ""}" data-act="pii-scan" ${S.piiBusy ? "disabled" : ""}>${S.piiBusy ? "Detecting…" : "Run detection"}</button>` : ""}${S.piiErr ? `<p class="cp-red">${esc(S.piiErr)}</p>` : ""}</section>`;
    const st = cols.stats, m = v.model || cols.model || {}, lg = v.logs || {};
    const all = Object.entries(cols.tables).flatMap(([t, tv]) => tv.columns.map((c) => ({ ...c, person_table: tv.person_table })));
    const q = S.detQ.trim().toLowerCase();
    const pick = (r) => S.detFilter === "personal" ? r.verdict === "confirmed" || r.verdict === "likely" : S.detFilter === "review" ? r.verdict === "possible"
      : S.detFilter === "changed" ? (!!r.v1) !== (r.verdict === "confirmed" || r.verdict === "likely") || !!r.feedback : true;
    const list = all.filter((r) => pick(r) && (!q || `${r.table}.${r.column} ${r.label || ""}`.toLowerCase().includes(q)));
    const byTable = {};
    list.forEach((r) => (byTable[r.table] ||= []).push(r));
    const order = ["confirmed", "likely", "possible", "not_personal"];
    const tiles = [
      ["Columns checked", num(st.columns), `${num(cols.sample)} values sampled per table`],
      ["Personal data", num(st.personal), `${st.confirmed} confirmed · ${st.likely} likely`],
      ["To review", num(st.possible), "not enough evidence to decide"],
      ["Found beyond names", num(st.new_vs_v1 ?? 0), `${st.hidden} hidden (values only)`],
      ["v1 false alarms", num(st.dropped), "flagged by name, not by values"],
      ["Engine precision", st.feedback ? `${Math.round((100 * (st.feedback_agreed ?? 0)) / st.feedback)}%` : "–", st.feedback ? `agreed with ${st.feedback_agreed ?? 0} of ${st.feedback} answers from your team` : "measured from your confirm / reject answers"],
    ];
    const kinds = v.kinds || {};
    const kindOpts = (cur) => Object.entries(kinds).map(([k, x]) => `<option value="${esc(k)}" ${k === cur ? "selected" : ""}>${esc(x.label)}</option>`).join("");
    return `<section class="panel dt-hero">
        <div><span class="dm-eyebrow">PII detection v2 · fused detection</span><h3>Every column checked four ways, with the evidence</h3>
          <p class="muted">Name and context · sampled values with checksums (Luhn, Verhoeff, PAN, GSTIN…) · links to people · ${m.available ? "a local language model for names in free text" : "language model off"}. Values are read only in memory and never stored. Scanned ${esc(ago(cols.at))} in ${cols.seconds}s.</p>
          <div class="dm-hacts">${can("datamap:Scan") ? `<button class="btn primary${S.piiBusy ? " loading" : ""}" data-act="pii-scan" ${S.piiBusy ? "disabled" : ""}>${S.piiBusy ? "Detecting…" : "Rescan detection"}</button>` : ""}
            <span class="dt-model ${m.available ? "on" : ""}">${m.available ? `● ${esc(m.model || "Presidio + spaCy (local)")}` : "Language model not installed"}</span></div>
          ${S.piiErr ? `<p class="cp-red">${esc(S.piiErr)}</p>` : ""}</div>
      </section>
      <div class="dm-tiles dt-tiles">${tiles.map(([l, b, sm]) => `<div class="panel dm-tile"><span>${esc(l)}</span><b>${b}</b><small class="muted">${esc(sm)}</small></div>`).join("")}</div>
      <section class="panel dt-logs"><div><h3>Log lines</h3><p class="muted">${num(lg.scanned)} lines checked (last ${lg.window_days || 7} days, then live) for personal data the log masker missed.</p></div>
        <div class="dt-lstats"><div class="${lg.leaks ? "bad" : "good"}"><b>${num(lg.leaks || 0)}</b><span>unmasked in stored logs</span></div>
          <div><b>${num(lg.masked_total || 0)}</b><span>masked by the pipeline</span></div>
          <div class="${lg.masked_false_positives ? "warn" : ""}"><b>${num(lg.masked_false_positives || 0)}</b><span>of those are false alarms (timestamps)</span></div></div>
        ${lg.leaks ? `<p>${Object.entries(lg.by_kind || {}).map(([k, n]) => `<span class="dm-sev s-high">${num(n)} ${esc((lg.kinds || {})[k] || k)}</span>`).join(" ")} <button class="btn ghost sm" data-act="go-unmasked">Open in Log Telemetry</button></p>` : `<p class="dm-okline">✓ No unmasked personal data in the stored logs.</p>`}</section>
      <div class="dm-invtools"><div class="dm-seg" role="group">${[["personal", `Personal (${st.personal})`], ["review", `To review (${st.possible})`], ["changed", "Changed vs v1"], ["all", "All columns"]].map(([k, l]) => `<button class="${S.detFilter === k ? "on" : ""}" data-detf="${k}">${l}</button>`).join("")}</div>
        <input type="search" id="dmDetQ" placeholder="Find a column…" value="${esc(S.detQ)}" aria-label="Find a column"></div>
      ${Object.keys(byTable).length ? Object.entries(byTable).map(([t, rows]) => `<section class="panel dt-table"><header><code class="dm-tname">${esc(t)}</code>${cols.tables[t]?.person_table ? `<span class="dm-sev s-np">about people</span>` : ""}<span class="muted">${rows.length} column${rows.length > 1 ? "s" : ""}</span></header>
        ${rows.sort((a, b) => order.indexOf(a.verdict) - order.indexOf(b.verdict) || b.confidence - a.confidence).map((r) => `<div class="dt-row v-${esc(r.verdict)}">
          <div class="dt-col"><code>${esc(r.column)}</code><small>${esc(r.type || "")}</small></div>
          <div class="dt-kind">${r.kind ? `<span class="dm-cchip" style="--c:${catOf(r.category).color}">${esc(r.label)}</span>` : `<span class="muted">–</span>`}${v1Badge(r)}</div>
          <div class="dt-conf"><span class="dt-verdict v-${esc(r.verdict)}">${VERDICT[r.verdict]}</span><span class="dt-bar"><i style="width:${r.verdict === "not_personal" ? 100 - r.confidence : r.confidence}%"></i></span><small>${r.verdict === "not_personal" ? "" : `${r.confidence}%`}</small></div>
          <ul class="dt-ev">${(r.evidence || []).map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
          ${edit ? `<div class="dt-acts">${r.feedback ? `<button class="btn ghost sm" data-fb="reset" data-t="${esc(r.table)}" data-c="${esc(r.column)}" title="Clear your answer">Reset</button>` : `
            <button class="btn ghost sm" data-fb="personal" data-t="${esc(r.table)}" data-c="${esc(r.column)}" data-k="${esc(r.kind || "")}" title="Yes, personal data">✓</button>
            <button class="btn ghost sm" data-fb="not_personal" data-t="${esc(r.table)}" data-c="${esc(r.column)}" title="Not personal data">✕</button>
            <select class="dt-fix" data-fbkind data-t="${esc(r.table)}" data-c="${esc(r.column)}" aria-label="It's actually"><option value="">It's actually…</option>${kindOpts("")}</select>`}</div>` : ""}
        </div>`).join("")}</section>`).join("") : `<div class="panel cp-empty">No columns match.</div>`}`;
  }
  async function piiScan() {
    S.piiBusy = true; S.piiErr = ""; render();
    try { await api("/api/pii/scan", { method: "POST" }); S.pii = await api("/api/pii"); flash("Detection updated"); }
    catch (e) { S.piiErr = e.message; }
    S.piiBusy = false; render();
  }
  async function piiFeedback(body) {
    try { await api("/api/pii/feedback", { method: "PUT", body: JSON.stringify(body) }); S.pii = await api("/api/pii"); flash(body.remove ? "Answer cleared" : "Saved: the verdict follows your answer on every scan"); }
    catch (e) { flash(e.message, "bad"); }
    render();
  }

  /* ---------- declarations ---------- */
  const clone = (o) => JSON.parse(JSON.stringify(o));
  function draft() {
    if (!S.draft) S.draft = clone({ services: S.config.services || {}, tables: S.config.tables || {}, processors: S.config.processors || [], ignore_tables: S.config.ignore_tables || [], rev: S.config.rev });
    return S.draft;
  }
  function declTab() {
    const d = L(), dr = draft(), edit = can("datamap:Edit"), ps = d.purposes;
    const dis = edit ? "" : "disabled";
    const svcNames = [...new Set([...d.services.map((s) => s.service), ...Object.keys(dr.services)])].sort();
    const usesPurpose = (svc, pid) => d.flows.some((f) => f.service === svc && f.personal && (d.tables.find((t) => t.table === f.table)?.purposes || []).includes(pid));
    const head = `<tr><th></th>${ps.map((p) => `<th><span class="dm-pdot" style="--c:${purposeColor(p.id)}"></span>${esc(p.name)}</th>`).join("")}</tr>`;
    const svcRows = svcNames.map((s) => {
      const v = dr.services[s] || { purposes: [], note: "" }, info = d.services.find((x) => x.service === s);
      return `<tr><th scope="row"><code>${esc(s)}</code><small>${esc(info?.display_name && info.display_name !== s ? info.display_name : "")}${info ? ` · ${num(info.personal_accesses)} personal accesses` : " · not seen in the logs"}</small>
        <input type="text" class="dm-note" data-svc-note="${esc(s)}" value="${esc(v.note || "")}" placeholder="What it does" maxlength="200" ${dis}></th>
        ${ps.map((p) => `<td><label class="dm-check${usesPurpose(s, p.id) && !v.purposes.includes(p.id) ? " uses" : ""}" title="${usesPurpose(s, p.id) && !v.purposes.includes(p.id) ? "It used data of this purpose but isn't allowed to" : ""}"><input type="checkbox" data-svc="${esc(s)}" data-p="${esc(p.id)}" ${v.purposes.includes(p.id) ? "checked" : ""} ${dis}><i></i></label></td>`).join("")}</tr>`;
    }).join("");
    const tabRows = d.tables.filter((t) => t.is_personal || (dr.tables[t.table]?.purposes || []).length).map((t) => {
      const v = dr.tables[t.table] || { purposes: [] }, pol = t.policy_purposes || [], rules = t.retention.filter((r) => r.type !== "declared");
      return `<tr><th scope="row"><code>${esc(t.table)}</code><small>${t.categories.map((c) => esc(catOf(c).label)).join(", ")}${rules.length ? ` · retention: ${esc(rules.map((r) => r.id).join(", "))}` : ""}</small>
        ${rules.length ? "" : `<input type="text" class="dm-note" data-tbl-ret="${esc(t.table)}" value="${esc(v.retention || "")}" placeholder="Retention, if no rule covers it (e.g. erased with the account)" maxlength="200" ${dis}>`}</th>
        ${ps.map((p) => pol.includes(p.id) ? `<td><label class="dm-check fixed" title="From the consent policy (edit it in Consent & Purpose)"><input type="checkbox" checked disabled><i></i></label></td>`
          : `<td><label class="dm-check"><input type="checkbox" data-tbl="${esc(t.table)}" data-p="${esc(p.id)}" ${v.purposes.includes(p.id) ? "checked" : ""} ${dis}><i></i></label></td>`).join("")}</tr>`;
    }).join("");
    const procCats = ["identity", "contact", "address", "financial", "credentials", "customer content", "device"];
    const det = Object.fromEntries((d.processors || []).map((p) => [p.id, p.detected]));
    const procRows = dr.processors.map((p, i) => `<article class="dm-proc">
        <div class="dm-pgrid">
          <label>Name<input type="text" data-proc="${i}" data-f="name" value="${esc(p.name)}" maxlength="80" ${dis}></label>
          <label>Role<input type="text" data-proc="${i}" data-f="role" value="${esc(p.role || "")}" maxlength="120" placeholder="e.g. Payment gateway" ${dis}></label>
          <label>Country / region<input type="text" data-proc="${i}" data-f="country" value="${esc(p.country || "")}" maxlength="60" placeholder="e.g. India" ${dis}></label>
          <label>Data processing agreement<select data-proc="${i}" data-f="dpa" ${dis}><option value="null" ${p.dpa == null ? "selected" : ""}>Not recorded</option><option value="true" ${p.dpa === true ? "selected" : ""}>Signed</option><option value="false" ${p.dpa === false ? "selected" : ""}>Not signed</option></select></label>
        </div>
        <div class="dm-prow"><span>Purposes</span><div class="dm-chips">${ps.map((x) => `<label class="dm-tog" style="--c:${purposeColor(x.id)}"><input type="checkbox" data-proc="${i}" data-pp="${esc(x.id)}" ${(p.purposes || []).includes(x.id) ? "checked" : ""} ${dis}><span>${esc(x.name)}</span></label>`).join("")}</div></div>
        <div class="dm-prow"><span>Data it receives</span><div class="dm-chips">${procCats.map((c) => `<label class="dm-tog" style="--c:${catOf(c).color}"><input type="checkbox" data-proc="${i}" data-pc="${esc(c)}" ${(p.data_categories || []).includes(c) ? "checked" : ""} ${dis}><span>${esc(catOf(c).label)}</span></label>`).join("")}</div></div>
        <div class="dm-prow"><span>Notes</span><input type="text" data-proc="${i}" data-f="notes" value="${esc(p.notes || "")}" maxlength="300" placeholder="Contract reference, contact…" ${dis}></div>
        <footer>${det[p.id] ? `<span class="dm-det">● Detected: ${esc(det[p.id])}</span>` : `<span class="muted">Declared by your team</span>`}${edit ? `<button class="btn ghost sm" data-act="proc-del" data-i="${i}">Remove</button>` : ""}</footer>
      </article>`).join("");
    return `${!edit ? `<div class="panel dm-ro">You can view the declarations. Changing them needs the <code>datamap:Edit</code> permission.</div>` : ""}
      <section class="panel dm-decl"><h3>Services and their purposes</h3><p class="muted">Tick what each service is allowed to use personal data for. An amber dot marks a purpose whose data the service used in the last ${d.window_days} days without being allowed to: tick it (and update the notice) or remove that access.</p>
        <div class="dm-tscroll"><table class="dm-matrix">${head}${svcRows}</table></div></section>
      <section class="panel dm-decl"><h3>Data stores and their purposes</h3><p class="muted">Purposes from the consent policy are fixed here (greyed); add any others a table serves. A table no retention rule covers can state how long it's kept instead (better: add a rule in Retention).</p>
        <div class="dm-tscroll"><table class="dm-matrix">${head}${tabRows}</table></div></section>
      <section class="panel dm-decl"><div class="dm-dh"><h3>Processors and recipients</h3>${edit ? `<button class="btn ghost sm" data-act="proc-add">+ Add a processor</button>` : ""}</div><p class="muted">Everyone outside ${esc(ME?.client?.name || "the company")} who receives personal data. Detected ones are found in the logs and settings on every scan.</p>
        <div class="dm-procs">${procRows || `<p class="muted">None yet.</p>`}</div></section>
      ${edit ? `<div class="dm-savebar${S.dirty ? " show" : ""}"><span>${S.saveErr ? `<b class="cp-red">${esc(S.saveErr)}</b>` : "You have unsaved changes."}</span><div><button class="btn ghost" data-act="discard">Discard</button><button class="btn primary${S.saving ? " loading" : ""}" data-act="save" ${S.saving ? "disabled" : ""}>Save and rescan</button></div></div>` : ""}`;
  }
  async function saveDecl() {
    S.saving = true; S.saveErr = ""; render();
    try {
      const dr = draft();
      const body = { ...dr, processors: dr.processors.filter((p) => (p.name || "").trim()) };
      S.config = await api("/api/datamap/config", { method: "PUT", body: JSON.stringify(body) });
      S.draft = null; S.dirty = false; S.saving = false; flash("Declarations saved");
      if (can("datamap:Scan")) await scan(); else render();
      return;
    } catch (e) { S.saveErr = e.status === 409 ? "Someone else changed the declarations. Discard to load theirs, then redo your change." : e.message; }
    S.saving = false; render();
  }

  /* ---------- export ---------- */
  function csv() {
    const d = L(), q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const head = ["Purpose", "Description", "Legal basis", "Consent", "Data principals", "Personal data (notice)", "Personal data (found)", "Data stores", "Services", "Recipients", "Retention", "Safeguards", "Open gaps"];
    const rows = d.ropa.map((r) => [r.name, r.description, BASIS[r.legal_basis] || r.legal_basis || "", r.consent_type || "", r.principals, (r.declared_categories || []).join("; "), (r.found_categories || []).join("; "),
      r.tables.join("; "), r.services.join("; "), r.recipients.map((x) => `${x.name}${x.country ? ` (${x.country})` : ""}${x.dpa === true ? " DPA signed" : " DPA not recorded"}`).join("; "),
      r.retention.map((x) => `${x.table}: ${x.rules.join(", ") || "no rule"}`).join("; "), r.safeguards.join("; "), r.gaps.length]);
    const text = [head, ...rows].map((r) => r.map(q).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv" }));
    a.download = `record-of-processing-${(ME?.client?.id || "client")}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  /* ---------- render ---------- */
  function render() {
    const body = $("dmBody"); if (!body) return;
    if (!S.last) {
      body.innerHTML = S.scanning || S.loading
        ? `<section class="panel dm-scanning"><div class="dm-pulse"><i></i><i></i><i></i><i></i></div><h3>${S.scanning ? "Mapping your personal data…" : "Loading…"}</h3><p class="muted">${S.scanning ? "Reading the database schema and row counts, the last 30 days of database logs, the consent policy and the retention rules." : ""}</p></section>`
        : `<section class="panel cp-empty dm-empty"><h3>See where your personal data lives</h3><p>${S.err ? `<span class="cp-red">${esc(S.err)}</span>` : "The data map reads the database schema and the logs to show which services use which personal data, for what purpose, and who receives it."}</p>
           ${can("datamap:Scan") ? `<button class="btn primary" data-act="scan">Build the data map</button>` : `<p class="muted">Ask someone with the <code>datamap:Scan</code> permission to run the first scan.</p>`}</section>`;
      return;
    }
    const keepScroll = window.scrollY;
    body.innerHTML = `<div id="dmTop">${hero()}</div>` + (S.err ? `<p class="cp-red dm-err">${esc(S.err)}</p>` : "") + `<div id="dmTabsBar">${tabs()}</div>`
      + `<div id="dmTabBody">${tabBody()}</div>`
      + `<div id="dmToast" class="ttoast dm-toast" role="status" hidden></div>`;
    if (S.tab === "map") drawMap();
    window.scrollTo(0, keepScroll);
  }
  const tabBody = () => (S.tab === "map" ? mapTab() : S.tab === "inventory" ? inventoryTab() : S.tab === "ropa" ? ropaTab() : S.tab === "gaps" ? gapsTab() : S.tab === "detect" ? detectTab() : declTab());
  const swap = (el, html) => { if (el && el._html !== html) { el.innerHTML = html; el._html = html; } };
  function liveUpdate() {
    // update in place: never steal focus or a click, drop an unsaved declaration, or close the drawer
    if (S.down) { S.pending = true; return; }
    S.pending = false;
    const top = $("dmTop"); if (!top) return render();
    const pill = livePill(), h = hero().replace(/<span id="dmLive">[\s\S]*?<\/span><\/div>/, `<span id="dmLive"></span></div>`);
    if (top._html !== h) { top.innerHTML = h; top._html = h; }
    swap($("dmLive"), pill);
    swap($("dmTabsBar"), tabs());
    if (S.tab === "map") { drawMap(); const f = $("dmFeed"); if (f) f.innerHTML = feedHtml(); const dr = $("dmDrawer"); if (dr && S.sel) dr.innerHTML = detail(S.sel); return; }
    if (S.tab === "decl" || S.tab === "detect") return;      // forms and dropdowns: never redrawn under the user
    const tb = $("dmTabBody"), active = document.activeElement;
    if (tb && active && tb.contains(active) && active.tagName === "INPUT") return;
    if (tb) tb.innerHTML = tabBody();
  }
  async function tick() {
    if (!S.last || S.scanning || S.ticking || S.loading || document.getElementById("view-datamap").hidden) return;
    S.ticking = true;
    try {
      const r = await api("/api/datamap/live", { method: "POST" });
      if (!r || !r.stats) { S.ticking = false; return; }
      S.liveErr = "";
      const lv = r.live || {};
      const badFlows = new Set((r.flows || []).filter((f) => f.personal && !f.in_purpose).map((f) => `${f.service}>${f.table}`));
      const now = Date.now();
      (lv.delta || []).forEach((d) => S.feed.unshift({ t: now, service: d.service, table: d.table, n: d.n, ops: d.ops || {}, isNew: d.new_flow, bad: badFlows.has(`${d.service}>${d.table}`) }));
      S.feed = S.feed.slice(0, 40);
      S.pulse = new Set((lv.delta || []).map((d) => `f:${d.service}>${d.table}`)); S.pulseUntil = now + 3500;
      S.last = r;
      if ((lv.new_gaps || []).length) flash(`New gap: ${lv.new_gaps[0].title}${lv.new_gaps.length > 1 ? ` (+${lv.new_gaps.length - 1} more)` : ""}`, "bad");
      else if ((lv.closed_gaps || []).length) flash(`Gap closed: ${lv.closed_gaps[0].title}`, "ok");
      liveUpdate();
    } catch (e) { S.liveErr = e.message; swap($("dmLive"), livePill()); }
    S.ticking = false;
  }
  function redrawMapOnly() { if (S.tab !== "map") return; drawMap(); const dr = $("dmDrawer"); if (dr) { dr.classList.toggle("open", !!S.sel); dr.innerHTML = S.sel ? detail(S.sel) : ""; } }

  function tip(e, html) {
    const t = $("dmTip"), w = $("dmWrap"); if (!t || !w) return;
    if (!html) { t.hidden = true; return; }
    const r = w.getBoundingClientRect();
    t.innerHTML = html; t.hidden = false;
    const x = Math.min(e.clientX - r.left + 14, r.width - t.offsetWidth - 8), y = e.clientY - r.top + 14;
    t.style.left = `${Math.max(8, x)}px`; t.style.top = `${y}px`;
  }
  function linkTip(id) {
    const d = L();
    if (id.startsWith("f:")) {
      const [s, t] = id.slice(2).split(">"), f = d.flows.find((x) => x.service === s && x.table === t); if (!f) return "";
      return `<b>${esc(s)} → ${esc(t)}</b><br>${num(f.count)} accesses · ${esc(Object.entries(f.ops).map(([o, n]) => `${o} ${num(n)}`).join(", "))}<br>${f.personal ? (f.in_purpose ? `<span class="dm-good">Within: ${f.purposes.map((p) => esc(purposeName(p))).join(", ")}</span>` : `<span class="dm-bad">Outside the service's purposes</span>`) : "Not personal data"}`;
    }
    if (id.startsWith("tp:")) { const [t, p] = id.slice(3).split(">"); return `<b>${esc(t)}</b> serves <b>${esc(purposeName(p))}</b>`; }
    if (id.startsWith("pr:")) { const [p, r] = id.slice(3).split(">"); return `<b>${esc(purposeName(p))}</b> data goes to <b>${esc(d.processors.find((x) => x.id === r)?.name || r)}</b>`; }
    return "";
  }
  function setDraft(fn) { draft(); fn(S.draft); S.dirty = true; S.saveErr = ""; const bar = document.querySelector(".dm-savebar"); if (bar) { bar.classList.add("show"); bar.querySelector("span").textContent = "You have unsaved changes."; } }

  function bind() {
    const body = $("dmBody");
    body.addEventListener("pointerdown", () => { S.down = true; });
    window.addEventListener("pointerup", () => { if (!S.down) return; S.down = false; if (S.pending) setTimeout(liveUpdate, 0); });
    window.addEventListener("pointercancel", () => { S.down = false; });
    body.addEventListener("click", (e) => {
      const c = e.target.closest("[data-cat]"); if (c) { S.cat = c.dataset.cat; S.sel = null; return render(); }
      const gs = e.target.closest("[data-gsev]"); if (gs) { S.gapSev = gs.dataset.gsev; S.tab = "gaps"; return render(); }
      const inv = e.target.closest("[data-inv]"); if (inv) { S.invFilter = inv.dataset.inv; return render(); }
      const df = e.target.closest("[data-detf]"); if (df) { S.detFilter = df.dataset.detf; return render(); }
      const fb = e.target.closest("[data-fb]");
      if (fb) { const d = fb.dataset; return piiFeedback(d.fb === "reset" ? { table: d.t, column: d.c, remove: true } : { table: d.t, column: d.c, verdict: d.fb, kind: d.fb === "personal" ? d.k || null : null }); }
      const b = e.target.closest("[data-act]");
      if (b) {
        const a = b.dataset.act;
        if (a === "scan") return scan();
        if (a === "pii-scan") return piiScan();
        if (a === "go-unmasked") return Telemetry.openUnmasked();
        if (a === "tab") { S.tab = b.dataset.tab; if (S.tab === "gaps" && b.closest(".dm-ropa")) S.gapSev = ""; return render(); }
        if (a === "tile") { const t = b.dataset.tile; S.tab = t === "g" ? "gaps" : t === "t" ? "inventory" : "map"; S.gapSev = ""; return render(); }
        if (a === "close") { S.sel = null; return redrawMapOnly(); }
        if (a === "locate") { S.tab = "map"; S.cat = ""; S.q = ""; const id = b.dataset.node; S.personalOnly = !(id.startsWith("t:") && !L().tables.find((t) => `t:${t.table}` === id)?.is_personal); S.sel = id; render(); $("dmWrap")?.scrollIntoView({ behavior: "smooth", block: "start" }); return; }
        if (a === "to-decl") { S.tab = "decl"; return render(); }
        if (a === "csv") return csv();
        if (a === "print") { document.body.classList.add("dm-printing"); const done = () => { document.body.classList.remove("dm-printing"); window.removeEventListener("afterprint", done); }; window.addEventListener("afterprint", done); window.print(); setTimeout(done, 1500); return; }
        if (a === "save") return saveDecl();
        if (a === "discard") { S.draft = null; S.dirty = false; S.saveErr = ""; return load(); }
        if (a === "proc-add") { setDraft((d) => d.processors.push({ id: "", name: "", role: "", purposes: [], data_categories: [], country: "", dpa: null, notes: "" })); return render(); }
        if (a === "proc-del") { setDraft((d) => d.processors.splice(+b.dataset.i, 1)); return render(); }
      }
      const fi = e.target.closest("[data-feed]");
      if (fi) { S.sel = fi.dataset.feed; return redrawMapOnly(); }
      const n = e.target.closest("[data-node]");
      if (n && S.tab === "map") { S.sel = S.sel === n.dataset.node ? null : n.dataset.node; return redrawMapOnly(); }
      if (n && S.tab === "inventory") { S.tab = "map"; S.sel = n.dataset.node; S.personalOnly = !!L().tables.find((t) => `t:${t.table}` === n.dataset.node)?.is_personal; return render(); }
    });
    body.addEventListener("keydown", (e) => {
      const n = e.target.closest?.("[data-node]");
      if (n && (e.key === "Enter" || e.key === " ") && S.tab === "map") { e.preventDefault(); S.sel = n.dataset.node; redrawMapOnly(); document.querySelector(`[data-node="${CSS.escape(S.sel)}"]`)?.focus(); }
      if (e.key === "Escape" && S.sel) { S.sel = null; redrawMapOnly(); }
    });
    body.addEventListener("mouseover", (e) => {
      if (S.tab !== "map" || !e.target.closest?.("#dmCanvas")) return;
      const n = e.target.closest(".dm-node");
      const id = n ? n.dataset.node : null;
      if (id !== S.hover) { S.hover = id; drawMap(); }
    });
    body.addEventListener("mouseout", (e) => {
      if (S.tab !== "map" || !S.hover) return;
      if (!e.relatedTarget || !e.relatedTarget.closest?.("#dmCanvas")) { S.hover = null; drawMap(); tip(null, ""); }
    });
    body.addEventListener("mousemove", (e) => {
      if (S.tab !== "map") return;
      const l = e.target.closest?.(".dm-link");
      if (l) tip(e, linkTip(l.dataset.link)); else if (!e.target.closest?.(".dm-tip")) tip(e, "");
    });
    body.addEventListener("input", (e) => {
      const t = e.target;
      if (t.id === "dmSearch") { S.q = t.value; return drawMap(); }
      if (t.id === "dmDetQ") { S.detQ = t.value; const pos = t.selectionStart; render(); const el = $("dmDetQ"); el?.focus(); el?.setSelectionRange(pos, pos); return; }
      if (t.id === "dmInvQ") { S.invQ = t.value; const pos = t.selectionStart; render(); const el = $("dmInvQ"); el?.focus(); el?.setSelectionRange(pos, pos); return; }
      if (t.dataset.tblRet != null) return setDraft((d) => { (d.tables[t.dataset.tblRet] ||= { purposes: [] }).retention = t.value; });
      if (t.dataset.svcNote != null) return setDraft((d) => { (d.services[t.dataset.svcNote] ||= { purposes: [], note: "" }).note = t.value; });
      if (t.dataset.proc != null && t.dataset.f && t.tagName === "INPUT") return setDraft((d) => { d.processors[+t.dataset.proc][t.dataset.f] = t.value; });
    });
    body.addEventListener("change", (e) => {
      const t = e.target;
      if (t.id === "dmPersonal") { S.personalOnly = t.checked; S.sel = null; return render(); }
      if (t.dataset.fbkind != null && t.value) return piiFeedback({ table: t.dataset.t, column: t.dataset.c, verdict: "personal", kind: t.value });
      if (t.dataset.svc) return setDraft((d) => { const v = (d.services[t.dataset.svc] ||= { purposes: [], note: "" }); v.purposes = t.checked ? [...new Set([...v.purposes, t.dataset.p])] : v.purposes.filter((x) => x !== t.dataset.p); });
      if (t.dataset.tbl) return setDraft((d) => { const v = (d.tables[t.dataset.tbl] ||= { purposes: [] }); v.purposes = t.checked ? [...new Set([...v.purposes, t.dataset.p])] : v.purposes.filter((x) => x !== t.dataset.p); });
      if (t.dataset.proc != null) {
        const i = +t.dataset.proc;
        if (t.dataset.f === "dpa") return setDraft((d) => { d.processors[i].dpa = t.value === "true" ? true : t.value === "false" ? false : null; });
        if (t.dataset.pp) return setDraft((d) => { const p = d.processors[i]; p.purposes = t.checked ? [...new Set([...(p.purposes || []), t.dataset.pp])] : (p.purposes || []).filter((x) => x !== t.dataset.pp); });
        if (t.dataset.pc) return setDraft((d) => { const p = d.processors[i]; p.data_categories = t.checked ? [...new Set([...(p.data_categories || []), t.dataset.pc])] : (p.data_categories || []).filter((x) => x !== t.dataset.pc); });
      }
    });
    let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => { if (S.tab === "map" && !document.getElementById("view-datamap").hidden) drawMap(); }, 150); });
    window.addEventListener("beforeunload", (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } });
  }

  return {
    show() { if (!S.started) { S.started = true; bind(); } if (!S.last || Date.now() - (S.loadedAt || 0) > 60000) { S.loadedAt = Date.now(); load(); } else render(); },
    tick,
    liveChanged() { if (S.started && !document.getElementById("view-datamap").hidden && $("dmTop")) { swap($("dmLive"), livePill()); const f = $("dmFeed"); if (f) f.innerHTML = feedHtml(); } },
    access() { // permissions arrived after the page first rendered
      if (!S.started || document.getElementById("view-datamap").hidden) return;
      const stale = !S.last || Date.now() - new Date(S.last.at) > 6 * 3600e3;
      if (!S.loading && !S.scanning && stale && can("datamap:Scan")) scan(); else render();
    },
    async summary() { try { return (await api("/api/datamap")).last; } catch { return null; } },
    aiItem() {
      const d = L(); if (!d) return null;
      return { name: `Data map (health ${d.score}/100, ${d.gaps.length} gaps)`, question: "Explain my data map: where personal data is at risk, which gaps matter most under the DPDP Act, and what to fix first.",
        text: JSON.stringify({ scanned: d.at, window_days: d.window_days, stats: d.stats,
          tables: d.tables.filter((t) => t.is_personal).map((t) => ({ table: t.table, categories: t.categories, purposes: t.purposes.map(purposeName), retention: t.retention.map((r) => r.rule), used_by: t.services })),
          services: d.services.map((s) => ({ service: s.service, purposes: s.purposes.map(purposeName), personal_accesses: s.personal_accesses })),
          outside_purpose_flows: d.flows.filter((f) => f.personal && !f.in_purpose).map((f) => `${f.service} → ${f.table} (${f.count})`),
          processors: d.processors.map((p) => ({ name: p.name, role: p.role, dpa: p.dpa, country: p.country || "not recorded", purposes: (p.purposes || []).map(purposeName) })),
          gaps: d.gaps.map((g) => `${g.severity}: ${g.title}. ${g.detail} [${g.ref}] Fix: ${g.fix}`) }, null, 1) };
    },
  };
})();
