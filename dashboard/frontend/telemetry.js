/* Log Telemetry — structured view of guardrail.activity_logs.
   activity_logs is the complete stream: every database_logs row is mirrored
   into it as a db_* event, so reading all_logs would show DB events twice.
   Layer is derived from the event (db_* = database, else application).
   Stored times are UTC; everything here renders in IST (Asia/Kolkata).
   Uses DASH_URL / DASH_KEY / session from app.js at call time. */
const Telemetry = (() => {
  const SCHEMA = (window.COMPLIANCE_CONFIG || {}).DB_SCHEMA || "guardrail";
  const TABLE = "/activity_logs";
  const PAGE = 100;
  const COUNT_EVERY_MS = 10000;
  const IST = "Asia/Kolkata";
  const IST_OFFSET_MS = 330 * 60000;
  const COLS = "id,logged_at,ingested_at,service,level,kind,event,trace_id,http_method,route,http_status," +
    "duration_ms,actor_type,actor_ref,data_category,purpose,consent_status,severity,risk_indicators," +
    "pii_masked,masked_pii_types,message,details,source_file,line_no,processing_status";

  // Compliance flags shown on a row. `rule` = guardrail.rule_* view keyed by event_ref.
  const FLAGS = {
    PII_IN_LOG: { sev: "high", title: "Personal data pattern in a log line (masked at ingest)", ref: "DPDP Act 2023 · s.8(5) reasonable security safeguards" },
    NO_CONSENT: { sev: "critical", title: "Marketing processing without valid consent", ref: "DPDP Act 2023 · s.6 consent", rule: "/rule_marketing_without_consent" },
    RETENTION_OVERDUE: { sev: "high", title: "Personal data retained past its retention deadline", ref: "DPDP Act 2023 · s.8(7) erasure", rule: "/rule_retention_overdue" },
    UNMASKED_PII: { sev: "critical", title: "Unmasked personal data stored in this log line (PII detection v2)", ref: "DPDP Act 2023 · s.8(5) · DPDP Rules Rule 6(1)(a)" },
    UNREGISTERED_COLUMN: { sev: "high", title: "Database column not registered in the data inventory", ref: "DPDP Act 2023 · s.5 notice / s.8 obligations" },
  };

  const S = {
    rows: [], ids: new Set(), svc: "", services: [], counts: {},
    trace: "", open: new Set(), fresh: new Set(), ruleFlags: new Map(),
    watermark: null, exhausted: false, total: null, seq: 0, lastCount: 0,
    rawLines: false, updatedAt: null, busy: false,
    inventory: new Map(), // "table.column" -> classification, from db_schema events
    pii: { cols: new Map(), leaks: new Map(), at: 0, view: null }, // PII detection v2: fused column verdicts, unmasked leaks by log id
  };
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => (n == null ? "–" : Number(n).toLocaleString("en-IN"));

  /* ---------- IST time ---------- */
  const fmt = (o) => new Intl.DateTimeFormat("en-IN", { timeZone: IST, ...o });
  const F_TIME = fmt({ hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const F_DAY = fmt({ weekday: "short", day: "numeric", month: "short", year: "numeric" });
  const F_FULL = fmt({ weekday: "short", day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3, hour12: true });
  const F_KEY = new Intl.DateTimeFormat("en-CA", { timeZone: IST, year: "numeric", month: "2-digit", day: "2-digit" });
  const ampm = (s) => s.replace(/\b(am|pm)\b/i, (m) => m.toUpperCase());
  const istTime = (d) => ampm(F_TIME.format(d));
  const istFull = (d) => ampm(F_FULL.format(d)) + " IST";
  const dayKey = (d) => F_KEY.format(d);
  function dayLabel(d) {
    const k = dayKey(d), now = Date.now();
    const rel = k === dayKey(new Date(now)) ? "Today" : k === dayKey(new Date(now - 864e5)) ? "Yesterday" : "";
    return (rel ? rel + " · " : "") + F_DAY.format(d);
  }
  // UTC instant of IST midnight, `daysAgo` days back
  function istMidnight(daysAgo = 0) {
    const [y, m, d] = dayKey(new Date(Date.now() - daysAgo * 864e5)).split("-").map(Number);
    return new Date(Date.UTC(y, m - 1, d) - IST_OFFSET_MS);
  }
  function ago(d) {
    const s = Math.max(0, Math.round((Date.now() - d) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
  function rangeBounds() {
    const v = $("tRange").value;
    if (v === "today") return [istMidnight(0), null];
    if (v === "yesterday") return [istMidnight(1), istMidnight(0)];
    if (v) return [new Date(Date.now() - Number(v) * 60000), null];
    return [null, null];
  }

  /* ---------- REST (guardrail schema, signed-in user via authedFetch) ---------- */
  const headers = (extra = {}) => ({ "Accept-Profile": SCHEMA, ...extra });
  function url(path, pairs) {
    const u = new URL(`${DASH_URL}/rest/v1${path}`);
    for (const [k, v] of pairs) if (v !== "" && v != null) u.searchParams.append(k, v);
    return u;
  }
  async function get(path, pairs) {
    const r = await authedFetch(url(path, pairs), { headers: headers() });
    if (!r.ok) {
      let m = `HTTP ${r.status}`;
      try { const j = await r.json(); m = j.message || m; } catch {}
      throw new Error(`${path.slice(1)}: ${m}`);
    }
    return r.json();
  }
  async function count(pairs) {
    const r = await authedFetch(url(TABLE, [["select", "id"], ...pairs]), { method: "HEAD", headers: headers({ Prefer: "count=exact" }) });
    if (!r.ok) throw new Error(`count: HTTP ${r.status}`);
    const n = Number((r.headers.get("content-range") || "").split("/")[1]);
    return Number.isFinite(n) ? n : null;
  }
  const q = (s) => `"${String(s).replace(/["\\]/g, "")}"`; // quote a value inside and=(...)

  /* ---------- Filters -> PostgREST params ---------- */
  function filterPairs({ withService = true, extraTree = [] } = {}) {
    const p = [], tree = [...extraTree];
    if (withService && S.svc) p.push(["service", `eq.${S.svc}`]);
    const lv = $("tLevel").value;
    if (lv === "WARN+") p.push(["level", "in.(WARN,ERROR)"]);
    else if (lv) p.push(["level", `eq.${lv}`]);
    const layer = $("tLayer").value;
    if (layer === "database") p.push(["event", "like.db_*"]);
    else if (layer === "application") tree.push("or(event.is.null,event.not.like.db_*)");
    const kind = $("tKind").value;
    if (kind) p.push(["kind", `eq.${kind}`]);
    const flag = $("tFlag").value;
    if (flag === "any") tree.push("or(pii_masked.is.true,risk_indicators.neq.{})");
    else if (flag === "pii") p.push(["pii_masked", "is.true"]);
    else if (flag === "personal") p.push(["risk_indicators", "cs.{personal_data_category}"]);
    else if (flag === "unmasked") p.push(["id", `in.(${[...S.pii.leaks.keys()].slice(0, 200).map((x) => `"${String(x).replace(/"/g, "")}"`).join(",") || '"none"'})`]);
    const [from, to] = rangeBounds();
    if (from) p.push(["logged_at", `gte.${from.toISOString()}`]);
    if (to) p.push(["logged_at", `lt.${to.toISOString()}`]);
    if (S.trace) p.push(["trace_id", `eq.${S.trace}`]);
    const text = $("tQ").value.trim().replace(/\*/g, " ");
    if (text) p.push(["message", `ilike.*${text}*`]);
    if (tree.length) p.push(["and", `(${tree.join(",")})`]);
    return p;
  }

  /* ---------- Data loading ---------- */
  async function loadServices() {
    try {
      S.services = await get("/service_registry", [["select", "service,display_name,has_database,active"], ["order", "service.asc"]]);
    } catch { S.services = []; }
  }

  async function reload() {
    const seq = ++S.seq;
    S.busy = true; renderStatus();
    try {
      const [rows, total, head] = await Promise.all([
        get(TABLE, [["select", COLS], ["order", "logged_at.desc,id.desc"], ["limit", PAGE], ...filterPairs()]),
        count(filterPairs()),
        get(TABLE, [["select", "ingested_at"], ["order", "ingested_at.desc"], ["limit", 1]]),
      ]);
      if (seq !== S.seq) return;
      S.rows = []; S.ids.clear(); S.fresh.clear(); S.ruleFlags.clear();
      addRows(rows);
      S.total = total;
      S.exhausted = rows.length < PAGE;
      S.watermark = head[0]?.ingested_at || S.watermark;
      S.updatedAt = new Date(); S.error = "";
      await loadRuleFlags(rows);
    } catch (e) {
      if (seq === S.seq) { S.error = e.message; S.rows = []; S.ids.clear(); }
    } finally {
      if (seq === S.seq) { S.busy = false; render(true); }
    }
    refreshCounts(true);
  }

  async function loadOlder() {
    const last = S.rows[S.rows.length - 1];
    if (!last || S.exhausted) return;
    const seq = S.seq;
    $("tMore").disabled = true;
    try {
      const keyset = `or(logged_at.lt.${q(last.logged_at)},and(logged_at.eq.${q(last.logged_at)},id.lt.${q(last.id)}))`;
      const rows = await get(TABLE, [["select", COLS], ["order", "logged_at.desc,id.desc"], ["limit", PAGE], ...filterPairs({ extraTree: [keyset] })]);
      if (seq !== S.seq) return;
      addRows(rows);
      S.exhausted = rows.length < PAGE;
      await loadRuleFlags(rows);
      render();
    } catch (e) { toast("Could not load older logs: " + e.message); }
    finally { $("tMore").disabled = false; }
  }

  // Live: rows ingested after the watermark, then merged in logged_at order.
  async function tick() {
    if (S.busy || !S.watermark) return;
    const seq = S.seq;
    try {
      const rows = await get(TABLE, [["select", COLS], ["order", "ingested_at.asc"], ["limit", 500],
        ["ingested_at", `gt.${S.watermark}`], ...filterPairs()]);
      const head = await get(TABLE, [["select", "ingested_at"], ["order", "ingested_at.desc"], ["limit", 1]]);
      if (seq !== S.seq) return;
      S.watermark = head[0]?.ingested_at || S.watermark;
      S.updatedAt = new Date(); S.error = "";
      const added = addRows(rows, true);
      if (added.length) {
        if (S.total != null) S.total += added.length;
        await loadRuleFlags(added);
        render();
      } else renderStatus();
    } catch (e) { S.error = e.message; renderStatus(); }
    refreshCounts();
  }

  function addRows(rows, fresh = false) {
    const added = [];
    for (const r of rows) {
      if (S.ids.has(r.id)) continue;
      S.ids.add(r.id); S.rows.push(r); added.push(r);
      if (r.event === "db_schema") learnSchema([r]);
      if (fresh) S.fresh.add(r.id);
    }
    if (fresh && added.length) {
      S.rows.sort((a, b) => (b.logged_at > a.logged_at ? 1 : b.logged_at < a.logged_at ? -1 : b.id > a.id ? 1 : -1));
    }
    return added;
  }

  // Detector rule hits (rule_* views) for the given rows, keyed by event_ref = log id.
  async function loadRuleFlags(rows) {
    const ids = rows.map((r) => r.id);
    if (!ids.length) return;
    const rules = Object.entries(FLAGS).filter(([, f]) => f.rule);
    const alertsReq = get("/compliance_alerts", [["select", "event_ref,rule_id,severity,status,description"], ["event_ref", `in.(${ids.join(",")})`]]).catch(() => []);
    const results = await Promise.all(rules.map(([code, f]) =>
      get(f.rule, [["select", "event_ref"], ["event_ref", `in.(${ids.join(",")})`]]).then((hits) => hits.map((h) => [h.event_ref, code])).catch(() => [])));
    for (const pairs of results) for (const [ref, code] of pairs) {
      const set = S.ruleFlags.get(ref) || new Set(); set.add(code); S.ruleFlags.set(ref, set);
    }
    for (const a of await alertsReq) {
      const set = S.ruleFlags.get(a.event_ref) || new Set(); set.add("ALERT:" + a.rule_id); S.ruleFlags.set(a.event_ref, set);
    }
  }

  // Tab counts; respect every filter except the service tab.
  async function refreshCounts(force = false) {
    if (!force && Date.now() - S.lastCount < COUNT_EVERY_MS) return;
    S.lastCount = Date.now();
    const seq = S.seq;
    const base = filterPairs({ withService: false });
    try {
      const svcNames = S.services.map((s) => s.service);
      const [all, ...rest] = await Promise.all([
        count(base),
        ...svcNames.map((n) => count([["service", `eq.${n}`], ...base])),
      ]);
      if (seq !== S.seq) return;
      S.counts = { "": all };
      svcNames.forEach((n, i) => (S.counts[n] = rest[i]));
      renderTabs();
    } catch {}
  }

  /* ---------- Personal-data inventory (db_schema events) ---------- */
  /* ---------- PII detection v2 ---------- */
  const PII_API = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  async function piiApi(path, opts = {}) {
    const go = () => fetch(PII_API + path, { ...opts, headers: { Authorization: `Bearer ${session?.access_token || ""}` } });
    let r = await go();
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }
  async function loadPii(force = false) {
    if (!force && Date.now() - S.pii.at < 60000) return;
    S.pii.at = Date.now();
    try {
      const [v, logs] = await Promise.all([piiApi("/api/pii"), piiApi("/api/pii/logs", { method: "POST" }).catch(() => null)]);
      const cols = new Map();
      for (const [t, tv] of Object.entries(v.columns?.tables || {})) for (const c of tv.columns) cols.set(`${t}.${c.column}`, c);
      S.pii.cols = cols;
      const lv = logs || v.logs || {};
      S.pii.leaks = new Map((lv.recent || []).map((x) => [x.id, x]));
      S.pii.view = lv;
      piiCache = new WeakMap();
    } catch { /* detection unavailable: the chips fall back to the log pipeline's own classification */ }
  }
  const PII_SHORT = { person_name: "NAME", city_state: "CITY/STATE", payment_ref: "PAYMENT REF", password_hash: "PASSWORD HASH", person_link: "PERSON LINK", free_text: "FREE TEXT", birth_date: "DOB", voter_id: "VOTER ID", bank_account: "BANK ACCOUNT" };
  const piiShort = (k) => PII_SHORT[k] || String(k || "").toUpperCase();
  const piiCatOf = (c) => (c === "credentials" ? "cred" : c === "financial" || c === "government ID" ? "fin" : "pii");
  const FP_CTX = /(time ?stamp|epoch|millis|duration|took|latency|\bat)\W{0,3}$/i;
  const FP_TOKENS = new Set(["CARD", "CREDIT_CARD", "AADHAAR", "PHONE", "PHONE_NUMBER", "BANK_ACCOUNT"]);
  function maskedFalse(msg, idx, tok) { return FP_TOKENS.has(tok) && FP_CTX.test(String(msg || "").slice(Math.max(0, idx - 24), idx)); }

  async function loadInventory() {
    for (let off = 0; ; off += 1000) {
      let rows;
      try {
        rows = await get("/database_logs", [["select", "db_table,schema_column,classification"], ["event", "eq.db_schema"],
          ["order", "logged_at.desc,id.desc"], ["limit", 1000], ["offset", off]]);
      } catch { return; }
      for (const r of rows) {
        const k = `${r.db_table}.${r.schema_column}`;
        if (r.db_table && r.schema_column && !S.inventory.has(k)) S.inventory.set(k, r.classification || "");
      }
      if (rows.length < 1000) return;
    }
  }
  function learnSchema(rows) {
    for (const l of rows) {
      const x = l.details || {};
      if (l.event === "db_schema" && x.table && x.column) S.inventory.set(`${x.table}.${x.column}`, x.classification || "");
    }
  }

  /* ---------- PII per log line ---------- */
  // Which classifications count as personal / sensitive data, and how to label them.
  function piiClass(cls) {
    const [group, sub = ""] = String(cls || "").split(":");
    if (group === "personal_data") return { cat: "pii", label: (sub || "personal_data").toUpperCase() };
    if (group === "credentials") return { cat: "cred", label: (sub || "credential").toUpperCase() };
    if (group === "financial") return { cat: "fin", label: "FINANCIAL" };
    if (cls === "communication:content") return { cat: "pii", label: "MESSAGE_CONTENT" };
    return null;
  }
  const ACTION = { SELECT: "read", INSERT: "write", UPDATE: "write", DELETE: "erase" };

  // Columns referenced by a logged SQL template, resolved against the inventory.
  function sqlFields(l) {
    const x = l.details || {}, sql = String(x.sqlTemplate || ""), op = String(x.dbOperation || "").toUpperCase();
    if (!sql) return [];
    const alias = {};
    for (const m of sql.matchAll(/\b(?:from|join|update)\s+(\w+)\s+(\w+_\d+)\b/gi)) alias[m[2]] = m[1];
    const whereAt = sql.search(/\swhere\s/i);
    const out = [];
    const push = (table, col, action) => {
      const v = S.pii.cols.get(`${table}.${col}`);
      if (v) {                                                     // PII detection v2 verdict wins
        if (v.verdict === "confirmed" || v.verdict === "likely") out.push({ table, col, cls: v.category, action, cat: piiCatOf(v.category), label: piiShort(v.kind), v2: v });
        return;
      }
      const cls = S.inventory.get(`${table}.${col}`), c = piiClass(cls);
      if (c) out.push({ table, col, cls, action, ...c });
    };
    // Truncated templates can lose the FROM clause; single-table queries fall back to the logged table.
    const soleTable = x.tables && !String(x.tables).includes(",") ? x.tables : x.table;
    for (const m of sql.matchAll(/\b(\w+_\d+)\.(\w+)\b/g)) {
      const table = alias[m[1]] || (Object.keys(alias).length ? null : soleTable); if (!table) continue;
      push(table, m[2], whereAt >= 0 && m.index > whereAt ? "lookup" : ACTION[op] || "read");
    }
    let m;
    if ((m = sql.match(/insert\s+into\s+(\w+)\s*\(([^)]*)\)/i))) m[2].split(",").forEach((c) => push(m[1], c.trim(), "write"));
    if ((m = sql.match(/^update\s+(\w+)(?:\s+\w+_\d+)?\s+set\s+(.*?)(?:\swhere\s(.*))?$/i))) {
      for (const a of m[2].matchAll(/(\w+)\s*=/g)) push(m[1], a[1], "write");
      for (const a of (m[3] || "").matchAll(/(\w+)\s*=/g)) push(m[1], a[1], "lookup");
    }
    if ((m = sql.match(/^delete\s+from\s+(\w+)/i))) {
      const t = m[1];
      for (const [k, cls] of S.inventory) if (k.startsWith(t + ".")) { const c = piiClass(cls); if (c) out.push({ table: t, col: k.slice(t.length + 1), cls, action: "erase", ...c }); }
    }
    const seen = new Set();
    return out.filter((f) => { const k = `${f.table}.${f.col}.${f.action}`; return !seen.has(k) && seen.add(k); });
  }

  // Everything personal about one log line: masked tokens, DB fields, declared columns, categories.
  let piiCache = new WeakMap();
  function piiOf(l) {
    const hit = piiCache.get(l);
    if (hit && hit.inv === S.inventory.size && hit.pv === S.pii.at) return hit;
    const x = l.details || {}, items = [];
    if ((l.masked_pii_types || []).length) {
      const msg = String(l.message || ""), toks = [...msg.matchAll(/\[([A-Z_]+)\]|<([A-Z_]+)>/g)];
      const fp = toks.filter((m) => maskedFalse(msg, m.index, m[1] || m[2])).length, real = Math.max(0, (toks.length || 1) - fp);
      for (const t of l.masked_pii_types) {
        if (fp) items.push({ cat: "fp", label: t, action: "false alarm", count: fp, source: "Masked by PII Guard, but it sits next to 'timestamp': a 13-digit time in milliseconds, not a card number (PII detection v2)" });
        if (real) items.push({ cat: "masked", label: t, action: "masked", count: real, source: "Log line · masked by PII Guard, raw value not stored" });
      }
    }
    const leak = S.pii.leaks.get(l.id);
    if (leak) for (const k of leak.kinds) items.push({ cat: "leak", label: piiShort(k), action: "unmasked", count: leak.kinds.filter((x) => x === k).length,
      source: `Stored unmasked in the ${leak.in === "message" ? "message" : leak.in === "sql" ? "SQL text" : "details"}: ${[...new Set(leak.spans.filter((x) => x.kind === k).map((x) => x.why))].join("; ") || "validated by PII detection v2"}` });
    if (l.event === "db_query") {
      for (const f of sqlFields(l)) items.push({ ...f, source: `SQL column ${f.table}.${f.col}` });
    }
    if (l.event === "db_schema") {
      const c = piiClass(x.classification);
      if (c) items.push({ ...c, table: x.table, col: x.column, cls: x.classification, action: "declared", source: `Schema column ${x.table}.${x.column}` });
    }
    const personal = (l.risk_indicators || []).includes("personal_data_category") || x.personalData === "true";
    if (!items.length && personal) {
      const cat = l.data_category || x.dataCategory || "personal_data";
      const op = String(x.dbOperation || "").toUpperCase();
      items.push({ cat: "category", label: cat.toUpperCase(), action: ACTION[op] || "processed", source: "Event data category · no classified personal columns referenced in the logged query" });
    }
    const res = { items, inv: S.inventory.size, pv: S.pii.at };
    piiCache.set(l, res);
    return res;
  }
  // Compact inline strip: one chip per (label, action), columns in the tooltip.
  function piiStrip(l) {
    const { items } = piiOf(l);
    if (!items.length) return "";
    const groups = new Map();
    for (const it of items) {
      const k = it.label + "|" + it.action;
      const g = groups.get(k) || { ...it, n: 0, cols: [] };
      g.n += it.count || 1; if (it.col) g.cols.push(`${it.table}.${it.col}`);
      groups.set(k, g);
    }
    const rank = { leak: -1, masked: 0, pii: 1, cred: 2, fin: 3, category: 4, fp: 5 }, act = { unmasked: -1, masked: 0, declared: 0, write: 1, erase: 1, read: 2, lookup: 3 };
    const chips = [...groups.values()].sort((a, b) => (rank[a.cat] - rank[b.cat]) || ((act[a.action] ?? 9) - (act[b.action] ?? 9))).map((g) =>
      `<span class="pchip ${g.cat}" title="${esc(g.v2 ? `${g.cols.join(", ")} · ${g.v2.label} · ${g.v2.verdict} ${g.v2.confidence}% · ${(g.v2.evidence || []).join("; ")}` : g.cols.length ? g.cols.join(", ") : g.source)}">${esc(g.label)}` +
      `${g.n > 1 ? `<b>×${g.n}</b>` : ""}<em>${esc(g.action)}</em></span>`).join("");
    const onlyFp = [...groups.values()].every((g) => g.cat === "fp");
    return `<div class="pii-strip"><span class="pii-tag${onlyFp ? " fp" : groups.size && [...groups.values()].some((g) => g.cat === "leak") ? " leak" : ""}" title="${onlyFp ? "Only masker false alarms in this event" : "Personal data in this event"}">${onlyFp ? "NO PII" : "PII"}</span>${chips}` +
      `</div>`;
  }
  function piiTable(l) {
    const { items } = piiOf(l);
    if (!items.length) return "";
    return `<div class="dsec"><h4>Personal data</h4>` +
      `<table class="ptable"><thead><tr><th>Data</th><th>Field</th><th>Action</th><th>Evidence (PII detection v2)</th></tr></thead><tbody>` +
      items.map((it) => `<tr><td><span class="pchip ${it.cat}">${esc(it.label)}</span></td>` +
        `<td class="mono">${it.col ? esc(`${it.table}.${it.col}`) : "–"}</td>` +
        `<td><span class="pact ${esc(it.action)}">${esc(it.action)}</span></td>` +
        `<td class="pev">${it.v2 ? `<b class="pconf v-${esc(it.v2.verdict)}">${esc(it.v2.verdict)} ${it.v2.confidence}%</b> ${esc((it.v2.evidence || []).slice(0, 2).join("; "))}` : esc(it.source || "")}</td></tr>`).join("") +
      `</tbody></table></div>`;
  }


  /* ---------- Row semantics ---------- */
  const isDb = (l) => (l.event || "").startsWith("db_");
  const layerOf = (l) => (isDb(l) ? "database" : "application");
  const d = (l) => l.details || {};
  function flagsOf(l) {
    const out = new Set();
    if (S.pii.leaks.has(l.id)) out.add("UNMASKED_PII");
    if (l.pii_masked) {
      const msg = String(l.message || ""), toks = [...msg.matchAll(/\[([A-Z_]+)\]|<([A-Z_]+)>/g)];
      if (!toks.length || toks.some((m) => !maskedFalse(msg, m.index, m[1] || m[2]))) out.add("PII_IN_LOG");
    }
    if (l.event === "db_schema" && String(d(l).registered) === "false") out.add("UNREGISTERED_COLUMN");
    for (const f of S.ruleFlags.get(l.id) || []) out.add(f);
    return [...out];
  }
  const shortSvc = (s) => String(s || "").replace(/-(service|server)$/, "");
  const svcName = (s) => S.services.find((x) => x.service === s)?.display_name || s;

  // Masked tokens like [CARD], [EMAIL], <PERSON> → highlighted with entity type.
  const MASK_TOKENS = new Set(["CARD", "EMAIL", "PHONE", "AADHAAR", "PAN", "PERSON", "NAME", "IP", "UPI", "ACCOUNT", "IFSC", "ADDRESS", "LOCATION", "PASSPORT", "SSN", "IBAN", "REDACTED", "MASKED"]);
  function highlightPii(text, l) {
    const types = l.masked_pii_types || [], raw = String(text ?? "");
    const leak = raw === String(l.message || "") ? S.pii.leaks.get(l.id) : null;
    const spans = (leak?.spans || []).filter((x) => x.end <= raw.length).sort((a, b) => a.start - b.start);
    const maskOne = (seg, offset) => esc(seg).replace(/\[([A-Z][A-Z_]{1,30})\]|&lt;([A-Z][A-Z_]{2,30})&gt;/g, (m, a, b) => {
      const tok = a || b;
      if (!MASK_TOKENS.has(tok) && !types.some((t) => t.includes(tok))) return m;
      const type = types.length === 1 ? types[0] : types.find((t) => t.includes(tok)) || tok;
      const at = raw.indexOf(a ? `[${a}]` : `<${b}>`, offset);
      if (maskedFalse(raw, at, tok)) return `<mark class="pii fp" title="Masked as ${esc(type)}, but it's a timestamp, not personal data (PII detection v2)">${m}<sup>not ${esc(type)}</sup></mark>`;
      return `<mark class="pii" title="Masked ${esc(type)}">${m}<sup>${esc(type)}</sup></mark>`;
    });
    if (!spans.length) return maskOne(raw, 0);
    let out = "", pos = 0;
    for (const sp of spans) {
      if (sp.start < pos) continue;
      out += maskOne(raw.slice(pos, sp.start), pos) + `<mark class="pii leak" title="Unmasked ${esc(piiShort(sp.kind))}: ${esc(sp.why || "")}">${esc(raw.slice(sp.start, sp.end))}<sup>UNMASKED ${esc(piiShort(sp.kind))}</sup></mark>`;
      pos = sp.end;
    }
    return out + maskOne(raw.slice(pos), pos);
  }
  const kv = (k, v, cls = "") => `<span class="kv ${cls}"><i>${esc(k)}</i>${v}</span>`;
  const hl = (s, l) => highlightPii(String(s ?? ""), l);
  function tryJson(s) { if (!s || s[0] !== "{") return null; try { return JSON.parse(s); } catch { return null; } }

  // One structured line per event shape; full raw line lives in the detail panel.
  function summary(l) {
    const x = d(l);
    if (l.event === "http_request") {
      const st = Number(l.http_status ?? x.status);
      const cls = st >= 500 ? "s5" : st >= 400 ? "s4" : st >= 300 ? "s3" : "s2";
      return `<span class="verb">${esc(l.http_method || x.method)}</span> <span class="route">${hl(l.route || x.path, l)}</span>` +
        ` <span class="status ${cls}">${esc(st || "–")}</span>` +
        (l.duration_ms != null || x.durationMs ? kv("time", `${esc(l.duration_ms ?? x.durationMs)} ms`) : "");
    }
    if (l.event === "db_query") {
      return `<span class="verb db">${esc(x.dbOperation || "QUERY")}</span> <span class="route">${esc(x.table || x.tables || "")}</span>` +
        kv("time", `${esc(x.durationMs ?? l.duration_ms ?? "–")} ms`, x.slow === "true" ? "warn" : "") +
        kv("rows", esc(x.rows ?? "–")) +
        (x.dataCategory ? kv("data", esc(x.dataCategory), x.personalData === "true" ? "pd" : "") : "") +
        (x.status && x.status !== "success" ? kv("status", esc(x.status), "bad") : "");
    }
    if (l.event === "db_schema") {
      const reg = String(x.registered) === "true";
      return `<span class="verb db">COLUMN</span> <span class="route">${esc(x.table)}.${esc(x.column)}</span>` +
        kv("type", esc(x.columnType)) + kv("class", esc(x.classification), String(x.classification || "").startsWith("personal_data") ? "pd" : "") +
        kv("inventory", reg ? "registered" : "UNREGISTERED", reg ? "" : "bad");
    }
    const j = tryJson(l.message);
    if (j) {
      return `<span class="evt">${esc(j.eventType || l.event || "event")}</span>` +
        (j.purpose || l.purpose ? kv("purpose", esc(j.purpose || l.purpose)) : "") +
        (j.dataCategory ? kv("data", esc(j.dataCategory), (l.risk_indicators || []).length ? "pd" : "") : "") +
        (j.actorRef ? kv("actor", esc(j.actorRef)) : "") +
        (j.outcome ? kv("outcome", esc(j.outcome), j.outcome === "SUCCESS" ? "" : "bad") : "");
    }
    if (/^event=\S+/.test(l.message || "")) {
      const skip = new Set(["event", "service", "traceId", "rawMessageSha256"]);
      const pairs = Object.entries(x).filter(([k]) => !skip.has(k)).slice(0, 5);
      return `<span class="evt">${esc(l.event || x.event)}</span>` + pairs.map(([k, v]) => kv(k, hl(v, l))).join("");
    }
    return hl(l.message, l);
  }

  /* ---------- Rendering ---------- */
  function flagChip(code) {
    if (code.startsWith("ALERT:")) return `<span class="flag sev-high" title="Compliance alert">${esc(code.slice(6))}</span>`;
    const f = FLAGS[code] || { sev: "high", title: code, ref: "" };
    return `<span class="flag sev-${f.sev}" title="${esc(f.title)}${f.ref ? " — " + esc(f.ref) : ""}">${esc(code)}</span>`;
  }
  function rowHtml(l) {
    const t = new Date(l.logged_at), open = S.open.has(l.id);
    const purpose = l.purpose || l.data_category || l.kind || "";
    const msg = S.rawLines ? `<span class="rawline">${hl(l.message, l)}</span>` : summary(l);
    return `<div class="lrow${open ? " open" : ""}${S.fresh.has(l.id) ? " fresh" : ""}" data-id="${esc(l.id)}" tabindex="0" role="row" aria-expanded="${open}">` +
      `<div class="c-time" role="cell"><time datetime="${esc(l.logged_at)}" title="${esc(istFull(t))}">${istTime(t)}</time></div>` +
      `<div class="c-lvl" role="cell"><span class="lvl ${esc(l.level)}">${esc(l.level)}</span></div>` +
      `<div class="c-svc" role="cell"><b title="${esc(svcName(l.service))}">${esc(l.service)}</b><small>${layerOf(l)}${purpose ? " · " + esc(purpose) : ""}</small></div>` +
      `<div class="c-msg" role="cell"><div class="msg-main">${msg}</div>${piiStrip(l)}</div>` +
      `<div class="c-flags" role="cell">${flagsOf(l).map(flagChip).join("")}</div>` +
      `</div>` + (open ? detailHtml(l) : "");
  }
  function field(label, value, mono = false) {
    if (value == null || value === "") return "";
    return `<div class="f"><dt>${esc(label)}</dt><dd${mono ? ' class="mono"' : ""}>${value}</dd></div>`;
  }
  function detailHtml(l) {
    const t = new Date(l.logged_at);
    const flags = flagsOf(l).filter((c) => !c.startsWith("ALERT:"));
    return `<div class="ldetail" role="region">` +
      `<dl class="fields">` +
      field("Time (IST)", esc(istFull(t))) +
      field("Service", esc(svcName(l.service))) +
      field("Layer", layerOf(l)) +
      field("Event", esc(l.event), true) +
      field("Trace ID", l.trace_id && l.trace_id !== "none" ? `<button class="link" data-trace="${esc(l.trace_id)}" title="Show all logs in this trace">${esc(l.trace_id)}</button>` : "", true) +
      field("Actor", l.actor_type || l.actor_ref ? esc([l.actor_type, l.actor_ref].filter(Boolean).join(" · ")) : "") +
      field("Data category", esc(l.data_category)) +
      field("Purpose", esc(l.purpose)) +
      field("Source", esc(`${l.source_file}:${l.line_no}`), true) +
      `</dl>` +
      (flags.length ? `<div class="dsec"><h4>Flags</h4>${flags.map((c) =>
        `<div class="fl">${flagChip(c)}<span>${esc(FLAGS[c]?.title || c)}</span></div>`).join("")}</div>` : "") +
      piiTable(l) +
      `<div class="dsec"><h4>Log line</h4><pre class="logline">${hl(l.message, l)}</pre></div>` +
      `</div>`;
  }


  function render(resetScroll = false) {
    const list = $("tList"), scroller = $("tScroll");
    const before = scroller.scrollHeight, top = scroller.scrollTop;
    if (S.error && !S.rows.length) {
      list.innerHTML = `<div class="tempty err">Could not load logs — ${esc(S.error)}</div>`;
    } else if (!S.rows.length) {
      list.innerHTML = `<div class="tempty">${S.busy ? "Loading logs…" : "No logs match these filters."}</div>`;
    } else {
      let html = "", last = "";
      for (const l of S.rows) {
        const t = new Date(l.logged_at), k = dayKey(t);
        if (k !== last) { html += `<div class="day-sep" role="row"><span>${esc(dayLabel(t))}</span></div>`; last = k; }
        html += rowHtml(l);
      }
      list.innerHTML = html;
    }
    if (resetScroll) scroller.scrollTop = 0;
    else if (top > 4) scroller.scrollTop = top + (scroller.scrollHeight - before); // keep reading position when live rows arrive
    S.fresh.clear();
    $("tShown").textContent = S.rows.length
      ? `Showing ${num(S.rows.length)} of ${num(S.total)}`
      : "";
    $("tMore").hidden = S.exhausted || !S.rows.length;
    renderStatus(); renderTabs();
  }
  function renderTabs() {
    const tabs = [["", "all"], ...S.services.map((s) => [s.service, shortSvc(s.service)])];
    $("tTabs").innerHTML = tabs.map(([v, label]) => {
      const n = S.counts[v];
      return `<button role="tab" class="ttab${S.svc === v ? " on" : ""}" aria-selected="${S.svc === v}" data-svc="${esc(v)}" title="${esc(v ? svcName(v) : "All services")}">` +
        `${esc(label)} <span class="n">(${n == null ? "…" : num(n)})</span></button>`;
    }).join("");
  }
  function renderStatus() {
    const live = $("live")?.checked;
    const el = $("tStatus");
    if (S.error) { el.className = "tstatus err"; el.textContent = "Connection issue · " + S.error; return; }
    el.className = "tstatus" + (live ? " live" : "");
    el.textContent = S.busy ? "Loading…" : S.updatedAt ? `Updated ${istTime(S.updatedAt)} IST` : "";
    $("tTrace").hidden = !S.trace;
    $("tTraceId").textContent = S.trace;
  }
  let toastT;
  function toast(m) { const t = $("tToast"); t.textContent = m; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4000); }

  /* ---------- Events ---------- */
  let started = false;
  function bind() {
    $("tTabs").onclick = (e) => {
      const b = e.target.closest("[data-svc]"); if (!b) return;
      S.svc = b.dataset.svc; S.open.clear(); reload();
    };
    ["tLevel", "tLayer", "tKind", "tFlag", "tRange"].forEach((id) => ($(id).onchange = () => { S.open.clear(); reload(); }));
    let qt; $("tQ").oninput = () => { clearTimeout(qt); qt = setTimeout(reload, 350); };
    $("tRaw").onchange = () => { S.rawLines = $("tRaw").checked; render(); };
    $("tMore").onclick = loadOlder;
    $("tReset").onclick = () => {
      ["tLevel", "tLayer", "tKind", "tFlag", "tRange"].forEach((id) => ($(id).value = ""));
      $("tQ").value = ""; S.trace = ""; S.svc = ""; S.open.clear(); reload();
    };
    $("tTraceClear").onclick = () => { S.trace = ""; reload(); };
    $("tList").onclick = (e) => {
      const tr = e.target.closest("[data-trace]");
      if (tr) { S.trace = tr.dataset.trace; S.open.clear(); reload(); return; }
      if (e.target.closest(".ldetail")) return;
      const row = e.target.closest(".lrow"); if (!row) return;
      if (String(window.getSelection?.() || "").length) return; // allow text selection
      toggle(row.dataset.id);
    };
    $("tList").onkeydown = (e) => {
      const row = e.target.closest?.(".lrow");
      if (row && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggle(row.dataset.id); }
    };
  }
  function toggle(id) {
    S.open.has(id) ? S.open.delete(id) : S.open.add(id);
    render();
    document.querySelector(`.lrow[data-id="${CSS.escape(id)}"]`)?.focus({ preventScroll: true });
  }

  return {
    async show() {
      if (!started) { started = true; bind(); await Promise.all([loadServices(), loadInventory(), loadPii(true)]); renderTabs(); }
      else loadPii();
      reload();
    },
    tick() { if (started) { tick(); loadPii(); } },
    async openUnmasked() { show("telemetry"); await loadPii(true); $("tFlag").value = "unmasked"; S.open.clear(); reload(); },
  };
})();
