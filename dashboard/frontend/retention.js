/* Retention — end-to-end retention and erasure monitoring.
   Schedule (versioned, editable) → deadlines measured on live data → what is past
   its deadline, due soon or held for legal reasons → erasure-request checklists and
   inactivity notices → exportable worklists. Nothing is deleted from here: the
   databases stay read-only, and worklists hand the deletions to the owning service.
   Shop data comes through consent_service (counts and pages are computed there);
   NigraniAI logs are read directly with the signed-in user's token.
   Uses session / refreshSession / authedFetch / DASH_URL / DB_SCHEMA from app.js. */
const Retention = (() => {
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
  const F_D = fmt({ day: "numeric", month: "short", year: "numeric" });
  const F_TIME = fmt({ hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const up = (s) => s.replace(/\b(am|pm)\b/i, (m) => m.toUpperCase());
  const ist = (v) => (v ? up(F_DT.format(new Date(v))) : "–");
  const day = (v) => (v ? F_D.format(new Date(v)) : "–");

  /* ---------- periods ---------- */
  const UNITS = ["seconds", "minutes", "hours", "days", "months", "years"];
  const UNIT_MS = { seconds: 1e3, minutes: 6e4, hours: 36e5, days: 864e5, months: 30.44 * 864e5, years: 365.25 * 864e5 };
  const periodText = (k) => (k ? plural(k.n, k.unit.replace(/s$/, ""), k.unit) : "–");
  const periodMs = (k) => (k ? k.n * UNIT_MS[k.unit] : 0);
  function shift(date, k, sign) {
    const d = new Date(date), n = sign * k.n;
    if (k.unit === "months") d.setMonth(d.getMonth() + n);
    else if (k.unit === "years") d.setFullYear(d.getFullYear() + n);
    else d.setTime(d.getTime() + n * UNIT_MS[k.unit]);
    return d;
  }
  function span(ms) {
    const a = Math.abs(ms), d = Math.floor(a / 864e5), h = Math.floor((a % 864e5) / 36e5), m = Math.round((a % 36e5) / 6e4);
    if (d >= 365) return `${(d / 365).toFixed(1)} years`;
    if (d >= 1) return `${d} d${h ? ` ${h} h` : ""}`;
    if (h >= 1) return `${h} h${m ? ` ${m} min` : ""}`;
    return `${Math.max(1, m)} min`;
  }

  /* ---------- rule templates ---------- */
  const TYPES = {
    erasure: { group: "On request", label: "Erasure request", desc: "Erase a customer's data within a set time of their request, and check every step was done." },
    age: { group: "After a period", label: "Delete or review after a period", desc: "Delete, anonymise or review records a set time after a date column." },
    legal_minimum: { group: "Kept for legal reasons", label: "Legal minimum", desc: "Records that must be kept for at least a set time, e.g. tax records. Flags delete rules that would remove them too early." },
    inactivity: { group: "Inactive accounts", label: "Inactive accounts", desc: "Erase customers after a period without activity, with advance notice." },
  };
  const GROUP_ORDER = ["On request", "After a period", "Kept for legal reasons", "Inactive accounts"];
  const STEPS = {
    anonymise_profile: { label: "Anonymise profile", check: "profile_anonymised", desc: "Name becomes “Erased customer”" },
    replace_email: { label: "Replace email", check: "email_replaced", desc: "Email replaced with a placeholder" },
    remove_phone: { label: "Remove phone", check: "phone_removed", desc: "Phone number removed" },
    marketing_off: { label: "Turn marketing off", check: "marketing_off", desc: "Marketing consent set to off" },
    delete_addresses: { label: "Delete addresses", check: "addresses_deleted", desc: "Saved addresses deleted" },
    delete_wishlist: { label: "Delete wishlist", check: "wishlist_deleted", desc: "Wishlist deleted" },
    revoke_sessions: { label: "Revoke sessions", check: "sessions_revoked", desc: "All active sessions revoked" },
  };
  const ACTIONS = { delete: "Delete", anonymise: "Anonymise", review: "Review" };
  const GUARDRAIL_TABLES = { activity_logs: ["logged_at", "ingested_at"], database_logs: ["logged_at", "ingested_at"] };

  const S = {
    started: false, tab: "overview", policy: null, draft: null, schema: {}, res: {}, erasure: null, inactivity: null,
    error: "", busy: false, loadedAt: null, gen: 0,
    sel: null, recFilter: "overdue", recPage: 0, recRows: null, recTotal: 0, recBusy: false,
    editRule: null, newRule: null, picking: false, history: null, erFilter: "all",
  };
  const P = () => S.draft || S.policy;

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
  // One query shape for both sources: filters "col.op.value", order "col.asc", limit, offset → {rows, total}.
  async function query(rule, { filters = [], order, limit = 0, offset = 0, columns = [] } = {}) {
    if (rule.source === "guardrail") {
      const u = new URL(`${DASH_URL}/rest/v1/${rule.table}`);
      u.searchParams.set("select", columns.length ? columns.join(",") : "id");
      for (const f of filters) { const [c, op, ...v] = f.split("."); u.searchParams.append(c, op === "notnull" ? "not.is.null" : op === "null" ? "is.null" : `${op}.${v.join(".")}`); }
      if (order) u.searchParams.set("order", order);
      u.searchParams.set("limit", String(limit)); u.searchParams.set("offset", String(offset));
      const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA, Prefer: "count=exact" } });
      if (!r.ok) throw new Error(`NigraniAI ${rule.table}: HTTP ${r.status}`);
      const total = Number((r.headers.get("content-range") || "").split("/")[1]);
      return { rows: await r.json(), total: Number.isFinite(total) ? total : 0 };
    }
    const qs = new URLSearchParams({ columns: columns.length ? columns.join(",") : "id", limit: String(limit), offset: String(offset) });
    for (const f of filters) qs.append("f", f);
    if (order) qs.set("order", order);
    return api(`/api/query/${encodeURIComponent(rule.table)}?${qs}`);
  }
  const baseFilters = (r) => (r.filter_column ? [`${r.filter_column}.${/^(true|false|null)$/.test(String(r.filter_value)) ? "is" : "eq"}.${r.filter_value}`] : []);

  /* ---------- engine: measure every rule on live data ---------- */
  async function measure(rule, now) {
    const soonDays = P().due_soon_days || 30;
    if (rule.type === "age" || rule.type === "legal_minimum") {
      const cutoff = shift(now, rule.keep, -1).toISOString();
      const soonCut = new Date(new Date(cutoff).getTime() + soonDays * 864e5).toISOString();
      const c = rule.clock_column, f = baseFilters(rule);
      const [past, soon, total, next, oldest] = await Promise.all([
        query(rule, { filters: [...f, `${c}.lt.${cutoff}`] }),
        query(rule, { filters: [...f, `${c}.gte.${cutoff}`, `${c}.lt.${soonCut}`] }),
        query(rule, { filters: [...f, `${c}.notnull`] }),
        query(rule, { filters: [...f, `${c}.gte.${cutoff}`], order: `${c}.asc`, limit: 1, columns: [c] }),
        query(rule, { filters: [...f, `${c}.lt.${cutoff}`], order: `${c}.asc`, limit: 1, columns: [c] }),
      ]);
      const nextStart = next.rows[0]?.[c], oldStart = oldest.rows[0]?.[c];
      return { past: past.total, soon: soon.total, total: total.total, cutoff, soonCut,
        nextDue: nextStart ? shift(nextStart, rule.keep, 1).toISOString() : null,
        oldestPast: oldStart ? shift(oldStart, rule.keep, 1).toISOString() : null };
    }
    if (rule.type === "erasure") {
      const delay = Math.round(periodMs(rule.keep) / 1000);
      const r = await api(`/api/retention/erasure?delay_seconds=${delay}&marketing_column=${encodeURIComponent(P().marketing_column || "")}`);
      S.erasure = r;
      const by = (st) => r.requests.filter((x) => x.status === st).length;
      return { past: by("overdue") + by("incomplete"), soon: r.requests.filter((x) => x.status === "pending" && new Date(x.due_at) - now < soonDays * 864e5).length,
        total: r.requests.length, open: by("pending") + by("overdue") + by("incomplete"), done: by("completed") + by("completed_late") };
    }
    if (rule.type === "inactivity") {
      const r = await api(`/api/retention/inactivity?after_days=${Math.round(periodMs(rule.keep) / 864e5)}&notice_hours=${rule.notice_hours || 0}`);
      S.inactivity = r;
      return { past: r.counts.overdue, soon: r.counts.notify, total: r.customers, nextDue: r.next?.erase_at || null, next: r.next };
    }
    return {};
  }
  function conflictsFor(rule, rules) {
    // A delete/anonymise rule shorter than a legal minimum on the same data would remove records too early.
    if (rule.type === "legal_minimum") return rules.filter((r) => r.enabled && r.type === "age" && r.action !== "review" && r.source === rule.source && r.table === rule.table && periodMs(r.keep) < periodMs(rule.keep));
    if (rule.type === "age" && rule.action !== "review") return rules.filter((r) => r.enabled && r.type === "legal_minimum" && r.source === rule.source && r.table === rule.table && periodMs(rule.keep) < periodMs(r.keep));
    return [];
  }
  async function measureAll() {
    const now = new Date(), gen = S.gen, pol = P();
    const out = {};
    await Promise.all(pol.rules.filter((r) => r.enabled).map(async (r) => {
      try { out[r.id] = await measure(r, now); } catch (e) { out[r.id] = { error: e.offline ? "The consent service isn't running." : e.message }; }
    }));
    if (gen !== S.gen) return false;
    S.res = out; S.loadedAt = now;
    return true;
  }
  function statusOf(r) {
    const m = S.res[r.id];
    if (!r.enabled) return ["off", "Off"];
    if (!m) return ["wait", "Checking…"];
    if (m.error) return ["err", "Couldn't check"];
    if (conflictsFor(r, P().rules).length) return ["bad", "Conflict"];
    if (r.type === "legal_minimum") return ["hold", "Legal hold"];
    if (m.past) return ["bad", r.type === "age" && r.action === "review" ? "Review overdue" : "Past deadline"];
    if (m.soon) return ["warn", r.type === "inactivity" ? "Notify now" : "Due soon"];
    return ["ok", "On track"];
  }

  /* ---------- loading ---------- */
  async function loadAll({ withPolicy = true } = {}) {
    const gen = S.gen;
    S.busy = true; renderMeta();
    try {
      const [pol, schema] = await Promise.all([withPolicy || !S.policy ? api("/api/retention-policy") : null, api("/api/schema")]);
      if (gen !== S.gen) return;
      if (pol) S.policy = pol;
      S.schema = schema.tables;
      await measureAll();
      S.error = "";
    } catch (e) { if (gen === S.gen) S.error = e.offline ? "offline" : e.message; }
    finally { S.busy = false; if (gen === S.gen) render(); else renderMeta(); }
  }

  /* ---------- sentences ---------- */
  const tok = (s) => `<span class="cp-tok">${esc(s)}</span>`;
  const clockLabel = (r) => r.clock_label || { expires_at: "they expire", created_at: "they were created", logged_at: "they were logged", added_at: "they were added" }[r.clock_column] || r.clock_column;
  function sentence(r) {
    switch (r.type) {
      case "erasure": return `Erase a customer's data within ${tok(periodText(r.keep))} of their erasure request: ${(r.steps || []).map((s) => tok(STEPS[s]?.label || s)).join(" ")}.`;
      case "age": return `${ACTIONS[r.action] || "Delete"} ${tok(r.name)} ${tok(periodText(r.keep))} after ${esc(clockLabel(r))}${r.filter_column ? ` (only where ${esc(r.filter_column)} is ${esc(r.filter_value)})` : ""}.`;
      case "legal_minimum": return `Keep ${tok(r.name)} for at least ${tok(periodText(r.keep))} after ${esc(clockLabel(r))}.`;
      case "inactivity": return `Erase customers inactive for ${tok(periodText(r.keep))}, notifying them ${tok(plural(r.notice_hours || 0, "hour"))} before.`;
      default: return esc(r.name);
    }
  }
  const where = (r) => (r.source === "guardrail" ? `NigraniAI · ${r.table}` : r.table ? `Shop · ${r.table}` : "Shop · customers");

  /* ---------- render shell ---------- */
  const pill = ([cls, label]) => `<span class="rt-pill ${cls}">${esc(label)}</span>`;
  function render() {
    renderMeta();
    const body = $("rtBody");
    if (S.error === "offline") { body.innerHTML = `<div class="panel cp-empty"><h3>The consent service isn't running</h3><p>Retention reads shop data through it. Start it from the project folder, then click Check now.</p><pre class="logline">python3 consent_service/server.py</pre></div>`; return; }
    if (S.error && !S.policy) { body.innerHTML = `<div class="panel cp-empty"><h3>Could not load retention data</h3><p>${esc(S.error)}</p></div>`; return; }
    if (!S.policy) { body.innerHTML = `<div class="panel cp-empty"><p>Checking retention…</p></div>`; return; }
    document.querySelectorAll("#rtTabs [data-tab]").forEach((b) => { const on = b.dataset.tab === S.tab; b.classList.toggle("on", on); b.setAttribute("aria-selected", on); });
    // Badge on the Records tab: only records that tab lists (period-based rules).
    const recPast = P().rules.reduce((n, r) => n + (r.enabled && r.type === "age" ? S.res[r.id]?.past || 0 : 0), 0);
    $("rtPastCount").textContent = num(recPast);
    $("rtPastCount").hidden = !recPast;
    const errs = P().rules.filter((r) => r.enabled && S.res[r.id]?.error);
    const banner = errs.length ? `<div class="cp-warn" role="alert"><b>Some checks could not run, so results may be incomplete.</b><span>${errs.map((r) => `${esc(r.name)}: ${esc(S.res[r.id].error)}`).join(" · ")}</span></div>` : "";
    body.innerHTML = banner + { overview: overviewHtml, records: recordsHtml, customers: customersHtml, schedule: scheduleHtml }[S.tab]();
    if (S.tab === "records" && !S.recRows && !S.recBusy) loadRecords();
    renderDraftBar();
  }
  function renderMeta() {
    const m = $("rtMeta"); if (!m) return;
    m.textContent = S.busy ? "Checking…" : S.policy ? `Checked ${S.loadedAt ? up(F_TIME.format(S.loadedAt)) + " IST" : "–"} · Schedule v${S.policy.version}` : "";
  }

  /* ---------- Overview ---------- */
  function overviewHtml() {
    const rules = P().rules.filter((r) => r.enabled), res = S.res;
    const sum = (pred, key) => rules.filter(pred).reduce((n, r) => n + (res[r.id]?.[key] || 0), 0);
    const past = sum((r) => r.type !== "legal_minimum", "past");
    const soon = sum((r) => r.type !== "legal_minimum", "soon");
    const held = rules.filter((r) => r.type === "legal_minimum").reduce((n, r) => n + Math.max(0, (res[r.id]?.total || 0) - (res[r.id]?.past || 0)), 0);
    const er = rules.find((r) => r.type === "erasure"), erm = er && res[er.id];
    const conflicts = rules.filter((r) => r.type === "legal_minimum" && conflictsFor(r, rules).length);
    const order = { bad: 0, err: 1, warn: 2, ok: 3, hold: 4, wait: 5, off: 6 };
    const sorted = [...rules].sort((a, b) => order[statusOf(a)[0]] - order[statusOf(b)[0]]);
    const kpi = (cls, label, value, sub) => `<div class="panel rt-kpi ${cls}"><span>${esc(label)}</span><b>${value}</b><small>${sub}</small></div>`;
    return `
      ${conflicts.length ? `<div class="rt-conflict" role="alert"><b>Schedule conflict.</b> ${conflicts.map((l) => `${conflictsFor(l, rules).map((a) => `${esc(a.id)} deletes ${esc(a.name)} after ${esc(periodText(a.keep))}`).join(", ")}, but ${esc(l.id)} requires keeping them for ${esc(periodText(l.keep))}.`).join(" ")} <button class="link" data-goto="schedule">Fix in Schedule</button></div>` : ""}
      <div class="rt-kpis">
        ${kpi(past ? "bad" : "ok", "Past their deadline", num(past), past ? "records to delete, anonymise or review now" : "nothing is overdue")}
        ${kpi(soon ? "warn" : "", `Due in the next ${P().due_soon_days || 30} days`, num(soon), soon ? "records reaching their deadline" : "nothing due soon")}
        ${kpi(erm?.past ? "bad" : "", "Erasure requests", num(erm?.open || 0), erm ? `${num(erm.past || 0)} overdue · ${num(erm.done || 0)} completed` : "no erasure rule")}
        ${kpi("hold", "Under legal hold", num(held), "records that must be kept")}
      </div>
      <section class="panel cp-list" aria-labelledby="rtSched">
        <div class="cp-list-head"><h3 id="rtSched">Retention schedule</h3><button class="link" data-goto="schedule">Edit schedule</button></div>
        ${sorted.map((r) => {
          const m = res[r.id] || {}, st = statusOf(r);
          const facts = m.error ? esc(m.error) : r.type === "legal_minimum"
            ? `${num((m.total || 0) - (m.past || 0))} held${m.nextDue ? ` · first release ${esc(day(m.nextDue))}` : ""}`
            : r.type === "erasure" ? `${plural(m.total || 0, "request")}${m.past ? ` · ${num(m.past)} overdue` : ""}`
            : r.type === "inactivity" ? `${plural(m.total || 0, "customer")} tracked${m.nextDue ? ` · next ${esc(day(m.nextDue))}` : ""}`
            : `${num(m.past || 0)} past · ${num(m.soon || 0)} due soon${m.nextDue && !m.past ? ` · next ${esc(day(m.nextDue))}` : ""}`;
          const go = r.type === "erasure" || r.type === "inactivity" ? `data-goto="customers"` : `data-record="${esc(r.id)}"`;
          return `<article class="rt-row">
            ${pill(st)}
            <div class="rt-row-main"><h4>${esc(r.name)} <small>${esc(where(r))}</small></h4><p>${sentence(r)}</p></div>
            <div class="rt-row-facts">${facts}<span>${esc(r.ref || "")}</span></div>
            <button class="btn ghost" ${go}>${r.type === "erasure" || r.type === "inactivity" ? "View customers" : "View records"}</button>
          </article>`;
        }).join("")}
      </section>
      <p class="rt-note">Deadlines are measured from each record's own date column. The dashboard never deletes anything: export a worklist from Records and hand it to the service that owns the data.</p>`;
  }

  /* ---------- Records ---------- */
  const recordRules = () => P().rules.filter((r) => r.enabled && (r.type === "age" || r.type === "legal_minimum"));
  function recordsHtml() {
    const list = recordRules();
    if (!list.length) return `<div class="panel cp-empty"><p>No period-based rules are switched on.</p></div>`;
    if (!list.some((r) => r.id === S.sel)) S.sel = list[0].id;
    const r = list.find((x) => x.id === S.sel), m = S.res[r.id] || {}, legal = r.type === "legal_minimum";
    const filters = legal ? [["held", "Held", (m.total || 0) - (m.past || 0)], ["released", "Hold ended", m.past || 0], ["all", "All", m.total || 0]]
      : [["overdue", "Past deadline", m.past || 0], ["soon", `Due in ${P().due_soon_days || 30} days`, m.soon || 0], ["all", "All", m.total || 0]];
    if (!filters.some(([k]) => k === S.recFilter)) S.recFilter = filters[0][0];
    const pages = Math.max(1, Math.ceil(S.recTotal / 25));
    const stat = (label, value) => `<div class="cp-stat"><span>${esc(label)}</span><b>${value}</b></div>`;
    return `<div class="cp-split">
      <section class="panel cp-side-list" aria-label="Retention rules">
        ${list.map((x) => `<button class="cp-row${x.id === S.sel ? " on" : ""}" data-record="${esc(x.id)}" aria-pressed="${x.id === S.sel}">
          <span class="cp-row-main"><b>${esc(x.name)}</b><span>${esc(where(x))} · ${esc(periodText(x.keep))}</span></span>${pill(statusOf(x))}</button>`).join("")}
      </section>
      <article class="panel cp-idetail" aria-labelledby="rtRecTitle">
        <div class="cp-ihead"><div class="cp-titlerow">${pill(statusOf(r))}<span class="cp-ref">Rule ${esc(r.id)} · ${esc(r.ref || "")}</span></div>
          <h2 id="rtRecTitle">${esc(r.name)}</h2><p class="rt-sentence">${sentence(r)}</p></div>
        <div class="cp-stats">
          ${legal ? stat("Must be kept", num((m.total || 0) - (m.past || 0))) + stat("Hold ended", num(m.past || 0)) + stat("First release", esc(m.nextDue ? day(m.nextDue) : "–"))
            : stat("Past deadline", `<span class="${m.past ? "cp-red" : ""}">${num(m.past || 0)}</span>`) + stat(`Due in ${P().due_soon_days || 30} days`, num(m.soon || 0)) + stat(m.past ? "Oldest deadline" : "Next deadline", esc(m.past ? ist(m.oldestPast) : m.nextDue ? ist(m.nextDue) : "–"))}
          ${stat("Records", num(m.total || 0))}
        </div>
        ${r.basis ? `<div><h3>Why</h3><p>${esc(r.basis)}</p></div>` : ""}
        ${conflictsFor(r, P().rules).length ? `<div class="rt-conflict">${legal ? "Rule" : "This rule deletes these records before"} ${conflictsFor(r, P().rules).map((c) => `${esc(c.id)} (${esc(c.name)}, ${esc(periodText(c.keep))})`).join(", ")}${legal ? " would delete these records before their legal minimum." : " requires. Lengthen the period or switch one rule off."}</div>` : ""}
        <div>
          <div class="cp-list-head flat"><div class="cp-chips">${filters.map(([k, l, n]) => `<button class="cp-chip${S.recFilter === k ? " on" : ""}" data-rec-filter="${k}" aria-pressed="${S.recFilter === k}">${l} · ${num(n)}</button>`).join("")}</div>
            ${legal ? "" : `<button class="btn ghost" data-act="worklist" ${m.past ? "" : "disabled"}>Export worklist (CSV)</button>`}</div>
          <div class="cp-tablewrap"><table class="cp-evidence">
            <thead><tr><th>Record</th>${r.source === "guardrail" ? "<th>Service</th>" : ""}<th>${esc(cap(clockLabel(r)))}</th><th>${legal ? "Keep until" : "Deadline"} (IST)</th><th>Status</th></tr></thead>
            <tbody>${S.recBusy ? `<tr><td colspan="5" class="cp-none">Loading…</td></tr>` : (S.recRows || []).length ? S.recRows.map((row) => {
              const start = row[r.clock_column], dl = start ? shift(start, r.keep, 1) : null, diff = dl ? dl - Date.now() : 0;
              const status = !dl ? "—" : legal ? (diff > 0 ? `Held · ${span(diff)} left` : "Hold ended") : diff <= 0 ? `<span class="cp-red">Overdue by ${span(diff)}</span>` : `Due in ${span(diff)}`;
              return `<tr><td class="nowrap">#${esc(row.id ?? "—")}</td>${r.source === "guardrail" ? `<td>${esc(row.service || "")}</td>` : ""}<td class="nowrap">${esc(ist(start))}</td><td class="nowrap">${esc(ist(dl))}</td><td class="nowrap">${status}</td></tr>`;
            }).join("") : `<tr><td colspan="5" class="cp-none">No records in this view.</td></tr>`}</tbody>
          </table></div>
          <div class="cp-cfoot"><span>${S.recTotal ? `Showing ${num(S.recPage * 25 + 1)}–${num(S.recPage * 25 + (S.recRows || []).length)} of ${num(S.recTotal)}` : ""}</span>
            <div class="cp-pager"><button class="btn ghost sm" data-rec-page="prev" ${S.recPage === 0 ? "disabled" : ""}>Previous</button><span>Page ${num(S.recPage + 1)} of ${num(pages)}</span><button class="btn ghost sm" data-rec-page="next" ${S.recPage >= pages - 1 ? "disabled" : ""}>Next</button></div></div>
        </div>
      </article>
    </div>`;
  }
  function recordFilters(r) {
    const m = S.res[r.id] || {}, c = r.clock_column, f = baseFilters(r);
    if (!m.cutoff) return null;
    return { overdue: [...f, `${c}.lt.${m.cutoff}`], released: [...f, `${c}.lt.${m.cutoff}`], soon: [...f, `${c}.gte.${m.cutoff}`, `${c}.lt.${m.soonCut}`], held: [...f, `${c}.gte.${m.cutoff}`], all: [...f, `${c}.notnull`] }[S.recFilter];
  }
  async function loadRecords() {
    const r = recordRules().find((x) => x.id === S.sel);
    const filters = r && recordFilters(r);
    if (!filters) return;
    S.recBusy = true; render();
    try {
      const cols = ["id", r.clock_column, ...(r.source === "guardrail" ? ["service"] : [])];
      const res = await query(r, { filters, order: `${r.clock_column}.asc`, limit: 25, offset: S.recPage * 25, columns: cols });
      S.recRows = res.rows; S.recTotal = res.total;
    } catch (e) { S.recRows = []; S.recTotal = 0; toast(e.message); }
    finally { S.recBusy = false; if (S.tab === "records") render(); }
  }
  async function exportWorklist() {
    const r = recordRules().find((x) => x.id === S.sel), m = S.res[r.id];
    const filters = [...baseFilters(r), `${r.clock_column}.lt.${m.cutoff}`], rows = [];
    for (let off = 0; off < 10000; off += 1000) {
      const page = await query(r, { filters, order: `${r.clock_column}.asc`, limit: 1000, offset: off, columns: ["id", r.clock_column] });
      rows.push(...page.rows);
      if (page.rows.length < 1000) break;
    }
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const head = ["Rule", "Action", "Source", "Table", "Record id", `${r.clock_column} (IST)`, "Deadline (IST)", "Overdue by", "Reference"];
    const lines = rows.map((row) => { const dl = shift(row[r.clock_column], r.keep, 1); return [r.id, ACTIONS[r.action] || "Delete", r.source, r.table, row.id, ist(row[r.clock_column]), ist(dl), span(dl - Date.now()), r.ref].map(q).join(","); });
    const blob = new Blob([[head.map(q).join(","), ...lines].join("\n")], { type: "text/csv" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `retention-worklist-${r.id}-${r.table}.csv` });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(`Worklist exported: ${plural(rows.length, "record")}.`, true);
  }

  /* ---------- Customers: erasure requests + inactivity ---------- */
  const ER_STATUS = { pending: ["warn", "In progress"], overdue: ["bad", "Overdue"], incomplete: ["bad", "Marked erased, data remains"], completed: ["ok", "Completed on time"], completed_late: ["warn", "Completed late"] };
  function customersHtml() {
    const er = P().rules.find((r) => r.type === "erasure" && r.enabled), ina = P().rules.find((r) => r.type === "inactivity" && r.enabled);
    const reqs = S.erasure?.requests || [], steps = er?.steps || [];
    const counts = { all: reqs.length }; for (const k of Object.keys(ER_STATUS)) counts[k] = reqs.filter((x) => x.status === k).length;
    const shown = S.erFilter === "all" ? reqs : reqs.filter((x) => x.status === S.erFilter);
    const mark = (v) => (v === null || v === undefined ? `<span class="muted" title="Not checked">–</span>` : v ? `<span class="rt-yes" title="Done">✓</span>` : `<span class="rt-no" title="Not done">✗</span>`);
    const remain = (x) => [x.remaining.addresses && plural(x.remaining.addresses, "address", "addresses"), x.remaining.wishlist && plural(x.remaining.wishlist, "wishlist item"), x.remaining.active_sessions && plural(x.remaining.active_sessions, "active session"), x.remaining.reviews && plural(x.remaining.reviews, "review") + " kept"].filter(Boolean).join(", ") || "Nothing";
    const iz = S.inactivity, att = iz?.attention || [];
    return `
      <section class="panel cp-cpanel" aria-labelledby="rtEr">
        <div class="cp-list-head"><div><h3 id="rtEr">Erasure requests</h3><p class="rt-sub">${er ? `Rule ${esc(er.id)}: erase within ${esc(periodText(er.keep))} of the request · ${esc(er.ref || "")}` : "No erasure rule is switched on."}</p></div></div>
        ${reqs.length ? `
          <div class="cp-chips rt-pad">${[["all", "All"], ...Object.entries(ER_STATUS).map(([k, [, l]]) => [k, l])].filter(([k]) => k === "all" || counts[k]).map(([k, l]) => `<button class="cp-chip${S.erFilter === k ? " on" : ""}" data-er-filter="${k}">${esc(l)} · ${num(counts[k])}</button>`).join("")}</div>
          <div class="cp-tablewrap"><table class="cp-ctable">
            <thead><tr><th>Customer</th><th>Requested (IST)</th><th>Due by</th><th>Status</th>${steps.map((s) => `<th class="center" title="${esc(STEPS[s]?.desc || "")}">${esc(STEPS[s]?.label || s)}</th>`).join("")}<th>Still held</th></tr></thead>
            <tbody>${shown.map((x) => `<tr><td><b>Customer #${esc(x.id)}</b></td><td class="nowrap">${esc(ist(x.requested_at))}</td><td class="nowrap">${esc(ist(x.due_at))}</td><td>${pill(ER_STATUS[x.status] || ["", x.status])}</td>
              ${steps.map((s) => `<td class="center">${mark(x.checks[STEPS[s]?.check])}</td>`).join("")}<td>${esc(remain(x))}</td></tr>`).join("")}</tbody>
          </table></div>`
        : `<div class="rt-empty">
            <div><b>No customer has asked for erasure yet.</b><p>When one does, this table tracks the request against its ${esc(periodText(er?.keep))} deadline and checks each step on the live data, without showing any personal data:</p></div>
            <ol class="rt-steps">${steps.map((s) => `<li><b>${esc(STEPS[s]?.label || s)}</b><span>${esc(STEPS[s]?.desc || "")}</span></li>`).join("")}</ol>
            <p class="muted">Orders and payments are kept as tax records; reviews and notifications are kept (open items in the data inventory).</p>
          </div>`}
      </section>
      <section class="panel cp-cpanel rt-gap" aria-labelledby="rtIn">
        <div class="cp-list-head"><div><h3 id="rtIn">Inactive accounts</h3><p class="rt-sub">${ina ? `Rule ${esc(ina.id)}: erase after ${esc(periodText(ina.keep))} without a sign-in or order, notifying ${esc(plural(ina.notice_hours || 0, "hour"))} before · ${esc(ina.ref || "")}` : "No inactivity rule is switched on."}</p></div></div>
        ${iz ? `<div class="rt-inactive">
          <div class="cp-stat"><span>Customers tracked</span><b>${num(iz.customers)}</b></div>
          <div class="cp-stat"><span>Notify now</span><b class="${iz.counts.notify ? "cp-red" : ""}">${num(iz.counts.notify)}</b></div>
          <div class="cp-stat"><span>Past deadline</span><b class="${iz.counts.overdue ? "cp-red" : ""}">${num(iz.counts.overdue)}</b></div>
          <div class="cp-stat"><span>Next deadline</span><b>${iz.next ? `${esc(day(iz.next.erase_at))}` : "–"}</b>${iz.next ? `<small>Customer #${esc(iz.next.id)} · notify from ${esc(day(iz.next.notify_at))}</small>` : ""}</div>
        </div>
        ${att.length ? `<div class="cp-tablewrap"><table class="cp-ctable"><thead><tr><th>Customer</th><th>Last activity (IST)</th><th>Notify by</th><th>Erase by</th><th>Status</th></tr></thead><tbody>${att.map((x) => `<tr><td><b>Customer #${esc(x.id)}</b></td><td>${esc(ist(x.last_activity))}</td><td>${esc(ist(x.notify_at))}</td><td>${esc(ist(x.erase_at))}</td><td>${pill(x.status === "overdue" ? ["bad", "Past deadline"] : ["warn", "Notify now"])}</td></tr>`).join("")}</tbody></table></div>`
          : `<p class="rt-pad muted">No customer is within ${esc(plural(ina?.notice_hours || 0, "hour"))} of the inactivity deadline.${iz.counts.no_activity ? ` ${plural(iz.counts.no_activity, "customer")} ${iz.counts.no_activity === 1 ? "has" : "have"} no sign-in or order on record yet.` : ""}</p>`}` : `<p class="rt-pad muted">${ina ? "Checking…" : ""}</p>`}
      </section>`;
  }

  /* ---------- Schedule (editor) ---------- */
  function scheduleHtml() {
    const pol = P(), rules = pol.rules.map((r, i) => ({ r, i }));
    const group = (g) => {
      const list = rules.filter(({ r }) => TYPES[r.type]?.group === g);
      const fresh = S.newRule && TYPES[S.newRule.type].group === g ? [S.newRule] : [];
      if (!list.length && !fresh.length) return "";
      return `<div class="panel cp-rgroup"><h3>${esc(g)}</h3>
        ${fresh.map((r) => `<div class="cp-rule editing new">${ruleForm(r, true)}</div>`).join("")}
        ${list.map(({ r, i }) => {
          const conf = conflictsFor(r, pol.rules);
          return `<div class="cp-rule${r.enabled ? "" : " off"}${S.editRule === r.id ? " editing" : ""}">
            <div class="cp-rrow">
              <button class="cp-switch" role="switch" aria-checked="${r.enabled}" aria-label="Rule ${esc(r.id)} ${r.enabled ? "on" : "off"}" data-toggle-rule="${i}"><i></i></button>
              <div class="cp-rtext"><p>${sentence(r)}</p><span>${esc(r.id)} · ${esc(where(r))} · ${esc(r.ref || "")}</span>
                ${conf.length && r.enabled ? `<span class="rt-conf-inline">Conflicts with ${conf.map((c) => esc(c.id)).join(", ")}</span>` : ""}</div>
              <div class="cp-rside">${pill(statusOf(r))}<button class="btn ghost" data-edit-rule="${esc(r.id)}" ${S.editRule === r.id ? "disabled" : ""}>Edit</button></div>
            </div>
            ${S.editRule === r.id ? ruleForm(r, false) : ""}
          </div>`;
        }).join("")}</div>`;
    };
    return `
      <div class="cp-rtop">
        <p>Schedule <b>v${esc(S.policy.version)}</b>, saved ${esc(ist(S.policy.updated_at))} by ${esc(S.policy.updated_by)}</p>
        <div class="cp-rbtns"><button class="btn ghost" data-act="export">Export</button><button class="btn primary" data-act="pick-rule" ${S.newRule ? "disabled" : ""}>Add rule</button></div>
      </div>
      ${S.picking ? `<div class="panel cp-picker"><div class="cp-list-head"><h3>What should the new rule do?</h3><button class="link" data-act="pick-cancel">Cancel</button></div>
        <div class="cp-pickgrid">${Object.entries(TYPES).map(([k, t]) => `<button class="cp-pick" data-new-rule="${k}"><b>${esc(t.label)}</b><span>${esc(t.desc)}</span></button>`).join("")}</div></div>` : ""}
      <div class="cp-rlayout">
        <div class="cp-rmain">${GROUP_ORDER.map(group).join("")}</div>
        <aside class="cp-rside-col">
          <div class="panel cp-scard"><h3>How deadlines work</h3>
            <p class="rt-help">A record's deadline is its date column plus the rule's period, in IST. Records within ${num(pol.due_soon_days || 30)} days of their deadline are “due soon”.</p>
            <p class="rt-help">Legal minimums protect records: a delete rule on the same data with a shorter period is flagged as a conflict.</p>
            <p class="rt-help">Nothing is deleted from the dashboard. Export a worklist and hand it to the service that owns the data.</p>
            <label class="field"><span>“Due soon” window (days)</span><input type="number" min="1" max="365" value="${esc(pol.due_soon_days || 30)}" data-soon-days></label>
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
    try { S.history = await api("/api/retention-policy/history"); } catch { S.history = []; }
    if (S.tab === "schedule") render();
  }
  function tableChoices(r) {
    const shop = Object.entries(S.schema).filter(([, cols]) => cols.some((c) => /timestamp|date/.test(c.type))).map(([t]) => `shop:${t}`).sort();
    return [...shop, ...Object.keys(GUARDRAIL_TABLES).map((t) => `guardrail:${t}`)];
  }
  function dateColumns(source, table) {
    if (source === "guardrail") return GUARDRAIL_TABLES[table] || [];
    return (S.schema[table] || []).filter((c) => /timestamp|date/.test(c.type)).map((c) => c.name);
  }
  function plainColumns(source, table) {
    if (source === "guardrail") return [];
    return (S.schema[table] || []).filter((c) => !/timestamp|date/.test(c.type) && /^[A-Za-z_][A-Za-z0-9_]*$/.test(c.name)).map((c) => c.name);
  }
  function ruleForm(r, isNew) {
    const period = (label = "Period") => `<label class="field"><span>${label}</span><span class="rt-period"><input name="keep_n" type="number" min="0" step="1" value="${esc(r.keep?.n ?? 1)}" aria-label="${label} amount">
      <select name="keep_unit" aria-label="${label} unit">${UNITS.map((u) => `<option ${r.keep?.unit === u ? "selected" : ""}>${u}</option>`).join("")}</select></span></label>`;
    const text = (name, label, v, wide) => `<label class="field${wide ? " wide" : ""}"><span>${label}</span><input name="${name}" type="text" value="${esc(v ?? "")}"></label>`;
    const src = `${r.source || "shop"}:${r.table || ""}`;
    let fields = "";
    if (r.type === "erasure") {
      fields = period("Erase within") + `<fieldset class="rt-stepset"><legend>Steps to check</legend>${Object.entries(STEPS).map(([k, s]) => `<label><input type="checkbox" name="step" value="${k}" ${(r.steps || []).includes(k) ? "checked" : ""}> ${esc(s.label)}</label>`).join("")}</fieldset>`;
    } else if (r.type === "inactivity") {
      fields = period("Inactive for") + `<label class="field"><span>Notice before erasure (hours)</span><input name="notice_hours" type="number" min="0" value="${esc(r.notice_hours ?? 48)}"></label>`;
    } else {
      fields = text("name", "Data name", r.name) +
        `<label class="field"><span>Table</span><select name="table" data-rt-table>${tableChoices().map((t) => `<option value="${esc(t)}" ${t === src ? "selected" : ""}>${esc(t.replace(":", " · "))}</option>`).join("")}</select></label>` +
        `<label class="field"><span>Measured from</span><select name="clock_column">${dateColumns(r.source || "shop", r.table).map((c) => `<option ${c === r.clock_column ? "selected" : ""}>${esc(c)}</option>`).join("")}</select></label>` +
        period(r.type === "legal_minimum" ? "Keep for at least" : "After") +
        (r.type === "age" ? `<label class="field"><span>Action</span><select name="action">${Object.entries(ACTIONS).map(([k, l]) => `<option value="${k}" ${r.action === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>` +
          `<label class="field"><span>Only where (optional)</span><span class="rt-period"><select name="filter_column"><option value="">Any record</option>${plainColumns(r.source || "shop", r.table).map((c) => `<option ${c === r.filter_column ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
            <input name="filter_value" type="text" placeholder="value" value="${esc(r.filter_value ?? "")}" aria-label="Filter value"></span></label>` : "");
    }
    return `<form class="cp-redit" data-rule="${esc(r.id)}" data-new="${isNew ? 1 : 0}">
      ${isNew ? `<p class="cp-newlabel">New rule · ${esc(TYPES[r.type].label)}</p>` : ""}
      <div class="cp-rfields">${fields}${r.type === "erasure" || r.type === "inactivity" ? text("name", "Rule name", r.name) : ""}
        ${text("ref", "Legal reference", r.ref, true)}</div>
      <label class="field"><span>Why (shown on the record list)</span><textarea name="basis" rows="2">${esc(r.basis || "")}</textarea></label>
      <div class="cp-rfoot"><span class="cp-preview" aria-live="polite"></span>
        <div class="cp-rbtns">${isNew ? "" : `<button type="button" class="btn ghost danger" data-act="delete-rule">Delete rule</button>`}
          <button type="button" class="btn ghost" data-act="cancel-rule">Cancel</button><button type="submit" class="btn primary">Apply</button></div></div>
    </form>`;
  }
  function readForm(form) {
    const isNew = form.dataset.new === "1", base = isNew ? S.newRule : P().rules.find((x) => x.id === form.dataset.rule);
    if (!base) return null;
    const v = (n) => form.querySelector(`[name="${n}"]`)?.value;
    const out = { ...base, name: (v("name") || base.name).trim(), ref: (v("ref") || "").trim(), basis: (v("basis") || "").trim(), keep: { n: Math.max(0, Number(v("keep_n")) || 0), unit: v("keep_unit") || base.keep?.unit || "days" } };
    if (base.type === "erasure") out.steps = [...form.querySelectorAll('[name="step"]:checked')].map((x) => x.value);
    if (base.type === "inactivity") out.notice_hours = Math.max(0, Number(v("notice_hours")) || 0);
    if (base.type === "age" || base.type === "legal_minimum") {
      const [source, table] = (v("table") || "shop:").split(":");
      Object.assign(out, { source, table, clock_column: v("clock_column") || dateColumns(source, table)[0] || "" });
      if (out.clock_column !== base.clock_column || table !== base.table) delete out.clock_label;
      if (base.type === "age") { out.action = v("action") || "delete"; out.filter_column = v("filter_column") || ""; out.filter_value = out.filter_column ? (v("filter_value") || "").trim() : ""; }
    }
    return { rule: out, isNew };
  }
  let previewT;
  function preview(form) {
    clearTimeout(previewT);
    previewT = setTimeout(async () => {
      // The form may be gone by now (applied, cancelled or re-rendered).
      if (!form.isConnected || !readForm(form)) return;
      const { rule } = readForm(form), el = form.querySelector(".cp-preview");
      if (rule.type === "erasure" || rule.type === "inactivity") { el.textContent = ""; return; }
      if (!rule.clock_column) { el.textContent = "Choose a date column."; return; }
      el.textContent = "Checking…";
      try {
        const m = await measure(rule, new Date());
        if (!form.isConnected) return;
        el.textContent = rule.type === "legal_minimum" ? `With these settings: ${num(m.total - m.past)} held, ${num(m.past)} past the minimum` : `With these settings: ${num(m.past)} past deadline, ${num(m.soon)} due soon`;
      } catch (e) { el.textContent = `Couldn't preview: ${e.message}`; }
    }, 350);
  }
  function apply(form) {
    const read = readForm(form);
    if (!read) return;
    clearTimeout(previewT);
    const { rule, isNew } = read;
    if (!rule.name) return toast("Give the rule a name.");
    if (rule.type === "erasure" && !rule.steps.length) return toast("Choose at least one erasure step.");
    if ((rule.type === "age" || rule.type === "legal_minimum") && !rule.clock_column) return toast("Choose the date column the period is measured from.");
    if (rule.type === "age" && rule.filter_column && !rule.filter_value) return toast("Enter the value for the “Only where” filter, or choose Any record.");
    S.editRule = null; S.newRule = null;
    edit((d) => { if (isNew) d.rules.push(rule); else d.rules[d.rules.findIndex((x) => x.id === rule.id)] = rule; });
  }

  /* ---------- drafts ---------- */
  async function edit(fn) {
    if (!S.draft) S.draft = clone(S.policy);
    fn(S.draft);
    S.recRows = null;
    render();
    S.busy = true; renderMeta();
    await measureAll();
    S.busy = false; render();
  }
  function pastTotal(res, rules) { return rules.reduce((n, r) => n + (r.enabled && r.type !== "legal_minimum" ? res[r.id]?.past || 0 : 0), 0); }
  function renderDraftBar() {
    const bar = $("rtDraft");
    if (!S.draft) { bar.hidden = true; return; }
    bar.hidden = false;
    const conflicts = S.draft.rules.filter((r) => r.enabled && r.type === "legal_minimum" && conflictsFor(r, S.draft.rules).length).length;
    $("rtDraftImpact").innerHTML = `Unsaved changes · past deadline now <b>${num(pastTotal(S.res, S.draft.rules))}</b>${conflicts ? ` · <span class="up">${plural(conflicts, "conflict")}</span>` : ""}`;
  }
  async function save() {
    const note = $("rtNote").value.trim();
    if (!note) { $("rtNote").focus(); return toast("Describe the change before saving."); }
    $("rtSave").disabled = true;
    try {
      const saved = await api("/api/retention-policy", { method: "PUT", body: JSON.stringify({ policy: S.draft, base_version: S.policy.version, change_note: note }) });
      S.gen++; S.policy = saved; S.draft = null; S.history = null; $("rtNote").value = "";
      await measureAll(); render(); toast(`Saved as version ${saved.version}.`, true);
    } catch (e) {
      if (e.status === 409 && e.body?.current) { S.gen++; S.policy = e.body.current; render(); toast(`${e.body.current.updated_by} saved version ${e.body.current.version} meanwhile. Your draft is kept; saving again replaces it.`); }
      else toast(e.message);
    } finally { $("rtSave").disabled = false; }
  }
  async function restore(v) {
    if (S.draft && !window.confirm("You have unsaved changes. Restore anyway and discard them?")) return;
    if (!window.confirm(`Restore schedule version ${v}? It will be saved as a new version.`)) return;
    try {
      const r = await api(`/api/retention-policy/restore/v${v}`, { method: "POST", body: JSON.stringify({ base_version: S.policy.version }) });
      S.gen++; S.policy = r; S.draft = null; S.history = null; S.recRows = null;
      await measureAll(); render(); toast(`Version ${v} restored as version ${r.version}.`, true);
    } catch (e) { toast(e.message); }
  }
  let toastT;
  function toast(m, ok = false) { const t = $("rtToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }

  /* ---------- events ---------- */
  function onClick(e) {
    const t = (s) => e.target.closest(s);
    let b;
    if ((b = t("[data-goto]"))) { S.tab = b.dataset.goto; return render(); }
    if ((b = t("[data-record]"))) { S.tab = "records"; S.sel = b.dataset.record; S.recPage = 0; S.recRows = null; S.recFilter = ""; return render(); }
    if ((b = t("[data-rec-filter]"))) { S.recFilter = b.dataset.recFilter; S.recPage = 0; S.recRows = null; return render(); }
    if ((b = t("[data-rec-page]"))) { S.recPage += b.dataset.recPage === "next" ? 1 : -1; S.recRows = null; return render(); }
    if ((b = t("[data-er-filter]"))) { S.erFilter = b.dataset.erFilter; return render(); }
    if ((b = t("[data-toggle-rule]"))) { const i = +b.dataset.toggleRule; return edit((d) => (d.rules[i].enabled = !d.rules[i].enabled)); }
    if ((b = t("[data-edit-rule]"))) { S.editRule = b.dataset.editRule; S.newRule = null; S.picking = false; render(); const f = document.querySelector("#rtBody .cp-redit"); f?.scrollIntoView({ block: "center" }); return f && preview(f); }
    if ((b = t("[data-new-rule]"))) {
      const type = b.dataset.newRule, pfx = { erasure: "E", age: "A", legal_minimum: "L", inactivity: "I" }[type];
      let n = 1; while (P().rules.some((r) => r.id === `${pfx}${n}`)) n++;
      const tbl = Object.keys(S.schema).find((t) => dateColumns("shop", t).length) || "";
      S.newRule = { id: `${pfx}${n}`, type, enabled: true, name: type === "erasure" ? "Erase customer data after an erasure request" : type === "inactivity" ? "Inactive customer accounts" : "New data", source: "shop", table: type === "erasure" || type === "inactivity" ? undefined : tbl,
        clock_column: dateColumns("shop", tbl)[0], keep: type === "erasure" ? { n: 30, unit: "days" } : type === "inactivity" ? { n: 3, unit: "years" } : { n: 1, unit: "years" },
        action: "delete", steps: type === "erasure" ? Object.keys(STEPS) : undefined, notice_hours: type === "inactivity" ? 48 : undefined, ref: "", basis: "" };
      S.picking = false; S.editRule = null; render();
      const f = document.querySelector("#rtBody .cp-redit"); f?.scrollIntoView({ block: "center" }); return f && preview(f);
    }
    if ((b = t("[data-restore]"))) return restore(+b.dataset.restore);
    b = t("[data-act]"); if (!b) return;
    switch (b.dataset.act) {
      case "worklist": return exportWorklist().catch((err) => toast(err.message));
      case "pick-rule": S.picking = true; S.editRule = null; return render();
      case "pick-cancel": S.picking = false; return render();
      case "cancel-rule": S.editRule = null; S.newRule = null; return render();
      case "delete-rule": { const id = b.closest(".cp-redit").dataset.rule; if (!window.confirm(`Delete rule ${id}? Nothing is saved until you click Save.`)) return; S.editRule = null; return edit((d) => d.rules.splice(d.rules.findIndex((x) => x.id === id), 1)); }
      case "export": { const blob = new Blob([JSON.stringify(P(), null, 2)], { type: "application/json" }); const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `retention-schedule-v${S.policy.version}${S.draft ? "-draft" : ""}.json` }); a.click(); return setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
    }
  }
  function onChange(e) {
    const t = e.target, form = t.closest(".cp-redit");
    if (t.matches("[data-rt-table]") && form) {
      // Table changed: refresh the date-column and filter choices for it.
      const [source, table] = t.value.split(":");
      const sel = form.querySelector('[name="clock_column"]');
      sel.innerHTML = dateColumns(source, table).map((c) => `<option>${esc(c)}</option>`).join("");
      const fc = form.querySelector('[name="filter_column"]');
      if (fc) fc.innerHTML = `<option value="">Any record</option>` + plainColumns(source, table).map((c) => `<option>${esc(c)}</option>`).join("");
    }
    if (form) return preview(form);
    if (t.matches("[data-soon-days]")) { const n = Math.min(365, Math.max(1, Number(t.value) || 30)); return edit((d) => (d.due_soon_days = n)); }
  }
  function bind() {
    $("rtTabs").onclick = (e) => { const b = e.target.closest("[data-tab]"); if (b) { S.tab = b.dataset.tab; render(); } };
    $("rtRefresh").onclick = () => loadAll({ withPolicy: !S.draft });
    $("rtSave").onclick = save;
    $("rtDiscard").onclick = async () => { if (!window.confirm("Discard all unsaved schedule changes?")) return; S.draft = null; S.editRule = null; S.newRule = null; S.recRows = null; await measureAll(); render(); };
    const body = $("rtBody");
    body.addEventListener("click", onClick);
    body.addEventListener("change", onChange);
    body.addEventListener("input", (e) => { const f = e.target.closest(".cp-redit"); if (f) preview(f); });
    body.addEventListener("submit", (e) => { if (e.target.matches(".cp-redit")) { e.preventDefault(); apply(e.target); } });
  }

  return {
    show() { if (!S.started) { S.started = true; bind(); } if (!S.policy || S.error) loadAll(); else render(); },
    tick() {
      const a = document.activeElement;
      const editing = S.editRule || S.newRule || S.picking || ($("view-retention").contains(a) && /SELECT|INPUT|TEXTAREA/.test(a.tagName));
      if (S.started && !S.busy && !editing) { S.recRows = null; loadAll({ withPolicy: !S.draft }); }
    },
    // For the main dashboard: loads once if needed, then reuses the result for 60 s.
    async summary() {
      for (let i = 0; i < 150 && S.busy; i++) await new Promise((r) => setTimeout(r, 200));   // a load already running: wait for it (max 30 s)
      if (!S.busy && (!S.policy || !S.loadedAt || Date.now() - S.loadedAt > 60000)) await loadAll({ withPolicy: !S.draft });
      if (!S.policy || !S.loadedAt) return null;
      const rules = P().rules.filter((r) => r.enabled), res = S.res;
      const sum = (pred, key) => rules.filter(pred).reduce((n, r) => n + (res[r.id]?.[key] || 0), 0);
      const er = rules.find((r) => r.type === "erasure"), ina = rules.find((r) => r.type === "inactivity");
      return { past: sum((r) => r.type !== "legal_minimum", "past"), soon: sum((r) => r.type !== "legal_minimum", "soon"), soonDays: P().due_soon_days || 30,
        held: rules.filter((r) => r.type === "legal_minimum").reduce((n, r) => n + Math.max(0, (res[r.id]?.total || 0) - (res[r.id]?.past || 0)), 0),
        erasureOpen: er ? res[er.id]?.open || 0 : 0, erasureOverdue: er ? res[er.id]?.past || 0 : 0, notify: ina ? res[ina.id]?.soon || 0 : 0,
        conflicts: rules.filter((r) => r.type === "legal_minimum" && conflictsFor(r, rules).length).length,
        rules: rules.filter((r) => r.type === "age" || r.type === "legal_minimum").map((r) => { const m = res[r.id] || {}; return { name: r.name, type: r.type, total: m.total || 0, past: m.past || 0, soon: m.soon || 0, held: r.type === "legal_minimum" ? Math.max(0, (m.total || 0) - (m.past || 0)) : 0 }; }) };
    },
    // For the AI assistant: the schedule with live measurements (ids, dates and counts only).
    async context() {
      await this.summary();
      if (!S.policy) return null;
      const txt = (h) => String(h).replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
      return {
        schedule_version: S.policy.version, checked_at: S.loadedAt, due_soon_days: P().due_soon_days || 30,
        rules: P().rules.map((r) => { const m = S.res[r.id] || {}; return { id: r.id, name: r.name, type: r.type, enabled: r.enabled, where: where(r), rule: txt(sentence(r)), status: statusOf(r)[1], ref: r.ref, basis: r.basis,
          past_deadline: m.past, due_soon: m.soon, total: m.total, next_deadline: m.nextDue || null, oldest_overdue_deadline: m.oldestPast || null, error: m.error, conflicts_with: conflictsFor(r, P().rules).map((c) => c.id) }; }),
        erasure_requests: (S.erasure?.requests || []).map((x) => ({ customer: `#${x.id}`, requested_at: x.requested_at, due_at: x.due_at, erased_at: x.erased_at, status: x.status, checks: x.checks, still_held: x.remaining })),
        inactivity: S.inactivity ? { customers_tracked: S.inactivity.customers, counts: S.inactivity.counts, next: S.inactivity.next ? { customer: `#${S.inactivity.next.id}`, erase_at: S.inactivity.next.erase_at } : null } : null,
      };
    },
    _shift: shift, _conflicts: conflictsFor,
  };
})();
