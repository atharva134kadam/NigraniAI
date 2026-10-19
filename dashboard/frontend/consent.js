/* Consent & Purpose — policy-driven consent and purpose-limitation checks.
   Data and policies come from consent_service (localhost:8091), which reads the
   ShopSmart shop database read-only and keeps the versioned policy file.
   The engine below is pure: evaluate(policy, schema, data) -> findings.
   Rules are instances of fixed templates (no code in policies), so any rule
   can be added, edited, disabled or removed from the UI without code changes.
   Screens: Overview (health + issues), Customers (consent timeline), Issues
   (one per rule: what / why / fix / evidence), Rules (plain-language sentences).
   Uses session / refreshSession from app.js at call time. */
const Consent = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const IST = "Asia/Kolkata";
  const SEV = ["critical", "high", "medium", "low"];
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const plural = (n, one, many = one + "s") => `${num(n)} ${n === 1 ? one : many}`;
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
  const joinList = (a) => (a.length <= 1 ? a[0] || "" : `${a.slice(0, -1).join(", ")} and ${a[a.length - 1]}`);
  const singular = (name) => (/ses$/i.test(name) ? name.slice(0, -2) : /s$/i.test(name) ? name.slice(0, -1) : name);
  const fmt = (o) => new Intl.DateTimeFormat("en-IN", { timeZone: IST, ...o });
  const F_DT = fmt({ day: "numeric", month: "short", hour: "numeric", minute: "2-digit", hour12: true });
  const F_TIME = fmt({ hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
  const F_HM = fmt({ hour: "numeric", minute: "2-digit", hour12: true });
  const F_DAY = fmt({ weekday: "short", day: "numeric", month: "short", year: "numeric" });
  const F_KEY = new Intl.DateTimeFormat("en-CA", { timeZone: IST, year: "numeric", month: "2-digit", day: "2-digit" });
  const up = (s) => s.replace(/\b(am|pm)\b/i, (m) => m.toUpperCase());
  const ist = (v) => (v ? up(F_DT.format(new Date(v))) + " IST" : "–");
  const istShort = (v) => (v ? up(F_DT.format(new Date(v))) : "–");
  const hm = (v) => up(F_HM.format(new Date(v)));

  /* Rule templates: group, wording, defaults. */
  const TEMPLATES = {
    notice_required: { group: "Consent", short: "No notice", label: "Notice required", name: "Processing without an accepted privacy notice", sev: "high", ref: "DPDP Act 2023 · s.5, s.6", params: () => ({ notice: P().notices[0]?.id || "" }), desc: "Processing for a customer who never accepted a notice." },
    before_consent: { group: "Consent", short: "Before consent", label: "Processing before consent", name: "Processing before consent was given", sev: "high", ref: "DPDP Act 2023 · s.6(1)", params: () => ({ grace_seconds: 60 }), desc: "Processing that happened before the recorded consent time." },
    opt_in_required: { group: "Consent", short: "No opt-in", label: "Opt-in required", name: "Opt-in purpose without consent", sev: "critical", ref: "DPDP Act 2023 · s.6(1), s.6(6)", params: () => ({}), desc: "Opt-in purposes (like marketing) used without an opt-in." },
    notice_outdated: { group: "Consent", short: "Outdated notice", label: "Outdated notice", name: "Consent given to an outdated notice", sev: "medium", ref: "DPDP Rules 2025 · Rule 3", params: () => ({ notice: P().notices[1]?.id || P().notices[0]?.id || "" }), desc: "Customers who accepted an older version of a notice." },
    after_erasure: { group: "Consent", short: "After erasure", label: "Processing after erasure request", name: "Processing after an erasure request", sev: "critical", ref: "DPDP Act 2023 · s.8(7), s.12(3)", params: () => ({ grace_seconds: 120 }), desc: "Processing after a customer asked to be erased." },
    undeclared_purpose: { group: "Purpose", short: "No declared purpose", label: "Undeclared purpose", name: "Processing for an undeclared purpose", sev: "high", ref: "DPDP Act 2023 · s.5(1), s.6(1)", params: () => ({}), desc: "Processing that matches none of the declared purposes." },
    unknown_principal: { group: "Records", short: "Unknown customer", label: "Unknown data principal", name: "Processing not linked to a known data principal", sev: "medium", ref: "DPDP Act 2023 · s.8(1)", params: () => ({}), desc: "Rows that can't be tied to a customer record." },
    signup_gate: { group: "Consent", short: "Sign-up gate failed", label: "Mandatory acceptance at sign-up", name: "Account created after acceptance became mandatory, with no acceptance recorded", sev: "critical", ref: "DPDP Act 2023 · s.5, s.6", params: () => ({}), desc: "Accounts that signed up after the mandatory notice went live but have no acceptance on record: the sign-up gate failed or didn't save." },
    legacy_reacceptance: { group: "Consent", short: "Existing account", label: "Existing accounts to re-accept", name: "Existing accounts that haven't accepted the mandatory notice yet", sev: "low", ref: "DPDP Act 2023 · s.5(2)", params: () => ({}), desc: "Accounts created before acceptance became mandatory. Show them the notice at their next sign-in." },
    inventory_drift: { group: "Records", short: "Inventory drift", label: "Inventory drift", name: "Consent records differ from the declared inventory", sev: "medium", ref: "DPDP Act 2023 · s.5, s.8(1)", params: () => ({ tables: ["customers"] }), desc: "Database columns that differ from the declared inventory." },
  };
  const GROUPS = ["Consent", "Purpose", "Records"];
  const FIELD_KEYS = ["notice_version", "consented_at", "consent_updated_at", "terms_accepted", "terms_accepted_at", "terms_version", "marketing", "deletion_requested_at", "erased_at"];
  const FIELD_LABEL = { notice_version: "Privacy notice version", consented_at: "Consent given at", consent_updated_at: "Consent updated at", terms_accepted: "Terms accepted", terms_accepted_at: "Terms accepted at", terms_version: "Terms version", marketing: "Marketing consent", deletion_requested_at: "Erasure requested at", erased_at: "Erased at" };
  const NOTICE_TIME = { notice_version: "consented_at", terms_version: "terms_accepted_at" };
  const CAPTURE = { mandatory_signup: "Mandatory at sign-up", prompted: "Asked after sign-up" };
  const SHEETS = { purposes: "Purposes", activities: "What counts as processing", notices: "Notices", fields: "Consent fields", inventory: "Data inventory", history: "Version history" };

  const C = {
    started: false, tab: "overview",
    policy: null, draft: null, schema: {}, blocked: [], data: null, result: null,
    sel: { customer: null, issue: null }, custFilter: "action", custQuery: "",
    custView: "list", custPage: 0, custPageSize: 25, custSort: "issues", custRule: "", lookup: null, lookupBusy: false,
    showAllTimeline: false, evidenceLimit: 25,
    editRule: null, newRule: null, picking: false, sheet: null,
    history: null, gen: 0, loadedAt: null, error: "", busy: false,
  };
  const P = () => C.draft || C.policy;

  /* ---------------- API (consent_service) ---------------- */
  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, {
      ...opts,
      headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) },
    });
    let r;
    try { r = await go(); } catch { throw Object.assign(new Error("offline"), { offline: true }); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error || `HTTP ${r.status}`), { status: r.status, body: j });
    return j;
  }

  // C.gen changes whenever this tab saves or restores a policy; a load that started
  // before that is stale and must not overwrite the newer policy.
  async function loadAll({ withPolicy = true } = {}) {
    const gen = C.gen;
    C.busy = true; renderMeta();
    try {
      const [policy, schema] = await Promise.all([withPolicy || !C.policy ? api("/api/policy") : null, api("/api/schema")]);
      if (gen !== C.gen) return;
      if (policy) C.policy = policy;
      C.schema = schema.tables; C.blocked = schema.blocked_columns;
      const data = await loadData(P());
      if (gen !== C.gen) return;
      C.data = data; C.error = ""; C.loadedAt = new Date();
    } catch (e) {
      if (gen === C.gen) C.error = e.offline ? "offline" : e.message;
    } finally {
      C.busy = false;
      if (gen === C.gen) { evaluateNow(); render(); } else renderMeta();
    }
  }
  async function loadData(policy) {
    const pt = policy.principal?.table || "customers";
    const reqs = [api(`/api/table/${pt}`)];
    const tableReq = (t, cols) => api(`/api/table/${encodeURIComponent(t)}?columns=${encodeURIComponent(cols.filter(Boolean).join(","))}`).catch((e) => ({ error: e.message, rows: [] }));
    for (const a of policy.activities) reqs.push(tableReq(a.table, ["id", a.principal_column, a.time_column, a.type_column, a.principal_via?.column]));
    // Linked tables used to find the customer when the activity row has none (e.g. payment -> order -> customer).
    const links = policy.activities.map((a) => a.principal_via).filter((v) => v?.table);
    for (const v of links) reqs.push(tableReq(v.table, [v.key, v.principal_column]));
    const sv = policy.signup?.via;
    reqs.push(sv?.table ? tableReq(sv.table, [sv.key, sv.time]) : Promise.resolve({ rows: [] }));
    const [principals, ...rest0] = await Promise.all(reqs);
    const signupRows = rest0.pop(), rest = rest0;
    const activities = {}, linked = {}, loadErrors = [];
    // A table that fails to load must never look "empty and compliant":
    // reuse its last good rows when we have them, and always say so.
    const settle = (res, prev, label) => {
      if (!res.error) return res;
      const stale = prev && !prev.error ? prev : null;
      loadErrors.push({ label, error: res.error, stale: !!stale });
      return stale ? { ...stale, stale: true } : res;
    };
    policy.activities.forEach((a, i) => (activities[a.id] = settle(rest[i], C.data?.activities?.[a.id], a.name)));
    links.forEach((v, i) => { const k = `${v.table}.${v.key}`; linked[k] = settle(rest[policy.activities.length + i], C.data?.linked?.[k], `${v.table} (customer lookup)`); });
    if (signupRows?.error) loadErrors.push({ label: `${sv.table} (sign-up dates)`, error: signupRows.error, stale: false });
    return { principals: principals.rows, activities, linked, signups: signupRows?.rows || [], loadErrors };
  }

  /* ---------------- Engine ---------------- */
  function evaluate(policy, schema, data) {
    const fm = policy.field_map || {};
    // A consent fact may live in more than one column (a renamed or duplicated set): use the first that holds a value.
    const get = (row, key) => {
      if (!row || !fm[key]) return undefined;
      for (const col of [].concat(fm[key])) { const v = row[col]; if (v !== null && v !== undefined && v !== "") return v; }
      return undefined;
    };
    const idCol = policy.principal?.id_column || "id";
    const principals = new Map((data.principals || []).map((r) => [String(r[idCol]), r]));
    const purposes = new Map(policy.purposes.map((p) => [p.id, p]));
    const notices = new Map(policy.notices.map((n) => [n.id, n]));
    const findings = [], byEvent = new Map();
    const add = (rule, f) => {
      findings.push({ rule: rule.id, ruleName: rule.name, ruleType: rule.type, severity: rule.severity, dpdp: rule.dpdp_ref, ...f });
      if (f.event) { const k = f.event.key; byEvent.set(k, [...(byEvent.get(k) || []), rule.id]); }
    };

    // Normalise every activity row into {activity, rowId, principal, at, purpose, typeValue}.
    const events = [];
    for (const a of policy.activities) {
      const rows = data.activities[a.id]?.rows || [];
      const via = a.principal_via?.table ? a.principal_via : null;
      const link = via ? new Map(((data.linked || {})[`${via.table}.${via.key}`]?.rows || []).map((r) => [String(r[via.key]), r[via.principal_column]])) : null;
      rows.forEach((r, i) => {
        const typeValue = a.type_column ? r[a.type_column] : null;
        const purpose = a.type_column ? (a.type_map || {})[typeValue] || "" : a.purpose || "";
        let principal = r[a.principal_column], linkedVia = "";
        if (principal == null && link && r[via.column] != null) { principal = link.get(String(r[via.column])); linkedVia = `${via.column} → ${via.table}`; }
        const rowId = r.id ?? i + 1;
        events.push({ key: `${a.id}:${rowId}`, activity: a, rowId, principal: principal == null ? null : String(principal), linkedVia, at: r[a.time_column], purpose, typeValue });
      });
    }
    const ts = (v) => (v ? new Date(v).getTime() : NaN);
    const where = (e) => `${singular(e.activity.name)} #${e.rowId}`;

    // When each customer signed up: their own column, a linked table (e.g. the login account), or their first activity.
    const su = policy.signup || {};
    const viaRows = su.via?.table ? new Map((data.signups || []).map((r) => [String(r[su.via.key]), r[su.via.time]])) : null;
    const firstEvent = new Map();
    for (const e of events) if (e.principal != null && e.at && (!firstEvent.has(e.principal) || e.at < firstEvent.get(e.principal))) firstEvent.set(e.principal, e.at);
    const signups = new Map();
    for (const [id, pr] of principals) {
      const own = [].concat(su.column || []).map((c) => pr[c]).find((v) => v);
      const via = viaRows && pr[su.via.column] != null ? viaRows.get(String(pr[su.via.column])) : null;
      const first = su.first_activity === false ? null : firstEvent.get(id);
      signups.set(id, own ? { at: own, how: "own record" } : via ? { at: via, how: `${su.via.table}.${su.via.time}` } : first ? { at: first, how: "first activity (estimate)" } : { at: null, how: "unknown" });
    }
    // Notices accepted at sign-up as a condition of the account: since when was that enforced?
    const mandatory = policy.notices.filter((n) => n.capture === "mandatory_signup" && n.since);
    const sinceOf = (n) => (n && n.capture === "mandatory_signup" && n.since ? ts(n.since) : NaN);
    const gateAt = mandatory.length ? Math.min(...mandatory.map(sinceOf)) : NaN;
    // "before": signed up before acceptance became mandatory (an existing account); "after": should have passed the gate.
    const originOf = (id, n) => {
      const g = n ? sinceOf(n) : gateAt, t = ts(signups.get(id)?.at);
      if (isNaN(g)) return "n/a";
      return isNaN(t) ? "unknown" : t < g ? "before" : "after";
    };

    for (const rule of policy.rules.filter((r) => r.enabled)) {
      const prm = rule.params || {};
      switch (rule.type) {
        case "notice_required": {
          const n = notices.get(prm.notice);
          if (!n) break;
          const g = sinceOf(n);
          for (const e of events) {
            const p = purposes.get(e.purpose), pr = principals.get(e.principal);
            if (!p || p.legal_basis !== "consent" || !pr || get(pr, n.field)) continue;
            const origin = originOf(e.principal, n);
            if (!isNaN(g) && origin !== "after" && !(ts(e.at) >= g)) continue;     // an existing account, before the notice became mandatory
            add(rule, { principal: e.principal, event: e, purpose: e.purpose, at: e.at, origin, detail: origin === "after"
              ? `${where(e)} was processed for ${p.name}; this customer signed up after the ${n.name} became mandatory, yet no acceptance is recorded.`
              : !isNaN(g) ? `${where(e)} was processed for ${p.name} after the ${n.name} became mandatory, but this existing customer hasn't accepted it yet.`
              : `${where(e)} was processed for ${p.name}, but this customer has not accepted the ${n.name}.` });
          }
          break;
        }
        case "before_consent": {
          const grace = (Number(prm.grace_seconds) || 0) * 1000;
          const consentNotice = policy.notices.find((x) => x.field === "notice_version");
          const g = sinceOf(consentNotice);
          for (const e of events) {
            const p = purposes.get(e.purpose), pr = principals.get(e.principal);
            const c = ts(get(pr, "consented_at"));
            if (!p || p.legal_basis !== "consent" || !pr || isNaN(c) || isNaN(ts(e.at))) continue;
            if (!isNaN(g) && ts(e.at) < g && originOf(e.principal, consentNotice) !== "after") continue;   // before acceptance was required at all
            if (ts(e.at) < c - grace) add(rule, { principal: e.principal, event: e, purpose: e.purpose, at: e.at, gapMs: c - ts(e.at), detail: `${where(e)} on ${ist(e.at)}, but consent was only given on ${ist(get(pr, "consented_at"))}.` });
          }
          break;
        }
        case "opt_in_required": {
          for (const e of events) {
            const p = purposes.get(e.purpose);
            if (!p || p.consent_type !== "opt_in") continue;
            const pr = principals.get(e.principal);
            const v = get(pr, p.consent_field);
            if (pr && v !== true) add(rule, { principal: e.principal, event: e, purpose: e.purpose, at: e.at, detail: `${where(e)} was sent for ${p.name}, but this customer's opt-in is ${v === false ? "declined" : "not recorded"}.` });
          }
          break;
        }
        case "undeclared_purpose": {
          for (const e of events) {
            if (e.purpose && purposes.has(e.purpose)) continue;
            const label = e.activity.type_column ? `${e.activity.type_column} = ${e.typeValue ?? "empty"}` : "no purpose set";
            add(rule, { principal: e.principal, event: e, purpose: "", at: e.at, detail: `${where(e)} (${label}) is not mapped to any declared purpose.` });
          }
          break;
        }
        case "notice_outdated": {
          const n = notices.get(prm.notice);
          if (!n) break;
          const consentNotices = policy.notices.filter((x) => x.id !== n.id);
          for (const [id, pr] of principals) {
            const consenting = consentNotices.some((x) => get(pr, x.field));
            if (!consenting) continue; // never consented → covered by "Notice required"
            const v = get(pr, n.field);
            const mand = n.capture === "mandatory_signup";
            if (v !== n.current_version) add(rule, { principal: id, purpose: "", at: get(pr, "consent_updated_at") || get(pr, "consented_at"), kind: v ? "old_version" : mand ? "not_saved" : "missing",
              detail: v ? `Accepted ${n.name} version ${v}; current version is ${n.current_version}. Re-consent needed.`
                : mand ? `Accepted the other notice, but no ${n.name} acceptance is recorded. Accepting it is mandatory, so the website most likely didn't save it.`
                : `Has not accepted the ${n.name} (current version ${n.current_version}). Re-consent needed.` });
          }
          break;
        }
        case "after_erasure": {
          const grace = (Number(prm.grace_seconds) || 0) * 1000;
          for (const e of events) {
            const pr = principals.get(e.principal);
            const del = Math.min(...[ts(get(pr, "deletion_requested_at")), ts(get(pr, "erased_at"))].filter((x) => !isNaN(x)));
            if (!pr || !isFinite(del) || isNaN(ts(e.at))) continue;
            if (ts(e.at) > del + grace) add(rule, { principal: e.principal, event: e, purpose: e.purpose, at: e.at, detail: `${where(e)} on ${ist(e.at)}, after the customer asked for erasure on ${ist(new Date(del))}.` });
          }
          break;
        }
        case "unknown_principal": {
          for (const e of events) {
            if (e.principal != null && principals.has(e.principal)) continue;
            add(rule, { principal: e.principal, event: e, purpose: e.purpose, at: e.at, detail: e.principal == null
              ? `${where(e)} cannot be linked to any customer, so its consent cannot be checked.`
              : `${where(e)} belongs to customer #${e.principal}, who has no profile record.` });
          }
          break;
        }
        case "signup_gate": {
          for (const [id, pr] of principals) for (const n of mandatory) {
            if (get(pr, n.field) || originOf(id, n) !== "after") continue;
            add(rule, { principal: id, purpose: "", at: signups.get(id)?.at, notice: n.id, detail: `Signed up on ${ist(signups.get(id)?.at)}, after the ${n.name} became mandatory on ${ist(n.since)}, but no acceptance is recorded.` });
          }
          break;
        }
        case "legacy_reacceptance": {
          const activeSince = new Set(events.filter((e) => e.principal != null && ts(e.at) >= gateAt).map((e) => e.principal));
          for (const [id, pr] of principals) {
            const missing = mandatory.filter((n) => !get(pr, n.field) && originOf(id, n) !== "after");
            if (!missing.length || policy.notices.some((n) => get(pr, n.field))) continue;   // partly accepted: covered by "outdated notice"
            if (activeSince.has(id)) continue;   // used the shop since go-live: raised (high) by "notice required" instead
            const su0 = signups.get(id);
            add(rule, { principal: id, purpose: "", at: su0?.at, detail: su0?.at ? `Account from ${ist(su0.at)} (${su0.how}), before acceptance became mandatory. Show the ${joinList(missing.map((n) => n.name))} at the next sign-in.`
              : `Sign-up date unknown and no activity recorded. If it's a real account, show the ${joinList(missing.map((n) => n.name))} at the next sign-in; if it's a test or seed account, remove it.` });
          }
          break;
        }
        case "inventory_drift": {
          const tables = Array.isArray(prm.tables) ? prm.tables : String(prm.tables || "").split(",").map((s) => s.trim()).filter(Boolean);
          for (const t of tables) {
            const live = (schema[t] || []).map((c) => c.name);
            const declared = (policy.inventory || {})[t] || [];
            if (!live.length) { add(rule, { principal: null, purpose: "", at: null, table: t, detail: `Table ${t} was not found in the shop database.` }); continue; }
            for (const c of declared.filter((c) => !live.includes(c))) add(rule, { principal: null, purpose: "", at: null, table: t, kind: "missing", detail: `Declared column ${t}.${c} is missing from the database (renamed or removed).` });
            for (const c of live.filter((c) => !declared.includes(c))) add(rule, { principal: null, purpose: "", at: null, table: t, kind: "extra", detail: `Column ${t}.${c} exists in the database but is not in the declared inventory.` });
            if (t === (policy.principal?.table || "customers")) {
              for (const [k, cols] of Object.entries(fm)) for (const col of [].concat(cols || [])) if (col && !live.includes(col)) add(rule, { principal: null, purpose: "", at: null, table: t, kind: "mapping", detail: `Consent field "${FIELD_LABEL[k] || k}" points to ${t}.${col}, which does not exist.` });
            }
          }
          break;
        }
      }
    }
    findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || String(b.at || "").localeCompare(String(a.at || "")));

    // Consent status per principal. Index events and findings once (O(n)), so this
    // stays fast with thousands of customers instead of rescanning per customer.
    const required = policy.notices.filter((x) => x.required);
    const evStats = new Map(), fStats = new Map();
    for (const e of events) {
      if (e.principal == null) continue;
      const st = evStats.get(e.principal) || { n: 0, last: "" };
      st.n++; if (e.at && e.at > st.last) st.last = e.at;
      evStats.set(e.principal, st);
    }
    for (const f of findings) {
      if (f.principal == null) continue;
      const st = fStats.get(f.principal) || { n: 0, rules: new Set() };
      st.n++; st.rules.add(f.rule);
      fStats.set(f.principal, st);
    }
    const coverage = [...principals.entries()].map(([id, pr]) => {
      const valid = required.every((x) => get(pr, x.field) === x.current_version);
      const any = policy.notices.some((x) => get(pr, x.field));
      const notices = policy.notices.map((n) => ({ notice: n, version: get(pr, n.field) || null, at: get(pr, NOTICE_TIME[n.field]) || get(pr, `${n.field}_at`) || null }));
      const optIns = policy.purposes.filter((p) => p.legal_basis === "consent" && p.consent_type === "opt_in").map((p) => ({ purpose: p, value: get(pr, p.consent_field) }));
      const origin = originOf(id), signup = signups.get(id) || { at: null, how: "unknown" };
      const activeAfter = !isNaN(gateAt) && (evStats.get(id)?.last || "") && ts(evStats.get(id).last) >= gateAt;
      const oldVersion = notices.some((x) => x.version && x.version !== x.notice.current_version && x.notice.required);
      // valid · accepted at sign-up · old version · accepted one notice but a mandatory one isn't saved
      // · an existing account still to re-accept (quiet / active since go-live) · signed up after go-live without accepting
      const status = valid ? "valid" : oldVersion ? "stale" : any ? "unsaved" : isNaN(gateAt) ? "none"
        : origin === "after" ? "gate_failure" : activeAfter ? "legacy_active" : "legacy";
      return {
        id, valid, status, origin, signupAt: signup.at, signupHow: signup.how, activeAfter: !!activeAfter, notices, optIns,
        consentedAt: get(pr, "consented_at") || null, updatedAt: get(pr, "consent_updated_at") || null,
        erasureAt: get(pr, "deletion_requested_at") || null, erasedAt: get(pr, "erased_at") || null,
        events: evStats.get(id)?.n || 0,
        lastAt: evStats.get(id)?.last || "",
        findings: fStats.get(id)?.n || 0,
        rules: [...(fStats.get(id)?.rules || [])],
      };
    });
    // The sign-up gate: of the accounts created since acceptance became mandatory, how many accepted (and how fast)?
    const gate = isNaN(gateAt) ? null : (() => {
      const after = coverage.filter((c) => c.origin === "after");
      const ok = after.filter((c) => mandatory.every((n) => c.notices.find((x) => x.notice.id === n.id)?.version));
      const lags = ok.map((c) => Math.max(...mandatory.map((n) => ts(c.notices.find((x) => x.notice.id === n.id)?.at) - ts(c.signupAt)))).filter((x) => isFinite(x) && x >= 0).sort((a, b) => a - b);
      return { since: new Date(gateAt).toISOString(), notices: mandatory.map((n) => n.name), after: after.length, accepted: ok.length, failures: after.length - ok.length,
               medianLagMs: lags.length ? lags[Math.floor(lags.length / 2)] : null, existing: coverage.filter((c) => c.origin !== "after").length };
    })();
    return { findings, coverage, events, byEvent, gate };
  }
  function evaluateNow() {
    C.result = C.data && P() ? evaluate(P(), C.schema, C.data) : null;
    C.baseCount = C.draft && C.data ? evaluate(C.policy, C.schema, C.data).findings.length : null;
  }

  /* ---------------- Issues: one per rule with findings ---------------- */
  function explain(rule, items) {
    const pol = P(), p = rule.params || {};
    const custs = [...new Set(items.map((f) => f.principal).filter((x) => x != null))];
    const n = items.length, k = custs.length;
    const acts = [...new Set(items.filter((f) => f.event).map((f) => f.event.activity.name.toLowerCase()))];
    const times = items.map((f) => f.at).filter(Boolean).sort();
    const who = k === 1 ? `Customer #${custs[0]}` : `${num(k)} customers`;
    const noticeName = pol.notices.find((x) => x.id === p.notice)?.name || "notice";
    const base = { customers: custs, events: n, first: times[0], last: times[times.length - 1] };
    switch (rule.type) {
      case "notice_required": {
        const nt = pol.notices.find((x) => x.id === p.notice), mand = nt?.capture === "mandatory_signup";
        const after = items.some((f) => f.origin === "after");
        if (mand) return { ...base, title: after ? `${who} signed up after the ${noticeName} became mandatory, yet ${k === 1 ? "has" : "have"} no acceptance and ${k === 1 ? "was" : "were"} processed` : `${who} (existing ${k === 1 ? "account" : "accounts"}) used the shop after the ${noticeName} became mandatory, without accepting it`,
          impact: `${plural(k, "customer")} · ${plural(n, "event")}`,
          what: `Their ${joinList(acts)} after ${istShort(nt.since)} IST were processed with no acceptance on record.`,
          why: after ? "Acceptance is mandatory at sign-up, so this should be impossible: the sign-up flow let them through, or didn't save the acceptance." : "These accounts existed before acceptance became mandatory. Once they come back, they must see and accept the notice before more processing.",
          fix: after ? ["Check the sign-up flow: the acceptance must be saved before the account is created.", "Ask these customers to accept the notice at their next sign-in."] : ["Show the notice at sign-in to existing customers who haven't accepted it, and block checkout until they do.", "Check again after the change: this clears once they accept."] };
        return { ...base, title: `${who} ${k === 1 ? "was" : "were"} processed without accepting the ${noticeName}`, impact: `${plural(k, "customer")} · ${plural(n, "event")}`,
          what: `Their ${joinList(acts)} were still processed.`,
          why: "Processing on the basis of consent needs a notice first and consent before use. These events have neither on record.",
          fix: ["Stop processing for these customers until the notice is accepted.", `Ask ${k === 1 ? "this customer" : "these customers"} to accept the current ${noticeName}.`, "Check whether sign-up or checkout lets people skip the notice."] };
      }
      case "before_consent": return { ...base, title: `${who} ${k === 1 ? "was" : "were"} processed before giving consent`, impact: `${plural(k, "customer")} · ${plural(n, "event")}`,
        what: `${cap(joinList(acts))} between ${istShort(base.first)} and ${istShort(base.last)} IST came before the customer's recorded consent.`,
        why: "The DPDP Act expects consent before data is processed for a purpose. Asking afterwards leaves these events without a recorded basis.",
        fix: ["Show the notice before checkout, and block placing an order until it is accepted.", "Review these events and record the basis for each one your team decides to keep.", "Check again after the change: this issue clears when no new event comes before consent."] };
      case "opt_in_required": {
        const ps = [...new Set(items.map((f) => pol.purposes.find((x) => x.id === f.purpose)?.name).filter(Boolean))];
        return { ...base, title: `${plural(n, "message")} for ${joinList(ps) || "an opt-in purpose"} without an opt-in`, impact: `${plural(k, "customer")} · ${plural(n, "event")}`,
          what: "Sent to customers whose opt-in is declined or not recorded.",
          why: "Opt-in purposes need their own consent, and a withdrawn opt-in must stop the processing it covered.",
          fix: ["Send opt-in purposes only to customers whose opt-in is on.", "Check the sending job filters on the opt-in field."] };
      }
      case "undeclared_purpose": {
        const vals = [...new Set(items.map((f) => (f.event?.activity.type_column ? `${f.event.activity.name.toLowerCase()} of type ${f.event.typeValue ?? "empty"}` : f.event?.activity.name.toLowerCase())).filter(Boolean))];
        return { ...base, title: `${plural(n, "event")} with no declared purpose`, impact: plural(n, "event"),
          what: `${cap(joinList(vals))} match none of the ${num(pol.purposes.length)} declared purposes.`,
          why: "Personal data may be processed only for a purpose stated in the notice.",
          fix: ["Map them to a declared purpose under Rules → What counts as processing, or stop this processing.", "If a new purpose is needed, add it to the notice before using it."] };
      }
      case "notice_outdated": {
        const cur = pol.notices.find((x) => x.id === p.notice)?.current_version || "";
        if (items.every((f) => f.kind === "not_saved")) return { ...base, title: `${who} accepted the privacy notice, but no ${noticeName} acceptance is saved`, impact: plural(k, "customer"),
          what: `Accepting the ${noticeName} is mandatory, so ${k === 1 ? "this customer" : "these customers"} must have accepted it, but the record is missing.`,
          why: "If the acceptance isn't stored, you can't prove it. DPDP expects the fiduciary to be able to show the consent it relies on.",
          fix: ["Check that the website saves the Terms acceptance (and its time and version) when the checkbox is ticked.", `Ask ${k === 1 ? "this customer" : "these customers"} to accept the ${noticeName} again so the record exists.`] };
        return { ...base, title: `${who} ${k === 1 ? "has" : "have"} not accepted the current ${noticeName}`, impact: plural(k, "customer"),
          what: `The current version is ${cur}. ${k === 1 ? "This customer" : "These customers"} accepted another notice but not this version.`,
          why: "Consent should be to the notice that is in force. A changed notice needs fresh consent.",
          fix: [`Ask ${k === 1 ? "this customer" : "these customers"} to accept version ${cur}.`, "Until then, review processing that relies on the older version."] };
      }
      case "signup_gate": return { ...base, title: `${who} signed up after acceptance became mandatory, but no acceptance is recorded`, impact: plural(k, "customer"),
        what: "Accepting the notices is mandatory at sign-up, so every new account should have an acceptance with a time and version.",
        why: "Either the sign-up flow let them skip it, or it didn't save the record. Without the record there's no proof of consent.",
        fix: ["Check the sign-up flow on the website: block account creation until the acceptance is saved.", "Ask these customers to accept at their next sign-in.", "This should stay at zero; anything here is a website bug."] };
      case "legacy_reacceptance": return { ...base, title: `${who} from before acceptance became mandatory ${k === 1 ? "hasn't" : "haven't"} accepted yet`, impact: plural(k, "existing account"),
        what: `${k === 1 ? "This account was" : "These accounts were"} created before the sign-up checkbox existed, so ${k === 1 ? "it" : "they"} never saw it.`,
        why: "Existing customers must get the notice too, as soon as reasonably practicable. They count as compliant once they accept.",
        fix: ["Show the privacy notice and Terms at the next sign-in, and block checkout until accepted.", "Optionally email them the notice with a link to accept.", "Remove test or seed accounts that aren't real customers."] };
      case "after_erasure": return { ...base, title: `${plural(n, "event")} after an erasure request`, impact: `${plural(k, "customer")} · ${plural(n, "event")}`,
        what: "Data was processed after the customer asked to be erased.",
        why: "Once a customer asks for erasure, their data must be erased and no longer processed, unless a law requires keeping it.",
        fix: ["Stop processing for customers who asked for erasure.", "Check that the erasure job runs on time."] };
      case "unknown_principal": {
        const ids = [...new Set(items.map((f) => f.principal).filter((x) => x != null))];
        return { ...base, title: `${plural(n, "event")} not linked to a known customer`, impact: plural(n, "event"),
          what: ids.length ? `They belong to customer ${joinList(ids.map((i) => "#" + i))}, who has no customer record.` : "These rows carry no customer id, so their consent cannot be checked.",
          why: "Without a customer record, there is no way to show which consent or notice covered this processing.",
          fix: ["Find the missing customer record, or remove the orphaned rows.", "Make sure every new row stores the customer id."] };
      }
      case "inventory_drift": {
        const tables = [...new Set(items.map((f) => f.table))];
        return { ...base, title: `${plural(n, "difference")} between the ${joinList(tables)} table and the declared inventory`, impact: plural(n, "difference"),
          what: "Columns were renamed, removed or added without updating the declared data inventory.",
          why: "The notice and inventory must describe the personal data actually held. Undeclared columns are personal data nobody was told about.",
          fix: ["Update the declared inventory under Rules → Data inventory.", "If consent columns were renamed, update Rules → Consent fields so checks keep working."] };
      }
      default: return { ...base, title: rule.name, impact: plural(n, "finding"), what: "", why: "", fix: [] };
    }
  }
  function issueList() {
    const all = C.result?.findings || [];
    return P().rules.filter((r) => r.enabled).map((rule) => ({ rule, items: all.filter((f) => f.rule === rule.id) }))
      .filter((x) => x.items.length)
      .map((x) => ({ ...x, ...explain(x.rule, x.items) }))
      .sort((a, b) => SEV.indexOf(a.rule.severity) - SEV.indexOf(b.rule.severity) || b.items.length - a.items.length);
  }

  /* ---------------- Render: shell ---------------- */
  const sevPill = (s) => `<span class="sev sev-${esc(s)}">${esc(cap(s))}</span>`;
  const purposeName = (id) => P().purposes.find((p) => p.id === id)?.name || "No purpose";
  const check = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>`;

  function render() {
    renderMeta();
    const body = $("cpBody");
    if (C.error === "offline") {
      body.innerHTML = `<div class="panel cp-empty"><h3>The consent service isn't running</h3><p>Start it from the project folder, then click Check now.</p><pre class="logline">python3 consent_service/server.py</pre></div>`;
      $("cpIssueCount").textContent = "–"; renderDraftBar(); return;
    }
    if (C.error && !C.result) { body.innerHTML = `<div class="panel cp-empty"><h3>Could not load consent data</h3><p>${esc(C.error)}</p></div>`; return; }
    if (!C.result) { body.innerHTML = `<div class="panel cp-empty"><p>Checking consent…</p></div>`; return; }
    document.querySelectorAll("#cpTabs [data-tab]").forEach((b) => { const on = b.dataset.tab === C.tab; b.classList.toggle("on", on); b.setAttribute("aria-selected", on); });
    $("cpIssueCount").textContent = num(issueList().length);
    const errs = C.data?.loadErrors || [];
    const banner = errs.length ? `<div class="cp-warn" role="alert"><b>Some data could not be refreshed, so results may be incomplete.</b>
      <span>${errs.map((e) => `${esc(e.label)}: ${e.stale ? "showing the last loaded data" : "not loaded"}`).join(" · ")}. Click Check now to retry.</span></div>` : "";
    body.innerHTML = banner + { overview: overviewHtml, customers: customersHtml, issues: issuesHtml, rules: rulesHtml }[C.tab]();
    if (C.tab === "rules") body.querySelectorAll(".cp-redit").forEach(updatePreview);
    renderDraftBar();
    if (C.sheet) renderSheet();
  }
  function renderMeta() {
    const m = $("cpMeta"); if (!m) return;
    const p = C.policy;
    m.textContent = C.busy ? "Checking…" : p ? `Checked ${C.loadedAt ? up(F_TIME.format(C.loadedAt)) + " IST" : "–"} · Policy v${p.version}` : "";
    if (p) m.title = `Policy v${p.version} saved ${ist(p.updated_at)} by ${p.updated_by}`;
  }

  /* ---------------- Overview ---------------- */
  function overviewHtml() {
    const cov = C.result.coverage, issues = issueList(), g = C.result.gate;
    const by = (...st) => cov.filter((c) => st.includes(c.status));
    const ids = (l) => (l.length && l.length <= 6 ? ` — ${l.map((c) => "#" + c.id).join(", ")}` : "");
    const seg = (n, cls) => (n ? `<span class="cp-seg ${cls}" style="flex:${n}"></span>` : "");
    const sevCount = SEV.map((s) => [s, issues.filter((i) => i.rule.severity === s).length]).filter(([, n]) => n);
    const passing = P().rules.filter((r) => r.enabled && !C.result.findings.some((f) => f.rule === r.id));
    const flagged = new Set(C.result.findings.filter((f) => f.event).map((f) => f.event.key)).size;
    const groups = [
      ["valid", by("valid"), "Accepted", "valid"],
      ["legacy", by("legacy"), "Existing accounts · re-accept at next sign-in", "legacy"],
      ["legacy_active", by("legacy_active"), "Existing · active without re-accepting", "none"],
      ["unsaved", by("unsaved"), "Acceptance not saved", "partial"],
      ["stale", by("stale"), "Old notice version", "partial"],
      ["gate_failure", by("gate_failure", "none"), g ? "Signed up without accepting" : "Never accepted", "none"],
    ].filter(([, l]) => l.length);
    const attention = cov.filter(ACTION).length;
    const lag = g?.medianLagMs == null ? "" : g.medianLagMs < 60000 ? `within ${Math.max(1, Math.round(g.medianLagMs / 1000))} s` : `within ${Math.round(g.medianLagMs / 60000)} min`;
    const gateCard = g ? `<div class="panel cp-gate ${g.failures ? "bad" : "ok"}">
        <div class="cp-gate-h"><span class="cp-label">Sign-up gate</span><span class="cp-gate-badge">${g.failures ? `${num(g.failures)} failed` : "Working"}</span></div>
        <b class="cp-big">${num(g.accepted)}<small> / ${num(g.after)}</small></b>
        <span>new accounts since <b>${esc(istShort(g.since))} IST</b> accepted the ${esc(joinList(g.notices))} at sign-up${lag ? `, ${lag}` : ""}.</span>
        <small class="muted">Acceptance is mandatory on the website. ${num(g.existing)} account${g.existing === 1 ? "" : "s"} existed before, and are asked at their next sign-in.</small>
        <button class="link" data-act="open-notices">Mandatory since… (edit)</button>
      </div>` : "";
    return `
      <div class="cp-health${g ? " with-gate" : ""}">
        <div class="panel cp-hcard">
          <div class="cp-hhead"><b>${num(by("valid").length)} of ${num(cov.length)}</b><span>customers have accepted${g ? "; " + (attention ? `<b class="cp-red">${num(attention)}</b> need action` : "nobody needs action") : ""}</span></div>
          <div class="cp-hbar" role="img" aria-label="${groups.map(([, l, t]) => `${l.length} ${t}`).join(", ")}">${groups.map(([, l, , cls]) => seg(l.length, cls)).join("")}</div>
          <div class="cp-hlegend">${groups.map(([k, l, t, cls]) => `<button data-cust-filter="${k === "legacy_active" ? "legacy" : k === "gate_failure" ? (g ? "gate_failure" : "action") : k}"><i class="cp-dot ${cls}"></i><b>${num(l.length)}</b> ${esc(t)}${esc(ids(l))}</button>`).join("")}</div>
        </div>
        ${gateCard}
        <div class="panel cp-hside">
          <span class="cp-label">Open issues</span>
          <b class="cp-big">${num(issues.length)}</b>
          <span>${sevCount.map(([s, n]) => `${n} ${s}`).join(" · ") || "None"}${flagged ? ` · from ${plural(flagged, "flagged event")}` : ""}</span>
          ${passing.length ? `<span class="cp-pass">${check}${plural(passing.length, "check")} passing</span>` : ""}
        </div>
      </div>
      <section class="panel cp-list" aria-labelledby="cpAttn">
        <div class="cp-list-head"><h3 id="cpAttn">What needs attention</h3>${issues.length ? `<button class="link" data-goto="issues">See all issues</button>` : ""}</div>
        ${issues.length ? issues.map((i) => `
          <article class="cp-issue">
            ${sevPill(i.rule.severity)}
            <div class="cp-issue-main">
              <h4>${esc(i.title)}</h4>
              <p>${esc(i.what)}</p>
              <p class="cp-fix"><b>Fix:</b> ${esc(i.fix[0] || "")}</p>
            </div>
            <div class="cp-issue-meta"><b>${esc(i.impact)}</b><span>${esc(i.rule.dpdp_ref)}</span></div>
            <button class="btn ghost" data-issue="${esc(i.rule.id)}">Review</button>
          </article>`).join("") : `<div class="cp-allgood">${check}<div><b>All checks pass.</b><p>Every processing event has consent and a declared purpose under the current rules.</p></div></div>`}
        ${passing.length && issues.length ? `<div class="cp-passing"><b>Passing</b>${passing.map((r) => `<span>${check}${esc(passLabel(r))}</span>`).join("")}</div>` : ""}
      </section>`;
  }
  function passLabel(r) {
    return { opt_in_required: "Opt-in purposes only reach customers who opted in", after_erasure: "No processing after an erasure request", undeclared_purpose: "Every event has a declared purpose", before_consent: "No processing before consent", notice_required: "Every customer accepted the notice", notice_outdated: "Everyone is on the current notice", unknown_principal: "Every event belongs to a known customer", inventory_drift: "Consent records match the declared inventory", signup_gate: "Every account created since go-live accepted at sign-up", legacy_reacceptance: "Every existing account has accepted" }[r.type] || r.name;
  }

  /* ---------------- Customers ---------------- */
  const STATUS = {
    valid: ["Accepted", "ok", "Accepted every required notice, current version"],
    legacy: ["Existing account · re-accept at next sign-in", "info", "Signed up before acceptance became mandatory; hasn't used the shop since"],
    legacy_active: ["Existing account · active without re-accepting", "bad", "Signed up before acceptance became mandatory and has been processed since, without accepting"],
    unsaved: ["Acceptance not saved", "warn", "Accepted one notice, but a mandatory one has no record: the website didn't save it"],
    stale: ["Needs re-consent (new version)", "warn", "Accepted an older version of a notice"],
    gate_failure: ["Signed up without accepting", "bad", "Created after acceptance became mandatory, but nothing is recorded: a website bug"],
    none: ["Never accepted the notice", "bad", "No acceptance on record"],
  };
  const ACTION = (c) => c.status !== "valid" && c.status !== "legacy";
  const STATUS_FILTERS = [["all", "All"], ["action", "Needs action"], ["legacy", "Existing · to re-accept"], ["unsaved", "Not saved"], ["stale", "Old version"], ["gate_failure", "Sign-up gate failed"], ["valid", "Accepted"]];
  const lookupLike = (q) => /@/.test(q) || q.replace(/\D/g, "").length >= 10;
  // Customers after status, issue, search and lookup filters, in the chosen order.
  function custFiltered() {
    const cov = C.result.coverage;
    const q = C.custQuery.trim().replace(/^#/, "");
    const idSearch = /^\d{1,9}$/.test(q) && !C.lookup;
    const lookupIds = C.lookup ? new Set(C.lookup.ids) : null;
    const list = cov.filter((c) =>
      (C.custFilter === "all" || (C.custFilter === "action" ? ACTION(c) : C.custFilter === "legacy" ? c.status === "legacy" || c.status === "legacy_active" : C.custFilter === c.status)) &&
      (!C.custRule || c.rules.includes(C.custRule)) &&
      (!lookupIds || lookupIds.has(c.id)) &&
      (!idSearch || c.id.startsWith(q)));
    const by = {
      issues: (a, b) => b.findings - a.findings || Number(a.id) - Number(b.id),
      id: (a, b) => Number(a.id) - Number(b.id),
      recent: (a, b) => String(b.lastAt).localeCompare(String(a.lastAt)) || Number(a.id) - Number(b.id),
    }[C.custSort];
    return list.sort(by);
  }
  function customersHtml() {
    const cov = C.result.coverage;
    if (C.custView === "detail") {
      const sel = cov.find((c) => c.id === C.sel.customer);
      if (sel) {
        const list = custFiltered(), i = list.findIndex((c) => c.id === sel.id);
        const prev = i > 0 ? list[i - 1] : null, next = i >= 0 && i < list.length - 1 ? list[i + 1] : null;
        return `<div class="cp-crumbs">
            <button class="link" data-act="cust-back">← All customers</button>
            ${i >= 0 ? `<span class="cp-pager"><span>${num(i + 1)} of ${num(list.length)}</span>
              <button class="btn ghost sm" data-cust="${prev ? esc(prev.id) : ""}" ${prev ? "" : "disabled"} aria-label="Previous customer">Previous</button>
              <button class="btn ghost sm" data-cust="${next ? esc(next.id) : ""}" ${next ? "" : "disabled"} aria-label="Next customer">Next</button></span>` : ""}
          </div>${customerDetail(sel)}`;
      }
      C.custView = "list";
    }
    const counts = { all: cov.length, action: cov.filter(ACTION).length, legacy: cov.filter((c) => c.status === "legacy" || c.status === "legacy_active").length };
    for (const st of ["unsaved", "stale", "gate_failure", "valid"]) counts[st] = cov.filter((c) => c.status === st).length;
    const list = custFiltered();
    const pages = Math.max(1, Math.ceil(list.length / C.custPageSize));
    C.custPage = Math.min(C.custPage, pages - 1);
    const start = C.custPage * C.custPageSize, page = list.slice(start, start + C.custPageSize);
    const rulesWithHits = P().rules.filter((r) => r.enabled && C.result.findings.some((f) => f.rule === r.id && f.principal != null));
    const q = C.custQuery.trim();
    const optIn = P().purposes.find((p) => p.legal_basis === "consent" && p.consent_type === "opt_in");
    const notice = (c, n) => { const x = c.notices.find((y) => y.notice.id === n.id); return x?.version ? `<span class="cp-ver ${x.version === n.current_version ? "ok" : "old"}">${esc(x.version)}</span>`
      : c.status === "unsaved" && n.capture === "mandatory_signup" ? `<span class="cp-red">Not saved</span>` : c.origin === "before" || c.origin === "unknown" ? `<span class="muted">Not yet (existing)</span>` : `<span class="muted">Not accepted</span>`; };
    const optCell = (c) => { const o = c.optIns.find((x) => x.purpose.id === optIn?.id); return !o ? "—" : o.value === true ? "Opted in" : o.value === false ? "Declined" : `<span class="muted">Not recorded</span>`; };
    const hint = C.lookup
      ? `<div class="cp-lookup">${plural(C.lookup.ids.length, "customer")} ${C.lookup.ids.length === 1 ? "matches" : "match"} that ${esc(C.lookup.kind)} <button class="link" data-act="clear-lookup">Clear</button></div>`
      : q && lookupLike(q) ? `<div class="cp-lookup muted">Press Enter or Search to look up this ${/@/.test(q) ? "email" : "phone number"}.</div>`
      : q && !/^#?\d{1,9}$/.test(q) ? `<div class="cp-lookup muted">Type a customer number, a full email address, or a phone number with at least 10 digits.</div>` : "";
    return `<section class="panel cp-cpanel" aria-label="Customers">
      <div class="cp-ctools">
        <form class="cp-search" data-lookup-form role="search">
          <label for="cpCustQ" class="sr-only">Search customers</label>
          <input id="cpCustQ" type="search" placeholder="Customer number, email or phone" value="${esc(C.custQuery)}" data-cust-q autocomplete="off">
          <button type="submit" class="btn primary" ${C.lookupBusy ? "disabled" : ""}>${C.lookupBusy ? "Searching…" : "Search"}</button>
        </form>
        <label class="cp-select"><span>Issue</span><select data-cust-rule>
          <option value="">Any</option>${rulesWithHits.map((r) => `<option value="${esc(r.id)}" ${C.custRule === r.id ? "selected" : ""}>${esc(TEMPLATES[r.type]?.short || r.name)}</option>`).join("")}
        </select></label>
        <label class="cp-select"><span>Sort</span><select data-cust-sort>
          <option value="issues" ${C.custSort === "issues" ? "selected" : ""}>Most issues</option>
          <option value="recent" ${C.custSort === "recent" ? "selected" : ""}>Latest activity</option>
          <option value="id" ${C.custSort === "id" ? "selected" : ""}>Customer number</option>
        </select></label>
      </div>
      <div class="cp-chips" role="group" aria-label="Consent status">${STATUS_FILTERS.filter(([k]) => counts[k] || k === "all" || k === "action" || k === C.custFilter).map(([k, l]) => `<button class="cp-chip${C.custFilter === k ? " on" : ""}" data-cust-filter="${k}" aria-pressed="${C.custFilter === k}">${l} · ${num(counts[k])}</button>`).join("")}</div>
      ${hint}
      <div class="cp-tablewrap"><table class="cp-ctable">
        <thead><tr><th>Customer</th><th>Consent</th><th>Account</th>${P().notices.map((n) => `<th>${esc(n.name)}</th>`).join("")}${optIn ? `<th>${esc(optIn.name)}</th>` : ""}<th class="num">Issues</th><th>Last activity (IST)</th></tr></thead>
        <tbody>${page.length ? page.map((c) => `
          <tr data-cust="${esc(c.id)}">
            <td><button class="link strong" data-cust="${esc(c.id)}">Customer #${esc(c.id)}</button></td>
            <td><span class="cp-status ${STATUS[c.status][1]}" title="${esc(STATUS[c.status][2])}">${STATUS[c.status][0]}</span></td>
            <td class="nowrap">${originCell(c)}</td>
            ${P().notices.map((n) => `<td>${notice(c, n)}</td>`).join("")}
            ${optIn ? `<td>${optCell(c)}</td>` : ""}
            <td class="num">${c.findings ? `<b class="cp-red">${num(c.findings)}</b>` : "—"}</td>
            <td class="nowrap">${c.lastAt ? esc(istShort(c.lastAt)) : "—"}</td>
          </tr>`).join("") : `<tr><td colspan="9" class="cp-none">No customers match these filters.</td></tr>`}</tbody>
      </table></div>
      <div class="cp-cfoot">
        <span>${list.length ? `Showing ${num(start + 1)}–${num(start + page.length)} of ${num(list.length)}` : "0 customers"}</span>
        <div class="cp-pager">
          <label class="cp-select"><span>Per page</span><select data-cust-size>${[25, 50, 100].map((n) => `<option ${C.custPageSize === n ? "selected" : ""}>${n}</option>`).join("")}</select></label>
          <button class="btn ghost sm" data-page="prev" ${C.custPage === 0 ? "disabled" : ""}>Previous</button>
          <span>Page ${num(C.custPage + 1)} of ${num(pages)}</span>
          <button class="btn ghost sm" data-page="next" ${C.custPage >= pages - 1 ? "disabled" : ""}>Next</button>
        </div>
      </div>
    </section>`;
  }
  function originCell(c) {
    if (c.origin === "n/a") return `<span class="muted">—</span>`;
    const when = c.signupAt ? istShort(c.signupAt).replace(/,.*$/, "") : "date unknown";
    return c.origin === "after" ? `<span class="cp-origin new" title="Signed up ${esc(ist(c.signupAt))} (${esc(c.signupHow)}): after acceptance became mandatory">New · ${esc(when)}</span>`
      : `<span class="cp-origin old" title="${c.signupAt ? `Signed up ${esc(ist(c.signupAt))} (${esc(c.signupHow)})` : "No sign-up date or activity on record"}: before acceptance became mandatory">Existing · ${esc(when)}</span>`;
  }
  async function runLookup() {
    const q = C.custQuery.trim();
    if (!q) { C.lookup = null; return render(); }
    if (/^#?\d{1,9}$/.test(q)) return render(); // customer number: filtered locally
    if (!lookupLike(q)) { toast("Type a customer number, a full email address, or a phone number with at least 10 digits."); return; }
    C.lookupBusy = true; render();
    try {
      const r = await api(`/api/customers/lookup?q=${encodeURIComponent(q)}`);
      C.lookup = r; C.custFilter = "all"; C.custPage = 0;
      if (r.ids.length === 1) { C.sel.customer = r.ids[0]; C.custView = "detail"; C.showAllTimeline = false; }
    } catch (e) { toast(e.message); }
    finally { C.lookupBusy = false; render(); }
  }
  function customerDetail(c) {
    const [label, tone] = STATUS[c.status];
    const flaggedEvents = new Set(C.result.findings.filter((f) => f.principal === c.id && f.event).map((f) => f.event.key)).size;
    const card = (title, value, sub, cls = "") => `<div class="cp-ccard ${cls}"><span>${esc(title)}</span><b>${esc(value)}</b><small>${esc(sub)}</small></div>`;
    const g = C.result.gate;
    const cards = [
      ...(g ? [card("Account", c.origin === "after" ? "New account" : "Existing account", c.signupAt ? `Signed up ${ist(c.signupAt)}${c.signupHow.includes("estimate") ? " (estimated)" : ""} · ${c.origin === "after" ? "after" : "before"} acceptance became mandatory (${istShort(g.since)})` : "No sign-up date or activity on record", c.origin === "after" ? "ok" : "")] : []),
      ...c.notices.map(({ notice, version, at }) => version === notice.current_version
        ? card(notice.name, `Accepted ${version}`, at ? ist(at) : "Current version", "ok")
        : version ? card(notice.name, `Accepted ${version}`, `Current version is ${notice.current_version}`, "warn")
        : c.status === "unsaved" && notice.capture === "mandatory_signup" ? card(notice.name, "Not saved", "Mandatory, so it was accepted, but the record is missing", "warn")
        : notice.capture === "mandatory_signup" && c.origin !== "after" ? card(notice.name, "Not yet accepted", "Existing account: show it at the next sign-in", "")
        : card(notice.name, "Not accepted", `Current version ${notice.current_version}`, notice.required ? "warn" : "")),
      ...c.optIns.map(({ purpose, value }) => card(purpose.name, value === true ? "Opted in" : value === false ? "Declined" : "Not recorded", "Separate opt-in", value === true ? "ok" : "")),
      c.erasedAt ? card("Erasure", "Erased", ist(c.erasedAt), "") : c.erasureAt ? card("Erasure", "Requested", ist(c.erasureAt), "warn") : card("Erasure", "Not requested", "—"),
    ];
    return `<section class="cp-detail" aria-labelledby="cpCustTitle">
      <div class="panel cp-dhead">
        <div class="cp-dtitle">
          <div><div class="cp-titlerow"><h2 id="cpCustTitle">Customer #${esc(c.id)}</h2><span class="cp-pill ${tone}" title="${esc(STATUS[c.status][2])}">${label}</span></div>
          <p>${c.findings ? `${plural(c.findings, "issue")} across ${plural(flaggedEvents, "event")}` : "No issues"} · ${plural(c.events, "processing event")}</p></div>
          ${c.findings ? `<button class="btn ghost" data-act="csv-customer">Export evidence</button>` : ""}
        </div>
        <div class="cp-ccards">${cards.join("")}</div>
      </div>
      ${timelineHtml(c)}
    </section>`;
  }
  function timelineHtml(c) {
    const items = [];
    for (const e of C.result.events.filter((e) => e.principal === c.id)) items.push({ at: e.at, kind: "proc", e, rules: C.result.byEvent.get(e.key) || [] });
    const optIn = c.optIns.filter((o) => o.value === true).map((o) => `opted in to ${o.purpose.name.toLowerCase()}`);
    for (const n of c.notices) if (n.at && n.version) items.push({ at: n.at, kind: "consent", title: `Accepted ${n.notice.name} ${n.version}`, detail: n.notice.field === "notice_version" && optIn.length ? cap(joinList(optIn)) : "" });
    if (c.updatedAt && c.updatedAt !== c.consentedAt) items.push({ at: c.updatedAt, kind: "consent", title: "Consent choices updated", detail: "" });
    if (c.signupAt && !c.signupHow.includes("estimate")) items.push({ at: c.signupAt, kind: "consent", title: "Account created", detail: c.origin === "after" ? "After acceptance became mandatory" : "Before acceptance became mandatory" });
    if (C.result.gate && c.origin !== "after") items.push({ at: C.result.gate.since, kind: "erasure", title: "Acceptance became mandatory at sign-up", detail: `For ${joinList(C.result.gate.notices)}` });
    if (c.erasureAt) items.push({ at: c.erasureAt, kind: "erasure", title: "Asked for erasure", detail: "" });
    if (c.erasedAt) items.push({ at: c.erasedAt, kind: "erasure", title: "Data erased", detail: "" });
    const dated = items.filter((i) => i.at).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    if (!dated.length) return `<div class="panel cp-empty"><p>No consent or processing events for this customer.</p></div>`;

    // Group processing events by minute; consent events stand alone.
    const groups = [];
    for (const it of dated) {
      const minute = hm(it.at), day = F_KEY.format(new Date(it.at));
      const g = groups[groups.length - 1];
      if (it.kind === "proc" && g && g.kind === "proc" && g.minute === minute && g.day === day) g.items.push(it);
      else groups.push({ kind: it.kind, minute, day, at: it.at, items: [it], title: it.title, detail: it.detail });
    }
    const limit = 10, shown = C.showAllTimeline ? groups : groups.slice(0, limit);
    const hiddenEvents = groups.slice(shown.length).reduce((n, g) => n + (g.kind === "proc" ? g.items.length : 1), 0);
    let lastDay = "", html = "";
    for (const g of shown) {
      if (g.day !== lastDay) { html += `<div class="cp-tday">${esc(F_DAY.format(new Date(g.at)))}</div>`; lastDay = g.day; }
      if (g.kind !== "proc") {
        html += tlItem(g.minute, g.kind === "consent" ? "consent" : "erasure", g.title, g.detail, "");
        continue;
      }
      const byAct = new Map();
      for (const it of g.items) byAct.set(it.e.activity.name, [...(byAct.get(it.e.activity.name) || []), it.e]);
      const order = P().activities.map((a) => a.name);
      const parts = [...byAct.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0])).map(([name, es]) => (es.length === 1 ? `${singular(name)} #${es[0].rowId}` : `${es.length} ${name.toLowerCase()}`));
      const rules = [...new Set(g.items.flatMap((it) => it.rules))].map((id) => P().rules.find((r) => r.id === id)).filter(Boolean);
      const purposes = [...new Set(g.items.map((it) => purposeName(it.e.purpose)))];
      const flags = [...new Set(rules.map((r) => TEMPLATES[r.type]?.short || r.name))];
      html += tlItem(g.minute, rules.length ? "flagged" : "proc", cap(joinList(parts)), purposes.join(", "), flags.map((f) => `<span class="cp-flag">${esc(f)}</span>`).join(""));
    }
    return `<div class="panel cp-timeline">
      <div class="cp-list-head"><h3>Consent and processing timeline</h3>
        <div class="cp-tlegend"><span><i class="cp-dot consent"></i>Consent</span><span><i class="cp-dot flagged"></i>Flagged processing</span><span><i class="cp-dot proc"></i>Processing</span></div></div>
      <div class="cp-tbody">${html}
        ${hiddenEvents ? `<button class="btn ghost cp-tmore" data-act="timeline-more">Show ${plural(hiddenEvents, "earlier event")}</button>` : C.showAllTimeline && groups.length > limit ? `<button class="btn ghost cp-tmore" data-act="timeline-less">Show fewer</button>` : ""}
      </div></div>`;
  }
  const tlItem = (time, kind, title, detail, flags) => `
    <div class="cp-titem ${kind}">
      <span class="cp-ttime">${esc(time)}</span>
      <span class="cp-tline"><i></i></span>
      <div class="cp-tcontent"><b>${esc(title)}</b>${detail ? `<span>${esc(detail)}</span>` : ""}${flags ? `<div class="cp-flags">${flags}</div>` : ""}</div>
    </div>`;

  /* ---------------- Issues ---------------- */
  function issuesHtml() {
    const issues = issueList();
    if (!issues.length) return `<div class="panel cp-allgood big">${check}<div><b>No open issues.</b><p>Every processing event has consent and a declared purpose under the current rules.</p></div></div>`;
    if (!issues.some((i) => i.rule.id === C.sel.issue)) C.sel.issue = issues[0].rule.id;
    const cur = issues.find((i) => i.rule.id === C.sel.issue);
    return `<div class="cp-split">
      <section class="panel cp-side-list" aria-label="Issues">
        ${issues.map((i) => `
          <button class="cp-row issue${i.rule.id === C.sel.issue ? " on" : ""}" data-issue="${esc(i.rule.id)}" aria-pressed="${i.rule.id === C.sel.issue}">
            ${sevPill(i.rule.severity)}
            <span class="cp-row-main"><b>${esc(i.title)}</b><span>${esc(i.impact)}</span></span>
          </button>`).join("")}
      </section>
      ${issueDetail(cur)}
    </div>`;
  }
  function issueDetail(i) {
    const items = i.items, isDrift = i.rule.type === "inventory_drift";
    const purposes = new Map();
    for (const f of items) if (f.event) purposes.set(purposeName(f.purpose), (purposes.get(purposeName(f.purpose)) || 0) + 1);
    const pmax = Math.max(1, ...purposes.values());
    const rows = items.slice(0, C.evidenceLimit);
    const gap = (ms) => { const m = Math.round(ms / 60000); return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`; };
    const stat = (label, value) => `<div class="cp-stat"><span>${esc(label)}</span><b>${esc(value)}</b></div>`;
    return `<article class="panel cp-idetail" aria-labelledby="cpIssueTitle">
      <div class="cp-ihead">
        <div class="cp-titlerow">${sevPill(i.rule.severity)}<span class="cp-ref">Rule ${esc(i.rule.id)} · ${esc(i.rule.dpdp_ref)}</span><button class="btn ghost sm ai-ask" data-ask-ai="consent:${esc(i.rule.id)}">✦ Ask AI</button></div>
        <h2 id="cpIssueTitle">${esc(i.title)}</h2>
      </div>
      <div class="cp-stats">
        ${stat(isDrift ? "Differences" : "Events affected", num(items.length))}
        ${i.customers.length ? stat("Customers", i.customers.length <= 5 ? i.customers.map((x) => "#" + x).join(", ") : `${i.customers.slice(0, 3).map((x) => "#" + x).join(", ")} and ${num(i.customers.length - 3)} more`) : ""}
        ${i.first ? stat(i.first === i.last ? "When" : "Between", i.first === i.last ? ist(i.first) : `${istShort(i.first)} – ${istShort(i.last)}`) : ""}
      </div>
      <div class="cp-whywhat">
        <div><h3>What happened</h3><p>${esc(i.what)}</p></div>
        <div><h3>Why it matters</h3><p>${esc(i.why)}</p></div>
      </div>
      <div><h3>How to fix</h3><ol class="cp-steps">${i.fix.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
      ${purposes.size ? `<div><h3>By purpose</h3><div class="cp-bars">${[...purposes.entries()].sort((a, b) => b[1] - a[1]).map(([name, n]) => `
        <div class="cp-barrow"><span>${esc(name)}</span><span class="cp-bar"><i style="width:${(n / pmax) * 100}%"></i></span><b>${num(n)}</b></div>`).join("")}</div></div>` : ""}
      <div>
        <div class="cp-list-head flat"><h3>Evidence</h3><button class="btn ghost" data-act="csv-issue">Export CSV</button></div>
        <div class="cp-tablewrap"><table class="cp-evidence">
          <thead><tr>${isDrift ? "<th>Table</th><th>Difference</th>" : `<th>Time (IST)</th><th>Customer</th><th>Event</th><th>Purpose</th><th>${i.rule.type === "before_consent" ? "Before consent by" : "Detail"}</th>`}</tr></thead>
          <tbody>${rows.map((f) => isDrift
            ? `<tr><td><code>${esc(f.table)}</code></td><td>${esc(f.detail)}</td></tr>`
            : `<tr><td class="nowrap">${f.at ? esc(istShort(f.at)) : "—"}</td><td class="nowrap">${f.principal != null ? `<button class="link" data-cust-go="${esc(f.principal)}">#${esc(f.principal)}</button>` : "—"}</td>
               <td class="nowrap">${f.event ? `${esc(singular(f.event.activity.name))} #${esc(f.event.rowId)}` : "—"}</td><td>${esc(f.event ? purposeName(f.purpose) : "—")}</td>
               <td>${i.rule.type === "before_consent" && f.gapMs ? `<span class="cp-red">${esc(gap(f.gapMs))}</span>` : esc(f.detail)}</td></tr>`).join("")}</tbody>
        </table></div>
        <div class="cp-efoot">
          <span>${[
            items.length > 25 ? `Showing ${num(rows.length)} of ${num(items.length)}` : "",
            rows.length < items.length ? `<button class="link" data-act="evidence-more">Show ${num(Math.min(25, items.length - rows.length))} more</button>` : "",
            rows.length > 25 ? `<button class="link" data-act="evidence-less">Show fewer</button>` : "",
          ].filter(Boolean).join(" · ")}</span>
          <span>From rule ${esc(i.rule.id)} · <button class="link" data-edit-rule="${esc(i.rule.id)}">Edit this rule</button></span>
        </div>
      </div>
    </article>`;
  }

  /* ---------------- Rules ---------------- */
  function sentence(r, edit) {
    const p = r.params || {}, pol = P();
    const tok = (s) => `<span class="cp-tok">${esc(s)}</span>`;
    const noticeSel = () => (edit
      ? `<select name="notice" aria-label="Notice">${pol.notices.map((n) => `<option value="${esc(n.id)}" ${n.id === p.notice ? "selected" : ""}>${esc(n.name)}</option>`).join("")}</select>`
      : tok(pol.notices.find((n) => n.id === p.notice)?.name || "a notice"));
    const secs = () => (edit ? `<input name="grace_seconds" type="number" min="0" step="1" value="${esc(p.grace_seconds ?? 0)}" aria-label="Grace period in seconds"> seconds` : tok(`${num(p.grace_seconds || 0)} seconds`));
    switch (r.type) {
      case "notice_required": return `Flag any processing for a customer who hasn’t accepted the ${noticeSel()}.`;
      case "before_consent": return `Flag processing that happens before the customer gives consent, allowing ${secs()} of grace.`;
      case "opt_in_required": { const ns = pol.purposes.filter((x) => x.legal_basis === "consent" && x.consent_type === "opt_in").map((x) => tok(x.name)); return `Flag processing for an opt-in purpose (${ns.join(", ") || "none declared"}) when the customer hasn’t opted in.`; }
      case "notice_outdated": { const n = pol.notices.find((x) => x.id === p.notice); return `Flag customers whose accepted version of the ${noticeSel()} isn’t the current one${!edit && n ? ` (${tok(n.current_version)})` : ""}.`; }
      case "after_erasure": return `Flag processing after a customer asks for erasure, allowing ${secs()} of grace.`;
      case "undeclared_purpose": return "Flag processing that matches none of the declared purposes.";
      case "unknown_principal": return "Flag processing that can’t be linked to a customer record.";
      case "inventory_drift": { const t = [].concat(p.tables || []); return `Flag differences between ${edit ? `<input name="tables" type="text" value="${esc(t.join(", "))}" aria-label="Tables, comma-separated">` : t.map(tok).join(", ") || "no tables"} and the declared data inventory.`; }
      default: return esc(r.name);
    }
  }
  function rulesHtml() {
    const pol = P(), all = C.result?.findings || [];
    const rows = pol.rules.map((r, i) => ({ r, i }));
    const group = (g) => {
      const list = rows.filter(({ r }) => (TEMPLATES[r.type]?.group || "Records") === g);
      const fresh = C.newRule && (TEMPLATES[C.newRule.type]?.group || "Records") === g ? [C.newRule] : [];
      if (!list.length && !fresh.length) return "";
      return `<div class="panel cp-rgroup"><h3>${g}</h3>
        ${fresh.map((r) => `<div class="cp-rule editing new">${ruleForm(r, true)}</div>`).join("")}
        ${list.map(({ r, i }) => {
          const n = all.filter((f) => f.rule === r.id).length;
          const status = !r.enabled ? `<span class="cp-rcount off">Off</span>` : n ? `<span class="cp-rcount bad">${num(n)} found</span>` : `<span class="cp-rcount ok">Passing</span>`;
          return `<div class="cp-rule${r.enabled ? "" : " off"}${C.editRule === r.id ? " editing" : ""}">
            <div class="cp-rrow">
              <button class="cp-switch" role="switch" aria-checked="${r.enabled}" aria-label="Rule ${esc(r.id)} ${r.enabled ? "on" : "off"}" data-toggle-rule="${i}"><i></i></button>
              <div class="cp-rtext"><p>${sentence(r, false)}</p><span>${esc(r.id)} · ${esc(r.name)} · ${esc(r.dpdp_ref)}</span></div>
              <div class="cp-rside">${sevPill(r.severity)}${status}<button class="btn ghost" data-edit-rule="${esc(r.id)}" ${C.editRule === r.id ? "disabled" : ""}>Edit</button></div>
            </div>
            ${C.editRule === r.id ? ruleForm(r, false) : ""}
          </div>`;
        }).join("")}
      </div>`;
    };
    const purposeHow = (p) => (p.legal_basis !== "consent" ? "Legitimate use" : p.consent_type === "opt_in" ? "Separate opt-in" : "Accepted at sign-up");
    const actPurpose = (a) => (a.type_column ? `By ${a.type_column}: ${Object.keys(a.type_map || {}).join(", ") || "not mapped"}` : purposeName(a.purpose));
    return `
      <div class="cp-rtop">
        <p>Policy <b>v${esc(C.policy.version)}</b>, saved ${esc(ist(C.policy.updated_at))} by ${esc(C.policy.updated_by)} · <button class="link" data-sheet="history">Version history</button></p>
        <div class="cp-rbtns">
          <button class="btn ghost" data-act="export">Export</button>
          <label class="btn ghost">Import<input type="file" accept="application/json" data-act="import" hidden></label>
          <button class="btn primary" data-act="pick-rule" ${C.newRule ? "disabled" : ""}>Add rule</button>
        </div>
      </div>
      ${C.picking ? `<div class="panel cp-picker"><div class="cp-list-head"><h3>What should the new rule check?</h3><button class="link" data-act="pick-cancel">Cancel</button></div>
        <div class="cp-pickgrid">${Object.entries(TEMPLATES).map(([k, t]) => `<button class="cp-pick" data-new-rule="${k}"><b>${esc(t.label)}</b><span>${esc(t.desc)}</span><small>${esc(t.group)}</small></button>`).join("")}</div></div>` : ""}
      <div class="cp-rlayout">
        <div class="cp-rmain">${GROUPS.map(group).join("")}</div>
        <aside class="cp-rside-col">
          <div class="panel cp-scard"><div class="cp-list-head flat"><h3>Purposes</h3><button class="link" data-sheet="purposes">Manage</button></div>
            ${pol.purposes.map((p) => `<div class="cp-kv"><span>${esc(p.name)}</span><span>${esc(purposeHow(p))}</span></div>`).join("")}</div>
          <div class="panel cp-scard"><div class="cp-list-head flat"><h3>What counts as processing</h3><button class="link" data-sheet="activities">Manage</button></div>
            ${pol.activities.map((a) => `<div class="cp-kv"><span>${esc(a.name)}</span><span>${esc(actPurpose(a))}</span></div>`).join("")}</div>
          <div class="panel cp-scard"><div class="cp-list-head flat"><h3>Current notices</h3><button class="link" data-sheet="notices">Manage</button></div>
            ${pol.notices.map((n) => `<div class="cp-kv"><span>${esc(n.name)}</span><code>${esc(n.current_version)}</code></div>`).join("")}</div>
          <div class="panel cp-scard"><h3>Advanced</h3>
            <button class="cp-adv" data-sheet="fields"><b>Consent fields</b><span>Which database columns hold each consent fact</span></button>
            <button class="cp-adv" data-sheet="inventory"><b>Data inventory</b><span>Declared columns, compared with the live database</span></button>
            <button class="cp-adv" data-sheet="history"><b>Version history</b><span>Every saved version; restore any of them</span></button>
          </div>
        </aside>
      </div>`;
  }
  function ruleForm(r, isNew) {
    return `<form class="cp-redit" data-rule="${esc(r.id)}" data-new="${isNew ? 1 : 0}">
      ${isNew ? `<p class="cp-newlabel">New rule · ${esc(TEMPLATES[r.type]?.label || r.type)}</p>` : ""}
      <p class="cp-sentence">${sentence(r, true)}</p>
      <div class="cp-rfields">
        <label class="field"><span>Name</span><input name="name" type="text" value="${esc(r.name)}" required></label>
        <label class="field"><span>Severity</span><select name="severity">${SEV.map((s) => `<option value="${s}" ${r.severity === s ? "selected" : ""}>${cap(s)}</option>`).join("")}</select></label>
        <label class="field wide"><span>DPDP reference</span><input name="dpdp_ref" type="text" value="${esc(r.dpdp_ref)}"></label>
      </div>
      <div class="cp-rfoot">
        <span class="cp-preview" aria-live="polite"></span>
        <div class="cp-rbtns">
          ${isNew ? "" : `<button type="button" class="btn ghost danger" data-act="delete-rule">Delete rule</button>`}
          <button type="button" class="btn ghost" data-act="cancel-rule">Cancel</button>
          <button type="submit" class="btn primary">Apply</button>
        </div>
      </div>
    </form>`;
  }
  function readRuleForm(form) {
    const isNew = form.dataset.new === "1";
    const base = isNew ? C.newRule : P().rules.find((r) => r.id === form.dataset.rule);
    const f = (n) => form.querySelector(`[name="${n}"]`);
    const params = { ...(base.params || {}) };
    if (f("notice")) params.notice = f("notice").value;
    if (f("grace_seconds")) params.grace_seconds = Math.max(0, Number(f("grace_seconds").value) || 0);
    if (f("tables")) params.tables = f("tables").value.split(",").map((s) => s.trim()).filter(Boolean);
    return { ...base, name: f("name").value.trim() || base.name, severity: f("severity").value, dpdp_ref: f("dpdp_ref").value.trim(), params, isNew };
  }
  function updatePreview(form) {
    if (!C.data) return;
    const rule = readRuleForm(form);
    const temp = clone(P());
    const { isNew, ...clean } = rule;
    const idx = temp.rules.findIndex((r) => r.id === clean.id);
    if (idx >= 0) temp.rules[idx] = { ...clean, enabled: true }; else temp.rules.push({ ...clean, enabled: true });
    const n = evaluate(temp, C.schema, C.data).findings.filter((x) => x.rule === clean.id).length;
    const unit = rule.type === "inventory_drift" ? "difference" : rule.type === "notice_outdated" ? "customer" : "event";
    form.querySelector(".cp-preview").textContent = n ? `With these settings: flags ${plural(n, unit)}` : "With these settings: nothing is flagged";
  }
  function applyRule(form) {
    const rule = readRuleForm(form);
    const { isNew, ...clean } = rule;
    if (!clean.name) { toast("Give the rule a name."); return; }
    C.editRule = null; C.newRule = null;
    edit((d) => { if (isNew) d.rules.push(clean); else d.rules[d.rules.findIndex((r) => r.id === clean.id)] = clean; });
  }

  /* ---------------- Manage sheet (purposes, sources, notices, fields, inventory, history) ---------------- */
  function openSheet(kind) {
    C.sheet = kind; renderSheet();
    const s = $("cpSheet"); if (!s.open) s.showModal();
  }
  function renderSheet() {
    if (!C.sheet || !P()) return;
    $("cpSheetTitle").textContent = SHEETS[C.sheet];
    $("cpSheetBody").innerHTML = { purposes: purposesHtml, activities: activitiesHtml, notices: noticesHtml, fields: fieldsHtml, inventory: inventoryHtml, history: historyHtml }[C.sheet]();
  }
  const sectionHead = (desc, addAct, addLabel) => `<div class="cp-phead"><p>${desc}</p>${addAct ? `<button class="btn primary" data-act="${addAct}">${addLabel}</button>` : ""}</div>`;
  const rowActions = (kind, i) => `<td class="cp-actions"><button class="btn ghost sm" data-act="edit-${kind}" data-i="${i}">Edit</button><button class="btn ghost sm danger" data-act="del-${kind}" data-i="${i}">Delete</button></td>`;
  function purposesHtml() {
    const pol = P();
    return sectionHead("Each purpose personal data is processed for, its legal basis and how consent is captured.", "add-purpose", "Add purpose") +
      `<div class="cp-tablewrap"><table class="cp-table"><thead><tr><th>Purpose</th><th>Legal basis</th><th>Consent</th><th>Used by</th><th></th></tr></thead><tbody>${pol.purposes.map((p, i) => {
        const used = pol.activities.filter((a) => a.purpose === p.id || Object.values(a.type_map || {}).includes(p.id)).map((a) => a.name);
        return `<tr><td><b>${esc(p.name)}</b><small>${esc(p.description || "")}</small></td>
          <td>${p.legal_basis === "consent" ? "Consent (s.6)" : "Legitimate use (s.7)"}</td>
          <td>${p.legal_basis !== "consent" ? "—" : p.consent_type === "opt_in" ? `Separate opt-in<small>${esc(FIELD_LABEL[p.consent_field] || p.consent_field)}</small>` : "Accepted at sign-up"}</td>
          <td>${used.length ? esc(used.join(", ")) : '<span class="muted">—</span>'}</td>${rowActions("purpose", i)}</tr>`;
      }).join("")}</tbody></table></div>`;
  }
  function activitiesHtml() {
    const pol = P();
    return sectionHead("Which shop tables count as processing, whose data each row is, and which purpose it serves.", "add-activity", "Add source") +
      `<div class="cp-tablewrap"><table class="cp-table"><thead><tr><th>Source</th><th>Table</th><th>Purpose</th><th>Rows</th><th></th></tr></thead><tbody>${pol.activities.map((a, i) => {
        const d = C.data?.activities[a.id];
        const purpose = a.type_column ? Object.entries(a.type_map || {}).map(([v, p]) => `<code>${esc(v)}</code> → ${esc(purposeName(p))}`).join("<br>") || '<span class="muted">not mapped</span>' : esc(purposeName(a.purpose));
        return `<tr><td><b>${esc(a.name)}</b></td>
          <td><code>${esc(a.table)}</code><small>customer: ${esc(a.principal_column)}${a.principal_via?.table ? ` (else ${esc(a.principal_via.column)} → ${esc(a.principal_via.table)})` : ""} · time: ${esc(a.time_column)}</small></td>
          <td>${purpose}</td><td>${d?.error ? `<span class="cp-tag warn" title="${esc(d.error)}">error</span>` : num(d?.rows?.length)}</td>${rowActions("activity", i)}</tr>`;
      }).join("")}</tbody></table></div>`;
  }
  function noticesHtml() {
    const pol = P();
    return sectionHead("The notices a customer accepts, how they're collected, and the version that is current. A notice that is mandatory at sign-up can't be skipped: accounts created after it went live must have it, and older accounts are asked at their next sign-in.", "add-notice", "Add notice") +
      `<div class="cp-tablewrap"><table class="cp-table"><thead><tr><th>Notice</th><th>How it's collected</th><th>Recorded in</th><th>Current version</th><th>Required</th><th></th></tr></thead><tbody>${pol.notices.map((n, i) => `
        <tr><td><b>${esc(n.name)}</b></td><td>${n.capture === "mandatory_signup" ? `<span class="cp-pill ok">Mandatory at sign-up</span><small>since ${esc(n.since ? ist(n.since) : "–")}</small>` : `<span class="muted">${esc(CAPTURE[n.capture] || "Asked after sign-up")}</span>`}</td>
        <td>${esc(FIELD_LABEL[n.field] || n.field)}<small><code>${esc([].concat(pol.field_map[n.field] || "not mapped").join(" · "))}</code></small></td>
        <td><code>${esc(n.current_version)}</code></td><td>${n.required ? "Yes" : "No"}</td>${rowActions("notice", i)}</tr>`).join("")}</tbody></table></div>`;
  }
  function fieldsHtml() {
    const pol = P(), cols = principalColumns();
    return sectionHead(`Where each consent fact lives in <code>${esc(pol.principal?.table || "customers")}</code>. Change these when columns are renamed.`) +
      `<div class="cp-fieldmap">${FIELD_KEYS.map((k) => `
        <label class="field"><span>${esc(FIELD_LABEL[k])}</span>
          <select data-fieldmap="${k}"><option value="">Not tracked</option>${cols.map((c) => `<option ${[].concat(pol.field_map[k] || [])[0] === c ? "selected" : ""}>${esc(c)}</option>`).join("")}${[].concat(pol.field_map[k] || [])[0] && !cols.includes([].concat(pol.field_map[k])[0]) ? `<option selected>${esc([].concat(pol.field_map[k])[0])} (missing)</option>` : ""}</select>
          ${[].concat(pol.field_map[k] || []).length > 1 ? `<small class="muted">Also read when empty: ${[].concat(pol.field_map[k]).slice(1).map((c) => `<code>${esc(c)}</code>`).join(", ")}</small>` : ""}
        </label>`).join("")}</div>`;
  }
  // datetime-local inputs in IST, stored as UTC ISO
  const toLocalIst = (iso) => new Date(new Date(iso).getTime() + 330 * 60000).toISOString().slice(0, 16);
  const fromLocalIst = (v) => new Date(new Date(v + ":00Z").getTime() - 330 * 60000).toISOString();
  function inventoryHtml() {
    const pol = P(), inv = pol.inventory || {};
    return sectionHead("Columns declared in the privacy notice and data inventory. The inventory-drift rule compares these with the live database.", "add-inventory", "Add table") +
      `<div class="cp-tablewrap"><table class="cp-table"><thead><tr><th>Table</th><th>Declared columns</th><th>Live database</th><th></th></tr></thead><tbody>${Object.entries(inv).map(([t, cols]) => {
        const live = (C.schema[t] || []).map((c) => c.name);
        const missing = cols.filter((c) => !live.includes(c)).length, extra = live.filter((c) => !cols.includes(c)).length;
        return `<tr><td><code>${esc(t)}</code></td><td class="cp-cols">${cols.map((c) => `<span class="cp-tag ${live.includes(c) ? "" : "warn"}">${esc(c)}</span>`).join(" ")}</td>
          <td>${missing || extra ? `<span class="cp-tag warn">${missing} missing · ${extra} undeclared</span>` : '<span class="cp-tag ok">Matches</span>'}</td>
          <td class="cp-actions"><button class="btn ghost sm" data-act="edit-inventory" data-t="${esc(t)}">Edit</button><button class="btn ghost sm danger" data-act="del-inventory" data-t="${esc(t)}">Delete</button></td></tr>`;
      }).join("")}</tbody></table></div>`;
  }
  function historyHtml() {
    if (!C.history) { loadHistory(); return `<p class="muted">Loading history…</p>`; }
    return sectionHead("Every saved change is kept. Restoring a version saves it as a new version, so nothing is lost.") +
      `<div class="cp-tablewrap"><table class="cp-table"><thead><tr><th>Version</th><th>Saved</th><th>By</th><th>Change</th><th></th></tr></thead><tbody>${C.history.map((h) => `
        <tr><td><b>v${h.version}</b>${h.version === C.policy.version ? ' <span class="cp-tag ok">Current</span>' : ""}</td><td class="nowrap">${esc(ist(h.updated_at))}</td><td>${esc(h.updated_by)}</td><td>${esc(h.change_note)}</td>
        <td class="cp-actions">${h.version === C.policy.version ? "" : `<button class="btn ghost sm" data-act="restore" data-v="${h.version}">Restore</button>`}</td></tr>`).join("")}</tbody></table></div>`;
  }
  async function loadHistory() {
    try { C.history = await api("/api/policy/history"); } catch (e) { C.history = []; toast(e.message); }
    if (C.sheet === "history") renderSheet();
  }
  function principalColumns() { return (C.schema[P().principal?.table || "customers"] || []).map((c) => c.name).filter((c) => !C.blocked.includes(c)); }

  /* ---------------- Draft handling ---------------- */
  function edit(fn) {
    if (!C.draft) C.draft = clone(C.policy);
    fn(C.draft);
    evaluateNow(); render();
  }
  function renderDraftBar() {
    const bar = $("cpDraft");
    if (!C.draft) { bar.hidden = true; return; }
    bar.hidden = false;
    const now = C.result?.findings.length ?? 0, before = C.baseCount ?? now, d = now - before;
    $("cpDraftImpact").innerHTML = `Unsaved changes · findings ${num(before)} → <b>${num(now)}</b>${d ? ` <span class="${d > 0 ? "up" : "down"}">(${d > 0 ? "+" : "−"}${num(Math.abs(d))})</span>` : ""}`;
  }
  async function saveDraft() {
    const note = $("cpNote").value.trim();
    if (!note) { $("cpNote").focus(); toast("Describe the change before saving."); return; }
    $("cpSave").disabled = true;
    try {
      const saved = await api("/api/policy", { method: "PUT", body: JSON.stringify({ policy: C.draft, base_version: C.policy.version, change_note: note }) });
      C.gen++; C.policy = saved; C.draft = null; C.history = null; $("cpNote").value = "";
      C.data = await loadData(C.policy);
      evaluateNow(); render(); toast(`Saved as version ${saved.version}.`, true);
    } catch (e) {
      if (e.status === 409 && e.body?.current) {
        C.gen++; C.policy = e.body.current; evaluateNow(); render();
        toast(`${e.body.current.updated_by} saved version ${e.body.current.version} meanwhile. Your draft is kept; saving again replaces their version with your draft.`);
      } else toast(e.message);
    } finally { $("cpSave").disabled = false; }
  }

  /* ---------------- Modal forms (purposes, sources, notices, inventory) ---------------- */
  function openForm(title, fields, values, onSubmit) {
    const dlg = $("cpDialog");
    $("cpDialogTitle").textContent = title;
    $("cpDialogBody").innerHTML = fields.map((f) => fieldHtml(f, values[f.key])).join("");
    $("cpDialogErr").textContent = "";
    dlg.showModal();
    $("cpDialogForm").onsubmit = (e) => {
      e.preventDefault();
      if (e.submitter?.value === "cancel") { dlg.close(); return; }
      const out = {};
      for (const f of fields) {
        const el = dlg.querySelector(`[name="${f.key}"]`);
        if (!el) continue;
        out[f.key] = f.type === "checkbox" ? el.checked : f.type === "number" ? Number(el.value) : f.type === "list" ? el.value.split(",").map((s) => s.trim()).filter(Boolean) : el.value.trim();
        if (f.required && (out[f.key] === "" || (Array.isArray(out[f.key]) && !out[f.key].length))) { $("cpDialogErr").textContent = `${f.label} is required.`; el.focus(); return; }
      }
      const err = onSubmit(out);
      if (err) { $("cpDialogErr").textContent = err; return; }
      dlg.close();
    };
  }
  function fieldHtml(f, v) {
    const id = `cpf-${f.key}`;
    const help = f.help ? `<small>${esc(f.help)}</small>` : "";
    if (f.type === "select") return `<label class="field" for="${id}"><span>${esc(f.label)}</span><select id="${id}" name="${f.key}">${f.options.map(([val, lab]) => `<option value="${esc(val)}" ${String(v ?? "") === String(val) ? "selected" : ""}>${esc(lab)}</option>`).join("")}</select>${help}</label>`;
    if (f.type === "checkbox") return `<label class="field check"><input type="checkbox" name="${f.key}" ${v ? "checked" : ""}><span>${esc(f.label)}</span></label>`;
    if (f.type === "textarea") return `<label class="field" for="${id}"><span>${esc(f.label)}</span><textarea id="${id}" name="${f.key}" rows="${f.rows || 3}">${esc(v ?? "")}</textarea>${help}</label>`;
    const val = Array.isArray(v) ? v.join(", ") : v ?? "";
    return `<label class="field" for="${id}"><span>${esc(f.label)}</span><input id="${id}" name="${f.key}" type="${f.type === "number" ? "number" : f.type === "datetime-local" ? "datetime-local" : "text"}" value="${esc(val)}" ${f.readonly ? "readonly" : ""}>${help}</label>`;
  }
  const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40);
  const purposeOptions = (blank) => [...(blank ? [["", blank]] : []), ...P().purposes.map((p) => [p.id, p.name])];
  const tableOptions = () => Object.keys(C.schema).sort().map((t) => [t, t]);

  function purposeForm(i) {
    const cur = i == null ? { legal_basis: "consent", consent_type: "notice", data_categories: [] } : P().purposes[i];
    openForm(i == null ? "Add purpose" : "Edit purpose", [
      { key: "name", label: "Name", required: true },
      { key: "description", label: "Description", type: "textarea", rows: 2 },
      { key: "legal_basis", label: "Legal basis", type: "select", options: [["consent", "Consent (DPDP s.6)"], ["legitimate_use", "Legitimate use (DPDP s.7)"]] },
      { key: "consent_type", label: "How consent is captured", type: "select", options: [["notice", "Accepted with the sign-up notice"], ["opt_in", "Separate opt-in"]] },
      { key: "consent_field", label: "Opt-in field (for opt-in purposes)", type: "select", options: [["", "—"], ...FIELD_KEYS.map((k) => [k, FIELD_LABEL[k]])] },
      { key: "data_categories", label: "Data categories", type: "list", help: "Comma-separated, e.g. identity, contact, address" },
    ], cur, (v) => {
      v.id = i == null ? slug(v.name) : cur.id;
      if (i == null && P().purposes.some((p) => p.id === v.id)) return `A purpose called "${v.name}" already exists.`;
      if (v.legal_basis === "consent" && v.consent_type === "opt_in" && !v.consent_field) return "Choose the field that records the opt-in.";
      edit((d) => { if (i == null) d.purposes.push(v); else d.purposes[i] = v; });
    });
  }
  function activityForm(i) {
    const cur = i == null ? { type_map: {} } : P().activities[i];
    const mapText = Object.entries(cur.type_map || {}).map(([k, v]) => `${k}=${v}`).join("\n");
    const values = [...new Set((C.data?.activities[cur.id]?.rows || []).map((r) => r[cur.type_column]).filter((x) => x != null))];
    openForm(i == null ? "Add processing source" : "Edit processing source", [
      { key: "name", label: "Name", required: true, help: "Plural, e.g. Orders" },
      { key: "table", label: "Shop table", type: "select", options: tableOptions(), required: true },
      { key: "principal_column", label: "Column with the customer id", required: true, help: "e.g. customer_id, recipient_id" },
      { key: "time_column", label: "Column with the processing time", required: true, help: "e.g. created_at" },
      { key: "purpose", label: "Purpose (when every row has the same purpose)", type: "select", options: purposeOptions("— decided by a type column —") },
      { key: "type_column", label: "Type column (optional)", help: "Column whose value decides the purpose, e.g. type" },
      { key: "type_map", label: "Type → purpose", type: "textarea", rows: 4, help: `One per line as VALUE=purpose_id.${values.length ? ` Values seen: ${values.join(", ")}` : ""}` },
      { key: "via_column", label: "If the customer id is empty, follow this column (optional)", help: "e.g. order_id" },
      { key: "via_table", label: "…into this table", type: "select", options: [["", "—"], ...tableOptions()] },
      { key: "via_key", label: "…matching this column", help: "e.g. id" },
      { key: "via_principal", label: "…and read the customer id from", help: "e.g. customer_id" },
    ], { ...cur, type_map: mapText, via_column: cur.principal_via?.column, via_table: cur.principal_via?.table, via_key: cur.principal_via?.key, via_principal: cur.principal_via?.principal_column }, (v) => {
      const map = {};
      for (const line of String(v.type_map).split("\n").map((s) => s.trim()).filter(Boolean)) {
        const [k, p] = line.split("=").map((s) => s.trim());
        if (!k || !p) return `Line "${line}" must look like VALUE=purpose_id.`;
        if (!P().purposes.some((x) => x.id === p)) return `Unknown purpose "${p}". Purpose ids: ${P().purposes.map((x) => x.id).join(", ")}.`;
        map[k] = p;
      }
      if (!v.purpose && !v.type_column) return "Choose a purpose or a type column.";
      const cols = (C.schema[v.table] || []).map((c) => c.name);
      for (const k of ["principal_column", "time_column", "type_column"]) if (v[k] && !cols.includes(v[k])) return `Column "${v[k]}" does not exist in ${v.table}.`;
      let principal_via = null;
      if (v.via_column || v.via_table) {
        if (!(v.via_column && v.via_table && v.via_key && v.via_principal)) return "Fill in all four linked-customer fields, or leave them all empty.";
        if (!cols.includes(v.via_column)) return `Column "${v.via_column}" does not exist in ${v.table}.`;
        const lc = (C.schema[v.via_table] || []).map((c) => c.name);
        for (const k of [v.via_key, v.via_principal]) if (!lc.includes(k)) return `Column "${k}" does not exist in ${v.via_table}.`;
        principal_via = { column: v.via_column, table: v.via_table, key: v.via_key, principal_column: v.via_principal };
      }
      const out = { id: i == null ? slug(v.name) || `act_${Date.now()}` : cur.id, name: v.name, table: v.table, principal_column: v.principal_column, time_column: v.time_column, type_column: v.type_column, purpose: v.purpose, type_map: map, principal_via };
      if (i == null && P().activities.some((a) => a.id === out.id)) out.id += `_${Date.now() % 1000}`;
      edit((d) => { if (i == null) d.activities.push(out); else d.activities[i] = out; });
      if (i == null || cur.table !== out.table || cur.type_column !== out.type_column || JSON.stringify(cur.principal_via || null) !== JSON.stringify(principal_via)) refreshData();
    });
  }
  function noticeForm(i) {
    const cur = i == null ? { required: true } : P().notices[i];
    openForm(i == null ? "Add notice" : "Edit notice", [
      { key: "name", label: "Name", required: true },
      { key: "field", label: "Consent field that records the accepted version", type: "select", options: FIELD_KEYS.map((k) => [k, FIELD_LABEL[k]]) },
      { key: "current_version", label: "Current version", required: true, help: "Customers on any other version need to re-consent." },
      { key: "required", label: "Required for consent-based processing", type: "checkbox" },
      { key: "capture", label: "How it's collected", type: "select", options: [["mandatory_signup", "Mandatory at sign-up (can't create an account without it)"], ["prompted", "Asked after sign-up"]] },
      { key: "since_local", label: "Mandatory since (IST)", type: "datetime-local", help: "Accounts created before this are existing accounts: they're asked at their next sign-in, not counted as violations." },
    ], { ...cur, capture: cur.capture || "prompted", since_local: cur.since ? toLocalIst(cur.since) : "" }, (v) => {
      const { since_local, ...rest } = v;
      if (rest.capture === "mandatory_signup" && !since_local) return "Give the date and time acceptance became mandatory.";
      const out = { id: i == null ? slug(v.name) : cur.id, ...rest, since: rest.capture === "mandatory_signup" && since_local ? fromLocalIst(since_local) : undefined };
      if (i == null && P().notices.some((n) => n.id === out.id)) return `A notice called "${v.name}" already exists.`;
      edit((d) => { if (i == null) d.notices.push(out); else d.notices[i] = out; });
    });
  }
  function inventoryForm(table) {
    const cur = table ? P().inventory[table] : [];
    openForm(table ? `Edit inventory · ${table}` : "Add table to inventory", [
      { key: "table", label: "Table", type: "select", options: tableOptions(), required: true },
      { key: "columns", label: "Declared columns", type: "textarea", rows: 5, help: `Comma-separated. Live columns: ${table ? (C.schema[table] || []).map((c) => c.name).join(", ") : "choose a table"}` },
    ], { table: table || "", columns: cur.join(", ") }, (v) => {
      const cols = v.columns.split(",").map((s) => s.trim()).filter(Boolean);
      if (!cols.length) return "List at least one declared column.";
      edit((d) => { if (table && table !== v.table) delete d.inventory[table]; d.inventory[v.table] = cols; });
    });
  }
  function confirmDelete(what, fn) { if (window.confirm(`Delete ${what}? Nothing is saved until you click Save.`)) edit(fn); }

  /* ---------------- CSV export ---------------- */
  function downloadCsv(name, items) {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const head = ["Time (IST)", "Customer", "Event", "Purpose", "Rule", "Severity", "DPDP reference", "Detail"];
    const lines = items.map((f) => [f.at ? ist(f.at) : "", f.principal ?? "", f.event ? `${singular(f.event.activity.name)} #${f.event.rowId}` : f.table || "", f.event ? purposeName(f.purpose) : "", `${f.rule} ${f.ruleName}`, f.severity, f.dpdp, f.detail].map(q).join(","));
    const blob = new Blob([[head.map(q).join(","), ...lines].join("\n")], { type: "text/csv" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* ---------------- Events ---------------- */
  function onClick(e) {
    const t = (sel) => e.target.closest(sel);
    let b;
    if ((b = t("[data-goto]"))) { C.tab = b.dataset.goto; return render(); }
    if ((b = t("[data-issue]"))) { C.tab = "issues"; C.sel.issue = b.dataset.issue; C.evidenceLimit = 25; return render(); }
    if ((b = t("[data-cust-filter]"))) { C.tab = "customers"; C.custView = "list"; C.custFilter = b.dataset.custFilter; C.custPage = 0; return render(); }
    if ((b = t("[data-page]"))) { C.custPage += b.dataset.page === "next" ? 1 : -1; render(); return $("cpBody").scrollIntoView({ block: "start" }); }
    if ((b = t("[data-cust]")) && b.dataset.cust) { C.sel.customer = b.dataset.cust; C.custView = "detail"; C.showAllTimeline = false; render(); return $("cpBody").scrollIntoView({ block: "start" }); }
    if ((b = t("[data-cust-go]"))) { C.tab = "customers"; C.custView = "detail"; C.custFilter = "all"; C.custQuery = ""; C.lookup = null; C.custRule = ""; C.sel.customer = b.dataset.custGo; C.showAllTimeline = false; return render(); }
    if ((b = t("[data-edit-rule]"))) { C.tab = "rules"; C.editRule = b.dataset.editRule; C.newRule = null; C.picking = false; render(); return document.querySelector(".cp-redit")?.scrollIntoView({ block: "center" }); }
    if ((b = t("[data-toggle-rule]"))) { const i = +b.dataset.toggleRule; return edit((d) => (d.rules[i].enabled = !d.rules[i].enabled)); }
    if ((b = t("[data-new-rule]"))) {
      const type = b.dataset.newRule, tpl = TEMPLATES[type];
      let n = 1; while (P().rules.some((r) => r.id === `R${n}`)) n++;
      C.newRule = { id: `R${n}`, type, name: tpl.name, enabled: true, severity: tpl.sev, dpdp_ref: tpl.ref, params: tpl.params() };
      C.editRule = null; C.picking = false; render();
      return document.querySelector(".cp-redit")?.scrollIntoView({ block: "center" });
    }
    if ((b = t("[data-sheet]"))) return openSheet(b.dataset.sheet);
    b = t("[data-act]");
    if (!b || b.tagName === "INPUT") return;
    const i = b.dataset.i != null ? +b.dataset.i : null, pol = P();
    switch (b.dataset.act) {
      case "timeline-more": C.showAllTimeline = true; return render();
      case "timeline-less": C.showAllTimeline = false; return render();
      case "evidence-more": C.evidenceLimit += 25; return render();
      case "evidence-less": C.evidenceLimit = 25; return render();
      case "cust-back": C.custView = "list"; return render();
      case "clear-lookup": C.lookup = null; C.custQuery = ""; C.custPage = 0; return render();
      case "csv-issue": { const iss = issueList().find((x) => x.rule.id === C.sel.issue); return iss && downloadCsv(`consent-issue-${iss.rule.id}.csv`, iss.items); }
      case "csv-customer": return downloadCsv(`consent-customer-${C.sel.customer}.csv`, C.result.findings.filter((f) => f.principal === C.sel.customer));
      case "pick-rule": C.picking = true; C.editRule = null; return render();
      case "pick-cancel": C.picking = false; return render();
      case "cancel-rule": C.editRule = null; C.newRule = null; return render();
      case "delete-rule": {
        const id = b.closest(".cp-redit").dataset.rule, r = pol.rules.find((x) => x.id === id);
        if (!window.confirm(`Delete rule ${id} "${r.name}"? Nothing is saved until you click Save.`)) return;
        C.editRule = null; return edit((d) => d.rules.splice(d.rules.findIndex((x) => x.id === id), 1));
      }
      case "add-purpose": return purposeForm(null);
      case "edit-purpose": return purposeForm(i);
      case "del-purpose": {
        const id = pol.purposes[i].id;
        const used = pol.activities.filter((a) => a.purpose === id || Object.values(a.type_map || {}).includes(id));
        if (used.length) return toast(`"${pol.purposes[i].name}" is used by ${used.map((a) => a.name).join(", ")}. Change those sources first.`);
        return confirmDelete(`purpose "${pol.purposes[i].name}"`, (d) => d.purposes.splice(i, 1));
      }
      case "add-activity": return activityForm(null);
      case "edit-activity": return activityForm(i);
      case "del-activity": return confirmDelete(`source "${pol.activities[i].name}"`, (d) => d.activities.splice(i, 1));
      case "add-notice": return noticeForm(null);
      case "open-notices": C.tab = "rules"; render(); return openSheet("notices");
      case "edit-notice": return noticeForm(i);
      case "del-notice": {
        const used = pol.rules.filter((r) => r.params?.notice === pol.notices[i].id);
        if (used.length) return toast(`Rules ${used.map((r) => r.id).join(", ")} use this notice. Change them first.`);
        return confirmDelete(`notice "${pol.notices[i].name}"`, (d) => d.notices.splice(i, 1));
      }
      case "add-inventory": return inventoryForm(null);
      case "edit-inventory": return inventoryForm(b.dataset.t);
      case "del-inventory": return confirmDelete(`inventory for ${b.dataset.t}`, (d) => delete d.inventory[b.dataset.t]);
      case "export": return exportPolicy();
      case "restore": return restore(+b.dataset.v);
    }
  }
  function onChange(e) {
    const t = e.target;
    if (t.closest(".cp-redit")) return updatePreview(t.closest(".cp-redit"));
    if (t.matches("[data-cust-rule]")) { C.custRule = t.value; C.custPage = 0; return render(); }
    if (t.matches("[data-cust-sort]")) { C.custSort = t.value; C.custPage = 0; return render(); }
    if (t.matches("[data-cust-size]")) { C.custPageSize = Number(t.value); C.custPage = 0; return render(); }
    if (t.dataset.fieldmap) edit((d) => {
      // the chosen column becomes the first one read; the other columns already mapped stay as fallbacks
      const v = t.value.replace(/ \(missing\)$/, ""), rest = [].concat(d.field_map[t.dataset.fieldmap] || []).slice(1).filter((c) => c !== v);
      d.field_map[t.dataset.fieldmap] = !v ? "" : rest.length ? [v, ...rest] : v;
    });
    else if (t.dataset.act === "import") importFile(t.files[0]);
  }
  function onInput(e) {
    const t = e.target;
    if (t.closest(".cp-redit")) return updatePreview(t.closest(".cp-redit"));
    if (t.matches("[data-cust-q]")) {
      C.custQuery = t.value; C.custPage = 0;
      if (C.lookup) C.lookup = null; // a new query replaces the previous lookup
      render();
      const el = $("cpCustQ"); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
    }
  }
  function bind() {
    $("cpTabs").onclick = (e) => { const b = e.target.closest("[data-tab]"); if (b) { C.tab = b.dataset.tab; render(); } };
    $("cpTabs").onkeydown = (e) => {
      if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
      const tabs = [...$("cpTabs").querySelectorAll("[data-tab]")], i = tabs.findIndex((x) => x.dataset.tab === C.tab);
      const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      C.tab = next.dataset.tab; render(); next.focus();
    };
    $("cpRefresh").onclick = () => loadAll({ withPolicy: !C.draft });
    $("cpSave").onclick = saveDraft;
    $("cpDiscard").onclick = () => { if (window.confirm("Discard all unsaved policy changes?")) { C.draft = null; C.editRule = null; C.newRule = null; refreshData(); } };
    $("cpSheetClose").onclick = () => $("cpSheet").close();
    $("cpSheet").addEventListener("close", () => (C.sheet = null));
    for (const el of [$("cpBody"), $("cpSheetBody")]) {
      el.addEventListener("click", onClick);
      el.addEventListener("change", onChange);
      el.addEventListener("input", onInput);
    }
    $("cpBody").addEventListener("submit", (e) => {
      if (e.target.matches(".cp-redit")) { e.preventDefault(); applyRule(e.target); }
      else if (e.target.matches("[data-lookup-form]")) { e.preventDefault(); runLookup(); }
    });
  }
  async function refreshData() {
    try { C.data = await loadData(P()); } catch (e) { toast(e.message); }
    evaluateNow(); render();
  }
  function exportPolicy() {
    const blob = new Blob([JSON.stringify(P(), null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `consent-policy-v${C.policy.version}${C.draft ? "-draft" : ""}.json` });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  async function importFile(file) {
    if (!file) return;
    try {
      const doc = JSON.parse(await file.text());
      for (const k of ["purposes", "activities", "notices", "field_map", "rules", "inventory"]) if (!(k in doc)) throw new Error(`File is missing "${k}".`);
      C.draft = doc; await refreshData(); toast("Imported as unsaved changes. Review the impact, then save.", true);
    } catch (e) { toast(`Import failed: ${e.message}`); }
  }
  async function restore(v) {
    if (C.draft && !window.confirm("You have unsaved changes. Restore anyway and discard them?")) return;
    if (!window.confirm(`Restore version ${v}? It will be saved as a new version.`)) return;
    try {
      const restored = await api(`/api/policy/restore/v${v}`, { method: "POST", body: JSON.stringify({ base_version: C.policy.version }) });
      C.gen++; C.policy = restored;
      C.draft = null; C.history = null; await refreshData(); toast(`Version ${v} restored as version ${C.policy.version}.`, true);
    } catch (e) {
      if (e.status === 409 && e.body?.current) { C.gen++; C.policy = e.body.current; C.history = null; render(); toast("A newer version was saved meanwhile. Review it, then restore again if needed."); }
      else toast(e.message);
    }
  }
  let toastT;
  function toast(m, ok = false) { const t = $("cpToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }

  return {
    show() {
      if (!C.started) { C.started = true; bind(); }
      if (!C.result || C.error) loadAll();
      else render();
    },
    // Live: re-check the shop data; pick up policy edits by others unless a draft is open.
    tick() {
      const a = document.activeElement;
      const editing = document.querySelector("#cpDialog[open], #cpSheet[open]") || C.editRule || C.newRule || C.picking || ($("view-consent").contains(a) && /SELECT|INPUT|TEXTAREA/.test(a.tagName));
      if (C.started && !C.busy && !editing) loadAll({ withPolicy: !C.draft });
    },
    // For the main dashboard: loads once if needed, then reuses the result for 60 s.
    async summary() {
      if (!C.busy && (!C.result || !C.loadedAt || Date.now() - C.loadedAt > 60000)) await loadAll({ withPolicy: !C.draft });
      if (!C.result) return null;
      const cov = C.result.coverage, issues = issueList();
      const st = (...x) => cov.filter((c) => x.includes(c.status)).length;
      return { customers: cov.length, valid: cov.filter((c) => c.valid).length, legacy: st("legacy"), attention: cov.filter(ACTION).length,
        partial: st("unsaved", "stale", "legacy_active"), none: st("gate_failure", "none"), gate: C.result.gate, findings: C.result.findings.length, issues: issues.length,
        high: issues.filter((x) => x.rule.severity === "high" || x.rule.severity === "critical").length,
        top: issues.slice(0, 2).map((x) => ({ title: x.title, impact: x.impact, severity: x.rule.severity })) };
    },
    // For the AI assistant: policy, issues and per-customer status (ids and counts only, no personal data).
    async context() {
      await this.summary();
      if (!C.result) return null;
      const pol = P(), cov = C.result.coverage, f = C.result.findings;
      return {
        policy_version: C.policy.version, checked_at: C.loadedAt,
        purposes: pol.purposes.map((p) => ({ id: p.id, name: p.name, legal_basis: p.legal_basis, consent_type: p.consent_type })),
        notices: pol.notices.map((n) => ({ name: n.name, current_version: n.current_version })),
        rules: pol.rules.map((r) => ({ id: r.id, name: r.name, type: r.type, severity: r.severity, enabled: r.enabled, dpdp_ref: r.dpdp_ref, findings: f.filter((x) => x.rule === r.id).length })),
        customers: { total: cov.length, valid: cov.filter((c) => c.valid).length, needs_reconsent: cov.filter((c) => c.status === "partial").length, never_accepted: cov.filter((c) => c.status === "none").length },
        issues: issueList().map((x) => ({ rule: x.rule.id, severity: x.rule.severity, title: x.title, impact: x.impact, what: x.what, why: x.why, fix: x.fix, first: x.first, last: x.last })),
        customer_list: [...cov].sort((a, b) => b.findings - a.findings).slice(0, 60).map((c) => ({ customer: `#${c.id}`, consent: c.status, findings: c.findings, rules: c.rules, events: c.events, last_activity: c.lastAt || null, erasure_requested: !!c.erasureAt })),
      };
    },
    aiItem(ruleId) {
      const x = issueList().find((i) => i.rule.id === ruleId);
      if (!x) return null;
      const ev = x.items.slice(0, 40).map((f) => ({ customer: f.principal != null ? `#${f.principal}` : null, at: f.at, purpose: purposeName(f.purpose), source: f.event?.activity.name }));
      return { name: `Consent issue ${ruleId}: ${x.title}`, question: `Explain this consent issue (${ruleId}) and tell me exactly how to fix and prevent it.`,
        text: JSON.stringify({ rule: { id: x.rule.id, name: x.rule.name, severity: x.rule.severity, dpdp_ref: x.rule.dpdp_ref }, title: x.title, impact: x.impact, what: x.what, why: x.why, fix: x.fix, evidence_sample: ev }, null, 1) };
    },
    _evaluate: evaluate,
  };
})();
