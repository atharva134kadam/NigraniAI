/* Access management, modelled on AWS IAM.
   Nothing is predefined: every user starts with no access; root writes policies (JSON
   statements: Effect Allow/Deny, Action with wildcards, optional Condition) and attaches
   them to users or groups. Explicit Deny beats Allow; anything not allowed is denied.
   Includes a visual + JSON policy editor with live validation, a policy simulator that
   explains every decision, and an access advisor. The rules run in consent_service.
   Uses session / refreshSession / can / show / ME from app.js. */
const IAM = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const ist = (v) => (v ? F.format(new Date(v)).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase()) : "–");
  const ago = (v) => { if (!v) return "never"; const m = Math.round((Date.now() - new Date(v)) / 6e4); return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 2880 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} days ago`; };
  const toLocal = (v) => { const d = new Date(new Date(v).getTime() + 330 * 6e4); return d.toISOString().slice(0, 16); };
  const fromLocal = (s) => (s ? new Date(`${s}:00+05:30`).toISOString() : null);
  const LEVELS = ["List", "Read", "Write", "Use", "Permissions management"];
  const COLORS = ["#2563eb", "#7c3aed", "#0891b2", "#16a34a", "#db2777", "#ea580c", "#475569"];
  const initials = (n, e) => ((n || e || "?").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2) || "?").toUpperCase();
  const avatar = (u) => `<span class="avatar" style="background:${COLORS[(u.email.charCodeAt(0) || 0) % COLORS.length]};color:#fff">${esc(initials(u.name, u.email))}</span>`;

  const S = { st: null, tab: "users", q: "", user: null, utab: "permissions", sim: null, simFor: null, creating: false, editPol: null, group: null, simForm: { email: "", at: "", draft: "" }, simFilter: "all", busy: false, err: "" };

  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r;
    try { r = await go(); } catch { throw new Error("The consent service isn't running."); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  async function load() {
    try { S.st = await api("/api/iam"); S.err = ""; } catch (e) { S.err = e.message; }
    render();
  }
  let toastT;
  function toast(m, ok = false) { const t = $("iamToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }
  const cat = () => S.st.catalog;
  const polName = (id) => S.st.policies?.[id]?.name || id;
  const grpName = (id) => S.st.groups?.[id]?.name || id;
  const chips = (ids, fn, cls = "") => (ids.length ? ids.map((x) => `<span class="iam-chip ${cls}">${esc(fn(x))}</span>`).join("") : `<span class="muted">–</span>`);
  const decisionPill = (d) => ({ allow: `<span class="iam-dec allow">Allowed</span>`, deny: `<span class="iam-dec deny">Explicit deny</span>`, implicit: `<span class="iam-dec implicit">Implicit deny</span>` }[d]);

  /* ---------- shell ---------- */
  function render() {
    const body = $("iamBody");
    if (S.err && !S.st) { body.innerHTML = `<div class="panel cp-empty"><h3>Access management isn't available</h3><p>${esc(S.err)}</p></div>`; return; }
    if (!S.st) { body.innerHTML = `<div class="panel cp-empty"><p>Loading access management…</p></div>`; return; }
    const tabs = [["users", "Users", S.st.users], ["groups", "Groups", S.st.groups], ["policies", "Policies", S.st.policies], ["simulator", "Policy simulator", can("iam:SimulatePolicy") || null], ["catalog", "Action catalogue", true]].filter((t) => t[2] !== null && t[2] !== undefined && t[2] !== false);
    if (!tabs.some((t) => t[0] === S.tab)) S.tab = tabs[0][0];
    const n = (o) => (o ? Object.keys(o).length : "–");
    body.innerHTML = `
      <div class="iam-kpis">
        <div class="panel iam-kpi"><span>Users</span><b>${S.st.users ? S.st.users.length : "–"}</b><small>${S.st.users ? `${S.st.users.filter((u) => !u.root && !u.allowed).length} with no access yet` : "no permission to list"}</small></div>
        <div class="panel iam-kpi"><span>Groups</span><b>${n(S.st.groups)}</b><small>share policies across users</small></div>
        <div class="panel iam-kpi"><span>Policies</span><b>${n(S.st.policies)}</b><small>written by you, none predefined</small></div>
        <div class="panel iam-kpi ${S.st.denied_24h ? "warn" : ""}"><span>Denied requests</span><b>${S.st.denied_24h}</b><small>in the last 24 hours</small></div>
      </div>
      <div class="cp-tabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" class="${S.tab === k ? "on" : ""}" aria-selected="${S.tab === k}" data-itab="${k}">${esc(l)}</button>`).join("")}</div>
      <div id="iamTab">${{ users: usersHtml, groups: groupsHtml, policies: policiesHtml, simulator: simHtml, catalog: catalogHtml }[S.tab]()}</div>`;
    if (S.tab === "policies" && S.editPol) syncEditor();
  }

  /* ---------- Users ---------- */
  function usersHtml() {
    if (S.user) return userDetailHtml();
    if (S.creating) return createUserHtml();
    const q = S.q.toLowerCase(), list = S.st.users.filter((u) => !q || `${u.name} ${u.email}`.toLowerCase().includes(q));
    const total = Object.values(cat()).reduce((n, s) => n + Object.keys(s.actions).length, 0);
    return `<section class="panel cp-cpanel">
      <div class="cp-ctools"><input type="search" class="iam-search" data-iq placeholder="Search users" value="${esc(S.q)}" aria-label="Search users">
        ${can("iam:ManageUsers") ? `<button class="btn primary iam-push" data-act="new-user">+ Create user</button>` : ""}</div>
      <div class="cp-tablewrap"><table class="cp-ctable iam-table"><thead><tr><th>User</th><th>Groups</th><th>Policies</th><th>Access</th><th>Last activity</th><th>Status</th></tr></thead>
      <tbody>${list.map((u) => { const last = Object.values(u.last_used || {}).sort().pop(); return `<tr data-user="${esc(u.id)}" tabindex="0">
        <td><div class="iam-who">${avatar(u)}<div><b>${esc(u.name || u.email.split("@")[0])}</b><span>${esc(u.email)}</span></div></div></td>
        <td>${u.root ? `<span class="muted">–</span>` : chips(u.groups, grpName, "g")}</td>
        <td>${u.root ? `<span class="role-chip root">Root: full access</span>` : chips(u.policies, polName)}</td>
        <td>${u.root ? `<span class="iam-bar"><i style="width:100%"></i></span><small>${total} of ${total} actions</small>` : `<span class="iam-bar"><i style="width:${((u.allowed / total) * 100).toFixed(1)}%"></i></span><small>${u.allowed ? `${u.allowed} of ${total} actions${u.denied ? ` · ${u.denied} denied` : ""}` : "No access"}</small>`}</td>
        <td>${esc(ago(last || u.last_sign_in_at))}</td>
        <td>${u.active ? `<span class="iam-dec allow">Active</span>` : `<span class="iam-dec deny">Deactivated</span>`}</td></tr>`; }).join("")}</tbody></table></div>
    </section>
    <p class="rt-note">New users start with no access. Attach policies to them directly or through groups. Anything a policy doesn't allow is denied, and an explicit Deny always wins.</p>`;
  }
  function pickList(name, items, sel, empty) {
    if (!items.length) return `<p class="muted">${empty}</p>`;
    return `<div class="iam-pick">${items.map(([id, label, sub]) => `<label><input type="checkbox" name="${name}" value="${esc(id)}" ${sel.includes(id) ? "checked" : ""}><span><b>${esc(label)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}</span></label>`).join("")}</div>`;
  }
  const polItems = () => Object.entries(S.st.policies || {}).map(([id, p]) => [id, p.name, p.description]);
  const grpItems = () => Object.entries(S.st.groups || {}).map(([id, g]) => [id, g.name, `${g.members.length} members · ${g.policies.map(polName).join(", ") || "no policies"}`]);
  function createUserHtml() {
    return `<div class="cp-crumbs"><button class="link" data-act="back">← Users</button></div>
    <form class="panel iam-form" id="iamNewUser">
      <h3>Create user</h3>
      <div class="iam-grid">
        <label class="field"><span>Name</span><input name="name" type="text" maxlength="80" required></label>
        <label class="field"><span>Email</span><input name="email" type="email" required></label>
        <label class="field"><span>Job title <small>optional</small></span><input name="title" type="text" maxlength="80"></label>
        <label class="field"><span>Temporary password <small>${esc(S.st.password_rule)}</small></span><span class="iam-pw"><input name="password" type="text" required minlength="8" autocomplete="off"><button type="button" class="btn ghost" data-act="gen">Generate</button></span></label>
      </div>
      ${can("iam:AttachPolicies") ? `<div class="iam-two"><div><h4>Add to groups</h4>${pickList("groups", grpItems(), [], "No groups yet.")}</div><div><h4>Attach policies directly</h4>${pickList("policies", polItems(), [], "No policies yet. Create one under Policies.")}</div></div>` : ""}
      <p class="iam-hint">Leave everything unticked to create the user with <b>no access</b>; you can grant it later.</p>
      <div class="ac-actions"><button type="button" class="btn ghost" data-act="back">Cancel</button><button class="btn primary">Create user</button></div>
    </form>`;
  }
  function userDetailHtml() {
    const u = S.st.users.find((x) => x.id === S.user);
    if (!u) { S.user = null; return usersHtml(); }
    const tabs = [["permissions", "Permissions"], ["effective", "Effective access"], ["advisor", "Access advisor"], ...(u.root ? [] : [["security", "Security"]])];
    let inner = "";
    if (S.utab === "permissions") inner = u.root ? `<p class="iam-root">The root user always has every permission and can't be restricted by any policy, like the AWS account root user. Set by <code>ROOT_EMAIL</code> in <code>.env</code>.</p>`
      : `<form id="iamAccess" data-uid="${esc(u.id)}"><div class="iam-two"><div><h4>Groups</h4>${pickList("groups", grpItems(), u.groups, "No groups yet.")}</div><div><h4>Policies attached directly</h4>${pickList("policies", polItems(), u.policies, "No policies yet. Create one under Policies.")}</div></div>
        ${can("iam:AttachPolicies") ? `<div class="ac-actions"><button class="btn primary">Save access</button></div>` : `<p class="iam-hint">You can see but not change access (needs iam:AttachPolicies).</p>`}</form>`;
    if (S.utab === "effective") inner = effectiveHtml(u);
    if (S.utab === "advisor") {
      const lu = u.last_used || {};
      inner = `<p class="iam-hint">When this user last used each service, like IAM's access advisor. Use it to remove access nobody uses.</p>
        <div class="cp-tablewrap"><table class="cp-ctable"><thead><tr><th>Service</th><th>Allowed actions</th><th>Last accessed</th></tr></thead><tbody>
        ${Object.entries(cat()).map(([svc, s]) => { const n = S.simFor === u.email && S.sim ? S.sim.results.filter((r) => r.action.startsWith(svc + ":") && r.decision === "allow").length : null;
          return `<tr><td><b>${esc(s.label)}</b> <code>${esc(svc)}</code></td><td>${n === null ? "…" : `${n} of ${Object.keys(s.actions).length}`}</td><td>${lu[svc] ? `${esc(ago(lu[svc]))} <small class="muted">${esc(ist(lu[svc]))}</small>` : `<span class="muted">Not accessed</span>`}</td></tr>`; }).join("")}</tbody></table></div>`;
      if (S.simFor !== u.email) runSim(u.email);
    }
    if (S.utab === "security") inner = `<div class="iam-sec">
      <div class="ac-row"><div><b>Reset password</b><span>Set a new temporary password and share it securely.</span></div><button class="btn ghost" data-act="reset-pw" ${can("iam:ManageUsers") ? "" : "disabled"}>Reset password</button></div>
      <div class="ac-row"><div><b>${u.active ? "Deactivate" : "Reactivate"}</b><span>${u.active ? "Blocks sign-in without deleting anything." : "Lets the user sign in again."}</span></div><button class="btn ghost" data-act="toggle-active" ${can("iam:ManageUsers") ? "" : "disabled"}>${u.active ? "Deactivate" : "Reactivate"}</button></div>
      <div class="ac-row"><div><b>Remove user</b><span>Deletes the account from Supabase Auth. Their activity stays in the log.</span></div><button class="btn ghost danger" data-act="remove" ${can("iam:ManageUsers") ? "" : "disabled"}>Remove</button></div></div>`;
    return `<div class="cp-crumbs"><button class="link" data-act="back">← Users</button></div>
      <div class="panel iam-uhead">${avatar(u)}<div><h3>${esc(u.name || u.email)} ${u.root ? `<span class="role-chip root">Root</span>` : ""}</h3><p>${esc(u.email)}${u.title ? ` · ${esc(u.title)}` : ""}</p><small>Created ${esc(ist(u.created_at))} · last sign-in ${esc(ago(u.last_sign_in_at))}${u.added_by ? ` · added by ${esc(u.added_by)}` : ""}${u.active ? "" : " · <b class='cp-red'>Deactivated</b>"}</small></div></div>
      <div class="panel iam-ubody"><div class="cp-chips iam-utabs">${tabs.map(([k, l]) => `<button class="cp-chip${S.utab === k ? " on" : ""}" data-utab="${k}">${l}</button>`).join("")}</div>${inner}</div>`;
  }
  function effectiveHtml(u) {
    if (S.simFor !== u.email || !S.sim) { runSim(u.email); return `<p class="muted">Evaluating every action…</p>`; }
    const by = {};
    for (const r of S.sim.results) (by[r.service] ||= []).push(r);
    return `<p class="iam-hint">Every action evaluated now, the way the server decides it. Hover an action to see which policy and statement decided it.</p>
      <div class="iam-eff">${Object.entries(by).map(([svc, rows]) => `<div class="iam-effrow"><b>${esc(svc)}</b><div>${rows.map((r) => `<span class="iam-act ${r.decision}" title="${esc(r.action)}: ${r.decision === "allow" ? `allowed by ${r.policy}${r.sid ? ` (${r.sid})` : ""}${r.via && r.via !== "direct" ? ` via ${r.via}` : ""}` : r.decision === "deny" ? `denied by ${r.policy}${r.sid ? ` (${r.sid})` : ""}` : "no policy allows it"}">${esc(r.action.split(":")[1])}</span>`).join("")}</div></div>`).join("")}</div>
      <div class="ch-legend sm"><span><i class="ch-key iam-k allow"></i>Allowed</span><span><i class="ch-key iam-k deny"></i>Explicit deny</span><span><i class="ch-key iam-k implicit"></i>Implicit deny</span></div>`;
  }
  async function runSim(email, extra = {}) {
    S.simFor = email; S.sim = null;
    try { S.sim = await api("/api/iam/simulate", { method: "POST", body: JSON.stringify({ email, ...extra }) }); } catch (e) { toast(e.message); }
    render();
  }

  /* ---------- Groups ---------- */
  function groupsHtml() {
    if (S.group) {
      const g = S.group === "new" ? { name: "", description: "", members: [], policies: [] } : S.st.groups[S.group];
      const users = (S.st.users || []).filter((u) => !u.root).map((u) => [u.email, u.name || u.email, u.email]);
      return `<div class="cp-crumbs"><button class="link" data-act="back">← Groups</button></div>
        <form class="panel iam-form" id="iamGroup" data-gid="${esc(S.group)}">
          <h3>${S.group === "new" ? "Create group" : `Edit group: ${esc(g.name)}`}</h3>
          <div class="iam-grid"><label class="field"><span>Group name</span><input name="name" value="${esc(g.name)}" required maxlength="64"></label>
            <label class="field"><span>Description</span><input name="description" value="${esc(g.description || "")}" maxlength="300"></label></div>
          <div class="iam-two"><div><h4>Members</h4>${pickList("members", users, g.members, S.st.users ? "No users to add yet." : "You can't list users.")}</div><div><h4>Policies</h4>${pickList("policies", polItems(), g.policies, "No policies yet.")}</div></div>
          <div class="ac-actions">${S.group !== "new" ? `<button type="button" class="btn ghost danger" data-act="del-group">Delete group</button>` : ""}<button type="button" class="btn ghost" data-act="back">Cancel</button><button class="btn primary">Save group</button></div>
        </form>`;
    }
    const gs = Object.entries(S.st.groups || {});
    return `<div class="cp-rtop"><p>Groups give the same policies to several people. A user gets the policies of every group they're in.</p>${can("iam:ManageGroups") ? `<button class="btn primary" data-act="new-group">+ Create group</button>` : ""}</div>
      ${gs.length ? `<div class="iam-cards">${gs.map(([id, g]) => `<button class="panel iam-card" data-group="${esc(id)}"><b>${esc(g.name)}</b><span>${esc(g.description || "")}</span>
        <div class="iam-cardf"><small>${g.members.length} member${g.members.length === 1 ? "" : "s"}</small><div>${chips(g.policies, polName)}</div></div></button>`).join("")}</div>`
      : `<div class="panel cp-empty"><h3>No groups yet</h3><p>Create a group such as "Breach responders", attach policies to it, then add people.</p></div>`}`;
  }

  /* ---------- Policies ---------- */
  function policiesHtml() {
    if (S.editPol) return editorHtml();
    const ps = Object.entries(S.st.policies || {});
    return `<div class="cp-rtop"><p>Each policy is a JSON document of statements. Nothing is predefined: write exactly the access you want to give.</p>${can("iam:ManagePolicies") ? `<button class="btn primary" data-act="new-policy">+ Create policy</button>` : ""}</div>
      ${ps.length ? `<section class="panel cp-cpanel"><div class="cp-tablewrap"><table class="cp-ctable"><thead><tr><th>Policy</th><th>Grants</th><th>Attached to</th><th>Version</th><th>Last change</th></tr></thead><tbody>
        ${ps.map(([id, p]) => { const sum = summary(p.document); return `<tr data-policy="${esc(id)}" tabindex="0"><td><b>${esc(p.name)}</b><div class="br-ttl">${esc(p.description || "")}</div></td>
          <td>${sum.slice(0, 3).map((x) => `<span class="iam-chip ${x.deny ? "d" : ""}">${x.deny ? "Deny " : ""}${esc(x.label)}: ${esc(x.levels.join(", "))}</span>`).join("")}${sum.length > 3 ? `<span class="muted">+${sum.length - 3}</span>` : ""}</td>
          <td>${p.attached}</td><td>v${p.version}</td><td>${esc(ago(p.updated_at))} · ${esc(p.updated_by)}</td></tr>`; }).join("")}</tbody></table></div></section>`
      : `<div class="panel cp-empty"><h3>No policies yet</h3><p>Create your first policy, for example read-only access to Breach Response, then attach it to a user or group.</p></div>`}`;
  }
  // Policy summary like the IAM console: per service, which access levels are allowed or denied.
  function summary(doc) {
    const out = {};
    for (const st of [].concat(doc?.Statement || [])) {
      const pats = [].concat(st.Action || st.NotAction || []).map((p) => String(p).toLowerCase());
      for (const [svc, s] of Object.entries(cat())) for (const [a, m] of Object.entries(s.actions)) {
        const name = `${svc}:${a}`.toLowerCase();
        let hit = pats.some((p) => new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(name));
        if (st.NotAction) hit = !hit;
        if (!hit) continue;
        const k = `${svc}|${st.Effect}`;
        (out[k] ||= { label: s.label, deny: st.Effect === "Deny", levels: new Set(), cond: !!st.Condition }).levels.add(m.level);
      }
    }
    return Object.values(out).map((x) => ({ ...x, levels: LEVELS.filter((l) => x.levels.has(l)) }));
  }

  /* visual editor model <-> JSON */
  const blankSt = () => ({ effect: "Allow", service: Object.keys(cat())[0], actions: [], until: "", hourFrom: "", hourTo: "", weekdays: false });
  function toDoc(sts) {
    return { Version: S.st.version, Statement: sts.map((v, i) => {
      const st = { Sid: `S${i + 1}`, Effect: v.effect, Action: v.service === "*" ? "*" : v.actions.includes("*") ? `${v.service}:*` : v.actions.map((a) => `${v.service}:${a}`) };
      const c = {};
      if (v.until) c.DateLessThan = { "dpdp:CurrentTime": fromLocal(v.until) };
      if (v.hourFrom !== "" && v.hourTo !== "") { c.NumericGreaterThanEquals = { "dpdp:IstHour": +v.hourFrom }; c.NumericLessThan = { "dpdp:IstHour": +v.hourTo }; }
      if (v.weekdays) c.StringNotEquals = { "dpdp:IstWeekday": ["Sat", "Sun"] };
      if (Object.keys(c).length) st.Condition = c;
      return st;
    }) };
  }
  function fromDoc(doc) {
    try {
      return [].concat(doc.Statement).map((st) => {
        if (st.NotAction) throw 0;
        const acts = [].concat(st.Action), v = blankSt();
        v.effect = st.Effect;
        if (acts.length === 1 && acts[0] === "*") { v.service = "*"; v.actions = ["*"]; }
        else {
          const svcs = [...new Set(acts.map((a) => a.split(":")[0]))];
          if (svcs.length !== 1 || !cat()[svcs[0]]) throw 0;
          v.service = svcs[0];
          v.actions = acts.map((a) => a.split(":")[1]);
          if (v.actions.some((a) => a !== "*" && !cat()[v.service].actions[a])) throw 0;
        }
        for (const [op, kv] of Object.entries(st.Condition || {})) {
          if (op === "DateLessThan" && kv["dpdp:CurrentTime"]) v.until = toLocal(kv["dpdp:CurrentTime"]);
          else if (op === "NumericGreaterThanEquals" && "dpdp:IstHour" in kv) v.hourFrom = kv["dpdp:IstHour"];
          else if (op === "NumericLessThan" && "dpdp:IstHour" in kv) v.hourTo = kv["dpdp:IstHour"];
          else if (op === "StringNotEquals" && JSON.stringify(kv["dpdp:IstWeekday"]) === '["Sat","Sun"]') v.weekdays = true;
          else throw 0;
        }
        return v;
      });
    } catch { return null; }
  }
  function editorHtml() {
    const E = S.editPol, p = E.id ? S.st.policies[E.id] : null, ro = !can("iam:ManagePolicies");
    const stCard = (v, i) => {
      const s = cat()[v.service];
      return `<div class="iam-st ${v.effect === "Deny" ? "deny" : ""}" data-i="${i}">
        <div class="iam-sthead"><div class="seg" role="radiogroup"><button type="button" class="${v.effect === "Allow" ? "on" : ""}" data-eff="Allow">Allow</button><button type="button" class="${v.effect === "Deny" ? "on" : ""}" data-eff="Deny">Deny</button></div>
          <select data-svc aria-label="Service">${Object.entries(cat()).map(([k, x]) => `<option value="${k}" ${v.service === k ? "selected" : ""}>${esc(x.label)}</option>`).join("")}<option value="*" ${v.service === "*" ? "selected" : ""}>Every service (*)</option></select>
          <span class="iam-stn">Statement ${i + 1}</span><button type="button" class="icon-btn" data-act="del-st" aria-label="Remove statement">×</button></div>
        ${v.service === "*" ? `<p class="iam-hint">${v.effect === "Allow" ? "Allows every action in every service, including permissions management." : "Denies every action, which overrides anything other policies allow."}</p>` : `
        <label class="iam-all"><input type="checkbox" data-allacts ${v.actions.includes("*") ? "checked" : ""}> All ${esc(s.label)} actions <code>${esc(v.service)}:*</code> <small>includes actions added later</small></label>
        ${v.actions.includes("*") ? "" : `<div class="iam-levels">${LEVELS.filter((l) => Object.values(s.actions).some((a) => a.level === l)).map((l) => `<div><h5>${l}</h5>${Object.entries(s.actions).filter(([, a]) => a.level === l).map(([a, m]) => `<label title="${esc(m.description)}"><input type="checkbox" data-act-cb value="${a}" ${v.actions.includes(a) ? "checked" : ""}><span><b>${a}</b><small>${esc(m.description)}${m.enforced === "interface" ? " · interface" : ""}</small></span></label>`).join("")}</div>`).join("")}</div>`}`}
        <details class="iam-cond" ${v.until || v.hourFrom !== "" || v.weekdays ? "open" : ""}><summary>Conditions <small>optional: only when…</small></summary>
          <div class="iam-condgrid">
            <label class="field"><span>Until (IST) <small>access expires</small></span><input type="datetime-local" data-c="until" value="${esc(v.until)}"></label>
            <label class="field"><span>Between IST hours <small>e.g. 9 to 18</small></span><span class="iam-hours"><input type="number" min="0" max="23" data-c="hourFrom" value="${esc(v.hourFrom)}" placeholder="from"><span>to</span><input type="number" min="1" max="24" data-c="hourTo" value="${esc(v.hourTo)}" placeholder="to"></span></label>
            <label class="iam-all"><input type="checkbox" data-c="weekdays" ${v.weekdays ? "checked" : ""}> Weekdays only (Mon–Fri)</label>
          </div></details>
      </div>`;
    };
    return `<div class="cp-crumbs"><button class="link" data-act="back">← Policies</button>${p ? `<span class="muted">v${p.version} · saved ${esc(ago(p.updated_at))} by ${esc(p.updated_by)}</span>` : ""}</div>
      <div class="iam-editor">
        <form class="panel iam-form" id="iamPolicy">
          <div class="iam-grid"><label class="field"><span>Policy name</span><input name="name" value="${esc(E.name)}" maxlength="64" placeholder="e.g. BreachResponder" ${ro ? "disabled" : ""}></label>
            <label class="field"><span>Description</span><input name="description" value="${esc(E.description)}" maxlength="300" placeholder="What this policy is for" ${ro ? "disabled" : ""}></label></div>
          <div class="iam-modes"><div class="seg"><button type="button" class="${E.mode === "visual" ? "on" : ""}" data-mode="visual">Visual editor</button><button type="button" class="${E.mode === "json" ? "on" : ""}" data-mode="json">JSON</button></div>
            ${E.mode === "visual" && !E.visual ? `<span class="cp-red">This policy uses JSON the visual editor can't show (e.g. NotAction or mixed services). Edit it as JSON.</span>` : ""}</div>
          ${E.mode === "visual" && E.visual ? `<div class="iam-sts">${E.visual.map(stCard).join("")}</div><button type="button" class="btn ghost" data-act="add-st">+ Add statement</button>`
            : `<textarea id="iamJson" class="iam-json" spellcheck="false" ${ro ? "readonly" : ""}>${esc(E.json)}</textarea>`}
          ${ro ? "" : `<div class="ac-actions">${E.id ? `<button type="button" class="btn ghost danger" data-act="del-policy">Delete</button>` : ""}<input class="iam-note" name="note" placeholder="Change note (optional)" maxlength="200"><button type="button" class="btn ghost" data-act="back">Cancel</button><button class="btn primary">${E.id ? "Save new version" : "Create policy"}</button></div>`}
        </form>
        <aside class="iam-side">
          <div class="panel cp-scard"><h3>Validation</h3><div id="iamVal"><p class="muted">Checking…</p></div></div>
          <div class="panel cp-scard"><h3>Summary</h3><div id="iamSum"></div></div>
          <div class="panel cp-scard"><h3>Test it</h3><p class="rt-help">Run the simulator with this draft added to a user's current policies.</p><button type="button" class="btn ghost" data-act="sim-draft">Open in simulator</button></div>
          ${p?.versions?.length ? `<div class="panel cp-scard"><h3>Versions</h3>${p.versions.map((v) => `<div class="rt-hist"><div><b>v${v.version}</b><span>${esc(ist(v.updated_at))} · ${esc(v.updated_by)}</span><small>${esc(v.note || "")}</small></div>${ro ? "" : `<button class="btn ghost sm" data-restore-pol="${v.version}">Restore</button>`}</div>`).join("")}</div>` : ""}
        </aside>
      </div>`;
  }
  function currentDoc() {
    const E = S.editPol;
    if (E.mode === "visual" && E.visual) return toDoc(E.visual);
    try { return JSON.parse(E.json); } catch { return null; }
  }
  let valT;
  function syncEditor() {
    const E = S.editPol, doc = currentDoc();
    if (E.mode === "visual" && E.visual) E.json = JSON.stringify(doc, null, 2);
    const sum = doc ? summary(doc) : [];
    $("iamSum").innerHTML = sum.length ? `<table class="iam-sumt">${sum.map((x) => `<tr><td><span class="iam-dec ${x.deny ? "deny" : "allow"}">${x.deny ? "Deny" : "Allow"}</span></td><td><b>${esc(x.label)}</b><small>${esc(x.levels.join(", "))}${x.cond ? " · with conditions" : ""}</small></td></tr>`).join("")}</table>` : `<p class="muted">No actions selected yet.</p>`;
    clearTimeout(valT);
    valT = setTimeout(async () => {
      const box = $("iamVal"); if (!box) return;
      if (!doc) { box.innerHTML = `<p class="iam-err">The JSON can't be parsed.</p>`; return; }
      try {
        const r = await api("/api/iam/validate", { method: "POST", body: JSON.stringify({ document: doc }) });
        box.innerHTML = (r.errors.map((x) => `<p class="iam-err">✕ ${esc(x)}</p>`).join("") + r.warnings.map((x) => `<p class="iam-warn">⚠ ${esc(x)}</p>`).join("")) || `<p class="iam-ok">✓ Valid policy</p>`;
      } catch (e) { box.innerHTML = `<p class="iam-err">${esc(e.message)}</p>`; }
    }, 250);
  }
  function openPolicy(id) {
    const p = id ? S.st.policies[id] : null;
    const doc = p ? p.document : { Version: S.st.version, Statement: [] };
    const visual = p ? fromDoc(doc) : [blankSt()];
    S.editPol = { id, name: p?.name || "", description: p?.description || "", mode: visual ? "visual" : "json", visual, json: JSON.stringify(p ? doc : toDoc(visual), null, 2) };
    render();
  }

  /* ---------- Simulator ---------- */
  function simHtml() {
    const f = S.simForm, users = S.st.users || [];
    if (!f.email && users.length) f.email = (users.find((u) => !u.root) || users[0]).email;
    const res = S.simFor === f.email && S.sim ? S.sim : null;
    const rows = res ? res.results.filter((r) => S.simFilter === "all" || r.decision === S.simFilter) : [];
    const n = (d) => (res ? res.results.filter((r) => r.decision === d).length : 0);
    return `<div class="iam-simgrid">
      <form class="panel iam-form" id="iamSim">
        <h3>Policy simulator</h3><p class="iam-hint">Test what a user can do, now or at another time (conditions like office hours and expiry are evaluated), optionally with a draft policy added. Nothing is saved.</p>
        <label class="field"><span>User</span><select name="email">${users.map((u) => `<option value="${esc(u.email)}" ${f.email === u.email ? "selected" : ""}>${esc(u.name || u.email)} (${esc(u.email)})${u.root ? " · root" : ""}</option>`).join("")}</select></label>
        <label class="field"><span>At (IST) <small>empty = now</small></span><input type="datetime-local" name="at" value="${esc(f.at)}"></label>
        <label class="field"><span>Draft policy JSON <small>optional, added to the user's policies</small></span><textarea name="draft" rows="6" class="iam-json sm" spellcheck="false" placeholder='{"Version":"${esc(S.st.version)}","Statement":[...]}'>${esc(f.draft)}</textarea></label>
        <div class="ac-actions"><button class="btn primary">Run simulation</button></div>
      </form>
      <section class="panel iam-simres">
        ${res ? `<div class="iam-simhead"><div><b>${esc(res.email)}</b><span>${res.root ? "Root user: every action is allowed." : `Policies: ${res.policies.map((p) => `${esc(p.name)}${p.via !== "direct" ? ` <small>(${esc(p.via)})</small>` : ""}`).join(", ") || "none"}`} · evaluated at ${esc(ist(res.at))}</span></div>
          <div class="cp-chips">${[["all", "All", res.results.length], ["allow", "Allowed", n("allow")], ["deny", "Explicit deny", n("deny")], ["implicit", "Implicit deny", n("implicit")]].map(([k, l, c]) => `<button class="cp-chip${S.simFilter === k ? " on" : ""}" data-sfilter="${k}">${l} · ${c}</button>`).join("")}</div></div>
          <div class="cp-tablewrap"><table class="cp-ctable"><thead><tr><th>Action</th><th>Access level</th><th>Decision</th><th>Decided by</th></tr></thead><tbody>
          ${rows.map((r) => `<tr><td><code>${esc(r.action)}</code><div class="br-ttl">${esc(r.description)}</div></td><td>${esc(r.level)}</td><td>${decisionPill(r.decision)}</td><td>${r.policy ? `${esc(r.policy)}${r.sid ? ` · <code>${esc(r.sid)}</code>` : ""}${r.via && !["direct", "root"].includes(r.via) ? ` <small class="muted">via ${esc(r.via)}</small>` : ""}` : `<span class="muted">No policy allows it</span>`}</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="cp-empty"><h3>Run a simulation</h3><p>Choose a user and click Run simulation to see every action as Allowed, Explicit deny or Implicit deny, with the policy and statement that decided it.</p></div>`}
      </section></div>`;
  }

  /* ---------- Catalogue ---------- */
  function catalogHtml() {
    return `<p class="rt-note iam-top">Every feature of the dashboard is an action. Use them in policies as <code>service:Action</code>; wildcards like <code>breach:*</code> or <code>*:Read*</code> work. “Server” actions are enforced by the consent service on every request; “Interface” actions are enforced in the dashboard (they read NigraniAI directly, which only checks that you're signed in).</p>
      <section class="panel cp-cpanel"><div class="cp-tablewrap"><table class="cp-ctable"><thead><tr><th>Action</th><th>Service</th><th>Access level</th><th>What it allows</th><th>Enforced</th></tr></thead><tbody>
      ${Object.entries(cat()).map(([svc, s]) => Object.entries(s.actions).map(([a, m]) => `<tr><td><code>${esc(svc)}:${esc(a)}</code></td><td>${esc(s.label)}</td><td>${esc(m.level)}</td><td class="iam-wrap">${esc(m.description)}</td><td>${m.enforced === "server" ? `<span class="iam-dec allow">Server</span>` : `<span class="iam-dec implicit">Interface</span>`}</td></tr>`).join("")).join("")}</tbody></table></div></section>`;
  }

  /* ---------- events ---------- */
  function genPassword() {
    const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", d = "23456789", all = a + d + "!@#$%";
    const r = (s) => s[crypto.getRandomValues(new Uint32Array(1))[0] % s.length];
    return [r(a), r(a), r(d), r(d), ...Array.from({ length: 8 }, () => r(all))].sort(() => crypto.getRandomValues(new Uint8Array(1))[0] - 128).join("");
  }
  const checked = (f, name) => [...f.querySelectorAll(`[name="${name}"]:checked`)].map((x) => x.value);
  async function onClick(e) {
    const t = (s) => e.target.closest(s);
    let b;
    if ((b = t("[data-itab]"))) { S.tab = b.dataset.itab; S.user = S.editPol = S.group = null; S.creating = false; render(); return load(); }
    if ((b = t("[data-user]"))) { S.user = b.dataset.user; S.utab = "permissions"; return render(); }
    if ((b = t("[data-utab]"))) { S.utab = b.dataset.utab; return render(); }
    if ((b = t("[data-policy]"))) return openPolicy(b.dataset.policy);
    if ((b = t("[data-group]"))) { S.group = b.dataset.group; return render(); }
    if ((b = t("[data-sfilter]"))) { S.simFilter = b.dataset.sfilter; return render(); }
    if ((b = t("[data-mode]"))) {
      const E = S.editPol;
      if (b.dataset.mode === "visual") { let doc; try { doc = JSON.parse(E.json); } catch { return toast("Fix the JSON before switching to the visual editor."); } E.visual = fromDoc(doc); }
      else if (E.visual) E.json = JSON.stringify(toDoc(E.visual), null, 2);
      E.mode = b.dataset.mode; return render();
    }
    const card = t(".iam-st"), E = S.editPol;
    if (card && E?.visual) {
      const v = E.visual[+card.dataset.i];
      if ((b = t("[data-eff]"))) { v.effect = b.dataset.eff; return render(); }
      if (t('[data-act="del-st"]')) { E.visual.splice(+card.dataset.i, 1); if (!E.visual.length) E.visual.push(blankSt()); return render(); }
    }
    if ((b = t("[data-restore-pol]"))) {
      if (!window.confirm(`Restore version ${b.dataset.restorePol}? It becomes a new version.`)) return;
      try { await api(`/api/iam/policies/${E.id}/restore/${b.dataset.restorePol}`, { method: "POST", body: "{}" }); toast("Version restored.", true); await load(); openPolicy(E.id); } catch (err) { toast(err.message); }
      return;
    }
    b = t("[data-act]"); if (!b) return;
    const u = S.user && S.st.users.find((x) => x.id === S.user);
    try {
      switch (b.dataset.act) {
        case "back": S.user = S.editPol = S.group = null; S.creating = false; return render();
        case "new-user": S.creating = true; return render();
        case "gen": { const f = b.closest("form").querySelector('[name="password"]'); f.value = genPassword(); return f.select(); }
        case "new-group": S.group = "new"; return render();
        case "new-policy": return openPolicy(null);
        case "add-st": E.visual.push(blankSt()); return render();
        case "sim-draft": { const doc = currentDoc(); if (!doc) return toast("Fix the JSON first."); S.simForm.draft = JSON.stringify(doc, null, 1); S.tab = "simulator"; S.editPol = null; S.sim = null; S.simFor = null; return render(); }
        case "del-policy":
          if (!window.confirm(`Delete policy "${E.name}"? It is detached from every user and group, and their access changes immediately.`)) return;
          await api(`/api/iam/policies/${E.id}`, { method: "DELETE" }); S.editPol = null; toast("Policy deleted.", true); return load();
        case "del-group":
          if (!window.confirm("Delete this group? Members lose the policies it gave them.")) return;
          await api(`/api/iam/groups/${S.group}`, { method: "DELETE" }); S.group = null; toast("Group deleted.", true); return load();
        case "reset-pw": {
          const pw = window.prompt(`New temporary password for ${u.email} (leave empty to generate one).`, "");
          if (pw === null) return;
          const val = pw.trim() || genPassword();
          await api(`/api/iam/users/${u.id}`, { method: "PUT", body: JSON.stringify({ password: val }) });
          window.prompt(`Password reset. Copy it now and share it securely with ${u.email}:`, val); return;
        }
        case "toggle-active":
          if (u.active && !window.confirm(`Deactivate ${u.email}? They can't sign in until reactivated.`)) return;
          await api(`/api/iam/users/${u.id}`, { method: "PUT", body: JSON.stringify({ active: !u.active }) }); toast(u.active ? "User deactivated." : "User reactivated.", true); return load();
        case "remove":
          if (!window.confirm(`Remove ${u.email}? Their account is deleted; their activity stays in the log.`)) return;
          await api(`/api/iam/users/${u.id}`, { method: "DELETE" }); S.user = null; toast("User removed.", true); return load();
      }
    } catch (err) { toast(err.message); }
  }
  function onInput(e) {
    const t = e.target, E = S.editPol;
    if (t.matches("[data-iq]")) { S.q = t.value; const pos = t.selectionStart; render(); const q = document.querySelector("[data-iq]"); q.focus(); q.setSelectionRange(pos, pos); return; }
    if (t.id === "iamJson" && E) { E.json = t.value; return syncEditor(); }
    if (t.closest("#iamPolicy [name]") && E) { E[t.name] = t.value; }
    const card = t.closest(".iam-st");
    if (card && E?.visual && t.dataset.c && t.type !== "checkbox") { E.visual[+card.dataset.i][t.dataset.c] = t.value; syncEditor(); }
  }
  function onChange(e) {
    const t = e.target, E = S.editPol, card = t.closest(".iam-st");
    if (card && E?.visual) {
      const v = E.visual[+card.dataset.i];
      if (t.matches("[data-svc]")) { v.service = t.value; v.actions = t.value === "*" ? ["*"] : []; return render(); }
      if (t.matches("[data-allacts]")) { v.actions = t.checked ? ["*"] : []; return render(); }
      if (t.matches("[data-act-cb]")) { v.actions = [...card.querySelectorAll("[data-act-cb]:checked")].map((x) => x.value); return syncEditor(); }
      if (t.dataset.c === "weekdays") { v.weekdays = t.checked; return syncEditor(); }
    }
    if (t.closest("#iamSim") && t.name === "email") { S.simForm.email = t.value; return render(); }
  }
  async function onSubmit(e) {
    e.preventDefault();
    const f = e.target, v = (n) => f.querySelector(`[name="${n}"]`)?.value.trim();
    const btn = f.querySelector("button.primary:not([type=button])"); if (btn) btn.disabled = true;
    try {
      if (f.id === "iamNewUser") {
        await api("/api/iam/users", { method: "POST", body: JSON.stringify({ name: v("name"), email: v("email"), title: v("title"), password: f.querySelector('[name="password"]').value, groups: checked(f, "groups"), policies: checked(f, "policies") }) });
        toast(`${v("email")} created. Share the temporary password securely.`, true); S.creating = false; await load();
      }
      if (f.id === "iamAccess") {
        await api(`/api/iam/users/${f.dataset.uid}/access`, { method: "PUT", body: JSON.stringify({ groups: checked(f, "groups"), policies: checked(f, "policies") }) });
        toast("Access saved. It applies immediately.", true); S.sim = null; S.simFor = null; await load();
      }
      if (f.id === "iamGroup") {
        const gid = f.dataset.gid;
        await api(gid === "new" ? "/api/iam/groups" : `/api/iam/groups/${gid}`, { method: gid === "new" ? "POST" : "PUT", body: JSON.stringify({ name: v("name"), description: v("description"), members: checked(f, "members"), policies: checked(f, "policies") }) });
        toast("Group saved.", true); S.group = null; await load();
      }
      if (f.id === "iamPolicy") {
        const E = S.editPol, doc = currentDoc();
        if (!doc) throw new Error("The JSON can't be parsed.");
        const body = { name: v("name"), description: v("description"), document: doc, note: v("note"), base_version: E.id ? S.st.policies[E.id].version : undefined };
        const r = await api(E.id ? `/api/iam/policies/${E.id}` : "/api/iam/policies", { method: E.id ? "PUT" : "POST", body: JSON.stringify(body) });
        toast(`Policy saved${r.warnings?.length ? ` with ${r.warnings.length} warning${r.warnings.length === 1 ? "" : "s"}` : ""}.`, true);
        await load(); openPolicy(r.id);
      }
      if (f.id === "iamSim") {
        S.simForm = { email: v("email"), at: f.querySelector('[name="at"]').value, draft: f.querySelector('[name="draft"]').value };
        let draft = null;
        if (S.simForm.draft.trim()) { try { draft = JSON.parse(S.simForm.draft); } catch { throw new Error("The draft policy isn't valid JSON."); } }
        await runSim(S.simForm.email, { at: fromLocal(S.simForm.at), document: draft });
      }
    } catch (err) { toast(err.message); }
    finally { if (btn?.isConnected) btn.disabled = false; }
  }
  let bound = false;
  function bind() {
    if (bound) return; bound = true;
    const v = $("view-iam");
    v.addEventListener("click", onClick); v.addEventListener("input", onInput); v.addEventListener("change", onChange); v.addEventListener("submit", onSubmit);
    v.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches("tr[data-user], tr[data-policy]")) e.target.click(); });
  }
  return { show() { bind(); S.st = null; render(); load(); } };
})();
