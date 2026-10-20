/* Account: the sidebar account menu and the Account page (profile, security,
   settings, users & roles, activity, system status). Profile, password and
   preferences are the user's own Supabase Auth record (user_metadata), so they
   follow the user across devices. Roles, user management, the audit log and system
   status come from consent_service, which enforces the roles on every write.
   Uses session / signedIn / signOut / refreshSession / setTheme / show / DASH_URL / DASH_KEY from app.js. */
const Account = (() => {
  const BASE = ((window.COMPLIANCE_CONFIG || {}).CONSENT_API || "http://localhost:8091").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const F = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", hour12: true });
  const ist = (v) => (v ? F.format(new Date(v)).replace(/\b(am|pm)\b/i, (m) => m.toUpperCase()) : "–");
  function ago(v) {
    if (!v) return "never";
    const m = Math.round((Date.now() - new Date(v)) / 6e4);
    if (m < 1) return "just now"; if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60); if (h < 48) return `${h} h ago`;
    return `${Math.round(h / 24)} days ago`;
  }
  const COLORS = ["#2563eb", "#7c3aed", "#0891b2", "#16a34a", "#db2777", "#ea580c", "#475569"];
  const VIEWS = { dashboard: "Dashboard", telemetry: "Log Telemetry", consent: "Consent & Purpose", retention: "Retention", breach: "Breach Response", ai: "AI Assistant" };
  const TABS = [
    ["profile", "Profile", "Name, title and your access"],
    ["security", "Security", "Password and sessions"],
    ["preferences", "Settings", "Theme, start page, live updates"],
    ["activity", "Activity", "Who did what, and when"],
    ["system", "System status", "Services, data stores and keys", "system:ReadStatus"],
  ];
  const ACTION = {
    "policy.save": ["Saved consent policy", "✎"], "policy.restore": ["Restored consent policy", "↺"], "retention.save": ["Saved retention schedule", "✎"], "retention.restore": ["Restored retention schedule", "↺"],
    "breach.save": ["Saved breach detectors", "✎"], "breach.restore": ["Restored breach detectors", "↺"], "incident.create": ["Reported an incident", "⚑"], "incident.update": ["Updated an incident", "⚑"],
    "signal.link": ["Linked a breach signal", "⚑"], "signal.dismiss": ["Dismissed a breach signal", "✕"], "signal.reopen": ["Reopened a breach signal", "↺"], "ai.ask": ["Asked the AI", "✦"],
    "customer.lookup": ["Looked up a customer", "⌕"], "iam.user.create": ["Added a user", "+"], "iam.user.update": ["Changed a user", "⚙"], "iam.user.delete": ["Removed a user", "−"],
    "iam.user.access": ["Changed a user's access", "🔑"], "iam.policy.save": ["Saved a policy", "📜"], "iam.policy.delete": ["Deleted a policy", "📜"], "iam.group.save": ["Saved a group", "👥"], "iam.group.delete": ["Deleted a group", "👥"],
    "access.denied": ["Access denied", "⛔"],
  };

  const S = { me: null, tab: "profile", audit: null, auditScope: "me", auditFilter: "", system: null, adding: false, busy: false, menuOpen: false };

  /* ---------- APIs ---------- */
  async function api(path, opts = {}) {
    const go = () => fetch(BASE + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${session?.access_token || ""}`, ...(opts.body ? { "Content-Type": "application/json" } : {}) } });
    let r;
    try { r = await go(); } catch { throw new Error("The consent service isn't running."); }
    if (r.status === 401 && session?.refresh_token) { try { await refreshSession(); r = await go(); } catch {} }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    return j;
  }
  async function authUser(body) {
    const r = await fetch(`${DASH_URL}/auth/v1/user`, { method: "PUT", headers: { apikey: DASH_KEY, Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.msg || j.error_description || j.message || `Request failed (${r.status})`);
    session.user = j; signedIn(session, true);
    return j;
  }

  /* ---------- identity helpers ---------- */
  const user = () => session?.user || {};
  const meta = () => user().user_metadata || {};
  const nameOf = () => meta().name || (user().email || "").split("@")[0];
  const initials = (n, e) => ((n || e || "?").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2) || "?").toUpperCase();
  const colorOf = () => meta().avatar_color || COLORS[0];
  const accessPill = () => (!S.me ? "" : S.me.root ? `<span class="role-chip root">Root</span>` : `<span class="role-chip ${S.me.allowed.length ? "admin" : "viewer"}">${S.me.allowed.length ? `${S.me.allowed.length} permission${S.me.allowed.length === 1 ? "" : "s"}` : "No access yet"}</span>`);
  const avatar = (n, e, c, cls = "") => `<span class="avatar ${cls}" style="background:${esc(c)};color:#fff">${esc(initials(n, e))}</span>`;
  const canDo = (a) => can(a);

  /* ---------- preferences (user_metadata.prefs; cached in localStorage) ---------- */
  const DEFAULT_PREFS = { theme: "light", start: "dashboard", live: true };
  function prefs() {
    let local = {};
    try { local = JSON.parse(localStorage.getItem("prefs")) || {}; } catch {}
    return { ...DEFAULT_PREFS, ...local, ...(meta().prefs || {}) };
  }
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  function applyTheme(p = prefs()) { setTheme(p.theme === "system" ? (mq.matches ? "dark" : "light") : p.theme, true); }
  mq.addEventListener?.("change", () => { if (prefs().theme === "system") applyTheme(); });
  let saveT;
  function setPref(k, v) {
    const p = { ...prefs(), [k]: v };
    try { localStorage.setItem("prefs", JSON.stringify(p)); } catch {}
    if (k === "theme") applyTheme(p);
    if (k === "live") $("live").checked = v;
    clearTimeout(saveT);
    saveT = setTimeout(() => authUser({ data: { prefs: p } }).then(() => toast("Settings saved to your account.", true)).catch((e) => toast(e.message)), 500);
    renderMenu(); if (!$("view-account").hidden) render();
  }

  /* ---------- sidebar account button + menu ---------- */
  function renderMenu() {
    const n = nameOf(), e = user().email || "", c = colorOf();
    const a = $("avatar"); a.textContent = initials(n, e); a.style.background = c; a.style.color = "#fff";
    $("acctName").textContent = n;
    $("acctRole").innerHTML = accessPill();
    if ($("wsName")) $("wsName").textContent = S.me?.client?.name || "";
    $("menuHead").innerHTML = `${avatar(n, e, c, "lg")}<div><b>${esc(n)}</b><small id="userEmail">${esc(e)}</small>${accessPill()}</div>`;
    document.querySelectorAll("#acctMenu [data-need]").forEach((b) => (b.hidden = !b.dataset.need.split("|").some(canDo)));
    const t = prefs().theme;
    document.querySelectorAll("#acctMenu [data-theme-pref]").forEach((b) => { const on = b.dataset.themePref === t; b.classList.toggle("on", on); b.setAttribute("aria-checked", on); });
  }
  function openMenu(open) {
    S.menuOpen = open ?? !S.menuOpen;
    $("acctMenu").hidden = !S.menuOpen;
    $("acctBtn").setAttribute("aria-expanded", S.menuOpen);
    if (S.menuOpen) $("acctMenu").querySelector("button:not([hidden])")?.focus();
  }

  /* ---------- Account page ---------- */
  function render() {
    const n = nameOf(), u = user(), visible = TABS.filter((t) => !t[3] || canDo(t[3]));
    if (!visible.some((t) => t[0] === S.tab)) S.tab = "profile";
    $("acctHead").innerHTML = `${avatar(n, u.email, colorOf(), "xl")}
      <div class="ac-id"><div class="ac-name"><h2>${esc(n)}</h2>${accessPill()}</div>
        <p>${esc(meta().title || "")}${meta().title ? " · " : ""}${esc(u.email || "")}</p>
        <div class="ac-facts"><span>Member since <b>${esc(ist(u.created_at).split(",")[0])}</b></span><span>Last sign-in <b>${esc(ago(u.last_sign_in_at))}</b></span><span>Sign-in <b>Email + password</b></span></div></div>`;
    $("acctNav").innerHTML = visible.map(([k, l, d]) => `<button class="${S.tab === k ? "on" : ""}" data-tab="${k}" aria-current="${S.tab === k ? "page" : "false"}"><b>${esc(l)}</b><span>${esc(d)}</span></button>`).join("");
    $("acctBody").innerHTML = { profile: profileHtml, security: securityHtml, preferences: prefsHtml, activity: activityHtml, system: systemHtml }[S.tab]();
  }
  const section = (title, sub, body, extra = "") => `<section class="ac-sec"><div class="ac-sech"><div><h3>${esc(title)}</h3>${sub ? `<p>${sub}</p>` : ""}</div>${extra}</div>${body}</section>`;

  function profileHtml() {
    const c = colorOf();
    return section("Profile", "How you appear across the dashboard, in incident activity and policy history.", `
      <form id="acProfile" class="ac-form">
        <label class="field"><span>Display name</span><input name="name" type="text" maxlength="80" value="${esc(meta().name || "")}" placeholder="Your name"></label>
        <label class="field"><span>Job title</span><input name="title" type="text" maxlength="80" value="${esc(meta().title || "")}" placeholder="e.g. Data Protection Officer"></label>
        <div class="field"><span>Avatar colour</span><div class="ac-swatches" role="radiogroup" aria-label="Avatar colour">${COLORS.map((x) => `<button type="button" role="radio" aria-checked="${x === c}" class="${x === c ? "on" : ""}" style="background:${x}" data-color="${x}" aria-label="Colour ${x}"></button>`).join("")}</div></div>
        <label class="field"><span>Email <small>sign-in identity, managed in Supabase Auth</small></span><input type="email" value="${esc(user().email || "")}" disabled></label>
        <div class="ac-actions"><button class="btn primary" type="submit">Save profile</button></div>
      </form>`)
    + accessHtml();
  }
  function accessHtml() {
    if (!S.me) return section("Your access", "Loading…", "");
    if (S.me.root) return section("Your access", `You are the root user of <b>${esc(S.me.client?.name || "")}</b>'s NigraniAI dashboard: every action is allowed and no policy can restrict you. Use Access management to decide what everyone else can do.`, "", `<button class="btn ghost" data-go-iam>Access management →</button>`);
    const cat = S.me.catalogMeta || {}, byS = {};
    for (const a of S.me.allowed) (byS[a.split(":")[0]] ||= []).push(a.split(":")[1]);
    return section("Your access", S.me.allowed.length ? `Granted by ${S.me.policies.length ? S.me.policies.map((p) => `<b>${esc(p)}</b>`).join(", ") : "your policies"}. Everything else is denied by default. Ask the root user if you need more.` : "No policy is attached to you yet, so every action is denied. Ask the root user to give you access.",
      S.me.allowed.length ? `<div class="ac-access">${Object.entries(byS).map(([svc, acts]) => `<div><b>${esc(cat[svc] || svc)}</b><span>${acts.map((x) => `<code>${esc(x)}</code>`).join(" ")}</span></div>`).join("")}</div>` : "");
  }
  function securityHtml() {
    const exp = session?.expires_at ? new Date(session.expires_at * 1000) : null;
    return section("Change password", "You'll stay signed in on this device. Use at least 8 characters with letters and numbers.", `
      <form id="acPassword" class="ac-form narrow" autocomplete="off">
        <label class="field"><span>Current password</span><input name="current" type="password" autocomplete="current-password" required></label>
        <label class="field"><span>New password</span><input name="next" type="password" autocomplete="new-password" required minlength="8"></label>
        <div class="ac-meter" aria-hidden="true"><i></i></div><small class="ac-mtext" id="acMeterText"></small>
        <label class="field"><span>Confirm new password</span><input name="confirm" type="password" autocomplete="new-password" required></label>
        <div class="ac-actions"><button class="btn primary" type="submit">Update password</button></div>
      </form>`)
    + section("Sessions", "Sessions refresh automatically while you use the dashboard.", `
      <div class="ac-kv"><span>This device</span><b>Signed in · ${esc(navigator.userAgent.match(/(Chrome|Firefox|Safari|Edg)\/[\d.]+/)?.[0]?.replace("Edg", "Edge") || "Browser")}</b></div>
      <div class="ac-kv"><span>Last sign-in</span><b>${esc(ist(user().last_sign_in_at))}</b></div>
      <div class="ac-kv"><span>Access token renews</span><b>${exp ? esc(ist(exp)) : "–"}</b></div>
      <div class="ac-actions split"><button class="btn ghost" data-act="signout">Sign out</button><button class="btn ghost danger" data-act="signout-all">Sign out of all devices</button></div>`);
  }
  function prefsHtml() {
    const p = prefs();
    const seg = (k, opts) => `<div class="seg" role="radiogroup">${opts.map(([v, l]) => `<button role="radio" aria-checked="${p[k] === v}" class="${p[k] === v ? "on" : ""}" data-pref="${k}" data-val="${v}">${l}</button>`).join("")}</div>`;
    return section("Appearance", "", `<div class="ac-row"><div><b>Theme</b><span>System follows your computer's light or dark setting.</span></div>${seg("theme", [["light", "Light"], ["dark", "Dark"], ["system", "System"]])}</div>`)
      + section("Behaviour", "Saved to your account, so they follow you to other devices.", `
        <div class="ac-row"><div><b>Start page</b><span>Where the dashboard opens after you sign in.</span></div><select data-pref-select="start">${Object.entries(VIEWS).map(([k, l]) => `<option value="${k}" ${p.start === k ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></div>
        <div class="ac-row"><div><b>Live updates</b><span>Refresh logs, charts and checks automatically. You can still pause from the top bar.</span></div><label class="switch"><input type="checkbox" data-pref-check="live" ${p.live ? "checked" : ""}><i></i></label></div>
        <div class="ac-row"><div><b>Time zone</b><span>Every time is shown in IST, the reference for DPDP reporting.</span></div><b class="muted">Asia/Kolkata (IST)</b></div>`)
      + section("AI assistant", "", `<div class="ac-row"><div><b>Saved conversations</b><span>AI conversations are kept in this browser only.</span></div><button class="btn ghost danger" data-act="clear-ai">Clear conversations</button></div>`);
  }
  function activityHtml() {
    if (!S.audit) { loadAudit(); return section("Activity", "", `<p class="muted">Loading activity…</p>`); }
    if (S.audit.error) return section("Activity", "", `<p class="cp-red">${esc(S.audit.error)}</p>`);
    const groups = { "": "All", policy: "Policies", incident: "Breach", signal: "Signals", ai: "AI", customer: "Lookups", iam: "Access", access: "Denied" };
    const list = S.audit.events.filter((e) => !S.auditFilter || e.action.split(".")[0] === S.auditFilter || (S.auditFilter === "policy" && /^(policy|retention|breach)\./.test(e.action)));
    let day = "";
    const rows = list.map((e) => {
      const d = new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", weekday: "short", day: "numeric", month: "short", year: "numeric" }).format(new Date(e.at));
      const head = d !== day ? `<li class="ac-day">${esc(d)}</li>` : ""; day = d;
      const [label, icon] = ACTION[e.action] || [e.action, "•"];
      return `${head}<li class="ac-ev"><span class="ac-evi">${esc(icon)}</span><div><b>${esc(label)}</b>${e.detail ? `<span>${esc(e.detail)}</span>` : ""}</div><small>${S.audit.scope === "all" ? `${esc(e.user)} · ` : ""}${esc(new Intl.DateTimeFormat("en-IN", { timeZone: "Asia/Kolkata", hour: "numeric", minute: "2-digit", hour12: true }).format(new Date(e.at)).toUpperCase())}</small></li>`;
    }).join("");
    return section("Activity", "Saved policies, breach actions, signal decisions, customer lookups, AI questions and user changes. Lookups record how many matched, never what was searched.", `
      <div class="ac-tools">${canDo("iam:ReadAllActivity") ? `<div class="seg"><button class="${S.auditScope === "me" ? "on" : ""}" data-scope="me">Mine</button><button class="${S.auditScope === "all" ? "on" : ""}" data-scope="all">Everyone</button></div>` : ""}
        <div class="cp-chips">${Object.entries(groups).map(([k, l]) => `<button class="cp-chip${S.auditFilter === k ? " on" : ""}" data-afilter="${k}">${l}</button>`).join("")}</div></div>
      ${list.length ? `<ol class="ac-feed">${rows}</ol>` : `<p class="muted ac-empty">No activity recorded yet. Actions you take from now on appear here.</p>`}`,
      `<button class="btn ghost" data-act="audit-csv" ${list.length ? "" : "disabled"}>Export CSV</button>`);
  }
  function systemHtml() {
    if (!S.system) { loadSystem(); return section("System status", "", `<p class="muted">Checking…</p>`); }
    if (S.system.error) return section("System status", "", `<p class="cp-red">${esc(S.system.error)}</p>`);
    const y = S.system, ok = (b, t = "Connected", f = "Not configured") => `<span class="ac-st ${b ? "ok" : "bad"}"><i></i>${b ? t : f}</span>`;
    const up = (s) => (s > 86400 ? `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h` : s > 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min` : `${Math.max(1, Math.floor(s / 60))} min`);
    const card = (t, st, rows) => `<div class="ac-card"><div class="ac-cardh"><b>${esc(t)}</b>${st}</div>${rows.map(([k, v]) => `<div class="ac-kv"><span>${esc(k)}</span><b>${v}</b></div>`).join("")}</div>`;
    const NAMES = { policy: "Consent policy", retention: "Retention schedule", breach: "Breach detectors" };
    return section("System status", "Live view of the services behind this dashboard. Keys are never shown.", `
      <div class="ac-cards">
        ${card("Consent service", ok(true, "Running"), [["Up for", esc(up(y.service.uptime_s))], ["Port", esc(y.service.port)], ["Allowed origins", esc(y.service.allowed_origins.join(", "))]])}
        ${card("NigraniAI (logs + sign-in)", ok(true), [["Project", `<code>${esc(y.guardrail.url.replace(/^https:\/\//, ""))}</code>`], ["Schema", esc(y.guardrail.schema)], ["User management", y.guardrail.user_admin ? "Enabled" : "Service key missing"]])}
        ${card("ShopSmart shop database", ok(y.shop.configured, "Connected (read-only)"), [["Project", `<code>${esc((y.shop.url || "").replace(/^https:\/\//, ""))}</code>`], ["Tables seen", esc(y.shop.tables ?? "–")], ["Access", "GET only, personal columns stripped"]])}
        ${card("AI assistant", ok(y.ai.configured), [["Provider", esc(y.ai.provider)], ["Model", esc(y.ai.model || "–")], ["Context budget", `${esc(y.ai.context_chars.toLocaleString("en-IN"))} chars`]])}
      </div>
      <div class="ac-matrixwrap"><table class="ac-matrix left"><thead><tr><th>Versioned store</th><th>Version</th><th>Last saved</th><th>By</th></tr></thead>
        <tbody>${Object.entries(y.stores).map(([k, v]) => `<tr><td>${esc(NAMES[k] || k)}</td><td>v${esc(v.version)}</td><td>${esc(ist(v.updated_at))}</td><td>${esc(v.updated_by)}</td></tr>`).join("")}
        <tr><td>Breach register</td><td>${esc(y.incidents)} incidents</td><td colspan="2">${esc(y.triaged_signals)} signals triaged</td></tr>
        <tr><td>Audit log</td><td colspan="3">${esc(y.audit_events)} events</td></tr>
        ${y.usage ? `<tr><td>Usage plan</td><td colspan="3">${esc(y.usage.plan)} · cycle from ${esc(new Date(y.usage.cycle_start).toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata", day: "numeric", month: "short" }))}</td></tr>` : ""}</tbody></table></div>
      <p class="ac-note">Built for <b>${esc(y.client?.name || "")}</b> · root user <b>${esc(y.root_email)}</b> (<code>ROOT_EMAIL</code> in <code>.env</code>) · online payments ${y.payments?.online ? (y.payments.test_mode ? "in test mode" : "live") : "not set up"}.</p>`, `<button class="btn ghost" data-act="sys-refresh">Check again</button>`);
  }

  /* ---------- loaders ---------- */
  async function loadMe() {
    try {
      S.me = await api("/api/me");
      S.me.catalog = S.me.catalog || [];
    } catch { S.me = null; }
    ME = S.me;
    try { const c = await api("/api/iam/catalog"); S.me && (S.me.catalog = c.actions, S.me.catalogMeta = c.services); } catch {}
    applyAccess(); renderMenu();
    if (typeof Usage !== "undefined") Usage.banner();
    if (!$("view-account").hidden) render();
  }
  async function loadAudit() { try { S.audit = await api(`/api/audit?scope=${S.auditScope}&limit=400`); } catch (e) { S.audit = { error: e.message }; } if (S.tab === "activity") render(); }
  async function loadSystem() { try { S.system = await api("/api/system"); } catch (e) { S.system = { error: e.message }; } if (S.tab === "system") render(); }

  let toastT;
  function toast(m, ok = false) { const t = $("acToast"); t.textContent = m; t.className = "ttoast" + (ok ? " ok" : ""); t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 4500); }
  function strength(pw) {
    let s = 0;
    if (pw.length >= 8) s++; if (pw.length >= 12) s++; if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++; if (/\d/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(4, s);
  }

  /* ---------- events ---------- */
  async function onClick(e) {
    const t = (s) => e.target.closest(s);
    let b;
    if ((b = t("[data-tab]"))) { S.tab = b.dataset.tab; return render(); }
    if (t("[data-go-iam]")) return show("iam");
    if ((b = t("[data-color]"))) { document.querySelectorAll(".ac-swatches button").forEach((x) => { const on = x === b; x.classList.toggle("on", on); x.setAttribute("aria-checked", on); }); return; }
    if ((b = t("[data-pref]"))) return setPref(b.dataset.pref, b.dataset.val);
    if ((b = t("[data-scope]"))) { S.auditScope = b.dataset.scope; S.audit = null; return render(); }
    if ((b = t("[data-afilter]"))) { S.auditFilter = b.dataset.afilter; return render(); }
    b = t("[data-act]"); if (!b) return;
    try {
      switch (b.dataset.act) {
        case "signout": return signOut();
        case "signout-all":
          if (!window.confirm("Sign out of every device, including this one?")) return;
          await fetch(`${DASH_URL}/auth/v1/logout?scope=global`, { method: "POST", headers: { apikey: DASH_KEY, Authorization: `Bearer ${session.access_token}` } });
          return signOut();
        case "clear-ai": if (!window.confirm("Delete all AI conversations saved in this browser?")) return; try { localStorage.removeItem("aiChats"); } catch {} return toast("AI conversations cleared. Reload the AI page to see the change.", true);
        case "audit-csv": {
          const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
          const lines = [["Time (IST)", "User", "Action", "Detail"].map(q).join(","), ...S.audit.events.map((x) => [ist(x.at), x.user, (ACTION[x.action] || [x.action])[0], x.detail].map(q).join(","))];
          const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" })), download: `activity-${S.auditScope}.csv` });
          a.click(); return setTimeout(() => URL.revokeObjectURL(a.href), 1000);
        }
        case "sys-refresh": S.system = null; return render();
      }
    } catch (err) { toast(err.message); }
  }
  async function onSubmit(e) {
    const f = e.target;
    e.preventDefault();
    const v = (n) => f.querySelector(`[name="${n}"]`)?.value.trim();
    const btn = f.querySelector('[type="submit"]');
    btn.disabled = true;
    try {
      if (f.id === "acProfile") {
        const color = f.querySelector(".ac-swatches .on")?.dataset.color || colorOf();
        await authUser({ data: { name: v("name"), title: v("title"), avatar_color: color } });
        renderMenu(); render(); toast("Profile saved.", true);
      }
      if (f.id === "acPassword") {
        const cur = f.querySelector('[name="current"]').value, next = f.querySelector('[name="next"]').value, conf = f.querySelector('[name="confirm"]').value;
        if (next !== conf) throw new Error("The new passwords don't match.");
        if (next.length < 8 || !/[A-Za-z]/.test(next) || !/\d/.test(next)) throw new Error("Use at least 8 characters with letters and numbers.");
        if (next === cur) throw new Error("Choose a password different from the current one.");
        // Re-check the current password before changing it.
        const r = await fetch(`${DASH_URL}/auth/v1/token?grant_type=password`, { method: "POST", headers: { apikey: DASH_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ email: user().email, password: cur }) });
        if (!r.ok) throw new Error("Your current password is incorrect.");
        const fresh = await r.json();
        signedIn({ ...fresh, expires_at: Math.floor(Date.now() / 1000) + (fresh.expires_in || 3600) }, true);
        await authUser({ password: next });
        f.reset(); toast("Password updated.", true);
      }
    } catch (err) { toast(err.message); }
    finally { btn.disabled = false; }
  }
  function onInput(e) {
    if (e.target.name === "next" && e.target.closest("#acPassword")) {
      const s = strength(e.target.value), m = document.querySelector(".ac-meter");
      m.dataset.s = e.target.value ? s : "";
      $("acMeterText").textContent = e.target.value ? ["Too weak", "Weak", "Fair", "Good", "Strong"][s] : "";
    }
  }
  async function onChange(e) {
    const t = e.target;
    if (t.matches("[data-pref-select]")) return setPref(t.dataset.prefSelect, t.value);
    if (t.matches("[data-pref-check]")) return setPref(t.dataset.prefCheck, t.checked);
  }

  let bound = false;
  function bind() {
    if (bound) return; bound = true;
    $("acctBtn").onclick = (e) => { e.stopPropagation(); openMenu(); };
    $("acctMenu").addEventListener("click", (e) => {
      const b = e.target.closest("[data-acct], [data-theme-pref]");
      if (!b) return;
      if (b.dataset.themePref) return setPref("theme", b.dataset.themePref);
      openMenu(false);
      if (b.dataset.acct === "iam") return show("iam");
      if (b.dataset.acct === "usage") return show("usage");
      S.tab = b.dataset.acct; show("account");
    });
    document.addEventListener("click", (e) => { if (S.menuOpen && !e.target.closest("#acctMenu, #acctBtn")) openMenu(false); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && S.menuOpen) { openMenu(false); $("acctBtn").focus(); } });
    const v = $("view-account");
    v.addEventListener("click", onClick); v.addEventListener("submit", onSubmit); v.addEventListener("input", onInput); v.addEventListener("change", onChange);
  }

  return {
    refreshMe: loadMe,
    // Called by app.js after every interactive sign-in or session restore.
    init() {
      bind();
      S.audit = S.system = null;
      applyTheme();
      $("live").checked = prefs().live !== false;
      renderMenu();
      loadMe();
      return prefs().start;
    },
    show(tab) { if (tab) S.tab = tab; S.audit = S.tab === "activity" ? null : S.audit; S.system = S.tab === "system" ? null : S.system; render(); },
    refreshMenu: renderMenu,
  };
})();
