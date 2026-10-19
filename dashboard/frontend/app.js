/* Compliance Dashboard shell: login, navigation, theme, and the main dashboard
   (dashboard.js). Log Telemetry lives in telemetry.js, the other sections in
   consent.js, retention.js and breach.js. */
const CFG = window.COMPLIANCE_CONFIG || {};
const DASH_URL = (CFG.DASHBOARD_URL || "").replace(/\/$/, "");
const DASH_KEY = CFG.DASHBOARD_ANON_KEY || "";
const DB_SCHEMA = CFG.DB_SCHEMA || "guardrail";

// Data requests carry the signed-in user's JWT; the "signed-in read" RLS
// policies on guardrail decide what it can see (anon key alone sees nothing).
let session = null, currentView = "dashboard", firstShow = true;
// Effective permissions from consent_service (/api/me): {email, root, allowed: [actions]}. Deny by default.
let ME = null;
const can = (action) => !!ME && (ME.root || ME.allowed.includes(action));
// The action each section needs before it appears in the navigation.
const VIEW_ACTION = { dashboard: "dashboard:View", telemetry: "telemetry:ReadLogs", consent: "consent:ReadFindings", retention: "retention:ReadSchedule", breach: "breach:ReadSignals", ai: "ai:Ask", iam: null, usage: null, readiness: null, datamap: "datamap:Read", account: null };
const canUsage = () => can("usage:ViewOwnUsage") || can("usage:ViewAllUsage");
function applyAccess() {
  document.querySelectorAll("#nav [data-view]").forEach((b) => (b.hidden = b.dataset.view === "iam" ? !(can("iam:ListUsers") || can("iam:ListPolicies")) : b.dataset.view === "usage" ? !canUsage() : b.dataset.view === "readiness" ? !(can("readiness:Read") || can("readiness:Run")) : !!VIEW_ACTION[b.dataset.view] && !can(VIEW_ACTION[b.dataset.view])));
  // body.deny-<service>-<Action> for every action not allowed; style.css hides the matching controls.
  const cls = [...document.body.classList].filter((c) => !c.startsWith("deny-"));
  document.body.className = cls.join(" ");
  if (ME && !ME.root) for (const a of ME.catalog || []) if (!ME.allowed.includes(a)) document.body.classList.add(`deny-${a.replace(":", "-")}`);
  if (ME && VIEW_ACTION[currentView] && !can(VIEW_ACTION[currentView])) show(firstAllowed());
  if (ME && currentView === "usage" && !canUsage()) show(firstAllowed());
  billingBanner();
  if ($("wsName")) $("wsName").textContent = ME?.client?.name || "";
  if (ME && currentView === "datamap") DataMap.access();
  if (ME && typeof Dashboard !== "undefined") Dashboard.access();
}
const firstAllowed = () => Object.keys(VIEW_ACTION).find((v) => VIEW_ACTION[v] && can(VIEW_ACTION[v])) || "account";
const $ = (id) => document.getElementById(id);

/* ---------- REST ---------- */
// fetch with the user's token; on 401 (expired JWT) refresh once and retry.
async function authedFetch(url, opts = {}) {
  const go = () => fetch(url, { ...opts, headers: { ...opts.headers, apikey: DASH_KEY, Authorization: `Bearer ${session?.access_token || DASH_KEY}` } });
  let r = await go();
  if (r.status === 401 && session?.refresh_token) {
    try { await refreshSession(); r = await go(); } catch { signOut(); }
  }
  return r;
}
async function rest(path, params = {}) {
  const u = new URL(`${DASH_URL}/rest/v1${path}`);
  Object.entries(params).forEach(([k, v]) => { if (v !== "" && v != null) u.searchParams.set(k, v); });
  const r = await authedFetch(u, { headers: { "Accept-Profile": DB_SCHEMA } });
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}

/* ---------- Theme ---------- */
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("theme", t); } catch {}
  document.querySelectorAll("[data-theme-set]").forEach((b) => {
    const on = b.dataset.themeSet === t;
    b.classList.toggle("on", on); b.setAttribute("aria-checked", on);
  });
}
document.querySelectorAll("[data-theme-set]").forEach((b) => (b.onclick = () => setTheme(b.dataset.themeSet)));
setTheme(document.documentElement.dataset.theme || "light");

/* ---------- Auth (Supabase GoTrue) ---------- */
const LS_KEY = "comp_session";
const loadStored = () => { try { return JSON.parse(localStorage.getItem(LS_KEY)); } catch { return null; } };
const store = (s) => { try { s ? localStorage.setItem(LS_KEY, JSON.stringify(s)) : localStorage.removeItem(LS_KEY); } catch {} };

async function auth(path, body) {
  const r = await fetch(`${DASH_URL}/auth/v1${path}`, {
    method: "POST", headers: { apikey: DASH_KEY, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.msg || d.error_description || d.error || `Request failed (${r.status})`);
  return d;
}
const withExpiry = (d) => ({ ...d, expires_at: d.expires_at || Math.floor(Date.now() / 1000) + (d.expires_in || 3600) });

let refreshTimer, refreshing = null;
// One in-flight refresh shared by the timer and any 401 retries.
function refreshSession() {
  refreshing ||= auth("/token?grant_type=refresh_token", { refresh_token: session.refresh_token })
    .then((d) => signedIn(withExpiry(d), true))
    .finally(() => (refreshing = null));
  return refreshing;
}
function scheduleRefresh(s) {
  clearTimeout(refreshTimer);
  const ms = Math.max(30, s.expires_at - Math.floor(Date.now() / 1000) - 120) * 1000;
  refreshTimer = setTimeout(() => refreshSession().catch(signOut), ms);
}

async function restoreSession() {
  const s = loadStored();
  if (!s?.access_token) return false;
  try {
    if (s.expires_at && s.expires_at - Date.now() / 1000 > 60) {
      const r = await fetch(`${DASH_URL}/auth/v1/user`, { headers: { apikey: DASH_KEY, Authorization: `Bearer ${s.access_token}` } });
      if (r.ok) { signedIn({ ...s, user: await r.json() }); return true; }
    }
    if (s.refresh_token) { signedIn(withExpiry(await auth("/token?grant_type=refresh_token", { refresh_token: s.refresh_token }))); return true; }
  } catch {}
  store(null);
  return false;
}

$("loginForm").onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("loginBtn"), err = $("loginErr");
  const email = $("email").value.trim(), password = $("password").value;
  err.textContent = "";
  if (!email || !password) { err.textContent = "Enter your email and password."; return; }
  btn.disabled = true; btn.classList.add("loading"); btn.textContent = "Signing in…";
  try {
    signedIn(withExpiry(await auth("/token?grant_type=password", { email, password })));
  } catch (ex) {
    err.textContent = /invalid/i.test(ex.message) ? "Incorrect email or password." : ex.message;
    $("password").select();
  } finally { btn.disabled = false; btn.classList.remove("loading"); btn.textContent = "Sign in"; }
};
$("pwToggle").onclick = () => {
  const p = $("password"), show = p.type === "password";
  p.type = show ? "text" : "password";
  $("pwToggle").setAttribute("aria-label", show ? "Hide password" : "Show password");
  $("pwToggle").classList.toggle("on", show);
};

function signedIn(s, silent = false) {
  session = s; store(s); scheduleRefresh(s);
  if (silent) return;
  document.activeElement?.blur?.(); // close any browser autofill popup on the login form
  $("loginView").hidden = true; $("appView").hidden = false;
  // Profile, role and saved preferences (theme, start page, live updates).
  const start = Account.init();
  const linked = location.hash.slice(1); // a refresh or a bookmarked #view opens that view
  let target = firstShow ? (TITLES[linked] && linked !== "account" ? linked : TITLES[start] ? start : currentView) : currentView;
  if (VIEW_ACTION[target] && ME && !can(VIEW_ACTION[target])) target = firstAllowed();
  show(target, { replace: true });
  firstShow = false;
}
async function signOut() {
  clearTimeout(refreshTimer);
  try { if (session?.access_token) await fetch(`${DASH_URL}/auth/v1/logout`, { method: "POST", headers: { apikey: DASH_KEY, Authorization: `Bearer ${session.access_token}` } }); } catch {}
  store(null); session = null; firstShow = true; ME = null;
  $("appView").hidden = true; $("loginView").hidden = false;
  $("password").value = ""; $("email").focus();
}
$("logoutBtn").onclick = signOut;

/* ---------- Navigation ---------- */
const TITLES = { dashboard: "Dashboard", telemetry: "Log Telemetry", consent: "Consent & Purpose", retention: "Retention", breach: "Breach Response", ai: "AI Assistant", iam: "Access management", usage: "Usage & plan", readiness: "DPDP readiness", datamap: "Data map", account: "Account" };
// An unpaid invoice shows on every page (with Pay now for people who may see billing).
function billingBanner() {
  const el = $("billBanner"), bl = ME?.billing;
  if (!el) return;
  el.hidden = !(bl && (bl.overdue || bl.restricted));
  if (el.hidden) return;
  el.innerHTML = `<span><b>${bl.restricted ? "Free-plan limits apply:" : "Invoice overdue:"}</b> ₹${Number(bl.amount_due).toLocaleString("en-IN")} unpaid.${bl.restricted ? " Pay to restore your plan; monitoring keeps running." : bl.limit_on ? ` Free-plan limits from ${new Date(bl.limit_on).toLocaleDateString("en-IN", { day: "numeric", month: "short" })} if unpaid.` : ""}</span><button class="link" onclick="Usage.openBilling()">Pay now</button>`;
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function show(view, opts = {}) {
  if (ME && VIEW_ACTION[view] && !can(VIEW_ACTION[view])) view = firstAllowed();
  currentView = view;
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  $("viewTitle").textContent = TITLES[view];
  Object.keys(TITLES).forEach((v) => ($(`view-${v}`).hidden = v !== view));
  $("tStatus").hidden = view !== "telemetry";
  $("live").closest("label").hidden = view === "account" || view === "ai" || view === "iam" || view === "readiness";
  billingBanner();
  if (view === "usage" && ME && !canUsage()) return show(firstAllowed(), { replace: true });
  // Each view is its own browser history entry (#view), so Back and Forward move between views
  // instead of leaving the dashboard.
  if (!opts.fromHistory && location.hash !== `#${view}`) history[opts.replace ? "replaceState" : "pushState"]({ view }, "", `#${view}`);
  if (typeof Usage !== "undefined") Usage.banner();
  if (view === "dashboard") Dashboard.show();
  else if (view === "telemetry") Telemetry.show();
  else if (view === "consent") Consent.show();
  else if (view === "retention") Retention.show();
  else if (view === "breach") Breach.show();
  else if (view === "ai") AI.show();
  else if (view === "account") Account.show();
  else if (view === "iam") IAM.show();
  else if (view === "usage") Usage.show();
  else if (view === "readiness") Readiness.show();
  else if (view === "datamap") DataMap.show();
}
document.querySelectorAll("#nav button").forEach((b) => (b.onclick = () => show(b.dataset.view)));
window.addEventListener("popstate", () => {
  const v = location.hash.slice(1);
  if (session && !$("appView").hidden && TITLES[v] && v !== currentView) show(v, { fromHistory: true });
});

// The "Live" badge in each section header follows the Live switch.
function syncLivePills() { const on = $("live").checked; document.querySelectorAll(".vh-live").forEach((p) => { p.classList.toggle("off", !on); p.textContent = on ? "Live" : "Paused"; }); }
syncLivePills();
$("live").addEventListener("change", () => { syncLivePills(); if (currentView === "datamap") DataMap.liveChanged(); });
let ticks = 0;
setInterval(() => {
  if (!$("live").checked || document.hidden || $("appView").hidden) return;
  ticks++;
  if (currentView === "dashboard") Dashboard.tick(ticks); // charts and module numbers every 10 s
  else if (currentView === "telemetry") Telemetry.tick();
  else if (currentView === "consent" && ticks % 8 === 0) Consent.tick(); // every 16 s
  else if (currentView === "retention" && ticks % 15 === 0) Retention.tick(); // every 30 s
  else if (currentView === "breach") Breach.tick(ticks); // re-scans about every 15 s
  else if (currentView === "usage") Usage.tick(ticks); // every 20 s
  else if (currentView === "datamap" && ticks % 2 === 0) DataMap.tick(); // new database-log rows every 4 s
  if (ticks % 30 === 0 && typeof Account !== "undefined") Account.refreshMe(); // usage banner and permissions every minute
}, 2000);

restoreSession().then((ok) => { if (!ok) { $("loginView").hidden = false; $("email").focus(); } });
