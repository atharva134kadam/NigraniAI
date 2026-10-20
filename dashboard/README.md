# NigraniAI — DPDP Compliance Monitoring for ShopSmart

<img src="frontend/assets/nigrani-logo.jpg" alt="NigraniAI" width="360">

> **Branding.** The product is **NigraniAI** (*nigrani*, "watchful oversight"). Logo files are in
> `frontend/assets/`: `nigrani-logo.jpg` (full logo, login page), `nigrani-mark.png` (round mark,
> sidebar) and `favicon.png`. The log store was earlier called "GuardRail"; its technical names stay
> unchanged because they are real identifiers: the Supabase schema `guardrail`, the setting
> `GUARDRAIL_ANON_KEY`, and `source: "guardrail"` in retention rules.

A compliance monitoring system built for **ShopSmart** (an independent e-commerce website) and handed
over to ShopSmart's admins. It checks ShopSmart against India's **Digital Personal Data Protection
Act, 2023** and the **DPDP Rules, 2025**, using what actually happens in its systems (service logs
and the customer database) rather than questionnaires.

It finds personal data in logs, checks consent and purpose, measures retention deadlines, detects
breaches with rules and an ML anomaly model, runs the Rule 7 breach-response clocks and drafts the
notices, answers questions with an AI assistant, and scores DPDP readiness. ShopSmart's admins see
their own **usage**, their **plan**, can move to a higher plan, and **pay invoices** inside the
dashboard, the way you see your usage and billing in a SaaS product.

**How it's delivered.** Each client gets **their own copy** of this system, customised to their
requirements and handed over completely. The provider (who builds and services it) has no login
inside the copy: the provider sets the plan catalogue, prices and seller details in a server-side
file (`provider.json`) and uses a few server commands. A separate central system for the provider to
track every client's usage and billing will be built later.

> **Principles.** Neither database is ever written to: every read is `GET`, retention produces
> worklists rather than deleting, and notices are drafts. The browser holds only public keys. Personal
> data is minimised before it reaches the browser or the AI. All times are in IST (Asia/Kolkata).
> DPDP references are aids for review, not legal advice.

_Status as of 18 Oct 2026._

---

## Contents

1. [Features at a glance](#1-features-at-a-glance)
2. [Quick start](#2-quick-start)
3. [Architecture](#3-architecture)
4. [Who does what](#4-who-does-what)
5. [Guide to every page](#5-guide-to-every-page)
6. [Access management (IAM)](#6-access-management-iam)
7. [Usage, plans and billing](#7-usage-plans-and-billing)
8. [Security and privacy](#8-security-and-privacy)
9. [API reference](#9-api-reference)
10. [Configuration](#10-configuration)
11. [Data storage](#11-data-storage)
12. [Operations and provider commands](#12-operations-and-provider-commands)
13. [Building the next client's copy](#13-building-the-next-clients-copy)
14. [Legal reference](#14-legal-reference)
15. [Known limitations](#15-known-limitations)
16. [Project structure](#16-project-structure)
17. [History](#17-history)

---

## 1. Features at a glance

| Area | What it does |
|---|---|
| **Dashboard** | Headline numbers from every module, live log-activity charts, "Needs attention", a status per DPDP area |
| **Log Telemetry** | Live structured log feed across all services, with the personal data each line touches shown inline |
| **Consent & Purpose** | Checks every processing event for consent and a declared purpose; 8 editable, versioned rules; customer timelines |
| **Retention** | Retention schedule measured on live data: past deadline, due soon, legal holds, erasure checklists, inactivity, worklists |
| **Breach Response** | 7 editable detectors + the ML anomaly model's signals, signal triage, breach register, Rule 7 / CERT-In clocks and notice drafts |
| **AI Assistant** | Chat grounded in the dashboard's own numbers (Groq, `openai/gpt-oss-120b`): explains, investigates, gives fixes and prevention |
| **Data map** | Live map of personal data: which tables hold it, which services use it, for which purposes, who receives it; inventory, record of processing (CSV / PDF) and gap analysis |
| **Readiness score** | 0–100 DPDP readiness score and grade from eight areas, each finding citing the law and giving a fix; open findings ranked by how much each could raise the score, with links to the section that fixes them and ✦ Ask AI on each |
| **Anomaly detection** | The ML model as its own section: services × time heatmap, a full explanation for every anomaly (what, which measures, how it was detected, likely cause, timeline, sample lines), learning from your reviews, backtest by sensitivity, settings with a test run, ✦ Ask AI |
| **Evidence & audit** | Its own section: tamper-evident records (hash chain, daily seals), a visual chain timeline, protected-record list, evidence packs for auditors, pack checking (drag and drop), and ✦ Ask AI on the status, any problem or a pack check |
| **Access management** | AWS IAM-style for ShopSmart's staff: 37 actions, JSON policies with Allow/Deny, wildcards and conditions, groups, simulator |
| **Usage & plan** | Usage meters (log lines, AI, lookups, users…), what the plan includes and what's left, per-person caps, alerts |
| **Billing** | Change plan (pro-rated), monthly GST tax invoices from the meters, pay with Razorpay, billing details, overdue rules |
| **Account** | Profile, password, sessions, synced settings, activity log, system status |

---

## 2. Quick start

### Requirements

- Python 3.10+ (developed on 3.14). Standard library only; no packages to install.
- Any static file server for `frontend/` (the examples use Python's).
- A modern browser. No build step, no Node, no framework.

### Configure

`.env` in the project root (read by `consent_service/server.py`; never served):

```ini
CLIENT_NAME=ShopSmart                        # shown in the dashboard, notices, invoices, AI instructions
CLIENT_ID=shopsmart

# NigraniAI project: dashboard sign-in and ShopSmart's logs
SUPABASE_URL=https://<guardrail-ref>.supabase.co
SUPABASE_SERVICE_KEY=<service role key>      # server only: Auth admin API (staff accounts)
GUARDRAIL_ANON_KEY=<anon key>                # verifies sign-ins; logs are read with the user's JWT
SUPABASE_DB_SCHEMA=guardrail

# ShopSmart shop database (read-only)
SHOP_SUPABASE_URL=https://<shop-ref>.supabase.co
SHOP_SUPABASE_SERVICE_KEY=<service role key>
SHOP_SUPABASE_ANON_KEY=<public anon key>

CONSENT_PORT=8091
CONSENT_ALLOWED_ORIGINS=http://localhost:8090
ROOT_EMAIL=root@example.com                  # the client's root admin (a test account today)
GROK_API_KEY=gsk_...                         # Groq (or xai-... for xAI)
RAZORPAY_KEY_ID=rzp_test_...                 # the provider's Razorpay account
RAZORPAY_KEY_SECRET=...
```

`consent_service/provider.json` holds the provider's seller details, billing rules and plan catalogue
(see [§7.2](#72-plans-providerjson)). `frontend/config.js` holds the browser settings (public values
only):

```js
window.COMPLIANCE_CONFIG = {
  DASHBOARD_URL: "https://<guardrail-ref>.supabase.co",
  DASHBOARD_ANON_KEY: "<anon key>",
  DB_SCHEMA: "guardrail",
  CONSENT_API: "http://localhost:8091"
};
```

### Run

```bash
cd frontend && python3 -m http.server 8090     # the dashboard  → http://localhost:8090
python3 consent_service/server.py              # the service    → http://localhost:8091
python3 consent_service/server.py help         # provider commands
```

Sign in as `root@example.com` (root, standing in for ShopSmart's admin). After code changes,
hard-refresh (Cmd+Shift+R): asset URLs in `index.html` carry a `?v=` version. Without the service,
only Log Telemetry and the log charts work (they read NigraniAI directly).

---

## 3. Architecture

```
          ┌──────────── Browser: frontend/ (static, :8090) ────────────┐
          │ sign-in · 12 pages · charts drawn as inline SVG             │
          └──────┬───────────────────────────────┬──────────────┬──────┘
   sign-in,      │                               │ every API     │ Razorpay Checkout
   log pages     │                               │ call (JWT)    │ (hosted window)
                 ▼                               ▼               ▼
 ┌─── NigraniAI Supabase project ───┐   ┌──── consent_service (:8091, Python) ─────┐
 │ auth: ShopSmart's staff accounts │   │ verifies JWT → IAM → meters              │
 │ guardrail.activity_logs, …       │◀──│ reads logs with the user's own JWT       │
 └──────────────────────────────────┘   │ detectors · anomaly model · retention    │
 ┌─── ShopSmart shop database ──────┐   │ versioned stores · breach register · IAM │
 │ customers, orders, payments, …   │◀──│ usage · plan · invoices · Razorpay       │
 └──────────────────────────────────┘   │ GET only, service key, minimised output  │
                                        │ data/ (JSON) · provider.json             │
                                        └──────┬─────────────────────┬─────────────┘
                                               │ AI context           │ orders, payments,
                                               ▼                      ▼ refunds
                                     Groq (gpt-oss-120b)     Razorpay (provider's account)
```

| Part | Where | Notes |
|---|---|---|
| UI, consent engine, charts, readiness scoring | browser | plain HTML/CSS/JS modules, no build |
| Authentication | NigraniAI Supabase Auth | email + password; sessions refreshed automatically |
| Everything needing a secret or trust | `consent_service` | one Python process, standard library only |
| Breach detectors and the ML model | `consent_service` | in memory; re-learned every 10 min, scored every ~10 s |
| AI | Groq | only aggregated, minimised context is sent |
| Payments | Razorpay | Checkout in the browser; orders, verification and refunds on the server |

**How every API request is handled:** (1) the `Authorization: Bearer <JWT>` is checked with Supabase
Auth (cached 60 s); (2) at most every 30 s the billing check runs (close finished cycles into
invoices, apply or lift overdue limits); (3) the route is mapped to an IAM action and the person's
policies are evaluated (root always allowed; denials return 403 and are logged); (4) the request and
any feature use (AI tokens, lookups, log lines…) are metered.

---

## 4. Who does what

| | **The client (ShopSmart's admins and staff)** | **The provider (builds and services the copy)** |
|---|---|---|
| Uses | every compliance page | — (no login in the copy) |
| People and permissions | root adds staff and gives them policies | — |
| Usage | sees usage, per-person caps, alerts | sees it with `status` (and later in the central system) |
| Plan | chooses / upgrades among the catalogue's plans; can't change prices | sets the catalogue and prices in `provider.json`; `plan set` |
| Invoices | receives them, pays with Razorpay, keeps billing details | seller details in `provider.json`; `bill-now`, `mark-paid`, `void`, `refund` |
| Money | pays | receives (Razorpay account in `.env`) |

`root@example.com` is the **root** user (`ROOT_EMAIL`), standing in for ShopSmart's admin.

---

## 5. Guide to every page

The sidebar shows only what the person may use, with the client's name under the logo. The account
menu (bottom corner) holds Profile, Security, Settings, Access management, Usage & plan, Activity,
System status, a Light/Dark/Auto theme switch and Sign out.

### 5.1 Dashboard

One page for every module, refreshed every 10 s with **Live** on. Charts are inline SVG in the theme
colours (light and dark).

| Part | What it shows |
|---|---|
| Headline cards | Breach response, Consent & purpose, Retention, Log telemetry (each opens its section) |
| Log activity | Stacked columns of log lines (Info/Warning/Error) per hour, 2 h or 6 h for 24 h / 3 days / 7 days, IST-aligned, with a personal-data line; peak, error rate, PII share; live badge |
| Donuts and bars | Logs by service, API responses (success, redirects, 401/403, other 4xx, 5xx), consent coverage, breach signals by detector, retention status per rule |
| Needs attention | The most urgent items across modules, worst first |
| Monitoring | All-time counts: services, application and database lines, PII lines, errors, latest line |
| Compliance at a glance | One card per DPDP area with its legal reference and status (On track / Watch / Action needed) |

NigraniAI doesn't allow aggregate queries, so the page loads a compact 7-day copy of `activity_logs`
(capped at 60k lines), buckets it in the browser, then fetches only newly ingested lines every 10 s
and reloads the window every 10 min. Module numbers are reused for up to 60 s.

### 5.2 Log Telemetry

Reads `activity_logs`, the complete stream for all services (`all_logs` isn't used: it would show
database events twice).

- **Tabs** per service with counts. **Filters:** time range (incl. Today / Yesterday in IST), level,
  layer (application / database), kind, PII, text search, trace.
- **Rows:** IST time, level, service and layer, purpose, a structured summary (HTTP request, SQL
  query, schema column, privacy event, key=value) and flags.
- **Inline PII** under each event, e.g. `EMAIL read`, `ADDRESS ×5 write`, `CREDIT_CARD masked`.
  SQL columns are matched against column classifications from `db_schema` events
  (`customers.email` → `personal_data:email`).
- **Row details:** trace (click for the whole trace), actor, purpose, source file:line, a
  personal-data table and the stored (masked) line. **Live:** new lines every 2 s.

How PII is detected: values are masked upstream by NigraniAI before storage (`pii_masked`,
`masked_pii_types`, `[EMAIL]`-style tokens), and SQL columns are labelled by the application's own
schema events. This page reads those labels; it doesn't run a model.

### 5.3 Consent & Purpose

Checks the customer database against a consent-and-purpose policy. The engine is a pure function in
the browser, `evaluate(policy, schema, data) → findings`, over minimised data; it re-checks every
16 s (paused while editing). 1,500 customers / 6,000 orders evaluate in ~40 ms; 20,000 / 80,000 in
~0.5 s.

| Tab | What it shows |
|---|---|
| Overview | Customers by status (accepted · existing to re-accept · active without re-accepting · not saved · old version · signed up without accepting); the **sign-up gate** card; one card per open issue with the first fix and the DPDP reference; passing checks |
| Customers | Paginated table with status chips, an **Account** column (new / existing, sign-up date), issue filter and sorting; search by number, or look up a full email or phone (see below); a customer's consent record and IST timeline (account created, acceptance went live, acceptances, processing) |
| Issues | Per rule: what happened, why it matters, fix steps, breakdown by purpose, evidence (CSV) |
| Rules | Each rule as an editable sentence with a switch and live preview; 8 templates; purposes, processing sources, notices, consent fields, data inventory, version history |

**Policy model:** purposes (legal basis s.6 consent / s.7 legitimate use; notice at sign-up or separate
opt-in), processing sources (which table counts as processing, customer and time columns, purpose,
optional linked lookup), notices and consent fields, rules (template instances with severity and
reference), and a data inventory compared with the live database. Every change is a draft with an
impact preview; saving needs a change note and creates a version.

| ID | Default rule | Severity | Reference |
|---|---|---|---|
| R1 | Processing without an accepted privacy notice | High | s.5, s.6 |
| R2 | Processing before consent was given | High | s.6(1) |
| R3 | Opt-in purpose (marketing) without consent | Critical | s.6(1), s.6(6) |
| R4 | Processing for an undeclared purpose | High | s.5(1), s.6(1) |
| R5 | Consent to an outdated notice (re-consent needed) | Medium | Rules 2025, Rule 3 |
| R6 | Processing after an erasure request | Critical | s.8(7), s.12(3) |
| R7 | Processing not linked to a known customer | Medium | s.8(1) |
| R8 | Consent records differ from the declared inventory | Medium | s.5, s.8(1) |
| R9 | Account created after acceptance became mandatory, with no acceptance recorded (the sign-up gate failed) | Critical | s.5, s.6 |
| R10 | Existing accounts (from before acceptance was mandatory) that haven't accepted yet, and haven't used the shop since | Low | s.5(2) |

**Mandatory acceptance at sign-up** (redesigned 19 Oct 2026). On ShopSmart's website, accepting the privacy notice and the Terms is mandatory to create an account. The policy records this per notice: `capture: "mandatory_signup"` and `since`, the moment it went live (15 Oct 2026, 12:16 PM IST, the first acceptance on record; edit it in Rules → Notices). Each customer's sign-up time comes from their own column, the linked login account (`policy.signup.via`: `customers.auth_user_id` → `auth_users.created_at`), or their first activity, marked as an estimate. From that, every customer without a record is put in an honest category instead of "never accepted":

| Status | Meaning | Severity |
|---|---|---|
| Accepted | every required notice, current version | – |
| Existing account · re-accept at next sign-in | signed up before acceptance became mandatory, no activity since | low (R10) |
| Existing account · active without re-accepting | an existing account processed after go-live without accepting: the re-acceptance prompt isn't working | high (R1) |
| Acceptance not saved | accepted one notice but a mandatory one has no record: a website saving bug | medium (R5) |
| Needs re-consent (new version) | accepted an older version | medium (R5) |
| Signed up without accepting | created after go-live with no record: the sign-up gate failed | critical (R9) |

Processing by an existing account **before** go-live is no longer counted as "before consent" or "without a notice". The **sign-up gate** card shows the accounts created since go-live, how many accepted at sign-up, and how quickly. Consent fields can read several columns, using the first that holds a value (e.g. `Terms_and_Condition`, then `terms_accepted`). ShopSmart's customers table has a duplicated consent column set, and both are read. The Dashboard donut and the Readiness score use the same categories; existing accounts waiting to re-accept count as on track, not as breaches.

ShopSmart (19 Oct 2026):
- **2 accepted at sign-up:** #8 and #9, in under a second. The gate works, 2 of 2.
- **4 existing accounts to re-accept:** #1, #3, #4 and #5.
- **#7 needs action:** an existing account active on 16 Oct without re-accepting.
- **#6 needs action:** the privacy notice was accepted, but the Terms acceptance wasn't saved.

**Customer lookup without exposing personal data:** the browser never receives emails or phones. A
full email or a 10+ digit phone goes to the service, which returns only the customer number. Partial
or wildcard input is refused; each lookup is logged with who searched and how many matched, never
the value.

### 5.4 Retention

Measures a retention schedule against live data: shop tables through the service and logs from
NigraniAI. Each record's deadline is its own date plus the rule's period. Re-checks every 30 s.
Nothing is deleted: the page shows what is due, checks erasures that should have happened, and
exports worklists for the service that owns the data.

| Tab | What it shows |
|---|---|
| Overview | Past deadline, due in 30 days, open erasure requests, legal holds; every rule's status; conflicts first |
| Records | Per rule: counts, reason and a paged record table; **Export worklist (CSV)** |
| Erasure & inactivity | Erasure requests with deadlines and a per-step true/false checklist; inactive accounts to notify or past deadline |
| Schedule | Each rule as a sentence with a switch and live preview; 4 templates; due-soon window; version history |

| Rule type | Checked |
|---|---|
| Erasure request | each request against its deadline, each step on the live data |
| After a period (delete / anonymise / review) | records past the deadline and due within the window |
| Legal minimum (keep at least) | records under hold; a shorter delete rule on the same data is a **conflict** |
| Inactive accounts | last sign-in or order → notify now, past deadline, next deadline |

Default schedule: E1 erasure within 120 s of a request (demo setting); A1 session tokens 1 day after
expiry; A2 review notifications at 180 days; A3 delete logs at 18 months; L1/L2 keep orders and
payments 8 years (CGST Act s.36); L3 keep logs at least 1 year (Rules 2025, Rule 8(3)); I1 erase
customers inactive 3 years with 48 h notice (Rule 8(1)–(2), Third Schedule; applied as good practice).

Privacy: erasure checks return only true/false per step and counts; counts and pages are computed in
the database (`/api/query`); filters on personal columns are refused.

### 5.5 Breach Response

Built for s.8(6) and Rule 7. Detectors and the anomaly model watch the logs; flagged activity becomes
a **signal** to review; a signal or a manual report becomes an **incident** in the breach register,
where the response clocks run and notices are drafted. A breach includes loss of access, not only
disclosure (s.2(u)), so outages and failed writes are watched too.

| Tab | What it shows |
|---|---|
| Overview | Open incidents, next deadline, signals to review, detectors on; live clocks; newest signals; detector activity |
| Signals | Every signal with severity, size, time and breach type; review shows why it matters, first checks and the log lines; open an incident, add to one, or dismiss with a reason (undo) |
| Breach register | Every incident with status, severity, awareness time, next deadline, one dot per obligation; search; CSV |
| Incident | Suspected → Confirmed → Contained → Closed (or Not a breach); four obligation cards with countdowns and "Mark as sent"; Board extension; the record; notices; evidence; activity log |
| Anomaly model ↗ | Opens the **Anomaly detection** section (its own sidebar item, below). ML signals here show their summary, cause and a *Full explanation* link |
| Detectors & settings | Detectors as sentences with switches; edit conditions, measure, threshold, window, grouping, type, severity, auto-open with a live preview; 6 templates; clock hours; notice contact; look-back; versions |

**Response clocks** (start at "Became aware"):

| Obligation | Default | Basis |
|---|---|---|
| CERT-In report (cyber incidents) | 6 h | CERT-In Directions, 28 Apr 2022 |
| Initial intimation to the Board | 24 h (target for "without delay") | Rule 7(2)(a) |
| Notice to each affected customer | 48 h (target for "without delay") | Rule 7(1) |
| Detailed report to the Board | 72 h (or the Board's extension) | Rule 7(2)(b) |

Clocks turn amber inside the warning window (12 h) and red when overdue. Rule 7 applies from
13 May 2027; the clocks run now so the process is ready.

**Notices** (drafts built from the incident, missing parts marked `[add: …]`): initial Board
intimation (Rule 7(2)(a)), detailed Board report (7(2)(b)(i)–(vi)), customer notice (7(1)(a)–(e)) and
the CERT-In report. The dashboard never sends anything itself.

**Default detectors:**

| ID | Detector | Signals when | Type · severity |
|---|---|---|---|
| D1 | Burst of failed sign-ins | 20+ HTTP 401 in 10 min per service | Confidentiality · High · auto-opens |
| D2 | Services holding personal data are failing | 5+ HTTP 5xx in 15 min per service | Availability · Medium |
| D3 | Personal data written to application logs | any masked PII pattern, per service per day | Confidentiality · Medium |
| D4 | Bulk read of personal data | 500+ personal-data rows in 5 min per service | Confidentiality · Critical · auto-opens |
| D5 | Staff opened the full customer list | any `CUSTOMER_LIST_VIEWED`, per staff member per hour | Confidentiality · Low |
| D6 | Database errors on personal-data services | any failed DB call in 15 min per service | Integrity · Medium |
| D7 | Erasure and retention jobs are failing | 3+ `retention_sweep_failed` in 1 h | Integrity · Medium |

Detectors count matching lines (or sum a field such as rows read) in a sliding window per group;
overlapping windows merge. Auto-open detectors start an incident the first time; repeats join the
open incident.

**Anomaly detection (machine learning, v2)**: its own section (`frontend/anomaly.js`, sidebar item
*Anomaly detection*, needs `breach:ReadSignals`). Unsupervised, so it needs no labelled breaches.

1. **Slice:** each service's logs are cut into 10-minute slices (5–60 configurable) with **13 measures**:
   HTTP requests, data operations, personal-data events, credential events, rejected sign-ins (401/403),
   PII in log text, errors, warnings, 5xx, p95 response time, and three rates: error rate, share of
   requests rejected, share of lines touching personal data (a rate needs ≥ 8–20 lines to count).
2. **Learn normal per service and time of day:** `log(1+x)`, then `z = (x − median) / max(1.4826·MAD, 0.5)`
   against that service's **day (08–20 IST) or night** normal, falling back to the whole-day normal while a
   time of day has under max(6, min_history/2) slices. A 3 AM burst is judged against nights.
3. **Score:** Isolation Forest (Liu, Ting & Zhou, 2008) in plain Python, trees stored as flat arrays
   (iterative scoring): 150 trees, 256-slice samples, depth 8, seed 7; `s = 2^(−E[h(x)]/c(ψ))`.
   Scores are cached per slice until the slice changes or normal is re-learned, so the live re-score only
   works on new slices (0.24 s → 0.10 s on the 7-day window, 1,242 slices).
4. **Gate:** an anomaly needs the score ≥ cut-off (low 0.72 / medium 0.67 / high 0.62) **and** a measure
   ≥ 3 MADs above normal by a meaningful amount. Consecutive slices merge into one anomaly.
5. **Explain** (stored on each anomaly): a plain-words `summary`; up to 4 `reasons` (value, usual, p95,
   spreads, × usual); `contributions`, which measures did the isolating (each split on the slice's path,
   weighted 1/depth and by how quickly the tree isolated it, times distance above normal); `checks`, the
   detection trail (score, above normal, amount, history, time-of-day normal, your reviews); a likely
   `cause` with confidence and what to check (credential stuffing, PII in logs, bulk personal-data read,
   credential activity, data-operation volume, service failure, traffic spike, outage across services,
   **start-up burst** after ≥ 1 h of silence); a `timeline` of the service around it; sample line ids.
6. **Learn from reviews:** dismissing an ML anomaly stores its pattern (service, leading measure, time of
   day) with the triage record. A later anomaly with the same pattern is **held back** (listed under
   *Held back*, not raised) unless it scores ≥ 0.06 above the cut-off.
7. **Backtest and quality:** each run also counts what low / medium / high would have raised on the same
   window (alerts per day), and the Model tab shows reviewed, became incidents, dismissed, held back.
8. **Live:** new lines scored every ~10 s (slice in progress included); normal re-learned every 10 min,
   on a settings change, or with *Retrain now*. When the window exceeds 100,000 lines the newest are kept.

**Page:** Overview (live status, *Right now* score, a services × hours heatmap of the last 72 h with
anomalies outlined and clickable, latest anomalies), Anomalies (filters: to review, all, high, dismissed,
held back; each opens a full report: summary, what was unusual, what made the model isolate it, how it was
detected, likely cause and what to check, timeline, sample log lines, review buttons and ✦ Ask AI), How the
model works (six steps, backtest, quality from your reviews, score distribution with the cut-off, what it
learned per service by day and night, performance) and Settings (sensitivity with alerts/day, slice, history,
auto-open; *Test on recent logs* before saving; saved as a new breach-policy version with a note). Reviews go
through Breach Response, so Signals stays the single triage queue. Auto-open stays off by default because
"unusual" isn't "breach".

### 5.6 AI Assistant

A chat for analysts. Answers are shaped as **Answer**, **Why it matters** (with DPDP references),
**What to do now** (naming real buttons), **How to prevent it**, followed by three suggested follow-ups.

- 16 suggested questions (Explain / Investigate / Fix / Prevent); streamed answers with Stop, Copy,
  Regenerate; data-source toggles (Logs, Consent, Retention, Breach); drag-and-drop a file (≤ 2 MB,
  first ~5,000 characters sent); "✦ Ask AI" buttons on consent issues, breach signals, incidents, the
  anomaly model and the readiness report; up to 25 conversations kept in the browser.
- The browser gathers a minimised snapshot (counts, ids, rules, findings, ranked log statistics,
  because models are unreliable at adding up raw data); the service adds a system prompt with a legal
  reference sheet and a map of the real controls, trims context to the token budget, and streams the
  answer from Groq.
- Groq's free tier allows 8,000 tokens per minute: the service trims context (`GROK_CONTEXT_CHARS`,
  default 10,000), halves it on "too large" and waits on "rate limited" (≤ 40 s) before retrying once.
- The model is picked from what the key can use (`openai/gpt-oss-120b`, then `qwen/qwen3.8-27b`,
  `openai/gpt-oss-20b`); `GROK_MODEL` forces one. An `xai-` key uses api.x.ai.
- AI questions and tokens are metered; caps and hard limits apply (§7).

### 5.7 Readiness score

A 0–100 score and grade (A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, else E), the average of the assessed areas:

| Area | Scored from | Law |
|---|---|---|
| Security monitoring | detectors on, anomaly model on, signals waiting, personal data in logs | s.8(5), Rule 6 |
| Breach readiness | notice contact, overdue notifications, 72 h Board and 6 h CERT-In clocks | s.8(6), Rule 7 |
| Consent & purpose | share of customers with valid consent, high-severity issues | ss.5–7 |
| Retention | records past deadline, overdue erasures, rule conflicts | s.8(7), Rule 8 |
| Access control | deny by default, people with near-full access, unused accounts | s.8(5) |
| Logging coverage | services logging, volume, masking, error rate | Rule 6(1)(c)–(e) |
| Records & evidence | ledger intact (60), no rule deletes logs before a year (30), daily seals made (10) | s.8(5), Rule 6(1)(e) |
| Data inventory | the Data map's health score and its critical/high gaps | ss.4–8, s.16 |

Every finding cites the law and gives a fix. Areas the person isn't allowed to read are "not
assessed" and don't count. Results are saved with a history (trend line), printable to PDF and
explainable with Ask AI.

**Page layout.** A header with the score ring, the grade, the change since the last run and the
counts of findings (to fix / to improve / passing); **Fix these first**, the six most important open
findings, problems before warnings, then by the most each could add to the overall score (an area's
missing points ÷ areas assessed, shared among its open findings), each with *Open <section>* and
✦ Ask AI; one card per area with its own score ring, the findings to work on, the passed checks folded
away and a link to its section; and the score history shaded by grade. Before a new run it shows the
last saved scores. While running, each area is ticked off as it is checked; areas wait for their
section's data if it is still loading, so a run right after sign-in scores correctly.

*Public exposure (removed 20 Oct 2026).* The test of what the shop's public key could read is gone
from the Readiness page, the score, the data map, evidence packs and the provider reports. Its last
results stay in `data/exposure.json`, still fingerprinted in the ledger, as part of the evidence.

**Evidence & audit section** (`frontend/evidence.js`; in the sidebar for `readiness:Read`, `readiness:VerifyIntegrity` or
`readiness:ExportEvidence`). Tabs: Overview (integrity checks, protected records with their last change,
log retention, chain activity per day), Chain timeline (latest 40 entries, filterable, each showing its
link to the previous fingerprint), Evidence packs (create with presets, drag-and-drop check, packs issued),
Daily seals (30-day calendar) and How it works. `GET /api/evidence` also returns `chain`, `protected`,
`by_type` and `per_day` (names, times and fingerprints only). The AI assistant has an **Evidence** data
source, and ✦ Ask AI buttons on the status, each integrity problem, a pack check and the how-it-works tab.
Makes the system's own records tamper-evident, so ShopSmart can show an auditor or the Board that
nothing was altered after the fact.

- **Ledger** (`data/ledger.jsonl`): one entry per activity-log event and per change to a record file
  (`policy`, `retention`, `breach`, `incidents`, `iam`, `plan`, `billing`, `readiness`, `exposure` (archived)
  and every saved version in `history/`, `retention_history/`, `breach_history/`). Each entry holds
  the record's SHA-256 and the previous entry's hash, so editing, deleting or reordering anything
  breaks the chain from that point. The first entry (genesis) fingerprints everything that existed
  when the ledger started. Not chained: `usage.json` (rewritten every 5 s) and IAM's last-used times.
- **Writes** go through `write_tracked()`, which writes the file and records it in one step under a
  thread lock plus a file lock (`data/.ledger.lock`), so the provider's CLI can run alongside the
  server. Each process re-syncs from the file when the other has appended.
- **Verify** (button, every page open, and daily before the seal) re-checks the chain, every activity
  record and every file, and names what changed: an edited, deleted or inserted activity record; a
  file changed, deleted or added outside the system; a broken ledger entry. A break is written to the
  activity log as `integrity.broken`; the last result is kept in `data/integrity.json`.
- **Daily seal**: after midnight IST the previous day's chain head is sealed (after a verify).
- **Log retention (Rule 6(1)(e))**: the oldest NigraniAI log line, and every retention rule on the
  logs table. A rule that deletes logs before 365 days fails.
- **Evidence pack** (`readiness:ExportEvidence`, metered as `evidence.packs`): for a date range (up to
  400 days) a JSON file plus a printable report with integrity and seals, log retention, readiness
  history, the breach register (incidents without sample ids), policy versions,
  users and policies, and the activity log (up to 5,000 events). Its SHA-256 `fingerprint` is
  recorded in the ledger as an `export` entry.
- **Check a pack** (`readiness:VerifyIntegrity`): upload a pack, and the system reports whether it's
  unchanged and whether this system issued it.
- **Limit**: someone with full server access could rewrite the *whole* ledger consistently. Keep a
  copy of the chain fingerprint outside the server: it's in every pack, or copy it from the tab
  monthly. Don't edit files in `data/` by hand; it will show as tampering (use the dashboard or CLI).

### 5.7a Data map

A separate page (sidebar → **Data map**, `datamap:Read`) answering the first question of any audit: *what
personal data do you hold, where, why, and who gets it?* It is built by the service on each scan
(`datamap:Scan`, about 10 s; automatic when the page opens and the last scan is over 6 hours old):

| Source | What it gives |
|---|---|
| Shop schema + row counts (service key, GET only) | every table, its columns, how many rows |
| Column classifier (`classify_columns`) | personal fields by kind and category; contact, address, credentials, financial/ID and birth data always count; a bare `name`, free text or network field only in a table about people (it has strong personal data, a customer/recipient link, or a person-like name), so a product's `name` isn't flagged |
| NigraniAI `database_logs`, last 30 days (user's token) | service → table flows: accesses, operations (SELECT/INSERT/…), personal-data flag |
| NigraniAI `activity_logs` | personal values that appeared in log lines (masked), Razorpay events |
| Consent policy + **Declarations** | which purposes each table and service serves |
| Retention rules | retention per table |
| Settings | Supabase hosts, the AI provider |

**Live.** With the Live switch on (top right), the page updates every 4 s: the service reads only
the `database_logs` rows ingested since the last update (`ingested_at` watermark; one request when
quiet), adds them to per-day buckets so the 30-day window keeps rolling, and recomputes flows, gaps,
the record of processing and the score in memory (about 1 s). Schema, row counts, the registry and
processors refresh every 5 minutes, or at once when the declarations change. Live updates are not
written to disk (the evidence ledger only records full scans and declaration changes) and not metered
beyond API requests; GET `/api/datamap` and the Readiness area return the live result. On the page:
a *Live* pill with accesses in the last minute; a **live activity** feed (time, service → table,
+count; red when outside purpose, "new flow" when a service touches a table for the first time); links
that just carried traffic pulse and their nodes glow; a notice pops up when a gap opens or closes (new
gaps are also written to the activity log). Updates are applied in place: they never move focus, eat a
click, close the details drawer or touch unsaved declarations. If the service restarts, the first live
call runs a full scan.

**Tabs**
- **Map**: an interactive four-column flow (Services → Data stores → Purposes → Recipients). Line
  thickness is access volume; red dashed lines are personal data used **outside the service's
  declared purposes**. Hover traces the full path; click opens a details drawer; filter by data
  category, personal-only, or search. Gap badges sit on the nodes.
- **Inventory**: a card per table: categories, personal fields, purposes, retention, public access,
  last use, and which services use it (bars).
- **Record of processing**: one entry per purpose (data principals, personal data stated in the notice vs
  found, data stores, services, recipients with DPA/country, retention, safeguards), plus a "not
  covered by a declared purpose" entry. Export CSV or print / save as PDF.
- **Gaps**: each with severity, the DPDP reference and the fix; "Show on map" jumps to the node.
- **Declarations** (`datamap:Edit`): a services × purposes matrix (an amber dot marks a purpose whose
  data a service used without being allowed), table purposes beyond the consent policy (policy ones
  are fixed), and the processors register (role, purposes, data received, country, DPA state, notes;
  detected processors are marked). Saving bumps a revision (conflicts are refused) and rescans.

**Gaps it finds**

| Gap | Severity | Law |
|---|---|---|
| A service uses personal data outside its declared purposes (grouped per service) | Critical if financial/credentials, else High | s.4(1)(b), s.6(1) |
| Personal data store with no purpose | High | s.5(1), s.6(1) |
| Table readable with the public key | Critical | s.8(5), Rule 6(1)(b) |
| No retention rule for a personal data store | Medium | s.8(7) |
| Data categories a purpose uses but the notice doesn't state | Medium | s.5(1)(i) |
| Personal values in application logs (grouped per value type) | Medium | s.8(5), Rule 6(1)(a) |
| Processor without a data processing agreement | Medium (High if "not signed") | s.8(2) |
| Processor location not recorded | Low | s.16 |
| Personal data no service used in 30 days | Low | s.8(7) |
| New personal columns since the last scan; services not in the declarations | Medium | s.5, s.8(1) |

Health score: 100 − 15/8/3/1 per critical/high/medium/low gap. It also feeds the Readiness score
(**Data inventory**) and the AI assistant (Ask AI). Only names and counts are read or stored, never values.
Results are kept in `data/datamap.json` (declarations, last scan, 30-scan history; chained in the
evidence ledger); starting declarations come from `default_datamap.json`. Each scan is metered
(`datamap.scans`, not billed) and audited.

ShopSmart's first scan: 9 of 17 tables hold personal data (40 fields), 7 services, 14 personal flows,
13 gaps; the critical one: `analytics-service` reads `payments`, `customer_orders`, `customers` and
`order_line_items` with no declared purpose.

### 5.7b PII detection v2 (fused detection)

Decides, for every column of the customer database, whether it holds personal data, **with evidence**. It does this by fusing independent signals into one verdict. The engine is `consent_service/pii_engine.py`; results are stored in `data/pii.json` (verdicts and evidence only, never values) and chained in the evidence ledger.

| Layer | What it checks |
|---|---|
| 1. Name and context | column and table names, as in v1 |
| 2. Values | up to 200 sampled values per table, tested with real checks: **Luhn** (cards), **Verhoeff** (Aadhaar), PAN holder-type letter, **GSTIN check character**, Indian mobile, email, UPI, IFSC, passport, voter ID, PIN code, Razorpay ids, password hashes (bcrypt/argon2/pbkdf2), JWTs, tokens (entropy), IPs, birth dates, address lines, Indian cities and states. Also flags true/false columns and placeholders (every value the same) |
| 3. Links | declared foreign keys, or **inferred** ones: the name points at a people table (`customer_id` → `customers`, `user_id` → `auth_users`) **and** at least 80% of values are existing ids. Orphans (ids of people who no longer exist) are reported |
| 4. Language model | free-text and name columns are read by a **local** NER model (Microsoft Presidio + spaCy `en_core_web_lg`) for people's names and places. It runs in its own environment (`consent_service/.pii-venv`) through `pii_ner_worker.py`; detection works without it |
| 5. Feedback | an admin's confirm or reject always wins and is kept across scans |

**Verdict:** kind, category (contact, identity, address, financial, **government ID**, credentials, device, customer content, linked to a person), confidence 0–100, and Confirmed (≥85), Likely (65–84), Possible (40–64) or Not personal. Each verdict lists its evidence, e.g. "100% of 10 sampled values match: phone number (Indian mobile format)", "link to customers.id (inferred …; 1 point to a customer that no longer exists)", "all 2 sampled values are true/false flags".

**Logs.** The same validators scan stored log lines (message, `details`, SQL templates; the last 7 days, then incrementally) for personal data the masker **missed**. They are token-aware: digits inside hashes, UUIDs and ids, or under keys like `sha`, `id`, `duration` or `count`, don't count. The language model reads business and error messages for names. Masked tokens next to "timestamp" are marked as masker false positives.

**Privacy.** Values are read with the service key (GET only), exist only in memory while a column is scored, and are dropped at once. Only statistics and evidence are stored. The model runs on the server; nothing goes to the outside AI. Scans run with a full Data map scan or on demand (`POST /api/pii/scan`), metered as `pii.scans`.

**ShopSmart results (19 Oct 2026):**
- 161 columns, **40 personal** (23 confirmed by values, 17 likely), 1 to review;
- every person link resolved, with 2 orphaned customer ids;
- `default_address` is correctly not personal (a flag);
- 43,179 log lines: **0 unmasked leaks**. A first, non-token-aware pass had wrongly found 369, all inside hashes and UUIDs;
- 30 of 30 masked `[CARD]` tokens are timestamps.

**Where it shows**

- **Data map → Detection tab:**
  - tiles: columns checked, personal (confirmed / likely), to review, found beyond names, v1 false alarms, and **engine precision** (how often the engine agreed with your team's answers);
  - a log card: lines checked, unmasked leaks, masked tokens and how many were false alarms;
  - every column, grouped by table: kind, verdict, confidence bar, evidence, and a v1 comparison ("new in v2", "v1 false alarm", "v1 agreed");
  - **✓ / ✕ / "It's actually…" / Reset** (`datamap:Edit`). Answers are kept across scans and audited, and Reset restores the engine's own verdict.
- **Data map, everywhere else:** inventory, map, record of processing and gaps all use the fused verdicts (confidence and evidence on hover). New gap types:
  - *hidden personal data* (the values prove it, the name doesn't);
  - *government ID numbers stored*;
  - *unmasked personal data in stored logs*;
  - *columns to confirm*.
- **Log Telemetry:**
  - SQL column chips use the fused verdict (hover shows confidence and evidence; v2's "not personal" columns lose their chip);
  - masked tokens next to a timestamp become grey, struck-through *false alarm* chips. Such lines are tagged **NO PII** and no longer raise the *PII in log* flag;
  - unmasked leaks get a red **PII** tag, an **UNMASKED_PII** flag and the exact span highlighted;
  - new filter: *Unmasked personal data (v2)*.
- **Breach Response:** a detector **"Unmasked personal data in logs"** (`PII`). It gives one signal per service per day, critical for cards, Aadhaar, PAN, passports and tokens, and high otherwise. It shows in the signals list and filter with a link to the matching log lines; triage and incidents work as for any detector.

**API**

| Method | Path | |
|---|---|---|
| GET | `/api/pii` | verdicts, live stats, feedback, log summary, model status [datamap:Read / telemetry:ReadLogs / readiness:Read] |
| POST | `/api/pii/scan` | re-sample every table and re-check the logs [datamap:Scan] |
| POST | `/api/pii/logs` | incremental log check → leaks (ids, kinds, spans; no values) [telemetry:ReadLogs / datamap:Read] |
| PUT | `/api/pii/feedback` | `{table, column, verdict: personal|not_personal, kind?, note?}` or `{table, column, remove: true}` [datamap:Edit] |

**Setup of the language model** (once per copy; optional):
```bash
cd consent_service
python3.11 -m venv .pii-venv
.pii-venv/bin/pip install "presidio-analyzer==2.2.*" "spacy==3.8.*"
.pii-venv/bin/python -m spacy download en_core_web_lg      # ~600 MB on disk
```
The service finds `.pii-venv` by itself. Without it, layers 1–3 and 5 still run, and the Detection tab says "Language model not installed". The worker loads the model once (about 3 s) and reads about 200 texts per second.

Tests: `python3 -m unittest test_pii_engine` in `consent_service/`. That's 25 tests covering checksums, validators, token-aware text scanning, false positives inside hashes and UUIDs, fusion, links, flags, staff links and feedback.

### 5.8 Access (IAM)

See [§6](#6-access-management-iam). Tabs: Users, Groups, Policies (visual + JSON editor), Policy
simulator, Action catalogue.

### 5.9 Usage & plan

| Tab | What it shows |
|---|---|
| Overview | Plan and cycle, bill so far and forecast (before GST), a card per billed meter (used, included, progress, forecast, overage), a running-total chart against the allowance, activity meters, CSV export |
| By user | Every person's usage this cycle (`usage:ViewAllUsage`) |
| Plan & limits | What the plan includes (read-only), per-person caps (e.g. 50 AI questions for one person) and alert levels (`usage:ManagePlan`) |
| Billing | Plan options with the pro-rated upgrade price, invoices (View / PDF, **Pay**), billing details (`billing:*`) |

With only `usage:ViewOwnUsage` a person sees just their own usage.

### 5.10 Account

| Tab | What it does |
|---|---|
| Profile | Name, title, avatar colour; your access: attached policies and allowed actions |
| Security | Change password (current one re-checked); sign out, or out of all devices |
| Settings | Theme (Light/Dark/System), start page, live updates; saved to the account |
| Activity | Day-grouped feed of everything that happened: saves, incidents, signal decisions, lookups (match counts only), AI questions, access changes, denials, usage alerts, billing events; Mine / Everyone (`iam:ReadAllActivity`); CSV |
| System status | Client, service uptime, NigraniAI and shop connections, AI model, store versions, usage plan, payments mode (`system:ReadStatus`) |

---

## 6. Access management (IAM)

Modelled on AWS IAM, for ShopSmart's own staff. **Nothing is predefined:** a new person can do
nothing until a policy grants it.

### 6.1 How a request is decided

- An **explicit Deny** in any matching statement wins; otherwise an **explicit Allow** grants;
  otherwise it is **implicitly denied**.
- Policies apply directly to a person or through their groups.
- The **root user** (`ROOT_EMAIL`) is never evaluated: always allowed, and can't be restricted,
  changed or removed from the dashboard.
- Denials return 403 ("Access denied: consent:ReadFindings is not allowed by any policy attached to
  you") and are logged as `access.denied`.

### 6.2 Policy documents

```json
{
  "Version": "2026-10-17",
  "Statement": [
    { "Sid": "Respond", "Effect": "Allow", "Action": ["breach:ReadSignals", "breach:*Incident", "ai:Ask"] },
    { "Sid": "OfficeHoursOnly", "Effect": "Allow", "Action": "retention:ReadSchedule",
      "Condition": { "NumericGreaterThanEquals": { "dpdp:IstHour": 9 }, "NumericLessThan": { "dpdp:IstHour": 18 },
                     "StringNotEquals": { "dpdp:IstWeekday": ["Sat", "Sun"] },
                     "DateLessThan": { "dpdp:CurrentTime": "2026-12-31T23:59:59+05:30" } } },
    { "Sid": "BlockExports", "Effect": "Deny", "Action": "*:Export*" }
  ]
}
```

- `Action` or `NotAction` with `*` and `?` wildcards (`breach:*`, `*:Read*`, `*`), case-insensitive.
- Conditions: `DateLessThan` / `DateGreaterThan` on `dpdp:CurrentTime`; `NumericLessThan` /
  `NumericGreaterThanEquals` on `dpdp:IstHour`; `StringEquals` / `StringNotEquals` on `dpdp:IstWeekday`.
- Live validation: errors block saving; warnings flag risky grants (self-escalation, `*`, Allow with
  NotAction) and patterns that match nothing. The last 5 versions are kept and restorable.

### 6.3 The Access page

| Tab | What it does |
|---|---|
| Users | People with groups, policies, allowed-actions bar, last activity, status. Create user (temporary password; no access unless groups or policies are ticked). A person's page: Permissions, Effective access (every action Allowed / Explicit deny / Implicit deny with the deciding policy), Access advisor (last use per service), Security (reset password, deactivate, remove) |
| Groups | Named sets of people sharing policies |
| Policies | Summary, attachments, versions; visual editor (per statement: effect, service, actions by level, conditions) and JSON editor kept in sync; validation; "Open in simulator" |
| Policy simulator | A person, an optional moment in time and an optional draft policy → every action with its decision and reason. Nothing is saved |
| Action catalogue | All actions with level, description and where enforced |

### 6.4 All 37 actions

| Service | Actions (access level) |
|---|---|
| `dashboard` | View (Read, interface) |
| `telemetry` | ReadLogs (Read, interface) |
| `consent` | ReadFindings (Read), LookupCustomer (Read), ExportEvidence (Read, interface), EditPolicy (Write), RestorePolicyVersion (Write) |
| `retention` | ReadSchedule (Read), ExportWorklist (Read, interface), EditSchedule (Write), RestoreScheduleVersion (Write) |
| `breach` | ReadSignals (Read), TriageSignal (Write), CreateIncident (Write), UpdateIncident (Write), ExportRegister (Read, interface), EditDetectors (Write), RestoreDetectorsVersion (Write) |
| `ai` | Ask (Use), AttachFile (Use) |
| `iam` | ListUsers (List), ManageUsers (Write), ListPolicies (List), ManagePolicies, ManageGroups, AttachPolicies (Permissions management), SimulatePolicy (Read), ReadAllActivity (Read) |
| `usage` | ViewOwnUsage (Read), ViewAllUsage (Read), ManagePlan (Write: caps, alerts and changing plan) |
| `billing` | ViewInvoices (Read), PayInvoices (Use), ManageBillingProfile (Write) |
| `datamap` | Read (Read), Scan (Use), Edit (Write) |
| `readiness` | Run (Use), Read (Read), VerifyIntegrity (Read), ExportEvidence (Use) |
| `system` | ReadStatus (Read) |

**Server** actions are checked by the service on every request. **Interface** actions are enforced
in the dashboard, because the log pages read NigraniAI directly and its RLS only checks that someone
is signed in. Navigation shows only permitted sections, write controls are hidden per action, and
the AI only uses data from permitted sections.

---

## 7. Usage, plans and billing

### 7.1 Meters

Counted by the service per person per IST day (the browser can't change them); kept 12 months.

| Meter | Counts | Billed | Hard limit allowed |
|---|---|---|---|
| Log lines analysed | each unique line once, when first read (an `ingested_at` watermark survives restarts) | yes | **no** |
| AI questions · AI tokens · Files attached to AI | answered questions; prompt + answer tokens (provider count, else ~4 chars/token); attachments | yes | yes |
| Customer lookups | email / phone lookups | yes | yes |
| Users (seats) | dashboard accounts now | yes | yes (blocks new users) |
| Detector scans · Detector line reads · Anomaly model runs · Incidents opened · API requests | activity, for transparency | no | no |

Background work (detector scans, the model) is counted for the person whose open page triggered it.

### 7.2 Plans (`provider.json`)

The provider's catalogue (starting values, edit freely): **Free** ₹0 (hard limits on AI, lookups,
users), **Starter** ₹19,999/month, **Growth** ₹79,999, **Enterprise** ₹2,50,000. Each plan has a
monthly fee and, per meter, `[included per month (null = unlimited), overage price per block]`
(blocks: log lines per 10,000; AI tokens per 1,00,000; others per unit) and which meters have hard
limits. ShopSmart is on **Growth** (`billing.initial_plan` sets the plan of a new copy).

- The client's admins **can't change prices or allowances**; they can choose another plan (Billing)
  and set per-person caps and alert levels (80% and 100% by default).
- **Soft limit** (default): usage continues and is billed as overage. **Hard limit**: the request is
  refused (HTTP 429) with a clear message. **Breach monitoring is never blocked.**
- **Alerts** fire once per cycle per level, go to the activity log and show as a banner.
- The provider changes the client's plan directly with `plan set <plan>` (no invoice).

### 7.3 Invoices

- **Monthly**, when a billing cycle closes: plan fee + one line per meter over its allowance. Billing
  starts the first time the service runs (`billing.json` → `started_at`); a first partial month is
  charged pro rata.
- **Plan change** (client, Billing tab): upgrade → pro-rated invoice `(new fee − current fee) × share
  of the cycle left`; the plan starts when it's paid. Downgrade → from the next cycle.
- **Bill now** (provider command): the current cycle's usage so far.
- **GST 18%:** CGST 9% + SGST 9% when the client's state is the seller's, IGST 18% otherwise (place of
  supply = the client's state). Can be switched off in `provider.json`.
- **Numbers** run per financial year: `DPDP/26-27/0001` (≤ 16 characters; prefix in `provider.json`).
- **Printable tax invoice:** seller and buyer names, addresses, states and GSTINs, place of supply,
  SAC, period, lines, taxable value, tax, total, amount in words, payment status.
- Statuses: issued, paid, overdue (display), void, refunded. Invoices can't be issued until the
  seller's legal name, state and GSTIN are filled in `provider.json`.

### 7.4 Payments (Razorpay)

1. **Pay** → the server creates a Razorpay **order** for the exact invoice amount (in paise; reused if
   unchanged). The secret never leaves the server; the browser can't change the amount.
2. **Razorpay Checkout** (card, UPI, netbanking, wallets) runs in Razorpay's own window; card data
   never reaches this system. The money goes to the provider's Razorpay account.
3. **Verify**: the server checks the signature `HMAC-SHA256(order_id|payment_id, key secret)`, then
   **fetches the payment from Razorpay** and requires it to be captured (capturing an authorised
   payment if needed) with a matching order and amount. Only then is the invoice marked paid, once
   per payment id; a paid upgrade switches the plan.
4. **Webhook** `POST /api/billing/webhook`: `payment.captured`, `payment.failed`, `refund.processed`,
   verified with `X-Razorpay-Signature` and `RAZORPAY_WEBHOOK_SECRET`; duplicates ignored. Needs a
   public URL, so it goes live when deployed.
5. **Provider commands:** `mark-paid` (bank transfer, needs a reference), `void` (unpaid only),
   `refund` (through Razorpay).

**Unpaid invoices:** banner from the due date (15 days after issue by default); after the grace
period (14 days past due) the dashboard drops to Free-plan limits until paid, then the plan is
restored (and a paid upgrade applies on top). Monitoring keeps running.

**Testing:** with `rzp_test_` keys no real money moves; pay with the UPI ID `success@razorpay` or a
Razorpay test card from their documentation.

---

## 8. Security and privacy

| Topic | How it's handled |
|---|---|
| Secrets | Only the NigraniAI **anon** key is in the browser. Service keys, the AI key and Razorpay keys live in `.env`, used only by the service; `provider.json` is never served |
| Sign-in | Supabase Auth; every API call carries the user's JWT, verified by the service; CORS limited to `CONSENT_ALLOWED_ORIGINS`; public sign-up disabled |
| Least privilege | Deny by default, explicit deny wins, every route mapped to an action; denials logged |
| Shop data | Reached only through the service with `GET`; direct identifiers, contact and address data, free text, credentials and payment references stripped (`BLOCKED_COLUMNS`); personal-column filters refused; lookups return numbers only |
| Logs | Read with the user's own JWT (RLS applies), never the service key |
| Prices | Set only by the provider on the server; the client can choose a plan, not change one |
| AI | Only aggregates and ids are sent; attachments are sent as-is (the UI warns) |
| Payments | Hosted Checkout; amounts fixed server-side; signature + server-to-Razorpay confirmation; webhook signatures; idempotent |
| Integrity | Versioned stores, revision checks (409 on stale edits), append-only activity log, per-incident activity log |

---

## 9. API reference

Base URL `http://localhost:8091`. JSON in and out. All routes need `Authorization: Bearer <JWT>`
except `/api/health` and the Razorpay webhook. The action in brackets is the IAM permission required.

### Account and access

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | **no sign-in** · service is up and configured |
| GET | `/api/me` | email, root flag, allowed actions, policies, client, billing flags, usage alerts, AI questions left |
| GET | `/api/iam/catalog` | every action and service |
| GET | `/api/audit?scope=me\|all&user=` | activity log (`all` needs `iam:ReadAllActivity`) |
| GET | `/api/system` | service status [system:ReadStatus] |
| GET | `/api/iam` | users, groups, policies [iam:ListUsers / iam:ListPolicies] |
| POST · PUT · DELETE | `/api/iam/users`, `/api/iam/users/<id>` | create · reset password / (de)activate · remove [iam:ManageUsers] |
| PUT | `/api/iam/users/<id>/access` | groups and direct policies [iam:AttachPolicies] |
| POST · PUT · DELETE | `/api/iam/policies[/<id>]`, POST `…/restore/<v>` | policies and versions [iam:ManagePolicies] |
| POST · PUT · DELETE | `/api/iam/groups[/<id>]` | groups and members [iam:ManageGroups] |
| POST | `/api/iam/validate` · `/api/iam/simulate` | validate a document · simulate a person at a time [iam:SimulatePolicy] |

### Data (customer database)

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/schema` | shop tables and columns, blocked columns |
| GET | `/api/table/<table>?columns=` | minimised rows |
| GET | `/api/query/<table>?f=col.op.value&order=&limit=&offset=` | filtered, paged rows with an exact total |
| GET | `/api/customers/lookup?q=` | customer numbers for a full email or phone [consent:LookupCustomer] |
| GET | `/api/retention/erasure` · `/api/retention/inactivity` | erasure checklists · inactivity [retention:ReadSchedule] |

### Versioned stores

`/api/policy` (consent), `/api/retention-policy`, `/api/breach-policy`, each with: GET (current), PUT
(`policy`, `base_version`, `change_note`; 409 if someone saved first), GET `…/history`, GET
`…/history/v<N>`, POST `…/restore/v<N>`.

### Breach Response

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/breach/scan` | detectors + anomaly model on the logs (cached 15 s), triage state, register; auto-opens incidents |
| POST | `/api/breach/preview` | dry run of draft detectors |
| GET | `/api/breach/model` | model summary, per-service baselines, every slice's score, anomalies |
| POST | `/api/breach/model/retrain` | retrain now; with `preview` (draft settings) nothing is stored |
| POST | `/api/breach/signals/<id>/dismiss\|reopen\|link` | triage [breach:TriageSignal] |
| GET · POST | `/api/incidents` | register · report by hand [breach:CreateIncident] |
| GET · PUT | `/api/incidents/<BR-YYYY-NNNN>` | one incident · update (`rev`, `changes`) [breach:UpdateIncident] |

### AI and readiness

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/ai/status` | provider and model |
| POST | `/api/ai/chat` | `question`, `context`, `history`, optional `attachment` → streamed text [ai:Ask] |
| GET · POST | `/api/readiness` | score history · save a result [readiness:Read / readiness:Run] |
| GET | `/api/evidence` | verify now + seals, exports, log retention [readiness:VerifyIntegrity / readiness:Read] |
| GET | `/api/datamap` | last scan, history, declarations [datamap:Read / readiness:Read] |
| POST | `/api/datamap/scan` | rebuild the data map [datamap:Scan] |
| POST | `/api/datamap/live` | incremental live update → result + `live` {new_rows, delta, new_gaps, closed_gaps} [datamap:Read / datamap:Scan] |
| PUT | `/api/datamap/config` | declarations with `rev` → 409 on conflict [datamap:Edit] |
| POST | `/api/evidence/verify` | run a verification [readiness:VerifyIntegrity] |
| POST | `/api/evidence/pack` | `from`, `to` (YYYY-MM-DD) → evidence pack JSON [readiness:ExportEvidence] |
| POST | `/api/evidence/check` | an evidence pack → `unchanged`, `recorded` [readiness:VerifyIntegrity] |

### Usage and billing

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/usage?scope=me\|all` | usage this cycle vs the plan, estimate, daily totals, alerts |
| PUT | `/api/usage/plan` | per-person caps and alert levels only (`rev`, `plan`) [usage:ManagePlan] |
| GET | `/api/billing` | plan options (pro-rated), invoices, billing details [billing:ViewInvoices] |
| PUT | `/api/billing/profile` | billing name, address, state, GSTIN, email [billing:ManageBillingProfile] |
| POST | `/api/billing/upgrade` | `{template, preview?}` [usage:ManagePlan] |
| POST | `/api/billing/invoices/<id>/pay` | create / reuse the Razorpay order [billing:PayInvoices] |
| POST | `/api/billing/verify` | Checkout result → signature + payment check → paid |
| POST | `/api/billing/webhook` | **no sign-in**, signed by Razorpay |

Common errors: 401 not signed in · 403 access denied · 409 stale edit · 429 usage limit.

---

## 10. Configuration

### `.env` (server only)

| Key | Required | Meaning |
|---|---|---|
| `CLIENT_NAME`, `CLIENT_ID` | yes | the client this copy is built for (default `ShopSmart`) |
| `SUPABASE_URL` | yes | NigraniAI project: sign-in and logs |
| `GUARDRAIL_ANON_KEY` | yes | verifies sign-ins; reads logs with the user's JWT |
| `SUPABASE_SERVICE_KEY` | yes | Auth admin API: creating, deactivating and deleting staff accounts |
| `SUPABASE_DB_SCHEMA` | yes | `guardrail` |
| `SUPABASE_DB_PASSWORD` | no | unused (left blank) |
| `SHOP_SUPABASE_URL`, `SHOP_SUPABASE_SERVICE_KEY` | yes | the client's shop database, read-only |
| `CENTRAL_URL`, `CENTRAL_ANON_KEY`, `CENTRAL_CLIENT_KEY` | for provider reporting | the provider console's Supabase URL, its public key, and this copy's client key (from Provider Console → Add client). Unset = no reporting |
| `CENTRAL_REPORT_MINUTES` | no (15) | how often this copy reports to the provider |
| `CONSENT_PORT`, `CONSENT_ALLOWED_ORIGINS` | no | `8091` · browser origins (default `http://localhost:8090`) |
| `ROOT_EMAIL` | yes | the client's root admin |
| `GROK_API_KEY` | for AI | `gsk_…` (Groq) or `xai-…` (xAI) |
| `GROK_MODEL`, `GROK_CONTEXT_CHARS`, `GROK_BASE_URL` | no | force a model · context budget (10,000) · another OpenAI-compatible endpoint |
| `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` | for payments | the provider's keys (`rzp_test_…` for test mode) |
| `RAZORPAY_WEBHOOK_SECRET` | no | verifies webhooks (set with the public webhook URL in Razorpay) |

Values are trimmed, so `KEY= value` works for the service (shell tools won't trim; avoid the space).

### `consent_service/provider.json` (provider only)

| Key | Meaning |
|---|---|
| `seller` | `legal_name`, `address`, `state`, `gstin`, `email`: printed on invoices (required before invoicing) |
| `billing` | `prefix` (invoice numbers), `due_days` (15), `gst` (true), `sac` (`998314`; check with your accountant), `grace_days` (14), `initial_plan` (`growth`) |
| `plans` | the catalogue: name, `base_fee`, per-meter `[included, overage]`, `hard` limits |

### `frontend/config.js` (browser, public values only)

`DASHBOARD_URL`, `DASHBOARD_ANON_KEY`, `DB_SCHEMA`, `CONSENT_API`.

### Fixed defaults in code

GST 18% · usage history 366 days · model 150 trees / 256 samples, rescore 10 s, re-learn 600 s ·
breach scan cache 15 s · billing check every 30 s.

---

## 11. Data storage

Everything the system stores is JSON in `consent_service/data/` (created on first run):

| File | Contents |
|---|---|
| `policy.json` + `history/` | consent policy and every version |
| `retention.json` + `retention_history/` | retention schedule and versions |
| `breach.json` + `breach_history/` | detectors, clocks, notice contact, anomaly settings, versions |
| `incidents.json` | the breach register and signal triage **(the legal breach record; back it up)** |
| `iam.json` | policies (with versions), groups, assignments, access-advisor data |
| `audit.jsonl` | append-only activity log |
| `plan.json` | the client's current plan (from the catalogue), per-person caps, alert levels |
| `usage.json` | meters per person per IST day, alert log, log watermark |
| `billing.json` | billing details, invoices, payments, refunds, invoice numbering, Razorpay orders, closed cycles, pending plan change, overdue state, `started_at` |
| `readiness.json` | readiness score history |
| `exposure.json` | archived: results of the removed public exposure test (kept as evidence) |
| `ledger.jsonl` | hash-chained evidence ledger (append-only; never edit) |
| `datamap.json` | data map declarations, last scan (names and counts only) and 30-scan history |
| `pii.json` | PII detection v2: per-column verdicts and evidence (no values), admin feedback |
| `integrity.json` | last verification result |
| `.ledger.lock` | file lock for ledger writes |

The ML model, scan results and log windows live only in memory and are rebuilt after a restart.

---

## 12. Operations and provider commands

Run on the server, next to `.env`:

```bash
python3 consent_service/server.py status                   # plan, usage this cycle, unpaid invoices
python3 consent_service/server.py plans                    # the catalogue in provider.json
python3 consent_service/server.py plan set enterprise      # move the client to a plan now (no invoice)
python3 consent_service/server.py invoices                 # every invoice
python3 consent_service/server.py bill-now                 # invoice the usage so far this cycle
python3 consent_service/server.py mark-paid DPDP/26-27/0001 NEFT-123   # record a bank transfer
python3 consent_service/server.py void DPDP/26-27/0002     # cancel an unpaid invoice
python3 consent_service/server.py refund DPDP/26-27/0001   # refund a Razorpay payment in full
```

Every command is written to the activity log as `provider`.

- **Restart** the service after changing `.env`, `provider.json` or `server.py`. Usage is flushed every
  5 s and on shutdown; the model re-learns in ~20 s.
- **Frontend changes:** bump the `?v=` of the changed file in `index.html`, then hard-refresh.
- **Backups:** `consent_service/data/` (especially `incidents.json`, `billing.json`, `audit.jsonl`,
  `ledger.jsonl`). Restore the whole folder together: a partial restore shows as tampering.
- **Before handing over / going live:**
  1. Serve both parts over HTTPS; set `CONSENT_API` and `CONSENT_ALLOWED_ORIGINS` to the real origins.
  2. Replace the test root account with the client's admin (`ROOT_EMAIL`) and create their staff.
  3. Fill in `provider.json` → `seller` (legal name, state, GSTIN) and review the plan prices.
  4. Switch Razorpay to live keys; add the webhook URL `https://<host>/api/billing/webhook` and
     `RAZORPAY_WEBHOOK_SECRET`.
  5. Start with an empty `data/` (defaults are recreated) so the ledger's genesis is the handover;
     note the chain fingerprint in the handover document.

---

### Reporting to the provider console

Each copy reports to the provider's own Supabase project (the **Provider Console**, a separate project in `~/Downloads/provider_console/`) so the provider can track every client together.

- **What and when:** `central_report()` sends the plan and allowances, usage meters (this cycle and per day for 35 days), invoices (number, period, status, amounts, line descriptions), health (readiness, data map, record integrity, open and overdue breach incidents) and service status. It goes 15 s after start, every `CENTRAL_REPORT_MINUTES`, and within about 5 s of any billing change (`write_billing` triggers it).
- **No personal data:** no customer records, log contents or emails, only counts, amounts and scores. A report is about 2–3 KB.
- **How:** POST `/rest/v1/rpc/report_in` on the console project with the public anon key plus this copy's client key. The key only lets it call that function, and a wrong key gets "not authorised".
- **Never blocks the copy:** a failure is logged, shown in System status (`provider_reporting`: last ok, last error, sent), and retried next interval.
- **Turn it off:** remove the three `CENTRAL_*` settings and restart.

---

## 13. Building the next client's copy

1. **Copy** the project without `consent_service/data/` (each copy starts with an empty data folder).
2. **`.env`:** the new client's `CLIENT_NAME` / `CLIENT_ID`, their NigraniAI-format log project and
   shop database URLs and keys, `ROOT_EMAIL` for their admin, your `GROK_API_KEY` and Razorpay keys.
3. **`frontend/config.js`:** their NigraniAI URL and anon key, and the service URL.
4. **`provider.json`:** your seller details, their plan catalogue and prices, `initial_plan`.
4a. **Provider console:** add the client there, and put the `CENTRAL_*` lines it shows into their `.env`.
5. **Starting policies** (`consent_service/default_*.json`), adjusted to their data inventory:
   - `default_policy.json`: purposes, processing sources, notices, consent fields, rules, inventory;
   - `default_retention.json`: retention rules for their tables and legal minimums;
   - `default_breach.json`: detectors, response clocks, notice contact, anomaly settings.
   - `default_datamap.json`: each service's and table's purposes, and the processors register.
   - Language model for PII detection (optional): create `consent_service/.pii-venv` as in §5.7b. Don't copy it between machines; recreate it.
6. **Customise** whatever their requirements need, then run, test and hand over (§12 checklist).

The provider's future central system will read each copy's usage and billing; the data it needs is in
`usage.json` and `billing.json` and in the `status` / `invoices` commands.

---

## 14. Legal reference

| Instrument | Used for |
|---|---|
| DPDP Act 2023 s.2(u) | definition of a personal data breach (incl. loss of access) |
| ss.4–7 | lawful processing, notice (s.5), consent (s.6), legitimate uses (s.7) |
| s.8(1), 8(5), 8(6), 8(7) | accountability, reasonable security safeguards, breach intimation, erasure when the purpose is served |
| s.9, s.10 | children's data; Significant Data Fiduciaries (not yet built) |
| ss.11–14 | Data Principal rights: access, correction and erasure, grievance, nomination (not yet built) |
| DPDP Rules 2025, Rule 3 | notice contents |
| Rule 6 | security safeguards: monitoring, logs, detection |
| Rule 7 | breach intimation: customers (7(1)), Board initial (7(2)(a)) and 72-hour report (7(2)(b)); applies from 13 May 2027 |
| Rule 8 and Third Schedule | retention, inactivity erasure with 48-hour notice, 1-year log retention |
| CERT-In Directions, 28 Apr 2022 | 6-hour cyber-incident reporting |
| CGST Act 2017 s.36 | 72-month retention of tax records (orders, payments) |

---

---

## 15. Known limitations

| Item | Detail |
|---|---|
| Interface-enforced actions | `dashboard:View`, `telemetry:ReadLogs` and CSV exports are enforced in the UI (logs are read directly from NigraniAI) |
| Webhooks | Need a public URL; until deployed, payments are confirmed by the Checkout verification |
| Local file storage | Stores are JSON files for one service instance, not database tables |
| PII false positives | NigraniAI's masker flags epoch timestamps as `[CARD]`; the fix belongs upstream |
| Truncated SQL | Long SQL templates are cut by the logger, so later fields can't be listed |
| Breach detection sees only logs | Lost laptops or misdirected emails must be reported by hand; detectors scan the look-back window (7 days, ≤ 20,000 lines per detector per scan) |
| Notices are drafts | Nothing is emailed to the Board, CERT-In or customers |
| No automatic deletion | Databases are read-only to this system; retention produces worklists |
| Revocation time | `auth_refresh_tokens` stores only whether a token is revoked; rules measure from issue time |
| Inactivity | Based on last sign-in or order only |
| Anomaly model | 3 days of mostly idle demo data, so "usually 0" is common; no hour-of-week seasonality yet; per service, not per person |
| AI | Answers can be wrong; check figures and citations; the free tier limits context size |
| Not yet built | Data Principal rights requests and grievances (ss.11–14, Rule 14), children's data (s.9), Significant Data Fiduciary duties (s.10) |

---

## 16. Project structure

```
frontend/                     static app (no build)
  index.html                  sign-in, sidebar, every page's container, icons
  style.css                   design system, light and dark tokens, print styles
  config.js                   public browser settings
  app.js                      session, authenticated fetch, navigation, access, banners
  dashboard.js                main dashboard: log window, SVG charts, module numbers
  telemetry.js                Log Telemetry
  consent.js                  Consent & Purpose engine and screens
  retention.js                Retention engine and screens
  breach.js                   Breach Response, clocks, notices, anomaly model view
  ai.js                       AI Assistant
  readiness.js                readiness scoring and report
  datamap.js                  data map: flow map, inventory, record of processing, gaps, declarations
  usage.js                    Usage & plan
  billing.js                  Billing tab, Razorpay Checkout, printable tax invoice
  iam.js                      Access management
  account.js                  account menu and Account page
consent_service/
  server.py                   the service: auth, IAM, stores, shop bridge, retention, breach detection
                              and register, anomaly model, AI proxy, usage, readiness, billing,
                              Razorpay, provider commands
  provider.json               the provider's seller details, billing rules and plan catalogue
  default_policy.json         starting consent policy (ShopSmart Customer Data Inventory)
  default_retention.json      starting retention schedule
  default_breach.json         starting detectors, clocks and anomaly settings
  data/                       created on first run (see §11)
.env                          server-side keys and settings (never served)
```

---

## 17. History

| Date | Milestone |
|---|---|
| 15 Oct 2026 | Log Telemetry, Consent & Purpose; the old two-project pipeline (`sync_bridge.py`, `pii_worker.py`, `pii_engine.py` with Presidio/spaCy) removed |
| 16–17 Oct 2026 | Retention, Breach Response, Dashboard charts, AI Assistant, Accounts, IAM, ML anomaly model (made live) |
| 18 Oct 2026 | Usage meters, plans, billing with GST and Razorpay; readiness score. A multi-company version (workspaces, public sign-up, setup wizard) was built and then removed: each client gets their own copy. Backup of that version: `~/Downloads/complaince_dashboard-backup-multicompany-2026-10-18/` |

Live snapshot (ShopSmart, 17–18 Oct 2026): 28,702 log lines from 9 services; 2 of 8 customers with
valid consent and 6 open consent issues; 16 detector signals and 8 anomalies over 7 days; nothing past
a retention deadline, 59 session tokens due soon, 28,742 records under legal hold; readiness 74–75 (B); data map health 53 (13 gaps); public exposure test 100 (all 17 tables blocked for the public key); records & evidence 100.

## Deployment (AWS Lightsail, Mumbai)

The whole system (dashboard, consent service, local AI model and the provider console) runs on **one
Lightsail server** `nigrani-1` in `ap-south-1`, behind nginx with a free Let's Encrypt certificate.

| | |
|---|---|
| Dashboard | https://<server-ip-dashed>.sslip.io |
| Provider console | https://<server-ip-dashed>.sslip.io/console/ |
| Server | Ubuntu 24.04, 1 GB RAM + 3 GB swap, static IP <server-ip> (the plan AWS allows a new account; move up via snapshot later) |
| AI model on the server | `en_core_web_md` (`PII_NER_MODEL` in the server's .env); `en_core_web_lg` locally |
| Backups | Lightsail automatic snapshot every day at 03:30 IST |

`sslip.io` turns the IP into a name so HTTPS works without buying a domain. With a real domain, point
it at the IP, change `HOSTNAME_PUBLIC` in `deploy/target.env` and `CONSENT_ALLOWED_ORIGINS` on the
server, and run `./deploy/deploy.sh setup`.

**Server layout** (`/opt/nigrani`): `releases/<time>/{app,console}` (code, last 5 kept), `current` →
the live release, and `shared/` holding what deploys never overwrite: `app.env`, `console.env`, `data/`
(live records and evidence ledger), `provider.json` and `pii-venv/`. Services: `nigrani-consent`
(:8091), `nigrani-console` (:8094) and nginx; all restart by themselves.

**Making changes:** edit and test locally, commit, then run

```
./deploy/deploy.sh            # deploy committed code (health check, automatic rollback)
./deploy/deploy.sh rollback   # back to the previous release
./deploy/deploy.sh status | logs [consent|console|nginx] | ssh | setup
```

SSH is open only to your current internet address; the script updates that rule when your address
changes. Policies, users and other settings changed in the live dashboard are saved on the server
and need no deploy. The local copy is for development: its provider reporting is switched off
(`CENTRAL_CLIENT_KEY` commented out in the local .env), so only the server reports as `shopsmart`.
