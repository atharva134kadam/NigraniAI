"""Consent & Purpose service for the DPDP dashboard.

Read-only bridge to the ShopSmart shop database plus a versioned policy store.

* Keeps the shop service_role key server-side (read from ../.env); the browser
  never sees it.
* Every /api call must carry a valid NigraniAI (dashboard) user JWT.
* Data minimisation: rows are returned without direct identifiers or free text
  (BLOCKED_COLUMNS), so the browser gets ids, timestamps, types and consent flags only.
* Only GET requests reach Supabase; nothing in either database is modified.
* Policies live in data/policy.json; every save is kept in data/history/.
* Access management modelled on AWS IAM: every request maps to an action (ROUTE_ACTIONS) and is
  denied unless a policy attached to the user (directly or through a group) allows it; an explicit
  Deny wins; the root user (ROOT_EMAIL in .env) is never restricted. Policies, groups and
  assignments live in data/iam.json; users are managed through the NigraniAI Auth admin API
  (service key, server-side). Key actions and denied requests go to data/audit.jsonl.
* AI assistant: /api/ai/chat streams answers from Groq / xAI (GROK_API_KEY in .env, never sent to
  the browser). The browser supplies only aggregated, minimised dashboard data as context.
* Breach response: detectors (data/breach.json, versioned) and a live ML anomaly model scan the
  NigraniAI logs with the caller's own token; the breach register lives in data/incidents.json,
  with a per-incident audit trail.
* Usage and billing: usage is metered per person per day (data/usage.json); the client's plan comes
  from the provider's catalogue (provider.json); invoices with GST are issued when a billing cycle
  closes and paid with Razorpay (data/billing.json).

This copy is built for one client (CLIENT_NAME in .env) and handed over to them.

Run the service:        python3 consent_service/server.py      (http://localhost:8091)
Provider commands:      python3 consent_service/server.py help
"""

import collections
import fcntl
import hashlib
import json
import math
import os
import random
import re
import statistics
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
HISTORY = DATA / "history"
POLICY_FILE = DATA / "policy.json"
DEFAULT_POLICY = ROOT / "default_policy.json"
RETENTION_FILE = DATA / "retention.json"
RETENTION_HISTORY = DATA / "retention_history"
DEFAULT_RETENTION = ROOT / "default_retention.json"
BREACH_FILE = DATA / "breach.json"
BREACH_HISTORY = DATA / "breach_history"
DEFAULT_BREACH = ROOT / "default_breach.json"
INCIDENTS_FILE = DATA / "incidents.json"


def load_env():
    env = ROOT.parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


load_env()
SHOP_URL = os.getenv("SHOP_SUPABASE_URL", "").rstrip("/")
SHOP_KEY = os.getenv("SHOP_SUPABASE_SERVICE_KEY", "")
SHOP_ANON = os.getenv("SHOP_SUPABASE_ANON_KEY", "")           # the public key the shop's website ships; used only by the exposure test
AUTH_URL = os.getenv("SUPABASE_URL", "").rstrip("/")          # NigraniAI project (dashboard login)
AUTH_ANON = os.getenv("GUARDRAIL_ANON_KEY", "")
GR_SCHEMA = os.getenv("SUPABASE_DB_SCHEMA", "guardrail")
PORT = int(os.getenv("CONSENT_PORT", "8091"))
ORIGINS = {o.strip() for o in os.getenv("CONSENT_ALLOWED_ORIGINS", "http://localhost:8090").split(",") if o.strip()}

# Direct identifiers, contact/address data, credentials and free text never leave this service.
BLOCKED_COLUMNS = {
    "name", "email", "phone", "full_name", "reviewer_name", "label",
    "line1", "line2", "city", "state", "pincode",
    "ship_full_name", "ship_phone", "ship_line1", "ship_line2", "ship_city", "ship_state", "ship_pincode",
    "password_hash", "token_hash", "message", "comment", "title", "note",
    "cancel_reason", "return_reason", "failure_reason", "reason",
    "payment_reference", "provider_order_id", "provider_payment_id", "refund_id", "idempotency_key",
}
IDENT = re.compile(r"^[A-Za-z0-9_.()\- ]{1,63}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- the client this copy is built for
# One copy of this system is built for and handed over to one client company. Its name appears in
# the dashboard, notices, invoices and the AI's instructions; its data sources are the .env settings.
CLIENT_NAME = (os.getenv("CLIENT_NAME") or "ShopSmart").strip()
CLIENT_ID = (os.getenv("CLIENT_ID") or re.sub(r"[^a-z0-9]+", "-", CLIENT_NAME.lower()).strip("-") or "client").strip()


# ---------------------------------------------------------------- Supabase (read-only)
def shop_get(path, params=None, accept_openapi=False, count=False):
    """GET from the shop database. With count=True returns (rows, total) using count=exact."""
    url = f"{SHOP_URL}/rest/v1{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"apikey": SHOP_KEY, "Authorization": f"Bearer {SHOP_KEY}"}
    if accept_openapi:
        headers["Accept"] = "application/openapi+json"
    if count:
        headers["Prefer"] = "count=exact"
    req = urllib.request.Request(url, headers=headers, method="GET")
    # Retry transient failures (network, timeouts, 5xx); a 4xx is a real answer.
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                if count:
                    total = (r.headers.get("Content-Range") or "*/0").split("/")[-1]
                    return json.load(r), int(total) if total.isdigit() else None
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(0.4 * (attempt + 1))


_schema_cache = {"at": 0, "value": None}
_schema_lock = threading.Lock()


def shop_schema():
    with _schema_lock:
        return _shop_schema()


def _shop_schema():
    if time.time() - _schema_cache["at"] > 30 or _schema_cache["value"] is None:
        spec = shop_get("/", accept_openapi=True)
        tables = {}
        for name, d in (spec.get("definitions") or {}).items():
            tables[name] = [{"name": c, "type": p.get("format") or p.get("type") or ""}
                            for c, p in (d.get("properties") or {}).items()]
        _schema_cache.update(at=time.time(), value=tables)
    return _schema_cache["value"]


def shop_rows(table, columns):
    """All rows of `table`, only `columns` that exist and are not blocked."""
    schema = shop_schema()
    if table not in schema:
        raise ValueError(f"unknown table: {table}")
    existing = [c["name"] for c in schema[table]]
    wanted = existing if columns == ["*"] else [c for c in columns if c in existing]
    keep = [c for c in wanted if c not in BLOCKED_COLUMNS]
    if not keep:
        return {"columns": [], "blocked": sorted(set(wanted) & BLOCKED_COLUMNS), "rows": []}
    rows, off = [], 0
    while True:
        # select=* then project: column names in this schema may contain dots/parentheses.
        page = shop_get(f"/{urllib.parse.quote(table)}", {"select": "*", "limit": 1000, "offset": off})
        rows += [{c: r.get(c) for c in keep} for r in page]
        if len(page) < 1000:
            break
        off += 1000
    return {"columns": keep, "blocked": sorted(set(wanted) & BLOCKED_COLUMNS), "rows": rows}


# ---------------------------------------------------------------- filtered queries (server-side counts and pages)
SAFE_COL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
SAFE_VAL = re.compile(r"^[A-Za-z0-9:.+\-_ ]{1,64}$")  # timestamps, numbers, simple words
FILTER_OPS = {"lt", "lte", "gt", "gte", "eq", "neq"}


def shop_query(table, columns, filters, order=None, limit=50, offset=0):
    """Filtered, ordered, paged rows of a shop table plus the exact total.

    Filters are "column.op.value" with op in lt/lte/gt/gte/eq/neq/is/null/notnull.
    Filtering on blocked (personal) columns is refused; returned rows are minimised.
    """
    schema = shop_schema()
    if table not in schema:
        raise ValueError(f"unknown table: {table}")
    existing = [c["name"] for c in schema[table]]
    params = [("select", "*"), ("limit", str(max(0, min(int(limit), 1000)))), ("offset", str(max(0, int(offset))))]
    for f in filters:
        parts = f.split(".", 2)
        col, op = parts[0], parts[1] if len(parts) > 1 else ""
        val = parts[2] if len(parts) > 2 else ""
        if not SAFE_COL.match(col) or col not in existing or col in BLOCKED_COLUMNS:
            raise ValueError(f"cannot filter on column: {col}")
        if op == "null":
            params.append((col, "is.null"))
        elif op == "notnull":
            params.append((col, "not.is.null"))
        elif op == "is" and val in ("true", "false", "null"):
            params.append((col, f"is.{val}"))
        elif op in FILTER_OPS and SAFE_VAL.match(val):
            params.append((col, f"{op}.{val}"))
        else:
            raise ValueError(f"invalid filter: {f}")
    if order:
        col, _, direction = order.partition(".")
        if not SAFE_COL.match(col) or col not in existing or direction not in ("asc", "desc"):
            raise ValueError(f"invalid order: {order}")
        params.append(("order", f"{col}.{direction}.nullslast"))
    rows, total = shop_get(f"/{urllib.parse.quote(table)}", params, count=True)
    wanted = existing if columns == ["*"] else [c for c in columns if c in existing]
    keep = [c for c in wanted if c not in BLOCKED_COLUMNS]
    return {"columns": keep, "rows": [{c: r.get(c) for c in keep} for r in rows], "total": total}


def _all(table, select="*", extra=None):
    rows, off = [], 0
    while True:
        page = shop_get(f"/{table}", [("select", select), ("limit", "1000"), ("offset", str(off))] + list(extra or []))
        rows += page
        if len(page) < 1000:
            return rows
        off += 1000


def _ts(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


ERASED_EMAIL = re.compile(r"erased|deleted|anonym|redacted|\.invalid$", re.I)


def erasure_status(delay_seconds, marketing_column):
    """Erasure requests with a per-customer checklist, computed here so the
    browser gets only true/false answers, never the personal data itself."""
    now = datetime.now(timezone.utc)
    cols = [c["name"] for c in shop_schema().get("customers", [])]
    if marketing_column and marketing_column not in cols:
        marketing_column = ""
    reqs = _all("customers", "*", [("or", "(deletion_requested_at.not.is.null,erased_at.not.is.null)")])
    if not reqs:
        return {"requests": [], "checked_at": now.isoformat(timespec="seconds")}
    ids = ",".join(str(r["id"]) for r in reqs)
    count_by = lambda rows, key: {str(k): sum(1 for r in rows if str(r.get(key)) == str(k)) for k in {r.get(key) for r in rows}}
    addresses = count_by(_all("customer_addresses", "customer_id", [("customer_id", f"in.({ids})")]), "customer_id")
    wishlist = count_by(_all("customer_wishlist", "customer_id", [("customer_id", f"in.({ids})")]), "customer_id")
    reviews = count_by(_all("product_reviews", "customer_id", [("customer_id", f"in.({ids})")]), "customer_id")
    users = ",".join(str(r["auth_user_id"]) for r in reqs if r.get("auth_user_id") is not None) or "0"
    tokens = _all("auth_refresh_tokens", "user_id,revoked,expires_at", [("user_id", f"in.({users})")])
    active = {}
    for t in tokens:
        exp = _ts(t.get("expires_at"))
        if not t.get("revoked") and exp and exp > now:
            active[str(t["user_id"])] = active.get(str(t["user_id"]), 0) + 1
    out = []
    for r in reqs:
        asked = _ts(r.get("deletion_requested_at"))
        done = _ts(r.get("erased_at"))
        due = asked + timedelta(seconds=delay_seconds) if asked else None
        cid = str(r["id"])
        checks = {
            "profile_anonymised": (r.get("name") or "").strip().lower() == "erased customer",
            "email_replaced": bool(ERASED_EMAIL.search(r.get("email") or "")) or not r.get("email"),
            "phone_removed": not r.get("phone"),
            "marketing_off": (r.get(marketing_column) in (False, None)) if marketing_column else None,
            "addresses_deleted": addresses.get(cid, 0) == 0,
            "wishlist_deleted": wishlist.get(cid, 0) == 0,
            "sessions_revoked": active.get(str(r.get("auth_user_id")), 0) == 0,
        }
        remaining = {"addresses": addresses.get(cid, 0), "wishlist": wishlist.get(cid, 0),
                     "active_sessions": active.get(str(r.get("auth_user_id")), 0), "reviews": reviews.get(cid, 0)}
        complete = all(v for v in checks.values() if v is not None)
        if done and complete:
            status = "completed" if not due or done <= due else "completed_late"
        elif done:
            status = "incomplete"            # marked erased, but data remains
        else:
            status = "overdue" if due and now > due else "pending"
        out.append({"id": cid, "requested_at": r.get("deletion_requested_at"), "erased_at": r.get("erased_at"),
                    "due_at": due.isoformat() if due else None, "status": status, "checks": checks, "remaining": remaining})
    return {"requests": sorted(out, key=lambda x: str(x["requested_at"]), reverse=True), "checked_at": now.isoformat(timespec="seconds")}


def inactivity_status(after_days, notice_hours, limit=200):
    """Customers approaching or past the inactivity erasure deadline.
    Last activity = latest sign-in (session token issued) or order."""
    now = datetime.now(timezone.utc)
    custs = _all("customers", "id,auth_user_id,erased_at")
    last_login, last_order = {}, {}
    for t in _all("auth_refresh_tokens", "user_id,created_at"):
        k, v = str(t["user_id"]), t.get("created_at")
        if v and v > last_login.get(k, ""):
            last_login[k] = v
    for o in _all("customer_orders", "customer_id,created_at"):
        k, v = str(o["customer_id"]), o.get("created_at")
        if v and v > last_order.get(k, ""):
            last_order[k] = v
    keep, notice = timedelta(days=after_days), timedelta(hours=notice_hours)
    rows = []
    for c in custs:
        if c.get("erased_at"):
            continue
        cands = [x for x in (last_login.get(str(c.get("auth_user_id"))), last_order.get(str(c["id"]))) if x]
        last = _ts(max(cands)) if cands else None
        if not last:
            rows.append({"id": str(c["id"]), "last_activity": None, "erase_at": None, "notify_at": None, "status": "no_activity"})
            continue
        erase_at = last + keep
        notify_at = erase_at - notice
        status = "overdue" if now >= erase_at else "notify" if now >= notify_at else "ok"
        rows.append({"id": str(c["id"]), "last_activity": last.isoformat(), "erase_at": erase_at.isoformat(),
                     "notify_at": notify_at.isoformat(), "status": status})
    rows.sort(key=lambda r: r["erase_at"] or "9999")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("overdue", "notify", "ok", "no_activity")}
    return {"customers": len(rows), "counts": counts, "next": next((r for r in rows if r["status"] == "ok"), None),
            "attention": [r for r in rows if r["status"] in ("overdue", "notify")][:limit]}


# ---------------------------------------------------------------- auth (NigraniAI users)
_token_cache = {}
_token_lock = threading.Lock()


def verify_user(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    with _token_lock:
        hit = _token_cache.get(token)
        if hit and hit[1] > time.time():
            return hit[0]
    req = urllib.request.Request(f"{AUTH_URL}/auth/v1/user",
                                 headers={"apikey": AUTH_ANON, "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            email = json.load(r).get("email") or "unknown"
    except urllib.error.HTTPError:
        return None
    with _token_lock:
        _token_cache[token] = (email, time.time() + 60)
    return email


# ---------------------------------------------------------------- policy stores (consent policy, retention schedule)
_policy_lock = threading.Lock()


def validate_policy(doc):
    for key in ("purposes", "activities", "notices", "field_map", "rules", "inventory"):
        if key not in doc:
            raise ValueError(f"policy is missing '{key}'")
    ids = [p.get("id") for p in doc["purposes"]]
    if len(ids) != len(set(ids)) or not all(ids):
        raise ValueError("every purpose needs a unique id")
    rule_ids = [r.get("id") for r in doc["rules"]]
    if len(rule_ids) != len(set(rule_ids)) or not all(rule_ids):
        raise ValueError("every rule needs a unique id")
    for a in doc["activities"]:
        for k in ("id", "table", "principal_column", "time_column"):
            if not a.get(k):
                raise ValueError(f"activity is missing '{k}'")
        for k in ("table", "principal_column", "time_column", "type_column"):
            if a.get(k) and not IDENT.match(a[k]):
                raise ValueError(f"invalid name in activity: {a[k]}")
        for k, v in (a.get("principal_via") or {}).items():
            if v and not IDENT.match(str(v)):
                raise ValueError(f"invalid name in activity link: {v}")
    for k, v in (doc.get("field_map") or {}).items():
        for col in (v if isinstance(v, list) else [v]):
            if col and not IDENT.match(str(col)):
                raise ValueError(f"invalid column for consent field {k}: {col}")
    for n in doc["notices"]:
        if n.get("capture") not in (None, "", "mandatory_signup", "prompted"):
            raise ValueError(f"notice {n.get('id')}: unknown capture '{n.get('capture')}'")
        if n.get("capture") == "mandatory_signup":
            try:
                datetime.fromisoformat(str(n.get("since") or "").replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"notice {n.get('id')}: a mandatory notice needs the date it became mandatory ('since')")
    su = doc.get("signup") or {}
    for col in ([su.get("column")] if isinstance(su.get("column"), str) else su.get("column") or []):
        if col and not IDENT.match(str(col)):
            raise ValueError(f"invalid sign-up column: {col}")
    for k, v in (su.get("via") or {}).items():
        if v and not IDENT.match(str(v)):
            raise ValueError(f"invalid name in sign-up link: {v}")


RETENTION_TYPES = {"erasure", "age", "legal_minimum", "inactivity"}


def validate_retention(doc):
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ValueError("retention schedule is missing 'rules'")
    ids = [r.get("id") for r in rules]
    if len(ids) != len(set(ids)) or not all(ids):
        raise ValueError("every retention rule needs a unique id")
    for r in rules:
        if r.get("type") not in RETENTION_TYPES:
            raise ValueError(f"unknown retention rule type: {r.get('type')}")
        if r.get("source", "shop") not in ("shop", "guardrail"):
            raise ValueError(f"unknown source: {r.get('source')}")
        for k in ("table", "clock_column", "filter_column"):
            if r.get(k) and not SAFE_COL.match(str(r[k])):
                raise ValueError(f"invalid name in rule {r.get('id')}: {r[k]}")
        keep = r.get("keep") or {}
        if r["type"] in ("erasure", "age", "legal_minimum", "inactivity"):
            if not isinstance(keep.get("n"), (int, float)) or keep.get("n") < 0 or keep.get("unit") not in ("seconds", "minutes", "hours", "days", "months", "years"):
                raise ValueError(f"rule {r.get('id')} needs a valid period")


# Fields a detector may match or group on, with their type.
DETECTOR_FIELDS = {
    "activity_logs": {"service": "text", "level": "text", "kind": "text", "event": "text", "route": "text",
                      "http_method": "text", "http_status": "int", "actor_type": "text", "actor_ref": "text",
                      "data_category": "text", "severity": "text", "purpose": "text", "consent_status": "text",
                      "risk_indicators": "array", "masked_pii_types": "array"},
    "database_logs": {"service": "text", "level": "text", "event": "text", "operation": "text", "db_table": "text",
                      "data_category": "text", "personal_data": "bool", "row_count": "int", "status": "text",
                      "sql_state": "text", "slow": "bool", "duration_ms": "int"},
}
DETECTOR_OPS = {"eq", "neq", "gt", "gte", "lt", "lte", "in", "is", "has"}
WINDOW_UNITS = {"minutes": 60, "hours": 3600, "days": 86400}
CATEGORIES = {"confidentiality", "integrity", "availability"}
SEVERITIES = ["low", "medium", "high", "critical"]


def validate_detector(d):
    did = d.get("id") or "?"
    fields = DETECTOR_FIELDS.get(d.get("source"))
    if not fields:
        raise ValueError(f"detector {did}: unknown log source {d.get('source')}")
    if d.get("category") not in CATEGORIES or d.get("severity") not in SEVERITIES:
        raise ValueError(f"detector {did}: invalid category or severity")
    for m in d.get("match") or []:
        if m.get("field") not in fields or m.get("op") not in DETECTOR_OPS:
            raise ValueError(f"detector {did}: invalid condition on {m.get('field')}")
        if not SAFE_VAL.match(str(m.get("value", ""))) and not (m.get("op") == "in" and re.fullmatch(r"[A-Za-z0-9:.+\-_ ,]{1,200}", str(m.get("value", "")))):
            raise ValueError(f"detector {did}: invalid value {m.get('value')!r}")
        if m["op"] == "has" and fields[m["field"]] != "array":
            raise ValueError(f"detector {did}: 'contains' only works on list fields")
    if d.get("group_by") and d["group_by"] not in fields:
        raise ValueError(f"detector {did}: cannot group by {d['group_by']}")
    if d.get("measure", "count") not in ("count", "sum"):
        raise ValueError(f"detector {did}: measure must be count or sum")
    if d.get("measure") == "sum" and fields.get(d.get("sum_field")) != "int":
        raise ValueError(f"detector {did}: sum needs a numeric field")
    w = d.get("window") or {}
    if w.get("unit") not in WINDOW_UNITS or not isinstance(w.get("n"), (int, float)) or w["n"] <= 0:
        raise ValueError(f"detector {did}: invalid time window")
    if not isinstance(d.get("threshold"), (int, float)) or d["threshold"] < 1:
        raise ValueError(f"detector {did}: threshold must be at least 1")


def validate_breach(doc):
    dets = doc.get("detectors")
    if not isinstance(dets, list):
        raise ValueError("breach settings are missing 'detectors'")
    ids = [d.get("id") for d in dets]
    if len(ids) != len(set(ids)) or not all(ids):
        raise ValueError("every detector needs a unique id")
    for d in dets:
        validate_detector(d)
    clocks = doc.get("clocks") or {}
    for k in ("cert_in_hours", "board_initial_hours", "principals_hours", "board_report_hours", "warn_hours"):
        if not isinstance(clocks.get(k), (int, float)) or not 0 < clocks[k] <= 720:
            raise ValueError(f"clock '{k}' must be between 1 and 720 hours")
    if not isinstance(doc.get("lookback_days"), (int, float)) or not 1 <= doc["lookback_days"] <= 90:
        raise ValueError("lookback must be between 1 and 90 days")
    validate_anomaly(doc.get("anomaly"))


STORES = {
    "policy": {"file": "policy.json", "history": "history", "default": DEFAULT_POLICY, "validate": validate_policy,
               "note": "Initial policy from the ShopSmart Customer Data Inventory"},
    "retention": {"file": "retention.json", "history": "retention_history", "default": DEFAULT_RETENTION, "validate": validate_retention,
                  "note": "Initial retention schedule from the ShopSmart Customer Data Inventory"},
    "breach": {"file": "breach.json", "history": "breach_history", "default": DEFAULT_BREACH, "validate": validate_breach,
               "note": "Initial breach detectors and response clocks (DPDP Rules 2025, Rule 7)"},
}


def store_paths(kind):
    """A versioned store's file and history folder."""
    st = STORES[kind]
    return DATA / st["file"], DATA / st["history"]


def read_doc(kind):
    st = STORES[kind]
    f, h = store_paths(kind)
    if not f.exists():
        h.mkdir(parents=True, exist_ok=True)
        doc = json.loads(st["default"].read_text())
        doc.update(version=1, updated_at=now_iso(), updated_by="system (default)", change_note=st["note"])
        write_tracked(f, json.dumps(doc, indent=2))
        write_tracked(h / "v1.json", json.dumps(doc, indent=2))
    return json.loads(f.read_text())


def save_doc(kind, doc, base_version, user, note):
    st = STORES[kind]
    with _policy_lock:
        current = read_doc(kind)
        if base_version != current["version"]:
            return None, current
        st["validate"](doc)
        doc = {k: v for k, v in doc.items() if k not in ("version", "updated_at", "updated_by", "change_note")}
        doc.update(version=current["version"] + 1, updated_at=now_iso(), updated_by=user,
                   change_note=(note or "").strip()[:300] or "Updated")
        f, h = store_paths(kind)
        write_tracked(f, json.dumps(doc, indent=2))
        h.mkdir(parents=True, exist_ok=True)
        write_tracked(h / f"v{doc['version']}.json", json.dumps(doc, indent=2))
        return doc, None


def history_of(kind):
    read_doc(kind)
    out = []
    for f in store_paths(kind)[1].glob("v*.json"):
        d = json.loads(f.read_text())
        out.append({k: d.get(k) for k in ("version", "updated_at", "updated_by", "change_note")})
    return sorted(out, key=lambda x: -x["version"])


# Route prefix -> store: /api/policy (consent), /api/retention-policy, /api/breach-policy.
STORE_ROUTE = re.compile(r"/api/(policy|retention-policy|breach-policy)(?:/(history)(?:/v(\d+))?|/restore/v(\d+))?")
INC_ROUTE = re.compile(r"/api/incidents/(BR-\d{4}-\d{4,6})")
SIGNAL_ROUTE = re.compile(r"/api/breach/signals/([0-9a-f]{12})/(dismiss|reopen|link)")
KIND_OF = {"policy": "policy", "retention-policy": "retention", "breach-policy": "breach"}


# ---------------------------------------------------------------- privacy-safe customer lookup
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


def lookup_customers(q):
    """Exact email, or phone by its last 10 digits -> matching customer ids only.

    The browser never receives emails or phones; staff type the full value they
    already know and get back only the customer number. Partial or wildcard
    queries are refused so the endpoint cannot be used to browse personal data.
    """
    q = (q or "").strip()
    if EMAIL_RE.match(q):
        kind = "email"
        rows = shop_get("/customers", {"select": "id", "email": f"eq.{q}"})
        if not rows and q != q.lower():
            rows = shop_get("/customers", {"select": "id", "email": f"eq.{q.lower()}"})
    else:
        digits = re.sub(r"\D", "", q)
        if len(digits) < 10 or re.search(r"[^\d\s+()\-]", q):
            raise ValueError("Enter a full email address or a phone number with at least 10 digits.")
        kind = "phone"
        rows = shop_get("/customers", {"select": "id", "phone": f"like.*{digits[-10:]}"})
    return kind, sorted({r["id"] for r in rows})


# ---------------------------------------------------------------- breach detection (NigraniAI logs, caller's token)
def gr_get(table, params, token):
    """Read NigraniAI with the signed-in user's own JWT, so its RLS policies apply."""
    url = f"{AUTH_URL}/rest/v1/{urllib.parse.quote(table)}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"apikey": AUTH_ANON, "Authorization": f"Bearer {token}", "Accept-Profile": GR_SCHEMA})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(0.4 * (attempt + 1))


SCAN_CAP = 20000   # events read per detector per scan


def detector_events(d, since, token):
    group = d.get("group_by") or ""
    cols = ["id", "logged_at", "service"] + [c for c in (group, d.get("sum_field") if d.get("measure") == "sum" else "") if c and c != "service"]
    params = [("select", ",".join(dict.fromkeys(cols))), ("logged_at", f"gte.{since}"), ("order", "logged_at.asc")]
    for m in d.get("match") or []:
        f, op, v = m["field"], m["op"], str(m["value"])
        if op == "has":
            params.append((f, f"cs.{{{v}}}"))
        elif op == "in":
            params.append((f, f"in.({','.join(x.strip() for x in v.split(',') if x.strip())})"))
        elif op == "is":
            params.append((f, f"is.{v if v in ('true', 'false', 'null') else 'null'}"))
        else:
            params.append((f, f"{op}.{v}"))
    rows, off = [], 0
    while off < SCAN_CAP:
        page = gr_get(d["source"], params + [("limit", "1000"), ("offset", str(off))], token)
        rows += page
        if len(page) < 1000:
            return rows, False
        off += 1000
    return rows, True


def detect(d, rows):
    """Sliding window per group: every stretch where the window total reaches the
    threshold becomes one signal (overlapping hot windows are merged)."""
    win = timedelta(seconds=d["window"]["n"] * WINDOW_UNITS[d["window"]["unit"]])
    group, thr = d.get("group_by") or "", d["threshold"]
    val = (lambda r: int(r.get(d["sum_field"]) or 0)) if d.get("measure") == "sum" else (lambda r: 1)
    groups = {}
    for r in rows:
        t = _ts(r.get("logged_at"))
        if t:
            groups.setdefault(str(r.get(group) if group else "") or ("(none)" if group else ""), []).append((t, r))
    signals = []
    for key, evs in groups.items():
        evs.sort(key=lambda x: x[0])
        j, total, hot_upto, cur = 0, 0, -1, None
        for i, (t, r) in enumerate(evs):
            total += val(r)
            while t - evs[j][0] > win:
                total -= val(evs[j][1])
                j += 1
            if total < thr:
                continue
            start_k = max(j, hot_upto + 1)
            if not (cur and evs[start_k][0] - cur["_last"] <= win):
                cur = {"_first": evs[start_k][0], "_last": None, "events": [], "peak": 0}
                signals.append((key, cur))
            for k in range(start_k, i + 1):
                cur["events"].append(evs[k][1])
            cur["_last"], cur["peak"], hot_upto = t, max(cur["peak"], total), i
    out = []
    for key, s in signals:
        ev = s["events"]
        start, end = s["_first"].isoformat(), s["_last"].isoformat()
        sid = hashlib.sha1(f"{d['id']}|{key}|{start}".encode()).hexdigest()[:12]
        out.append({"id": sid, "detector": d["id"], "source": d["source"], "group": key, "start": start, "end": end,
                    "events": len(ev), "total": sum(val(r) for r in ev), "peak": s["peak"],
                    "services": sorted({r.get("service") or "" for r in ev} - {""}),
                    "sample_ids": [r["id"] for r in ev[:25]]})
    return sorted(out, key=lambda x: x["end"], reverse=True)


def run_detectors(doc, detectors, token):
    since = (datetime.now(timezone.utc) - timedelta(days=doc.get("lookback_days", 7))).isoformat(timespec="seconds")
    def one(d):
        try:
            rows, truncated = detector_events(d, since, token)
            return {"scanned": len(rows), "truncated": truncated, "signals": detect(d, rows)}
        except urllib.error.HTTPError as e:
            return {"error": f"NigraniAI answered {e.code}", "signals": []}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}", "signals": []}
    active = [d for d in detectors if d.get("enabled")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        return since, dict(zip([d["id"] for d in active], pool.map(one, active)))


_scan_cache = {"key": None, "at": 0, "value": None}


def breach_scan(token, user):
    """Current detectors on the live logs, merged with triage state. Signals from
    auto-open detectors start an incident the first time they are seen."""
    doc = read_doc("breach")
    key = doc["version"]
    with ThreadPoolExecutor(max_workers=1) as pool:
        # The anomaly model scores new log lines on every scan, in parallel with the detectors.
        ml = pool.submit(ml_model, doc, token, wait=False, user=user) if anomaly_cfg(doc)["enabled"] else None
        if not ml:
            ml_window_refresh(doc, token, user)   # keeps "log lines analysed" metered while the model is off
        if _scan_cache["key"] == key and time.time() - _scan_cache["at"] < 15:
            since, results = _scan_cache["value"]
        else:
            since, results = run_detectors(doc, doc["detectors"], token)
            _scan_cache.update(key=key, at=time.time(), value=(since, results))
            meter(user, "detector.runs")
            meter(user, "detector.lines", sum(r.get("scanned", 0) for r in results.values()))
        results = dict(results)
        if ml:
            m = ml.result()
            results[ML_ID] = {"scanned": m.get("scanned", 0), "signals": m.get("signals", []), "model": True, "status": m.get("status", "ready"),
                              "scored_at": m.get("scored_at"), **({"error": m["error"]} if m.get("error") else {})}
    if time.time() - _pii_logs["at"] > PII_LOG_REFRESH_S and not _pii_logs["busy"]:
        threading.Thread(target=pii_scan_logs, args=(token,), daemon=True).start()     # incremental, off the request
    results[PII_ID] = {"scanned": _pii_logs["scanned"], "signals": pii_signals(), "model": "pii", "scored_at": pii_logs_view()["at"]}
    dets = {d["id"]: d for d in doc["detectors"]} | {ML_ID: ml_detector() | {"auto_open": anomaly_cfg(doc)["auto_open"]}, PII_ID: dict(PII_DETECTOR)}
    with _inc_lock:
        reg = read_incidents()
        changed = False
        for did, res in results.items():
            d = dets.get(did) or {}
            for s in res["signals"]:
                if d.get("auto_open") and s["id"] not in reg["triage"]:
                    # Repeat signals from the same detector and group join the incident already open for them.
                    inc = next((i for i in reg["incidents"] if i["status"] not in ("closed", "not_breach")
                                and any(x.get("detector") == did and x.get("group") == s["group"] for x in i["signals"])), None)
                    if inc:
                        inc["rev"] += 1
                        inc["updated_at"] = now_iso()
                        if s["start"] < (inc.get("occurred_from") or s["start"]):
                            inc["occurred_from"] = s["start"]
                        if s["end"] > (inc.get("occurred_to") or ""):
                            inc["occurred_to"] = s["end"]
                    else:
                        inc = _new_incident(reg, {"title": f"{d.get('name')} · {s['group'] or 'all services'}",
                                                  "severity": s.get("severity") or d.get("severity"), "categories": [s.get("category") or d.get("category")],
                                                  "occurred_from": s["start"], "occurred_to": s["end"],
                                                  "services": s["services"], "cyber_incident": True},
                                            "detector (auto-open)", source="detector")
                    _link_signal(inc, s, d, "detector (auto-open)")
                    reg["triage"][s["id"]] = {"state": "linked", "incident": inc["id"], "by": "detector (auto-open)", "at": now_iso()}
                    changed = True
        if changed:
            write_incidents(reg)
    return {"since": since, "version": doc["version"], "results": results, "triage": reg["triage"], "incidents": reg["incidents"]}


# ---------------------------------------------------------------- anomaly model (unsupervised ML on the NigraniAI logs)
# Each service's activity is cut into time slices (10 min by default). Every slice becomes a feature
# vector (requests, errors, sign-in failures, personal data touched…). Features are put on a log
# scale and compared with that service's own usual level (median and MAD), then an Isolation Forest
# (Liu, Ting & Zhou, 2008), written here in plain Python, scores how easy each slice is to isolate
# from the rest. Slices that score high AND are clearly above normal on at least one feature become
# signals, with the features that explain them. Only slices with activity are learned from, so
# periods when a service was switched off don't count as "normal".
ML_ID = "ML"
ANOMALY_DEFAULT = {"enabled": True, "sensitivity": "medium", "bucket_minutes": 10, "min_history": 12, "auto_open": False}
SENSITIVITY = {"low": 0.72, "medium": 0.67, "high": 0.62}      # anomaly-score cut-off
ML_FEATURES = [  # key, label, category it points to, smallest value worth flagging
    ("requests", "HTTP requests", "confidentiality", 20),
    ("operations", "data operations", "confidentiality", 30),
    ("personal_data", "personal-data events", "confidentiality", 10),
    ("credentials", "credential / password events", "confidentiality", 5),
    ("auth_failures", "rejected sign-ins (401/403)", "confidentiality", 5),
    ("masked_pii", "PII caught in log text", "confidentiality", 1),
    ("errors", "errors", "availability", 3),
    ("warnings", "warnings", "integrity", 5),
    ("server_errors", "server errors (5xx)", "availability", 3),
    ("latency_p95", "response time p95 (ms)", "availability", 1000),
]
ML_KEYS = [f[0] for f in ML_FEATURES]
ML_COLS = "id,logged_at,ingested_at,service,level,kind,http_status,data_category,risk_indicators,duration_ms"
ML_ROW_CAP = 100000
ML_TREES, ML_SAMPLE, ML_Z = 150, 256, 3.0
ML_DETECTOR = {
    "id": ML_ID, "name": "Unusual activity (ML model)", "source": "activity_logs", "category": "confidentiality", "severity": "medium",
    "why": "The anomaly model learned what normal looks like for each service from the logs, and this stretch is far outside it. "
           "Nobody wrote a rule for it, so it can catch patterns the detectors miss: a quiet scrape of customer records, "
           "unusual sign-in failures, or a service misbehaving.",
    "steps": ["Read the reasons: which measures are above normal, and by how much", "Open the log lines and check who or what caused them",
              "If personal data may have been accessed, lost or exposed, open an incident; otherwise dismiss with a reason"],
    "ref": "DPDP Act 2023 · s.8(5) reasonable security safeguards · Rule 6(1)(c)-(e) monitoring and detection",
}


def anomaly_cfg(doc):
    return {**ANOMALY_DEFAULT, **(doc.get("anomaly") or {})}


def validate_anomaly(a):
    if a is None:
        return
    if not isinstance(a, dict) or a.get("sensitivity", "medium") not in SENSITIVITY:
        raise ValueError("anomaly model: sensitivity must be low, medium or high")
    if a.get("bucket_minutes", 10) not in (5, 10, 15, 30, 60):
        raise ValueError("anomaly model: time slice must be 5, 10, 15, 30 or 60 minutes")
    if not isinstance(a.get("min_history", 12), int) or not 4 <= a.get("min_history", 12) <= 1000:
        raise ValueError("anomaly model: minimum history must be 4 to 1000 slices")


def ml_detector(s=None):
    """Detector-shaped description of the model, so its signals flow through triage and incidents."""
    d = dict(ML_DETECTOR)
    if s:
        d.update(severity=s.get("severity", d["severity"]), category=s.get("category", d["category"]))
    return d


def ml_fetch(flt, token, parallel=True):
    """Compact columns of activity_logs matching `flt`; pages fetched 6 at a time (or one at a
    time for the small incremental reads)."""
    base = [("select", ML_COLS), flt, ("order", "ingested_at.asc,id.asc"), ("limit", "1000")]
    rows, off, truncated, n = [], 0, False, 6 if parallel else 1
    with ThreadPoolExecutor(max_workers=n) as pool:
        while True:
            if off >= ML_ROW_CAP:
                truncated = True
                break
            pages = list(pool.map(lambda o: gr_get("activity_logs", base + [("offset", str(o))], token), range(off, off + n * 1000, 1000)))
            for p in pages:
                rows += p
            if any(len(p) < 1000 for p in pages):
                break
            off += n * 1000
    return rows, truncated


def ml_features(rows, bucket_s):
    agg, dur, ids = {}, {}, {}
    for r in rows:
        t = _ts(r.get("logged_at"))
        if not t or not r.get("service"):
            continue
        k = (r["service"], int(t.timestamp()) // bucket_s * bucket_s)
        a = agg.get(k)
        if a is None:
            a = agg[k] = dict.fromkeys(ML_KEYS, 0.0) | {"lines": 0}
            ids[k] = {f: [] for f in ML_KEYS}
        st, cat, risk = r.get("http_status") or 0, r.get("data_category"), r.get("risk_indicators") or []
        hit = {"requests": r.get("kind") == "request", "operations": r.get("kind") == "business",
               "personal_data": cat in ("personal_data", "financial", "customer_profile"), "credentials": cat == "credentials",
               "auth_failures": st in (401, 403), "masked_pii": "pii_pattern_masked" in risk,
               "errors": r.get("level") == "ERROR", "warnings": r.get("level") == "WARN", "server_errors": st >= 500}
        a["lines"] += 1
        for f, on in hit.items():
            if on:
                a[f] += 1
                if len(ids[k][f]) < 25:
                    ids[k][f].append(r["id"])
        if r.get("duration_ms") is not None:
            dur.setdefault(k, []).append((r["duration_ms"], r["id"]))
    for k, v in dur.items():
        v.sort()
        agg[k]["latency_p95"] = float(v[int(0.95 * (len(v) - 1))][0])
        ids[k]["latency_p95"] = [i for _, i in v[-25:]]
    return agg, ids


def _c(n):   # average path length of an unsuccessful binary-search-tree search (Isolation Forest normaliser)
    return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n if n > 2 else 1.0 if n == 2 else 0.0


class IsolationForest:
    """Isolation Forest: random axis-aligned splits; anomalies are isolated in fewer splits."""

    def __init__(self, trees=ML_TREES, sample=ML_SAMPLE, seed=7):
        self.n, self.psi, self.rng, self.trees = trees, sample, random.Random(seed), []

    def _grow(self, pts, depth, limit):
        if depth >= limit or len(pts) <= 1:
            return len(pts)
        dims = len(pts[0])
        for _ in range(dims):   # pick a feature that actually varies in this node
            j = self.rng.randrange(dims)
            lo, hi = min(p[j] for p in pts), max(p[j] for p in pts)
            if hi > lo:
                break
        else:
            return len(pts)
        s = self.rng.uniform(lo, hi)
        return (j, s, self._grow([p for p in pts if p[j] < s], depth + 1, limit), self._grow([p for p in pts if p[j] >= s], depth + 1, limit))

    def fit(self, X):
        self.psi = min(self.psi, len(X))
        limit = math.ceil(math.log2(max(self.psi, 2)))
        self.trees = [self._grow(self.rng.sample(X, self.psi), 0, limit) for _ in range(self.n)]
        return self

    def score(self, x):
        total = 0.0
        for t in self.trees:
            d = 0
            while isinstance(t, tuple):
                t = t[2] if x[t[0]] < t[1] else t[3]
                d += 1
            total += d + _c(t)
        return 2 ** (-(total / len(self.trees)) / (_c(self.psi) or 1))


def _q(vals, p):
    v = sorted(vals)
    return v[min(len(v) - 1, int(p * (len(v) - 1) + 0.5))] if v else 0.0


def ml_fit(cfg, agg, keys):
    """Learn normal: per-service median / MAD of every measure, and the Isolation Forest, from
    completed slices only (the slice in progress is scored, never learned from)."""
    X = {k: [math.log1p(agg[k][f]) for f in ML_KEYS] for k in keys}
    by_svc = {}
    for k in keys:
        by_svc.setdefault(k[0], []).append(k)
    base = {}
    for svc, ks in by_svc.items():
        cols = list(zip(*(X[k] for k in ks)))
        med = [statistics.median(c) for c in cols]
        mad = [max(1.4826 * statistics.median(abs(v - m) for v in c), 0.5) for c, m in zip(cols, med)]
        base[svc] = (med, mad)
    Z = [[(X[k][j] - base[k[0]][0][j]) / base[k[0]][1][j] for j in range(len(ML_KEYS))] for k in keys]
    typical = {svc: {f: (round(math.expm1(base[svc][0][j]), 1), round(_q([agg[k][f] for k in ks], 0.95), 1))
                     for j, f in enumerate(ML_KEYS)} for svc, ks in by_svc.items()}
    return {"base": base, "forest": IsolationForest().fit(Z), "counts": {svc: len(ks) for svc, ks in by_svc.items()},
            "typical": typical, "fitted_at": now_iso(), "slices": len(keys), "bucket_minutes": cfg["bucket_minutes"]}


def ml_train(cfg, rows, truncated, since, fit=None):
    """Score every slice in the window, including the one in progress, against the learned
    normal (`fit`); fit first when none is given. Returns (result, fit)."""
    started = time.time()
    bucket_s = cfg["bucket_minutes"] * 60
    agg, ids = ml_features(rows, bucket_s)
    keys = sorted(agg)
    live_b = int(time.time()) // bucket_s * bucket_s
    out = {"since": since, "lines": len(rows), "truncated": truncated, "slices": len(keys),
           "bucket_minutes": cfg["bucket_minutes"], "sensitivity": cfg["sensitivity"], "cutoff": SENSITIVITY[cfg["sensitivity"]],
           "features": [{"key": k, "label": l, "category": c} for k, l, c, _ in ML_FEATURES], "algorithm":
           f"Isolation Forest, {ML_TREES} trees, {ML_SAMPLE}-slice samples, per-service robust scaling (median / MAD)",
           "services": [], "signals": [], "series": [], "scanned": len(rows), "scored_at": now_iso(),
           "live_slice": datetime.fromtimestamp(live_b, timezone.utc).isoformat(),
           "live_lines": int(sum(agg[k]["lines"] for k in keys if k[1] == live_b))}
    if fit is None:
        done = [k for k in keys if k[1] < live_b]
        if len(done) < 2 * cfg["min_history"]:
            out["note"] = "Not enough activity yet to learn what normal looks like."
            out["trained_at"] = out["fitted_at"] = now_iso()
            return out, None
        fit = ml_fit(cfg, agg, done)
    out["trained_at"] = out["fitted_at"] = fit["fitted_at"]
    out["fit_slices"] = fit["slices"]
    base, typical, counts = fit["base"], fit["typical"], fit["counts"]
    keys = [k for k in keys if k[0] in base]          # a service first seen after the last fit waits for the next one
    Z = {k: [(math.log1p(agg[k][f]) - base[k[0]][0][j]) / base[k[0]][1][j] for j, f in enumerate(ML_KEYS)] for k in keys}
    score = {k: fit["forest"].score(Z[k]) for k in keys}
    by_svc = {}
    for k in keys:
        by_svc.setdefault(k[0], []).append(k)
    cut = out["cutoff"]
    flagged = {}
    for k in keys:
        if score[k] < cut or counts.get(k[0], 0) < cfg["min_history"]:
            continue
        reasons = [j for j, (f, _, _, floor) in enumerate(ML_FEATURES) if Z[k][j] >= ML_Z and agg[k][f] >= floor]
        if reasons:
            flagged[k] = sorted(reasons, key=lambda j: -Z[k][j])
    # Consecutive flagged slices of a service (gap of at most one slice) become one signal.
    for svc, ks in by_svc.items():
        run = []
        for k in ks + [None]:
            if k in flagged and (not run or k[1] - run[-1][1] <= 2 * bucket_s):
                run.append(k)
                continue
            if run:
                sg = _ml_signal(svc, run, agg, ids, Z, score, flagged, typical[svc], cut, bucket_s)
                sg["live"] = run[-1][1] == live_b
                out["signals"].append(sg)
            run = [k] if k in flagged else []
    # Several services unusual in the same slice usually means a deploy, restart or shared outage.
    at = {}
    for k in flagged:
        at.setdefault(k[1], set()).add(k[0])
    for sg in out["signals"]:
        t0, t1 = _ts(sg["start"]).timestamp(), _ts(sg["end"]).timestamp()
        sg["together"] = sorted({x for t, v in at.items() if t0 <= t < t1 for x in v} - {sg["group"]})
    out["signals"].sort(key=lambda s: s["end"], reverse=True)
    for svc, ks in sorted(by_svc.items()):
        out["services"].append({"service": svc, "slices": counts.get(svc, 0), "learning": counts.get(svc, 0) < cfg["min_history"],
                                "flagged": sum(1 for k in ks if k in flagged), "max_score": round(max(score[k] for k in ks), 3),
                                "typical": typical[svc], "live": score.get((svc, live_b))})
        out["series"].append({"service": svc, "points": [[datetime.fromtimestamp(k[1], timezone.utc).isoformat(), round(score[k], 3), int(k in flagged), int(k[1] == live_b)] for k in ks]})
    if score:
        out["scores"] = {"p50": round(_q(score.values(), 0.5), 3), "p90": round(_q(score.values(), 0.9), 3), "p99": round(_q(score.values(), 0.99), 3), "max": round(max(score.values()), 3)}
    out["seconds"] = round(time.time() - started, 2)
    return out, fit


def _ml_signal(svc, run, agg, ids, Z, score, flagged, typical, cut, bucket_s):
    peak_k = max(run, key=lambda k: score[k])
    top = {}
    for k in run:
        for j in flagged[k]:
            f = ML_KEYS[j]
            if f not in top or Z[k][j] > top[f]["z"]:
                med, p95 = typical[f]
                top[f] = {"feature": f, "label": ML_FEATURES[j][1], "value": agg[k][f], "usual": med, "p95": p95, "z": round(Z[k][j], 1),
                          "times": round((agg[k][f] + 1) / (med + 1), 1), "category": ML_FEATURES[j][2]}
    reasons = sorted(top.values(), key=lambda r: -r["z"])[:4]
    sample = list(dict.fromkeys(i for r in reasons for k in run for i in ids[k][r["feature"]]))[:25]
    s_max = score[peak_k]
    sev = "high" if s_max >= cut + 0.07 else "medium" if s_max >= cut + 0.03 else "low"
    if reasons[0]["feature"] in ("credentials", "auth_failures", "masked_pii") and sev == "low":
        sev = "medium"
    start = datetime.fromtimestamp(run[0][1], timezone.utc).isoformat()
    lines = int(sum(agg[k]["lines"] for k in run))
    return {"id": hashlib.sha1(f"{ML_ID}|{svc}|{start}".encode()).hexdigest()[:12], "detector": ML_ID, "source": "activity_logs",
            "group": svc, "start": start, "end": datetime.fromtimestamp(run[-1][1] + bucket_s, timezone.utc).isoformat(),
            "events": lines, "total": lines, "peak": round(s_max, 3), "services": [svc], "sample_ids": sample,
            "score": round(s_max, 3), "severity": sev, "category": reasons[0]["category"], "slices": len(run), "reasons": reasons}


_ml_lock = threading.Lock()
_ml_cache = {"key": None, "at": 0, "value": None, "rows": {}, "lookback": None, "max_ing": None, "truncated": False,
             "training": False, "fit": None, "fit_key": None, "fit_at": 0}
ML_RESCORE_S = 10    # new log lines are scored at most this often (each scan, i.e. live)
ML_REFIT_S = 600     # "normal" is re-learned this often, or at once when the settings change


def _ml_rows(lookback, token, user="system"):
    """The log window, kept in memory: one full read, then only lines ingested since the last read."""
    c = _ml_cache
    since = (datetime.now(timezone.utc) - timedelta(days=lookback)).isoformat(timespec="seconds")
    if c["lookback"] != lookback or not c["rows"]:
        rows, c["truncated"] = ml_fetch(("logged_at", f"gte.{since}"), token)
        c["rows"], c["lookback"] = {r["id"]: r for r in rows}, lookback
        meter_new_lines(user, rows)
    else:
        rows, _ = ml_fetch(("ingested_at", f"gt.{c['max_ing']}"), token, parallel=False)
        c["rows"].update((r["id"], r) for r in rows)
        meter_new_lines(user, rows)
    cut = _ts(since)
    c["rows"] = {k: r for k, r in c["rows"].items() if (_ts(r.get("logged_at")) or cut) >= cut}
    c["max_ing"] = max((r.get("ingested_at") or "" for r in c["rows"].values()), default=since) or since
    return list(c["rows"].values()), c["truncated"], since


def ml_model(doc, token, force=False, preview=None, wait=True, user="system"):
    """Live model: new log lines are read and scored every ML_RESCORE_S seconds against the learned
    normal, which is re-learned every ML_REFIT_S seconds, when settings change, or with force=True.
    `preview` fits and scores the cached window with draft settings and stores nothing. With
    wait=False the very first (slow) read of the window runs in the background."""
    lookback = doc.get("lookback_days", 7)
    cfg = {**anomaly_cfg(doc), **(preview or {})}
    key = json.dumps([cfg, lookback], sort_keys=True)
    c = _ml_cache
    if not preview and not force and c["key"] == key and time.time() - c["at"] < ML_RESCORE_S:
        return c["value"]
    if not wait and not preview and (c["training"] or not c["rows"] or c["lookback"] != lookback):
        if not c["training"]:
            c["training"] = True
            threading.Thread(target=ml_model, args=(doc, token), kwargs={"force": force, "user": user}, daemon=True).start()
        return c["value"] if c["value"] and c["key"] == key else {"status": "training", "signals": [], "scanned": 0}
    with _ml_lock:
        if not preview and not force and c["key"] == key and time.time() - c["at"] < ML_RESCORE_S:
            return c["value"]   # scored by another request while this one waited
        try:
            if preview and c["rows"]:
                rows, truncated, since = list(c["rows"].values()), c["truncated"], (datetime.now(timezone.utc) - timedelta(days=lookback)).isoformat(timespec="seconds")
            else:
                rows, truncated, since = _ml_rows(lookback, token, user)
            refit = preview or force or c["fit"] is None or c["fit_key"] != key or time.time() - c["fit_at"] > ML_REFIT_S
            value, fit = ml_train(cfg, rows, truncated, since, None if refit else c["fit"])
            if refit and not preview:
                c.update(fit=fit, fit_key=key, fit_at=time.time())
            value["refit_every_s"], value["rescore_every_s"] = ML_REFIT_S, ML_RESCORE_S
            if not preview:
                meter(user, "ml.runs")
        except urllib.error.HTTPError as e:
            value = {"error": f"NigraniAI answered {e.code}", "signals": [], "trained_at": now_iso()}
        except Exception as e:
            value = {"error": f"{type(e).__name__}: {e}", "signals": [], "trained_at": now_iso()}
        finally:
            if not preview:
                c["training"] = False
        if not preview:
            c.update(key=key, at=time.time(), value=value)
        return value


def ml_window_refresh(doc, token, user):
    """With the model off, still read new log lines every 10 s (in the background) so usage is metered."""
    c = _ml_cache
    if c["training"] or time.time() - c.get("window_at", 0) < ML_RESCORE_S:
        return
    c["training"], c["window_at"] = True, time.time()

    def run():
        try:
            with _ml_lock:
                _ml_rows(doc.get("lookback_days", 7), token, user)
        except Exception as e:
            sys.stderr.write(f"[consent] log window refresh failed: {e}\n")
        finally:
            c["training"] = False
    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------- breach register (data/incidents.json)
_inc_lock = threading.Lock()
INC_STATUS = ["suspected", "confirmed", "contained", "closed", "not_breach"]
OBLIGATIONS = {"cert_in", "board_initial", "principals", "board_report"}
DATA_CATEGORIES = {"identity", "contact", "address", "financial", "orders", "credentials", "usage", "consent", "other"}
TEXT_FIELDS = {"title": 200, "description": 5000, "location": 500, "impact": 5000, "cause": 5000, "mitigation": 5000,
               "remedial": 5000, "person_findings": 3000, "safety_advice": 3000, "closure_note": 3000, "principal_note": 2000}
TIME_FIELDS = {"aware_at", "occurred_from", "occurred_to", "extension_until"}
LONG_TEXT = {"description", "impact", "cause", "mitigation", "remedial", "person_findings", "safety_advice", "closure_note", "principal_note"}
FIELD_LABELS = {"title": "Title", "status": "Status", "severity": "Severity", "categories": "Breach type", "aware_at": "Became aware",
                "occurred_from": "Started", "occurred_to": "Ended", "location": "Location", "services": "Systems",
                "data_categories": "Data involved", "principals_affected": "Customers affected", "description": "Nature and extent",
                "impact": "Likely impact", "cause": "Cause", "mitigation": "Mitigation", "remedial": "Remedial measures",
                "person_findings": "Findings on who caused it", "safety_advice": "Advice to customers", "cyber_incident": "Cyber incident (CERT-In)",
                "extension_until": "Board extension until", "closure_note": "Closure note", "principal_note": "Notice channel", "owner": "Owner"}


def read_incidents():
    if not INCIDENTS_FILE.exists():
        return {"seq": 0, "incidents": [], "triage": {}}
    return json.loads(INCIDENTS_FILE.read_text())


def write_incidents(reg):
    DATA.mkdir(exist_ok=True)
    write_tracked(INCIDENTS_FILE, json.dumps(reg, indent=2))


def _clean(changes):
    """Validate an incident patch; returns only known, well-formed fields."""
    out = {}
    for k, v in changes.items():
        if k in TEXT_FIELDS:
            out[k] = str(v or "")[:TEXT_FIELDS[k]]
        elif k == "owner":
            out[k] = str(v or "")[:120]
        elif k in TIME_FIELDS:
            if k == "aware_at" and not v:
                raise ValueError("'Became aware' is required: the response clocks start there.")
            if v and not _ts(v):
                raise ValueError(f"invalid date for {FIELD_LABELS.get(k, k)}")
            out[k] = _ts(v).isoformat() if v else None
        elif k == "status":
            if v not in INC_STATUS:
                raise ValueError("invalid status")
            out[k] = v
        elif k == "severity":
            if v not in SEVERITIES:
                raise ValueError("invalid severity")
            out[k] = v
        elif k == "categories":
            out[k] = [c for c in (v or []) if c in CATEGORIES]
        elif k == "data_categories":
            out[k] = [c for c in (v or []) if c in DATA_CATEGORIES]
        elif k == "services":
            out[k] = [str(x)[:80] for x in (v or [])][:30]
        elif k == "principals_affected":
            out[k] = None if v in (None, "") else max(0, int(v))
        elif k == "cyber_incident":
            out[k] = bool(v)
        elif k == "obligations":
            obs = {}
            for ok, ov in (v or {}).items():
                if ok not in OBLIGATIONS:
                    raise ValueError(f"unknown obligation {ok}")
                if ov is None:
                    obs[ok] = None
                    continue
                if ov.get("done_at") and not _ts(ov["done_at"]):
                    raise ValueError("invalid date for obligation")
                obs[ok] = {"done_at": _ts(ov["done_at"]).isoformat() if ov.get("done_at") else None,
                           "ref": str(ov.get("ref") or "")[:120], "note": str(ov.get("note") or "")[:1000],
                           "count": None if ov.get("count") in (None, "") else max(0, int(ov["count"]))}
            out[k] = obs
    return out


def _new_incident(reg, data, user, source="manual"):
    reg["seq"] += 1
    now = now_iso()
    inc = {"id": f"BR-{datetime.now(timezone.utc).year}-{reg['seq']:04d}", "rev": 1, "created_at": now, "created_by": user,
           "updated_at": now, "source": source, "status": "suspected", "severity": "medium", "categories": [],
           "aware_at": now, "occurred_from": None, "occurred_to": None, "location": "", "services": [], "data_categories": [],
           "principals_affected": None, "description": "", "impact": "", "cause": "", "mitigation": "", "remedial": "",
           "person_findings": "", "safety_advice": "", "cyber_incident": False, "extension_until": None, "closure_note": "",
           "principal_note": "", "owner": user if source == "manual" else "", "title": "Untitled incident",
           "obligations": {k: None for k in OBLIGATIONS}, "signals": [], "log": []}
    inc.update(_clean(data))
    inc["log"].append({"at": now, "by": user, "text": "Opened from a detector signal" if source == "detector" else "Reported manually"})
    reg["incidents"].append(inc)
    meter(user, "incidents")
    return inc


def _link_signal(inc, s, d, user):
    if any(x["id"] == s.get("id") for x in inc["signals"]):
        return
    inc["signals"].append({k: s.get(k) for k in ("id", "detector", "source", "group", "start", "end", "events", "total", "peak", "services", "sample_ids", "score", "reasons") if k in s}
                          | {"detector_name": d.get("name") if d else s.get("detector_name"), "linked_at": now_iso(), "linked_by": user})
    inc["log"].append({"at": now_iso(), "by": user, "text": f"Linked signal: {d.get('name') if d else s.get('detector')} · {s.get('group') or 'all'} ({s.get('events')} events)"})


IST_TZ = timezone(timedelta(hours=5, minutes=30))


def _short(v, key=""):
    if key in TIME_FIELDS and v:
        t = _ts(v)
        return t.astimezone(IST_TZ).strftime("%d %b %Y, %I:%M %p IST").lstrip("0") if t else str(v)
    if isinstance(v, list):
        return ", ".join(map(str, v)) or "none"
    if v in (None, ""):
        return "empty"
    return str(v)[:80]


OB_LABELS = {"cert_in": "CERT-In report", "board_initial": "Initial intimation to the Board", "principals": "Notice to affected customers", "board_report": "Detailed report to the Board"}


def update_incident(iid, rev, changes, user):
    with _inc_lock:
        reg = read_incidents()
        inc = next((x for x in reg["incidents"] if x["id"] == iid), None)
        if not inc:
            return None, "missing"
        if rev != inc["rev"]:
            return inc, "conflict"
        clean = _clean(changes)
        now = now_iso()
        for k, v in clean.items():
            if k == "obligations":
                for ok, ov in v.items():
                    before = inc["obligations"].get(ok)
                    if ov == before:
                        continue
                    if ov and ov.get("done_at"):
                        ov["by"] = (before or {}).get("by") if before and before.get("done_at") == ov["done_at"] else user
                        inc["log"].append({"at": now, "by": user, "text": f"{OB_LABELS[ok]}: sent {_short(ov['done_at'], 'aware_at')}" + (f" · ref {ov['ref']}" if ov.get("ref") else "")})
                    elif before and before.get("done_at"):
                        inc["log"].append({"at": now, "by": user, "text": f"{OB_LABELS[ok]}: marked not done"})
                    inc["obligations"][ok] = ov
                continue
            if inc.get(k) == v:
                continue
            label = FIELD_LABELS.get(k, k)
            text = f"{label} updated" if k in LONG_TEXT else f"{label}: {_short(inc.get(k), k)} → {_short(v, k)}"
            inc["log"].append({"at": now, "by": user, "text": text})
            inc[k] = v
        inc["rev"] += 1
        inc["updated_at"] = now
        write_incidents(reg)
        return inc, None


def triage_signal(sid, action, body, user):
    with _inc_lock:
        reg = read_incidents()
        if action == "dismiss":
            reason = str(body.get("reason") or "").strip()[:300]
            if not reason:
                raise ValueError("Give a reason for dismissing the signal.")
            reg["triage"][sid] = {"state": "dismissed", "reason": reason, "by": user, "at": now_iso()}
        elif action == "reopen":
            t = reg["triage"].get(sid)
            if t and t.get("state") == "linked":
                raise ValueError("This signal is linked to an incident.")
            reg["triage"].pop(sid, None)
        elif action == "link":
            s = body.get("signal") or {}
            if s.get("id") != sid:
                raise ValueError("signal snapshot does not match")
            dets = {d["id"]: d for d in read_doc("breach")["detectors"]}
            d = ml_detector(s) if s.get("detector") == ML_ID else dets.get(s.get("detector")) or {"name": s.get("detector_name") or s.get("detector")}
            if body.get("incident"):
                inc = next((x for x in reg["incidents"] if x["id"] == body["incident"]), None)
                if not inc:
                    raise ValueError("no such incident")
                inc["rev"] += 1
                inc["updated_at"] = now_iso()
            else:
                inc = _new_incident(reg, {"title": f"{d.get('name')} · {s.get('group') or 'all services'}", "severity": d.get("severity", "medium"),
                                          "categories": [d.get("category")] if d.get("category") else [],
                                          "occurred_from": s.get("start"), "occurred_to": s.get("end"), "services": s.get("services") or []},
                                    user, source="detector")
            _link_signal(inc, s, d, user)
            reg["triage"][sid] = {"state": "linked", "incident": inc["id"], "by": user, "at": now_iso()}
            write_incidents(reg)
            return {"incident": inc, "triage": reg["triage"]}
        else:
            raise ValueError("unknown action")
        write_incidents(reg)
        return {"triage": reg["triage"]}


# ---------------------------------------------------------------- AI assistant (Groq / xAI, OpenAI-compatible)
AI_KEY = os.getenv("GROK_API_KEY", "")
AI_BASE = os.getenv("GROK_BASE_URL", "").rstrip("/") or (
    "https://api.groq.com/openai/v1" if AI_KEY.startswith("gsk_") else "https://api.x.ai/v1")
AI_PREFER = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b", "llama-3.3-70b-versatile",
             "grok-4-fast", "grok-4", "grok-3-mini", "grok-3"]
_ai_model = {"value": os.getenv("GROK_MODEL", ""), "at": 0}
AI_UA = "DPDP-Compliance-Dashboard/1.0"   # the providers' firewalls reject Python's default User-Agent

AI_SYSTEM = """You are NigraniAI, the AI analyst inside the NigraniAI DPDP compliance system for ShopSmart, an Indian e-commerce company.
You help a privacy/compliance analyst understand and act on what the dashboard shows, under India's Digital Personal
Data Protection Act 2023 (DPDP Act) and the DPDP Rules 2025.

The dashboard has these sections (you can explain how they work):
- Log Telemetry: live structured logs from 9 ShopSmart services (NigraniAI activity_logs), with personal data masked and shown inline.
- Consent & Purpose: an editable, versioned policy (purposes, processing sources, notices, rules R1..R8 built from templates) evaluated on the shop database; findings per customer and per rule.
- Retention: an editable schedule (erasure requests, delete/review periods, legal minimums, inactivity) measured on live data; worklists, never deletes.
- Breach Response: detectors on the logs raise signals; incidents in a breach register with Rule 7 clocks (CERT-In 6 h, Board initial "without delay", customers "without delay", Board detailed report 72 h) and drafted notices.
- Dashboard: live charts and the "Needs attention" list.

LEGAL REFERENCE (use these; do not cite sections you are unsure of):
- DPDP Act 2023: s.2(u) personal data breach (unauthorised processing, accidental disclosure, acquisition, sharing, use, alteration, destruction or loss of access compromising confidentiality, integrity or availability); s.4 lawful processing (consent or legitimate use); s.5 notice; s.6 consent: free, specific, informed, unambiguous, withdrawable as easily as given (s.6(4)); s.7 legitimate uses; s.8 fiduciary duties: s.8(1) accountable, s.8(3) accuracy, s.8(4) technical and organisational measures, s.8(5) reasonable security safeguards, s.8(6) breach intimation to the Board and each affected principal, s.8(7) erase when purpose served or consent withdrawn unless law requires retention, s.8(9) contact person, s.8(10) grievance redressal; s.9 children's data (verifiable parental consent, no tracking/targeted ads); s.10 Significant Data Fiduciaries (DPO, audit, DPIA); s.11 right to access; s.12 correction and erasure (s.12(3) erase on request); s.13 grievance redressal; s.14 nomination; s.15 duties of principals; s.16 cross-border transfer; s.33 + Schedule penalties: up to ₹250 crore for failing security safeguards, ₹200 crore for failing breach intimation, ₹200 crore for children's-data duties, ₹150 crore for SDF duties, ₹50 crore for other breaches; principals up to ₹10,000. Penalties are civil (imposed by the Data Protection Board); the Act has no imprisonment.
- DPDP Rules 2025 (notified 13 Nov 2025; most obligations incl. Rules 3, 6, 7, 8 apply from 13 May 2027): Rule 3 notice contents (itemised data, purposes, how to withdraw, how to complain); Rule 4 consent managers; Rule 6 security measures (encryption/masking, access control, logs, monitoring, backups, keep logs 1 year); Rule 7 breach: to each affected principal without delay (nature, consequences, mitigation, safety steps, contact), to the Board without delay and a detailed report within 72 hours; Rule 8 erasure: e-commerce with 2 crore+ users erase after 3 years of inactivity with 48 hours' notice; keep personal data, traffic data and logs 1 year minimum; Rule 9 publish contact details; Rule 10 children; Rule 13 SDF; Rule 14 rights requests.
- CERT-In Directions (28 Apr 2022): report cyber incidents within 6 hours of noticing.
- Penalty mapping: notice, consent and purpose failures (s.4-s.7) and erasure/retention failures fall under "other obligations": up to ₹50 crore. ₹250 crore applies only to failing reasonable security safeguards that leads to a breach; ₹200 crore to failing breach intimation. Each figure is a maximum per instance decided by the Board considering severity, mitigation and repetition; never add maximums together.

UI MAP (the only controls that exist; never invent buttons or features):
- Dashboard: headline cards, charts, "Needs attention" list (read-only; links to sections).
- Log Telemetry: service tabs; filters for time range, level, layer, kind, PII; search; click a row for details; click a trace id to see the whole trace; "Raw lines" toggle; "Load older". There is no export in Log Telemetry.
- Consent & Purpose: tabs Overview, Customers (search by customer number, "Look up" a full email or phone, status filters, open a customer to see the consent record and timeline), Issues (issue detail with fix steps, evidence table, "Export CSV", "Ask AI"), Rules (switch rules on/off, "Edit" a rule, "Add rule"; side panels to manage Purposes, Processing sources, Notices, Consent fields, Data inventory; "Version history"/"Restore"; changes need "Save new version" with a note).
- Retention: tabs Overview, Records ("Export worklist (CSV)"), Erasure & inactivity, Schedule (edit/add rules, "due soon" window, version history).
- Breach Response: "Report a breach", "Check now"; Signals ("Review", "Open incident", add to an open incident, "Dismiss" with a reason, "Ask AI"); Breach register (search, "Export register (CSV)"); incident page (status steps Suspected/Confirmed/Contained/Closed/Not a breach, "Cyber incident" toggle, "Mark as sent" per obligation, Board extension date, incident form + "Save changes", Notices: "Copy", "Download .txt", "Mark as sent"); Detectors & settings (edit/add detectors, response clocks, notice contact, look-back days, version history).
- The dashboard is read-only towards ShopSmart: it cannot stop processing, message customers, send notices or delete data. Say those actions are done in ShopSmart's own systems (e.g. the customer-service or notification job) and the dashboard verifies them afterwards.

Rules:
1. Ground every factual statement about ShopSmart in the CONTEXT JSON supplied with the question. Quote the actual numbers, ids, rule ids, detector names and dates. Never invent data. Use the pre-computed totals and rankings in CONTEXT instead of adding numbers up yourself. "Server errors" means HTTP 5xx responses; "error lines" means log level ERROR; keep them distinct. If the context does not contain what is needed, say what is missing and where in the dashboard to look.
2. Explain the law precisely and cite sections (e.g. "DPDP Act s.6(1)", "Rules 2025, Rule 7(2)(b)"). If unsure of a citation, say so. Rule 7 (breach intimation) applies from 13 May 2027.
3. Be practical. Shape the answer to the question; use these headings when they help: **Answer**, **Why it matters**, **What to do now** (numbered, concrete steps, naming the dashboard section/button), **How to prevent it**. Skip headings that add nothing. Keep it tight: at most about 300 words unless asked for detail; short bullets; a table only when comparing several items.
4. Timestamps in CONTEXT are UTC (ISO); always present them in IST (UTC+5:30), e.g. "16 Oct, 2:08 PM IST". Customers are referred to only by number (e.g. "Customer #6"). Never ask for or output names, emails, phone numbers or other personal data.
5. You cannot change data or settings; tell the analyst exactly where to do it.
6. This is decision support, not legal advice; mention that only when the question is about legal liability.
7. Always finish with this final line (mandatory, even for short answers): three short follow-up questions the analyst might ask next, in exactly this form:
FOLLOW_UPS: question one | question two | question three"""


def ai_model():
    if _ai_model["value"]:
        return _ai_model["value"]
    if time.time() - _ai_model["at"] < 300:
        return AI_PREFER[0]
    _ai_model["at"] = time.time()
    try:
        req = urllib.request.Request(f"{AI_BASE}/models", headers={"Authorization": f"Bearer {AI_KEY}", "User-Agent": AI_UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            ids = {m["id"] for m in json.load(r).get("data", [])}
        _ai_model["value"] = next((m for m in AI_PREFER if m in ids), sorted(ids)[0] if ids else AI_PREFER[0])
    except Exception as e:
        sys.stderr.write(f"[consent] AI model list failed: {e}\n")
        return AI_PREFER[0]
    return _ai_model["value"]


AI_CTX_CHARS = int(os.getenv("GROK_CONTEXT_CHARS", "10000"))   # Groq free tier: 8,000 tokens per minute


def shrink(obj, limit):
    """Serialise context within `limit` chars: halve the longest lists (noting what was cut),
    then shorten the longest strings, until it fits."""
    s = json.dumps(obj, separators=(",", ":"), default=str)
    for _ in range(200):
        if len(s) <= limit:
            break
        best = None   # (size, parent, key)

        def walk(node):
            nonlocal best
            items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else []
            for k, v in items:
                if isinstance(v, list) and len(v) > 2:
                    n = len(json.dumps(v, default=str))
                    if not best or n > best[0]:
                        best = (n, node, k)
                if isinstance(v, (dict, list)):
                    walk(v)
        walk(obj)
        if best:
            lst = best[1][best[2]]
            prior = 0
            if lst and isinstance(lst[-1], dict) and "_more" in lst[-1]:
                prior = int(lst[-1]["_more"].split()[0]); lst = lst[:-1]
            keep = max(2, len(lst) // 2)
            best[1][best[2]] = lst[:keep] + [{"_more": f"{prior + len(lst) - keep} more not shown"}]
        else:
            longest = None

            def walk_s(node):
                nonlocal longest
                items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else []
                for k, v in items:
                    if isinstance(v, str) and len(v) > 120 and (not longest or len(v) > len(longest[1][longest[2]])):
                        longest = (None, node, k)
                    elif isinstance(v, (dict, list)):
                        walk_s(v)
            walk_s(obj)
            if not longest:
                return s[:limit] + "…(truncated)"
            v = longest[1][longest[2]]
            longest[1][longest[2]] = v[: len(v) // 2] + "…"
        s = json.dumps(obj, separators=(",", ":"), default=str)
    return s


def ai_messages(body, limit=AI_CTX_CHARS):
    q = str(body.get("question") or "").strip()[:4000]
    if not q:
        raise ValueError("Ask a question.")
    ctx_json = shrink(json.loads(json.dumps(body.get("context") or {}, default=str)), limit)
    msgs = [{"role": "system", "content": AI_SYSTEM.replace("ShopSmart", CLIENT_NAME)}]
    for h in (body.get("history") or [])[-4:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            msgs.append({"role": h["role"], "content": str(h["content"])[:1500]})
    att = body.get("attachment") or {}
    extra = ""
    if att.get("text"):
        extra = f"\n\nATTACHED ({str(att.get('name') or 'item')[:120]}):\n{str(att['text'])[:limit // 2]}"
    now = datetime.now(IST_TZ).strftime("%d %b %Y, %I:%M %p IST")
    msgs.append({"role": "user", "content": f"Now: {now}\nCONTEXT (live dashboard data, JSON):\n{ctx_json}{extra}\n\nQUESTION: {q}"})
    return msgs


def ai_stream(handler, body, user):
    """Proxy a streamed chat completion; the browser receives plain text chunks."""
    model = ai_model()
    resp, limit = None, AI_CTX_CHARS
    for attempt in range(3):
        msgs = ai_messages(body, limit)
        payload = {"model": model, "messages": msgs, "stream": True, "temperature": 0.3, "max_completion_tokens": 1400}
        if "gpt-oss" in model:
            payload.update(reasoning_effort="low", include_reasoning=False)
        req = urllib.request.Request(f"{AI_BASE}/chat/completions", data=json.dumps(payload).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json", "User-Agent": AI_UA})
        try:
            resp = urllib.request.urlopen(req, timeout=60)
            break
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            sys.stderr.write(f"[consent] AI provider answered {e.code}: {detail}\n")
            wait = e.headers.get("retry-after")
            if e.code == 413 and attempt < 2:
                limit = limit // 2                     # too big for the token budget: send less context
                continue
            if e.code == 429 and attempt < 2 and wait and float(wait) <= 40:
                time.sleep(float(wait) + 0.5)          # per-minute token budget: wait, then retry once
                continue
            msg = {429: "The AI is busy (free-tier limit of 8,000 tokens per minute). Wait about a minute and try again.",
                   413: "The question and data are too large for the AI's free tier. Untick some data sources and try again."}.get(e.code, f"The AI provider answered {e.code}.")
            return handler.send(502, {"error": msg})
    sys.stderr.write(f"[consent] AI question by {user} ({model}, {len(msgs[-1]['content'])} chars)\n")
    handler.send_response(200)
    handler.cors()
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-AI-Model", model)
    handler.send_header("Access-Control-Expose-Headers", "X-AI-Model")
    handler.end_headers()
    out_chars, usage = 0, None
    try:
        with resp:
            for raw in resp:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                    usage = chunk.get("usage") or (chunk.get("x_groq") or {}).get("usage") or usage
                    delta = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content") or ""
                except (ValueError, KeyError, IndexError, AttributeError):
                    continue
                out_chars += len(delta)
                if delta:
                    handler.wfile.write(delta.encode())
                    handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass   # analyst pressed Stop
    except Exception as e:
        try:
            handler.wfile.write(f"\n\n[The answer was cut off: {type(e).__name__}]".encode())
        except OSError:
            pass
    finally:
        # Provider's own token count when it sends one; otherwise about 4 characters per token.
        tokens = (usage or {}).get("total_tokens") or (sum(len(m["content"]) for m in msgs) + out_chars) // 4
        meter(user, "ai.questions")
        meter(user, "ai.tokens", int(tokens))
    handler.close_connection = True


# ---------------------------------------------------------------- access management (IAM-style), user admin, audit
# Modelled on AWS IAM: every request is denied unless a policy explicitly allows the action; an
# explicit Deny always wins; the root user (ROOT_EMAIL) is never restricted. Policies are JSON
# documents of statements (Effect, Action / NotAction with wildcards, optional Condition) attached
# to users directly or through groups. Nothing is predefined: root writes every policy.
import fnmatch

ROOT_EMAIL = os.getenv("ROOT_EMAIL", "root@example.com").strip().lower()
GR_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
IAM_FILE = DATA / "iam.json"
AUDIT_FILE = DATA / "audit.jsonl"
POLICY_VERSION = "2026-10-17"

# Action catalogue: service -> action -> (access level, description, where it is enforced).
SERVICES = {
    "dashboard": ("Dashboard", {"View": ("Read", "Open the main dashboard and its charts", "interface")}),
    "telemetry": ("Log Telemetry", {"ReadLogs": ("Read", "Read the structured service logs and inline personal data", "interface")}),
    "consent": ("Consent & Purpose", {
        "ReadFindings": ("Read", "Read the consent policy, findings, customers and issues", "server"),
        "LookupCustomer": ("Read", "Find a customer number from a full email or phone", "server"),
        "ExportEvidence": ("Read", "Download issue evidence and customer findings as CSV", "interface"),
        "EditPolicy": ("Write", "Change purposes, rules, notices and the data inventory; save new versions", "server"),
        "RestorePolicyVersion": ("Write", "Restore an earlier consent policy version", "server")}),
    "retention": ("Retention", {
        "ReadSchedule": ("Read", "Read the retention schedule, deadlines, erasure checklists and inactivity", "server"),
        "ExportWorklist": ("Read", "Download a deletion worklist as CSV", "interface"),
        "EditSchedule": ("Write", "Change retention rules and save new versions", "server"),
        "RestoreScheduleVersion": ("Write", "Restore an earlier schedule version", "server")}),
    "breach": ("Breach Response", {
        "ReadSignals": ("Read", "Read detectors, signals, the breach register and notices", "server"),
        "TriageSignal": ("Write", "Dismiss, reopen or link breach signals", "server"),
        "CreateIncident": ("Write", "Report a breach or open an incident from a signal", "server"),
        "UpdateIncident": ("Write", "Edit incidents, change status, mark notices as sent", "server"),
        "ExportRegister": ("Read", "Download the breach register as CSV", "interface"),
        "EditDetectors": ("Write", "Change detectors, response clocks and the notice contact", "server"),
        "RestoreDetectorsVersion": ("Write", "Restore an earlier detector version", "server")}),
    "ai": ("AI Assistant", {
        "Ask": ("Use", "Ask the AI assistant about the dashboard data", "server"),
        "AttachFile": ("Use", "Attach a file to an AI question", "server")}),
    "iam": ("Access management", {
        "ListUsers": ("List", "See users, their groups and attached policies", "server"),
        "ManageUsers": ("Write", "Add users, reset passwords, deactivate or remove users", "server"),
        "ListPolicies": ("List", "See policies and groups", "server"),
        "ManagePolicies": ("Permissions management", "Create, edit, delete and restore policies", "server"),
        "ManageGroups": ("Permissions management", "Create groups and change their members", "server"),
        "AttachPolicies": ("Permissions management", "Attach or detach policies on users and groups", "server"),
        "SimulatePolicy": ("Read", "Run the policy simulator", "server"),
        "ReadAllActivity": ("Read", "See every user's activity, including denied requests", "server")}),
    "usage": ("Usage & plan", {
        "ViewOwnUsage": ("Read", "See your own usage this billing cycle", "server"),
        "ViewAllUsage": ("Read", "See everyone's usage, the bill estimate and usage alerts", "server"),
        "ManagePlan": ("Write", "Change the plan, allowances, overage prices, hard limits and per-user caps", "server")}),
    "billing": ("Billing", {
        "ViewInvoices": ("Read", "See invoices, payments and the billing profile", "server"),
        "PayInvoices": ("Use", "Pay invoices online with Razorpay", "server"),
        "ManageBillingProfile": ("Write", "Change the billing name, address, state and GSTIN", "server")}),
    "datamap": ("Data map", {
        "Read": ("Read", "See the data map, inventory, record of processing and gaps", "server"),
        "Scan": ("Use", "Rebuild the data map from the database schema and the logs", "server"),
        "Edit": ("Write", "Change the declared purposes of services and tables, and the processors register", "server")}),
    "readiness": ("Readiness score", {
        "Run": ("Use", "Run and save the DPDP readiness score", "server"),
        "Read": ("Read", "See the DPDP readiness score and its history", "server"),
        "VerifyIntegrity": ("Read", "See the evidence ledger, verify that records weren't altered, and check an evidence pack", "server"),
        "ExportEvidence": ("Use", "Export an evidence pack for an auditor or the Data Protection Board", "server")}),
    "system": ("System status", {"ReadStatus": ("Read", "See service, database and AI status", "server")}),
}
ALL_ACTIONS = [f"{s}:{a}" for s, (_, acts) in SERVICES.items() for a in acts]
COND_KEYS = {"dpdp:CurrentTime": "date", "dpdp:IstHour": "number", "dpdp:IstWeekday": "string"}
COND_OPS = {"DateLessThan": "date", "DateGreaterThan": "date", "NumericLessThan": "number", "NumericGreaterThanEquals": "number",
            "StringEquals": "string", "StringNotEquals": "string"}

_iam_lock = threading.Lock()
_audit_lock = threading.Lock()
_last_used, _last_saved = {}, [0.0]


def read_iam():
    d = json.loads(IAM_FILE.read_text()) if IAM_FILE.exists() else {}
    for k in ("users", "groups", "policies", "last_used"):
        d.setdefault(k, {})
    return d


def write_iam(d):
    DATA.mkdir(exist_ok=True)
    write_tracked(IAM_FILE, json.dumps(d, indent=2))


def _as_list(v):
    return [] if v is None else list(v) if isinstance(v, (list, tuple)) else [v]


def validate_document(doc):
    """Errors block saving; warnings are advice (unknown actions, risky grants), like Access Analyzer."""
    errors, warnings = [], []
    if not isinstance(doc, dict):
        return ["The policy must be a JSON object."], []
    if doc.get("Version") != POLICY_VERSION:
        errors.append(f'"Version" must be "{POLICY_VERSION}".')
    sts = doc.get("Statement")
    if isinstance(sts, dict):
        sts = [sts]
    if not isinstance(sts, list) or not sts:
        return errors + ['"Statement" must be a non-empty list.'], warnings
    sids = set()
    for i, st in enumerate(sts, 1):
        where = f"Statement {i}" + (f' ("{st.get("Sid")}")' if isinstance(st, dict) and st.get("Sid") else "")
        if not isinstance(st, dict):
            errors.append(f"{where} must be an object."); continue
        if st.get("Sid"):
            if not re.fullmatch(r"[A-Za-z0-9]{1,64}", str(st["Sid"])):
                errors.append(f"{where}: Sid may contain only letters and digits.")
            if st["Sid"] in sids:
                errors.append(f"{where}: Sid must be unique.")
            sids.add(st["Sid"])
        if st.get("Effect") not in ("Allow", "Deny"):
            errors.append(f'{where}: "Effect" must be "Allow" or "Deny".')
        if ("Action" in st) == ("NotAction" in st):
            errors.append(f'{where}: use exactly one of "Action" or "NotAction".')
        pats = _as_list(st.get("Action") or st.get("NotAction"))
        for p in pats:
            if not isinstance(p, str) or not re.fullmatch(r"(\*|[a-z*?]+:[A-Za-z*?]+)", p):
                errors.append(f'{where}: "{p}" is not an action (use service:Action, wildcards * and ? allowed).'); continue
            if not any(fnmatch.fnmatchcase(a.lower(), p.lower()) for a in ALL_ACTIONS):
                warnings.append(f'{where}: "{p}" matches no action.')
        if st.get("Effect") == "Allow" and "Action" in st:
            granted = {a for a in ALL_ACTIONS for p in pats if isinstance(p, str) and fnmatch.fnmatchcase(a.lower(), p.lower())}
            if {"iam:ManagePolicies", "iam:AttachPolicies"} & granted:
                warnings.append(f"{where} lets the user change permissions, including their own. Grant it only to people you'd trust with root.")
            if "*" in pats:
                warnings.append(f'{where} allows every action ("*"). Prefer listing services or actions.')
        if st.get("Effect") == "Allow" and "NotAction" in st:
            warnings.append(f'{where}: "Allow" with "NotAction" also grants every action added in future.')
        for op, kv in (st.get("Condition") or {}).items():
            if op not in COND_OPS:
                errors.append(f'{where}: unknown condition operator "{op}".'); continue
            if not isinstance(kv, dict):
                errors.append(f"{where}: condition {op} needs {{key: value}}."); continue
            for k, v in kv.items():
                if COND_KEYS.get(k) != COND_OPS[op]:
                    errors.append(f'{where}: {op} can\'t test "{k}".'); continue
                for x in _as_list(v):
                    if COND_OPS[op] == "date" and not _ts(x):
                        errors.append(f'{where}: "{x}" is not a date-time.')
                    if COND_OPS[op] == "number" and not isinstance(x, (int, float)):
                        errors.append(f"{where}: {k} needs a number.")
    return errors, warnings


def _cond_ok(cond, at):
    ist = at.astimezone(timezone(timedelta(hours=5, minutes=30)))
    ctx = {"dpdp:CurrentTime": at, "dpdp:IstHour": ist.hour, "dpdp:IstWeekday": ist.strftime("%a")}
    for op, kv in (cond or {}).items():
        for k, v in kv.items():
            x, vals = ctx.get(k), _as_list(v)
            if op == "DateLessThan" and not all(x < _ts(w) for w in vals): return False
            if op == "DateGreaterThan" and not all(x > _ts(w) for w in vals): return False
            if op == "NumericLessThan" and not all(x < w for w in vals): return False
            if op == "NumericGreaterThanEquals" and not all(x >= w for w in vals): return False
            if op == "StringEquals" and x not in vals: return False
            if op == "StringNotEquals" and x in vals: return False
    return True


def policies_for(email, iam=None):
    """(policy id, via) for every policy that applies to the user: direct and through groups."""
    iam = iam or read_iam()
    out = [(pid, "direct") for pid in iam["users"].get(email, {}).get("policies", [])]
    for gid, g in iam["groups"].items():
        if email in g.get("members", []):
            out += [(pid, f"group {g['name']}") for pid in g.get("policies", [])]
    return [(pid, via) for pid, via in out if pid in iam["policies"]]


def decide(email, action, at=None, iam=None, extra_docs=None):
    """AWS order: explicit Deny > explicit Allow > implicit deny. Returns (decision, policy, sid, via)."""
    email = (email or "").lower()
    if email == ROOT_EMAIL:
        return "allow", "root user", None, "root"
    at = at or datetime.now(timezone.utc)
    iam = iam or read_iam()
    docs = [(iam["policies"][pid]["name"], iam["policies"][pid]["document"], via) for pid, via in policies_for(email, iam)]
    docs += [(n, d, "simulated") for n, d in (extra_docs or [])]
    allow = None
    a = action.lower()
    for name, doc, via in docs:
        sts = doc.get("Statement")
        for st in ([sts] if isinstance(sts, dict) else sts or []):
            pats = [p.lower() for p in _as_list(st.get("Action") or st.get("NotAction"))]
            hit = any(fnmatch.fnmatchcase(a, p) for p in pats)
            if "NotAction" in st:
                hit = not hit
            if not hit or not _cond_ok(st.get("Condition"), at):
                continue
            if st.get("Effect") == "Deny":
                return "deny", name, st.get("Sid"), via
            allow = allow or ("allow", name, st.get("Sid"), via)
    return allow or ("implicit", None, None, None)


def allowed(email, action):
    return decide(email, action)[0] == "allow"


def touch(email, action):
    """Access advisor: remember when each user last used each service."""
    svc = action.split(":")[0]
    lu = _last_used
    lu.setdefault(email, {})[svc] = now_iso()
    if time.time() - _last_saved[0] > 30:
        _last_saved[0] = time.time()
        with _iam_lock:
            d = read_iam()
            for e, m in lu.items():
                d["last_used"].setdefault(e, {}).update(m)
            write_iam(d)


def last_used(email):
    return {**read_iam()["last_used"].get(email, {}), **_last_used.get(email, {})}


def audit(user, action, detail=""):
    line = json.dumps({"at": now_iso(), "user": user, "action": action, "detail": str(detail)[:300]})
    with _audit_lock, _ledger_lock:
        DATA.mkdir(exist_ok=True)
        with AUDIT_FILE.open("a") as fh:
            fh.write(line + "\n")
        ledger_audit_line(line)


def read_audit(user=None, limit=300):
    if not AUDIT_FILE.exists():
        return []
    out = []
    for line in AUDIT_FILE.read_text().splitlines()[-5000:]:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not user or e.get("user") == user:
            out.append(e)
    return out[-limit:][::-1]


def gotrue_admin(method, path, body=None):
    """NigraniAI Auth admin API (service key, server-side only)."""
    if not GR_SERVICE_KEY:
        raise ValueError("SUPABASE_SERVICE_KEY is not set in .env, so users can't be managed here.")
    req = urllib.request.Request(f"{AUTH_URL}/auth/v1/admin{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"apikey": GR_SERVICE_KEY, "Authorization": f"Bearer {GR_SERVICE_KEY}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read() or b"{}")
            msg = j.get("msg") or j.get("message") or j.get("error_description")
        except ValueError:
            msg = None
        raise ValueError(msg or f"Supabase Auth answered {e.code}")


def effective(email, iam=None):
    iam = iam or read_iam()
    return {a: decide(email, a, iam=iam)[0] for a in ALL_ACTIONS}


def list_users(iam=None):
    iam = iam or read_iam()
    data = gotrue_admin("GET", "/users?per_page=200")
    out = []
    for u in data.get("users", data if isinstance(data, list) else []):
        email = (u.get("email") or "").lower()
        meta = u.get("user_metadata") or {}
        banned = u.get("banned_until")
        eff = effective(email, iam)
        out.append({"id": u["id"], "email": email, "name": meta.get("name") or "", "title": meta.get("title") or "",
                    "root": email == ROOT_EMAIL, "created_at": u.get("created_at"), "last_sign_in_at": u.get("last_sign_in_at"),
                    "active": not (banned and _ts(banned) and _ts(banned) > datetime.now(timezone.utc)),
                    "policies": iam["users"].get(email, {}).get("policies", []),
                    "groups": [gid for gid, g in iam["groups"].items() if email in g.get("members", [])],
                    "allowed": sum(1 for v in eff.values() if v == "allow"), "denied": sum(1 for v in eff.values() if v == "deny"),
                    "last_used": last_used(email), "added_by": iam["users"].get(email, {}).get("added_by")})
    return sorted(out, key=lambda x: (not x["root"], x["email"]))


def _user_by_id(uid):
    return next((u for u in list_users() if u["id"] == uid), None)


PASSWORD_RULE = "Use at least 8 characters with letters and numbers."


def strong(pw):
    return isinstance(pw, str) and len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def _new_id(prefix, existing):
    n = 1
    while f"{prefix}{n}" in existing:
        n += 1
    return f"{prefix}{n}"


def create_user(body, actor):
    email = str(body.get("email") or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError("Enter a valid email address.")
    if email == ROOT_EMAIL:
        raise ValueError("That is the root user.")
    if not strong(body.get("password")):
        raise ValueError(f"Temporary password: {PASSWORD_RULE}")
    blocked = quota_block(actor, "seats")
    if blocked:
        raise ValueError(blocked)
    iam = read_iam()
    pols = [p for p in body.get("policies") or [] if p in iam["policies"]]
    grps = [g for g in body.get("groups") or [] if g in iam["groups"]]
    if (pols or grps) and not allowed(actor, "iam:AttachPolicies"):
        raise PermissionError("Attaching policies needs iam:AttachPolicies.")
    gotrue_admin("POST", "/users", {"email": email, "password": body["password"], "email_confirm": True,
                                    "user_metadata": {"name": str(body.get("name") or "").strip()[:80], "title": str(body.get("title") or "").strip()[:80]}})
    _seat_cache["at"] = 0
    with _iam_lock:
        iam = read_iam()
        iam["users"][email] = {"policies": pols, "added_by": actor, "added_at": now_iso()}
        for g in grps:
            iam["groups"][g].setdefault("members", []).append(email)
        write_iam(iam)
    audit(actor, "iam.user.create", f"{email}" + (f" with {len(pols)} policies, {len(grps)} groups" if pols or grps else " (no access yet)"))
    return email


def update_user(uid, body, actor):
    target = _user_by_id(uid)
    if not target:
        raise ValueError("No such user.")
    if target["root"]:
        raise ValueError("The root user can't be changed here: it always has full access (ROOT_EMAIL in .env).")
    done = []
    if "active" in body:
        gotrue_admin("PUT", f"/users/{uid}", {"ban_duration": "none" if body["active"] else "876000h"})
        done.append("reactivated" if body["active"] else "deactivated")
    if body.get("password"):
        if not strong(body["password"]):
            raise ValueError(PASSWORD_RULE)
        gotrue_admin("PUT", f"/users/{uid}", {"password": body["password"]})
        done.append("password reset")
    if done:
        audit(actor, "iam.user.update", f"{target['email']}: {', '.join(done)}")
    return _user_by_id(uid)


def set_user_access(uid, body, actor):
    target = _user_by_id(uid)
    if not target or target["root"]:
        raise ValueError("The root user always has full access." if target else "No such user.")
    with _iam_lock:
        iam = read_iam()
        pols = [p for p in body.get("policies") or [] if p in iam["policies"]]
        grps = set(g for g in body.get("groups") or [] if g in iam["groups"])
        iam["users"].setdefault(target["email"], {"added_by": actor, "added_at": now_iso()})["policies"] = pols
        for gid, g in iam["groups"].items():
            mem = set(g.get("members", []))
            mem.add(target["email"]) if gid in grps else mem.discard(target["email"])
            g["members"] = sorted(mem)
        write_iam(iam)
    audit(actor, "iam.user.access", f"{target['email']}: policies {', '.join(iam['policies'][p]['name'] for p in pols) or 'none'}; groups {', '.join(iam['groups'][g]['name'] for g in grps) or 'none'}")
    return _user_by_id(uid)


def delete_user(uid, actor):
    target = _user_by_id(uid)
    if not target:
        raise ValueError("No such user.")
    if target["root"]:
        raise ValueError("The root user can't be removed.")
    gotrue_admin("DELETE", f"/users/{uid}")
    _seat_cache["at"] = 0
    with _iam_lock:
        iam = read_iam()
        iam["users"].pop(target["email"], None)
        for g in iam["groups"].values():
            g["members"] = [m for m in g.get("members", []) if m != target["email"]]
        write_iam(iam)
    audit(actor, "iam.user.delete", target["email"])


def save_policy(pid, body, actor):
    name = str(body.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_ -]{1,64}", name):
        raise ValueError("Policy name: 1-64 letters, digits, spaces or + = , . @ _ -")
    doc = body.get("document")
    errors, warnings = validate_document(doc)
    if errors:
        raise ValueError("Fix the policy first: " + " ".join(errors[:3]))
    with _iam_lock:
        iam = read_iam()
        if any(p["name"].lower() == name.lower() and k != pid for k, p in iam["policies"].items()):
            raise ValueError(f'A policy named "{name}" already exists.')
        now = now_iso()
        if pid:
            p = iam["policies"].get(pid)
            if not p:
                raise ValueError("No such policy.")
            if body.get("base_version") != p["version"]:
                raise ValueError("Someone else changed this policy. Reload it and try again.")
            p.setdefault("versions", []).insert(0, {k: p[k] for k in ("version", "document", "updated_at", "updated_by", "note")})
            p["versions"] = p["versions"][:5]            # like IAM: keep the last five versions
            p.update(name=name, description=str(body.get("description") or "")[:300], document=doc, version=p["version"] + 1,
                     updated_at=now, updated_by=actor, note=str(body.get("note") or "")[:200])
        else:
            pid = _new_id("pol-", iam["policies"])
            iam["policies"][pid] = {"name": name, "description": str(body.get("description") or "")[:300], "document": doc, "version": 1,
                                    "created_at": now, "created_by": actor, "updated_at": now, "updated_by": actor, "note": "Created", "versions": []}
        write_iam(iam)
    audit(actor, "iam.policy.save", f"{name} v{iam['policies'][pid]['version']}")
    return pid, warnings


def restore_policy(pid, v, actor):
    iam = read_iam()
    p = iam["policies"].get(pid)
    old = next((x for x in (p or {}).get("versions", []) if x["version"] == v), None)
    if not old:
        raise ValueError("No such version.")
    return save_policy(pid, {"name": p["name"], "description": p["description"], "document": old["document"],
                             "base_version": p["version"], "note": f"Restored version {v}"}, actor)


def delete_policy(pid, actor):
    with _iam_lock:
        iam = read_iam()
        p = iam["policies"].pop(pid, None)
        if not p:
            raise ValueError("No such policy.")
        for u in iam["users"].values():
            u["policies"] = [x for x in u.get("policies", []) if x != pid]
        for g in iam["groups"].values():
            g["policies"] = [x for x in g.get("policies", []) if x != pid]
        write_iam(iam)
    audit(actor, "iam.policy.delete", p["name"])


def save_group(gid, body, actor):
    name = str(body.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_ -]{1,64}", name):
        raise ValueError("Group name: 1-64 letters, digits, spaces or + = , . @ _ -")
    with _iam_lock:
        iam = read_iam()
        if any(g["name"].lower() == name.lower() and k != gid for k, g in iam["groups"].items()):
            raise ValueError(f'A group named "{name}" already exists.')
        pols = [p for p in body.get("policies") or [] if p in iam["policies"]]
        g = iam["groups"].get(gid) if gid else None
        if gid and not g:
            raise ValueError("No such group.")
        if pols != (g or {}).get("policies", []) and not allowed(actor, "iam:AttachPolicies"):
            raise PermissionError("Attaching policies to a group needs iam:AttachPolicies.")
        members = sorted({str(m).lower() for m in body.get("members") or [] if str(m).lower() != ROOT_EMAIL})
        if not gid:
            gid = _new_id("grp-", iam["groups"])
            g = iam["groups"][gid] = {"created_at": now_iso(), "created_by": actor}
        g.update(name=name, description=str(body.get("description") or "")[:300], members=members, policies=pols, updated_at=now_iso())
        write_iam(iam)
    audit(actor, "iam.group.save", f"{name}: {len(members)} members, {len(pols)} policies")
    return gid


def delete_group(gid, actor):
    with _iam_lock:
        iam = read_iam()
        g = iam["groups"].pop(gid, None)
        if not g:
            raise ValueError("No such group.")
        write_iam(iam)
    audit(actor, "iam.group.delete", g["name"])


def simulate(body):
    """Policy simulator: decisions for every action for a user (optionally plus a draft policy) at a moment."""
    iam = read_iam()
    email = str(body.get("email") or "").lower()
    at = _ts(body.get("at")) or datetime.now(timezone.utc)
    extra = []
    if body.get("document"):
        errors, _ = validate_document(body["document"])
        if errors:
            raise ValueError("Draft policy: " + " ".join(errors[:2]))
        extra = [("draft policy", body["document"])]
    rows = []
    for svc, (label, acts) in SERVICES.items():
        for act, (level, desc, where) in acts.items():
            d, pol, sid, via = decide(email, f"{svc}:{act}", at, iam, extra)
            rows.append({"action": f"{svc}:{act}", "service": label, "level": level, "description": desc, "enforced": where,
                         "decision": d, "policy": pol, "sid": sid, "via": via})
    return {"email": email, "at": at.isoformat(), "root": email == ROOT_EMAIL, "results": rows,
            "policies": [{"id": pid, "name": iam["policies"][pid]["name"], "via": via} for pid, via in policies_for(email, iam)]}


def iam_state(user):
    iam = read_iam()
    can_users = allowed(user, "iam:ListUsers")
    return {"users": list_users(iam) if can_users else None,
            "groups": {k: g for k, g in iam["groups"].items()} if allowed(user, "iam:ListPolicies") else None,
            "policies": {k: {**p, "attached": sum(k in u.get("policies", []) for u in iam["users"].values()) + sum(k in g.get("policies", []) for g in iam["groups"].values())}
                         for k, p in iam["policies"].items()} if allowed(user, "iam:ListPolicies") else None,
            "catalog": {s: {"label": l, "actions": {a: {"level": v[0], "description": v[1], "enforced": v[2]} for a, v in acts.items()}} for s, (l, acts) in SERVICES.items()},
            "version": POLICY_VERSION, "condition_keys": COND_KEYS, "condition_ops": list(COND_OPS), "root_email": ROOT_EMAIL, "password_rule": PASSWORD_RULE,
            "denied_24h": sum(1 for e in read_audit(None, 5000) if e["action"] == "access.denied" and _ts(e["at"]) > datetime.now(timezone.utc) - timedelta(days=1))}


def system_status():
    stores = {k: {"version": read_doc(k)["version"], "updated_at": read_doc(k)["updated_at"], "updated_by": read_doc(k)["updated_by"]} for k in STORES}
    reg, iam = read_incidents(), read_iam()
    return {"client": {"name": CLIENT_NAME, "id": CLIENT_ID},
            "service": {"started_at": _started_at, "uptime_s": int(time.time() - _started_epoch), "port": PORT, "allowed_origins": sorted(ORIGINS)},
            "guardrail": {"url": AUTH_URL, "schema": GR_SCHEMA, "user_admin": bool(GR_SERVICE_KEY)},
            "shop": {"url": SHOP_URL, "configured": bool(SHOP_URL and SHOP_KEY), "tables": len(_schema_cache["value"] or {}) or None},
            "ai": {"configured": bool(AI_KEY), "provider": "Groq" if "groq" in AI_BASE else "xAI", "model": ai_model() if AI_KEY else None, "context_chars": AI_CTX_CHARS},
            "stores": stores, "incidents": len(reg["incidents"]), "triaged_signals": len(reg["triage"]),
            "iam": {"policies": len(iam["policies"]), "groups": len(iam["groups"]), "users_with_access": len(iam["users"])},
            "usage": {"plan": read_plan()["name"], "cycle_start": cycle_bounds(read_plan())[0].isoformat()},
            "payments": {"online": bool(RZP_KEY_ID and RZP_SECRET), "test_mode": RZP_KEY_ID.startswith("rzp_test_"), "webhook": bool(RZP_WEBHOOK_SECRET)},
            "provider_reporting": central_status(),
            "root_email": ROOT_EMAIL, "audit_events": sum(1 for _ in AUDIT_FILE.open()) if AUDIT_FILE.exists() else 0}


# ---------------------------------------------------------------- usage metering and plan limits (data/usage.json, data/plan.json)
# The service meters what each person uses, per IST day: log lines brought into analysis, detector and
# model runs, AI questions and tokens, attached files, customer lookups, incidents, API requests and
# seats. The client's plan (chosen from the provider's catalogue in provider.json) gives each billed
# meter a monthly allowance, an overage price and, where it is safe, a hard limit. Monitoring meters
# are never blocked: breach detection must not stop because an allowance ran out; extra use is billed.
USAGE_FILE = DATA / "usage.json"
PLAN_FILE = DATA / "plan.json"
PROVIDER_FILE = ROOT / "provider.json"
USAGE_KEEP_DAYS = 366          # usage history kept for 12 months
_usage_lock = threading.Lock()
# key: (label, unit, kind, can hard-limit, billing unit size, description)
METERS = {
    "logs.analysed": ("Log lines analysed", "lines", "meter", False, 10000, "Unique log lines brought into analysis (detectors and the anomaly model). Counted once, when first read"),
    "detector.runs": ("Detector scans", "scans", "meter", False, 1, "Times the breach detectors ran over the log window"),
    "detector.lines": ("Detector line reads", "reads", "meter", False, 10000, "Log lines read by detectors across all scans (a line is re-read by every scan that covers it)"),
    "ml.runs": ("Anomaly model runs", "runs", "meter", False, 1, "Times the anomaly model scored the log window (live, about every 10 s while in use)"),
    "ai.questions": ("AI questions", "questions", "meter", True, 1, "Questions answered by the AI assistant"),
    "ai.tokens": ("AI tokens", "tokens", "meter", True, 100000, "Tokens sent to and received from the AI provider (prompt + answer)"),
    "ai.attachments": ("Files attached to AI", "files", "meter", True, 1, "Files dropped into AI questions"),
    "lookups": ("Customer lookups", "lookups", "meter", True, 1, "Customer number lookups by full email or phone"),
    "exposure.tests": ("Exposure tests", "tests", "meter", False, 1, "Public exposure tests run against the customer database (part of the readiness score)"),
    "evidence.packs": ("Evidence packs", "packs", "meter", False, 1, "Evidence packs exported for an auditor or the Board"),
    "pii.scans": ("PII detection scans", "scans", "meter", False, 1, "Sampled-value PII detection runs over the customer database"),
    "datamap.scans": ("Data map scans", "scans", "meter", False, 1, "Rebuilds of the data map from the database schema and logs"),
    "incidents": ("Incidents opened", "incidents", "meter", False, 1, "Incidents reported by hand, from signals or by auto-open detectors"),
    "api.requests": ("API requests", "requests", "meter", False, 1000, "Authenticated requests to the service"),
    "seats": ("Users", "users", "gauge", True, 1, "People with a dashboard account (counted now, not summed)"),
}
DEFAULT_PLANS = {
    "free": {"name": "Free", "base_fee": 0, "meters": {
        "logs.analysed": [100000, 0], "ai.questions": [50, 0], "ai.tokens": [300000, 0], "ai.attachments": [10, 0], "lookups": [20, 0], "seats": [2, 0]},
        "hard": ["ai.questions", "ai.tokens", "ai.attachments", "lookups", "seats"]},
    "starter": {"name": "Starter", "base_fee": 19999, "meters": {
        "logs.analysed": [1000000, 25], "ai.questions": [500, 0], "ai.tokens": [3000000, 40], "ai.attachments": [100, 5], "lookups": [300, 2], "seats": [5, 1500]},
        "hard": ["seats"]},
    "growth": {"name": "Growth", "base_fee": 79999, "meters": {
        "logs.analysed": [10000000, 15], "ai.questions": [3000, 0], "ai.tokens": [20000000, 30], "ai.attachments": [1000, 3], "lookups": [3000, 1], "seats": [25, 1200]},
        "hard": []},
    "enterprise": {"name": "Enterprise", "base_fee": 250000, "meters": {
        "logs.analysed": [None, 0], "ai.questions": [None, 0], "ai.tokens": [None, 0], "ai.attachments": [None, 0], "lookups": [None, 0], "seats": [None, 0]},
        "hard": []},
}


def provider():
    """The provider's settings for this copy (provider.json, edited only by the provider on the server):
    seller details for invoices, billing rules and the plan catalogue the client chooses from."""
    d = json.loads(PROVIDER_FILE.read_text()) if PROVIDER_FILE.exists() else {}
    d.setdefault("seller", {})
    d["billing"] = {"prefix": "DPDP", "due_days": 15, "gst": True, "sac": "998314", "grace_days": 14, "initial_plan": "growth", **(d.get("billing") or {})}
    d["plans"] = d.get("plans") or DEFAULT_PLANS
    return d


def plans():
    return provider()["plans"]


def _plan_from_template(t, user="system"):
    tp = plans()[t]
    return {"rev": 1, "template": t, "name": tp["name"], "currency": "INR", "cycle_day": 1, "base_fee": tp["base_fee"],
            "meters": {k: {"included": v[0], "overage": v[1]} for k, v in tp["meters"].items()},
            "hard": list(tp.get("hard") or []), "user_caps": {}, "alert_at": [80, 100], "updated_at": now_iso(), "updated_by": user}


def read_plan():
    if not PLAN_FILE.exists():
        DATA.mkdir(exist_ok=True)
        write_tracked(PLAN_FILE, json.dumps(_plan_from_template(provider()["billing"]["initial_plan"], "provider (initial plan)"), indent=2))
    return json.loads(PLAN_FILE.read_text())


def write_plan(p):
    DATA.mkdir(exist_ok=True)
    write_tracked(PLAN_FILE, json.dumps(p, indent=2))


def validate_caps(p):
    for email, caps in (p.get("user_caps") or {}).items():
        for k, v in caps.items():
            if k not in METERS or not METERS[k][3] or METERS[k][2] != "meter" or not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"invalid per-user cap {k} for {email}")
    at = p.get("alert_at") or []
    if not all(isinstance(x, (int, float)) and 1 <= x <= 200 for x in at) or len(at) > 4:
        raise ValueError("Alert thresholds must be 1 to 200 percent (up to 4).")


def save_plan(body, user):
    """The client's admins may change only per-person caps and alert levels. Prices and allowances come
    from the plan they chose (Billing → change plan) in the provider's catalogue."""
    with _usage_lock:
        cur = read_plan()
        if body.get("rev") != cur["rev"]:
            raise PermissionError(json.dumps({"error": f"{cur['updated_by']} changed the plan meanwhile. Reload and try again.", "current": cur}))
        if body.get("template"):
            raise ValueError("Change your plan in Usage & plan → Billing.")
        p = body.get("plan") or {}
        new = {**cur, "user_caps": p.get("user_caps", cur.get("user_caps", {})), "alert_at": sorted(set(p.get("alert_at", cur.get("alert_at")) or []))}
        validate_caps(new)
        new.update(rev=cur["rev"] + 1, updated_at=now_iso(), updated_by=user)
        write_plan(new)
        doc = _usage_doc()
        for k in new["meters"]:          # a new alert level can be crossed without new usage
            if METERS[k][2] == "meter":
                _check_alerts(doc, k)
        _usage["dirty"] = True
    audit(user, "usage.plan", f"caps and alerts updated (rev {new['rev']})")
    return new


def cycle_bounds(plan, at=None):
    """Billing cycle containing `at`, in IST, starting on the plan's cycle day."""
    now = (at or datetime.now(timezone.utc)).astimezone(IST_TZ)
    d = plan.get("cycle_day", 1)
    start = now.replace(day=d, hour=0, minute=0, second=0, microsecond=0)
    if now < start:
        start = (start.replace(day=1) - timedelta(days=1)).replace(day=d)
    end = (start.replace(day=28) + timedelta(days=8)).replace(day=d)
    return start, end


_usage = {"data": None, "dirty": False, "saved": 0}


def _usage_doc():
    if _usage["data"] is None:
        _usage["data"] = json.loads(USAGE_FILE.read_text()) if USAGE_FILE.exists() else {"days": {}, "watermark": None, "alerts": {}}
    return _usage["data"]


def _flush_usage(force=False):
    if _usage["dirty"] and (force or time.time() - _usage["saved"] > 5):
        keep = (datetime.now(IST_TZ) - timedelta(days=USAGE_KEEP_DAYS)).strftime("%Y-%m-%d")
        d = _usage["data"]
        d["days"] = {k: v for k, v in d["days"].items() if k >= keep}
        DATA.mkdir(exist_ok=True)
        tmp = USAGE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, separators=(",", ":")))
        tmp.replace(USAGE_FILE)
        _usage.update(dirty=False, saved=time.time())


def meter(user, key, n=1):
    """Add n to a person's meter for today (IST) and fire any threshold alerts."""
    if not n or not user:
        return
    with _usage_lock:
        doc = _usage_doc()
        day = datetime.now(IST_TZ).strftime("%Y-%m-%d")
        u = doc["days"].setdefault(day, {}).setdefault(user, {})
        u[key] = u.get(key, 0) + n
        _usage["dirty"] = True
        _check_alerts(doc, key)
        _flush_usage()


def _cycle_totals(doc, plan, start, end, user=None):
    tot, a, b = {}, start.strftime("%Y-%m-%d"), (end - timedelta(days=1)).strftime("%Y-%m-%d")
    for day, users in doc["days"].items():
        if a <= day <= b:
            for e, ms in users.items():
                if user is None or e == user:
                    for k, v in ms.items():
                        tot[k] = tot.get(k, 0) + v
    return tot


_seat_cache = {"n": None, "at": 0}


def seat_count():
    """Seats: dashboard accounts now (cached for a minute)."""
    if time.time() - _seat_cache["at"] > 60 or _seat_cache["n"] is None:
        try:
            _seat_cache.update(n=len(gotrue_admin("GET", "/users?per_page=1000").get("users", [])), at=time.time())
        except Exception:
            _seat_cache["at"] = time.time()
    return _seat_cache["n"] or 0


def _check_alerts(doc, key):
    plan = read_plan()
    inc = (plan["meters"].get(key) or {}).get("included")
    if not inc:
        return
    start, end = cycle_bounds(plan)
    used = _cycle_totals(doc, plan, start, end).get(key, 0)
    fired = doc["alerts"].setdefault(start.strftime("%Y-%m-%d"), {}).setdefault(key, [])
    for pct in plan.get("alert_at") or []:
        if used >= inc * pct / 100 and pct not in fired:
            fired.append(pct)
            doc["alerts"][start.strftime("%Y-%m-%d")].setdefault("_log", []).append({"meter": key, "pct": pct, "at": now_iso(), "used": used, "included": inc})
            audit("usage monitor", "usage.alert", f"{METERS[key][0]} at {pct}% of the plan ({used:,} of {inc:,})")


def quota_block(user, key, add=1):
    """Return an error message when a hard limit (plan-wide or this person's cap) would be exceeded."""
    plan = read_plan()
    start, end = cycle_bounds(plan)
    label = METERS[key][0]
    label = label if label[:2].isupper() else label[0].lower() + label[1:]
    with _usage_lock:
        doc = _usage_doc()
        cap = (plan.get("user_caps") or {}).get(user, {}).get(key)
        if cap is not None and _cycle_totals(doc, plan, start, end, user).get(key, 0) + add > cap:
            return f"Usage limit reached: your {label} cap is {cap:,} this cycle. Ask your administrator to raise it."
        if key not in (plan.get("hard") or []):
            return None
        inc = (plan["meters"].get(key) or {}).get("included")
        if inc is None:
            return None
        used = None if key == "seats" else _cycle_totals(doc, plan, start, end).get(key, 0)
    if used is None:
        used = seat_count()
    if used + add > inc:
        return (f"Usage limit reached: {label} {used:,} of {inc:,} on the {plan['name']} plan"
                + ("" if key == "seats" else f" this cycle (resets {end.strftime('%d %b')})") + ". Your administrator can move to a higher plan in Usage & plan → Billing.")
    return None


def usage_report(user, scope="me"):
    plan = read_plan()
    start, end = cycle_bounds(plan)
    now = datetime.now(IST_TZ)
    elapsed = max(1e-6, (now - start).total_seconds() / (end - start).total_seconds())
    with _usage_lock:
        doc = _usage_doc()
        tot = _cycle_totals(doc, plan, start, end)
        mine = _cycle_totals(doc, plan, start, end, user)
        a, b = start.strftime("%Y-%m-%d"), (end - timedelta(days=1)).strftime("%Y-%m-%d")
        daily, by_user = {}, {}
        for day, users in sorted(doc["days"].items()):
            if not a <= day <= b:
                continue
            for e, ms in users.items():
                if scope == "all" or e == user:
                    dd = daily.setdefault(day, {})
                    for k, v in ms.items():
                        dd[k] = dd.get(k, 0) + v
                if scope == "all":
                    bu = by_user.setdefault(e, {})
                    for k, v in ms.items():
                        bu[k] = bu.get(k, 0) + v
        alerts = list((doc["alerts"].get(start.strftime("%Y-%m-%d")) or {}).get("_log", []))
    seats = seat_count()
    rows, overage_total, forecast_over = [], 0.0, 0.0
    for k, (label, unit, kind, hardable, size, desc) in METERS.items():
        pm = plan["meters"].get(k) or {}
        used = seats if kind == "gauge" else (tot if scope == "all" else mine).get(k, 0)
        org_used = seats if kind == "gauge" else tot.get(k, 0)
        inc, price = pm.get("included"), pm.get("overage", 0) or 0
        forecast = org_used if kind == "gauge" else org_used / elapsed
        over = max(0, org_used - inc) if inc is not None else 0
        f_over = max(0, forecast - inc) if inc is not None else 0
        cost = math.ceil(over / size) * price if over else 0
        f_cost = math.ceil(f_over / size) * price if f_over else 0
        if k in plan["meters"]:
            overage_total += cost
            forecast_over += f_cost
        rows.append({"key": k, "label": label, "unit": unit, "kind": kind, "desc": desc, "billed": k in plan["meters"], "hardable": hardable,
                     "unit_size": size, "used": used, "org_used": org_used, "mine": seats if kind == "gauge" else mine.get(k, 0),
                     "included": inc, "overage_price": price, "hard": k in (plan.get("hard") or []),
                     "pct": round(org_used / inc * 100, 1) if inc else None, "forecast": round(forecast), "overage_units": over,
                     "overage_cost": cost, "forecast_cost": f_cost, "my_cap": (plan.get("user_caps") or {}).get(user, {}).get(k)})
    return {"plan": plan, "scope": scope, "client": CLIENT_NAME, "cycle": {"start": start.isoformat(), "end": end.isoformat(), "elapsed": round(elapsed, 4),
            "days_left": max(0, (end - now).days)}, "meters": rows, "daily": daily, "by_user": by_user if scope == "all" else {},
            "alerts": alerts, "estimate": {"base_fee": plan["base_fee"], "overage": overage_total, "total": plan["base_fee"] + overage_total,
            "forecast_total": plan["base_fee"] + forecast_over}, "generated_at": now_iso()}


def remaining(user, key):
    """How many more units this person may use this cycle under a cap or hard limit (None: no limit)."""
    plan = read_plan()
    start, end = cycle_bounds(plan)
    left = []
    with _usage_lock:
        doc = _usage_doc()
        cap = (plan.get("user_caps") or {}).get(user, {}).get(key)
        if cap is not None:
            left.append(cap - _cycle_totals(doc, plan, start, end, user).get(key, 0))
        inc = (plan["meters"].get(key) or {}).get("included")
        if key in (plan.get("hard") or []) and inc is not None:
            left.append(inc - _cycle_totals(doc, plan, start, end).get(key, 0))
    return max(0, min(left)) if left else None


def usage_alerts_for(user):
    """Meters at or above 80% of the plan this cycle (for the banner)."""
    try:
        r = usage_report(user, "me")
    except Exception:
        return []
    return [{"key": m["key"], "label": m["label"], "pct": m["pct"], "hard": m["hard"], "used": m["org_used"], "included": m["included"]}
            for m in r["meters"] if m["billed"] and m["pct"] is not None and m["pct"] >= 80]


def meter_new_lines(user, rows):
    """logs.analysed: count each log line once, the first time it is read, using an ingested_at
    watermark that survives restarts (lines ingested before the current cycle are not counted)."""
    plan = read_plan()
    start, _ = cycle_bounds(plan)
    with _usage_lock:
        doc = _usage_doc()
        # Plain string comparison works: NigraniAI timestamps and the cycle start are both UTC "+00:00".
        wm = max(doc.get("watermark") or "", start.astimezone(timezone.utc).isoformat())
        fresh = [r.get("ingested_at") for r in rows if (r.get("ingested_at") or "") > wm]
        if fresh:
            doc["watermark"] = max(fresh)
            _usage["dirty"] = True
    if fresh:
        meter(user, "logs.analysed", len(fresh))


def _usage_flusher():
    while True:
        time.sleep(5)
        try:
            with _usage_lock:
                _flush_usage(force=True)
        except Exception as e:
            sys.stderr.write(f"[consent] could not save usage: {e}\n")


threading.Thread(target=_usage_flusher, daemon=True).start()


# ---------------------------------------------------------------- readiness score history (data/readiness.json)
READINESS_FILE = DATA / "readiness.json"


def read_readiness():
    return json.loads(READINESS_FILE.read_text()) if READINESS_FILE.exists() else []


def save_readiness(body, actor):
    score = body.get("score")
    areas = body.get("areas") or []
    if not isinstance(score, (int, float)) or not 0 <= score <= 100 or not isinstance(areas, list) or len(areas) > 10:
        raise ValueError("invalid readiness result")
    clean = [{"key": str(a.get("key"))[:30], "label": str(a.get("label"))[:60], "score": a.get("score") if isinstance(a.get("score"), (int, float)) else None,
              "findings": len(a.get("findings") or [])} for a in areas]
    entry = {"at": now_iso(), "by": actor, "score": round(score), "grade": str(body.get("grade") or "")[:2], "areas": clean}
    hist = (read_readiness() + [entry])[-30:]
    DATA.mkdir(exist_ok=True)
    write_tracked(READINESS_FILE, json.dumps(hist, indent=2))
    audit(actor, "readiness.run", f"score {entry['score']} ({entry['grade']})")
    return entry


# ---------------------------------------------------------------- public exposure test (data/exposure.json)
# Reads the shop's database the way anyone on the internet can: with the public anon key that the
# shop's website already ships. GET requests only, at most one row per table, and the values are
# dropped at once: only table names, column names and counts are kept. Writes and database functions
# are never attempted (they could change data), so they are reported for review, not tested.
EXPOSURE_FILE = DATA / "exposure.json"
_exposure_lock = threading.Lock()
PII_PATTERNS = [   # (kind, sensitivity, column-name pattern; matched on whole words of the name)
    ("credentials", "critical", r"(^|_)(password|passwd|pwd|secret|otp|api_?key|token|refresh_token|access_token)(_hash)?($|_)|_hash$"),
    ("financial / ID", "critical", r"(^|_)(card(_number)?|cvv|iban|account_(no|number)|ifsc|upi(_id)?|aadhaa?r|pan(_number)?|passport|gstin|payment_(reference|id)|provider_(order|payment)_id|refund_id)($|_)"),
    ("contact", "critical", r"(^|_)(e_?mail|phone|mobile|whatsapp)($|_)"),
    ("network", "high", r"(^|_)(ip|ip_address|user_agent|device_id)$"),
    ("address", "critical", r"(^|_)(line1|line2|address|street|city|pin_?code|zip|postal_code|latitude|longitude|lat|lng)($|_)|^((ship|shipping|billing)_)?state$"),
    ("name", "high", r"^((ship|shipping|billing|customer|reviewer|contact)_)?(name|full_name|first_name|last_name)$"),
    ("birth / age", "high", r"(^|_)(dob|date_of_birth|birth_date|birthday|age|gender)$"),
    ("free text", "high", r"(^|_)(message|comment|comments|note|notes|reason|review_text|body)$"),
    ("person link", "medium", r"(^|_)(user|customer|profile|member|buyer|recipient)_?id$"),
]
STRONG_KINDS = {"credentials", "financial / ID", "contact", "address", "birth / age"}
PERSON_TABLE = re.compile(r"customer|user|profile|member|account|auth|recipient|review|contact|address|employee|staff|people|person|subscriber|buyer")
STAFF_LINK = re.compile(r"^(actor|created_by|updated_by|staff|admin|operator)")
SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}


def _col_kind(col):
    c = col.lower()
    return next(((k, sev) for k, sev, rx in PII_PATTERNS if re.search(rx, c)), None)


def classify_columns(table, cols):
    """Personal columns of a table, judged in context: contact, address, credentials, financial/ID and
    birth data always count; a bare name, free text or network field only when the table is about
    people (it has strong personal data, links to a customer, or is named like a person table), so a
    product's `name` or a stock note isn't flagged. Staff links (actor_user_id …) don't make context."""
    found = [(c, _col_kind(c)) for c in cols]
    found = [(c, k) for c, k in found if k]
    strong = any(k[0] in STRONG_KINDS for _, k in found)
    linked = any(k[0] == "person link" and not STAFF_LINK.match(c.lower()) for c, k in found)
    person = strong or linked or bool(PERSON_TABLE.search(table.lower()))
    out = []
    for c, k in found:
        if k[0] in STRONG_KINDS or (k[0] == "person link" and not STAFF_LINK.match(c.lower())) or person and k[0] != "person link":
            out.append((c, k))
    return out


def anon_get(path, params=None, accept=None, base="/rest/v1", count=False):
    """GET with the public anon key only. Returns (status, json-or-None, headers)."""
    url = f"{SHOP_URL}{base}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"apikey": SHOP_ANON, "Authorization": f"Bearer {SHOP_ANON}"}
    if accept:
        headers["Accept"] = accept
    if count:
        headers["Prefer"] = "count=exact"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r), r.headers
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"null")
        except ValueError:
            body = None
        return e.code, body, e.headers


def _range_total(h):
    total = ((h or {}).get("Content-Range") or "*/0").split("/")[-1]
    return int(total) if total.isdigit() else None


def _fix_sql(table, cols):
    owner = next((c for c in cols if re.search(r"(^|_)(user|customer|profile)_?id$", c.lower())), None)
    sql = [f"-- {table}: stop the public (anon) key from reading it",
           f"alter table public.{table} enable row level security;",
           f"revoke select on public.{table} from anon;"]
    if owner:
        sql += [f"-- let each signed-in customer read only their own rows",
                f"create policy \"{table}_own_rows\" on public.{table} for select to authenticated using (auth.uid() = {owner});"]
    return "\n".join(sql)


def _probe_table(table, cols_known):
    st, body, h = anon_get(f"/{urllib.parse.quote(table)}", {"select": "*", "limit": "1"}, count=True)
    if st in (401, 403) or (isinstance(body, dict) and body.get("code") in ("42501", "PGRST301", "PGRST302")):
        return {"table": table, "state": "blocked"}
    if st != 200 and st != 206:
        return {"table": table, "state": "error", "detail": f"HTTP {st}"}
    cols = list(body[0].keys()) if isinstance(body, list) and body else []
    del body                                      # the row's values are never kept
    visible = _range_total(h)
    if not cols:
        try:
            _, total = shop_get(f"/{urllib.parse.quote(table)}", {"select": "*", "limit": "0"}, count=True)
        except Exception:
            total = None
        return {"table": table, "state": "protected" if total else "empty", "rows_total": total}
    fused = pii_personal_for(table, set(cols))
    personal = ([{"column": r["column"], "kind": r["label"], "sensitivity": r["sensitivity"]} for r in fused] if fused is not None
                else [{"column": c, "kind": k[0], "sensitivity": k[1]} for c, k in classify_columns(table, cols)])
    sev = max((p["sensitivity"] for p in personal), key=lambda x: SEV_RANK[x], default="info")
    return {"table": table, "state": "exposed", "rows_visible": visible, "columns": len(cols), "personal": personal,
            "severity": sev, "fix": _fix_sql(table, cols) if personal else None}


def run_exposure(actor):
    if not (SHOP_URL and SHOP_ANON):
        raise ValueError("Add SHOP_SUPABASE_ANON_KEY (the shop's public key) to .env to run the exposure test.")
    with _exposure_lock:
        started = time.time()
        schema = shop_schema()
        tables = sorted(schema)
        with ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(lambda t: _probe_table(t, schema[t]), tables))
        checks = []
        st, _, _ = anon_get("/", accept="application/openapi+json")
        checks.append({"key": "schema", "severity": "low" if st == 200 else "ok",
                       "text": "Table and column names are listed publicly by the API." if st == 200 else "The API doesn't list tables and columns to the public.",
                       "fix": "Supabase → Settings → API: turn off the public OpenAPI schema." if st == 200 else None})
        st, auth, _ = anon_get("/settings", base="/auth/v1")
        if st == 200 and isinstance(auth, dict):
            if auth.get("mailer_autoconfirm") or auth.get("phone_autoconfirm"):
                checks.append({"key": "autoconfirm", "severity": "medium", "text": "New accounts are confirmed without verifying the email or phone, so anyone can create accounts with someone else's address.",
                               "fix": "Supabase → Authentication → Providers: turn on Confirm email."})
            else:
                checks.append({"key": "autoconfirm", "severity": "ok", "text": "New accounts must verify their email before they can sign in."})
            if auth.get("external", {}).get("anonymous_users"):
                checks.append({"key": "anonymous", "severity": "medium", "text": "Anonymous sign-ins are on: anyone gets a signed-in session, so data open to all signed-in users is open to everyone.",
                               "fix": "Turn off anonymous sign-ins unless the shop needs them, and check policies written 'to authenticated'."})
            if not auth.get("disable_signup"):
                checks.append({"key": "signup", "severity": "info", "text": "Public sign-up is open (normal for a shop). Rows readable by every signed-in user are only one sign-up away from the public.",
                               "fix": "Write policies per customer (auth.uid() = user_id), not 'to authenticated using (true)'."})
        try:
            req = urllib.request.Request(f"{SHOP_URL}/storage/v1/bucket", headers={"apikey": SHOP_KEY, "Authorization": f"Bearer {SHOP_KEY}"}, method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                buckets = json.load(r)
        except Exception:
            buckets = None
        if isinstance(buckets, list):
            pub = [b for b in buckets if b.get("public")]
            for b in pub:
                risky = re.search(r"invoice|kyc|id|doc|avatar|user|customer|profile|private|upload|return|bill", str(b.get("name", "")).lower())
                checks.append({"key": f"bucket:{b.get('name')}", "severity": "high" if risky else "low",
                               "text": f"Storage bucket '{b.get('name')}' is public: anyone with a file's link can download it.",
                               "fix": f"If it holds customers' files, make it private: update storage.buckets set public = false where id = '{b.get('id')}';"})
            if not pub:
                checks.append({"key": "buckets", "severity": "ok", "text": f"No public storage buckets ({len(buckets)} bucket(s) in all)."})
        try:
            rpcs = [p[5:] for p in (shop_get("/", accept_openapi=True).get("paths") or {}) if p.startswith("/rpc/")]
        except Exception:
            rpcs = []
        if rpcs:
            checks.append({"key": "rpc", "severity": "info", "text": f"{len(rpcs)} database function(s) exist: {', '.join(rpcs[:8])}{'…' if len(rpcs) > 8 else ''}. They weren't called (that could change data); check who may run them.",
                           "fix": "\n".join(f"revoke execute on function public.{f} from anon;" for f in rpcs[:20])})
        exposed = [r for r in results if r["state"] == "exposed"]
        personal = [r for r in exposed if r.get("personal")]
        penalty = sum({"critical": 30, "high": 18, "medium": 8}.get(r["severity"], 0) for r in personal)
        penalty += sum({"high": 15, "medium": 6, "low": 3}.get(c["severity"], 0) for c in checks)
        out = {"at": now_iso(), "by": actor, "seconds": round(time.time() - started, 1), "score": max(0, 100 - penalty),
               "tables": results, "checks": checks,
               "counts": {"tables": len(results), "exposed": len(exposed), "personal": len(personal),
                          "critical": sum(r["severity"] == "critical" for r in personal), "blocked": sum(r["state"] in ("blocked", "protected") for r in results),
                          "empty": sum(r["state"] == "empty" for r in results), "errors": sum(r["state"] == "error" for r in results)}}
        prev = read_exposure()
        before = {r["table"] for r in (prev.get("last") or {}).get("tables", []) if r.get("state") == "exposed" and r.get("personal")}
        out["new_exposures"] = sorted({r["table"] for r in personal} - before) if prev.get("last") else []
        hist = (prev.get("history") or []) + [{"at": out["at"], "score": out["score"], **out["counts"]}]
        DATA.mkdir(exist_ok=True)
        write_tracked(EXPOSURE_FILE, json.dumps({"last": out, "history": hist[-30:]}, indent=2))
    meter(actor, "exposure.tests")
    audit(actor, "exposure.run", f"score {out['score']}: {len(personal)} table(s) with personal data readable with the public key")
    return out


def read_exposure():
    try:
        return json.loads(EXPOSURE_FILE.read_text()) if EXPOSURE_FILE.exists() else {}
    except ValueError:
        return {}


def exposure_view():
    d = read_exposure()
    return {"configured": bool(SHOP_URL and SHOP_ANON), "last": d.get("last"), "history": d.get("history", [])[-20:]}


def _exposure_daily():
    """Re-run the test once a day after the first run, so a new leak shows up without anyone asking."""
    while True:
        time.sleep(600)
        try:
            last = (read_exposure().get("last") or {}).get("at")
            if SHOP_ANON and last and (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() > 86400:
                run_exposure("daily exposure test")
        except Exception as e:
            sys.stderr.write(f"[consent] daily exposure test failed: {e}\n")


threading.Thread(target=_exposure_daily, daemon=True).start()


# ---------------------------------------------------------------- evidence ledger (data/ledger.jsonl)
# A tamper-evident record of everything the service writes. Each audit event and each change to a
# compliance record file (policies, retention, breach detectors and incidents, access, plan, billing,
# readiness, exposure, and every saved version) adds a ledger entry holding that record's SHA-256
# fingerprint; each entry also holds the previous entry's hash, so editing, deleting or reordering any
# past entry breaks the chain. Once a day (IST) the chain's head is sealed. Verification re-reads the
# audit log and the files and checks them against the ledger. usage.json (meters, rewritten every few
# seconds) is not tracked; IAM's last-used times are left out of its fingerprint for the same reason.
LEDGER_FILE = DATA / "ledger.jsonl"
INTEGRITY_FILE = DATA / "integrity.json"     # the last verification result (status only)
TRACKED_FILES = ["policy.json", "retention.json", "breach.json", "incidents.json", "iam.json", "plan.json",
                 "billing.json", "readiness.json", "exposure.json", "datamap.json", "pii.json"]
TRACKED_DIRS = ["history", "retention_history", "breach_history"]
FP_IGNORE = {"iam.json": ("last_used",)}
GENESIS_HASH = "0" * 64
_ledger_rlock = threading.RLock()
_ledger_depth = [0]
_ledger = {"size": -1, "loaded": False, "seq": 0, "head": GENESIS_HASH, "files": {}, "audit_lines": 0, "seal_day": None, "genesis_at": None}


class _LedgerGuard:
    """Thread lock + a cross-process file lock (the provider's CLI may write while the server runs).
    On the outermost entry, re-load the ledger's state if another process appended to it."""
    def __enter__(self):
        _ledger_rlock.acquire()
        _ledger_depth[0] += 1
        if _ledger_depth[0] == 1:
            DATA.mkdir(exist_ok=True)
            self.fh = open(DATA / ".ledger.lock", "a")
            fcntl.flock(self.fh, fcntl.LOCK_EX)
            size = LEDGER_FILE.stat().st_size if LEDGER_FILE.exists() else 0
            if _ledger["loaded"] and size != _ledger["size"]:
                _ledger.update(loaded=False, seq=0, head=GENESIS_HASH, files={}, audit_lines=0, seal_day=None)
        return self

    def __exit__(self, *exc):
        _ledger_depth[0] -= 1
        if _ledger_depth[0] == 0:
            _ledger["size"] = LEDGER_FILE.stat().st_size if LEDGER_FILE.exists() else 0
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
        _ledger_rlock.release()


_ledger_lock = _LedgerGuard()


def _canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(s):
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def _rel(path):
    return Path(path).resolve().relative_to(DATA.resolve()).as_posix()


def _file_fp(rel):
    p = DATA / rel
    if not p.exists():
        return None
    raw = p.read_bytes()
    drop = FP_IGNORE.get(rel)
    if drop:
        try:
            d = json.loads(raw)
            for k in drop:
                d.pop(k, None)
            return _sha(_canon(d))
        except ValueError:
            pass
    return _sha(raw)


def _tracked_now():
    rels = list(TRACKED_FILES)
    for d in TRACKED_DIRS:
        if (DATA / d).is_dir():
            rels += sorted(f"{d}/{f.name}" for f in (DATA / d).glob("*.json"))
    return rels


def _audit_lines():
    return AUDIT_FILE.read_text().splitlines() if AUDIT_FILE.exists() else []


def _ledger_entries():
    if not LEDGER_FILE.exists():
        return []
    out = []
    for line in LEDGER_FILE.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"_bad": line[:80]})
    return out


def _ledger_write(entry):
    entry["seq"] = _ledger["seq"] + 1
    entry["prev"] = _ledger["head"]
    entry.setdefault("at", now_iso())
    entry["hash"] = _sha(_canon({k: v for k, v in entry.items() if k != "hash"}))
    DATA.mkdir(exist_ok=True)
    with LEDGER_FILE.open("a") as fh:
        fh.write(_canon(entry) + "\n")
    _ledger.update(seq=entry["seq"], head=entry["hash"])
    return entry


def _ledger_ready():
    """Load the ledger's state, or start it (genesis) by fingerprinting what exists now."""
    with _ledger_lock:
        if _ledger["loaded"]:
            return
        entries = _ledger_entries()
        if not entries:
            lines = _audit_lines()
            files = {r: _file_fp(r) for r in _tracked_now()}
            _ledger.update(loaded=True, files=dict(files), audit_lines=len(lines))
            g = _ledger_write({"type": "genesis", "audit_lines": len(lines), "audit_sha": _sha("".join(l + "\n" for l in lines)), "files": files,
                               "note": "Ledger started. Records before this moment are fingerprinted as they were, not individually."})
            _ledger["genesis_at"] = g["at"]
            return
        for e in entries:
            t = e.get("type")
            if t == "genesis":
                _ledger.update(files=dict(e.get("files") or {}), audit_lines=e.get("audit_lines", 0), genesis_at=e.get("at"))
            elif t == "audit":
                _ledger["audit_lines"] = e.get("line", _ledger["audit_lines"])
            elif t == "write":
                _ledger["files"][e["file"]] = e.get("sha")
            elif t == "seal":
                _ledger["seal_day"] = e.get("day")
        last = entries[-1]
        _ledger.update(loaded=True, seq=last.get("seq", len(entries)), head=last.get("hash", GENESIS_HASH))


def ledger_audit_line(line):
    """Called by audit() (under its lock) right after it appends `line`."""
    with _ledger_lock:
        _ledger_ready()
        _ledger["audit_lines"] += 1
        _ledger_write({"type": "audit", "line": _ledger["audit_lines"], "sha": _sha(line)})


def write_tracked(path, text):
    """Write a compliance record file and record its fingerprint in one step, so a verification
    never sees the file between the write and the ledger entry."""
    path = Path(path)
    with _ledger_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text)
        tmp.replace(path)
        ledger_file(path)


def ledger_file(path):
    """Record a compliance record file's new fingerprint after the service writes it."""
    try:
        rel = _rel(path)
    except ValueError:
        return
    with _ledger_lock:
        _ledger_ready()
        fp = _file_fp(rel)
        if fp != _ledger["files"].get(rel):
            _ledger["files"][rel] = fp
            _ledger_write({"type": "write", "file": rel, "sha": fp})


def verify_integrity(actor=None):
    """Re-check the chain, the audit log and every tracked file against the ledger."""
    with _audit_lock, _ledger_lock:
        _ledger_ready()
        entries, lines = _ledger_entries(), _audit_lines()
        problems, prev, files, audit_n, genesis, seals, exports = [], GENESIS_HASH, {}, 0, None, [], []
        for i, e in enumerate(entries, 1):
            if "_bad" in e:
                problems.append({"kind": "ledger", "text": f"Ledger line {i} is not readable: it was edited by hand."})
                break
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != i or e.get("prev") != prev or _sha(_canon(body)) != e.get("hash"):
                problems.append({"kind": "ledger", "at": e.get("at"), "text": f"Ledger entry #{i} ({e.get('type')}, {e.get('at')}) was changed, removed or reordered. Nothing after it can be trusted."})
                break
            prev = e["hash"]
            t = e.get("type")
            if t == "genesis":
                genesis = e
                files = dict(e.get("files") or {})
                audit_n = e.get("audit_lines", 0)
                if _sha("".join(l + "\n" for l in lines[:audit_n])) != e.get("audit_sha"):
                    problems.append({"kind": "audit", "at": e.get("at"), "text": f"The {audit_n} activity records from before the ledger started were changed."})
            elif t == "audit":
                n = e.get("line")
                if n is None or n > len(lines):
                    problems.append({"kind": "audit", "at": e.get("at"), "text": f"Activity record #{n} ({e.get('at')}) has been deleted."})
                elif _sha(lines[n - 1]) != e.get("sha"):
                    problems.append({"kind": "audit", "at": e.get("at"), "text": f"Activity record #{n} ({e.get('at')}) was edited after it was written."})
                audit_n = max(audit_n, n or 0)
            elif t == "write":
                files[e["file"]] = e.get("sha")
            elif t == "seal":
                seals.append({"day": e.get("day"), "at": e.get("at"), "head": e.get("prev"), "entries": e.get("entries"), "intact": e.get("intact")})
            elif t == "export":
                exports.append({"at": e.get("at"), "by": e.get("by"), "sha": e.get("sha"), "from": e.get("from"), "to": e.get("to")})
        if len(lines) > audit_n and not any(p["kind"] == "ledger" for p in problems):
            problems.append({"kind": "audit", "text": f"{len(lines) - audit_n} activity record(s) were added to the log outside the system."})
        changed = []
        if not any(p["kind"] == "ledger" for p in problems):
            for rel in sorted(set(files) | set(_tracked_now())):
                want, have = files.get(rel), _file_fp(rel)
                if want != have:
                    changed.append(rel)
                    problems.append({"kind": "file", "file": rel, "text": f"{rel} was deleted outside the system." if have is None else
                                     f"{rel} appeared without the system writing it." if want is None else f"{rel} was changed outside the system."})
        res = {"ok": not problems, "checked_at": now_iso(), "checked_by": actor or "integrity monitor", "entries": len(entries), "head": prev,
               "audit_records": len(lines), "files_tracked": len(set(files) | set(_tracked_now())), "since": (genesis or {}).get("at"),
               "problems": problems[:50], "problem_count": len(problems), "seals": seals[-60:], "exports": exports[-30:]}
    prior = {}
    try:
        prior = json.loads(INTEGRITY_FILE.read_text()) if INTEGRITY_FILE.exists() else {}
    except ValueError:
        pass
    INTEGRITY_FILE.write_text(json.dumps({k: res[k] for k in ("ok", "checked_at", "checked_by", "problem_count", "head")}, indent=2))
    if problems and (prior.get("ok", True) or prior.get("problem_count") != len(problems)):
        audit("integrity monitor", "integrity.broken", f"{len(problems)} problem(s): {problems[0]['text']}")
    return res


def _seal_tick():
    """Seal yesterday's chain head once the IST day has turned (after verifying it)."""
    with _ledger_lock:
        _ledger_ready()
        today = datetime.now(IST_TZ).date()
        day = (today - timedelta(days=1)).isoformat()
        start = datetime.fromisoformat(_ledger["genesis_at"]).astimezone(IST_TZ).date() if _ledger["genesis_at"] else today
        if _ledger["seal_day"] and _ledger["seal_day"] >= day or start > today - timedelta(days=1):
            return None
    v = verify_integrity()
    with _ledger_lock:
        e = _ledger_write({"type": "seal", "day": day, "entries": _ledger["seq"], "intact": v["ok"], "files": dict(_ledger["files"])})
        _ledger["seal_day"] = day
        return e


def _integrity_daily():
    while True:
        try:
            _seal_tick()
        except Exception as e:
            sys.stderr.write(f"[consent] ledger seal failed: {e}\n")
        time.sleep(60)


def _keep_days(k):
    n, u = (k or {}).get("n") or 0, (k or {}).get("unit") or "days"
    return n * {"seconds": 1 / 86400, "minutes": 1 / 1440, "hours": 1 / 24, "days": 1, "weeks": 7, "months": 30.44, "years": 365.25}.get(u, 1)


def log_retention(token):
    """Rule 6(1)(e): logs kept for at least one year. Reads the oldest NigraniAI log line and the
    retention rules for the logs table."""
    out = {"oldest": None, "days": None, "rules": [], "ok": True, "findings": []}
    try:
        r = gr_get("activity_logs", [("select", "logged_at"), ("order", "logged_at.asc"), ("limit", "1")], token)
        if r:
            out["oldest"] = r[0]["logged_at"]
            out["days"] = round((datetime.now(timezone.utc) - _ts(r[0]["logged_at"])).total_seconds() / 86400, 1)
    except Exception as e:
        out["error"] = f"Couldn't read the logs: {e}"
    for rule in read_doc("retention").get("rules", []):
        if rule.get("table") == "activity_logs" or rule.get("source") == "guardrail":
            d = _keep_days(rule.get("keep"))
            out["rules"].append({"id": rule.get("id"), "name": rule.get("name"), "keep_days": round(d, 1), "action": rule.get("action"), "enabled": rule.get("enabled", True)})
            if rule.get("enabled", True) and rule.get("action") == "delete" and d < 365:
                out["ok"] = False
                out["findings"].append(f"Retention rule {rule.get('id')} deletes logs after {round(d)} days; the Rules require at least one year.")
    return out


EVIDENCE_MAX_DAYS = 400


def build_pack(actor, frm, to, token):
    try:
        d0 = datetime.fromisoformat(frm).replace(tzinfo=IST_TZ) if frm else datetime.now(IST_TZ) - timedelta(days=90)
        d1 = datetime.fromisoformat(to).replace(tzinfo=IST_TZ) + timedelta(days=1) if to else datetime.now(IST_TZ) + timedelta(seconds=1)
    except ValueError:
        raise ValueError("Dates must be YYYY-MM-DD.")
    if d1 <= d0 or (d1 - d0).days > EVIDENCE_MAX_DAYS:
        raise ValueError(f"Pick a range of 1 to {EVIDENCE_MAX_DAYS} days.")
    inr = lambda v: bool(v) and d0 <= (_ts(v) or d0 - timedelta(days=1)) < d1
    integrity = verify_integrity(actor)
    stores = {}
    for kind in STORES:
        cur = read_doc(kind)
        _, h = store_paths(kind)
        vers = []
        for f in sorted(h.glob("v*.json"), key=lambda p: int(re.sub(r"\D", "", p.stem) or 0)):
            try:
                v = json.loads(f.read_text())
                vers.append({k: v.get(k) for k in ("version", "updated_at", "updated_by", "change_note")})
            except ValueError:
                pass
        stores[kind] = {"current_version": cur.get("version"), "updated_at": cur.get("updated_at"), "updated_by": cur.get("updated_by"),
                        "versions_in_range": [v for v in vers if inr(v["updated_at"])], "versions_total": len(vers)}
    incidents = []
    for inc in read_incidents().get("incidents", []):
        if inr(inc.get("created_at")) or inc.get("status") not in ("closed", "dismissed"):
            x = {k: v for k, v in inc.items() if k != "signals"}
            x["signals"] = [{k: v for k, v in s.items() if k != "sample_ids"} for s in inc.get("signals", [])]
            incidents.append(x)
    try:
        users = [{k: u.get(k) for k in ("email", "root", "created_at", "last_sign_in_at", "active", "policies")} for u in list_users()]
    except Exception:
        users = None
    iam = read_iam()
    events = []
    for line in _audit_lines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if inr(ev.get("at")):
            events.append(ev)
    exp = read_exposure()
    pack = {"kind": "dpdp-evidence-pack", "format": 1, "client": {"name": CLIENT_NAME, "id": CLIENT_ID},
            "generated_at": now_iso(), "generated_by": actor, "from": d0.date().isoformat(), "to": (d1 - timedelta(days=1)).date().isoformat(),
            "integrity": {k: integrity[k] for k in ("ok", "checked_at", "entries", "head", "audit_records", "files_tracked", "since", "problems", "problem_count")},
            "seals": [s for s in integrity["seals"] if d0.date().isoformat() <= (s["day"] or "") < d1.date().isoformat()],
            "readiness": [h for h in read_readiness() if inr(h.get("at"))],
            "exposure": {"last": {k: (exp.get("last") or {}).get(k) for k in ("at", "by", "score", "counts", "checks", "new_exposures")} if exp.get("last") else None,
                         "exposed_tables": [t for t in (exp.get("last") or {}).get("tables", []) if t.get("state") == "exposed"],
                         "history": [h for h in exp.get("history", []) if inr(h.get("at"))]},
            "log_retention": log_retention(token),
            "breach": {"incidents": incidents, "clocks_hours": read_doc("breach").get("clocks")},
            "records": stores,
            "access": {"users": users, "policies": [{"id": k, "name": p.get("name"), "version": p.get("version"), "updated_at": p.get("updated_at"), "document": p.get("document")}
                                                    for k, p in iam.get("policies", {}).items()]},
            "activity": {"count": len(events), "events": events[-5000:]},
            "about": "Generated by the DPDP compliance system. 'fingerprint' is the SHA-256 of this file's canonical JSON without it; "
                     "the same fingerprint is recorded in the system's ledger, so the pack can be checked later (Evidence & audit → Check a pack)."}
    pack["fingerprint"] = _sha(_canon(pack))
    with _ledger_lock:
        _ledger_ready()
        _ledger_write({"type": "export", "sha": pack["fingerprint"], "by": actor, "from": pack["from"], "to": pack["to"]})
    meter(actor, "evidence.packs")
    audit(actor, "evidence.export", f"evidence pack {pack['from']} to {pack['to']} · {pack['fingerprint'][:16]}")
    return pack


def check_pack(pack):
    if not isinstance(pack, dict) or pack.get("kind") != "dpdp-evidence-pack":
        raise ValueError("This isn't an evidence pack from this system.")
    claimed = pack.get("fingerprint")
    actual = _sha(_canon({k: v for k, v in pack.items() if k != "fingerprint"}))
    rec = next((e for e in _ledger_entries() if e.get("type") == "export" and e.get("sha") == actual), None)
    return {"unchanged": claimed == actual, "recorded": bool(rec), "recorded_at": (rec or {}).get("at"), "recorded_by": (rec or {}).get("by"),
            "from": pack.get("from"), "to": pack.get("to"), "client": (pack.get("client") or {}).get("name"), "fingerprint": actual}


def _ledger_summary(entries, n=40):
    """For the Evidence & audit page: the latest chain entries, the last change to each protected file,
    entry counts by type and per IST day (last 14 days). Names, times and fingerprints only."""
    chain, files, by_type, per_day = [], {}, {}, {}
    for e in entries:
        if "_bad" in e:
            continue
        t = e.get("type")
        by_type[t] = by_type.get(t, 0) + 1
        try:
            day = (datetime.fromisoformat(e["at"]) + timedelta(hours=5, minutes=30)).date().isoformat()
            per_day[day] = per_day.get(day, 0) + 1
        except (KeyError, ValueError, TypeError):
            pass
        if t == "write" and e.get("file"):
            f = files.setdefault(e["file"], {"file": e["file"], "writes": 0})
            f.update(writes=f["writes"] + 1, at=e.get("at"), sha=e.get("sha"), seq=e.get("seq"))
    lines = _audit_lines()
    for e in entries[-n:]:
        if "_bad" in e:
            continue
        x = {k: e.get(k) for k in ("seq", "at", "type", "file", "line", "day", "by", "from", "to", "entries", "intact")
             if e.get(k) is not None} | {"hash": e.get("hash"), "prev": e.get("prev")}
        if e.get("type") == "audit" and isinstance(e.get("line"), int) and 0 < e["line"] <= len(lines):
            try:
                a = json.loads(lines[e["line"] - 1])
                x.update(action=a.get("action"), by=a.get("user"))
            except ValueError:
                pass
        chain.append(x)
    days = sorted(per_day)[-14:]
    return {"chain": chain[::-1], "protected": sorted(files.values(), key=lambda f: f.get("at") or "", reverse=True),
            "by_type": by_type, "per_day": [{"day": d, "entries": per_day[d]} for d in days]}


def evidence_view(token):
    v = verify_integrity()
    return {**v, **_ledger_summary(_ledger_entries()), "log_retention": log_retention(token),
            "next_seal": "after midnight IST", "genesis_at": _ledger["genesis_at"]}


threading.Thread(target=_integrity_daily, daemon=True).start()


# ---------------------------------------------------------------- data map and record of processing (data/datamap.json)
# Builds a live map of personal data: which tables hold it (column names classified), which services
# read and write it (from NigraniAI's database_logs), which purposes cover it (the consent policy and
# the declarations below) and which processors receive it (detected in the logs and the settings, plus
# a register the admins keep). From that it writes the record of processing and finds the gaps: data
# with no purpose, services using data outside their purposes, missing retention, public exposure,
# processors without a contract. Reads only: shop schema and row counts (service key), log rows (the
# user's own token). No values are read or stored, only names and counts.
DATAMAP_FILE = DATA / "datamap.json"
DEFAULT_DATAMAP = ROOT / "default_datamap.json"
DATAMAP_WINDOW_DAYS = 30
DATAMAP_ROW_CAP = 100000
_datamap_lock = threading.Lock()
KIND_CATEGORY = {"credentials": "credentials", "financial / ID": "financial", "contact": "contact", "address": "address",
                 "name": "identity", "birth / age": "identity", "network": "device", "free text": "customer content",
                 "person link": "identifier"}
LOG_CATEGORY = {"personal_data": "personal", "financial": "financial", "credentials": "credentials", "communication": "communication"}
ERASURE_STEP_TABLES = {"anonymise_profile": "customers", "replace_email": "customers", "remove_phone": "customers", "marketing_off": "customers",
                       "delete_addresses": "customer_addresses", "delete_wishlist": "customer_wishlist", "revoke_sessions": "auth_refresh_tokens"}
GAP_WEIGHT = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
MASKER_TIMESTAMP_FP = re.compile(r"time ?stamp\W{0,3}\[CARD\]", re.I)
SOFT_CATEGORIES = {"identifier", "device", "customer content", "linked to a person"}   # not checked against the notice
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
DPA_STATES = (True, False, None)


def read_datamap():
    try:
        d = json.loads(DATAMAP_FILE.read_text()) if DATAMAP_FILE.exists() else {}
    except ValueError:
        d = {}
    if not d.get("config"):
        base = json.loads(DEFAULT_DATAMAP.read_text())
        base.pop("_about", None)
        d["config"] = {**base, "rev": 1, "updated_at": now_iso(), "updated_by": "system (default)"}
    d.setdefault("history", [])
    return d


def _clean_text(v, n):
    return str(v or "").strip()[:n]


def save_datamap_config(body, actor):
    """Replace the declarations (service and table purposes, processors). Purposes must exist in
    the consent policy; `rev` must match the current one (two admins editing at once)."""
    purposes = {p["id"] for p in read_doc("policy").get("purposes", [])}
    with _datamap_lock:
        d = read_datamap()
        cur = d["config"]
        if body.get("rev") != cur.get("rev"):
            raise PermissionError("Someone else changed the declarations meanwhile. Reload and try again.")
        def plist(v, where):
            v = [str(x) for x in (v or [])]
            bad = [x for x in v if x not in purposes]
            if bad:
                raise ValueError(f"{where}: unknown purpose {', '.join(bad)}")
            return list(dict.fromkeys(v))
        services = {}
        for k, v in (body.get("services") or {}).items():
            if not IDENT.match(str(k)):
                raise ValueError(f"bad service name: {k}")
            services[str(k)] = {"purposes": plist((v or {}).get("purposes"), k), "note": _clean_text((v or {}).get("note"), 200)}
        tables = {}
        for k, v in (body.get("tables") or {}).items():
            if not IDENT.match(str(k)):
                raise ValueError(f"bad table name: {k}")
            tables[str(k)] = {"purposes": plist((v or {}).get("purposes"), k), "retention": _clean_text((v or {}).get("retention"), 200)}
        procs, ids = [], set()
        raw = body.get("processors") or []
        if not isinstance(raw, list) or len(raw) > 60:
            raise ValueError("processors must be a list of at most 60")
        for p in raw:
            name = _clean_text(p.get("name"), 80)
            if not name:
                raise ValueError("every processor needs a name")
            pid = re.sub(r"[^a-z0-9]+", "-", str(p.get("id") or name).lower()).strip("-")[:40] or "processor"
            while pid in ids:
                pid += "-2"
            ids.add(pid)
            cats = [c for c in dict.fromkeys(str(x) for x in (p.get("data_categories") or [])) if re.fullmatch(r"[a-z ]{2,30}", c)]
            procs.append({"id": pid, "name": name, "role": _clean_text(p.get("role"), 120), "purposes": plist(p.get("purposes"), name),
                          "data_categories": cats[:12], "country": _clean_text(p.get("country"), 60),
                          "dpa": p.get("dpa") if p.get("dpa") in DPA_STATES else None, "notes": _clean_text(p.get("notes"), 300)})
        cfg = {"services": services, "tables": tables, "processors": procs,
               "ignore_tables": [str(x)[:63] for x in (body.get("ignore_tables") if isinstance(body.get("ignore_tables"), list) else cur.get("ignore_tables", []))][:50],
               "rev": cur.get("rev", 1) + 1, "updated_at": now_iso(), "updated_by": actor}
        d["config"] = cfg
        write_tracked(DATAMAP_FILE, json.dumps(d, indent=2))
    audit(actor, "datamap.declare", f"declarations rev {cfg['rev']}: {len(services)} services, {len(tables)} tables, {len(procs)} processors")
    return cfg


def _gr_pages(table, params, token, cap=DATAMAP_ROW_CAP):
    rows, off = [], 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        while off < cap:
            pages = list(pool.map(lambda o: gr_get(table, params + [("limit", "1000"), ("offset", str(o))], token), range(off, off + 6000, 1000)))
            for p in pages:
                rows += p
            if any(len(p) < 1000 for p in pages):
                break
            off += 6000
    return rows


def _row_count(table):
    try:
        _, total = shop_get(f"/{urllib.parse.quote(table)}", {"limit": "0"}, count=True)
        return total
    except Exception:
        return None


def _dm_context(token):
    """Everything the map needs except the log flows: schema, row counts, purposes, retention,
    exposure, the service registry, personal data seen in log lines, detected processors."""
    policy, retention = read_doc("policy"), read_doc("retention")
    purposes = {p["id"]: p for p in policy.get("purposes", [])}
    with _datamap_lock:
        cfg = read_datamap()["config"]
    prev = (read_datamap().get("last") or {})
    ignore = set(cfg.get("ignore_tables") or [])
    schema = shop_schema()
    since = (datetime.now(timezone.utc) - timedelta(days=DATAMAP_WINDOW_DAYS)).isoformat(timespec="seconds")

    # -- where the data is: tables and their personal columns
    with ThreadPoolExecutor(max_workers=6) as ex:
        counts = dict(zip(schema, ex.map(_row_count, list(schema))))
    exposure = {t["table"]: t for t in ((read_exposure().get("last") or {}).get("tables") or [])}
    table_purposes = {}
    for a in policy.get("activities", []):
        if a.get("table"):
            ps = table_purposes.setdefault(a["table"], [])
            for pid in [a.get("purpose")] + list((a.get("type_map") or {}).values()):
                if pid and pid not in ps:
                    ps.append(pid)
    policy_purposes = {t: list(v) for t, v in table_purposes.items()}
    for t, v in (cfg.get("tables") or {}).items():
        ps = table_purposes.setdefault(t, [])
        ps += [p for p in v.get("purposes", []) if p not in ps]
    retention_by = {}
    for r in retention.get("rules", []):
        if not r.get("enabled", True):
            continue
        k = r.get("keep") or {}
        label = {"age": f"{r.get('action') or 'review'} after {k.get('n')} {k.get('unit')}", "legal_minimum": f"keep at least {k.get('n')} {k.get('unit')} (legal)",
                 "erasure": f"erase {k.get('n')} {k.get('unit')} after a request", "inactivity": f"review after {k.get('n')} {k.get('unit')} inactive"}.get(r.get("type"), r.get("type"))
        targets = [r["table"]] if r.get("table") else [ERASURE_STEP_TABLES[s] for s in r.get("steps", []) if s in ERASURE_STEP_TABLES] if r.get("type") == "erasure" else \
                  [(policy.get("principal") or {}).get("table")] if r.get("type") == "inactivity" else []
        for t in dict.fromkeys(x for x in targets if x):
            retention_by.setdefault(t, []).append({"id": r.get("id"), "name": r.get("name"), "type": r.get("type"), "rule": label})
    for t, v in (cfg.get("tables") or {}).items():
        if (v.get("retention") or "").strip() and t not in retention_by:
            retention_by[t] = [{"id": "declared", "name": "Declared", "type": "declared", "rule": v["retention"].strip()}]
    tables = {}
    for t, cols in schema.items():
        if t in ignore:
            continue
        fused = pii_personal_for(t)
        if fused is not None:
            personal = [{"column": r["column"], "kind": r["label"], "sensitivity": r["sensitivity"] if r["sensitivity"] != "medium" else "medium",
                         "category": r["category"], "confidence": r["confidence"], "verdict": r["verdict"], "evidence": r["evidence"][:3], "v2": True}
                        for r in fused]
        else:
            personal = [{"column": c, "kind": k[0], "sensitivity": k[1], "category": KIND_CATEGORY.get(k[0], "other")}
                        for c, k in classify_columns(t, [c["name"] for c in cols])]
        cats = sorted({p["category"] for p in personal if p["category"] != "identifier"})
        if not cats and personal and PERSON_TABLE.search(t.lower()):
            cats = ["linked to a person"]
        ex = exposure.get(t) or {}
        tables[t] = {"table": t, "rows": counts.get(t), "columns": len(cols), "personal": personal, "categories": cats,
                     "is_personal": bool(cats), "sensitivity": max((p["sensitivity"] for p in personal), key=lambda s: SEV_RANK.get(s, 0), default=None),
                     "purposes": [p for p in table_purposes.get(t, []) if p in purposes], "retention": retention_by.get(t, []),
                     "policy_purposes": [p for p in policy_purposes.get(t, []) if p in purposes],
                     "public": ex.get("state") if ex else None, "services": {}, "accesses": 0, "last_access": None}

    # -- who uses it: service → table flows from the database logs
    registry = {}
    try:
        for s in gr_get("service_registry", [("select", "service,display_name,has_database,active")], token):
            registry[s["service"]] = s
    except Exception:
        pass
    # personal data in log lines (masked before storage), per service
    log_pii, log_pii_fp = collections.Counter(), collections.Counter()
    try:
        for r in _gr_pages("activity_logs", [("select", "service,masked_pii_types,message"), ("masked_pii_types", "neq.{}"), ("logged_at", f"gte.{since}")], token, cap=20000):
            msg = r.get("message") or ""
            for k in r.get("masked_pii_types") or []:
                # the log masker also masks 13-digit epoch-millisecond timestamps as card numbers
                if k == "CREDIT_CARD" and MASKER_TIMESTAMP_FP.search(msg):
                    log_pii_fp[(r.get("service"), k)] += 1
                else:
                    log_pii[(r.get("service"), k)] += 1
    except Exception:
        pass
    rzp = None
    try:
        hit = gr_get("activity_logs", [("select", "service,message,logged_at"), ("event", "like.razorpay*"), ("order", "logged_at.desc"), ("limit", "1")], token)
        rzp = hit[0] if hit else None
    except Exception:
        pass
    return {"built": time.time(), "policy": policy, "purposes": purposes, "cfg": cfg, "prev": prev, "tables": tables, "registry": registry,
            "log_pii": log_pii, "log_pii_fp": log_pii_fp, "rzp": rzp, "counts": counts}


def _dm_bucket_rows(buckets, rows):
    """Add database-log rows to per-day buckets keyed by (service, table), so the 30-day window can roll."""
    n = 0
    for r in rows:
        t, sv = r.get("db_table"), r.get("service")
        if not t or not sv:
            continue
        day = (r.get("logged_at") or "")[:10]
        b = buckets.setdefault((sv, t), {}).setdefault(day, {"count": 0, "ops": collections.Counter(), "cats": set(), "personal": False, "last": ""})
        b["count"] += 1
        b["ops"][(r.get("operation") or "ACCESS").upper()] += 1
        if r.get("data_category") in LOG_CATEGORY:
            b["cats"].add(LOG_CATEGORY[r["data_category"]])
        b["personal"] = b["personal"] or bool(r.get("personal_data"))
        b["last"] = max(b["last"], r.get("logged_at") or "")
        n += 1
    return n


def _dm_flows(buckets, tables, since):
    day0 = since[:10]
    flows = {}
    for (sv, t), days in buckets.items():
        if t not in tables:
            continue
        for day in [d for d in days if d < day0]:
            del days[day]
        for b in days.values():
            f = flows.setdefault((sv, t), {"service": sv, "table": t, "count": 0, "ops": collections.Counter(), "log_categories": set(), "personal": False, "last": None})
            f["count"] += b["count"]
            f["ops"].update(b["ops"])
            f["log_categories"] |= b["cats"]
            f["personal"] = f["personal"] or b["personal"]
            f["last"] = max(f["last"] or "", b["last"]) or None
    return flows


def _dm_compute(ctx, flows, actor, started, log_rows, truncated, since):
    policy, purposes, cfg, prev, registry, log_pii, rzp, counts = (ctx[k] for k in ("policy", "purposes", "cfg", "prev", "registry", "log_pii", "rzp", "counts"))
    tables = json.loads(json.dumps(ctx["tables"]))
    services = {}
    for name in sorted(set(registry) | {s for s, _ in flows} | set(cfg.get("services") or {})):
        decl = (cfg.get("services") or {}).get(name) or {}
        reg = registry.get(name) or {}
        services[name] = {"service": name, "display_name": reg.get("display_name") or name, "registered": bool(reg), "active": reg.get("active", True),
                          "declared": name in (cfg.get("services") or {}), "purposes": [p for p in decl.get("purposes", []) if p in purposes],
                          "note": decl.get("note", ""), "tables": [], "accesses": 0, "personal_accesses": 0,
                          "log_pii": {k: n for (s, k), n in log_pii.items() if s == name}}
    flow_list = []
    for (s, t), f in sorted(flows.items(), key=lambda kv: -kv[1]["count"]):
        tb, sv = tables[t], services[s]
        personal = tb["is_personal"] or f["personal"]
        overlap = sorted(set(tb["purposes"]) & set(sv["purposes"]))
        writes = sum(n for op, n in f["ops"].items() if op in ("INSERT", "UPDATE", "DELETE", "ALTER", "UPSERT"))
        fl = {"service": s, "table": t, "count": f["count"], "ops": dict(f["ops"].most_common()), "writes": writes, "personal": personal,
              "categories": sorted(set(tb["categories"]) | (f["log_categories"] - {"personal", "communication"})), "purposes": overlap,
              "in_purpose": bool(overlap) or not personal, "last": f["last"]}
        flow_list.append(fl)
        tb["services"][s] = f["count"]
        tb["accesses"] += f["count"]
        tb["last_access"] = max(tb["last_access"] or "", f["last"] or "") or None
        sv["tables"].append(t)
        sv["accesses"] += f["count"]
        if personal:
            sv["personal_accesses"] += f["count"]

    # -- who receives it: processors (declared, plus what the logs and settings show)
    detected = {}
    if rzp:
        mode = re.search(r"mode=(\w+)", rzp.get("message") or "")
        mode_txt = " (mode %s)" % mode.group(1) if mode else ""
        detected["razorpay"] = f"{rzp.get('service')} logs Razorpay events{mode_txt}, last {(rzp.get('logged_at') or '')[:10]}"
    if SHOP_URL:
        detected["supabase-shop"] = f"The shop database is hosted at {urllib.parse.urlparse(SHOP_URL).hostname}"
    if AUTH_URL:
        detected["supabase-logs"] = f"Application logs are stored at {urllib.parse.urlparse(AUTH_URL).hostname}"
    procs = [dict(p) for p in cfg.get("processors") or []]
    if AI_KEY and not any(p["id"] == "ai-provider" for p in procs):
        procs.append({"id": "ai-provider", "name": "Groq" if "groq" in AI_BASE else "xAI", "role": "AI assistant for the compliance team", "purposes": [],
                      "data_categories": [], "country": "", "dpa": None, "notes": "Receives questions and masked summaries from this dashboard; no customer records."})
    if AI_KEY:
        detected["ai-provider"] = "GROK_API_KEY is set: the AI assistant is on"
    all_personal = sorted({c for t in tables.values() for c in t["categories"]})
    log_cats = sorted({"financial" if k in ("CREDIT_CARD", "BANK_ACCOUNT", "UPI", "IFSC") else "contact" if k in ("EMAIL", "PHONE") else "identity" for (_, k) in log_pii})
    for p in procs:
        p["detected"] = detected.get(p["id"])
        if p["id"] == "supabase-shop" and not p.get("data_categories"):
            p["data_categories"], p["auto_categories"] = all_personal, True
        if p["id"] == "supabase-logs" and not p.get("data_categories"):
            p["data_categories"], p["auto_categories"] = log_cats, True
        if p["id"] == "supabase-shop" and not p.get("purposes"):
            p["purposes"], p["auto_purposes"] = sorted({x for t in tables.values() for x in t["purposes"]}), True
        p["handles_personal"] = bool(p.get("data_categories")) or bool(p.get("purposes"))

    # -- gaps
    gaps = []
    def gap(kind, key, sev, title, detail, ref, fix, node=None):
        gaps.append({"id": f"{kind}:{key}", "kind": kind, "severity": sev, "title": title, "detail": detail, "ref": ref, "fix": fix, "node": node})
    for t in tables.values():
        if not t["is_personal"]:
            continue
        cats = ", ".join(t["categories"])
        rows_txt = "" if t["rows"] is None else ", %s rows" % format(t["rows"], ",")
        if not t["purposes"]:
            gap("no_purpose", t["table"], "high", f"{t['table']} holds personal data with no declared purpose",
                f"{len(t['personal'])} personal column(s) ({cats}){rows_txt}; no purpose in the consent policy or the declarations covers it.",
                "DPDP Act s.5(1), s.6(1) · purpose limitation", "Declare the purpose it serves (Declarations → Tables), tell customers in the notice, or stop collecting it.", f"t:{t['table']}")
        if not t["retention"]:
            gap("no_retention", t["table"], "medium", f"{t['table']} has no retention rule",
                f"Personal data ({cats}) is kept with no deadline.", "DPDP Act s.8(7) · erase when the purpose is served",
                "Add a retention rule for this table in Retention → Rules.", f"t:{t['table']}")
        if t["public"] == "exposed":
            gap("public", t["table"], "critical", f"{t['table']} is readable by anyone with the public key",
                "The public exposure test could read this table without signing in.", "DPDP Act s.8(5) · DPDP Rules Rule 6(1)(b)",
                "Apply the fix in Readiness → Public exposure.", f"t:{t['table']}")
        if t["rows"] and not t["accesses"]:
            gap("dormant", t["table"], "low", f"{t['table']}: personal data no service used in {DATAMAP_WINDOW_DAYS} days",
                f"{t['rows']:,} rows with {cats}, untouched in the logs for {DATAMAP_WINDOW_DAYS} days.", "DPDP Act s.8(7)",
                "Check whether it's still needed; if not, delete it or schedule it in Retention.", f"t:{t['table']}")
    off_by = collections.defaultdict(list)
    for f in flow_list:
        if f["personal"] and not f["in_purpose"]:
            off_by[f["service"]].append(f)
    for svc, fl in off_by.items():
        sv = services[svc]
        cats = sorted({c for f in fl for c in f["categories"]} - SOFT_CATEGORIES)
        sens = "critical" if {"financial", "credentials"} & set(cats) else "high"
        per = "; ".join("%s: %s accesses (%s), serves %s" % (f["table"], format(f["count"], ","), ", ".join("%s %s" % (k, format(v, ",")) for k, v in f["ops"].items()),
                        ", ".join(purposes[x]["name"] for x in tables[f["table"]]["purposes"]) or "no declared purpose") for f in fl)
        gap("purpose_gap", svc, sens, f"{svc} uses personal data from {len(fl)} table(s) outside its purposes",
            "It declares %s, but in %d days it used %s data. %s." % (", ".join(purposes[x]["name"] for x in sv["purposes"]) or "no purpose",
                                                                       DATAMAP_WINDOW_DAYS, ", ".join(cats) or "personal", per),
            "DPDP Act s.4(1)(b), s.6(1) · process only for the specified purpose",
            "Declare the purpose this service needs the data for (and add it to the notice), give it aggregated or anonymised data instead, or remove its access.",
            f"s:{svc}")
    for pid, p in purposes.items():
        mine = [t for t in tables.values() if pid in t["purposes"] and t["is_personal"]]
        found = sorted({c for t in mine for c in t["categories"]})
        declared = set(p.get("data_categories") or []) | ({"identity"} if "customer content" in (p.get("data_categories") or []) else set())
        extra = [c for c in found if c not in declared and c not in SOFT_CATEGORIES]
        if extra:
            gap("undeclared_category", pid, "medium", f"{p['name']}: data categories not stated in the notice",
                f"Tables used for {p['name']} hold {', '.join(extra)}, which the purpose doesn't list ({', '.join(p.get('data_categories') or []) or 'none listed'}).",
                "DPDP Act s.5(1)(i) · notice must itemise the personal data", f"Add {', '.join(extra)} to the purpose in Consent & Purpose → Policy, so the notice states it.", f"p:{pid}")
    for s in services.values():
        if s["personal_accesses"] and not s["declared"]:
            gap("undeclared_service", s["service"], "medium", f"{s['service']} isn't in the declarations",
                f"It used personal data {s['personal_accesses']:,} times in {DATAMAP_WINDOW_DAYS} days.", "DPDP Act s.8(1) · accountability",
                "Add it in Declarations → Services with the purposes it serves.", f"s:{s['service']}")
    for k in sorted({k for (_, k) in log_pii}):
        per = sorted(((svc, n) for (svc, kk), n in log_pii.items() if kk == k), key=lambda x: -x[1])
        label = k.replace("_", " ").lower()
        gap("pii_in_logs", k, "medium", f"{label.capitalize()} values appear in the logs of {len(per)} service(s)",
            "%s log line(s) in %d days carried a %s (masked before storage): %s." % (format(sum(n for _, n in per), ","), DATAMAP_WINDOW_DAYS, label,
                                                                                     ", ".join("%s %d" % (svc, n) for svc, n in per)),
            "DPDP Act s.8(5) · Rule 6(1)(a)", "Find where these values enter the log messages and stop writing them at the source.", "r:supabase-logs")
    fp = ctx.get("log_pii_fp") or {}
    if fp:
        n_fp, svcs = sum(fp.values()), sorted({svc for (svc, _) in fp})
        gap("masker_false_positive", "CREDIT_CARD", "info", "The log masker mistakes timestamps for card numbers",
            "%s log line(s) in %d days had a 13-digit timestamp masked as [CARD] (Eureka / Spring status messages) in %d service(s): %s. These are not card numbers and are not counted as personal data in logs."
            % (format(n_fp, ","), DATAMAP_WINDOW_DAYS, len(svcs), ", ".join(svcs)),
            "DPDP Rules Rule 6(1)(a) · accurate masking", "Tune the masker: require a Luhn-valid 15–16 digit number and skip values next to 'timestamp'.", "r:supabase-logs")
    for p in procs:
        if not p["handles_personal"]:
            continue
        if p.get("dpa") is not True:
            det_txt = "; detected: %s" % p["detected"] if p.get("detected") else ""
            gap("processor_contract", p["id"], "medium" if p.get("dpa") is None else "high", f"{p['name']}: no data processing agreement on record",
                f"{p['name']} ({p.get('role') or 'processor'}) handles {', '.join(p.get('data_categories') or []) or 'personal data'}{det_txt}.",
                "DPDP Act s.8(2) · engage a processor only under a valid contract", "Sign or file a data processing agreement and mark it in Declarations → Processors.", f"r:{p['id']}")
        if not p.get("country"):
            gap("processor_country", p["id"], "low", f"{p['name']}: processing location not recorded",
                "Where the data is processed decides whether cross-border rules apply.", "DPDP Act s.16 · transfer outside India",
                "Record the country (or region) in Declarations → Processors.", f"r:{p['id']}")
    before = {f"{t['table']}.{c['column']}" for t in (prev.get("tables") or []) for c in t.get("personal", [])} if prev else None
    now_cols = {f"{t['table']}.{c['column']}" for t in tables.values() for c in t["personal"]}
    new_cols = sorted(now_cols - before) if before is not None else []
    if new_cols:
        gap("new_personal", ",".join(new_cols)[:80], "medium", f"{len(new_cols)} new personal column(s) since the last scan",
            ", ".join(new_cols[:12]) + ("…" if len(new_cols) > 12 else ""), "DPDP Act s.5, s.8(1)",
            "Check that a purpose, a notice and a retention rule cover them.")
    # PII detection v2: hidden personal data, government IDs, unmasked personal data in logs, columns to review
    for t in tables.values():
        hid = [p for p in t["personal"] if p.get("v2") and any("hidden personal data" in e for e in p.get("evidence", []))]
        if hid:
            gap("hidden_pii", t["table"], "high", f"{t['table']}: personal data in columns whose names don't say so",
                "; ".join(f"{p['column']}: {p['kind'].lower()} ({p['confidence']}%)" for p in hid) + ". Easy to miss in reviews, exports and deletion.",
                "DPDP Act s.8(5) · s.8(7)", "Rename the columns (or record them), and make sure purpose, retention and erasure cover them.", f"t:{t['table']}")
        gov = [p for p in t["personal"] if p.get("category") == "government ID"]
        if gov:
            gap("government_id", t["table"], "high", f"{t['table']} stores government ID numbers",
                "; ".join(f"{p['column']}: {p['kind']} ({p['confidence']}%)" for p in gov) + ".",
                "DPDP Act s.8(5) · Aadhaar Act s.29 · DPDP Rules Rule 6(1)(a)",
                "Keep them only if a law requires it; otherwise remove them. Store masked or encrypted (e.g. last 4 digits), and limit who can read them.", f"t:{t['table']}")
    lk = list(_pii_logs["leaks"].values())
    for k in sorted({k for x in lk for k in x["kinds"]}):
        xs = [x for x in lk if k in x["kinds"]]
        svcs = collections.Counter(x["service"] for x in xs)
        gap("unmasked_log_pii", k, "critical" if k in ("card", "aadhaar", "jwt", "pan", "passport") else "high",
            f"Unmasked {pii_engine.KINDS.get(k, (k,))[0].lower()}s in stored logs",
            "%d log line(s) in %d days hold a validated %s the masker didn't catch: %s." % (len(xs), PII_LOG_WINDOW_DAYS, pii_engine.KINDS.get(k, (k,))[0].lower(),
                                                                                         ", ".join("%s %d" % (sv, n) for sv, n in svcs.most_common())),
            "DPDP Act s.8(5) · DPDP Rules Rule 6(1)(a)", "Stop the services writing the value to their logs, extend the masker, and purge the stored lines. Log Telemetry → filter 'Unmasked personal data' lists them.",
            "r:supabase-logs")
    pv = [(tn, c, r) for tn, m in pii_columns().items() for c, r in m.items() if r["verdict"] == "possible"]
    if pv:
        gap("pii_review", str(len(pv)), "low", f"{len(pv)} column(s) might hold personal data: please confirm",
            ", ".join(f"{tn}.{c}" for tn, c, _ in pv[:10]) + ("…" if len(pv) > 10 else "") + ". The evidence was not strong enough to decide.",
            "DPDP Act s.8(1) · accountability", "Open Data map → Detection and confirm or reject each one; the answer is kept.")
    gaps.sort(key=lambda g: (SEV_ORDER.index(g["severity"]), g["kind"], g["id"]))

    # -- record of processing: one row per purpose
    by_table_services = {t: set(v["services"]) for t, v in tables.items()}
    ropa = []
    for pid, p in purposes.items():
        mine = [t for t in tables.values() if pid in t["purposes"]]
        svcs = sorted({s for t in mine for s in by_table_services[t["table"]]} | {s for s, v in services.items() if pid in v["purposes"]})
        ropa.append({"purpose": pid, "name": p["name"], "description": p.get("description", ""), "legal_basis": p.get("legal_basis"), "consent_type": p.get("consent_type"),
                     "principals": "Customers", "declared_categories": p.get("data_categories") or [],
                     "found_categories": sorted({c for t in mine for c in t["categories"]} - {"identifier"}),
                     "tables": [t["table"] for t in mine], "services": svcs,
                     "recipients": [{"name": x["name"], "role": x.get("role"), "country": x.get("country"), "dpa": x.get("dpa")} for x in procs if pid in (x.get("purposes") or [])],
                     "retention": [{"table": t["table"], "rules": [r["rule"] for r in t["retention"]]} for t in mine],
                     "safeguards": [s for s in [
                         "Public key blocked on every table" if mine and all(t["public"] in ("blocked", "protected") for t in mine) else
                         ("Public exposure: " + ", ".join(t["table"] for t in mine if t["public"] == "exposed")) if any(t["public"] == "exposed" for t in mine) else None,
                         "Dashboard access is deny-by-default (IAM policies)", "Personal data masked in application logs"] if s],
                     "gaps": [g["id"] for g in gaps if g.get("node") in [f"p:{pid}"] + [f"t:{t['table']}" for t in mine]]})
    orphan = [t["table"] for t in tables.values() if t["is_personal"] and not t["purposes"]]
    off = [f for f in flow_list if f["personal"] and not f["in_purpose"]]
    if orphan or off:
        ropa.append({"purpose": None, "name": "Not covered by a declared purpose", "description": "Personal data held or used without a purpose: see the gaps.",
                     "legal_basis": None, "consent_type": None, "principals": "Customers", "declared_categories": [],
                     "found_categories": sorted({c for t in orphan for c in tables[t]["categories"]} | {c for f in off for c in f["categories"]} - {"identifier"}),
                     "tables": sorted(set(orphan) | {f["table"] for f in off}), "services": sorted({f["service"] for f in off}), "recipients": [], "retention": [],
                     "safeguards": [], "gaps": [g["id"] for g in gaps if g["kind"] in ("no_purpose", "purpose_gap")]})

    sev = collections.Counter(g["severity"] for g in gaps)
    personal_tables = [t for t in tables.values() if t["is_personal"]]
    out = {"at": now_iso(), "by": actor, "seconds": round(time.time() - started, 1), "window_days": DATAMAP_WINDOW_DAYS, "since": since,
           "log_rows": log_rows, "truncated": truncated,
           "score": max(0, 100 - sum(GAP_WEIGHT[g["severity"]] for g in gaps)),
           "stats": {"tables": len(tables), "personal_tables": len(personal_tables), "personal_columns": sum(len(t["personal"]) for t in personal_tables),
                     "services": len(services), "personal_services": sum(1 for s in services.values() if s["personal_accesses"]),
                     "flows": len(flow_list), "personal_flows": sum(1 for f in flow_list if f["personal"]), "accesses": sum(f["count"] for f in flow_list),
                     "processors": len(procs), "principals": counts.get((policy.get("principal") or {}).get("table")),
                     "gaps": len(gaps), **{f"gaps_{k}": sev.get(k, 0) for k in SEV_ORDER}},
           "purposes": [{"id": pid, "name": p["name"], "legal_basis": p.get("legal_basis"), "consent_type": p.get("consent_type"),
                         "description": p.get("description", ""), "data_categories": p.get("data_categories") or []} for pid, p in purposes.items()],
           "tables": sorted(tables.values(), key=lambda t: (not t["is_personal"], -(t["accesses"] or 0), t["table"])),
           "services": sorted(services.values(), key=lambda s: (-s["personal_accesses"], s["service"])),
           "flows": flow_list, "processors": procs, "gaps": gaps, "ropa": ropa, "new_columns": new_cols,
           "config_rev": cfg.get("rev")}
    return out


_dm_live = {"ctx": None, "buckets": None, "watermark": None, "rows": 0, "truncated": False, "result": None, "ticks": 0}
_dm_live_lock = threading.Lock()
DM_CONTEXT_TTL = 300        # schema, row counts, registry and processors refresh every 5 minutes while live
DM_LIVE_PAGE_CAP = 20000    # new log rows read per live tick


def scan_datamap(actor, token):
    """Full rebuild: context plus every database-log row of the window. Saved, metered, audited, and
    the starting point for live updates."""
    started = time.time()
    since = (datetime.now(timezone.utc) - timedelta(days=DATAMAP_WINDOW_DAYS)).isoformat(timespec="seconds")
    try:
        pii_scan_columns(actor)                       # fresh fused verdicts for every column
        if _pii_logs["at"]:
            pii_scan_logs(token, force=True)          # incremental: only lines since the last scan
        else:
            threading.Thread(target=pii_scan_logs, args=(token, True), daemon=True).start()   # first 7-day read runs in the background
    except Exception as e:
        sys.stderr.write(f"[consent] PII detection failed, using names only: {e}\n")
    ctx = _dm_context(token)
    try:
        rows = _gr_pages("database_logs", [("select", "service,db_table,operation,data_category,personal_data,logged_at,ingested_at"), ("logged_at", f"gte.{since}"), ("order", "logged_at.asc,id.asc")], token)
    except Exception as e:
        rows = []
        sys.stderr.write(f"[consent] data map could not read database_logs: {e}\n")
    truncated = len(rows) >= DATAMAP_ROW_CAP
    buckets = {}
    _dm_bucket_rows(buckets, rows)
    watermark = max((r.get("ingested_at") or "" for r in rows), default="") or now_iso()
    out = _dm_compute(ctx, _dm_flows(buckets, ctx["tables"], since), actor, started, len(rows), truncated, since)
    out["live"] = {"at": out["at"], "new_rows": 0, "delta": [], "new_gaps": [], "closed_gaps": [], "base_at": out["at"], "watermark": watermark}
    with _dm_live_lock:
        _dm_live.update(ctx=ctx, buckets=buckets, watermark=watermark, rows=len(rows), truncated=truncated, result=out, ticks=0)
    with _datamap_lock:
        d = read_datamap()
        d["last"] = out
        d["history"] = (d.get("history") or [])[-29:] + [{"at": out["at"], "score": out["score"], "gaps": out["stats"]["gaps"],
                                                          "personal_tables": out["stats"]["personal_tables"], "personal_columns": out["stats"]["personal_columns"]}]
        write_tracked(DATAMAP_FILE, json.dumps(d, indent=1))
    meter(actor, "datamap.scans")
    st = out["stats"]
    audit(actor, "datamap.scan", f"score {out['score']}: {st['personal_tables']} personal tables, {st['flows']} flows, {st['gaps']} gap(s)")
    return out


def live_datamap(actor, token):
    """Live update: read only the database-log rows ingested since the last update, add them to the
    rolling buckets and recompute the map, gaps and record of processing in memory (no file write, so
    the evidence ledger isn't flooded). The context refreshes every DM_CONTEXT_TTL seconds or when the
    declarations change. Starts with a full scan if there is no live state yet."""
    with _dm_live_lock:
        ready = _dm_live["result"] is not None
    if not ready:
        return scan_datamap(actor, token)
    started = time.time()
    with _dm_live_lock:
        L = _dm_live
        cfg_rev = read_datamap()["config"].get("rev")
        if time.time() - L["ctx"]["built"] > DM_CONTEXT_TTL or L["ctx"]["cfg"].get("rev") != cfg_rev:
            L["ctx"] = _dm_context(token)
        new = []
        try:
            q = [("select", "service,db_table,operation,data_category,personal_data,logged_at,ingested_at"),
                 ("ingested_at", f"gt.{L['watermark']}"), ("order", "ingested_at.asc,id.asc")]
            while len(new) < DM_LIVE_PAGE_CAP:                  # one request when quiet; page on only while pages are full
                page = gr_get("database_logs", q + [("limit", "1000"), ("offset", str(len(new)))], token)
                new += page
                if len(page) < 1000:
                    break
        except Exception as e:
            sys.stderr.write(f"[consent] data map live read failed: {e}\n")
        before = {(f["service"], f["table"]): f["count"] for f in L["result"]["flows"]}
        old_gaps = {g["id"]: g for g in L["result"]["gaps"]}
        L["rows"] += _dm_bucket_rows(L["buckets"], new)
        if new:
            L["watermark"] = max(L["watermark"], max(r.get("ingested_at") or "" for r in new))
        since = (datetime.now(timezone.utc) - timedelta(days=DATAMAP_WINDOW_DAYS)).isoformat(timespec="seconds")
        out = _dm_compute(L["ctx"], _dm_flows(L["buckets"], L["ctx"]["tables"], since), actor, started, L["rows"], L["truncated"], since)
        out["at"], out["by"] = L["result"]["at"], L["result"]["by"]       # when the last full scan ran
        delta = collections.Counter()
        ops = collections.defaultdict(collections.Counter)
        for r in new:
            k = (r.get("service"), r.get("db_table"))
            if k[1] in L["ctx"]["tables"]:
                delta[k] += 1
                ops[k][(r.get("operation") or "ACCESS").upper()] += 1
        new_gaps = [{"id": g["id"], "severity": g["severity"], "title": g["title"]} for g in out["gaps"] if g["id"] not in old_gaps]
        closed = [{"id": i, "title": g["title"]} for i, g in old_gaps.items() if i not in {x["id"] for x in out["gaps"]}]
        out["live"] = {"at": now_iso(), "new_rows": len(new), "base_at": L["result"]["live"].get("base_at"), "watermark": L["watermark"],
                       "delta": [{"service": k[0], "table": k[1], "n": n, "ops": dict(ops[k]), "new_flow": k not in before} for k, n in delta.most_common(12)],
                       "new_gaps": new_gaps, "closed_gaps": closed, "seconds": round(time.time() - started, 2),
                       "context_age": round(time.time() - L["ctx"]["built"])}
        L["result"] = out
        L["ticks"] += 1
    if new_gaps:
        audit(actor, "datamap.gap", f"new: {'; '.join(g['title'] for g in new_gaps)[:250]}")
    return out


def datamap_view():
    d = read_datamap()
    with _dm_live_lock:
        live = _dm_live["result"]
    last = live if live and (not d.get("last") or live["live"]["at"] >= (d["last"].get("live") or {}).get("at", d["last"]["at"])) else d.get("last")
    return {"last": last, "history": d.get("history", [])[-30:], "config": d["config"]}

# ---------------------------------------------------------------- PII detection v2 (pii_engine.py, data/pii.json)
# Fused verdicts for every shop column: name and context, sampled values with checksums, links to
# people (declared or inferred from the values), a local language model for free text, and admin
# feedback. Up to PII_SAMPLE rows per table are read with the service key on a full scan; the values
# live only in memory while the column is scored, and only statistics and evidence are kept. The same
# validators (and the model) scan log messages for personal data the log masker missed.
import pii_engine

PII_FILE = DATA / "pii.json"
PII_SAMPLE = 200
PII_LOG_WINDOW_DAYS = 7
PII_LOG_REFRESH_S = 60
PII_NER_LOG_CAP = 600
_pii_lock = threading.Lock()
_pii_logs = {"watermark": {}, "leaks": {}, "masked_fp": {}, "masked_total": 0, "scanned": 0, "at": 0, "ner_used": False, "busy": False}


def read_pii():
    try:
        d = json.loads(PII_FILE.read_text()) if PII_FILE.exists() else {}
    except ValueError:
        d = {}
    d.setdefault("feedback", {})
    return d


def _fk_map():
    """Declared foreign keys from the API description, if the database has any."""
    out = {}
    try:
        spec = shop_get("/", accept_openapi=True)
        for t, d in (spec.get("definitions") or {}).items():
            for c, p in (d.get("properties") or {}).items():
                m = re.search(r"<fk table='([^']+)' column='([^']+)'", p.get("description") or "")
                if m:
                    out[(t, c)] = f"{m.group(1)}.{m.group(2)}"
    except Exception:
        pass
    return out


def pii_scan_columns(actor):
    """Sample every table, fuse the signals, keep verdicts and evidence (no values)."""
    started = time.time()
    schema = shop_schema()
    policy = read_doc("policy")
    principal = (policy.get("principal") or {}).get("table")
    feedback = read_pii().get("feedback", {})
    fks = _fk_map()
    def sample(t):
        try:
            return shop_get(f"/{urllib.parse.quote(t)}", {"select": "*", "limit": str(PII_SAMPLE)})
        except Exception:
            return []
    with ThreadPoolExecutor(max_workers=6) as ex:
        rows = dict(zip(schema, ex.map(sample, list(schema))))
    try:
        v1 = {(t, c): k[0] for t, cols in schema.items() for c, k in classify_columns(t, [x["name"] for x in cols])}
        # language model: one batch for every free-text or name-like column
        ner_jobs = []
        for t, cols in schema.items():
            for c in cols:
                nk = pii_engine.name_kind(c["name"])
                vals = [str(r.get(c["name"])) for r in rows[t] if isinstance(r.get(c["name"]), str) and r.get(c["name"]).strip()]
                if vals and (nk in ("free_text", "person_name") or (not nk and sum(len(v.split()) >= 4 for v in vals) >= max(2, len(vals) // 3))):
                    ner_jobs.append(((t, c["name"]), vals[:40]))
        flat = [v for _, vs in ner_jobs for v in vs]
        res = pii_engine.ner_names(flat) if flat else []
        ner_by, i = {}, 0
        for key, vs in ner_jobs:
            if res is not None:
                ner_by[key] = res[i:i + len(vs)]
            i += len(vs)
        # links: ids of tables about people, to infer links from the values when no foreign key is declared
        def ids_of(t):
            try:
                return {str(r.get("id")) for r in shop_get(f"/{urllib.parse.quote(t)}", {"select": "id", "limit": "5000"}) if r.get("id") is not None}
            except Exception:
                return set()
        # tables that ARE people (the principal, user / member / staff tables), the only targets links are inferred to
        person_tables = {principal} | {t for t in schema if re.fullmatch(r"(auth_)?(users?|members?|profiles?|employees?|staff|accounts?)", t)}
        id_sets = {t: ids_of(t) for t in person_tables if t in schema and any(c["name"] == "id" for c in schema[t])}
        def link_targets(col):
            base = col[:-3].lower().rstrip("_") if col.lower().endswith("_id") else ""
            if not base:
                return []
            out = []
            if re.search(r"(customer|buyer|recipient|member|profile|principal|client)$", base):
                out.append(principal)
            if re.search(r"user$", base):
                out += [t for t in id_sets if re.search(r"users?$", t)]
            out += [t for t in id_sets if base.endswith(t.rstrip("s")) and t not in out]
            return [t for t in out if t in id_sets]
        def score_all(person_set):
            out = {}
            for t, cols in schema.items():
                table_rows = rows[t]
                res_t = []
                for c in cols:
                    col = c["name"]
                    vals = [r.get(col) for r in table_rows]
                    fk = fks.get((t, col))
                    if not fk and col != "id":
                        # inferred link: the name points at a people table AND the values are its ids
                        nonnull = {str(v) for v in vals if v is not None}
                        for pt in link_targets(col):
                            ids = id_sets.get(pt) or set()
                            hit = len(nonnull & ids) / len(nonnull) if nonnull and ids else 0
                            if pt != t and hit >= 0.8:
                                orphans = len(nonnull - ids)
                                fk = (f"{pt}.id (inferred: the name points to {pt} and {round(100 * hit)}% of {len(nonnull)} distinct sampled values are existing {pt}.id"
                                      + (f"; {orphans} point to a {pt.rstrip('s')} that no longer exists" if orphans else "") + ")")
                                break
                    fk_person = bool(fk) and fk.split(".")[0] in person_tables
                    r = pii_engine.score_column(t, col, c.get("type") or "", vals, fk=fk if fk_person else None, person_table=t in person_set,
                                                v1=v1.get((t, col)), ner_counts=ner_by.get((t, col)), feedback=feedback.get(f"{t}.{col}"))
                    res_t.append(r)
                out[t] = res_t
            return out
        first = score_all(person_tables)
        strong = {"contact", "government ID", "address", "credentials"}
        person_set = set(person_tables) | {t for t, rs in first.items()
                                           if any(r["verdict"] in ("confirmed", "likely") and (r["category"] in strong or r["kind"] == "person_link") for r in rs)}
        final = score_all(person_set)
    finally:
        rows = None                                  # sampled values are dropped here
    cols_all = [r for rs in final.values() for r in rs]
    personal = [r for r in cols_all if r["verdict"] in ("confirmed", "likely")]
    hidden = [r for r in personal if any("hidden personal data" in e for e in r["evidence"])]
    dropped = [r for r in cols_all if r.get("v1") and r["verdict"] in ("not_personal", "possible")]
    fb = [r for r in cols_all if r.get("feedback")]
    out = {"at": now_iso(), "by": actor, "seconds": round(time.time() - started, 1), "sample": PII_SAMPLE,
           "model": pii_engine.ner.status(), "person_tables": sorted(person_set & set(schema)),
           "tables": {t: {"person_table": t in person_set, "columns": rs} for t, rs in final.items()},
           "stats": {"columns": len(cols_all), "personal": len(personal), "new_vs_v1": sum(1 for r in personal if not r.get("v1")), "confirmed": sum(r["verdict"] == "confirmed" for r in cols_all),
                     "likely": sum(r["verdict"] == "likely" for r in cols_all), "possible": sum(r["verdict"] == "possible" for r in cols_all),
                     "hidden": len(hidden), "dropped": len(dropped), "government_ids": sum(r["category"] == "government ID" and r in personal for r in cols_all),
                     "feedback": len(fb), "feedback_confirmed": sum(r["feedback"]["verdict"] != "not_personal" for r in fb),
                     "feedback_rejected": sum(r["feedback"]["verdict"] == "not_personal" for r in fb),
                     "v1_personal": len({(t, c) for (t, c) in v1})}}
    with _pii_lock:
        d = read_pii()
        d["columns"] = out
        write_tracked(PII_FILE, json.dumps(d, indent=1))
    meter(actor, "pii.scans")
    audit(actor, "pii.scan", f"{len(personal)} personal columns ({out['stats']['confirmed']} confirmed), {len(hidden)} hidden, {len(dropped)} v1 false positives")
    return out


def pii_columns():
    """table -> column -> verdict (from the last scan), or {} before the first scan."""
    cols = (read_pii().get("columns") or {}).get("tables") or {}
    return {t: {r["column"]: r for r in v["columns"]} for t, v in cols.items()}


def pii_personal_for(table, columns=None):
    """Fused personal columns of a table (confirmed / likely), or None when the table wasn't scanned."""
    m = pii_columns().get(table)
    if m is None:
        return None
    return [r for c, r in m.items() if r["verdict"] in ("confirmed", "likely") and (columns is None or c in columns)]


def pii_feedback(body, actor):
    t, c = str(body.get("table") or ""), str(body.get("column") or "")
    if not (IDENT.match(t) and IDENT.match(c)):
        raise ValueError("table and column are required")
    key = f"{t}.{c}"
    with _pii_lock:
        d = read_pii()
        if body.get("remove"):
            d["feedback"].pop(key, None)
            action = "cleared"
        else:
            v = body.get("verdict")
            if v not in ("personal", "not_personal"):
                raise ValueError("verdict must be personal or not_personal")
            kind = body.get("kind")
            if kind and kind not in pii_engine.KINDS:
                raise ValueError(f"unknown kind: {kind}")
            d["feedback"][key] = {"verdict": v, "kind": kind, "by": actor, "at": now_iso(), "note": str(body.get("note") or "")[:200]}
            action = v
        # re-score this column right away from the stored evidence: the verdict follows the feedback
        cols = (d.get("columns") or {}).get("tables", {}).get(t, {}).get("columns", [])
        for i, r in enumerate(cols):
            if r["column"] == c:
                fb = d["feedback"].get(key)
                auto = r.get("auto") or {k: r.get(k) for k in pii_engine.AUTO_FIELDS}
                base = {k: v for k, v in r.items() if k != "feedback"}
                base.update(auto)                                # start from the engine's own verdict
                auto_ev = list(r.get("auto_evidence") or [e for e in r.get("evidence", []) if not re.match(r"^(confirmed|marked not personal) by ", e)])
                base["evidence"] = list(auto_ev)
                if fb:
                    kind = fb.get("kind") or auto.get("kind") or "free_text"
                    if fb["verdict"] == "not_personal":
                        base.update(verdict="not_personal", confidence=100, kind=None, label=None, category=None, sensitivity=None)
                    else:
                        base.update(verdict="confirmed", confidence=100, kind=kind, label=pii_engine.KINDS[kind][0], category=pii_engine.KINDS[kind][1], sensitivity=pii_engine.KINDS[kind][2])
                    base["evidence"] = [f"{'confirmed' if fb['verdict'] != 'not_personal' else 'marked not personal'} by {actor}" + (f": {fb['note']}" if fb.get("note") else "")] + base["evidence"]
                    base["feedback"] = fb
                base["auto"], base["auto_evidence"] = auto, auto_ev
                cols[i] = base
        write_tracked(PII_FILE, json.dumps(d, indent=1))
    audit(actor, "pii.feedback", f"{key}: {action}")
    return d["feedback"].get(key) or {"cleared": True}


def _log_sources(token, since_iso, wm):
    out = []
    for table, sel in (("activity_logs", "id,logged_at,ingested_at,service,event,kind,level,message,details"),
                       ("database_logs", "id,logged_at,ingested_at,service,event,level,message,sql_template")):
        flt = ("ingested_at", f"gt.{wm[table]}") if wm.get(table) else ("logged_at", f"gte.{since_iso}")
        try:
            rows = _gr_pages(table, [("select", sel), flt, ("order", "ingested_at.asc,id.asc")], token, cap=60000)
        except Exception as e:
            sys.stderr.write(f"[consent] PII log scan could not read {table}: {e}\n")
            rows = []
        out.append((table, rows))
    return out


def pii_scan_logs(token, force=False):
    """Unmasked personal data in log lines, plus masked tokens that are false positives. Incremental:
    the first call reads PII_LOG_WINDOW_DAYS, later calls only lines ingested since."""
    L = _pii_logs
    with _pii_lock:
        if L["busy"] or (not force and time.time() - L["at"] < PII_LOG_REFRESH_S):
            return pii_logs_view()
        L["busy"] = True
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=PII_LOG_WINDOW_DAYS)).isoformat(timespec="seconds")
        ner_queue = []
        for table, rows in _log_sources(token, since, dict(L["watermark"])):
            for r in rows:
                L["scanned"] += 1
                if r.get("ingested_at"):
                    L["watermark"][table] = max(L["watermark"].get(table) or "", r["ingested_at"])
                msg = r.get("message") or ""
                text = msg
                if table == "activity_logs" and r.get("details"):
                    text += "\n" + json.dumps(r["details"], default=str)
                if table == "database_logs" and r.get("sql_template"):
                    text += "\n" + str(r["sql_template"])
                hits = pii_engine.scan_text(text)
                mv = pii_engine.masked_token_verdicts(msg)
                if mv:
                    L["masked_total"] += len(mv)
                    fps = [m for m in mv if m["false_positive"]]
                    if fps:
                        L["masked_fp"][r["id"]] = {"tokens": [m["token"] for m in fps], "service": r.get("service"), "why": fps[0]["why"]}
                if hits:
                    L["leaks"][r["id"]] = {"id": r["id"], "source": table, "logged_at": r.get("logged_at"), "service": r.get("service"), "event": r.get("event"),
                                           "kinds": sorted({h[0] for h in hits}), "spans": [{"kind": h[0], "start": h[1], "end": h[2], "why": h[3]} for h in hits if h[2] <= len(msg)],
                                           "in": "message" if any(h[2] <= len(msg) for h in hits) else ("details" if table == "activity_logs" else "sql")}
                elif table == "activity_logs" and msg and r.get("kind") in ("business", "error", "request", "privacy", "security") and not pii_engine.MASK_TOKEN.search(msg) \
                        and re.search(r"\b[A-Z][a-z]{2,}\b", msg) and len(ner_queue) < PII_NER_LOG_CAP:
                    ner_queue.append(r)
        if ner_queue:
            res = pii_engine.ner.analyse([r["message"] for r in ner_queue])
            if res is not None:
                L["ner_used"] = True
                for r, ents in zip(ner_queue, res):
                    names = [e for e in ents if e["type"] == "PERSON" and e["score"] >= 0.85]
                    names = [e for e in names if (lambda s: len(s) >= 3 and s.lower() not in pii_engine.NER_STOP and not re.search(r"[a-z][A-Z]|[_/\\{}=<>\[\]@\d]", s) and s[0].isupper())(r["message"][e["start"]:e["end"]])]
                    if names:
                        L["leaks"][r["id"]] = {"id": r["id"], "source": "activity_logs", "logged_at": r.get("logged_at"), "service": r.get("service"), "event": r.get("event"),
                                               "kinds": ["person_name"], "spans": [{"kind": "person_name", "start": e["start"], "end": e["end"], "why": f"language model: a person's name ({e['score']:.2f})"} for e in names],
                                               "in": "message"}
        cut = since
        for k in [k for k, v in L["leaks"].items() if (v.get("logged_at") or "") < cut]:
            del L["leaks"][k]
        L["at"] = time.time()
    finally:
        L["busy"] = False
    return pii_logs_view()


def pii_logs_view():
    L = _pii_logs
    leaks = list(L["leaks"].values())
    by_kind, by_service = collections.Counter(), collections.Counter()
    for x in leaks:
        by_service[x["service"]] += 1
        for k in x["kinds"]:
            by_kind[k] += 1
    return {"scanned": L["scanned"], "window_days": PII_LOG_WINDOW_DAYS, "at": datetime.fromtimestamp(L["at"], timezone.utc).isoformat(timespec="seconds") if L["at"] else None,
            "leaks": len(leaks), "by_kind": dict(by_kind), "by_service": dict(by_service), "ner_used": L["ner_used"],
            "masked_total": L["masked_total"], "masked_false_positives": sum(len(v["tokens"]) for v in L["masked_fp"].values()),
            "recent": sorted(leaks, key=lambda x: x.get("logged_at") or "", reverse=True)[:200],
            "kinds": {k: pii_engine.KINDS[k][0] for k in by_kind if k in pii_engine.KINDS}}


PII_ID = "PII"
PII_DETECTOR = {
    "id": PII_ID, "name": "Unmasked personal data in logs", "source": "activity_logs", "category": "confidentiality", "severity": "high",
    "why": "Log lines were stored with personal data the log masker didn't catch: validated emails, phone numbers, card or Aadhaar numbers "
           "(checksums pass), access tokens, or people's names found by the language model. Anyone who can read the logs can see them.",
    "steps": ["Open the log lines and check what was written", "Fix the service so it stops logging the value, or extend the masker",
              "Decide whether stored logs need purging; if the data was exposed, open an incident"],
    "ref": "DPDP Act 2023 · s.8(5) reasonable security safeguards · DPDP Rules Rule 6(1)(a)",
}


def pii_signals():
    """Breach signals: one per service and day with unmasked personal data in its logs."""
    groups = collections.defaultdict(list)
    for x in _pii_logs["leaks"].values():
        groups[(x["service"], (x.get("logged_at") or "")[:10])].append(x)
    out = []
    for (svc, day), xs in groups.items():
        kinds = sorted({k for x in xs for k in x["kinds"]})
        sev = "critical" if set(kinds) & {"card", "aadhaar", "jwt", "pan", "passport"} else "high"
        xs.sort(key=lambda x: x.get("logged_at") or "")
        out.append({"id": hashlib.sha1(f"{PII_ID}|{svc}|{day}".encode()).hexdigest()[:12], "detector": PII_ID, "source": "activity_logs", "group": svc,
                    "start": xs[0].get("logged_at"), "end": xs[-1].get("logged_at"), "events": len(xs), "total": len(xs), "peak": len(xs),
                    "services": [svc], "sample_ids": [x["id"] for x in xs[:20]], "severity": sev, "category": "confidentiality",
                    "reasons": [{"feature": k, "label": pii_engine.KINDS.get(k, (k,))[0], "count": sum(k in x["kinds"] for x in xs)} for k in kinds]})
    return out


def _pii_live_stats(cols):
    """The verdict counts as they are now (after admin answers), on top of the scan's own numbers."""
    rs = [r for tv in (cols.get("tables") or {}).values() for r in tv["columns"]]
    personal = [r for r in rs if r["verdict"] in ("confirmed", "likely")]
    fb = [r for r in rs if r.get("feedback")]
    return {**cols.get("stats", {}), "columns": len(rs), "personal": len(personal), "confirmed": sum(r["verdict"] == "confirmed" for r in rs),
            "likely": sum(r["verdict"] == "likely" for r in rs), "possible": sum(r["verdict"] == "possible" for r in rs),
            "new_vs_v1": sum(1 for r in personal if not r.get("v1")), "hidden": sum(1 for r in personal if any("hidden personal data" in e for e in r.get("auto_evidence") or r["evidence"])),
            "dropped": sum(1 for r in rs if r.get("v1") and r["verdict"] in ("not_personal", "possible")),
            "government_ids": sum(1 for r in personal if r["category"] == "government ID"), "feedback": len(fb),
            "feedback_confirmed": sum(1 for r in fb if r["feedback"]["verdict"] != "not_personal"),
            "feedback_rejected": sum(1 for r in fb if r["feedback"]["verdict"] == "not_personal"),
            # precision of the engine's own verdicts against the team's answers
            "feedback_agreed": sum(1 for r in fb if ((r.get("auto") or {}).get("verdict") in ("confirmed", "likely")) == (r["feedback"]["verdict"] != "not_personal"))}


def pii_view():
    d = read_pii()
    if d.get("columns"):
        d["columns"]["stats"] = _pii_live_stats(d["columns"])
    return {"columns": d.get("columns"), "feedback": d.get("feedback", {}), "logs": pii_logs_view(), "model": pii_engine.ner.status(),
            "kinds": {k: {"label": v[0], "category": v[1], "sensitivity": v[2]} for k, v in pii_engine.KINDS.items()}}


# ---------------------------------------------------------------- billing: invoices, GST, Razorpay (data/billing.json)
# The client pays the provider for this system by plan and usage. When a billing cycle closes, an
# invoice is issued from the meters (plan fee + overage + 18% GST: CGST/SGST within the seller's state,
# IGST otherwise). The client's admins pay each invoice with Razorpay Checkout into the provider's
# Razorpay account: the server creates the order (amount fixed here, the secret never leaves), checks
# the payment signature, then confirms the payment with Razorpay before marking the invoice paid.
# Unpaid invoices: reminders from the due date; after the grace period, Free-plan limits until paid.
# Seller details, billing rules and the plan catalogue are the provider's (provider.json); the
# provider's own actions (mark paid, void, refund, bill now, set plan) are server commands (see main()).
import hmac
import base64

RZP_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RZP_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
RZP_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()
GST_RATE = 18
BILLING_FILE = DATA / "billing.json"
GSTIN_RE = re.compile(r"^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")
STATES = {"01": "Jammu and Kashmir", "02": "Himachal Pradesh", "03": "Punjab", "04": "Chandigarh", "05": "Uttarakhand", "06": "Haryana",
          "07": "Delhi", "08": "Rajasthan", "09": "Uttar Pradesh", "10": "Bihar", "11": "Sikkim", "12": "Arunachal Pradesh", "13": "Nagaland",
          "14": "Manipur", "15": "Mizoram", "16": "Tripura", "17": "Meghalaya", "18": "Assam", "19": "West Bengal", "20": "Jharkhand",
          "21": "Odisha", "22": "Chhattisgarh", "23": "Madhya Pradesh", "24": "Gujarat", "26": "Dadra and Nagar Haveli and Daman and Diu",
          "27": "Maharashtra", "29": "Karnataka", "30": "Goa", "31": "Lakshadweep", "32": "Kerala", "33": "Tamil Nadu", "34": "Puducherry",
          "35": "Andaman and Nicobar Islands", "36": "Telangana", "37": "Andhra Pradesh", "38": "Ladakh"}
_billing_lock = threading.RLock()


def seller():
    p = provider()
    return {"legal_name": "", "address": "", "state": "", "gstin": "", "email": "", **p["seller"], **{k: p["billing"][k] for k in ("sac", "prefix", "due_days", "gst")}}


def grace_days():
    return int(provider()["billing"].get("grace_days", 14))


def _seller_ready():
    s = seller()
    if not s["legal_name"] or not s["state"] or (s["gst"] and not s["gstin"]):
        raise ValueError("Invoices can't be issued yet: the provider's seller details (legal name, state, GSTIN) are missing in provider.json.")


def read_billing():
    d = json.loads(BILLING_FILE.read_text()) if BILLING_FILE.exists() else {}
    for k, v in (("profile", {}), ("invoices", []), ("closed_cycles", []), ("invoice_seq", {}), ("orders", {})):
        d.setdefault(k, v)
    return d


def write_billing(d):
    DATA.mkdir(exist_ok=True)
    write_tracked(BILLING_FILE, json.dumps(d, indent=2))
    central_kick("billing")          # invoices and payments reach the provider within seconds


def save_billing_profile(body, actor):
    prof = {k: str(body.get(k) or "").strip()[:300 if k == "address" else 120] for k in ("legal_name", "address", "state", "gstin", "email")}
    prof["gstin"] = prof["gstin"].upper()
    if prof["state"] and prof["state"] not in STATES.values():
        raise ValueError("Pick the state from the list.")
    if prof["gstin"] and not GSTIN_RE.match(prof["gstin"]):
        raise ValueError("That GSTIN doesn't look right (15 characters, e.g. 29AAACR5055K1Z5).")
    if prof["gstin"] and prof["state"] and STATES.get(prof["gstin"][:2]) != prof["state"]:
        raise ValueError(f"The GSTIN starts with {prof['gstin'][:2]} ({STATES.get(prof['gstin'][:2], 'unknown')}), which doesn't match {prof['state']}.")
    if prof["email"] and not EMAIL_RE.match(prof["email"]):
        raise ValueError("Enter a valid invoice email.")
    with _billing_lock:
        b = read_billing()
        b["profile"] = prof
        write_billing(b)
    audit(actor, "billing.profile", f"{prof['legal_name']} · {prof['state']}")
    return prof


def _fy(at):
    a = at.astimezone(IST_TZ)
    y = a.year if a.month >= 4 else a.year - 1
    return f"{y % 100:02d}-{(y + 1) % 100:02d}"


def _money(x):
    return round(float(x) + 1e-9, 2)


def _tax(subtotal, buyer_state):
    s = seller()
    if not s["gst"]:
        return {"type": None, "rate": 0, "cgst": 0, "sgst": 0, "igst": 0, "total": 0}
    t = _money(subtotal * GST_RATE / 100)
    if not buyer_state or buyer_state == s["state"]:
        half = _money(t / 2)
        return {"type": "CGST+SGST", "rate": GST_RATE, "cgst": half, "sgst": _money(t - half), "igst": 0, "total": t}
    return {"type": "IGST", "rate": GST_RATE, "cgst": 0, "sgst": 0, "igst": t, "total": t}


def _make_invoice(kind, lines, period, actor, extra=None):
    """Append an invoice (numbered per financial year, e.g. DPDP/26-27/0001). Caller holds _billing_lock."""
    b = read_billing()
    now = datetime.now(timezone.utc)
    fy = _fy(now)
    b["invoice_seq"][fy] = b["invoice_seq"].get(fy, 0) + 1
    s, prof = seller(), b["profile"]
    sub = _money(sum(l["amount"] for l in lines))
    tax = _tax(sub, prof.get("state"))
    inv = {"id": f"inv_{uuid.uuid4().hex[:12]}", "number": f"{s['prefix']}/{fy}/{b['invoice_seq'][fy]:04d}", "kind": kind, "issued_at": now_iso(),
           "due_at": (now + timedelta(days=s["due_days"])).isoformat(timespec="seconds"), "status": "issued",
           "period_start": period[0], "period_end": period[1], "lines": lines, "subtotal": sub, "tax": tax, "total": _money(sub + tax["total"]),
           "currency": "INR", "seller": {k: s[k] for k in ("legal_name", "address", "state", "gstin", "sac", "email")},
           "buyer": {"name": prof.get("legal_name") or CLIENT_NAME, "address": prof.get("address", ""), "state": prof.get("state", ""),
                     "gstin": prof.get("gstin", ""), "email": prof.get("email") or ROOT_EMAIL},
           "place_of_supply": prof.get("state") or s["state"], "payments": [], "refunds": [], "attempts": [], "created_by": actor, **(extra or {})}
    b["invoices"].append(inv)
    write_billing(b)
    audit(actor, "billing.invoice", f"{inv['number']} {kind} ₹{inv['total']:,.2f}")
    return inv


def cycle_lines(start, end, billed_from=None):
    """Invoice lines for one cycle: the plan fee (pro-rated when billing began mid-cycle) and each
    meter's overage."""
    plan = read_plan()
    with _usage_lock:
        tot = _cycle_totals(_usage_doc(), plan, start, end)
    lines = []
    if plan["base_fee"]:
        frac = 1.0
        if billed_from and start < billed_from < end:
            frac = (end - billed_from).total_seconds() / (end - start).total_seconds()
        first = billed_from if billed_from and start < billed_from < end else start
        fee = _money(plan["base_fee"] * frac)
        lines.append({"desc": f"{plan['name']} plan, {first.strftime('%d %b')} – {(end - timedelta(days=1)).strftime('%d %b %Y')}"
                              + (f" ({round(frac * 100)}% of the month: billing started {first.strftime('%d %b')})" if frac < 1 else ""),
                      "qty": 1, "unit": "month", "rate": fee, "amount": fee})
    for k, pm in plan["meters"].items():
        inc, price = pm.get("included"), pm.get("overage") or 0
        used = seat_count() if METERS[k][2] == "gauge" else tot.get(k, 0)
        if inc is None or used <= inc or not price:
            continue
        blocks = math.ceil((used - inc) / METERS[k][4])
        unit = "" if METERS[k][4] == 1 else f" of {METERS[k][4]:,}"
        lines.append({"desc": f"{METERS[k][0]}: {used - inc:,} {METERS[k][1]} over the {inc:,} included", "qty": blocks,
                      "unit": f"block{unit}" if unit else METERS[k][1].rstrip("s"), "rate": _money(price), "amount": _money(blocks * price)})
    return lines


def bill_now(actor):
    """Provider command: invoice the current cycle's usage so far."""
    _seller_ready()
    plan = read_plan()
    start, end = cycle_bounds(plan)
    b = read_billing()
    lines = cycle_lines(start, end, _ts(b.get("started_at")))
    if not lines:
        raise ValueError("Nothing to bill: the plan has no fee and there's no overage so far.")
    with _billing_lock:
        return _make_invoice("interim", lines, (start.isoformat(), now_iso()), actor)


def billing_tick():
    """Runs on requests (at most every 30 s): close finished cycles into invoices, apply a scheduled
    plan change, and apply or lift the overdue limits."""
    with _billing_lock:
        b = read_billing()
        if not b.get("started_at"):            # billing starts the first time this runs
            b["started_at"] = now_iso()
            write_billing(b)
            return
        started = _ts(b["started_at"])
        plan = read_plan()
        start, _ = cycle_bounds(plan)
        prev_start, prev_end = cycle_bounds(plan, start - timedelta(seconds=1))
        key = prev_start.strftime("%Y-%m-%d")
        if key not in b["closed_cycles"] and prev_end > started:
            b["closed_cycles"].append(key)
            write_billing(b)
            lines = cycle_lines(prev_start, prev_end, started)
            if lines:
                try:
                    _seller_ready()
                    _make_invoice("cycle", lines, (max(prev_start, started).isoformat(), prev_end.isoformat()), "billing (cycle close)")
                except ValueError as e:
                    sys.stderr.write(f"[consent] cycle {key} not invoiced: {e}\n")
                    b = read_billing(); b["closed_cycles"].remove(key); write_billing(b)
            b = read_billing()
            if b.get("pending_plan"):           # a downgrade chosen last cycle starts now
                _apply_template(b.pop("pending_plan"), "billing (scheduled change)")
                write_billing(b)
        now = datetime.now(timezone.utc)
        overdue = [i for i in b["invoices"] if i["status"] == "issued" and _ts(i["due_at"]) + timedelta(days=grace_days()) < now]
        if overdue and not b.get("restricted_plan"):
            cur = read_plan()
            b["restricted_plan"] = cur
            free = _plan_from_template("free", "billing (overdue)")
            free.update(rev=cur.get("rev", 0) + 1, name=f"{cur['name']} (limited: overdue invoice)", user_caps=cur.get("user_caps", {}))
            write_plan(free)
            write_billing(b)
            audit("billing", "billing.restricted", f"{overdue[0]['number']} is {grace_days()}+ days overdue: Free-plan limits until paid")


def _restore_if_settled():
    b = read_billing()
    if b.get("restricted_plan") and not any(i["status"] == "issued" and _ts(i["due_at"]) + timedelta(days=grace_days()) < datetime.now(timezone.utc) for i in b["invoices"]):
        old = b.pop("restricted_plan")
        old["rev"] = read_plan().get("rev", 0) + 1
        write_plan(old)
        write_billing(b)
        audit("billing", "billing.restored", "Overdue invoices paid: the plan is restored")


def _apply_template(template, actor):
    cur = read_plan()
    new = _plan_from_template(template, actor)
    new.update(rev=cur.get("rev", 0) + 1, user_caps=cur.get("user_caps", {}), alert_at=cur.get("alert_at", [80, 100]), cycle_day=cur.get("cycle_day", 1))
    write_plan(new)
    audit(actor, "billing.plan", f"plan changed to {new['name']}")


def upgrade(body, actor, preview=False):
    """The client chooses another plan from the catalogue: a higher one now (pro-rated invoice; the
    plan starts when it's paid), a lower one from the next cycle."""
    t, cat = body.get("template"), plans()
    if t not in cat or t == "free":
        raise ValueError("Pick a paid plan.")
    plan = read_plan()
    start, end = cycle_bounds(plan)
    now = datetime.now(IST_TZ)
    left = max(0.0, (end - now).total_seconds() / (end - start).total_seconds())
    old_fee, new_fee = plan.get("base_fee", 0), cat[t]["base_fee"]
    if plan.get("template") == t:
        return {"kind": "current"} if preview else {"kind": "current", "error": "You're already on this plan."}
    diff = _money((new_fee - old_fee) * left)
    if new_fee < old_fee:
        if preview:
            return {"kind": "downgrade", "starts": end.isoformat(), "amount": 0}
        with _billing_lock:
            b = read_billing()
            b["pending_plan"] = t
            write_billing(b)
        audit(actor, "billing.downgrade", f"to {cat[t]['name']} from the next cycle ({end.strftime('%d %b')})")
        return {"kind": "downgrade", "starts": end.isoformat()}
    if not preview:
        _seller_ready()
    tax = _tax(diff, read_billing()["profile"].get("state"))
    if preview:
        return {"kind": "upgrade", "amount": diff, "total": _money(diff + tax["total"]), "fraction": round(left, 3), "ends": end.isoformat()}
    if diff <= 0:
        _apply_template(t, actor)
        return {"kind": "switched"}
    line = {"desc": f"Upgrade to {cat[t]['name']} for the rest of the cycle ({now.strftime('%d %b')} – {(end - timedelta(days=1)).strftime('%d %b %Y')}, "
                    f"{round(left * 100)}% of ₹{new_fee:,} minus ₹{old_fee:,} already billed)", "qty": 1, "unit": "pro-rated", "rate": diff, "amount": diff}
    with _billing_lock:
        return {"kind": "invoice", "invoice": _make_invoice("upgrade", [line], (now.isoformat(timespec="seconds"), end.isoformat()), actor, {"upgrade_to": t})}


# ---- Razorpay REST (no SDK)
def rzp(method, path, body=None):
    if not (RZP_KEY_ID and RZP_SECRET):
        raise ValueError("Online payment isn't set up: add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env.")
    req = urllib.request.Request(f"https://api.razorpay.com/v1{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Basic " + base64.b64encode(f"{RZP_KEY_ID}:{RZP_SECRET}".encode()).decode(),
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read() or b"{}").get("error", {}).get("description")
        except ValueError:
            msg = None
        raise ValueError(f"Razorpay: {msg or f'HTTP {e.code}'}")


def _find_invoice(b, ref):
    """By id (inv_…) or number (DPDP/26-27/0001)."""
    inv = next((i for i in b["invoices"] if ref in (i["id"], i["number"])), None)
    if not inv:
        raise ValueError(f"No invoice {ref}.")
    return inv


def start_payment(iid, actor):
    with _billing_lock:
        b = read_billing()
        inv = _find_invoice(b, iid)
        if inv["status"] != "issued":
            raise ValueError(f"This invoice is {inv['status']}.")
        amount = int(round(inv["total"] * 100))
        if not inv.get("rzp_order") or inv.get("rzp_amount") != amount:
            order = rzp("POST", "/orders", {"amount": amount, "currency": "INR", "receipt": inv["number"][:40],
                                            "notes": {"client": CLIENT_ID, "invoice": inv["id"], "number": inv["number"]}})
            inv["rzp_order"], inv["rzp_amount"] = order["id"], amount
            b["orders"][order["id"]] = inv["id"]
            write_billing(b)
    audit(actor, "billing.checkout", f"{inv['number']} ₹{inv['total']:,.2f}")
    return {"key": RZP_KEY_ID, "order_id": inv["rzp_order"], "amount": amount, "currency": "INR", "name": seller()["legal_name"] or "Compliance monitoring",
            "description": f"Invoice {inv['number']}", "prefill": {"email": inv["buyer"]["email"], "name": inv["buyer"]["name"]},
            "notes": {"invoice": inv["number"], "client": CLIENT_NAME}}


def _mark_paid(inv, payment, via, actor):
    """Shared by checkout verification, the webhook and the provider command. Idempotent per payment id."""
    if any(p["id"] == payment["id"] for p in inv["payments"]):
        return False
    inv["payments"].append({"id": payment["id"], "amount": payment["amount"], "method": payment.get("method", ""), "at": now_iso(), "via": via})
    inv["status"] = "paid"
    inv["paid_at"] = now_iso()
    audit(actor, "billing.paid", f"{inv['number']} ₹{inv['total']:,.2f} via {via} ({payment['id']})")
    return True


def _after_paid(inv):
    _restore_if_settled()   # first lift an overdue restriction, then apply a paid upgrade on top
    if inv.get("upgrade_to"):
        _apply_template(inv["upgrade_to"], "billing (upgrade paid)")


def verify_payment(body, actor):
    oid, pid, sig = (str(body.get(k) or "") for k in ("razorpay_order_id", "razorpay_payment_id", "razorpay_signature"))
    if not (oid and pid and sig):
        raise ValueError("Payment details are missing.")
    expected = hmac.new(RZP_SECRET.encode(), f"{oid}|{pid}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        audit(actor, "billing.verify_failed", f"bad signature for order {oid}")
        raise PermissionError("The payment signature doesn't match. Nothing was recorded.")
    with _billing_lock:
        b = read_billing()
        inv = next((i for i in b["invoices"] if i.get("rzp_order") == oid), None)
        if not inv:
            raise ValueError("No invoice matches that payment.")
        pay = rzp("GET", f"/payments/{pid}")
        if pay.get("order_id") != oid or int(pay.get("amount", 0)) != inv["rzp_amount"]:
            raise PermissionError("The payment doesn't match the invoice amount. Nothing was recorded.")
        if pay.get("status") == "authorized":
            pay = rzp("POST", f"/payments/{pid}/capture", {"amount": inv["rzp_amount"], "currency": "INR"})
        if pay.get("status") != "captured":
            inv["attempts"].append({"payment": pid, "status": pay.get("status"), "at": now_iso()})
            write_billing(b)
            raise ValueError(f"The payment is {pay.get('status')}, not completed.")
        new = _mark_paid(inv, {"id": pid, "amount": pay["amount"] / 100, "method": pay.get("method")}, "Razorpay Checkout", actor)
        write_billing(b)
    if new:
        _after_paid(inv)
    return inv


def webhook(handler, raw):
    """Razorpay events (payment.captured, payment.failed, refund.processed), verified with the webhook secret."""
    if not RZP_WEBHOOK_SECRET:
        return handler.send(503, {"error": "RAZORPAY_WEBHOOK_SECRET isn't set."})
    sig = handler.headers.get("X-Razorpay-Signature", "")
    if not hmac.compare_digest(hmac.new(RZP_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest(), sig):
        return handler.send(400, {"error": "bad signature"})
    ev = json.loads(raw or b"{}")
    kind, payload = ev.get("event", ""), ev.get("payload") or {}
    pay = (payload.get("payment") or {}).get("entity") or {}
    refund = (payload.get("refund") or {}).get("entity") or {}
    new = False
    with _billing_lock:
        b = read_billing()
        iid = b["orders"].get(pay.get("order_id") or "")
        if not iid:
            return handler.send(200, {"ok": True, "ignored": "unknown order"})
        inv = _find_invoice(b, iid)
        if kind == "payment.captured" and int(pay.get("amount", 0)) == inv.get("rzp_amount"):
            new = _mark_paid(inv, {"id": pay["id"], "amount": pay["amount"] / 100, "method": pay.get("method")}, "Razorpay webhook", "razorpay")
        elif kind == "payment.failed":
            inv["attempts"].append({"payment": pay.get("id"), "status": "failed", "reason": (pay.get("error_description") or "")[:200], "at": now_iso()})
            audit("razorpay", "billing.payment_failed", f"{inv['number']}: {pay.get('error_description') or 'failed'}")
        elif kind == "refund.processed" and not any(r.get("id") == refund.get("id") for r in inv["refunds"]):
            inv["refunds"].append({"id": refund.get("id"), "amount": refund.get("amount", 0) / 100, "status": "processed", "at": now_iso()})
            inv["status"] = "refunded"
            audit("razorpay", "billing.refund", f"{inv['number']} ({refund.get('id')})")
        write_billing(b)
    if new:
        _after_paid(inv)
    return handler.send(200, {"ok": True})


def invoice_action(ref, act, reference="", actor="provider"):
    """Provider commands on one invoice: mark_paid (bank transfer), void, refund (through Razorpay)."""
    with _billing_lock:
        b = read_billing()
        inv = _find_invoice(b, ref)
        new = False
        if act == "mark_paid":
            if inv["status"] != "issued":
                raise ValueError(f"This invoice is {inv['status']}.")
            if not reference.strip():
                raise ValueError("Give the bank transfer or cheque reference.")
            new = _mark_paid(inv, {"id": f"manual:{reference.strip()[:80]}", "amount": inv["total"], "method": "bank transfer"}, "recorded by the provider", actor)
        elif act == "void":
            if inv["status"] != "issued":
                raise ValueError("Only unpaid invoices can be voided.")
            inv["status"], inv["voided_at"] = "void", now_iso()
            audit(actor, "billing.void", inv["number"])
        elif act == "refund":
            pay = next((p for p in inv["payments"] if not p["id"].startswith("manual:")), None)
            if inv["status"] != "paid" or not pay:
                raise ValueError("Only invoices paid through Razorpay can be refunded this way.")
            if inv["refunds"]:
                raise ValueError("This invoice has already been refunded.")
            r = rzp("POST", f"/payments/{pay['id']}/refund", {"notes": {"invoice": inv["number"]}})
            inv["refunds"].append({"id": r.get("id"), "amount": r.get("amount", 0) / 100, "status": r.get("status"), "at": now_iso()})
            inv["status"] = "refunded"
            audit(actor, "billing.refund", f"{inv['number']} ({r.get('id')})")
        else:
            raise ValueError("unknown action")
        write_billing(b)
    if new:
        _after_paid(inv)
    return inv


def billing_view(user):
    billing_tick()
    b, plan, cat = read_billing(), read_plan(), plans()
    options = {}
    for t, tp in cat.items():
        if t == "free":
            continue
        try:
            options[t] = {"name": tp["name"], "base_fee": tp["base_fee"], **upgrade({"template": t}, user, preview=True)}
        except ValueError:
            pass
    now = datetime.now(timezone.utc)
    for i in b["invoices"]:
        i["overdue"] = i["status"] == "issued" and _ts(i["due_at"]) < now
    s = seller()
    return {"profile": b["profile"], "invoices": sorted(b["invoices"], key=lambda i: i["issued_at"], reverse=True), "states": sorted(STATES.values()),
            "plan": {"name": plan["name"], "template": plan.get("template"), "base_fee": plan["base_fee"]}, "pending_plan": b.get("pending_plan"),
            "restricted": bool(b.get("restricted_plan")), "upgrades": options, "online_payment": bool(RZP_KEY_ID and RZP_SECRET),
            "test_mode": RZP_KEY_ID.startswith("rzp_test_"), "seller": {k: s[k] for k in ("legal_name", "state", "gstin")}, "gst": s["gst"],
            "grace_days": grace_days(), "can_pay": allowed(user, "billing:PayInvoices"), "can_profile": allowed(user, "billing:ManageBillingProfile"),
            "can_change_plan": allowed(user, "usage:ManagePlan")}


def billing_flags():
    """Unpaid / overdue / restricted state for the banner."""
    b = read_billing()
    now = datetime.now(timezone.utc)
    due = [i for i in b["invoices"] if i["status"] == "issued"]
    late = [i for i in due if _ts(i["due_at"]) < now]
    return {"unpaid": len(due), "overdue": len(late), "restricted": bool(b.get("restricted_plan")),
            "limit_on": min((_ts(i["due_at"]) + timedelta(days=grace_days())).isoformat() for i in late) if late else None,
            "amount_due": _money(sum(i["total"] for i in due))}


# ---------------------------------------------------------------- reporting to the provider's central system
# Every copy reports to the provider's own Supabase project (the provider console) through
# public.report_in() with this copy's client key: plan, usage meters, invoices, and health scores.
# Counts, amounts and scores only, never personal data, log contents or customer records. Off unless
# CENTRAL_URL, CENTRAL_ANON_KEY and CENTRAL_CLIENT_KEY are set. A failed report never affects the
# copy; it's retried on the next interval.
APP_VERSION = "2026.10.19"
CENTRAL_URL = os.getenv("CENTRAL_URL", "").rstrip("/")
CENTRAL_ANON = os.getenv("CENTRAL_ANON_KEY", "")
CENTRAL_KEY = os.getenv("CENTRAL_CLIENT_KEY", "")
CENTRAL_MINUTES = max(1, int(os.getenv("CENTRAL_REPORT_MINUTES", "15") or 15))
_central = {"last_ok": None, "last_try": None, "last_error": None, "sent": 0, "kind": None}
_central_wake = threading.Event()
_central_why = ["startup"]


def central_configured():
    return bool(CENTRAL_URL and CENTRAL_ANON and CENTRAL_KEY)


def central_kick(why="event"):
    if central_configured():
        _central_why[0] = why
        _central_wake.set()


def central_report(kind="periodic"):
    """The report: plan, usage this cycle and per day, invoices, health, services. No personal data."""
    plan = read_plan()
    start, end = cycle_bounds(plan)
    keep = (datetime.now(IST_TZ) - timedelta(days=35)).strftime("%Y-%m-%d")
    with _usage_lock:
        doc = _usage_doc()
        cycle = _cycle_totals(doc, plan, start, end)
        days = {}
        for day, users in doc["days"].items():
            if day >= keep:
                tot = {}
                for ms in users.values():
                    for k, v in ms.items():
                        tot[k] = tot.get(k, 0) + v
                days[day] = tot
    b = read_billing()
    invoices = [{"id": i["id"], "number": i["number"], "kind": i.get("kind"), "status": i["status"], "issued_at": i.get("issued_at"), "due_at": i.get("due_at"),
                 "paid_at": i.get("paid_at"), "period_start": i.get("period_start"), "period_end": i.get("period_end"), "subtotal": i.get("subtotal", 0),
                 "tax": (i.get("tax") or {}).get("total", 0), "total": i.get("total", 0), "currency": i.get("currency", "INR"),
                 "lines": [{"desc": l.get("desc"), "amount": l.get("amount")} for l in i.get("lines", [])]} for i in b["invoices"][-200:]]
    rd = (read_readiness() or [None])[-1] or {}
    ex = read_exposure().get("last") or {}
    with _dm_live_lock:
        dm = _dm_live["result"]
    dm = dm or (read_datamap().get("last") or {})
    try:
        ig = json.loads(INTEGRITY_FILE.read_text()) if INTEGRITY_FILE.exists() else {}
    except ValueError:
        ig = {}
    reg, clocks, now = read_incidents(), read_doc("breach").get("clocks") or {}, datetime.now(timezone.utc)
    open_inc = [i for i in reg.get("incidents", []) if i.get("status") not in ("closed", "not_breach")]
    overdue = 0
    for i in open_inc:
        aware = _ts(i.get("aware_at"))
        for ob, hours in (("board_initial", "board_initial_hours"), ("principals", "principals_hours"), ("board_report", "board_report_hours")):
            if aware and not (i.get("obligations") or {}).get(ob) and now > aware + timedelta(hours=clocks.get(hours, 72)):
                overdue += 1
                break
    flags = billing_flags()
    exc = ex.get("counts") or {}
    dms = dm.get("stats") or {}
    return {"kind": kind, "version": APP_VERSION, "reported_at": now_iso(), "client": {"id": CLIENT_ID, "name": CLIENT_NAME},
            "plan": {"name": plan.get("name"), "template": plan.get("template"), "base_fee": plan.get("base_fee"), "currency": plan.get("currency", "INR"),
                     "cycle_day": plan.get("cycle_day", 1),
                     "meters": {k: {"included": m.get("included"), "overage": m.get("overage"), "label": METERS.get(k, (k,))[0]} for k, m in plan.get("meters", {}).items()}},
            "usage": {"cycle_start": start.isoformat(), "cycle_end": end.isoformat(), "cycle": cycle, "seats": seat_count(), "days": days},
            "billing": {"invoices": invoices, "restricted": flags["restricted"], "unpaid": flags["unpaid"], "overdue": flags["overdue"],
                        "amount_due": flags["amount_due"], "pending_plan": b.get("pending_plan")},
            "health": {"readiness": {"score": rd.get("score"), "grade": rd.get("grade"), "at": rd.get("at"), "areas": {a.get("key"): a.get("score") for a in rd.get("areas", [])}},
                       "exposure": {"score": ex.get("score"), "at": ex.get("at"), "tables": exc.get("tables"), "personal": exc.get("personal")},
                       "datamap": {"score": dm.get("score"), "at": (dm.get("live") or {}).get("at") or dm.get("at"), "gaps": dms.get("gaps"),
                                   "critical": dms.get("gaps_critical"), "high": dms.get("gaps_high")},
                       "integrity": {"ok": ig.get("ok"), "checked_at": ig.get("checked_at"), "problem_count": ig.get("problem_count")},
                       "breach": {"open": len(open_inc), "overdue": overdue}},
            "services": {"uptime_s": int(time.time() - _started_epoch), "shop": bool(SHOP_URL and SHOP_KEY), "logs": bool(AUTH_URL),
                         "ai": {"configured": bool(AI_KEY), "provider": "Groq" if "groq" in AI_BASE else "xAI"},
                         "payments": {"online": bool(RZP_KEY_ID and RZP_SECRET), "test_mode": RZP_KEY_ID.startswith("rzp_test_")}}}


def central_send(kind="periodic"):
    _central["last_try"] = now_iso()
    try:
        body = json.dumps({"p_client": CLIENT_ID, "p_key": CENTRAL_KEY, "p_payload": central_report(kind)}, default=str).encode()
        req = urllib.request.Request(f"{CENTRAL_URL}/rest/v1/rpc/report_in", data=body, method="POST",
                                     headers={"apikey": CENTRAL_ANON, "Authorization": f"Bearer {CENTRAL_ANON}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            json.load(r)
        _central.update(last_ok=now_iso(), last_error=None, sent=_central["sent"] + 1, kind=kind)
        return True
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")[:200]
        _central["last_error"] = "The provider rejected this copy's key" if e.code in (401, 403) or "not authorised" in msg else f"HTTP {e.code}: {msg}"
    except Exception as e:
        _central["last_error"] = str(e)[:200]
    sys.stderr.write(f"[consent] report to the provider failed: {_central['last_error']}\n")
    return False


def _central_loop():
    time.sleep(15)                       # let the service settle, then report once at startup
    kind = "startup"
    while True:
        central_send(kind)
        fired = _central_wake.wait(CENTRAL_MINUTES * 60)
        _central_wake.clear()
        if fired:
            time.sleep(5)                # batch a burst of billing writes into one report
            _central_wake.clear()
        kind = _central_why[0] if fired else "periodic"
        _central_why[0] = "event"


def central_status():
    return {"configured": central_configured(), "every_minutes": CENTRAL_MINUTES, **_central}


BILL_PAY_ROUTE = re.compile(r"/api/billing/invoices/(inv_[0-9a-f]{12})/pay")


_tick_at = [0.0]
_started_epoch = time.time()
_started_at = now_iso()

# Route -> required action(s). A tuple means any one of them is enough. None: any signed-in user.
STORE_ACTIONS = {"policy": ("consent:ReadFindings", "consent:EditPolicy", "consent:RestorePolicyVersion"),
                 "retention-policy": ("retention:ReadSchedule", "retention:EditSchedule", "retention:RestoreScheduleVersion"),
                 "breach-policy": ("breach:ReadSignals", "breach:EditDetectors", "breach:RestoreDetectorsVersion")}
ROUTE_ACTIONS = [
    ("GET", r"/api/(me|audit|ai/status|iam/catalog)", None),
    ("GET", r"/api/iam", ("iam:ListUsers", "iam:ListPolicies")),
    ("POST", r"/api/iam/validate", ("iam:ListPolicies", "iam:ManagePolicies")),
    ("POST", r"/api/iam/simulate", "iam:SimulatePolicy"),
    ("POST", r"/api/iam/users", "iam:ManageUsers"),
    ("PUT|DELETE", r"/api/iam/users/[0-9a-f-]{36}", "iam:ManageUsers"),
    ("PUT", r"/api/iam/users/[0-9a-f-]{36}/access", "iam:AttachPolicies"),
    ("POST", r"/api/iam/policies", "iam:ManagePolicies"),
    ("PUT|DELETE", r"/api/iam/policies/pol-\d+", "iam:ManagePolicies"),
    ("POST", r"/api/iam/policies/pol-\d+/restore/\d+", "iam:ManagePolicies"),
    ("POST", r"/api/iam/groups", "iam:ManageGroups"),
    ("PUT|DELETE", r"/api/iam/groups/grp-\d+", "iam:ManageGroups"),
    ("GET", r"/api/system", "system:ReadStatus"),
    ("GET", r"/api/usage", ("usage:ViewOwnUsage", "usage:ViewAllUsage")),
    ("GET", r"/api/billing", "billing:ViewInvoices"),
    ("PUT", r"/api/billing/profile", "billing:ManageBillingProfile"),
    ("POST", r"/api/billing/upgrade", "usage:ManagePlan"),
    ("POST", r"/api/billing/invoices/inv_[0-9a-f]{12}/pay|/api/billing/verify", "billing:PayInvoices"),
    ("GET", r"/api/readiness", ("readiness:Read", "readiness:Run")),
    ("POST", r"/api/readiness", "readiness:Run"),
    ("GET", r"/api/readiness/exposure", ("readiness:Read", "readiness:Run")),
    ("POST", r"/api/readiness/exposure", "readiness:Run"),
    ("GET", r"/api/evidence", ("readiness:VerifyIntegrity", "readiness:Read")),
    ("GET", r"/api/datamap", ("datamap:Read", "readiness:Read")),
    ("GET", r"/api/pii", ("datamap:Read", "telemetry:ReadLogs", "readiness:Read")),
    ("POST", r"/api/pii/scan", "datamap:Scan"),
    ("POST", r"/api/pii/logs", ("telemetry:ReadLogs", "datamap:Read")),
    ("PUT", r"/api/pii/feedback", "datamap:Edit"),
    ("POST", r"/api/datamap/scan", "datamap:Scan"),
    ("POST", r"/api/datamap/live", ("datamap:Read", "datamap:Scan")),
    ("PUT", r"/api/datamap/config", "datamap:Edit"),
    ("POST", r"/api/evidence/verify", "readiness:VerifyIntegrity"),
    ("POST", r"/api/evidence/check", "readiness:VerifyIntegrity"),
    ("POST", r"/api/evidence/pack", "readiness:ExportEvidence"),
    ("PUT", r"/api/usage/plan", "usage:ManagePlan"),
    ("GET", r"/api/customers/lookup", "consent:LookupCustomer"),
    ("GET", r"/api/schema", ("consent:ReadFindings", "retention:ReadSchedule")),
    ("GET", r"/api/table/\w+", ("consent:ReadFindings", "retention:ReadSchedule")),
    ("GET", r"/api/query/\w+", "retention:ReadSchedule"),
    ("GET", r"/api/retention/(erasure|inactivity)", "retention:ReadSchedule"),
    ("POST", r"/api/ai/chat", "ai:Ask"),
    ("GET", r"/api/breach/scan|/api/incidents(/BR-[\w-]+)?", "breach:ReadSignals"),
    ("POST", r"/api/breach/preview", "breach:ReadSignals"),
    ("GET", r"/api/breach/model", "breach:ReadSignals"),
    ("POST", r"/api/breach/model/retrain", "breach:ReadSignals"),
    ("POST", r"/api/breach/signals/\w+/\w+", "breach:TriageSignal"),
    ("POST", r"/api/incidents", "breach:CreateIncident"),
    ("PUT", r"/api/incidents/BR-[\w-]+", "breach:UpdateIncident"),
]


def required_action(method, path):
    m = STORE_ROUTE.fullmatch(path)
    if m:
        read, write, restore = STORE_ACTIONS[m.group(1)]
        return restore if m.group(4) else write if method == "PUT" else read
    for meth, rx, act in ROUTE_ACTIONS:
        if method in meth.split("|") and re.fullmatch(rx, path):
            return act
    return "deny:unknown-route"


IAM_USER_ROUTE = re.compile(r"/api/iam/users/([0-9a-f-]{36})(/access)?")
IAM_POLICY_ROUTE = re.compile(r"/api/iam/policies/(pol-\d+)(?:/restore/(\d+))?")
IAM_GROUP_ROUTE = re.compile(r"/api/iam/groups/(grp-\d+)")


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "ConsentService/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[consent] %s %s\n" % (self.address_string(), fmt % args))

    def cors(self):
        origin = self.headers.get("Origin")
        if origin in ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")

    def send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def body(self, limit=1_000_000):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def guard(self, *_):
        """Authenticate, then authorise the route's action (see ROUTE_ACTIONS): deny unless allowed."""
        user = verify_user(self.headers.get("Authorization"))
        if not user:
            self.send(401, {"error": "Sign in to the dashboard first."})
            return None
        path = urllib.parse.urlparse(self.path).path
        need = required_action(self.command, path)
        if time.time() - _tick_at[0] > 30:     # close finished billing cycles, apply overdue limits
            _tick_at[0] = time.time()
            try:
                billing_tick()
            except Exception as e:
                sys.stderr.write(f"[consent] billing check failed: {e}\n")
        if need is None:
            return user
        acts = (need,) if isinstance(need, str) else need
        if not any(allowed(user, a) for a in acts if not a.startswith("deny:")):
            d = decide(user, acts[0])
            why = f'explicitly denied by policy "{d[1]}"' + (f" (statement {d[2]})" if d[2] else "") if d[0] == "deny" else "not allowed by any policy attached to you"
            audit(user, "access.denied", f"{' or '.join(acts)}: {why}")
            self.send(403, {"error": f"Access denied: {' or '.join(acts)} is {why}. Ask the root user for access.", "action": acts[0], "decision": d[0]})
            return None
        touch(user, acts[0])
        meter(user, "api.requests")
        return user

    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        if path.path == "/api/health":
            return self.send(200, {"ok": True, "shop_configured": bool(SHOP_URL and SHOP_KEY)})
        if path.path == "/api/billing":
            return self.billing("GET", path.path)
        user = self.guard()
        if not user:
            return
        try:
            if path.path == "/api/readiness":
                return self.send(200, {"history": read_readiness()[-20:]})
            if path.path == "/api/readiness/exposure":
                return self.send(200, exposure_view())
            if path.path == "/api/evidence":
                return self.send(200, evidence_view(self.token()))
            if path.path == "/api/datamap":
                return self.send(200, datamap_view())
            if path.path == "/api/pii":
                return self.send(200, pii_view())
            if path.path == "/api/me":
                eff = effective(user)
                return self.send(200, {"email": user, "root": user == ROOT_EMAIL, "allowed": [a for a, d in eff.items() if d == "allow"],
                                       "client": {"name": CLIENT_NAME, "id": CLIENT_ID},
                                       "billing": billing_flags() if eff.get("billing:ViewInvoices") == "allow" else None,
                                       "policies": [read_iam()["policies"][pid]["name"] for pid, _ in policies_for(user)],
                                       "ai_left": remaining(user, "ai.questions"),
                                       "usage_alerts": usage_alerts_for(user) if eff.get("usage:ViewAllUsage") == "allow" or eff.get("usage:ViewOwnUsage") == "allow" else []})
            if path.path == "/api/iam/catalog":
                return self.send(200, {"actions": ALL_ACTIONS, "services": {k: v[0] for k, v in SERVICES.items()}})
            if path.path == "/api/iam":
                return self.send(200, iam_state(user))
            if path.path == "/api/audit":
                q = urllib.parse.parse_qs(path.query)
                everyone = (q.get("scope") or ["me"])[0] == "all" and allowed(user, "iam:ReadAllActivity")
                who = (q.get("user") or [""])[0].lower()
                target = who if who and allowed(user, "iam:ReadAllActivity") else (None if everyone else user)
                return self.send(200, {"events": read_audit(target, min(500, int((q.get("limit") or ["300"])[0]))), "scope": "all" if everyone else "me"})
            if path.path == "/api/system":
                return self.send(200, system_status())
            if path.path == "/api/usage":
                scope = (urllib.parse.parse_qs(path.query).get("scope") or ["me"])[0]
                if scope == "all" and not allowed(user, "usage:ViewAllUsage"):
                    audit(user, "access.denied", "usage:ViewAllUsage: not allowed by any policy attached to you")
                    return self.send(403, {"error": "Access denied: usage:ViewAllUsage is not allowed by any policy attached to you."})
                if scope == "me" and not allowed(user, "usage:ViewOwnUsage") and not allowed(user, "usage:ViewAllUsage"):
                    return self.send(403, {"error": "Access denied: usage:ViewOwnUsage is not allowed by any policy attached to you."})
                return self.send(200, usage_report(user, "all" if scope == "all" else "me"))
            if path.path == "/api/customers/lookup":
                q = urllib.parse.parse_qs(path.query).get("q", [""])[0]
                blocked = quota_block(user, "lookups")
                if blocked:
                    audit(user, "usage.blocked", blocked)
                    return self.send(429, {"error": blocked, "meter": "lookups"})
                kind, ids = lookup_customers(q)
                meter(user, "lookups")
                # Audit trail without the personal data itself.
                sys.stderr.write(f"[consent] lookup by {user}: {kind} -> {len(ids)} match(es)\n")
                audit(user, "customer.lookup", f"by {kind}: {len(ids)} match(es)")
                return self.send(200, {"kind": kind, "ids": [str(i) for i in ids]})
            if path.path == "/api/schema":
                return self.send(200, {"tables": shop_schema(), "blocked_columns": sorted(BLOCKED_COLUMNS)})
            m = re.fullmatch(r"/api/table/([A-Za-z0-9_]+)", path.path)
            if m:
                q = urllib.parse.parse_qs(path.query)
                cols = [c for c in (q.get("columns", ["*"])[0]).split(",") if c]
                if cols != ["*"] and not all(IDENT.match(c) for c in cols):
                    return self.send(400, {"error": "invalid column name"})
                return self.send(200, shop_rows(m.group(1), cols))
            m = re.fullmatch(r"/api/query/([A-Za-z0-9_]+)", path.path)
            if m:
                q = urllib.parse.parse_qs(path.query)
                cols = [c for c in (q.get("columns", ["*"])[0]).split(",") if c]
                if cols != ["*"] and not all(IDENT.match(c) for c in cols):
                    return self.send(400, {"error": "invalid column name"})
                return self.send(200, shop_query(m.group(1), cols, q.get("f", []), (q.get("order") or [None])[0],
                                                 (q.get("limit") or ["50"])[0], (q.get("offset") or ["0"])[0]))
            if path.path == "/api/retention/erasure":
                q = urllib.parse.parse_qs(path.query)
                delay = max(0, int(float((q.get("delay_seconds") or ["0"])[0])))
                mcol = (q.get("marketing_column") or [""])[0]
                return self.send(200, erasure_status(delay, mcol if IDENT.match(mcol or "x") else ""))
            if path.path == "/api/retention/inactivity":
                q = urllib.parse.parse_qs(path.query)
                return self.send(200, inactivity_status(max(1, int(float((q.get("after_days") or ["1095"])[0]))),
                                                        max(0, int(float((q.get("notice_hours") or ["48"])[0])))))
            if path.path == "/api/ai/status":
                return self.send(200, {"configured": bool(AI_KEY), "provider": "Groq" if "groq" in AI_BASE else "xAI",
                                       "model": ai_model() if AI_KEY else None})
            if path.path == "/api/breach/scan":
                return self.send(200, breach_scan(self.token(), user))
            if path.path == "/api/breach/model":
                return self.send(200, ml_model(read_doc("breach"), self.token(), user=user))
            if path.path == "/api/incidents":
                return self.send(200, read_incidents()["incidents"])
            m = INC_ROUTE.fullmatch(path.path)
            if m:
                inc = next((x for x in read_incidents()["incidents"] if x["id"] == m.group(1)), None)
                return self.send(200, inc) if inc else self.send(404, {"error": "no such incident"})
            m = STORE_ROUTE.fullmatch(path.path)
            if m and not m.group(4):
                kind = KIND_OF[m.group(1)]
                if not m.group(2):
                    return self.send(200, read_doc(kind))
                if not m.group(3):
                    return self.send(200, history_of(kind))
                f = store_paths(kind)[1] / f"v{int(m.group(3))}.json"
                return self.send(200, json.loads(f.read_text())) if f.exists() else self.send(404, {"error": "no such version"})
            return self.send(404, {"error": "not found"})
        except ValueError as e:
            return self.send(400, {"error": str(e)})
        except urllib.error.HTTPError as e:
            sys.stderr.write(f"[consent] shop database answered {e.code} for {self.path}\n")
            return self.send(502, {"error": f"shop database answered {e.code}"})
        except Exception as e:  # network etc.
            sys.stderr.write(f"[consent] {type(e).__name__}: {e} for {self.path}\n")
            return self.send(502, {"error": f"{type(e).__name__}: {e}"})

    def token(self):
        return (self.headers.get("Authorization") or "")[7:]

    def do_PUT(self):
        p = urllib.parse.urlparse(self.path).path
        if p.startswith("/api/iam/"):
            return self.iam_write("PUT", p)
        if p.startswith("/api/billing/"):
            return self.billing("PUT", p)
        if p == "/api/pii/feedback":
            user = self.guard()
            if not user:
                return
            try:
                return self.send(200, pii_feedback(self.body(), user))
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p == "/api/datamap/config":
            user = self.guard()
            if not user:
                return
            try:
                return self.send(200, save_datamap_config(self.body(), user))
            except PermissionError as e:
                return self.send(409, {"error": str(e)})
            except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p == "/api/usage/plan":
            user = self.guard()
            if not user:
                return
            try:
                return self.send(200, save_plan(self.body(), user))
            except PermissionError as e:
                return self.send(409, json.loads(str(e)))
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        im = INC_ROUTE.fullmatch(p)
        if im:
            user = self.guard("respond")
            if not user:
                return
            try:
                b = self.body()
                inc, err = update_incident(im.group(1), b.get("rev"), b.get("changes") or {}, user)
                if not err:
                    audit(user, "incident.update", f"{im.group(1)}: {', '.join(sorted((b.get('changes') or {}).keys()))}")
                if err == "missing":
                    return self.send(404, {"error": "no such incident"})
                if err == "conflict":
                    return self.send(409, {"error": "Someone else changed this incident. It has been reloaded; re-apply your change.", "current": inc})
                return self.send(200, inc)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        m = STORE_ROUTE.fullmatch(urllib.parse.urlparse(self.path).path)
        if not m or m.group(2) or m.group(4):
            return self.send(404, {"error": "not found"})
        kind = KIND_OF[m.group(1)]
        user = self.guard("policy")
        if not user:
            return
        try:
            b = self.body()
            doc, current = save_doc(kind, b.get("policy") or {}, b.get("base_version"), user, b.get("change_note"))
            if current:
                return self.send(409, {"error": "The policy was changed by someone else. Reload and try again.", "current": current})
            audit(user, f"{kind}.save", f"v{doc['version']}: {doc['change_note']}")
            return self.send(200, doc)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/api/billing/webhook":
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if 0 < n <= 1_000_000 else b""
            try:
                return webhook(self, raw)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p.startswith("/api/billing/"):
            return self.billing("POST", p)
        if p in ("/api/pii/scan", "/api/pii/logs"):
            user = self.guard()
            if not user:
                return
            try:
                if p == "/api/pii/scan":
                    cols = pii_scan_columns(user)
                    return self.send(201, {**pii_view(), "columns": cols, "logs": pii_scan_logs(self.token(), force=True)})
                return self.send(200, pii_scan_logs(self.token()))
            except (urllib.error.URLError, TimeoutError) as e:
                return self.send(502, {"error": f"Couldn't reach the database or the logs: {e}"})
        if p in ("/api/datamap/scan", "/api/datamap/live"):
            user = self.guard()
            if not user:
                return
            try:
                if p == "/api/datamap/live":
                    if not allowed(user, "datamap:Scan"):
                        with _dm_live_lock:
                            if _dm_live["result"] is None:
                                return self.send(200, datamap_view()["last"] or {})
                    return self.send(200, live_datamap(user, self.token()))
                return self.send(201, scan_datamap(user, self.token()))
            except (urllib.error.URLError, TimeoutError) as e:
                return self.send(502, {"error": f"Couldn't reach the database or the logs: {e}"})
        if p.startswith("/api/evidence/"):
            user = self.guard()
            if not user:
                return
            try:
                if p == "/api/evidence/verify":
                    return self.send(200, verify_integrity(user))
                if p == "/api/evidence/check":
                    return self.send(200, check_pack(self.body(limit=25_000_000)))
                if p == "/api/evidence/pack":
                    b = self.body()
                    return self.send(201, build_pack(user, b.get("from"), b.get("to"), self.token()))
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
            return self.send(404, {"error": "not found"})
        if p == "/api/readiness/exposure":
            user = self.guard()
            if not user:
                return
            try:
                return self.send(201, run_exposure(user))
            except ValueError as e:
                return self.send(400, {"error": str(e)})
            except (urllib.error.URLError, TimeoutError) as e:
                return self.send(502, {"error": f"Couldn't reach the customer database: {e}"})
        if p == "/api/readiness":
            user = self.guard()
            if not user:
                return
            try:
                return self.send(201, save_readiness(self.body(), user))
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p.startswith("/api/iam"):
            return self.iam_write("POST", p)
        if p == "/api/ai/chat":
            user = self.guard("ai")
            if not user:
                return
            if not AI_KEY:
                return self.send(503, {"error": "The AI assistant isn't configured: add GROK_API_KEY to .env and restart the service."})
            for k in ("ai.questions", "ai.tokens"):
                blocked = quota_block(user, k)
                if blocked:
                    audit(user, "usage.blocked", blocked)
                    return self.send(429, {"error": blocked, "meter": k})
            try:
                b = self.body()
                if (b.get("attachment") or {}).get("text") and not allowed(user, "ai:AttachFile"):
                    audit(user, "access.denied", "ai:AttachFile: not allowed by any policy attached to you")
                    return self.send(403, {"error": "Access denied: ai:AttachFile is not allowed by any policy attached to you."})
                if (b.get("attachment") or {}).get("text"):
                    blocked = quota_block(user, "ai.attachments")
                    if blocked:
                        audit(user, "usage.blocked", blocked)
                        return self.send(429, {"error": blocked, "meter": "ai.attachments"})
                    meter(user, "ai.attachments")
                audit(user, "ai.ask", str(b.get("question") or "")[:160])
                return ai_stream(self, b, user)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p == "/api/breach/model/retrain":
            user = self.guard()
            if not user:
                return
            try:
                b = self.body()
                if b.get("preview"):
                    validate_anomaly(b["preview"])
                    return self.send(200, ml_model(read_doc("breach"), self.token(), preview=b["preview"]))
                m = ml_model(read_doc("breach"), self.token(), force=True, user=user)
                _scan_cache["key"] = None
                audit(user, "model.retrain", f"{m.get('slices', 0)} slices, {len(m.get('signals', []))} anomalies")
                return self.send(200, m)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
        if p in ("/api/breach/preview", "/api/incidents") or SIGNAL_ROUTE.fullmatch(p):
            user = self.guard("read" if p == "/api/breach/preview" else "respond")
            if not user:
                return
            try:
                b = self.body()
                if p == "/api/breach/preview":
                    # Dry run of draft detectors: nothing is stored, nothing auto-opens.
                    dets = b.get("detectors") or []
                    for d in dets:
                        validate_detector(d)
                    doc = {"lookback_days": max(1, min(90, int(b.get("lookback_days") or 7)))}
                    since, results = run_detectors(doc, dets, self.token())
                    return self.send(200, {"since": since, "results": results})
                if p == "/api/incidents":
                    with _inc_lock:
                        reg = read_incidents()
                        inc = _new_incident(reg, b.get("incident") or {}, user)
                        write_incidents(reg)
                    audit(user, "incident.create", f"{inc['id']}: {inc['title']}")
                    return self.send(201, inc)
                sm = SIGNAL_ROUTE.fullmatch(p)
                res = triage_signal(sm.group(1), sm.group(2), b, user)
                audit(user, f"signal.{sm.group(2)}", sm.group(1) + (f" → {res['incident']['id']}" if res.get("incident") else f": {b.get('reason')}" if b.get("reason") else ""))
                return self.send(200, res)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
            except urllib.error.HTTPError as e:
                return self.send(502, {"error": f"NigraniAI answered {e.code}"})
            except Exception as e:
                sys.stderr.write(f"[consent] {type(e).__name__}: {e} for {self.path}\n")
                return self.send(502, {"error": f"{type(e).__name__}: {e}"})
        m = STORE_ROUTE.fullmatch(p)
        if not m or not m.group(4):
            return self.send(404, {"error": "not found"})
        kind, v = KIND_OF[m.group(1)], m.group(4)
        user = self.guard("policy")
        if not user:
            return
        f = store_paths(kind)[1] / f"v{int(v)}.json"
        if not f.exists():
            return self.send(404, {"error": "no such version"})
        b = self.body()
        doc, current = save_doc(kind, json.loads(f.read_text()), b.get("base_version"), user, f"Restored version {v}")
        if current:
            return self.send(409, {"error": "The policy was changed by someone else. Reload and try again.", "current": current})
        audit(user, f"{kind}.restore", f"v{v} → v{doc['version']}")
        return self.send(200, doc)

    def do_DELETE(self):
        p = urllib.parse.urlparse(self.path).path
        if p.startswith("/api/iam/"):
            return self.iam_write("DELETE", p)
        return self.send(404, {"error": "not found"})

    def billing(self, method, p):
        """The client's billing: billing profile, invoices, plan changes and Razorpay payments."""
        user = self.guard()
        if not user:
            return
        try:
            pm = BILL_PAY_ROUTE.fullmatch(p)
            if method == "GET" and p == "/api/billing":
                return self.send(200, billing_view(user))
            if method == "PUT" and p == "/api/billing/profile":
                return self.send(200, save_billing_profile(self.body(), user))
            if method == "POST" and p == "/api/billing/upgrade":
                b = self.body()
                return self.send(200, upgrade(b, user, preview=bool(b.get("preview"))))
            if method == "POST" and pm:
                return self.send(200, start_payment(pm.group(1), user))
            if method == "POST" and p == "/api/billing/verify":
                return self.send(200, verify_payment(self.body(), user))
            return self.send(404, {"error": "not found"})
        except PermissionError as e:
            return self.send(400, {"error": str(e), "code": "verification_failed"})
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})

    def iam_write(self, method, p):
        user = self.guard()
        if not user:
            return
        try:
            b = self.body() if method != "DELETE" else {}
            um, pm, gm = IAM_USER_ROUTE.fullmatch(p), IAM_POLICY_ROUTE.fullmatch(p), IAM_GROUP_ROUTE.fullmatch(p)
            if p == "/api/iam/validate":
                errors, warnings = validate_document(b.get("document"))
                return self.send(200, {"errors": errors, "warnings": warnings})
            if p == "/api/iam/simulate":
                return self.send(200, simulate(b))
            if p == "/api/iam/users" and method == "POST":
                return self.send(201, {"email": create_user(b, user)})
            if um and um.group(2) and method == "PUT":
                return self.send(200, set_user_access(um.group(1), b, user))
            if um and method == "PUT":
                return self.send(200, update_user(um.group(1), b, user))
            if um and method == "DELETE":
                delete_user(um.group(1), user); return self.send(200, {"ok": True})
            if p == "/api/iam/policies" and method == "POST":
                pid, warnings = save_policy(None, b, user); return self.send(201, {"id": pid, "warnings": warnings})
            if pm and pm.group(2) and method == "POST":
                pid, warnings = restore_policy(pm.group(1), int(pm.group(2)), user); return self.send(200, {"id": pid, "warnings": warnings})
            if pm and method == "PUT":
                pid, warnings = save_policy(pm.group(1), b, user); return self.send(200, {"id": pid, "warnings": warnings})
            if pm and method == "DELETE":
                delete_policy(pm.group(1), user); return self.send(200, {"ok": True})
            if p == "/api/iam/groups" and method == "POST":
                return self.send(201, {"id": save_group(None, b, user)})
            if gm and method == "PUT":
                return self.send(200, {"id": save_group(gm.group(1), b, user)})
            if gm and method == "DELETE":
                delete_group(gm.group(1), user); return self.send(200, {"ok": True})
            return self.send(404, {"error": "not found"})
        except PermissionError as e:
            audit(user, "access.denied", str(e))
            return self.send(403, {"error": f"Access denied: {e}"})
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})


CLI_HELP = """Provider commands (run on the server, next to .env):
  status                         client, plan, usage this cycle, unpaid invoices
  plans                          the plan catalogue in provider.json
  plan set <plan>                move the client to a plan now (no invoice)
  invoices                       every invoice
  bill-now                       invoice the usage so far this cycle
  mark-paid <invoice> <ref>      record a bank transfer / cheque (invoice id or number)
  void <invoice>                 cancel an unpaid invoice
  refund <invoice>               refund a Razorpay payment in full
"""


def cli(args):
    """The provider's own actions on this copy. There is no provider login in the dashboard."""
    cmd = args[0] if args else "help"
    inr = lambda x: f"₹{x:,.2f}"
    if cmd == "status":
        plan, b = read_plan(), read_billing()
        start, end = cycle_bounds(plan)
        tot = _cycle_totals(_usage_doc(), plan, start, end)
        print(f"{CLIENT_NAME} ({CLIENT_ID}) · plan {plan['name']} · {inr(plan['base_fee'])}/month · cycle {start:%d %b} – {(end - timedelta(days=1)):%d %b %Y}")
        for k, pm in plan["meters"].items():
            used = seat_count() if METERS[k][2] == "gauge" else tot.get(k, 0)
            inc = "unlimited" if pm.get("included") is None else f"{pm['included']:,}"
            print(f"  {METERS[k][0]:<24} {used:>12,} of {inc}")
        due = [i for i in b["invoices"] if i["status"] == "issued"]
        print(f"Unpaid invoices: {len(due)} ({inr(sum(i['total'] for i in due))})" + (" · RESTRICTED to Free limits" if b.get("restricted_plan") else ""))
    elif cmd == "plans":
        for k, p in plans().items():
            print(f"  {k:<12} {p['name']:<12} {inr(p['base_fee'])}/month")
    elif cmd == "plan" and len(args) == 3 and args[1] == "set":
        if args[2] not in plans():
            sys.exit(f"Unknown plan {args[2]}. Plans: {', '.join(plans())}")
        _apply_template(args[2], "provider")
        print(f"{CLIENT_NAME} is now on the {plans()[args[2]]['name']} plan.")
    elif cmd == "invoices":
        for i in sorted(read_billing()["invoices"], key=lambda i: i["issued_at"]):
            print(f"  {i['number']:<18} {i['id']}  {i['kind']:<8} {i['issued_at'][:10]}  {inr(i['total']):>14}  {i['status']}")
    elif cmd == "bill-now":
        inv = bill_now("provider")
        print(f"Issued {inv['number']}: {inr(inv['total'])} (incl. {inr(inv['tax']['total'])} GST)")
    elif cmd in ("mark-paid", "void", "refund") and len(args) >= 2:
        if cmd == "mark-paid" and len(args) < 3:
            sys.exit("Usage: mark-paid <invoice> <reference>")
        inv = invoice_action(args[1], cmd.replace("-", "_"), " ".join(args[2:]), "provider")
        print(f"{inv['number']} is now {inv['status']}.")
    else:
        print(CLI_HELP)


def main():
    if len(sys.argv) > 1:
        try:
            return cli(sys.argv[1:])
        except ValueError as e:
            sys.exit(f"Error: {e}")
    missing = [k for k, v in {"SHOP_SUPABASE_URL": SHOP_URL, "SHOP_SUPABASE_SERVICE_KEY": SHOP_KEY,
                              "SUPABASE_URL": AUTH_URL, "GUARDRAIL_ANON_KEY": AUTH_ANON}.items() if not v]
    if missing:
        sys.exit(f"Missing in .env: {', '.join(missing)}")
    read_doc("policy")
    read_doc("retention")
    read_doc("breach")
    with _ledger_lock:
        _ledger_ready()
    if central_configured():
        threading.Thread(target=_central_loop, daemon=True).start()
    read_plan()
    print(f"[consent] listening on http://localhost:{PORT}  (allowed origins: {', '.join(sorted(ORIGINS))})", flush=True)
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    finally:
        with _usage_lock:
            _flush_usage(force=True)


if __name__ == "__main__":
    main()
