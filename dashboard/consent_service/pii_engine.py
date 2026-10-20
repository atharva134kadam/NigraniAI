"""PII detection v2: fused verdicts with evidence.

Every database column gets one verdict built from independent signals:

1. name and context   the column's name and its table (the v1 classifier in server.py)
2. values             a sample of values tested with format checks and checksums: Luhn (cards),
                      Verhoeff (Aadhaar), PAN holder type, GSTIN check character, Indian mobile,
                      email, PIN code, IFSC, UPI, passport, voter ID, password hashes, tokens,
                      IP addresses, birth dates, street addresses
3. links              foreign keys from the database schema (customer_id → customers.id)
4. language model     for free-text columns, a local NER model (Presidio + spaCy, run by
                      pii_ner_worker.py in its own environment) finds names and places; anything it
                      calls a number must still pass the validators
5. feedback           an admin's confirm / correct, which always wins and is kept across scans

The verdict is: kind, category, confidence 0-100, Confirmed / Likely / Possible / Not personal, and
the evidence that produced it. Sampled values exist only in memory while a column is scored; only the
statistics and the evidence text are kept. The same validators scan log messages for personal data
the log masker missed. Python standard library only (the NER model is optional).
"""
import ipaddress
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------- kinds
# kind: (label, category, sensitivity)
KINDS = {
    "email": ("Email address", "contact", "critical"),
    "phone": ("Phone number", "contact", "critical"),
    "card": ("Payment card number", "financial", "critical"),
    "aadhaar": ("Aadhaar number", "government ID", "critical"),
    "pan": ("PAN", "government ID", "critical"),
    "gstin": ("GSTIN", "financial", "high"),
    "passport": ("Passport number", "government ID", "critical"),
    "voter_id": ("Voter ID (EPIC)", "government ID", "critical"),
    "ifsc": ("Bank IFSC", "financial", "high"),
    "bank_account": ("Bank account number", "financial", "critical"),
    "upi": ("UPI ID", "financial", "critical"),
    "payment_ref": ("Payment reference", "financial", "high"),
    "password_hash": ("Password hash", "credentials", "critical"),
    "token": ("Secret / token", "credentials", "critical"),
    "jwt": ("Access token (JWT)", "credentials", "critical"),
    "ip": ("IP address", "device", "high"),
    "birth_date": ("Date of birth", "identity", "high"),
    "person_name": ("Person's name", "identity", "high"),
    "address": ("Street address", "address", "critical"),
    "pincode": ("PIN code", "address", "high"),
    "city_state": ("City / state", "address", "high"),
    "geo": ("Location coordinates", "address", "critical"),
    "free_text": ("Free text", "customer content", "high"),
    "person_link": ("Link to a person", "linked to a person", "medium"),
}
# v1 (name-based) kinds from server.py → v2 kinds
V1_TO_V2 = {"contact": None, "credentials": "token", "financial / ID": None, "address": "address", "name": "person_name",
            "birth / age": "birth_date", "network": "ip", "free text": "free_text", "person link": "person_link"}
NAME_HINTS = [  # (kind, column-name pattern on whole words)
    ("email", r"(^|_)e_?mail($|_)"), ("phone", r"(^|_)(phone|mobile|whatsapp|contact_no|msisdn)($|_)"),
    ("card", r"(^|_)(card(_number|_no)?|cc_?num|pan_card)($|_)"), ("aadhaar", r"(^|_)aadhaa?r"), ("pan", r"(^|_)pan(_number|_no)?$"),
    ("gstin", r"(^|_)gstin?($|_)"), ("passport", r"passport"), ("voter_id", r"(^|_)(epic|voter_?id)($|_)"),
    ("ifsc", r"(^|_)ifsc"), ("bank_account", r"(^|_)(account_(no|number)|acct_?no|bank_account)($|_)"), ("upi", r"(^|_)(upi|vpa)(_id)?($|_)"),
    ("payment_ref", r"(^|_)(payment_(reference|id)|provider_(order|payment)_id|refund_id|transaction_id|utr)($|_)"),
    ("password_hash", r"(^|_)(password|passwd|pwd)(_hash)?($|_)"), ("token", r"(^|_)(token|secret|api_?key|otp|refresh_token|access_token)(_hash)?($|_)|_hash$"),
    ("ip", r"(^|_)(ip|ip_address|client_ip|remote_addr)$"), ("birth_date", r"(^|_)(dob|date_of_birth|birth_?date|birthday)$"),
    ("person_name", r"^((ship|shipping|billing|customer|reviewer|contact|recipient)_)?(name|full_name|first_name|last_name)$"),
    ("address", r"(^|_)(line1|line2|address(_line\d)?|street|default_address)($|_)"), ("pincode", r"(^|_)(pin_?code|zip|postal_code)($|_)"),
    ("city_state", r"^((ship|shipping|billing)_)?(city|state|district)$"), ("geo", r"(^|_)(lat|lng|latitude|longitude)$"),
    ("free_text", r"(^|_)(message|comment|comments|note|notes|reason|review_text|body|description)$"),
    ("person_link", r"(^|_)(user|customer|profile|member|buyer|recipient)_?id$"),
]
NAME_RX = [(k, re.compile(rx, re.I)) for k, rx in NAME_HINTS]


STAFF_LINK = re.compile(r"^(actor|created_by|updated_by|modified_by|staff|admin|operator|approved_by|reviewed_by)", re.I)


def name_kind(column):
    return next((k for k, rx in NAME_RX if rx.search(column)), None)


# ---------------------------------------------------------------- checksums
def luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
       [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
       [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
       [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[i % 8][ord(ch) - 48]]
    return c == 0


_B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_ok(g):
    if not re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]", g):
        return False
    if not (1 <= int(g[:2]) <= 38 or g[:2] in ("97", "99")):
        return False
    total = 0
    for i, ch in enumerate(g[:14]):
        v = _B36.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return _B36[(36 - total % 36) % 36] == g[14]


# ---------------------------------------------------------------- value validators
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$")
UPI_RE = re.compile(r"^[A-Za-z0-9._-]{2,256}@[A-Za-z]{2,64}$")
PAN_RE = re.compile(r"^[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]$")
IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
PASSPORT_RE = re.compile(r"^[A-PR-WY][1-9]\d{6}$")
EPIC_RE = re.compile(r"^[A-Z]{3}\d{7}$")
RZP_RE = re.compile(r"^(pay|order|rfnd|plink|cust|inv|sub|qr|txn|pout|fa|va)_[A-Za-z0-9]{14}$")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}$")
HASH_RE = re.compile(r"^(\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(id|i|d)\$.+|pbkdf2_[a-z0-9]+\$\d+\$.+|\$[156]\$.+\$.+|scrypt:.+)$")
HEX_RE = re.compile(r"^[a-f0-9]{32,128}$", re.I)
ADDRESS_WORDS = re.compile(r"\b(road|rd|street|st|lane|ln|marg|nagar|colony|sector|block|flat|floor|apartment|apt|house|plot|society|layout|"
                           r"phase|cross|main|near|opp|behind|tower|wing|chowk|bazaar|gali|mohalla|village|taluk|district|enclave|residency|avenue)\b", re.I)
STATES = {s.lower() for s in ["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", "Haryana", "Himachal Pradesh",
          "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab",
          "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal", "Delhi", "Jammu and Kashmir",
          "Ladakh", "Puducherry", "Chandigarh", "Andaman and Nicobar Islands", "Lakshadweep", "Dadra and Nagar Haveli and Daman and Diu"]}
CITIES = {"mumbai", "delhi", "new delhi", "bengaluru", "bangalore", "hyderabad", "ahmedabad", "chennai", "kolkata", "surat", "pune", "jaipur",
          "lucknow", "kanpur", "nagpur", "indore", "thane", "bhopal", "visakhapatnam", "patna", "vadodara", "ghaziabad", "ludhiana", "agra",
          "nashik", "faridabad", "meerut", "rajkot", "varanasi", "srinagar", "aurangabad", "dhanbad", "amritsar", "navi mumbai", "allahabad",
          "prayagraj", "ranchi", "howrah", "coimbatore", "jabalpur", "gwalior", "vijayawada", "jodhpur", "madurai", "raipur", "kota", "guwahati",
          "chandigarh", "solapur", "mysuru", "mysore", "noida", "gurugram", "gurgaon", "kochi", "trivandrum", "thiruvananthapuram", "bhubaneswar",
          "dehradun", "udaipur", "goa", "panaji", "mangaluru", "mangalore", "nellore", "belgaum", "belagavi", "hubli", "tiruchirappalli", "salem"}


def _digits(s):
    return re.sub(r"[\s\-().]", "", s)


def is_epoch_ms(d):
    """13-digit numbers that are epoch milliseconds between 2001 and 2040 (often masked as cards)."""
    return len(d) == 13 and d.isdigit() and 978307200000 <= int(d) <= 2208988800000


def classify_value(v, sql_type=""):
    """The set of kinds one value passes (a value can pass more than one, e.g. a UPI that looks like an email)."""
    if v is None:
        return set()
    if isinstance(v, bool):
        return set()
    if isinstance(v, (int, float)):
        if isinstance(v, float) and -90 <= v <= 90 and not float(v).is_integer():
            return {"geo_lat"}
        s = str(int(v)) if float(v).is_integer() else str(v)
    else:
        s = str(v).strip()
    if not s or len(s) > 2000:
        return set()
    out = set()
    if EMAIL_RE.match(s):
        out.add("email")
    elif UPI_RE.match(s):
        out.add("upi")
    d = _digits(s)
    if d.startswith("+91"):
        d = d[3:]
    elif d.startswith("91") and len(d) == 12 and d[2] in "6789":
        d = d[2:]
    elif d.startswith("0") and len(d) == 11:
        d = d[1:]
    if d.isdigit():
        if len(d) == 10 and d[0] in "6789" and len(set(d)) > 2:
            out.add("phone")
        raw = re.sub(r"[\s-]", "", s)
        if raw.isdigit():
            if 13 <= len(raw) <= 19 and luhn_ok(raw) and not is_epoch_ms(raw) and raw[0] in "23456" and len(set(raw)) > 1:
                out.add("card")
            if len(raw) == 12 and raw[0] in "23456789" and verhoeff_ok(raw):
                out.add("aadhaar")
            if len(raw) == 6 and raw[0] in "123456789":
                out.add("pincode")
            if 9 <= len(raw) <= 18 and "card" not in out and "aadhaar" not in out and "phone" not in out:
                out.add("bank_account_shape")
    u = s.upper()
    if PAN_RE.match(u) and s == u:
        out.add("pan")
    if len(s) == 15 and gstin_ok(u):
        out.add("gstin")
    if IFSC_RE.match(u) and s == u:
        out.add("ifsc")
    if PASSPORT_RE.match(u) and s == u:
        out.add("passport")
    if EPIC_RE.match(u) and s == u:
        out.add("voter_id")
    if JWT_RE.match(s):
        out.add("jwt")
    if RZP_RE.match(s):
        out.add("payment_ref")
    elif re.fullmatch(r"[A-Za-z0-9_-]{8,64}", s) and re.search(r"\d", s) and re.search(r"[A-Za-z]", s):
        out.add("id_shape")
    if HASH_RE.match(s):
        out.add("password_hash")
    elif HEX_RE.match(s) or (len(s) >= 24 and " " not in s and entropy(s) >= 4.0 and re.search(r"\d", s) and re.search(r"[A-Za-z]", s)):
        out.add("token")
    if re.fullmatch(r"[0-9a-fA-F:.]{7,45}", s):
        try:
            ip = ipaddress.ip_address(s)
            out.add("ip_private" if ip.is_private or ip.is_loopback else "ip")
        except ValueError:
            pass
    dob = _as_date(v, sql_type)
    if dob:
        age = (date.today() - dob).days / 365.25
        out.add("adult_age_date" if 13 <= age <= 100 else "other_date")
    low = s.lower()
    if len(s) >= 12 and re.search(r"\d", s) and ADDRESS_WORDS.search(s):
        out.add("address")
    elif 4 <= len(s) <= 200 and (re.search(r"\d", s) and re.search(r"[A-Za-z]{3,}", s) or ADDRESS_WORDS.search(s)
                                 or re.fullmatch(r"[A-Za-z][A-Za-z.'-]*(?:[ ,]+[A-Za-z0-9.'/-]+){1,8}", s)) and not EMAIL_RE.match(s) and "@" not in s:
        out.add("address_loose")
    if low in STATES or low in CITIES:
        out.add("city_state")
    if re.fullmatch(r"[A-Z][a-z]+(?:[ .'-][A-Z][a-z]+){1,3}", s) and not re.search(r"\d", s):
        out.add("name_shape")
    if len(s) >= 20 and len(s.split()) >= 4:
        out.add("sentence")
    return out


def _as_date(v, sql_type):
    if not ("date" in sql_type or "timestamp" in sql_type) and not isinstance(v, str):
        return None
    if not isinstance(v, str) or not re.match(r"^\d{4}-\d{2}-\d{2}", v):
        return None
    try:
        return date.fromisoformat(v[:10])
    except ValueError:
        return None


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s))) if n else 0.0


# ---------------------------------------------------------------- text scanning (log messages, free text)
TEXT_PATTERNS = [
    ("email", re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")),
    ("phone", re.compile(r"(?<![\w+])(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")),
    ("card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
    ("aadhaar", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")),
    ("pan", re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z](?![A-Z0-9])")),
    ("gstin", re.compile(r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Z0-9])")),
    ("ifsc", re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])")),
    ("upi", re.compile(r"(?<![\w.-])[A-Za-z0-9._-]{2,64}@(?:ok)?(?:upi|ybl|paytm|okaxis|okhdfcbank|okicici|oksbi|ibl|axl|apl|fbl|icici|sbi|hdfcbank|axisbank|kotak|yesbank|idfcbank|pnb|boi|barodampay|unionbank)(?![\w.-])", re.I)),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("ip", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
]
CONTEXT_FP = re.compile(r"(time ?stamp|epoch|millis|nanos|duration|elapsed|took|latency|trace|span|request[_-]?id|order[_-]?id|uuid|version|port|pid|thread|offset|count|size|bytes|ms\b)", re.I)
MASK_TOKEN = re.compile(r"\[[A-Z_]{2,30}\]|<[A-Z_]{2,30}>")
NONPII_KEY = re.compile(r"(sha|hash|digest|checksum|uuid|guid|(^|_|[a-z])(id|ids)$|Id$|trace|span|time|stamp|ts$|_at$|At$|nanos|millis|micros|duration|elapsed|latency|count|size|bytes|length|version|port|pid|seq|offset|index|line|code|status|amount|price|total|quantity|qty)", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _token_around(text, a, b):
    """The whole token a match sits in (letters, digits, - _ . :), to tell a real number from a piece of an id or hash."""
    i, j = a, b
    while i > 0 and (text[i - 1].isalnum() or text[i - 1] in "-_."):
        i -= 1
    while j < len(text) and (text[j].isalnum() or text[j] in "-_."):
        j += 1
    return text[i:j]


def _embedded(text, a, b, kind):
    tok = _token_around(text, a, b).strip("-_.")
    if UUID_RE.match(tok) or re.fullmatch(r"[0-9a-f]{16,}", tok, re.I):
        return True
    if kind in ("card", "aadhaar", "phone") and tok and re.search(r"[A-Za-z]", tok.replace("+91", "")):
        return True                                   # digits glued to letters: an id, hash or code
    m = re.search(r'"([A-Za-z_][\w]*)"\s*:\s*"?[^",{}]{0,6}$', text[max(0, a - 48):a])
    return bool(m and NONPII_KEY.search(m.group(1)) and kind in ("card", "aadhaar", "phone", "ip"))


def scan_text(text):
    """Personal data found in `text`, as (kind, start, end, evidence). Every match is validated
    (checksums, ranges) and checked against its context, so timestamps, ids and versions don't count."""
    if not text:
        return []
    found, taken = [], []
    def free(a, b):
        return all(b <= x or a >= y for x, y in taken)
    for kind, rx in TEXT_PATTERNS:
        for m in rx.finditer(text):
            a, b, s = m.start(), m.end(), m.group(0)
            if not free(a, b):
                continue
            before = text[max(0, a - 24):a]
            if kind in ("card", "aadhaar", "phone", "ip", "pan", "ifsc", "gstin") and _embedded(text, a, b, kind):
                continue
            ev = None
            if kind == "email":
                if UPI_RE.match(s) and not EMAIL_RE.match(s):
                    continue
                if re.search(r"@(example|test|localhost|domain)\.", s, re.I):
                    continue
                ev = "email format"
            elif kind == "phone":
                d = _digits(s)[-10:]
                if CONTEXT_FP.search(before) or len(set(d)) <= 2:
                    continue
                ev = "Indian mobile (10 digits, starts 6–9)"
            elif kind == "card":
                raw = re.sub(r"[ -]", "", s)
                if not (13 <= len(raw) <= 19 and luhn_ok(raw) and raw[0] in "23456") or is_epoch_ms(raw) or CONTEXT_FP.search(before) or len(set(raw)) <= 1:
                    continue
                ev = "passes the Luhn check"
            elif kind == "aadhaar":
                raw = re.sub(r"[ -]", "", s)
                if not verhoeff_ok(raw) or CONTEXT_FP.search(before) or is_epoch_ms(raw):
                    continue
                ev = "passes the Verhoeff check"
            elif kind == "pan":
                ev = "PAN format with a valid holder type"
            elif kind == "gstin":
                if not gstin_ok(s):
                    continue
                ev = "GSTIN check character is valid"
            elif kind == "ifsc":
                ev = "IFSC format"
            elif kind == "upi":
                ev = "UPI handle"
            elif kind == "jwt":
                ev = "signed access token"
            elif kind == "ip":
                try:
                    ip = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified or CONTEXT_FP.search(before) or s.startswith("0."):
                    continue
                ev = "public IP address"
            taken.append((a, b))
            found.append((kind, a, b, ev))
    return sorted(found, key=lambda x: x[1])


def masked_token_verdicts(message):
    """For each masked token in a log message ([CARD], [EMAIL], …): is it likely a false positive?"""
    out = []
    for m in MASK_TOKEN.finditer(message or ""):
        tok, before = m.group(0)[1:-1], message[max(0, m.start() - 24):m.start()]
        fp = tok in ("CARD", "CREDIT_CARD", "AADHAAR", "PHONE", "PHONE_NUMBER", "BANK_ACCOUNT") and bool(re.search(r"time ?stamp|epoch|millis|duration|took|latency|\bat\W{0,3}$", before, re.I))
        out.append({"token": tok, "start": m.start(), "false_positive": fp,
                    "why": "the value sits next to 'timestamp' (a 13-digit time in milliseconds, not a card)" if fp else None})
    return out


# ---------------------------------------------------------------- NER (optional, local)
class NER:
    """A long-running pii_ner_worker.py in its own Python environment (Presidio + spaCy). Optional:
    if the environment or model is missing, detection runs without it."""
    def __init__(self):
        self.proc, self.lock, self.error, self.model = None, threading.Lock(), None, None
        venv = ROOT / ".pii-venv" / "bin" / "python"
        self.python = str(venv) if venv.exists() else None
        self.worker = str(ROOT / "pii_ner_worker.py")

    def available(self):
        return bool(self.python) and Path(self.worker).exists()

    def _start(self):
        self.proc = subprocess.Popen([self.python, "-I", self.worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
        hello = json.loads(self.proc.stdout.readline() or "{}")
        if not hello.get("ready"):
            raise RuntimeError(hello.get("error") or "NER worker didn't start")
        self.model = hello.get("model")

    def analyse(self, texts, timeout=120):
        """[[{"type": "PERSON", "start", "end", "score"}, …] per text] or None if unavailable."""
        if not self.available() or not texts:
            return None
        with self.lock:
            try:
                if not self.proc or self.proc.poll() is not None:
                    self._start()
                self.proc.stdin.write(json.dumps({"texts": [t[:2000] for t in texts]}) + "\n")
                self.proc.stdin.flush()
                res = {}
                t = threading.Thread(target=lambda: res.update(line=self.proc.stdout.readline()), daemon=True)
                t.start()
                t.join(timeout)
                if "line" not in res:
                    self.proc.kill()
                    raise TimeoutError("NER worker timed out")
                out = json.loads(res["line"])
                self.error = None
                return out.get("results")
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"[:200]
                try:
                    self.proc and self.proc.kill()
                except Exception:
                    pass
                self.proc = None
                return None

    def status(self):
        return {"available": self.available(), "model": self.model, "error": self.error, "running": bool(self.proc and self.proc.poll() is None)}


ner = NER()
NER_STOP = {"shopsmart", "razorpay", "supabase", "guardrail", "nigraniai", "nigrani", "eureka", "spring", "java", "postgres", "json", "http", "https", "api", "id", "null",
            "true", "false", "order", "customer", "payment", "service", "admin", "user", "test", "demo", "india", "rupee", "inr", "upi"}


def ner_names(texts):
    """Per text: (persons, places) found by the model, filtered so tool, brand and service words don't count."""
    res = ner.analyse(texts)
    if res is None:
        return None
    out = []
    for t, ents in zip(texts, res):
        p = l = 0
        for e in ents:
            span = t[e["start"]:e["end"]].strip()
            if len(span) < 3 or span.lower() in NER_STOP or not re.search(r"[A-Za-z]", span) or re.search(r"[_/\\{}=<>\[\]@]", span):
                continue
            if e["type"] == "PERSON" and e["score"] >= 0.7 and span[0].isupper():
                p += 1
            elif e["type"] == "LOCATION" and e["score"] >= 0.7:
                l += 1
        out.append((p, l))
    return out


# ---------------------------------------------------------------- fusion
VALUE_KINDS = ["email", "phone", "card", "aadhaar", "pan", "gstin", "passport", "voter_id", "ifsc", "upi", "jwt", "password_hash", "token", "ip",
               "address", "pincode", "city_state", "birth_date", "person_name", "geo"]


def verdict_of(conf):
    return "confirmed" if conf >= 85 else "likely" if conf >= 65 else "possible" if conf >= 40 else "not_personal"


def score_column(table, column, sql_type, values, fk=None, person_table=False, v1=None, ner_counts=None, feedback=None):
    """One column's fused verdict. `values`: sampled values (used here, never returned)."""
    ev, n = [], 0
    counts = {}
    nonnull = [v for v in values if v not in (None, "")]
    n = len(nonnull)
    for v in nonnull:
        for k in classify_value(v, sql_type):
            counts[k] = counts.get(k, 0) + 1
    ratio = lambda k: counts.get(k, 0) / n if n else 0.0
    distinct = len({str(v) for v in nonnull})
    nk = name_kind(column)
    if n and all(isinstance(v, bool) or str(v).lower() in ("true", "false") for v in nonnull):
        r = {"table": table, "column": column, "type": sql_type, "kind": None, "label": None, "category": None, "sensitivity": None, "confidence": 0,
             "verdict": "not_personal", "evidence": [f"all {n} sampled values are true/false flags" + (f", not {_plural(KINDS[nk][0].lower())}" if nk else "")],
             "sampled": n, "distinct": min(distinct, n), "v1": v1, "source": "fused"}
        return _apply_feedback(r, feedback, r["evidence"])
    best, best_r = None, 0.0
    for k in ("email", "upi", "phone", "card", "aadhaar", "pan", "gstin", "passport", "voter_id", "ifsc", "jwt", "password_hash", "payment_ref"):
        if ratio(k) > best_r:
            best, best_r = k, ratio(k)
    # weaker shapes only count when the name or the context agrees
    if not best or best_r < 0.5:
        if nk == "token" and ratio("token") >= 0.6:
            best, best_r = "token", ratio("token")
        elif nk == "ip" and (ratio("ip") + ratio("ip_private")) >= 0.6:
            best, best_r = "ip", ratio("ip") + ratio("ip_private")
        elif nk == "pincode" and ratio("pincode") >= 0.6:
            best, best_r = "pincode", ratio("pincode")
        elif ratio("address") >= 0.5 and (nk in ("address", None, "free_text")):
            best, best_r = "address", ratio("address")
        elif nk == "address" and person_table and ratio("address") >= 0.3:
            best, best_r = "address", ratio("address") + ratio("address_loose")
        elif nk == "address" and person_table and ratio("address_loose") >= 0.6:
            best, best_r = "address", ratio("address_loose")
        elif nk == "payment_ref" and ratio("id_shape") + ratio("payment_ref") >= 0.6:
            best, best_r = "payment_ref", ratio("id_shape") + ratio("payment_ref")
        elif ratio("city_state") >= 0.6 and nk in ("city_state", "address", None):
            best, best_r = "city_state", ratio("city_state")
        elif nk == "birth_date" and ratio("adult_age_date") >= 0.6:
            best, best_r = "birth_date", ratio("adult_age_date")
        elif nk == "person_name" and ratio("name_shape") >= 0.4 and person_table:
            best, best_r = "person_name", ratio("name_shape")
        elif nk == "geo" and ratio("geo_lat") >= 0.6:
            best, best_r = "geo", ratio("geo_lat")
        elif nk == "bank_account" and ratio("bank_account_shape") >= 0.6:
            best, best_r = "bank_account", ratio("bank_account_shape")
    if best == "upi" and nk == "email":
        best = "email"
    if nk == "person_name" and ner_counts:
        pr = sum(1 for p, _ in ner_counts if p) / len(ner_counts)
        if pr > best_r and pr >= 0.3 and (person_table or pr >= 0.6):
            best, best_r = "person_name", pr
            ner_note = f"; the language model reads {round(pr * 100)}% as people's names"
        else:
            ner_note = ""
    else:
        ner_note = ""
    conf, kind = 0, None
    if best and n >= 1 and best_r >= 0.5:
        kind = best
        small = 0 if n >= 5 else 6 if n >= 2 else 12           # fewer values, less certainty
        conf = round(min(99, 62 + 35 * best_r + (5 if nk == best else 0) - small))
        if best == "address" and ratio("address") < 0.3:
            conf = min(conf, 80)
        loose = best == "address" and ratio("address") < 0.3
        ev.append((f"{round(best_r * 100)}% of {n} sampled value{'s' if n != 1 else ''} are shaped like address lines" if loose else
                   f"{round(best_r * 100)}% of {n} sampled value{'s' if n != 1 else ''} match: {KINDS[best][0].lower()}" + _check_note(best))
                  + (" (small sample)" if small else "") + ner_note)
        if nk and nk != best and nk not in ("person_link", "free_text"):
            ev.append(f"named like {KINDS[nk][0].lower()}, but the values say {KINDS[best][0].lower()}")
        elif not nk:
            ev.append("the column name doesn't say so: hidden personal data")
    elif best and n >= 3 and best_r >= 0.15 and nk in ("free_text", None) and best in ("email", "phone", "card", "aadhaar", "pan", "upi"):
        kind = "free_text"
        conf = round(min(95, 70 + 50 * best_r))
        ev.append(f"{round(best_r * 100)}% of {n} sampled texts contain a {KINDS[best][0].lower()}")
    if fk and (not kind or kind == "person_link"):
        kind, conf = "person_link", max(conf, 96)
        ev.append(f"link to {fk}" if "inferred" in fk else f"foreign key to {fk} (a table about people)")
    if nk and not kind:
        if nk == "person_link" and STAFF_LINK.match(column) and not fk:
            kind, conf = "person_link", 50
            ev.append("named like a link to a staff account (who made the change)" + ("; no values yet to check" if not n else "; the values couldn't be matched to user accounts"))
        elif nk == "person_link":
            kind, conf = "person_link", 80 if person_table else 70
            ev.append("named like a link to a customer or user; the values couldn't be matched to a people table")
        elif n == 0:
            kind = nk
            conf = (72 if KINDS[nk][2] == "critical" else 68) if person_table else (58 if KINDS[nk][2] == "critical" else 50)
            ev.append(f"named like {KINDS[nk][0].lower()}" + (" in a table about people" if person_table else "") + "; no values yet to check")
        elif nk == "free_text":
            kind = "free_text"
            texty = ratio("sentence")
            persons = sum(1 for p, _ in (ner_counts or []) if p)
            if ner_counts is not None and persons:
                conf = round(min(95, 72 + 60 * persons / max(1, len(ner_counts))))
                ev.append(f"the language model found people's names in {persons} of {len(ner_counts)} sampled texts")
            elif person_table:
                conf = 66
                ev.append("free text written by or about a person" + (f" ({round(texty * 100)}% are sentences)" if texty else ""))
            else:
                conf = 35
                ev.append("free text, but no personal data found in the sample")
        elif nk == "person_name":
            shape = ratio("name_shape")
            persons = sum(1 for p, _ in (ner_counts or []) if p)
            if ner_counts and persons / max(1, len(ner_counts)) >= 0.4:
                kind, conf = "person_name", round(min(97, 70 + 30 * persons / len(ner_counts)))
                ev.append(f"the language model reads {persons} of {len(ner_counts)} sampled values as people's names")
            elif person_table and shape >= 0.2:
                kind, conf = "person_name", round(68 + 25 * shape)
                ev.append(f"named like a person's name; {round(shape * 100)}% look like names")
            elif person_table:
                kind, conf = "person_name", 60
                ev.append("named like a person's name in a table about people")
            else:
                kind, conf = "person_name", 20
                ev.append("called 'name', but the values aren't people's names (e.g. product names)")
        elif nk in ("city_state",):
            kind, conf = nk, (78 if person_table else 40)
            ev.append("city / state of a person's address" if person_table else "a place, not linked to a person")
        else:
            kind = nk
            conf = 30
            ev.append(f"named like {KINDS[nk][0].lower()}, but none of {n} sampled values match")
    if ner_counts and kind not in ("person_name",) and (kind in (None, "free_text")):
        persons = sum(1 for p, _ in ner_counts if p)
        if persons and kind is None and persons / len(ner_counts) >= 0.3:
            kind, conf = "person_name", round(min(92, 65 + 40 * persons / len(ner_counts)))
            ev.append(f"the language model found people's names in {persons} of {len(ner_counts)} sampled values")
    if kind and distinct == 1 and n >= 5 and kind not in ("person_link",):
        conf = min(conf, 45)
        ev.append("every sampled value is the same (a placeholder?)")
    if v1 and kind is None and n >= 3:
        ev.append(f"v1 flagged it ({v1}) by name; the values don't support it")
    result = {"table": table, "column": column, "type": sql_type, "kind": kind, "label": KINDS[kind][0] if kind else None,
              "category": KINDS[kind][1] if kind else None, "sensitivity": KINDS[kind][2] if kind else None,
              "confidence": int(conf), "verdict": verdict_of(conf) if kind else "not_personal", "evidence": ev,
              "sampled": n, "distinct": min(distinct, n), "v1": v1, "source": "fused"}
    return _apply_feedback(result, feedback, ev)


AUTO_FIELDS = ("kind", "label", "category", "sensitivity", "confidence", "verdict")


def _apply_feedback(result, feedback, ev):
    result["auto"] = {k: result[k] for k in AUTO_FIELDS}            # the engine's own verdict, kept under any admin answer
    result["auto_evidence"] = list(ev)
    if feedback:
        fb_kind = feedback.get("kind") or result["kind"]
        if feedback.get("verdict") == "not_personal":
            result.update(verdict="not_personal", confidence=100, kind=None, label=None, category=None, sensitivity=None)
        else:
            fb_kind = fb_kind if fb_kind in KINDS else (result["kind"] or "free_text")
            result.update(verdict="confirmed", confidence=100, kind=fb_kind, label=KINDS[fb_kind][0], category=KINDS[fb_kind][1], sensitivity=KINDS[fb_kind][2])
        result["evidence"] = [f"{'confirmed' if feedback.get('verdict') != 'not_personal' else 'marked not personal'} by {feedback.get('by', 'an admin')}"
                              + (f": {feedback['note']}" if feedback.get("note") else "")] + ev
        result["feedback"] = {k: feedback.get(k) for k in ("verdict", "kind", "by", "at", "note")}
    return result


def _plural(w):
    return w if w.endswith("s") else w[:-1] + "ies" if w.endswith("y") and not w.endswith(("ay", "ey", "oy")) else w + ("es" if w.endswith(("sh", "ch", "x")) else "s")


def _check_note(kind):
    return {"card": " (Luhn check)", "aadhaar": " (Verhoeff check)", "gstin": " (check character)", "pan": " (holder-type letter)",
            "phone": " (Indian mobile format)", "password_hash": " (bcrypt / argon2 / pbkdf2 shape)", "jwt": " (signed token shape)"}.get(kind, "")
