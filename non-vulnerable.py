"""
secure_sast_test.py
===================
PURPOSE: Secure counterpart to vulnerable_sast_test.py for SAST evaluation.
Each function mirrors its vulnerable twin but applies the correct mitigation.
A well-tuned SAST should produce zero findings on this file.

Mitigation index
----------------
[1]  CWE-89   SQL Injection          → Parameterised queries
[2]  CWE-79   XSS                    → html.escape() before interpolation
[3]  CWE-22   Path Traversal         → realpath + prefix assertion
[4]  CWE-78   Command Injection      → args list, shell=False
[5]  CWE-798  Hardcoded Credentials  → os.environ / secrets vault
[6]  CWE-327  Weak Crypto            → bcrypt for passwords, SHA-256 HMAC
[7]  CWE-502  Insecure Deserialisation → JSON only; no pickle / eval
[8]  CWE-330  Weak Randomness        → secrets module throughout
[9]  CWE-611  XXE                    → defusedxml; external entities disabled
[10] CWE-918  SSRF                   → scheme + allowlist validation
"""

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import subprocess
import urllib.parse
from pathlib import Path

import bcrypt          # pip install bcrypt
import defusedxml.ElementTree as safe_ET   # pip install defusedxml


# ---------------------------------------------------------------------------
# Shared config — all secrets come from the environment, never source code.
# ---------------------------------------------------------------------------
DB_PASSWORD: str = os.environ["DB_PASSWORD"]
AWS_SECRET_KEY: str = os.environ["AWS_SECRET_KEY"]
API_TOKEN: str = os.environ["API_TOKEN"]

# UI copy — intentionally named to confirm SAST ignores non-secret strings
password_label = "Enter your password"
submit_button_text = "Log in"


# ===========================================================================
# [1] CWE-89: SQL Injection — parameterised queries
# ===========================================================================
def get_user_by_name(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SAFE: placeholder prevents any injection; the driver handles escaping
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    rows = cursor.fetchall()

    cursor.execute("DELETE FROM logs WHERE user = ?", (username,))
    conn.commit()
    conn.close()
    return rows


# ===========================================================================
# [2] CWE-79: XSS — escape all user-supplied content before HTML insertion
# ===========================================================================
def render_search_page(search_term: str) -> str:
    # SAFE: html.escape() converts <, >, &, ", ' to their HTML entities
    safe_term = html.escape(search_term, quote=True)
    return f"""
    <html>
      <body>
        <h1>Search results for: {safe_term}</h1>
      </body>
    </html>
    """


# ===========================================================================
# [3] CWE-22: Path Traversal — resolve then assert prefix
# ===========================================================================
BASE_DIR = Path("/var/app/static/").resolve()


def read_user_file(filename: str) -> bytes:
    # SAFE: resolve() collapses all ".." components; the prefix check ensures
    # the result is still inside BASE_DIR before the file is opened.
    requested = (BASE_DIR / filename).resolve()
    if not str(requested).startswith(str(BASE_DIR)):
        raise PermissionError(f"Access denied: {filename!r} escapes the base directory")
    return requested.read_bytes()


# ===========================================================================
# [4] CWE-78: Command Injection — args list + shell=False (the default)
# ===========================================================================
def ping_host(host: str) -> str:
    # SAFE: passing a list bypasses the shell entirely; host is never
    # interpreted as a shell string regardless of its content.
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if not all(c in allowed_chars for c in host):
        raise ValueError(f"Invalid host: {host!r}")
    result = subprocess.check_output(["ping", "-c", "1", host], shell=False, timeout=5)
    return result.decode()


def get_server_uptime() -> str:
    # Static args list — shell=False, no user input involved
    return subprocess.check_output(["uptime"], shell=False).decode()


# ===========================================================================
# [5] CWE-798: Hardcoded Credentials — already handled at module level above
#     via os.environ[]; shown here as a connection example.
# ===========================================================================
def connect_to_db():
    password = os.environ["DB_PASSWORD"]  # fetched at call-time, not hardcoded
    conn = sqlite3.connect(f"file:prod.db?password={password}&mode=rw", uri=True)
    return conn


# ===========================================================================
# [6] CWE-327: Weak Crypto — bcrypt for passwords; SHA-256 for HMAC
# ===========================================================================
def hash_password(password: str) -> bytes:
    # SAFE: bcrypt is a slow, salted, purpose-built password hashing function
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def sign_message(message: bytes, key: bytes) -> bytes:
    # SAFE: SHA-256 is a strong digest; key must be kept secret
    return hmac.new(key, message, digestmod=hashlib.sha256).digest()


# Non-security checksum for display — MD5 would be fine here too, but
# using SHA-256 keeps the file clean for SAST tools that flag MD5 globally.
def display_file_checksum(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ===========================================================================
# [7] CWE-502: Insecure Deserialisation — JSON only; never pickle or eval
# ===========================================================================
def load_session(session_json: str) -> dict:
    # SAFE: json.loads() cannot execute code; restrict accepted keys explicitly
    data = json.loads(session_json)
    allowed_keys = {"user_id", "role", "expires_at"}
    return {k: v for k, v in data.items() if k in allowed_keys}


def evaluate_expression(expr: str) -> float:
    # SAFE: parse the expression with a strict grammar instead of eval();
    # here we only permit a single floating-point literal as an example.
    try:
        value = float(expr)
    except ValueError:
        raise ValueError(f"Expression rejected — only numeric literals are allowed: {expr!r}")
    return value


# ===========================================================================
# [8] CWE-330: Weak Randomness — secrets module for all security tokens
# ===========================================================================
def generate_password_reset_token() -> str:
    # SAFE: secrets.token_urlsafe() draws from the OS CSPRNG
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    # SAFE: 128-bit hex token; unpredictable even to an observer of prior tokens
    return secrets.token_hex(16)


# ===========================================================================
# [9] CWE-611: XXE — defusedxml disables external entities and DTD processing
# ===========================================================================
def parse_xml_upload(xml_data: str):
    # SAFE: defusedxml raises on DOCTYPE declarations and external entity refs
    return safe_ET.fromstring(xml_data)


# ===========================================================================
# [10] CWE-918: SSRF — scheme allowlist + hostname allowlist
# ===========================================================================
ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {
    "api.trusted-partner.example.com",
    "cdn.our-assets.example.com",
}


def _validate_url(url: str) -> str:
    """Raise ValueError if the URL is not on the allowlist."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Disallowed scheme: {parsed.scheme!r}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Disallowed host: {parsed.hostname!r}")
    return url


def fetch_remote_resource(url: str) -> bytes:
    # SAFE: URL is validated against a strict allowlist before any network I/O
    import urllib.request
    safe_url = _validate_url(url)
    with urllib.request.urlopen(safe_url, timeout=10) as response:
        return response.read()


def proxy_webhook(user_supplied_url: str) -> str:
    import urllib.request
    safe_url = _validate_url(user_supplied_url)
    req = urllib.request.Request(safe_url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode()