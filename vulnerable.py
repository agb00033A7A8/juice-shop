"""
vulnerable_sast_test.py
=======================
PURPOSE: Intentionally vulnerable code for SAST tool evaluation.
DO NOT deploy or execute in any real environment.

Each vulnerability is tagged with its CWE ID and a brief description
so you can verify whether your SAST tool correctly identifies it.

Vulnerability index
-------------------
[1]  CWE-89   SQL Injection
[2]  CWE-79   Cross-Site Scripting (XSS) — reflected
[3]  CWE-22   Path Traversal
[4]  CWE-78   OS Command Injection
[5]  CWE-798  Hardcoded Credentials
[6]  CWE-327  Use of Broken / Weak Cryptographic Algorithm (MD5, DES)
[7]  CWE-502  Insecure Deserialization (pickle, eval)
[8]  CWE-330  Use of Insufficiently Random Values (random module for tokens)
[9]  CWE-611  XML External Entity (XXE) Injection
[10] CWE-918  Server-Side Request Forgery (SSRF)

False-positive bait (should NOT fire)
--------------------------------------
[FP-1] Variable named `password_label` containing UI text, not a credential
[FP-2] MD5 used only for a non-security checksum (file integrity display)
[FP-3] subprocess call with a fully static, hard-coded argument list
"""

import hashlib
import hmac
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from hashlib import md5

# ---------------------------------------------------------------------------
# [FP-1] FALSE-POSITIVE BAIT — should NOT trigger a hardcoded-secret finding.
# This is a UI label string, not an actual credential.
# ---------------------------------------------------------------------------
password_label = "Enter your password"
submit_button_text = "Log in"


# ===========================================================================
# [1] CWE-89: SQL Injection
#     User-supplied input is concatenated directly into a SQL query string.
#     A SAST tool should flag the string formatting inside execute().
# ===========================================================================
def get_user_by_name(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULN: direct string interpolation — attacker can inject arbitrary SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    # ALSO VULN: f-string variant to give SAST a second pattern to catch
    cursor.execute(f"DELETE FROM logs WHERE user = '{username}'")

    return cursor.fetchall()


# ===========================================================================
# [2] CWE-79: Cross-Site Scripting (XSS) — reflected
#     User input is written directly into an HTML response without escaping.
# ===========================================================================
def render_search_page(search_term: str) -> str:
    # VULN: search_term injected into HTML with no sanitisation
    html = f"""
    <html>
      <body>
        <h1>Search results for: {search_term}</h1>
      </body>
    </html>
    """
    return html


# ===========================================================================
# [3] CWE-22: Path Traversal
#     The filename from the request is used without stripping "../" sequences.
# ===========================================================================
BASE_DIR = "/var/app/static/"


def read_user_file(filename: str) -> bytes:
    # VULN: no os.path.basename() or realpath() check; "../../etc/passwd" works
    full_path = os.path.join(BASE_DIR, filename)
    with open(full_path, "rb") as f:
        return f.read()


# ===========================================================================
# [4] CWE-78: OS Command Injection
#     User-controlled data is passed to a shell via shell=True.
# ===========================================================================
def ping_host(host: str) -> str:
    # VULN: host could be "8.8.8.8; rm -rf /" — shell=True makes this dangerous
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result.decode()


# [FP-3] FALSE-POSITIVE BAIT — fully static args list, no user input.
#         A good SAST should NOT flag this as command injection.
def get_server_uptime() -> str:
    result = subprocess.check_output(["uptime"], shell=False)
    return result.decode()


# ===========================================================================
# [5] CWE-798: Hardcoded Credentials
#     Secret material embedded directly in source code.
# ===========================================================================
DB_PASSWORD = "Sup3rS3cr3tP@ssw0rd!"          # VULN: hardcoded DB password
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULN: AWS key
API_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"         # VULN: GitHub PAT


def connect_to_db():
    # VULN: password literal passed straight to connection call
    conn = sqlite3.connect(f"file:prod.db?password={DB_PASSWORD}&mode=rw", uri=True)
    return conn


# ===========================================================================
# [6] CWE-327: Use of a Broken or Risky Cryptographic Algorithm
#     MD5 and single-DES are considered cryptographically broken.
# ===========================================================================
def hash_password(password: str) -> str:
    # VULN: MD5 is not collision-resistant and must not be used for passwords
    return md5(password.encode()).hexdigest()


def sign_message(message: bytes, key: bytes) -> bytes:
    # VULN: MD5 as the HMAC digest is weak; SHA-256 should be used instead
    return hmac.new(key, message, digestmod=hashlib.md5).digest()


# [FP-2] FALSE-POSITIVE BAIT — MD5 used only for a non-security file checksum
#         displayed in a UI. A smart SAST should down-rank or skip this.
def display_file_checksum(path: str) -> str:
    with open(path, "rb") as f:
        return md5(f.read()).hexdigest()


# ===========================================================================
# [7] CWE-502: Deserialization of Untrusted Data
#     pickle.loads() and eval() on attacker-supplied bytes/strings.
# ===========================================================================
def load_session(session_bytes: bytes):
    # VULN: pickle can execute arbitrary code during deserialisation
    return pickle.loads(session_bytes)


def evaluate_expression(expr: str):
    # VULN: eval() on user input allows arbitrary code execution
    return eval(expr)


# ===========================================================================
# [8] CWE-330: Use of Insufficiently Random Values
#     The random module is not cryptographically secure; use secrets instead.
# ===========================================================================
def generate_password_reset_token() -> str:
    # VULN: random.choices() is predictable; use secrets.token_urlsafe()
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choices(chars, k=32))


def generate_session_id() -> int:
    # VULN: random.randint() is not suitable for security-sensitive IDs
    return random.randint(100000, 999999)


# ===========================================================================
# [9] CWE-611: XML External Entity (XXE) Injection
#     xml.etree.ElementTree does NOT expand external entities by default,
#     but lxml does when resolve_entities=True (shown below).
#     Many SAST tools also flag ET.fromstring on untrusted input.
# ===========================================================================
def parse_xml_upload(xml_data: str):
    # VULN (lxml pattern): using lxml with resolve_entities=True
    # Shown as a comment so the file is runnable without lxml installed,
    # but a SAST should still detect the pattern if lxml is in scope.
    #
    #   from lxml import etree
    #   parser = etree.XMLParser(resolve_entities=True)   # VULN
    #   return etree.fromstring(xml_data.encode(), parser)

    # Also flag-worthy: ET.fromstring on raw untrusted network input
    return ET.fromstring(xml_data)  # VULN: no input validation before parsing


# ===========================================================================
# [10] CWE-918: Server-Side Request Forgery (SSRF)
#      The application fetches a URL that is entirely controlled by the user.
# ===========================================================================
def fetch_remote_resource(url: str) -> bytes:
    # VULN: no allowlist or scheme check; attacker can request
    # internal services, cloud metadata endpoints, etc.
    with urllib.request.urlopen(url) as response:
        return response.read()


def proxy_webhook(user_supplied_url: str) -> str:
    # VULN: same pattern, using requests-style urllib wrapper
    req = urllib.request.Request(user_supplied_url)
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode()