"""
Intentionally Vulnerable Cloud Function
========================================
WARNING: This code contains deliberate vulnerabilities for security training.
DO NOT deploy in production environments.

Vulnerabilities present:
  - SSRF  (Server-Side Request Forgery) via ?url=
  - RCE   (Remote Code Execution) via ?cmd=
  - Environment variable disclosure via ?env=
  - Secret disclosure via ?secret=
  - Path traversal via ?file=
"""
import os
import json
import subprocess
import urllib.request
from flask import Request


def vulnerable_handler(request: Request):
    """Entry point for the Cloud Function."""

    # ── SSRF ── No URL validation whatsoever
    if "url" in request.args:
        url = request.args.get("url", "")
        try:
            # Allows fetching GCP metadata: http://metadata.google.internal/...
            resp = urllib.request.urlopen(url, timeout=5)
            return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return f"Error fetching URL: {exc}", 500

    # ── RCE ── Direct shell execution, no sanitisation
    if "cmd" in request.args:
        cmd = request.args.get("cmd", "")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout + result.stderr
        except Exception as exc:
            return f"Error running command: {exc}", 500

    # ── Environment variable dump ──
    if "env" in request.args:
        return json.dumps(dict(os.environ), indent=2)

    # ── Single secret disclosure ──
    if "secret" in request.args:
        key = request.args.get("secret", "SECRET_KEY")
        return os.environ.get(key, f"Variable '{key}' not found")

    # ── Path traversal (reads files from the function's filesystem) ──
    if "file" in request.args:
        path = request.args.get("file", "")
        try:
            with open(path) as fh:
                return fh.read()
        except Exception as exc:
            return f"Error reading file: {exc}", 500

    # ── Default — endpoint documentation (information disclosure) ──
    return """
<h1>Vulnerable Cloud Function</h1>
<p>Available endpoints (all intentionally insecure):</p>
<ul>
  <li><code>?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token</code> &mdash; SSRF</li>
  <li><code>?cmd=id</code> &mdash; Command injection (RCE)</li>
  <li><code>?env=1</code> &mdash; Dump all environment variables</li>
  <li><code>?secret=SECRET_KEY</code> &mdash; Read a specific env var</li>
  <li><code>?file=/etc/passwd</code> &mdash; Path traversal / file read</li>
</ul>
<p><em>For pentest lab use only.</em></p>
"""
