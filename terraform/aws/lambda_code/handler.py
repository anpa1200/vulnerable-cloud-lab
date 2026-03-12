"""
Intentionally vulnerable Lambda function for security training.
DO NOT deploy in production.

Vulnerabilities demonstrated:
  - SSRF via ?url= (includes access to IMDSv1 at 169.254.169.254)
  - RCE via ?cmd= (shell=True, no sanitisation)
  - Environment variable dump via ?env=1 (exposes hardcoded credentials)
  - Path traversal via ?file= (reads arbitrary files)
"""
import json
import os
import subprocess
import urllib.request


def handler(event, context):
    params = (event.get("queryStringParameters") or {})

    # SSRF — fetch any URL including http://169.254.169.254/...
    if "url" in params:
        try:
            req = urllib.request.Request(
                params["url"],
                headers={"X-Forwarded-For": "127.0.0.1"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            return {"statusCode": 200, "body": body}
        except Exception as e:
            return {"statusCode": 500, "body": str(e)}

    # RCE — direct shell execution
    if "cmd" in params:
        try:
            result = subprocess.run(
                params["cmd"], shell=True,
                capture_output=True, text=True, timeout=10,
            )
            return {"statusCode": 200, "body": result.stdout + result.stderr}
        except Exception as e:
            return {"statusCode": 500, "body": str(e)}

    # Environment variable dump — exposes DB_URL, API_KEY, SECRET_TOKEN, etc.
    if "env" in params:
        return {"statusCode": 200, "body": json.dumps(dict(os.environ), indent=2)}

    # Path traversal — reads any file the runtime process can access
    if "file" in params:
        try:
            with open(params["file"]) as fh:
                return {"statusCode": 200, "body": fh.read()}
        except Exception as e:
            return {"statusCode": 500, "body": str(e)}

    return {
        "statusCode": 200,
        "body": (
            "Vulnerable Lambda — try:\n"
            "  ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  ?cmd=id\n"
            "  ?env=1\n"
            "  ?file=/etc/passwd\n"
        ),
    }
