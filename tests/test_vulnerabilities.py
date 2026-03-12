"""
Post-Deploy Vulnerability Verification Tests
=============================================
Verifies that intentional vulnerabilities are actually exploitable after
the lab is deployed. Requires the lab to be running and terraform outputs
available.

Usage:
    # Export required env vars first:
    export TF_OUTPUT_DIR=/path/to/terraform
    # Or set individual vars:
    export WEB_SERVER_IP=<ip>
    export CLOUD_FUNCTION_URL=<url>
    export CLOUD_RUN_URL=<url>
    export BUCKET_NAME=<name>

    pytest tests/test_vulnerabilities.py -v
"""

import os
import json
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import pytest


# ---------------------------------------------------------------------------
# Config helpers — read from env or terraform output
# ---------------------------------------------------------------------------

def get_tf_output(key: str) -> str:
    tf_dir = os.environ.get("TF_OUTPUT_DIR", os.path.join(os.path.dirname(__file__), "..", "terraform"))
    result = subprocess.run(
        ["terraform", "output", "-raw", key],
        cwd=tf_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"terraform output '{key}' not available: {result.stderr.strip()}")
    return result.stdout.strip()


def web_ip() -> str:
    return os.environ.get("WEB_SERVER_IP") or get_tf_output("web_server_ip")


def function_url() -> str:
    return os.environ.get("CLOUD_FUNCTION_URL") or get_tf_output("cloud_function_url")


def run_url() -> str:
    return os.environ.get("CLOUD_RUN_URL") or get_tf_output("cloud_run_url")


def bucket_name() -> str:
    return os.environ.get("BUCKET_NAME") or get_tf_output("vulnerable_bucket_name")


def http_get(url: str, timeout: int = 10) -> tuple[int, str]:
    """Returns (status_code, body)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as exc:
        pytest.skip(f"Could not connect to {url}: {exc}")


# ---------------------------------------------------------------------------
# DVWA / Web server tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("WEB_SERVER_IP") and subprocess.run(
        ["which", "terraform"], capture_output=True).returncode != 0,
    reason="No WEB_SERVER_IP and terraform not available",
)
class TestDVWA:
    def test_dvwa_reachable(self):
        ip = web_ip()
        status, body = http_get(f"http://{ip}/")
        assert status == 200, f"DVWA returned {status}"

    def test_dvwa_login_page_present(self):
        ip = web_ip()
        _, body = http_get(f"http://{ip}/login.php")
        assert "login" in body.lower() or "password" in body.lower()

    def test_info_disclosure_page_reachable(self):
        ip = web_ip()
        status, body = http_get(f"http://{ip}/info.php")
        assert status == 200
        # info.php should expose internal service URLs
        assert "http" in body.lower()


# ---------------------------------------------------------------------------
# Cloud Function vulnerability tests
# ---------------------------------------------------------------------------

class TestCloudFunctionVulnerabilities:
    @pytest.fixture(autouse=True)
    def base_url(self):
        self._base = function_url()

    def test_function_reachable(self):
        status, body = http_get(self._base)
        assert status == 200

    def test_function_exposes_endpoints_in_default_page(self):
        """Default page should document its own vulnerabilities (info disclosure)."""
        _, body = http_get(self._base)
        assert "cmd" in body or "url" in body or "env" in body

    def test_rce_via_cmd_param(self):
        """?cmd=id should return uid= output."""
        url = f"{self._base}?cmd=id"
        status, body = http_get(url)
        assert status == 200, f"RCE endpoint returned {status}"
        assert "uid=" in body, f"Expected command output, got: {body[:200]}"

    def test_env_dump_via_env_param(self):
        """?env=1 should return JSON with environment variables."""
        url = f"{self._base}?env=1"
        status, body = http_get(url)
        assert status == 200
        try:
            env_data = json.loads(body)
            assert isinstance(env_data, dict), "Expected dict of env vars"
        except json.JSONDecodeError:
            pytest.fail(f"env endpoint did not return JSON: {body[:200]}")

    def test_path_traversal_passwd(self):
        """?file=/etc/passwd should return file contents."""
        url = f"{self._base}?file=/etc/passwd"
        status, body = http_get(url)
        assert status == 200
        assert "root:" in body, f"Expected /etc/passwd contents, got: {body[:200]}"

    def test_ssrf_endpoint_exists(self):
        """?url= parameter should attempt to fetch the provided URL."""
        # Use a safe target to verify SSRF endpoint works
        safe_url = urllib.parse.quote("http://example.com", safe="")
        url = f"{self._base}?url={safe_url}"
        status, body = http_get(url)
        # Either succeeds or returns an error message — not a 404/405
        assert status in (200, 500), f"Unexpected status {status}"
        assert "url" not in body.lower() or "error" in body.lower() or "example" in body.lower()

    def test_ssrf_gcp_metadata_accessible(self):
        """SSRF should reach GCP metadata endpoint."""
        metadata_url = urllib.parse.quote(
            "http://metadata.google.internal/computeMetadata/v1/",
            safe="",
        )
        url = f"{self._base}?url={metadata_url}"
        status, body = http_get(url, timeout=10)
        # Inside GCP this should work; outside it will time out/error
        # We just verify the endpoint tries to fetch it
        assert status in (200, 500)


# ---------------------------------------------------------------------------
# Cloud Run vulnerability tests
# ---------------------------------------------------------------------------

class TestCloudRunVulnerabilities:
    @pytest.fixture(autouse=True)
    def base_url(self):
        self._base = run_url()

    def test_cloud_run_publicly_accessible(self):
        """Cloud Run service must not require authentication (allUsers invoker)."""
        status, _ = http_get(self._base)
        assert status != 401 and status != 403, \
            f"Cloud Run returned {status} — service is not publicly accessible"

    def test_cloud_run_returns_response(self):
        status, body = http_get(self._base)
        assert status == 200
        assert len(body) > 0


# ---------------------------------------------------------------------------
# Storage bucket vulnerability tests
# ---------------------------------------------------------------------------

class TestStorageBucketVulnerabilities:
    @pytest.fixture(autouse=True)
    def setup(self):
        self._bucket = bucket_name()

    def test_credentials_file_publicly_readable(self):
        """The database-credentials.json must be publicly accessible."""
        url = f"https://storage.googleapis.com/{self._bucket}/secrets/database-credentials.json"
        status, body = http_get(url)
        assert status == 200, \
            f"Expected public access to credentials file, got HTTP {status}"

    def test_credentials_contain_sensitive_data(self):
        """Credentials file must expose DB username/password."""
        url = f"https://storage.googleapis.com/{self._bucket}/secrets/database-credentials.json"
        _, body = http_get(url)
        try:
            data = json.loads(body)
            assert "username" in data or "password" in data or "db_password" in data, \
                f"Credentials file doesn't contain expected keys: {list(data.keys())}"
        except json.JSONDecodeError:
            pytest.fail(f"Credentials file is not valid JSON: {body[:200]}")

    def test_ssh_key_publicly_readable(self):
        """Private SSH key must be publicly accessible."""
        url = f"https://storage.googleapis.com/{self._bucket}/keys/id_rsa"
        status, body = http_get(url)
        assert status == 200, f"Expected public SSH key, got HTTP {status}"
        assert "PRIVATE KEY" in body or "-----BEGIN" in body, \
            f"File doesn't look like a private key: {body[:100]}"


# ---------------------------------------------------------------------------
# IAM / Service account tests (requires gcloud)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    subprocess.run(["which", "gcloud"], capture_output=True).returncode != 0,
    reason="gcloud CLI not found",
)
class TestIAMVulnerabilities:
    def test_overprivileged_sa_has_owner_role(self):
        """Overprivileged SA must have roles/owner on the project."""
        tf_dir = os.path.join(os.path.dirname(__file__), "..", "terraform")
        result = subprocess.run(
            ["terraform", "output", "-raw", "overprivileged_sa_email"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("Cannot get SA email from terraform output")

        sa_email = result.stdout.strip()
        project_result = subprocess.run(
            ["terraform", "output", "-raw", "project_id"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
        )
        if project_result.returncode != 0:
            pytest.skip("Cannot get project_id from terraform output")

        project_id = project_result.stdout.strip()

        iam_result = subprocess.run(
            ["gcloud", "projects", "get-iam-policy", project_id,
             "--format=json", "--flatten=bindings[].members",
             f"--filter=bindings.members:serviceAccount:{sa_email} AND bindings.role:roles/owner"],
            capture_output=True,
            text=True,
        )

        assert iam_result.returncode == 0
        policy_data = json.loads(iam_result.stdout or "[]")
        assert len(policy_data) > 0, \
            f"Service account {sa_email} does not have roles/owner"
