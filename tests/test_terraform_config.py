"""
Terraform Configuration Tests
==============================
Validates that all required Terraform files and configurations exist
and contain the expected resource definitions. Run with pytest.

Usage:
    pytest tests/test_terraform_config.py -v
"""

import os
import re
import subprocess
import pytest

TERRAFORM_DIR = os.path.join(os.path.dirname(__file__), "..", "terraform")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def read_tf(filename: str) -> str:
    path = os.path.join(TERRAFORM_DIR, filename)
    with open(path) as fh:
        return fh.read()


def tf_files():
    """Return list of .tf filenames in the terraform directory."""
    return [f for f in os.listdir(TERRAFORM_DIR) if f.endswith(".tf")]


# ---------------------------------------------------------------------------
# File-existence tests
# ---------------------------------------------------------------------------

class TestRequiredFilesExist:
    def test_providers_tf(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "providers.tf"))

    def test_variables_tf(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "variables.tf"))

    def test_main_tf(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "main.tf"))

    def test_outputs_tf(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "outputs.tf"))

    def test_tfvars_example(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "terraform.tfvars.example"))

    def test_makefile(self):
        assert os.path.exists(os.path.join(TERRAFORM_DIR, "Makefile"))

    def test_function_code_main(self):
        path = os.path.join(TERRAFORM_DIR, "function_code", "main.py")
        assert os.path.exists(path)

    def test_function_code_requirements(self):
        path = os.path.join(TERRAFORM_DIR, "function_code", "requirements.txt")
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# Provider / version tests
# ---------------------------------------------------------------------------

class TestProvidersConfig:
    def setup_method(self):
        self.content = read_tf("providers.tf")

    def test_requires_google_provider(self):
        assert "hashicorp/google" in self.content

    def test_requires_archive_provider(self):
        assert "hashicorp/archive" in self.content

    def test_requires_random_provider(self):
        assert "hashicorp/random" in self.content

    def test_terraform_version_constraint(self):
        assert "required_version" in self.content

    def test_google_provider_uses_variables(self):
        assert "var.project_id" in self.content
        assert "var.region" in self.content


# ---------------------------------------------------------------------------
# Variables tests
# ---------------------------------------------------------------------------

class TestVariables:
    def setup_method(self):
        self.content = read_tf("variables.tf")

    def test_project_id_variable(self):
        assert 'variable "project_id"' in self.content

    def test_region_variable(self):
        assert 'variable "region"' in self.content

    def test_zone_variable(self):
        assert 'variable "zone"' in self.content


# ---------------------------------------------------------------------------
# Main infrastructure tests
# ---------------------------------------------------------------------------

class TestMainTf:
    def setup_method(self):
        self.content = read_tf("main.tf")

    # Networking
    def test_vpc_defined(self):
        assert "google_compute_network" in self.content

    def test_public_subnet_defined(self):
        assert "google_compute_subnetwork" in self.content

    def test_firewall_allows_http(self):
        assert '"80"' in self.content or '"80", "443"' in self.content or "80" in self.content

    def test_open_ssh_firewall(self):
        """SSH should be open from anywhere (intentional vuln)."""
        assert '"22"' in self.content or "22" in self.content
        assert "0.0.0.0/0" in self.content

    # Compute
    def test_web_server_instance(self):
        assert 'google_compute_instance' in self.content
        assert "web_server" in self.content

    def test_db_server_instance(self):
        assert "db_server" in self.content

    # IAM — overprivileged service account
    def test_overprivileged_sa_defined(self):
        assert "google_service_account" in self.content
        assert "overprivileged" in self.content

    def test_owner_role_granted(self):
        assert "roles/owner" in self.content

    def test_sa_key_created(self):
        assert "google_service_account_key" in self.content

    # Storage
    def test_vulnerable_bucket_defined(self):
        assert "google_storage_bucket" in self.content
        assert "vulnerable" in self.content

    def test_public_bucket_iam(self):
        """Bucket must be world-readable (intentional vuln)."""
        assert "allUsers" in self.content

    # Cloud Function
    def test_cloud_function_defined(self):
        assert "google_cloudfunctions_function" in self.content

    def test_cloud_function_python_runtime(self):
        assert "python39" in self.content or "python3" in self.content

    def test_cloud_function_public_invoker(self):
        assert "cloudfunctions.invoker" in self.content

    # Cloud Run
    def test_cloud_run_defined(self):
        assert "google_cloud_run_service" in self.content

    def test_cloud_run_public_invoker(self):
        assert "run.invoker" in self.content

    # Secret Manager
    def test_secret_manager_secret(self):
        assert "google_secret_manager_secret" in self.content


# ---------------------------------------------------------------------------
# Outputs tests
# ---------------------------------------------------------------------------

class TestOutputs:
    def setup_method(self):
        self.content = read_tf("outputs.tf")

    def test_web_server_ip_output(self):
        assert "web_server_ip" in self.content

    def test_cloud_function_url_output(self):
        assert "cloud_function_url" in self.content

    def test_cloud_run_url_output(self):
        assert "cloud_run_url" in self.content

    def test_vulnerable_bucket_url_output(self):
        assert "vulnerable_bucket_url" in self.content

    def test_overprivileged_sa_output(self):
        assert "overprivileged_sa_email" in self.content

    def test_lab_summary_output(self):
        assert "lab_summary" in self.content

    def test_dvwa_url_output(self):
        assert "dvwa_url" in self.content


# ---------------------------------------------------------------------------
# Function code tests
# ---------------------------------------------------------------------------

class TestFunctionCode:
    def setup_method(self):
        path = os.path.join(TERRAFORM_DIR, "function_code", "main.py")
        with open(path) as fh:
            self.content = fh.read()

    def test_ssrf_endpoint(self):
        assert "url" in self.content
        assert "urlopen" in self.content

    def test_rce_endpoint(self):
        assert "cmd" in self.content
        assert "subprocess" in self.content
        assert "shell=True" in self.content

    def test_env_dump_endpoint(self):
        assert "os.environ" in self.content

    def test_path_traversal_endpoint(self):
        assert "file" in self.content
        assert "open(path)" in self.content

    def test_requirements_file_has_flask(self):
        req_path = os.path.join(TERRAFORM_DIR, "function_code", "requirements.txt")
        with open(req_path) as fh:
            content = fh.read()
        assert "flask" in content.lower()
        assert "functions-framework" in content.lower()


# ---------------------------------------------------------------------------
# tfvars.example tests
# ---------------------------------------------------------------------------

class TestTfvarsExample:
    def setup_method(self):
        path = os.path.join(TERRAFORM_DIR, "terraform.tfvars.example")
        with open(path) as fh:
            self.content = fh.read()

    def test_project_id_placeholder(self):
        assert "project_id" in self.content

    def test_region_placeholder(self):
        assert "region" in self.content

    def test_no_real_project_id(self):
        """Must not contain a real GCP project ID."""
        assert "your-gcp-project-id" in self.content


# ---------------------------------------------------------------------------
# Terraform validate (requires terraform CLI and gcloud auth)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    subprocess.run(["which", "terraform"], capture_output=True).returncode != 0,
    reason="terraform CLI not found",
)
class TestTerraformValidate:
    def test_terraform_validate(self):
        """Runs 'terraform validate' — requires terraform init first."""
        result = subprocess.run(
            ["terraform", "validate"],
            cwd=TERRAFORM_DIR,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"terraform validate failed:\n{result.stdout}\n{result.stderr}"
