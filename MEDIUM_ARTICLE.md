# I Built a Fully Automated GCP Pentest Lab That Audits Itself With AI — And You Can Too

*How to deploy a deliberately vulnerable Google Cloud environment, scan it with an AI-powered security tool, and get a prioritized attack chain report — all from a single command*

---

## Table of Contents

1. [The Problem With Learning Cloud Security](#the-problem-with-learning-cloud-security)
2. [What We're Building](#what-were-building)
3. [Part 1: The Vulnerable GCP Lab](#part-1-the-vulnerable-gcp-lab)
   - [What's Deployed](#whats-deployed)
   - [The Attack Surface at a Glance](#the-attack-surface-at-a-glance)
4. [Part 2: StratusAI — The Scanner](#part-2-stratusai--the-scanner)
   - [How the AI Analysis Works](#how-the-ai-analysis-works)
5. [Part 3: Running the Full Audit](#part-3-running-the-full-audit)
   - [Interactive Setup](#interactive-setup-2-minutes)
   - [Terraform Deployment](#terraform-deployment-8-minutes)
   - [Internal GCP Scan](#internal-gcp-scan-4-minutes)
   - [External Scans](#external-scans-6-minutes-total-3-targets)
   - [The Report](#the-report)
   - [Teardown](#teardown)
6. [What the AI Actually Finds](#what-the-ai-actually-finds)
7. [The Architecture Decisions Worth Stealing](#the-architecture-decisions-worth-stealing)
8. [Running It Against Your Own GCP Project](#running-it-against-your-own-gcp-project)
9. [What's Next](#whats-next)
10. [Getting Started (TL;DR)](#getting-started-tldr)

---

## The Problem With Learning Cloud Security

Cloud security is hard to practice. You can't run SQL injection against someone else's database. You can't test SSRF against a production metadata server. You can't enumerate IAM misconfigurations in an account you don't own.

Most security courses hand you a checklist: "Check if your S3 bucket is public. Check if root MFA is enabled." That teaches you *what to look for*, not *how to find it*, and certainly not *what an attacker does next*.

What I wanted was a realistic GCP environment where:
- Everything is intentionally broken
- I can run real tools against real infrastructure
- The tool explains not just *what's wrong* but *how the findings chain together into full compromises*
- The whole thing tears itself down when I'm done

So I built it. Two open-source repositories, one shell script, and about 15 minutes to a fully deployed vulnerable GCP lab with an AI-generated security report.

Here's everything.

---

## What We're Building

The system has three parts:

```
┌─────────────────────────────────────────────────────────────────┐
│  vulnerable-cloud-lab                                           │
│  Terraform → deploys intentionally broken GCP infrastructure   │
│                                                                 │
│  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌─────────┐  │
│  │   DVWA   │  │  Cloud     │  │  Cloud Run   │  │ Public  │  │
│  │  (SSH    │  │  Function  │  │  (hardcoded  │  │ Storage │  │
│  │  open)   │  │  SSRF/RCE  │  │  DB creds)   │  │ Bucket  │  │
│  └──────────┘  └────────────┘  └──────────────┘  └─────────┘  │
│                                                                 │
│  + Overprivileged Service Account with roles/owner             │
│  + SA key exposed in metadata AND Secret Manager               │
│  + No audit logging, no VPC flow logs                          │
└───────────────────────────┬─────────────────────────────────────┘
                            │  terraform output (IPs, URLs)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  stratus-ai                                                     │
│  Docker container → scans, sends to Claude, generates reports  │
│                                                                 │
│  Internal mode (GCP API):    External mode (network):          │
│  ├─ gcp_iam                  ├─ Port scan (nmap)               │
│  ├─ gcp_compute              ├─ TLS/SSL analysis               │
│  ├─ gcp_storage              ├─ HTTP security headers          │
│  ├─ gcp_cloudfunctions       └─ DNS (SPF/DMARC/DNSSEC)         │
│  ├─ gcp_cloudrun                                               │
│  ├─ gcp_secretmanager           AI Analysis (Claude):          │
│  └─ gcp_logging              ├─ Per-module findings            │
│                              ├─ Attack chain synthesis         │
│                              └─ Prioritized remediation        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  full_audit.sh (in vulnerable-cloud-lab)                       │
│  Orchestrates the entire workflow end-to-end                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 1: The Vulnerable GCP Lab

### What's Deployed

The Terraform configuration in [vulnerable-cloud-lab](https://github.com/anpa1200/vulnerable-cloud-lab) deploys a complete, intentionally broken GCP environment:

**Compute (DVWA + Database)**
```hcl
resource "google_compute_instance" "web_server" {
  name         = "dvwa-web-server-${random_id.suffix.hex}"
  machine_type = "e2-medium"

  service_account {
    email  = google_service_account.overprivileged_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    # Intentional vuln: SA key embedded in instance metadata
    sa-key               = base64encode(google_service_account_key.exposed_key.private_key)
    startup-script       = local.dvwa_startup_script
  }
}
```

The web server runs [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) — a PHP/MySQL application with every classic web vulnerability enabled. But the interesting stuff is in the cloud layer.

**The Overprivileged Service Account**
```hcl
resource "google_project_iam_member" "overprivileged_owner" {
  role   = "roles/owner"
  member = "serviceAccount:${google_service_account.overprivileged_sa.email}"
}

# ...plus compute.admin, storage.admin, secretmanager.admin, iam.securityAdmin
```

This is the SA the web server runs as. If you can reach the metadata server from inside a compromised app, you own the project.

**The Cloud Function (SSRF + RCE + Env Dump + Path Traversal)**

```python
def vulnerable_handler(request: Request):
    # SSRF — fetch anything, including http://metadata.google.internal/...
    if "url" in request.args:
        resp = urllib.request.urlopen(request.args["url"], timeout=5)
        return resp.read().decode("utf-8", errors="replace")

    # RCE — direct shell execution
    if "cmd" in request.args:
        result = subprocess.run(request.args["cmd"], shell=True,
                                capture_output=True, text=True, timeout=10)
        return result.stdout + result.stderr

    # Environment variable dump
    if "env" in request.args:
        return json.dumps(dict(os.environ), indent=2)

    # Path traversal
    if "file" in request.args:
        with open(request.args["file"]) as fh:
            return fh.read()
```

This function is publicly invokable (`allUsers` has `roles/cloudfunctions.invoker`). One URL is all it takes.

**The Public Bucket**
```hcl
resource "google_storage_bucket_iam_member" "public_viewer" {
  bucket = google_storage_bucket.vulnerable_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

The bucket contains `secrets/database-credentials.json` and `keys/id_rsa`. Both world-readable. No questions asked.

**Cloud Run with Hardcoded Credentials**
```hcl
env {
  name  = "DB_URL"
  value = "mysql://admin:S3cr3tP@ssw0rd@${google_compute_instance.db_server.network_interface[0].network_ip}:3306/app"
}
env {
  name  = "API_KEY"
  value = "sk-prod-9x8y7z6w5v4u3t2s1r0q"
}
env {
  name  = "SECRET_TOKEN"
  value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

These environment variables are visible in the Cloud Run service configuration to anyone with project-level read access.

### The Attack Surface at a Glance

After `terraform apply`, you get this summary:

```
============================================================
 GCP Vulnerable Cloud Lab — Attack Surface Summary
============================================================
 Web Server (DVWA):  http://34.72.xxx.xxx/
 DVWA Credentials:   admin / password
 Info Disclosure:    http://34.72.xxx.xxx/info.php
 Cloud Function:     https://us-central1-myproject.cloudfunctions.net/vulnerable-fn
 Cloud Run:          https://vulnerable-api-abc123-uc.a.run.app
 Public Bucket:      gs://vulnerable-bucket-a1b2c3d4
 Secret Creds:       https://storage.googleapis.com/vulnerable-bucket-a1b2c3d4/secrets/database-credentials.json
 SA Key on Disk:     /tmp/sa-key.json (on web server)
 Overprivileged SA:  overprivileged-sa@myproject.iam.gserviceaccount.com
============================================================
 WARNING: Destroy with `terraform destroy` when finished!
============================================================
```

---

## Part 2: StratusAI — The Scanner

[StratusAI](https://github.com/anpa1200/stratus-ai) is an AI-powered cloud security assessment tool. It runs entirely in Docker and operates in two modes:

- **Internal mode**: Uses cloud provider credentials to enumerate your configuration via API — IAM policies, firewall rules, bucket ACLs, running services, etc.
- **External mode**: Scans public-facing endpoints from the network — open ports, TLS configuration, HTTP security headers, DNS.

For GCP (just added), the internal scanner has 7 modules:

| Module | What it checks |
|--------|---------------|
| `gcp_iam` | Service account keys and age, project IAM policy, `allUsers` bindings, `roles/owner` grants |
| `gcp_compute` | Firewall rules open to `0.0.0.0/0`, instances with public IPs and full API scope, sensitive metadata keys |
| `gcp_storage` | Buckets with `allUsers` bindings, uniform access disabled, versioning/logging status |
| `gcp_cloudfunctions` | Public invoker, deprecated runtimes, secrets in env var names, ingress settings |
| `gcp_cloudrun` | Public invoker, hardcoded credentials in environment variables |
| `gcp_secretmanager` | Secrets accessible by `allUsers`, missing rotation, no CMEK |
| `gcp_logging` | Data Access audit logs disabled, no log sinks, subnets without VPC flow logs |

### How the AI Analysis Works

Every scanner returns raw data — no findings extracted by the scanner itself. The data flows to Claude in two stages:

**Stage 1: Per-module analysis**

Each module's output is preprocessed (60–90% size reduction by filtering out clean resources), then sent to Claude with a structured prompt:

```
Analyze this GCP IAM scan output for security issues.
Provider: gcp | Module: gcp_iam | Project: my-project

{
  "public_bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": ["allUsers"],
      "issue": "Role granted to allUsers or allAuthenticatedUsers"
    }
  ],
  "overprivileged_bindings": [
    {
      "role": "roles/owner",
      "members": ["serviceAccount:overprivileged-sa@my-project.iam.gserviceaccount.com"],
      "issue": "Overprivileged role roles/owner granted"
    }
  ],
  "flagged_service_accounts": [
    {
      "email": "overprivileged-sa@my-project.iam.gserviceaccount.com",
      "keys": [{"age_days": 0, "key_type": "USER_MANAGED"}],
      "_issues": ["1 user-managed key(s)"]
    }
  ]
}
```

Claude returns structured JSON:

```json
{
  "findings": [
    {
      "id": "gcp_iam_owner_sa",
      "title": "Service Account Has Project Owner Role",
      "severity": "CRITICAL",
      "category": "gcp_iam",
      "resource": "overprivileged-sa@my-project.iam.gserviceaccount.com",
      "description": "A service account has been granted roles/owner on the project, giving it unrestricted control over all GCP resources. If this SA's credentials are compromised, the entire project is at risk.",
      "evidence": "roles/owner bound to serviceAccount:overprivileged-sa@my-project.iam.gserviceaccount.com",
      "remediation": "gcloud projects remove-iam-policy-binding PROJECT_ID --member='serviceAccount:SA_EMAIL' --role='roles/owner'"
    }
  ],
  "module_risk_score": 95,
  "module_summary": "Critical IAM misconfiguration: a service account with project owner role is actively used by compute instances, creating an direct path to full project compromise via metadata SSRF."
}
```

**Stage 2: Synthesis**

After all modules are analyzed, all findings are aggregated and sent to Claude again for cross-module synthesis. This is where attack chains emerge:

```json
{
  "attack_chains": [
    {
      "title": "SSRF to Full Project Takeover via Metadata Server",
      "steps": [
        "Exploit SSRF endpoint: GET ?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "Obtain OAuth2 access token for the overprivileged service account (roles/owner)",
        "Use token to enumerate all project resources: gcloud compute instances list, gsutil ls",
        "Access Secret Manager secret containing exported SA key for persistent access",
        "Activate SA key for long-term persistence: gcloud auth activate-service-account --key-file=sa-key.json"
      ],
      "findings_involved": ["gcp_cf_public_invoker", "gcp_iam_owner_sa", "gcp_sm_exposed_key"],
      "likelihood": "HIGH",
      "impact": "CRITICAL"
    },
    {
      "title": "Public Bucket Credential Theft to Project Pivot",
      "steps": [
        "List and download public bucket contents: curl https://storage.googleapis.com/BUCKET/secrets/database-credentials.json",
        "Download exported SA private key: curl https://storage.googleapis.com/BUCKET/keys/id_rsa",
        "Authenticate as overprivileged SA: gcloud auth activate-service-account --key-file=sa-key.json",
        "Full project access achieved — enumerate, exfiltrate, or pivot to other projects via org-level roles"
      ],
      "findings_involved": ["gcp_storage_public_bucket", "gcp_iam_owner_sa"],
      "likelihood": "CRITICAL",
      "impact": "CRITICAL"
    }
  ],
  "overall_risk_rating": "CRITICAL",
  "overall_risk_score": 98,
  "top_10_priorities": [
    "gcp_iam_owner_sa",
    "gcp_cf_public_invoker",
    "gcp_cf_rce_risk",
    "gcp_storage_public_bucket",
    "gcp_compute_ssh_open",
    "gcp_cr_public_invoker",
    "gcp_cr_hardcoded_credentials",
    "gcp_sm_no_rotation",
    "gcp_logging_no_data_access",
    "gcp_compute_full_api_scope"
  ]
}
```

This is the key insight: the scanner finds individual problems, but Claude understands how they combine. An SSRF endpoint alone is medium severity. An SSRF endpoint on a machine with full API scope running as a project owner SA is a one-step full compromise. Claude sees that.

---

## Part 3: Running the Full Audit

The `full_audit.sh` script in the `vulnerable-cloud-lab` repo orchestrates everything:

```bash
git clone https://github.com/anpa1200/vulnerable-cloud-lab.git
cd vulnerable-cloud-lab

export ANTHROPIC_API_KEY=sk-ant-...
bash scripts/full_audit.sh
```

Here's what happens:

### Interactive Setup (~2 minutes)

```
━━━  Step 2: Gathering variables ━━━━━━━━━━━━━━━━━━━━━━━━━━

  GCP Project ID [my-pentest-project]: █
  GCP Region [us-central1]:
```

The script auto-detects your gcloud project, StratusAI location (`~/cloud_audit`), and checks ADC credentials. One confirmation and it's running.

### Terraform Deployment (~8 minutes)

```
━━━  Step 4: Deploying vulnerable GCP lab ━━━━━━━━━━━━━━━━━

[14:22:01] Running terraform init...
[14:22:08] Running terraform plan...

  Plan: 31 to add, 0 to change, 0 to destroy.

  Apply this plan? Type 'yes' to confirm: yes

[14:22:10] Applying Terraform plan...
google_compute_network.lab_vpc: Creating...
google_service_account.overprivileged_sa: Creating...
...
google_compute_instance.web_server: Creation complete after 35s
google_cloudfunctions_function.vulnerable_function: Creation complete after 4m12s

Apply complete! Resources: 31 added, 0 changed, 0 destroyed.
```

### Internal GCP Scan (~4 minutes)

```
━━━  Step 7: Internal GCP security scan ━━━━━━━━━━━━━━━━━━━

[14:31:05] Scanning project: my-pentest-project
[14:31:05] Modules: iam, compute, storage, cloudfunctions, cloudrun, secretmanager, logging

► Running 7 scanner modules...
  Modules: gcp/gcp_iam, gcp/gcp_compute, gcp/gcp_storage, gcp/gcp_cloudfunctions,
           gcp/gcp_cloudrun, gcp/gcp_secretmanager, gcp/gcp_logging

  ✓ gcp_iam            3.2s
  ✓ gcp_compute        2.8s
  ✓ gcp_storage        1.4s
  ✓ gcp_cloudfunctions 1.9s
  ✓ gcp_cloudrun       2.1s
  ✓ gcp_secretmanager  1.2s
  ✓ gcp_logging        1.8s

► Running AI analysis (claude-sonnet-4-6)...
  Analyzing modules...
  Running synthesis...

╔══════════════════════ SUMMARY ════════════════════════╗
  Overall Risk: CRITICAL (98/100)
  Provider: GCP — my-pentest-project
  Findings:
    8 Critical  6 High  4 Medium  3 Low

  Top Action: Remove roles/owner from service account and replace with
              least-privilege roles specific to each workload

  AI Cost: $0.0847 (28,412 in / 4,891 out tokens)
╚════════════════════════════════════════════════════════╝
```

### External Scans (~6 minutes total, 3 targets)

```
━━━  Step 8: External security scans ━━━━━━━━━━━━━━━━━━━━━

[14:35:22] External scan: DVWA web server (34.72.xxx.xxx)
  ✓ ports         open: 22 (SSH), 80 (HTTP), 8080 (HTTP-alt)
  ✓ ssl           no TLS on port 80 — plain HTTP
  ✓ http_headers  missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  ✓ dns

[14:37:41] External scan: Cloud Function (us-central1-myproject.cloudfunctions.net)
  ✓ ports         443 open (HTTPS)
  ✓ ssl           TLS 1.3, valid cert, expires in 87 days
  ✓ http_headers  missing: CSP, X-Frame-Options — server: ESF disclosed

[14:39:58] External scan: Cloud Run (vulnerable-api-abc123-uc.a.run.app)
  ✓ ports         443 open (HTTPS)
  ✓ ssl           TLS 1.3, valid cert
  ✓ http_headers  missing: CSP — server: Google Frontend disclosed
```

### The Report

Every scan generates an HTML and Markdown report in `audit_output/YYYY-MM-DDTHH-MM-SS/`:

```
audit_output/2025-03-12T14-22-00/
├── terraform_outputs.json
├── internal/
│   ├── report_2025-03-12T14-31-05Z.html   ← dark-theme interactive report
│   └── report_2025-03-12T14-31-05Z.md
├── external_web/
│   ├── report_2025-03-12T14-35-22Z.html
│   └── report_2025-03-12T14-35-22Z.md
├── external_function/
│   ├── report_2025-03-12T14-37-41Z.html
│   └── report_2025-03-12T14-37-41Z.md
└── external_cloudrun/
    ├── report_2025-03-12T14-39-58Z.html
    └── report_2025-03-12T14-39-58Z.md
```

The HTML report has live severity filtering, full-text search across findings, attack chain visualization, and remediation CLI commands for every finding.

### Teardown

```
  The vulnerable lab is still running and accruing GCP charges.

  Destroy the lab now? Type 'destroy' to confirm (or press Enter to skip): destroy

━━━  Step 10: Destroying lab infrastructure ━━━━━━━━━━━━━━━

[14:45:01] Running terraform destroy...
...
Destroy complete! Resources: 31 destroyed.

  Done. Reports saved to: audit_output/2025-03-12T14-22-00/
```

Total time from `bash full_audit.sh` to complete teardown: **~25 minutes**.

---

## What the AI Actually Finds

Here's a condensed version of the CRITICAL findings Claude identifies from this lab:

**Finding 1: SSRF → Metadata Server → Full Compromise**
> The Cloud Function at `?url=` accepts arbitrary URLs with no validation. Inside GCP, this allows fetching `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` which returns an OAuth2 token for the Compute instance's service account. That service account has `roles/owner`. One HTTP request gives an attacker full project control.

**Finding 2: Remote Code Execution on Cloud Function**
> `?cmd=` passes user input directly to `subprocess.run(shell=True)`. Any OS command executes as the function's runtime user. Combined with the `?env=1` endpoint (which dumps all environment variables), this gives immediate credential access without even touching the metadata server.

**Finding 3: Public Bucket with Credentials**
> `gs://vulnerable-bucket-XXXXX` has `allUsers: roles/storage.objectViewer`. The bucket contains `secrets/database-credentials.json` (production DB credentials) and `keys/id_rsa` (private SSH key). Anyone with the bucket name — discoverable via Google dorks or bruteforce — can download both files unauthenticated.

**Finding 4: Service Account with Project Owner**
> A single service account holds `roles/owner`, `roles/storage.admin`, `roles/compute.admin`, `roles/secretmanager.admin`, and `roles/iam.securityAdmin`. The web server, Cloud Function, and the public bucket all provide paths to obtain its credentials. This is the "blast radius" node that turns a minor misconfiguration into a full project compromise.

**Finding 5: SSH Open to Internet**
> Firewall rule `allow-ssh` permits `tcp:22` from `0.0.0.0/0`. Combined with the SA key embedded in instance metadata (readable via SSRF), an attacker can authenticate directly to the server without needing to know a password.

---

## The Architecture Decisions Worth Stealing

**Scanners collect data; AI finds issues.**
Every scanner returns raw cloud API data. It doesn't decide what's a finding — Claude does. This means you get context-aware findings instead of pattern-matched alerts. Claude knows that `allUsers` on a bucket storing SSH keys is more critical than `allUsers` on a bucket serving static website content.

**Preprocessing reduces cost by 60–90%.**
Before sending data to Claude, each module's output is filtered to remove clean resources. If 47 out of 50 IAM users have no issues, only the 3 flagged ones get sent. This keeps API costs low (~$0.05–$0.15 per full GCP scan) and keeps Claude focused on what matters.

**Two-stage analysis catches what single-module analysis misses.**
Per-module analysis finds individual issues. The synthesis stage finds *how they combine*. An SSRF vulnerability and an overprivileged SA in separate modules become an "SSRF → full project takeover" attack chain only when Claude sees both together.

**Everything runs in Docker.**
The entire tool — Python, nmap, sslscan, dnsutils, gcloud CLI — is packaged in a single container. No dependency hell, no version conflicts. `docker build && docker run` is the complete installation.

---

## Running It Against Your Own GCP Project

The scanner works against any GCP project, not just the vulnerable lab. To run it against your actual cloud environment:

```bash
git clone https://github.com/anpa1200/stratus-ai.git
cd stratus-ai

export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_CLOUD_PROJECT=your-real-project-id

# Authenticate
gcloud auth application-default login

# Internal scan only (no external network scanning)
./run.sh --provider gcp --mode internal --project your-real-project-id

# Both internal and external (requires a public endpoint)
./run.sh --provider gcp --mode both \
  --project your-real-project-id \
  --target your-app.example.com
```

The tool is **read-only**. It calls GCP APIs with your credentials but never modifies any resources. Minimum required IAM roles:

```
roles/iam.securityReviewer
roles/compute.viewer
roles/storage.objectViewer (for bucket IAM policies)
roles/cloudfunctions.viewer
roles/run.viewer
roles/secretmanager.viewer
roles/logging.viewer
```

For the vulnerable lab, you obviously have `roles/owner` — which is kind of the point.

---

## What's Next

Both tools are open-source and actively maintained:

- **[vulnerable-cloud-lab](https://github.com/anpa1200/vulnerable-cloud-lab)** — The GCP pentest environment. Planned additions: Kubernetes (GKE) with misconfigured RBAC, Cloud SQL with public IP, BigQuery with overly permissive dataset ACLs, and a simulated credential breach via a compromised CI/CD pipeline.

- **[stratus-ai](https://github.com/anpa1200/stratus-ai)** — The scanner. AWS support is already comprehensive (IAM, S3, EC2, Lambda, RDS, EKS, KMS, Secrets Manager, CloudTrail). GCP support just shipped. Azure is next.

The combination of a realistic vulnerable environment and an AI-powered scanner that synthesizes findings into attack chains is — in my opinion — the most effective way to learn cloud security that exists right now. You're not reading about what *could* go wrong. You're watching it go wrong in real time, with an AI explaining exactly what an attacker would do next.

Deploy it. Break it. Fix it. Repeat.

---

## Getting Started (TL;DR)

**Requirements**: terraform, gcloud, docker, an Anthropic API key, a GCP project

### Deploy directly from GitHub (Cloud Shell / Codespaces)

If you want to run this from a cloud-based shell (Cloud Shell, Codespaces, etc.), the same repo + script flow works:

```bash
# 1. Clone the lab
git clone https://github.com/anpa1200/vulnerable-cloud-lab.git
cd vulnerable-cloud-lab

# 2. Clone the scanner (auto-detected by full_audit.sh)
git clone https://github.com/anpa1200/stratus-ai.git ~/cloud_audit

# 3. Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# 4. Run everything
bash scripts/full_audit.sh
```

That's it. ~25 minutes later you have a deployed vulnerable GCP lab, an AI-generated security report with attack chains and priorities, and an offer to tear it all down.

---

*Both repositories are MIT licensed. Contributions welcome.*

*The vulnerable infrastructure is intentional and for educational purposes only. Never deploy in production. Always destroy when finished.*
