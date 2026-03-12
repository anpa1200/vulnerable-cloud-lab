# Building a Vulnerable Cloud Pentest Lab with Terraform

A complete, step-by-step guide to deploying intentionally misconfigured cloud resources for hands-on security training on GCP and AWS.

---

## Introduction

This guide walks you through building a comprehensive vulnerable cloud lab environment using Terraform. The included deployment wizard supports both Google Cloud Platform (GCP) and Amazon Web Services (AWS). The lab includes intentionally misconfigured resources designed for cloud penetration testing training.

⚠️ **WARNING:** This lab contains intentional vulnerabilities. Only deploy in isolated test environments with proper authorization.

### What You'll Build

The lab deploys a collection of intentionally vulnerable cloud services designed for penetration testing and red team training. The exact resources depend on the chosen provider, but both deployments include:

- **A vulnerable web application (DVWA) exposed to the public internet**
- **Overprivileged compute identity / service account (owner/admin privileges)**
- **Public storage bucket hosting secrets and private keys**
- **A vulnerable serverless function (SSRF, RCE, env dump, path traversal)**
- **Hardcoded credentials and exposed secrets**
- **An information disclosure page revealing internal endpoints and metadata**

Provider-specific details:

- **GCP:** Cloud Run service, Cloud Function, GCS bucket, IAM service account, Compute Engine VM.
- **AWS:** EC2 instance running DVWA, Lambda function + Function URL, S3 bucket, IAM role, Secrets Manager secret.

**Estimated Time:** 30–45 minutes

**Estimated Cost:** ~$12–15/month (depends on region and resource usage)

---

If you like this research, buy me a coffee (PayPal) — keep the lab running.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [GCP Project Setup](#gcp-project-setup)
4. [Local Environment Setup](#local-environment-setup)
5. [Terraform Configuration](#terraform-configuration)
6. [Deployment Process](#deployment-process)
7. [Verification](#verification)
8. [Accessing the Lab](#accessing-the-lab)
9. [Cleanup](#cleanup)

---

## Prerequisites

### Required Accounts & Services

- **Google Cloud Platform account** with billing enabled (for GCP deployment)
- **Amazon Web Services account** with billing enabled (for AWS deployment)
- Permission to create projects/resources or equivalent IAM permissions in the target account

### Local Machine Requirements

- Linux, macOS, or Windows with WSL
- Internet connection
- Terminal / command line access

### Required Software

#### 1. Google Cloud SDK (`gcloud`)

**Linux**
```bash
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
# Verify
gcloud version
```

**macOS**
```bash
brew install --cask google-cloud-sdk
```

**Windows**
Download and run the installer from:
https://cloud.google.com/sdk/docs/install

#### 2. AWS CLI (optional, for AWS deployment)

The deploy wizard can also target AWS instead of GCP. If you plan to use AWS, install and configure the AWS CLI.

**Linux**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
```

**macOS**
```bash
brew install awscli
```

**Windows**
Download and install from:
https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

#### 3. Terraform

**Linux**
```bash
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
rm terraform_1.6.0_linux_amd64.zip
terraform version
```

**macOS**
```bash
brew install terraform
```

**Windows**
Download from: https://www.terraform.io/downloads

#### 3. Git

```bash
# Linux
sudo apt-get install git  # Debian/Ubuntu
sudo yum install git      # RHEL/CentOS

# macOS
brew install git

git --version
```

#### 4. Zip Utility (Cloud Function packaging)

**Linux**
```bash
sudo apt-get install zip
```

**macOS** (usually pre-installed)

**Windows**: Use built-in compression or 7-Zip.

---

## Cloud Account Setup

### AWS Account Setup (optional)

If you selected **AWS** in the deploy wizard, make sure your AWS CLI is configured with credentials that can create/upkeep infrastructure.

```bash
aws configure
```

### GCP Project Setup (optional)

If you selected **GCP** in the deploy wizard, create a project and enable billing:

#### Option A: Using gcloud CLI

```bash
export PROJECT_ID="cloud-pentest-lab-$(date +%s)"
export REGION="us-central1"
export ZONE="us-central1-a"

gcloud projects create $PROJECT_ID \
  --name="Cloud Pentest Lab" \
  --set-as-default

gcloud billing projects link $PROJECT_ID \
  --billing-account=$(gcloud billing accounts list --format="value(name)" | head -1)
```

#### Option B: Using GCP Console

1. Go to the GCP Console.
2. Click “Select a project” → “New Project”.
3. Enter project name: **Cloud Pentest Lab**.
4. Click **Create**.
5. Note your **Project ID**.

#### Option A: Using gcloud CLI

```bash
export PROJECT_ID="cloud-pentest-lab-$(date +%s)"
export REGION="us-central1"
export ZONE="us-central1-a"

gcloud projects create $PROJECT_ID \
  --name="Cloud Pentest Lab" \
  --set-as-default

gcloud billing projects link $PROJECT_ID \
  --billing-account=$(gcloud billing accounts list --format="value(name)" | head -1)
```

#### Option B: Using GCP Console

1. Go to the GCP Console.
2. Click “Select a project” → “New Project”.
3. Enter project name: **Cloud Pentest Lab**.
4. Click **Create**.
5. Note your **Project ID**.

### Step 2: Enable Required APIs (GCP only)

Terraform will enable most APIs automatically, but enabling them before deploy avoids delays.

```bash
gcloud config set project $PROJECT_ID

gcloud services enable \
  compute.googleapis.com \
  storage.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  secretmanager.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  cloudbuild.googleapis.com

# Verify
gcloud services list --enabled
```

### Step 3: Authenticate & Configure Application Default Credentials (GCP only)

⚠️ Required: Terraform uses Application Default Credentials (ADC) to authenticate.

```bash
gcloud auth login
gcloud auth application-default login
```

Verify:

```bash
gcloud auth application-default print-access-token
```

---

## Local Environment Setup

### Clone the Lab Repository

```bash
git clone https://github.com/anpa1200/vulnerable-cloud-lab.git
cd vulnerable-cloud-lab
```

### (Optional) Clone the Scanner Repo

The deploy script auto-detects `~/cloud_audit`, but you can clone it explicitly:

```bash
git clone https://github.com/anpa1200/stratus-ai.git ~/cloud_audit
```

---

## Terraform Configuration

### Configure Variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
project_id = "your-gcp-project-id"
region     = "us-central1"
zone       = "us-central1-a"
```

---

## Deployment Process

### Option A: Quick Deploy (recommended)

```bash
bash scripts/deploy.sh
```

This runs an interactive wizard that prompts you to select a cloud provider (GCP or AWS) and then gathers the required deployment parameters.

- For **GCP**, it prompts for Project ID, region, and zone and creates `terraform/terraform.tfvars`.
- For **AWS**, it prompts for region, resource prefix, and intentional lab secrets and creates `terraform/aws/terraform.tfvars`.

The rest of the deployment is handled via Terraform and the script prints key output values.

### Option B: Full Audit (lab + StratusAI scan)

```bash
bash scripts/full_audit.sh
```

This runs the lab deployment, performs the internal + external scans, and generates HTML/MD reports.

---

## Verification

This repository includes a verification script (`scripts/verify.sh`) that checks the most important vulnerabilities (DVWA, Cloud Function/Lambda, public bucket, etc.) for both GCP and AWS deployments.

Run:

```bash
bash scripts/verify.sh
```

The script will ask which provider you deployed and then validate:

- DVWA web server access + info disclosure
- Vulnerable function (RCE, SSRF, env dump, path traversal)
- Public bucket secrets and keys

### Web Server & DVWA

```bash
WEB_IP=$(terraform output -raw web_server_ip)
# Visit in your browser:
# http://$WEB_IP/
```

DVWA credentials:
- **Username:** admin
- **Password:** password

### Storage Bucket

```bash
BUCKET=$(terraform output -raw vulnerable_bucket_name)
gsutil ls gs://$BUCKET/
gsutil cat gs://$BUCKET/secrets/database-credentials.json
```

### Cloud Function

```bash
FUNCTION_URL=$(terraform output -raw cloud_function_url)
curl "$FUNCTION_URL?env=1"
```

### Cloud Run

```bash
CLOUD_RUN_URL=$(terraform output -raw cloud_run_url)
curl $CLOUD_RUN_URL
```

---

## Accessing the Lab

### GCP (Cloud Run / Cloud Function / Compute)

The web server exposes an `info.php` page with internal service URLs:

```
http://<WEB_IP>/info.php
```

You can SSH into the instance using the Terraform outputs:

```bash
gcloud compute ssh $(terraform output -raw web_server_name) \
  --zone=$(terraform output -raw zone) \
  --project=$(terraform output -raw project_id)
```

### AWS (EC2 / Lambda)

The AWS lab exposes the DVWA web app and an info page via the `dvwa_url` output:

```bash
dvwa_url=$(terraform -chdir=terraform/aws output -raw dvwa_url)
echo "DVWA: $dvwa_url"
```

The exposed web app also provides an `info.php` page at:

```
${dvwa_url}info.php
```

To SSH into the EC2 instance, use the public IP or instance ID from Terraform outputs (or the AWS console).

---

## Cleanup

Destroy everything when you’re done:

```bash
cd vulnerable-cloud-lab
bash scripts/cleanup.sh
```

---

## GitHub Deployment (Cloud Shell / Codespaces)

This repo can be deployed directly from a GitHub-hosted shell:

```bash
git clone https://github.com/anpa1200/vulnerable-cloud-lab.git
cd vulnerable-cloud-lab
bash scripts/deploy.sh
```

---

## Summary Checklist

- [ ] GCP account created + billing enabled (if using GCP)
- [ ] AWS account created + billing enabled (if using AWS)
- [ ] `gcloud` and/or `aws` CLI installed and configured
- [ ] Terraform installed
- [ ] Repo cloned
- [ ] Terraform variables configured (via wizard or `terraform.tfvars`)
- [ ] `bash scripts/deploy.sh` completed
- [ ] `bash scripts/verify.sh` confirms vulnerabilities are reachable
- [ ] Lab destroyed when finished (`bash scripts/cleanup.sh`)

---

If you like this research, buy me a coffee (PayPal) — keep the lab running.
