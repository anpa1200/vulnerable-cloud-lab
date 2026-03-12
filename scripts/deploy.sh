#!/usr/bin/env bash
# =============================================================================
# deploy.sh — One-command deployment for the Vulnerable Cloud Lab
# =============================================================================
# WARNING: This script deploys intentionally vulnerable infrastructure.
#          Use only in isolated cloud accounts dedicated to security training.
#          Destroy resources when finished: make -C terraform destroy
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Terraform paths for each cloud provider
TERRAFORM_DIR_GCP="${REPO_ROOT}/terraform"
TERRAFORM_DIR_AWS="${REPO_ROOT}/terraform/aws"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║          Vulnerable Cloud Lab — Deployment Wizard            ║"
  echo "║          FOR SECURITY TRAINING USE ONLY                      ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
die()  { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------

select_provider() {
  echo ""
  echo "Which cloud provider would you like to deploy the lab to?"
  echo "  1) Google Cloud Platform (GCP)"
  echo "  2) Amazon Web Services (AWS)"
  echo ""

  read -rp "  Choose [1/2] (default 1): " choice
  choice="${choice:-1}"

  case "$choice" in
    1|gcp|GCP)
      PROVIDER="gcp"
      TERRAFORM_DIR="${TERRAFORM_DIR_GCP}"
      SUMMARY_OUTPUT="lab_summary"
      ;;
    2|aws|AWS)
      PROVIDER="aws"
      TERRAFORM_DIR="${TERRAFORM_DIR_AWS}"
      SUMMARY_OUTPUT="attack_surface_summary"
      ;;
    *)
      warn "Invalid choice. Please enter 1 for GCP or 2 for AWS."
      select_provider
      ;;
  esac

  ok "Selected provider: ${PROVIDER^^}"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

check_dependencies() {
  info "Checking dependencies..."
  local missing=()
  local tools=(terraform)

  if [[ "$PROVIDER" == "gcp" ]]; then
    tools+=(gcloud)
  else
    tools+=(aws)
  fi

  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      missing+=("$tool")
    else
      ok "$tool found: $(command -v "$tool")"
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}. Install them and retry."
  fi
}

check_gcloud_auth() {
  info "Checking Google Cloud authentication..."
  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q '@'; then
    warn "No active gcloud account found. Running 'gcloud auth login'..."
    gcloud auth login
  fi
  local account
  account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
  ok "Authenticated as: ${account}"

  info "Checking Application Default Credentials..."
  if ! gcloud auth application-default print-access-token &>/dev/null; then
    warn "ADC not configured. Running 'gcloud auth application-default login'..."
    gcloud auth application-default login
  fi
  ok "Application Default Credentials are configured."
}

check_aws_auth() {
  info "Checking AWS authentication..."
  if ! aws sts get-caller-identity --output text &>/dev/null; then
    warn "Unable to query AWS identity. Please configure AWS credentials."
    echo "  You can run: aws configure"
    echo "  Or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_REGION environment variables."
    read -rp "  Continue after configuring AWS credentials? (yes/no): " cont
    [[ "$cont" != "yes" ]] && die "AWS credentials not configured. Aborting."

    if ! aws sts get-caller-identity --output text &>/dev/null; then
      die "Still unable to authenticate to AWS. Please check your credentials and retry."
    fi
  fi

  local account
  account=$(aws sts get-caller-identity --query Account --output text)
  ok "AWS authenticated as account: ${account}"
}

setup_tfvars_gcp() {
  local tfvars="${TERRAFORM_DIR}/terraform.tfvars"
  if [[ -f "$tfvars" ]]; then
    ok "terraform.tfvars already exists — skipping setup."
    return
  fi

  warn "terraform.tfvars not found."
  echo ""
  echo -e "${BOLD}Please provide your GCP project details:${NC}"

  read -rp "  GCP Project ID: " project_id
  [[ -z "$project_id" ]] && die "Project ID cannot be empty."

  read -rp "  Region [us-central1]: " region
  region="${region:-us-central1}"

  read -rp "  Zone [us-central1-a]: " zone
  zone="${zone:-us-central1-a}"

  cat > "$tfvars" <<EOF
project_id = "${project_id}"
region     = "${region}"
zone       = "${zone}"
EOF
  ok "Created ${tfvars}"
}

setup_tfvars_aws() {
  local tfvars="${TERRAFORM_DIR}/terraform.tfvars"
  if [[ -f "$tfvars" ]]; then
    ok "terraform.tfvars already exists — skipping setup."
    return
  fi

  warn "terraform.tfvars not found."
  echo ""
  echo -e "${BOLD}Please provide your AWS deployment settings:${NC}"

  read -rp "  AWS Region [us-east-1]: " aws_region
  aws_region="${aws_region:-us-east-1}"

  read -rp "  Resource name prefix [vuln-lab]: " name_prefix
  name_prefix="${name_prefix:-vuln-lab}"

  read -rp "  Allowed SSH CIDR (default open, intentional vuln) [0.0.0.0/0]: " allowed_ssh_cidr
  allowed_ssh_cidr="${allowed_ssh_cidr:-0.0.0.0/0}"

  read -rp "  DVWA admin password [password]: " dvwa_admin_password
  dvwa_admin_password="${dvwa_admin_password:-password}"

  read -rp "  Database password [S3cr3tP@ssw0rd]: " db_password
  db_password="${db_password:-S3cr3tP@ssw0rd}"

  cat > "$tfvars" <<EOF
aws_region        = "${aws_region}"
name_prefix       = "${name_prefix}"
allowed_ssh_cidr  = "${allowed_ssh_cidr}"
dvwa_admin_password = "${dvwa_admin_password}"
db_password        = "${db_password}"
EOF
  ok "Created ${tfvars}"
}

# ---------------------------------------------------------------------------
# Deployment steps
# ---------------------------------------------------------------------------

terraform_init() {
  info "Initialising Terraform..."
  terraform -chdir="${TERRAFORM_DIR}" init -upgrade
  ok "Terraform initialised."
}

terraform_plan() {
  info "Creating Terraform plan..."
  terraform -chdir="${TERRAFORM_DIR}" plan -out="${TERRAFORM_DIR}/tfplan"
  ok "Plan saved to terraform/tfplan"
}

terraform_apply() {
  info "Applying Terraform plan..."
  terraform -chdir="${TERRAFORM_DIR}" apply "${TERRAFORM_DIR}/tfplan"
  ok "Infrastructure deployed."
}

print_summary() {
  echo ""
  echo -e "${GREEN}${BOLD}Deployment complete!${NC}"
  echo ""
  terraform -chdir="${TERRAFORM_DIR}" output "${SUMMARY_OUTPUT}"
  echo ""
  echo -e "${RED}${BOLD}REMINDER: Run 'bash scripts/cleanup.sh' when finished to avoid unexpected cloud charges.${NC}"
  echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

banner

select_provider

echo -e "${RED}${BOLD}"
echo "  WARNING: You are about to deploy intentionally VULNERABLE"
echo "  infrastructure to ${PROVIDER^^}."
echo "  Only proceed if you understand the risks and are using an"
echo "  isolated cloud account dedicated to security training."
echo -e "${NC}"

read -rp "  Type 'yes' to confirm and continue: " confirm
[[ "$confirm" != "yes" ]] && die "Aborted."

check_dependencies

if [[ "$PROVIDER" == "gcp" ]]; then
  check_gcloud_auth
  setup_tfvars_gcp
else
  check_aws_auth
  setup_tfvars_aws
fi

terraform_init
terraform_plan
terraform_apply
print_summary
