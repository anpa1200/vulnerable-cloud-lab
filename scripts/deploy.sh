#!/usr/bin/env bash
# =============================================================================
# deploy.sh — One-command deployment for the GCP Vulnerable Cloud Lab
# =============================================================================
# WARNING: This script deploys intentionally vulnerable infrastructure.
#          Use only in isolated GCP projects dedicated to security training.
#          Destroy resources when finished: make -C terraform destroy
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/terraform"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║          GCP Vulnerable Cloud Lab — Deployment               ║"
  echo "║          FOR SECURITY TRAINING USE ONLY                      ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
die()  { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

check_dependencies() {
  info "Checking dependencies..."
  for tool in terraform gcloud; do
    if ! command -v "$tool" &>/dev/null; then
      die "'$tool' is not installed or not in PATH. Install it and retry."
    fi
    ok "$tool found: $(command -v "$tool")"
  done
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

setup_tfvars() {
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

# ---------------------------------------------------------------------------
# Deployment
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
  terraform -chdir="${TERRAFORM_DIR}" output lab_summary
  echo ""
  echo -e "${RED}${BOLD}REMINDER: Run 'bash scripts/cleanup.sh' or 'make -C terraform destroy'"
  echo -e "          when you are finished to avoid unexpected GCP charges.${NC}"
  echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

banner

echo -e "${RED}${BOLD}"
echo "  WARNING: You are about to deploy intentionally VULNERABLE"
echo "  infrastructure to Google Cloud Platform."
echo "  Only proceed if you understand the risks and are using an"
echo "  isolated GCP project dedicated to security training."
echo -e "${NC}"

read -rp "  Type 'yes' to confirm and continue: " confirm
[[ "$confirm" != "yes" ]] && die "Aborted."

check_dependencies
check_gcloud_auth
setup_tfvars
terraform_init
terraform_plan
terraform_apply
print_summary
