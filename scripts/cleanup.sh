#!/usr/bin/env bash
# =============================================================================
# cleanup.sh — Safe teardown of the GCP Vulnerable Cloud Lab
# =============================================================================
# Destroys all Terraform-managed resources and cleans up local artifacts.
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

info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          GCP Vulnerable Cloud Lab — Cleanup                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check terraform is available
if ! command -v terraform &>/dev/null; then
  die "'terraform' not found in PATH."
fi

# Check terraform.tfvars exists (lab was deployed)
if [[ ! -f "${TERRAFORM_DIR}/terraform.tfvars" ]]; then
  warn "terraform.tfvars not found — the lab may not have been deployed."
  read -rp "  Continue anyway? (yes/no): " confirm
  [[ "$confirm" != "yes" ]] && { info "Aborted."; exit 0; }
fi

# Show what will be destroyed
info "Reading current deployment..."
if terraform -chdir="${TERRAFORM_DIR}" output lab_summary 2>/dev/null; then
  echo ""
fi

echo -e "${RED}${BOLD}"
echo "  You are about to DESTROY all lab infrastructure."
echo "  This will delete:"
echo "    • Compute instances (web server, database)"
echo "    • Cloud Run service"
echo "    • Cloud Function"
echo "    • Storage bucket and all contents"
echo "    • Service accounts and IAM bindings"
echo "    • VPC, subnets, firewall rules"
echo "    • Secret Manager secrets"
echo -e "${NC}"

read -rp "  Type 'destroy' to confirm: " confirm
[[ "$confirm" != "destroy" ]] && { info "Aborted — no resources were deleted."; exit 0; }

echo ""
info "Destroying infrastructure with Terraform..."
terraform -chdir="${TERRAFORM_DIR}" destroy -auto-approve

echo ""
ok "All GCP resources destroyed."

# Clean local artifacts
info "Cleaning local Terraform artifacts..."
rm -f "${TERRAFORM_DIR}/tfplan"
rm -f "${TERRAFORM_DIR}/function_code.zip"
ok "Local artifacts cleaned."

echo ""
echo -e "${GREEN}${BOLD}Cleanup complete!${NC}"
echo ""
echo "  Tip: You can verify no resources remain by checking the GCP console."
echo "  To redeploy the lab, run: bash scripts/deploy.sh"
echo ""
