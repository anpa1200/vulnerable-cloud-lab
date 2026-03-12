#!/usr/bin/env bash
# =============================================================================
# aws_full_audit.sh — End-to-end vulnerable AWS lab deployment + security audit
# =============================================================================
#
# Flow:
#   1. Prerequisite checks (terraform, aws CLI, docker, API keys)
#   2. Variable gathering (region, profile, AI model)
#   3. Terraform deployment of the vulnerable AWS lab
#   4. StratusAI internal AWS scan (IAM, S3, EC2, Lambda, CloudTrail, etc.)
#   5. StratusAI external scans (DVWA, Lambda URL)
#   6. Report summary
#   7. Optional teardown
#
# Requirements:
#   - terraform >= 1.0
#   - AWS CLI configured (aws configure or env vars)
#   - docker
#   - ANTHROPIC_API_KEY (or OPENAI_API_KEY / GOOGLE_API_KEY for other LLMs)
#   - StratusAI repo at ~/cloud_audit (or set STRATUS_DIR)
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   bash scripts/aws_full_audit.sh
# =============================================================================
set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/terraform/aws"
TIMESTAMP="$(date +%Y-%m-%dT%H-%M-%S)"
AUDIT_OUTPUT="${REPO_ROOT}/audit_output/aws_${TIMESTAMP}"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()    { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()   { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}${CYAN}━━━  $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }
hr()    { echo -e "${DIM}────────────────────────────────────────────────────────────${NC}"; }

tf_out() { terraform -chdir="${TERRAFORM_DIR}" output -raw "$1" 2>/dev/null || echo ""; }
url_host() { python3 -c "from urllib.parse import urlparse; print(urlparse('$1').netloc)" 2>/dev/null || echo "$1"; }

# =============================================================================
# Banner
# =============================================================================
clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        Vulnerable AWS Cloud Lab — Full Security Audit                   ║
║        Deploy → Scan → Report → Destroy                                 ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# =============================================================================
# Step 1: Prerequisite checks
# =============================================================================
step "Step 1: Checking prerequisites"

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    die "Required command not found: $1. Please install it first."
  fi
  ok "$1 found: $(command -v "$1")"
}

check_cmd terraform
check_cmd aws
check_cmd docker
check_cmd python3

# Check AWS credentials
if ! aws sts get-caller-identity &>/dev/null; then
  die "AWS credentials not configured. Run 'aws configure' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY."
fi
AWS_IDENTITY=$(aws sts get-caller-identity --output json)
AWS_ACCOUNT=$(echo "$AWS_IDENTITY" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])")
AWS_ARN=$(echo "$AWS_IDENTITY" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])")
ok "AWS credentials OK — Account: ${AWS_ACCOUNT}"
info "  Identity: ${AWS_ARN}"

# Check StratusAI
STRATUS_DIR="${STRATUS_DIR:-${HOME}/cloud_audit}"
if [[ ! -d "${STRATUS_DIR}" ]]; then
  die "StratusAI not found at ${STRATUS_DIR}. Set STRATUS_DIR or clone it:\n  git clone https://github.com/anpa1200/stratus-ai.git ~/cloud_audit"
fi
ok "StratusAI found at ${STRATUS_DIR}"

# Check AI key
AI_MODEL="${AI_MODEL:-claude-sonnet-4-6}"
if [[ "${AI_MODEL}" == claude-* ]] && [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  die "ANTHROPIC_API_KEY not set.\n  export ANTHROPIC_API_KEY=sk-ant-...\n  Or set AI_MODEL=gpt-4o and OPENAI_API_KEY, or AI_MODEL=gemini-2.0-flash and GOOGLE_API_KEY."
fi
if [[ "${AI_MODEL}" == gpt-* || "${AI_MODEL}" == o[134]-* ]] && [[ -z "${OPENAI_API_KEY:-}" ]]; then
  die "OPENAI_API_KEY not set for model ${AI_MODEL}."
fi
ok "AI model: ${AI_MODEL}"

# Check docker daemon
if ! docker info &>/dev/null; then
  die "Docker daemon not running. Start Docker and retry."
fi

# =============================================================================
# Step 2: Gather variables
# =============================================================================
step "Step 2: Gathering variables"

# AWS region
DEFAULT_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
read -rp "  AWS Region [${DEFAULT_REGION}]: " AWS_REGION
AWS_REGION="${AWS_REGION:-${DEFAULT_REGION}}"

# AWS profile (optional)
read -rp "  AWS Profile (press Enter for default): " AWS_PROFILE
if [[ -n "${AWS_PROFILE}" ]]; then
  export AWS_PROFILE
  # Re-verify with the chosen profile
  if ! aws sts get-caller-identity &>/dev/null; then
    die "Profile '${AWS_PROFILE}' not configured or invalid."
  fi
fi

# Environment context
read -rp "  Environment context for AI (e.g. 'Dev lab, not production') [Vulnerable pentest lab, intentionally misconfigured]: " ENV_CONTEXT
ENV_CONTEXT="${ENV_CONTEXT:-Vulnerable pentest lab, intentionally misconfigured for security training}"

hr
info "  Region:   ${AWS_REGION}"
info "  Account:  ${AWS_ACCOUNT}"
info "  Profile:  ${AWS_PROFILE:-default}"
info "  AI Model: ${AI_MODEL}"
info "  Context:  ${ENV_CONTEXT}"
hr

read -rp "  Proceed with deployment? [y/N]: " CONFIRM
[[ "${CONFIRM}" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

# =============================================================================
# Step 3: Build StratusAI Docker image
# =============================================================================
step "Step 3: Building StratusAI Docker image"

info "Building stratus-ai image..."
docker build -q -t stratus-ai "${STRATUS_DIR}" && ok "Docker image built"

# =============================================================================
# Step 4: Deploy Terraform
# =============================================================================
step "Step 4: Deploying vulnerable AWS lab"

mkdir -p "${TERRAFORM_DIR}/.build"

info "Running terraform init..."
terraform -chdir="${TERRAFORM_DIR}" init -input=false -upgrade -no-color

info "Running terraform plan..."
terraform -chdir="${TERRAFORM_DIR}" plan \
  -var="aws_region=${AWS_REGION}" \
  -input=false -no-color -out="${TERRAFORM_DIR}/.build/tfplan"

echo ""
read -rp "  Apply this plan? Type 'yes' to confirm: " TF_CONFIRM
[[ "${TF_CONFIRM}" == "yes" ]] || { info "Deployment cancelled."; exit 0; }

info "Applying Terraform plan..."
terraform -chdir="${TERRAFORM_DIR}" apply \
  -input=false -no-color "${TERRAFORM_DIR}/.build/tfplan"

ok "Terraform deployment complete"

# ─── Collect outputs ──────────────────────────────────────────────────────────
DVWA_IP=$(tf_out "dvwa_public_ip")
DVWA_URL=$(tf_out "dvwa_url")
LAMBDA_URL=$(tf_out "lambda_url")
LAMBDA_HOST=$(url_host "${LAMBDA_URL}")
S3_BUCKET=$(tf_out "s3_bucket_name")

echo ""
terraform -chdir="${TERRAFORM_DIR}" output attack_surface_summary
echo ""

# Save terraform outputs to file
mkdir -p "${AUDIT_OUTPUT}"
terraform -chdir="${TERRAFORM_DIR}" output -json > "${AUDIT_OUTPUT}/terraform_outputs.json"
ok "Outputs saved to ${AUDIT_OUTPUT}/terraform_outputs.json"

# =============================================================================
# Step 5: Wait for EC2 to be ready
# =============================================================================
step "Step 5: Waiting for DVWA to initialise"

info "Waiting for DVWA on ${DVWA_IP}:80..."
MAX_WAIT=120
WAITED=0
until curl -sf --max-time 3 "http://${DVWA_IP}/" &>/dev/null || [[ ${WAITED} -ge ${MAX_WAIT} ]]; do
  sleep 5
  WAITED=$((WAITED + 5))
  info "  Still waiting... (${WAITED}s)"
done

if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
  warn "DVWA didn't respond within ${MAX_WAIT}s — EC2 may still be starting. Continuing with scans..."
else
  ok "DVWA is responding at http://${DVWA_IP}/"
fi

# =============================================================================
# Step 6: StratusAI helper
# =============================================================================

run_stratus() {
  local label="$1"; shift
  local out_dir="${AUDIT_OUTPUT}/${label}"
  mkdir -p "${out_dir}"

  info "Running StratusAI scan: ${label}"

  # Mount ADC for GCP; pass AWS env through
  DOCKER_ARGS=(
    --rm
    -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}"
    -e "OPENAI_API_KEY=${OPENAI_API_KEY:-}"
    -e "GOOGLE_API_KEY=${GOOGLE_API_KEY:-}"
    -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}"
    -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}"
    -e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}"
    -e "AWS_REGION=${AWS_REGION}"
    -v "${out_dir}:/app/output"
  )
  if [[ -n "${AWS_PROFILE:-}" ]]; then
    DOCKER_ARGS+=(-e "AWS_PROFILE=${AWS_PROFILE}" -v "${HOME}/.aws:/root/.aws:ro")
  else
    DOCKER_ARGS+=(-v "${HOME}/.aws:/root/.aws:ro")
  fi

  docker run "${DOCKER_ARGS[@]}" stratus-ai "$@" \
    --model "${AI_MODEL}" \
    --context "${ENV_CONTEXT}" \
    --output-dir /app/output \
    --severity INFO

  ok "Scan complete: ${label} → ${out_dir}"
}

# =============================================================================
# Step 7: Internal AWS scan
# =============================================================================
step "Step 7: Internal AWS security scan"

info "Scanning account: ${AWS_ACCOUNT} | Region: ${AWS_REGION}"
info "Modules: iam, s3, ec2, cloudtrail, rds, lambda, kms, secretsmanager, eks"

run_stratus "internal" \
  --provider aws \
  --mode internal \
  --region "${AWS_REGION}"

# =============================================================================
# Step 8: External scans
# =============================================================================
step "Step 8: External security scans"

if [[ -n "${DVWA_IP}" ]]; then
  info "External scan: DVWA web server (${DVWA_IP})"
  run_stratus "external_dvwa" \
    --mode external \
    --target "${DVWA_IP}"
else
  warn "No DVWA IP found — skipping external DVWA scan"
fi

if [[ -n "${LAMBDA_HOST}" ]]; then
  info "External scan: Lambda function (${LAMBDA_HOST})"
  run_stratus "external_lambda" \
    --mode external \
    --target "${LAMBDA_HOST}"
else
  warn "No Lambda host found — skipping external Lambda scan"
fi

# =============================================================================
# Step 9: Summary
# =============================================================================
step "Step 9: Audit complete"

echo -e "${BOLD}Reports saved to:${NC} ${AUDIT_OUTPUT}/"
echo ""
echo "  internal/"
echo "    ├── report_*.html   ← Internal AWS scan (IAM, S3, EC2, Lambda, ...)"
echo "    └── report_*.md"
if [[ -n "${DVWA_IP}" ]]; then
echo "  external_dvwa/"
echo "    ├── report_*.html   ← External scan of DVWA (${DVWA_IP})"
echo "    └── report_*.md"
fi
if [[ -n "${LAMBDA_HOST}" ]]; then
echo "  external_lambda/"
echo "    ├── report_*.html   ← External scan of Lambda (${LAMBDA_HOST})"
echo "    └── report_*.md"
fi
echo ""

# Open report if possible
REPORT_FILE=$(find "${AUDIT_OUTPUT}/internal" -name "*.html" 2>/dev/null | head -1)
if [[ -n "${REPORT_FILE}" ]]; then
  ok "Internal report: ${REPORT_FILE}"
  if command -v xdg-open &>/dev/null; then
    xdg-open "${REPORT_FILE}" 2>/dev/null &
  elif command -v open &>/dev/null; then
    open "${REPORT_FILE}" 2>/dev/null &
  fi
fi

# =============================================================================
# Step 10: Optional teardown
# =============================================================================
step "Step 10: Cleanup"

echo -e "${YELLOW}"
echo "  The vulnerable lab is still running and accruing AWS charges."
echo ""
echo "  Resources deployed:"
echo "    - EC2 instance (t3.small) — ~\$0.02/hour"
echo "    - Lambda function"
echo "    - S3 bucket: s3://${S3_BUCKET}"
echo "    - Secrets Manager secret"
echo "    - IAM roles with AdministratorAccess"
echo -e "${NC}"

read -rp "  Destroy the lab now? Type 'destroy' to confirm (or press Enter to skip): " DESTROY_CONFIRM

if [[ "${DESTROY_CONFIRM}" == "destroy" ]]; then
  step "Step 10: Destroying lab infrastructure"

  info "Running terraform destroy..."
  terraform -chdir="${TERRAFORM_DIR}" destroy \
    -var="aws_region=${AWS_REGION}" \
    -auto-approve -no-color

  ok "Lab destroyed. All resources removed."
else
  warn "Lab NOT destroyed. Remember to run 'terraform destroy' in ${TERRAFORM_DIR} when finished."
  warn "Command: cd ${TERRAFORM_DIR} && terraform destroy -var=\"aws_region=${AWS_REGION}\""
fi

echo ""
ok "Done. Reports saved to: ${AUDIT_OUTPUT}/"
echo ""
