#!/usr/bin/env bash
# =============================================================================
# full_audit.sh — End-to-end vulnerable GCP lab deployment + security audit
# =============================================================================
#
# Flow:
#   1. Prerequisite checks (terraform, gcloud, docker, API keys)
#   2. Variable gathering (project, region, credentials)
#   3. Terraform deployment of the vulnerable lab
#   4. StratusAI internal GCP scan (IAM, compute, storage, functions, etc.)
#   5. StratusAI external scans (DVWA, Cloud Function, Cloud Run endpoints)
#   6. Report summary
#   7. Optional teardown
#
# Requirements:
#   - terraform >= 1.0
#   - gcloud CLI + Application Default Credentials
#   - docker
#   - ANTHROPIC_API_KEY env var
#   - StratusAI repo at ~/cloud_audit (or set STRATUS_DIR)
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...
#   bash scripts/full_audit.sh
# =============================================================================
set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/terraform"
TIMESTAMP="$(date +%Y-%m-%dT%H-%M-%S)"
AUDIT_OUTPUT="${REPO_ROOT}/audit_output/${TIMESTAMP}"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ─── Logging ──────────────────────────────────────────────────────────────────
info()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()    { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()   { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}${CYAN}━━━  $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }
hr()    { echo -e "${DIM}────────────────────────────────────────────────────────────${NC}"; }

# ─── Terraform output helper ──────────────────────────────────────────────────
tf_out() { terraform -chdir="${TERRAFORM_DIR}" output -raw "$1" 2>/dev/null || echo ""; }

# ─── Extract hostname from URL ────────────────────────────────────────────────
url_host() { python3 -c "from urllib.parse import urlparse; print(urlparse('$1').netloc)" 2>/dev/null || echo "$1"; }

# =============================================================================
# Banner
# =============================================================================
clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        GCP Vulnerable Cloud Lab  —  Full Security Audit                 ║
║                                                                          ║
║   Deploy  →  Internal Scan  →  External Scans  →  Report  →  Destroy   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo -e "${RED}${BOLD}  WARNING: This script deploys intentionally vulnerable infrastructure"
echo -e "  to Google Cloud Platform for security training purposes only.${NC}"
echo ""

# =============================================================================
# Step 1: Prerequisites
# =============================================================================
step "Step 1: Checking prerequisites"

MISSING=()
for tool in terraform gcloud docker python3; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool: $(command -v "$tool")"
    else
        warn "$tool: NOT FOUND"
        MISSING+=("$tool")
    fi
done

[[ ${#MISSING[@]} -gt 0 ]] && die "Missing required tools: ${MISSING[*]}"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    die "ANTHROPIC_API_KEY is not set.\n  export ANTHROPIC_API_KEY=sk-ant-..."
fi
ok "ANTHROPIC_API_KEY: set (${#ANTHROPIC_API_KEY} chars)"

# Find StratusAI directory
STRATUS_DIR="${STRATUS_DIR:-}"
if [[ -z "$STRATUS_DIR" ]]; then
    for candidate in \
        "${HOME}/cloud_audit" \
        "${REPO_ROOT}/../cloud_audit" \
        "${REPO_ROOT}/../stratus-ai"
    do
        if [[ -f "${candidate}/run.sh" ]]; then
            STRATUS_DIR="$(cd "$candidate" && pwd)"
            break
        fi
    done
fi

if [[ -z "$STRATUS_DIR" || ! -f "${STRATUS_DIR}/run.sh" ]]; then
    echo ""
    warn "StratusAI not found automatically."
    read -rp "  Path to StratusAI repo (contains run.sh): " STRATUS_DIR
    [[ -f "${STRATUS_DIR}/run.sh" ]] || die "run.sh not found at ${STRATUS_DIR}"
fi
ok "StratusAI: ${STRATUS_DIR}"

# =============================================================================
# Step 2: Variable gathering
# =============================================================================
step "Step 2: Gathering variables"

# GCP Project ID
if [[ -z "${GOOGLE_CLOUD_PROJECT:-}" ]]; then
    DETECTED_PROJECT="$(gcloud config get-value project 2>/dev/null || echo "")"
    echo ""
    if [[ -n "$DETECTED_PROJECT" ]]; then
        read -rp "  GCP Project ID [${DETECTED_PROJECT}]: " GCP_PROJECT
        GCP_PROJECT="${GCP_PROJECT:-$DETECTED_PROJECT}"
    else
        read -rp "  GCP Project ID: " GCP_PROJECT
    fi
else
    GCP_PROJECT="${GOOGLE_CLOUD_PROJECT}"
    info "Using GOOGLE_CLOUD_PROJECT=${GCP_PROJECT}"
fi
[[ -z "$GCP_PROJECT" ]] && die "GCP Project ID is required."
export GOOGLE_CLOUD_PROJECT="${GCP_PROJECT}"

# Region
read -rp "  GCP Region [us-central1]: " GCP_REGION
GCP_REGION="${GCP_REGION:-us-central1}"

# Create output directories
mkdir -p "${AUDIT_OUTPUT}/internal"
mkdir -p "${AUDIT_OUTPUT}/external_web"
mkdir -p "${AUDIT_OUTPUT}/external_function"
mkdir -p "${AUDIT_OUTPUT}/external_cloudrun"

ok "Project: ${GCP_PROJECT}"
ok "Region:  ${GCP_REGION}"
ok "Reports: ${AUDIT_OUTPUT}"

# =============================================================================
# Step 3: GCP Authentication
# =============================================================================
step "Step 3: GCP Authentication"

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 || echo "")"
if [[ -z "$ACTIVE_ACCOUNT" ]]; then
    warn "No active gcloud account. Running 'gcloud auth login'..."
    gcloud auth login
fi
ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)"
ok "gcloud account: ${ACTIVE_ACCOUNT}"

if ! gcloud auth application-default print-access-token &>/dev/null 2>&1; then
    warn "Application Default Credentials not configured."
    info "Running 'gcloud auth application-default login'..."
    gcloud auth application-default login
fi
ok "Application Default Credentials: configured"

gcloud config set project "${GCP_PROJECT}" --quiet 2>/dev/null || true

# =============================================================================
# Step 4: Terraform Deployment
# =============================================================================
step "Step 4: Deploying vulnerable GCP lab"

# Check if already deployed
EXISTING_IP="$(tf_out web_server_ip 2>/dev/null || echo "")"
if [[ -n "$EXISTING_IP" ]]; then
    warn "Lab appears to already be deployed (web_server_ip=${EXISTING_IP})."
    read -rp "  Re-deploy? This will update existing resources. [y/N]: " REDEPLOY
    if [[ ! "$REDEPLOY" =~ ^[Yy]$ ]]; then
        info "Skipping deployment — using existing infrastructure."
    else
        EXISTING_IP=""
    fi
fi

if [[ -z "$EXISTING_IP" ]]; then
    # Create tfvars if missing
    TFVARS="${TERRAFORM_DIR}/terraform.tfvars"
    if [[ ! -f "$TFVARS" ]]; then
        cat > "$TFVARS" <<EOF
project_id = "${GCP_PROJECT}"
region     = "${GCP_REGION}"
zone       = "${GCP_REGION}-a"
EOF
        ok "Created terraform.tfvars"
    fi

    info "Running terraform init..."
    terraform -chdir="${TERRAFORM_DIR}" init -upgrade -input=false >/dev/null

    info "Running terraform plan..."
    terraform -chdir="${TERRAFORM_DIR}" plan -out="${TERRAFORM_DIR}/tfplan" -input=false

    echo ""
    read -rp "  Apply this plan? Type 'yes' to confirm: " TF_CONFIRM
    [[ "$TF_CONFIRM" != "yes" ]] && die "Deployment cancelled."

    info "Applying Terraform plan..."
    terraform -chdir="${TERRAFORM_DIR}" apply "${TERRAFORM_DIR}/tfplan"
fi

# Read outputs
info "Reading deployment outputs..."
WEB_IP="$(tf_out web_server_ip)"
FUNC_URL="$(tf_out cloud_function_url)"
RUN_URL="$(tf_out cloud_run_url)"
BUCKET="$(tf_out vulnerable_bucket_name)"
SA_EMAIL="$(tf_out overprivileged_sa_email)"
DVWA_URL="$(tf_out dvwa_url)"

[[ -z "$WEB_IP" ]] && die "Could not read web_server_ip from terraform output."

# Save outputs to file
terraform -chdir="${TERRAFORM_DIR}" output -json > "${AUDIT_OUTPUT}/terraform_outputs.json"
ok "Terraform outputs saved to ${AUDIT_OUTPUT}/terraform_outputs.json"

terraform -chdir="${TERRAFORM_DIR}" output lab_summary

# =============================================================================
# Step 5: Wait for lab readiness
# =============================================================================
step "Step 5: Waiting for lab to be ready"

info "Waiting for DVWA to respond at http://${WEB_IP}/ ..."
MAX_WAIT=300
WAITED=0
until curl -s --max-time 5 "http://${WEB_IP}/" | grep -qi "dvwa\|login\|html" 2>/dev/null; do
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        warn "DVWA did not respond after ${MAX_WAIT}s — continuing anyway."
        break
    fi
    echo -n "."
    sleep 10
    WAITED=$((WAITED + 10))
done
echo ""
ok "Lab is ready. Proceeding to security audit."

# =============================================================================
# Step 6: Build StratusAI Docker image
# =============================================================================
step "Step 6: Building StratusAI Docker image"

info "Building stratusai:latest..."
docker build -q -t stratusai:latest "${STRATUS_DIR}" && ok "Image built."

# Helper: run a StratusAI scan
# Usage: run_stratus <output_subdir> [extra docker flags...] -- [stratusai args...]
run_stratus() {
    local output_subdir="$1"; shift
    local output_dir="${AUDIT_OUTPUT}/${output_subdir}"
    mkdir -p "$output_dir"

    # Collect docker args up to --
    local docker_args=()
    while [[ "$1" != "--" && $# -gt 0 ]]; do
        docker_args+=("$1"); shift
    done
    shift  # consume --

    # Rest are stratusai args
    local stratus_args=("$@")

    docker run --rm \
        -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
        -e "GOOGLE_CLOUD_PROJECT=${GCP_PROJECT}" \
        -v "${HOME}/.config/gcloud:/root/.config/gcloud:ro" \
        -v "${output_dir}:/app/output" \
        --network host \
        "${docker_args[@]}" \
        stratusai:latest \
        "${stratus_args[@]}"
}

# =============================================================================
# Step 7: Internal GCP Scan
# =============================================================================
step "Step 7: Internal GCP security scan"
info "Scanning project: ${GCP_PROJECT}"
info "Modules: iam, compute, storage, cloudfunctions, cloudrun, secretmanager, logging"
info "Reports → ${AUDIT_OUTPUT}/internal/"

run_stratus "internal" -- \
    --provider gcp \
    --mode internal \
    --project "${GCP_PROJECT}" \
    --region "${GCP_REGION}" \
    --output-dir /app/output \
    --severity INFO

ok "Internal scan complete."

# =============================================================================
# Step 8: External Scans
# =============================================================================
step "Step 8: External security scans"

# ── 8a: DVWA web server ───────────────────────────────────────────────────────
info "External scan: DVWA web server (${WEB_IP})"
info "Reports → ${AUDIT_OUTPUT}/external_web/"

run_stratus "external_web" -- \
    --mode external \
    --target "${WEB_IP}" \
    --output-dir /app/output \
    --severity INFO

ok "External scan: web server complete."

# ── 8b: Cloud Function ────────────────────────────────────────────────────────
FUNC_HOST="$(url_host "$FUNC_URL")"
if [[ -n "$FUNC_HOST" ]]; then
    info "External scan: Cloud Function (${FUNC_HOST})"
    info "Reports → ${AUDIT_OUTPUT}/external_function/"

    run_stratus "external_function" -- \
        --mode external \
        --target "${FUNC_HOST}" \
        --output-dir /app/output \
        --severity INFO

    ok "External scan: Cloud Function complete."
else
    warn "Could not determine Cloud Function hostname — skipping external scan."
fi

# ── 8c: Cloud Run ─────────────────────────────────────────────────────────────
RUN_HOST="$(url_host "$RUN_URL")"
if [[ -n "$RUN_HOST" ]]; then
    info "External scan: Cloud Run (${RUN_HOST})"
    info "Reports → ${AUDIT_OUTPUT}/external_cloudrun/"

    run_stratus "external_cloudrun" -- \
        --mode external \
        --target "${RUN_HOST}" \
        --output-dir /app/output \
        --severity INFO

    ok "External scan: Cloud Run complete."
else
    warn "Could not determine Cloud Run hostname — skipping external scan."
fi

# =============================================================================
# Step 9: Audit Summary
# =============================================================================
step "Step 9: Audit complete"

hr
echo ""
echo -e "${BOLD}  Lab Endpoints Scanned:${NC}"
echo "    DVWA web server:   http://${WEB_IP}/  (admin / password)"
echo "    Cloud Function:    ${FUNC_URL}"
echo "    Cloud Run:         ${RUN_URL}"
echo "    Public Bucket:     gs://${BUCKET}"
echo "    Overprivileged SA: ${SA_EMAIL}"
echo ""
echo -e "${BOLD}  Reports generated:${NC}"
for d in internal external_web external_function external_cloudrun; do
    html_file="$(ls "${AUDIT_OUTPUT}/${d}"/*.html 2>/dev/null | head -1 || echo "")"
    md_file="$(ls "${AUDIT_OUTPUT}/${d}"/*.md 2>/dev/null | head -1 || echo "")"
    if [[ -n "$html_file" ]]; then
        echo -e "    ${GREEN}${d}${NC}"
        echo "      HTML: ${html_file}"
        [[ -n "$md_file" ]] && echo "      MD:   ${md_file}"
    else
        echo -e "    ${DIM}${d}: no report (scan skipped or failed)${NC}"
    fi
done
echo ""
echo -e "  All reports: ${BOLD}${AUDIT_OUTPUT}/${NC}"
hr

# =============================================================================
# Step 10: Optional Teardown
# =============================================================================
echo ""
echo -e "${RED}${BOLD}"
echo "  The vulnerable lab is still running and accruing GCP charges."
echo "  Destroy all resources when you are finished."
echo -e "${NC}"
read -rp "  Destroy the lab now? Type 'destroy' to confirm (or press Enter to skip): " DESTROY_CONFIRM

if [[ "$DESTROY_CONFIRM" == "destroy" ]]; then
    step "Step 10: Destroying lab infrastructure"
    info "Running terraform destroy..."
    terraform -chdir="${TERRAFORM_DIR}" destroy -auto-approve
    ok "All resources destroyed."
    rm -f "${TERRAFORM_DIR}/tfplan"
else
    echo ""
    warn "Lab is still running. Destroy it later with:"
    echo "       bash ${SCRIPT_DIR}/cleanup.sh"
    echo "    or: cd ${TERRAFORM_DIR} && terraform destroy -auto-approve"
fi

echo ""
echo -e "${GREEN}${BOLD}  Done. Reports saved to: ${AUDIT_OUTPUT}/${NC}"
echo ""
