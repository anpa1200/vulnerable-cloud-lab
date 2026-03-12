#!/usr/bin/env bash
# =============================================================================
# verify.sh — Post-deploy vulnerability verification for the GCP Lab
# =============================================================================
# Checks that all intentional vulnerabilities are reachable and working.
# Run this after 'deploy.sh' completes.
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

PASS=0
FAIL=0

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[PASS]${NC} $*"; ((PASS++)) || true; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; ((FAIL++)) || true; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()   { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Get terraform outputs
# ---------------------------------------------------------------------------

tf_output() {
  terraform -chdir="${TERRAFORM_DIR}" output -raw "$1" 2>/dev/null || echo ""
}

get_outputs() {
  info "Reading Terraform outputs..."
  WEB_IP=$(tf_output web_server_ip)
  FUNCTION_URL=$(tf_output cloud_function_url)
  RUN_URL=$(tf_output cloud_run_url)
  BUCKET_NAME=$(tf_output vulnerable_bucket_name)

  [[ -z "$WEB_IP" ]]       && die "Could not read web_server_ip from terraform output. Is the lab deployed?"
  [[ -z "$FUNCTION_URL" ]] && die "Could not read cloud_function_url"
  [[ -z "$RUN_URL" ]]      && die "Could not read cloud_run_url"
  [[ -z "$BUCKET_NAME" ]]  && die "Could not read vulnerable_bucket_name"

  info "Web server IP  : ${WEB_IP}"
  info "Cloud Function : ${FUNCTION_URL}"
  info "Cloud Run      : ${RUN_URL}"
  info "Bucket         : ${BUCKET_NAME}"
  echo ""
}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

http_status() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$1" 2>/dev/null || echo "000"
}

http_body() {
  curl -s --max-time 10 "$1" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# DVWA checks
# ---------------------------------------------------------------------------

check_dvwa() {
  echo -e "${BOLD}── DVWA / Web Server ──────────────────────────────────────────${NC}"

  local status
  status=$(http_status "http://${WEB_IP}/")
  if [[ "$status" == "200" || "$status" == "302" ]]; then
    ok "DVWA is reachable at http://${WEB_IP}/ (HTTP ${status})"
  else
    fail "DVWA not reachable (HTTP ${status})"
  fi

  status=$(http_status "http://${WEB_IP}/info.php")
  if [[ "$status" == "200" ]]; then
    ok "Information disclosure page accessible: http://${WEB_IP}/info.php"
  else
    fail "info.php not reachable (HTTP ${status})"
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# Cloud Function checks
# ---------------------------------------------------------------------------

check_cloud_function() {
  echo -e "${BOLD}── Cloud Function Vulnerabilities ─────────────────────────────${NC}"

  local status
  status=$(http_status "${FUNCTION_URL}")
  if [[ "$status" == "200" ]]; then
    ok "Cloud Function reachable (HTTP 200)"
  else
    fail "Cloud Function not reachable (HTTP ${status})"
    return
  fi

  # RCE
  local rce_body
  rce_body=$(http_body "${FUNCTION_URL}?cmd=id")
  if echo "$rce_body" | grep -q "uid="; then
    ok "RCE (?cmd=id): confirmed — output: $(echo "$rce_body" | head -1)"
  else
    fail "RCE (?cmd=id): unexpected response: ${rce_body:0:100}"
  fi

  # Env dump
  local env_body
  env_body=$(http_body "${FUNCTION_URL}?env=1")
  if echo "$env_body" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    ok "Env dump (?env=1): returns JSON environment variables"
  else
    fail "Env dump (?env=1): did not return valid JSON"
  fi

  # Path traversal
  local pt_body
  pt_body=$(http_body "${FUNCTION_URL}?file=/etc/passwd")
  if echo "$pt_body" | grep -q "root:"; then
    ok "Path traversal (?file=/etc/passwd): confirmed — /etc/passwd readable"
  else
    fail "Path traversal (?file=/etc/passwd): unexpected response"
  fi

  # SSRF endpoint exists
  status=$(http_status "${FUNCTION_URL}?url=http://example.com")
  if [[ "$status" == "200" || "$status" == "500" ]]; then
    ok "SSRF (?url=): endpoint active (HTTP ${status})"
  else
    fail "SSRF endpoint returned unexpected status ${status}"
  fi

  echo ""
}

# ---------------------------------------------------------------------------
# Cloud Run checks
# ---------------------------------------------------------------------------

check_cloud_run() {
  echo -e "${BOLD}── Cloud Run ───────────────────────────────────────────────────${NC}"

  local status
  status=$(http_status "${RUN_URL}")
  if [[ "$status" == "200" ]]; then
    ok "Cloud Run publicly accessible (HTTP 200) — no auth required"
  elif [[ "$status" == "401" || "$status" == "403" ]]; then
    fail "Cloud Run requires authentication (HTTP ${status}) — allUsers invoker not set"
  else
    fail "Cloud Run returned unexpected HTTP ${status}"
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# Storage bucket checks
# ---------------------------------------------------------------------------

check_bucket() {
  echo -e "${BOLD}── Public Storage Bucket ───────────────────────────────────────${NC}"

  local creds_url="https://storage.googleapis.com/${BUCKET_NAME}/secrets/database-credentials.json"
  local status
  status=$(http_status "$creds_url")
  if [[ "$status" == "200" ]]; then
    ok "Database credentials publicly accessible: ${creds_url}"
    local body
    body=$(http_body "$creds_url")
    if echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys()))" 2>/dev/null; then
      ok "Credentials file is valid JSON with sensitive fields"
    fi
  else
    fail "Credentials file not accessible (HTTP ${status})"
  fi

  local key_url="https://storage.googleapis.com/${BUCKET_NAME}/keys/id_rsa"
  status=$(http_status "$key_url")
  if [[ "$status" == "200" ]]; then
    local key_body
    key_body=$(http_body "$key_url")
    if echo "$key_body" | grep -q "PRIVATE KEY\|BEGIN RSA"; then
      ok "Private SSH key publicly readable: ${key_url}"
    else
      warn "SSH key file accessible but content looks unexpected"
    fi
  else
    fail "SSH key not accessible (HTTP ${status})"
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Verification Summary${NC}"
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
  echo -e "  ${GREEN}Passed: ${PASS}${NC}"
  echo -e "  ${RED}Failed: ${FAIL}${NC}"
  echo ""

  if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}  All checks passed! The lab is fully operational.${NC}"
  else
    echo -e "${YELLOW}${BOLD}  Some checks failed. Review the output above.${NC}"
    echo "  The lab may still be initialising — wait a few minutes and retry."
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo -e "${CYAN}${BOLD}"
echo "  GCP Vulnerable Cloud Lab — Post-Deploy Verification"
echo -e "${NC}"

get_outputs
check_dvwa
check_cloud_function
check_cloud_run
check_bucket
print_summary
