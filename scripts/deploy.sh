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

IS_NEW_PROJECT=false

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

  if [[ -n "${DEPLOY_PROVIDER:-}" ]]; then
    choice="$DEPLOY_PROVIDER"
    echo "  Choose [1/2] (default 1): $choice"
  else
    read -rp "  Choose [1/2] (default 1): " choice
    choice="${choice:-1}"
  fi

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
  # ---------------------------------------------------------------------------
  # Step 1 — make sure at least one account is logged in
  # ---------------------------------------------------------------------------
  if ! gcloud auth list --format="value(account)" 2>/dev/null | grep -q '@'; then
    warn "No gcloud accounts found. Starting login..."
    gcloud auth login --update-adc
    ok "Logged in."
  fi

  # ---------------------------------------------------------------------------
  # Step 2 — let the user choose which account to use
  # ---------------------------------------------------------------------------
  echo ""
  echo -e "${BOLD}Google Cloud Account:${NC}"

  # Collect all known accounts (active or not), filtering out service accounts
  mapfile -t all_accounts < <(
    gcloud auth list --format="value(account)" 2>/dev/null \
      | grep -v 'iam\.gserviceaccount\.com' || true
  )
  # Also grab which one is currently active
  local current_active
  current_active=$(gcloud auth list --filter="status:ACTIVE" \
    --format="value(account)" 2>/dev/null | head -1 || echo "")

  echo "  Authenticated accounts:"
  for i in "${!all_accounts[@]}"; do
    local marker="  "
    [[ "${all_accounts[$i]}" == "$current_active" ]] && marker="* "
    printf "  %2d) %s%s\n" "$((i+1))" "$marker" "${all_accounts[$i]}"
  done
  local new_opt=$(( ${#all_accounts[@]} + 1 ))
  printf "  %2d)  Add / login with a different account\n" "$new_opt"
  echo ""

  # Find default selection index (currently active account)
  local default_idx=1
  for i in "${!all_accounts[@]}"; do
    [[ "${all_accounts[$i]}" == "$current_active" ]] && default_idx=$((i+1))
  done

  local acct_sel
  read -rp "  Choose account [${default_idx}]: " acct_sel
  acct_sel="${acct_sel:-$default_idx}"

  local chosen_account
  if [[ "$acct_sel" == "$new_opt" ]]; then
    # Login with a new account and update ADC at the same time
    gcloud auth login --update-adc
    chosen_account=$(gcloud auth list --filter="status:ACTIVE" \
      --format="value(account)" 2>/dev/null | head -1)
  elif [[ "$acct_sel" =~ ^[0-9]+$ ]] && (( acct_sel >= 1 && acct_sel <= ${#all_accounts[@]} )); then
    chosen_account="${all_accounts[$((acct_sel-1))]}"
  else
    die "Invalid selection '$acct_sel'."
  fi

  # Switch active account
  gcloud config set account "$chosen_account" --quiet
  ok "Using account: ${chosen_account}"

  # ---------------------------------------------------------------------------
  # Step 3 — ensure Application Default Credentials match the chosen account
  # ---------------------------------------------------------------------------
  info "Checking Application Default Credentials..."
  local adc_account=""
  adc_account=$(gcloud auth application-default print-access-token \
    --format=json 2>/dev/null \
    | python3 -c "import sys,json; t=json.load(sys.stdin); \
      print(t.get('token_info',{}).get('email',''))" 2>/dev/null || true)

  # If ADC isn't set, or belongs to a different account, refresh it
  if ! gcloud auth application-default print-access-token &>/dev/null \
      || [[ -n "$adc_account" && "$adc_account" != "$chosen_account" ]]; then
    warn "Refreshing ADC for ${chosen_account}..."
    gcloud auth application-default login --account "$chosen_account"
  fi
  ok "Application Default Credentials are configured for ${chosen_account}."
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
  local prev_project="" region="" zone=""

  # Load previous values as defaults — but do NOT skip the interactive menu
  if [[ -f "$tfvars" ]]; then
    prev_project=$(grep -E '^project_id\s*=' "$tfvars" | awk -F'=' '{gsub(/["[:space:]]/, "", $2); print $2}')
    region=$(grep -E '^region\s*=' "$tfvars" | awk -F'=' '{gsub(/["[:space:]]/, "", $2); print $2}')
    zone=$(grep -E '^zone\s*=' "$tfvars" | awk -F'=' '{gsub(/["[:space:]]/, "", $2); print $2}')
  fi

  region="${GCP_REGION:-$region}"
  zone="${GCP_ZONE:-$zone}"

  # Non-interactive shortcut: GCP_PROJECT_ID env var is set
  if [[ -n "${GCP_PROJECT_ID:-}" ]]; then
    PROJECT_ID="$GCP_PROJECT_ID"
    info "Using GCP_PROJECT_ID from environment: $PROJECT_ID"
  else
    # Always show the project setup menu
    echo ""
    echo -e "${BOLD}GCP Project Setup:${NC}"
    if [[ -n "$prev_project" ]]; then
      echo -e "  Previously used project: ${CYAN}${prev_project}${NC}"
    fi
    echo "  1) Use existing project"
    echo "  2) Create new project"
    echo ""

    local proj_choice
    if [[ -n "${GCP_PROJECT_ACTION:-}" ]]; then
      proj_choice="$GCP_PROJECT_ACTION"
      echo "  Choose [1/2] (default 1): $proj_choice"
    else
      read -rp "  Choose [1/2] (default 1): " proj_choice
      proj_choice="${proj_choice:-1}"
    fi

    case "$proj_choice" in
      1)
        echo ""
        echo -e "${BOLD}Existing GCP project:${NC}"
        # Use prev_project as default, fall back to active gcloud project
        local default_project="${prev_project:-$(gcloud config get-value project 2>/dev/null || echo "")}"
        read -rp "  GCP Project ID [${default_project}]: " PROJECT_ID
        PROJECT_ID="${PROJECT_ID:-$default_project}"
        [[ -z "$PROJECT_ID" ]] && die "Project ID cannot be empty."
        if ! gcloud projects describe "$PROJECT_ID" &>/dev/null; then
          die "Project '$PROJECT_ID' not found. Check the ID or choose option 2 to create it."
        fi
        ok "Using project: $PROJECT_ID"
        ;;

      2)
        echo ""
        echo -e "${BOLD}Create a new GCP project:${NC}"
        read -rp "  New Project ID (globally unique, e.g. mylab-$(date +%Y%m%d)): " PROJECT_ID
        [[ -z "$PROJECT_ID" ]] && die "Project ID cannot be empty."
        if gcloud projects describe "$PROJECT_ID" &>/dev/null; then
          die "Project '$PROJECT_ID' already exists. Choose a different ID or use option 1."
        fi

        info "Creating project $PROJECT_ID..."
        gcloud projects create "$PROJECT_ID" --name="Cloud Pentest Lab" --set-as-default
        ok "Project created: $PROJECT_ID"
        IS_NEW_PROJECT=true

        gcloud config set project "$PROJECT_ID" --quiet

        # Enable Service Usage API — required before billing or any paid API can be managed
        info "Enabling Service Usage API on new project..."
        gcloud services enable serviceusage.googleapis.com \
          --project "$PROJECT_ID" --quiet \
          || warn "Could not enable Service Usage API yet (billing may be needed first — continuing)."

        # Grant Service Usage roles (project creator is Owner, but explicit roles are safer)
        local _account
        _account=$(gcloud config get-value account)
        info "Granting Service Usage permissions to $_account..."
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
          --member="user:$_account" \
          --role="roles/serviceusage.serviceUsageConsumer" \
          --quiet || warn "serviceUsageConsumer: may already be covered by Owner role"
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
          --member="user:$_account" \
          --role="roles/serviceusage.serviceUsageAdmin" \
          --quiet || warn "serviceUsageAdmin: may already be covered by Owner role"
        ok "New project permissions configured."
        ;;

      *)
        warn "Invalid choice '$proj_choice'. Please enter 1 or 2."
        setup_tfvars_gcp
        return
        ;;
    esac
  fi

  # Ensure we have region/zone values
  region="${GCP_REGION:-${region:-us-central1}}"
  zone="${GCP_ZONE:-${zone:-us-central1-a}}"

  cat > "$tfvars" <<EOF
project_id = "${PROJECT_ID}"
region     = "${region}"
zone       = "${zone}"
EOF
  ok "Created/updated ${tfvars}"
}

check_gcp_billing() {
  info "Checking GCP billing for project: $PROJECT_ID"

  local billing_account
  billing_account=$(gcloud billing projects describe "$PROJECT_ID" --format="value(billingAccountName)" 2>/dev/null || echo "")

  if [[ -n "$billing_account" && "$IS_NEW_PROJECT" == "false" ]]; then
    ok "Billing account linked: $billing_account"
    return
  fi

  if [[ "$IS_NEW_PROJECT" == "true" ]]; then
    echo ""
    echo -e "${BOLD}New project requires a billing account.${NC}"
    echo "Please select a billing account to link to project ${CYAN}${PROJECT_ID}${NC}:"
  else
    info "No billing account linked to project $PROJECT_ID. Attempting to link one."
  fi

  if [[ -n "${BILLING_ACCOUNT_ID:-}" ]]; then
    selected_name="$BILLING_ACCOUNT_ID"
    echo "Using BILLING_ACCOUNT_ID from env: $selected_name"
  else
    # List available billing accounts — format: billingAccountId TAB displayName TAB open
    mapfile -t acct_ids    < <(gcloud billing accounts list --format="value(name)"        2>/dev/null)
    mapfile -t acct_names  < <(gcloud billing accounts list --format="value(displayName)" 2>/dev/null)
    mapfile -t acct_open   < <(gcloud billing accounts list --format="value(open)"        2>/dev/null)

    if [[ ${#acct_ids[@]} -eq 0 ]]; then
      local cur_user
      cur_user=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1 || echo "<unknown>")
      warn "No billing accounts visible for: $cur_user"
      echo ""
      echo "  To grant yourself Billing Account Viewer so the list shows up, ask a billing admin to run:"
      echo "    gcloud beta billing accounts add-iam-policy-binding <BILLING_ACCOUNT_ID> \\"
      echo "      --member=\"user:${cur_user}\" --role=\"roles/billing.viewer\""
      echo ""
      echo "  Or enter the billing account ID directly. Format: XXXXXX-XXXXXX-XXXXXX"
      echo "  (find it at https://console.cloud.google.com/billing)"
      echo ""
      read -rp "  Billing account ID (or leave empty to abort): " manual_billing
      [[ -z "$manual_billing" ]] && die "No billing account selected. Fix permissions and re-run the script."
      # Normalise: strip leading "billingAccounts/" if user pasted the full resource name
      manual_billing="${manual_billing#billingAccounts/}"
      selected_name="$manual_billing"
    else
      echo ""
      echo "  Available billing accounts:"
      echo "  ─────────────────────────────────────────────────────────────────────"
      for i in "${!acct_ids[@]}"; do
        local status_label="open"
        [[ "${acct_open[$i]:-True}" != "True" ]] && status_label="closed"
        # Strip "billingAccounts/" prefix for display — gcloud billing projects link accepts both
        local short_id="${acct_ids[$i]#billingAccounts/}"
        printf "  %2d)  %-35s  %-22s  [%s]\n" \
          "$((i+1))" "${acct_names[$i]}" "$short_id" "$status_label"
      done
      echo "  ─────────────────────────────────────────────────────────────────────"
      echo ""

      local acct_choice
      read -rp "  Select billing account [1]: " acct_choice
      acct_choice="${acct_choice:-1}"

      if ! [[ "$acct_choice" =~ ^[0-9]+$ ]] || (( acct_choice < 1 || acct_choice > ${#acct_ids[@]} )); then
        die "Invalid selection '$acct_choice'. Please rerun the script and choose a valid number."
      fi

      # Use the full resource name (billingAccounts/XXXX) — gcloud accepts it
      selected_name="${acct_ids[$((acct_choice-1))]}"
      ok "Selected: ${acct_names[$((acct_choice-1))]}  (${selected_name#billingAccounts/})"
    fi
  fi

  info "Linking project $PROJECT_ID to billing account $selected_name..."
  local link_err
  if ! link_err=$(gcloud billing projects link "$PROJECT_ID" --billing-account "$selected_name" --quiet 2>&1); then
    warn "Failed to link billing account."
    echo "--- gcloud output ---"
    echo "$link_err"
    echo "---------------------"

    echo "It looks like your user does not have permission to link the project to the billing account."
    echo "Common fixes:"
    echo "  • Ensure you are using a user with Billing Account User/Administrator access on the billing account." 
    echo "  • Make sure the project is owned by or you have Owner access to the project."
    echo "  • If using an org, ensure there are no policy restrictions preventing billing associations."

    local _cur_user
    _cur_user=$(gcloud config get-value account 2>/dev/null || echo "YOU@example.com")
    echo "  To grant the required permission, a billing admin must run:"
    echo "    gcloud beta billing accounts add-iam-policy-binding ${selected_name#billingAccounts/} \\"
    echo "      --member=\"user:${_cur_user}\" --role=\"roles/billing.user\""

    read -rp "Alternatively, you can link the billing account manually in the GCP Console (https://console.cloud.google.com/billing/projects) and then press Enter to continue, or type 'abort' to exit: " manual_link
    if [[ "$manual_link" == "abort" ]]; then
      die "Billing linking aborted. Fix permissions and re-run the script."
    fi

    # Check again after manual link
    billing_account=$(gcloud billing projects describe "$PROJECT_ID" --format="value(billingAccountName)" 2>/dev/null || echo "")
    if [[ -z "$billing_account" ]]; then
      die "Billing still not linked after manual attempt. Please ensure it's linked in the console and re-run the script."
    fi
  else
    billing_account=$(gcloud billing projects describe "$PROJECT_ID" --format="value(billingAccountName)" 2>/dev/null || echo "")
    if [[ -z "$billing_account" ]]; then
      die "Failed to verify billing association after linking. Please check the project and billing settings." 
    fi
  fi

  ok "Billing account linked: $billing_account"
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

setup_gcp_project() {
  info "Setting up GCP project: $PROJECT_ID"

  # Set project in gcloud config
  gcloud config set project "$PROJECT_ID" --quiet

  # Set ADC quota project
  gcloud auth application-default set-quota-project "$PROJECT_ID" --quiet \
    || warn "Could not set ADC quota project (may not be needed)"

  # Ensure Service Usage API is enabled (idempotent — already done for new projects)
  info "Enabling Service Usage API..."
  gcloud services enable serviceusage.googleapis.com --project "$PROJECT_ID" --quiet

  # Grant Service Usage roles (idempotent)
  local account
  account=$(gcloud config get-value account)
  info "Granting Service Usage permissions to $account..."
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="user:$account" \
    --role="roles/serviceusage.serviceUsageConsumer" \
    --quiet || warn "serviceUsageConsumer may already be set"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="user:$account" \
    --role="roles/serviceusage.serviceUsageAdmin" \
    --quiet || warn "serviceUsageAdmin may already be set"

  # Enable all required APIs
  info "Enabling required GCP APIs..."
  gcloud services enable \
    compute.googleapis.com \
    storage.googleapis.com \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com \
    secretmanager.googleapis.com \
    container.googleapis.com \
    run.googleapis.com \
    cloudfunctions.googleapis.com \
    cloudbuild.googleapis.com \
    --project "$PROJECT_ID" \
    --quiet

  ok "GCP project setup complete."
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
  check_gcp_billing
  setup_gcp_project
else
  check_aws_auth
  setup_tfvars_aws
fi

terraform_init
terraform_plan
terraform_apply
print_summary
