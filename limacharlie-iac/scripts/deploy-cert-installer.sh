#!/bin/bash

# F0RT1KA Certificate Auto-Installation Deployment Script
# Deploys certificate installation automation to LimaCharlie organizations
#
# Prerequisites:
#   - LimaCharlie CLI installed (pip install limacharlie)
#   - API keys configured for target organizations
#   - Payload uploaded to LimaCharlie
#
# Usage:
#   ./deploy-cert-installer.sh <org-name>           # Deploy to single org
#   ./deploy-cert-installer.sh all                  # Deploy to all orgs
#   ./deploy-cert-installer.sh --test <org-name>    # Test mode (dry run)

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAC_DIR="$(dirname "$SCRIPT_DIR")"
PAYLOAD_FILE="$IAC_DIR/payloads/install-f0rtika-cert.ps1"
RULE_FILE="$IAC_DIR/rules/f0rtika-cert-auto-install.yaml"
MONITOR_RULE_FILE="$IAC_DIR/rules/f0rtika-cert-install-monitor.yaml"
SUCCESS_RULE_FILE="$IAC_DIR/rules/f0rtika-cert-install-success-monitor.yaml"

# Organization list (customize as needed)
ORGS=("sb" "tpsgl" "rga")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo ""
    echo "================================================================="
    echo "  F0RT1KA Certificate Auto-Installation - LimaCharlie Deployment"
    echo "================================================================="
    echo ""
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check if limacharlie CLI is installed
    if ! command -v limacharlie &> /dev/null; then
        print_error "LimaCharlie CLI not found. Install it with: pip install limacharlie"
        exit 1
    fi

    print_success "LimaCharlie CLI found: $(limacharlie --version 2>&1 | head -1)"

    # Check if payload file exists
    if [[ ! -f "$PAYLOAD_FILE" ]]; then
        print_error "Payload file not found: $PAYLOAD_FILE"
        exit 1
    fi

    print_success "Payload file found: $PAYLOAD_FILE"

    # Check if rule files exist
    if [[ ! -f "$RULE_FILE" ]]; then
        print_error "Rule file not found: $RULE_FILE"
        exit 1
    fi

    print_success "Rule file found: $RULE_FILE"

    echo ""
}

upload_payload() {
    local org=$1
    local test_mode=$2

    print_info "Uploading payload to organization: $org"

    if [[ "$test_mode" == "true" ]]; then
        print_warning "TEST MODE: Would upload $PAYLOAD_FILE as 'f0rtika-cert-installer'"
        return 0
    fi

    # Note: This requires manual upload via web UI or REST API
    # The CLI doesn't have a direct payload upload command
    print_warning "Payload upload must be done via LimaCharlie Web UI or REST API:"
    echo "   1. Navigate to: Sensors > Payloads"
    echo "   2. Click 'Create Payload'"
    echo "   3. Name: f0rtika-cert-installer"
    echo "   4. Upload: $PAYLOAD_FILE"
    echo ""
    print_info "Press Enter once payload is uploaded, or Ctrl+C to cancel..."
    read -r

    print_success "Payload upload confirmed"
}

deploy_rule() {
    local org=$1
    local rule_file=$2
    local rule_name=$3
    local test_mode=$4

    print_info "Deploying rule '$rule_name' to organization: $org"

    if [[ "$test_mode" == "true" ]]; then
        print_warning "TEST MODE: Would deploy rule from $rule_file"
        return 0
    fi

    # Deploy using limacharlie CLI
    if limacharlie --org "$org" dr add "$rule_file" 2>&1; then
        print_success "Rule deployed successfully: $rule_name"
    else
        print_error "Failed to deploy rule: $rule_name"
        return 1
    fi
}

deploy_to_org() {
    local org=$1
    local test_mode=$2

    echo ""
    echo "================================================================="
    print_info "Deploying to Organization: $org"
    echo "================================================================="

    # Step 1: Upload payload (manual confirmation)
    upload_payload "$org" "$test_mode"

    # Step 2: Deploy auto-installation rule
    deploy_rule "$org" "$RULE_FILE" "f0rtika-cert-auto-install" "$test_mode"

    # Step 3: Deploy monitoring rule (optional)
    read -p "Deploy monitoring rule for installation failures? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        deploy_rule "$org" "$MONITOR_RULE_FILE" "f0rtika-cert-install-monitor" "$test_mode"
    fi

    # Step 4: Deploy success monitoring rule (optional)
    read -p "Deploy success monitoring rule for audit trail? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        deploy_rule "$org" "$SUCCESS_RULE_FILE" "f0rtika-cert-install-success-monitor" "$test_mode"
    fi

    echo ""
    print_success "Deployment to $org completed!"
    echo "================================================================="
}

verify_deployment() {
    local org=$1

    print_info "Verifying deployment for organization: $org"

    # Check if rule exists
    if limacharlie --org "$org" dr list 2>&1 | grep -q "f0rtika-cert-auto-install"; then
        print_success "Auto-installation rule found in organization"
    else
        print_warning "Auto-installation rule NOT found in organization"
    fi
}

# Main execution
print_banner
check_prerequisites

TEST_MODE=false

# Parse arguments
if [[ "$1" == "--test" ]]; then
    TEST_MODE=true
    shift
    print_warning "Running in TEST MODE (dry run)"
    echo ""
fi

TARGET_ORG=$1

if [[ -z "$TARGET_ORG" ]]; then
    print_error "Usage: $0 [--test] <org-name|all>"
    echo ""
    echo "Examples:"
    echo "  $0 sb              # Deploy to 'sb' organization"
    echo "  $0 all             # Deploy to all organizations"
    echo "  $0 --test sb       # Test mode (dry run)"
    echo ""
    echo "Available organizations: ${ORGS[*]}"
    exit 1
fi

if [[ "$TARGET_ORG" == "all" ]]; then
    print_info "Deploying to ALL organizations: ${ORGS[*]}"
    echo ""

    for org in "${ORGS[@]}"; do
        deploy_to_org "$org" "$TEST_MODE"
        sleep 2
    done

    print_success "All deployments completed!"

else
    # Single organization deployment
    deploy_to_org "$TARGET_ORG" "$TEST_MODE"
fi

echo ""
print_success "Deployment script completed!"
echo ""
print_info "Next steps:"
echo "  1. Install a LimaCharlie sensor on a Windows VM"
echo "  2. Monitor deployment events for CONNECTED trigger"
echo "  3. Check RECEIPT event for installation output"
echo "  4. Verify certificate: certutil -store Root | findstr /i 'F0RT1KA'"
echo "  5. Deploy F0RT1KA tests (no cert_installer needed)"
echo ""
