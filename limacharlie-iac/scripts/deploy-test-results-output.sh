#!/bin/bash

# F0RT1KA Test Results - Elasticsearch Output Deployment Script
# Deploys Elasticsearch output configuration and D&R rule to LimaCharlie organizations
#
# Prerequisites:
#   - LimaCharlie CLI installed (pip install limacharlie)
#   - Authenticated with LimaCharlie (limacharlie login)
#   - Elastic Cloud credentials (cloud_id and api_key)
#
# Usage:
#   ./deploy-test-results-output.sh <org-name>           # Deploy to single org
#   ./deploy-test-results-output.sh all                  # Deploy to all orgs
#   ./deploy-test-results-output.sh --test <org-name>    # Test mode (dry run)
#
# Environment Variables (optional):
#   ELASTIC_CLOUD_ID    - Elastic Cloud deployment ID
#   ELASTIC_API_KEY     - Elasticsearch API key

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAC_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$IAC_DIR/outputs"
RULE_FILE="$IAC_DIR/rules/f0-test-results-to-elasticsearch.yaml"

# Organization list
ORGS=("sb" "tpsgl" "rga")

# Organization to index mapping
declare -A ORG_INDICES
ORG_INDICES["sb"]="f0rtika-results-sb"
ORG_INDICES["tpsgl"]="f0rtika-results-tpsgl"
ORG_INDICES["rga"]="f0rtika-results-rga"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo ""
    echo "================================================================="
    echo "  F0RT1KA Test Results - Elasticsearch Output Deployment"
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

print_step() {
    echo -e "${CYAN}[STEP $1]${NC} $2"
}

check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check if limacharlie CLI is installed
    if ! command -v limacharlie &> /dev/null; then
        print_error "LimaCharlie CLI not found. Install it with: pip install limacharlie"
        exit 1
    fi

    print_success "LimaCharlie CLI found: $(limacharlie --version 2>&1 | head -1)"

    # Check if rule file exists
    if [[ ! -f "$RULE_FILE" ]]; then
        print_error "Rule file not found: $RULE_FILE"
        exit 1
    fi

    print_success "Rule file found: $RULE_FILE"

    # Check if output configs exist
    for org in "${ORGS[@]}"; do
        output_file="$OUTPUT_DIR/f0-elasticsearch-output-$org.yaml"
        if [[ ! -f "$output_file" ]]; then
            print_warning "Output config not found for $org: $output_file"
        fi
    done

    echo ""
}

get_elastic_credentials() {
    local org=$1

    # Check for environment variables first
    if [[ -n "$ELASTIC_CLOUD_ID" ]] && [[ -n "$ELASTIC_API_KEY" ]]; then
        print_info "Using Elastic credentials from environment variables"
        CLOUD_ID="$ELASTIC_CLOUD_ID"
        API_KEY="$ELASTIC_API_KEY"
        return 0
    fi

    # Prompt for credentials
    echo ""
    print_info "Enter Elastic Cloud credentials for organization: $org"
    echo ""

    read -p "Elastic Cloud ID: " CLOUD_ID
    if [[ -z "$CLOUD_ID" ]]; then
        print_error "Cloud ID is required"
        return 1
    fi

    read -s -p "Elasticsearch API Key: " API_KEY
    echo ""
    if [[ -z "$API_KEY" ]]; then
        print_error "API Key is required"
        return 1
    fi

    print_success "Credentials collected"
    echo ""
}

configure_output() {
    local org=$1
    local test_mode=$2

    local index="${ORG_INDICES[$org]}"
    local output_name="f0-test-results-elasticsearch"

    print_step "1/3" "Configuring Elasticsearch output for: $org"
    print_info "Output name: $output_name"
    print_info "Target index: $index"

    if [[ "$test_mode" == "true" ]]; then
        print_warning "TEST MODE: Would configure output with:"
        echo "   module: elastic"
        echo "   stream: tailored"
        echo "   cloud_id: <redacted>"
        echo "   api_key: <redacted>"
        echo "   index: $index"
        return 0
    fi

    # Switch to organization
    print_info "Switching to organization: $org"
    if ! limacharlie use "$org" 2>&1; then
        print_error "Failed to switch to organization: $org"
        return 1
    fi

    # Check if output already exists
    if limacharlie output list 2>&1 | grep -q "$output_name"; then
        print_warning "Output '$output_name' already exists. Updating..."
        # Delete existing output first
        limacharlie output delete "$output_name" 2>&1 || true
    fi

    # Create the output
    if limacharlie output add "$output_name" \
        --module elastic \
        --stream tailored \
        --config "cloud_id=$CLOUD_ID" \
        --config "api_key=$API_KEY" \
        --config "index=$index" 2>&1; then
        print_success "Elasticsearch output configured: $output_name -> $index"
    else
        print_error "Failed to configure Elasticsearch output"
        return 1
    fi
}

deploy_rule() {
    local org=$1
    local test_mode=$2

    local rule_name="f0-test-results-to-elasticsearch"

    print_step "2/3" "Deploying D&R rule: $rule_name"

    if [[ "$test_mode" == "true" ]]; then
        print_warning "TEST MODE: Would deploy rule from $RULE_FILE"
        return 0
    fi

    # Ensure we're on the right organization
    if ! limacharlie use "$org" 2>&1; then
        print_error "Failed to switch to organization: $org"
        return 1
    fi

    # Check if rule already exists
    if limacharlie dr list 2>&1 | grep -q "$rule_name"; then
        print_warning "Rule '$rule_name' already exists. Updating..."
        limacharlie dr delete "$rule_name" 2>&1 || true
    fi

    # Deploy rule
    if limacharlie dr add -f "$RULE_FILE" 2>&1; then
        print_success "D&R rule deployed: $rule_name"
    else
        print_error "Failed to deploy D&R rule"
        return 1
    fi
}

verify_deployment() {
    local org=$1

    print_step "3/3" "Verifying deployment for: $org"

    if ! limacharlie use "$org" 2>&1; then
        print_error "Failed to switch to organization: $org"
        return 1
    fi

    # Check output
    if limacharlie output list 2>&1 | grep -q "f0-test-results-elasticsearch"; then
        print_success "Elasticsearch output found"
    else
        print_warning "Elasticsearch output NOT found"
    fi

    # Check rule
    if limacharlie dr list 2>&1 | grep -q "f0-test-results-to-elasticsearch"; then
        print_success "D&R rule found"
    else
        print_warning "D&R rule NOT found"
    fi
}

deploy_to_org() {
    local org=$1
    local test_mode=$2

    echo ""
    echo "================================================================="
    print_info "Deploying to Organization: $org"
    echo "  Index: ${ORG_INDICES[$org]}"
    echo "================================================================="

    # Get credentials for this org
    get_elastic_credentials "$org"

    # Step 1: Configure Elasticsearch output
    configure_output "$org" "$test_mode"

    # Step 2: Deploy D&R rule
    deploy_rule "$org" "$test_mode"

    # Step 3: Verify deployment
    verify_deployment "$org"

    echo ""
    print_success "Deployment to $org completed!"
    echo "================================================================="
}

print_usage() {
    echo ""
    echo "Usage: $0 [--test] <org-name|all>"
    echo ""
    echo "Arguments:"
    echo "  org-name    Deploy to specific organization (sb, tpsgl, rga)"
    echo "  all         Deploy to all organizations"
    echo ""
    echo "Options:"
    echo "  --test      Test mode (dry run, no actual changes)"
    echo ""
    echo "Environment Variables:"
    echo "  ELASTIC_CLOUD_ID    Elastic Cloud deployment ID (optional)"
    echo "  ELASTIC_API_KEY     Elasticsearch API key (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 sb                           # Deploy to 'sb' organization"
    echo "  $0 all                          # Deploy to all organizations"
    echo "  $0 --test sb                    # Test mode (dry run)"
    echo ""
    echo "  # Using environment variables:"
    echo "  ELASTIC_CLOUD_ID=xxx ELASTIC_API_KEY=yyy $0 sb"
    echo ""
    echo "Available organizations: ${ORGS[*]}"
    echo ""
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

if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    print_usage
    exit 0
fi

TARGET_ORG=$1

if [[ -z "$TARGET_ORG" ]]; then
    print_error "No organization specified"
    print_usage
    exit 1
fi

# Validate organization
if [[ "$TARGET_ORG" != "all" ]]; then
    valid_org=false
    for org in "${ORGS[@]}"; do
        if [[ "$org" == "$TARGET_ORG" ]]; then
            valid_org=true
            break
        fi
    done

    if [[ "$valid_org" == "false" ]]; then
        print_error "Invalid organization: $TARGET_ORG"
        echo "Available organizations: ${ORGS[*]}"
        exit 1
    fi
fi

if [[ "$TARGET_ORG" == "all" ]]; then
    print_info "Deploying to ALL organizations: ${ORGS[*]}"
    echo ""

    # Ask if same credentials for all orgs
    read -p "Use same Elastic credentials for all organizations? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        get_elastic_credentials "all"
        for org in "${ORGS[@]}"; do
            configure_output "$org" "$TEST_MODE"
            deploy_rule "$org" "$TEST_MODE"
            verify_deployment "$org"
            echo ""
            sleep 2
        done
    else
        for org in "${ORGS[@]}"; do
            deploy_to_org "$org" "$TEST_MODE"
            sleep 2
        done
    fi

    print_success "All deployments completed!"

else
    # Single organization deployment
    deploy_to_org "$TARGET_ORG" "$TEST_MODE"
fi

echo ""
print_success "Deployment script completed!"
echo ""
print_info "Next steps:"
echo "  1. Run a F0RT1KA test on a monitored endpoint:"
echo "     limacharlie run --sid <sensor-id> --path c:\\F0\\test-uuid.exe --timeout 420"
echo ""
echo "  2. Check LimaCharlie for RECEIPT event"
echo ""
echo "  3. Verify document in Elasticsearch:"
echo "     GET /f0rtika-results-{org}/_search?q=routing.event_type:RECEIPT"
echo ""
echo "  4. Create Kibana dashboard for test results visualization"
echo ""
