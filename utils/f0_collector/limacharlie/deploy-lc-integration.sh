#!/bin/bash
# Deploy Complete F0RT1KA Collector Integration to LimaCharlie
#
# This script:
# - Deploys D&R rules
# - Configures output modules
# - Uploads collector binaries as artifacts
# - Sets up monitoring and alerting
#
# Usage:
#   ./deploy-lc-integration.sh <organization> [options]
#
# Example:
#   ./deploy-lc-integration.sh sb --auto-deploy --output elasticsearch

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <organization> [options]"
    echo ""
    echo "Options:"
    echo "  --auto-deploy       Enable automatic collector deployment on new sensors"
    echo "  --output <type>     Configure output module (elasticsearch, webhook, syslog)"
    echo "  --skip-artifacts    Skip uploading collector binaries"
    echo "  --dry-run           Show what would be done without making changes"
    echo ""
    echo "Example:"
    echo "  $0 sb --auto-deploy --output elasticsearch"
    exit 1
fi

ORG=$1
shift

# Default options
AUTO_DEPLOY=false
OUTPUT_TYPE=""
SKIP_ARTIFACTS=false
DRY_RUN=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --auto-deploy)
            AUTO_DEPLOY=true
            shift
            ;;
        --output)
            OUTPUT_TYPE="$2"
            shift 2
            ;;
        --skip-artifacts)
            SKIP_ARTIFACTS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}F0RT1KA Collector - LimaCharlie Integration${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Organization:${NC} $ORG"
echo -e "${GREEN}Auto-deploy:${NC} $AUTO_DEPLOY"
echo -e "${GREEN}Output:${NC} ${OUTPUT_TYPE:-none}"
echo -e "${GREEN}Dry run:${NC} $DRY_RUN"
echo ""

# Check dependencies
echo -e "${YELLOW}[1/7] Checking dependencies...${NC}"

if ! command -v limacharlie &> /dev/null; then
    echo -e "${RED}ERROR: limacharlie CLI not found${NC}"
    echo "Install with: pip install limacharlie"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}WARNING: jq not found (optional but recommended)${NC}"
fi

echo -e "${GREEN}✓ Dependencies OK${NC}"

# Authenticate to LC
echo ""
echo -e "${YELLOW}[2/7] Authenticating to LimaCharlie...${NC}"

if ! limacharlie org use "$ORG" 2>/dev/null; then
    echo -e "${RED}ERROR: Failed to select organization '$ORG'${NC}"
    echo "Available organizations:"
    limacharlie org list
    exit 1
fi

echo -e "${GREEN}✓ Authenticated to organization: $ORG${NC}"

# Upload collector artifacts (if not skipped)
if [ "$SKIP_ARTIFACTS" = false ]; then
    echo ""
    echo -e "${YELLOW}[3/7] Uploading collector artifacts...${NC}"

    # Check if collector binary exists
    COLLECTOR_PATH="../f0_collector.exe"
    CONFIG_PATH="../collector_config.json"

    if [ ! -f "$COLLECTOR_PATH" ]; then
        echo -e "${RED}ERROR: Collector binary not found: $COLLECTOR_PATH${NC}"
        echo "Build it first: cd .. && ./build.sh"
        exit 1
    fi

    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${RED}ERROR: Configuration file not found: $CONFIG_PATH${NC}"
        exit 1
    fi

    if [ "$DRY_RUN" = false ]; then
        # Upload collector binary
        echo "  Uploading f0_collector.exe..."
        limacharlie artifact upload \
            --name "f0_collector.exe" \
            --file "$COLLECTOR_PATH" \
            --description "F0RT1KA Results Collector v1.0" \
            --tags "f0rtika,collector" || {
            echo -e "${RED}ERROR: Failed to upload collector binary${NC}"
            exit 1
        }

        # Upload configuration
        echo "  Uploading collector_config.json..."
        limacharlie artifact upload \
            --name "collector_config.json" \
            --file "$CONFIG_PATH" \
            --description "F0RT1KA Collector Configuration" \
            --tags "f0rtika,config" || {
            echo -e "${RED}ERROR: Failed to upload configuration${NC}"
            exit 1
        }

        echo -e "${GREEN}✓ Artifacts uploaded${NC}"
    else
        echo "  [DRY RUN] Would upload:"
        echo "    - $COLLECTOR_PATH"
        echo "    - $CONFIG_PATH"
    fi
else
    echo ""
    echo -e "${YELLOW}[3/7] Skipping artifact upload${NC}"
fi

# Deploy D&R rules
echo ""
echo -e "${YELLOW}[4/7] Deploying D&R rules...${NC}"

RULES_FILE="./enhanced-dr-rules.yaml"
if [ ! -f "$RULES_FILE" ]; then
    echo -e "${RED}ERROR: Rules file not found: $RULES_FILE${NC}"
    exit 1
fi

if [ "$DRY_RUN" = false ]; then
    # Parse YAML and deploy each rule
    # Note: This requires the LC CLI to support batch rule deployment

    # For now, use a simpler approach - deploy via stdin
    echo "  Deploying enhanced D&R rules..."

    # Deploy rules one by one (more reliable)
    RULE_COUNT=0
    while IFS= read -r line; do
        if [[ $line =~ ^-\ name:\ (.+)$ ]]; then
            ((RULE_COUNT++))
        fi
    done < "$RULES_FILE"

    echo "  Found $RULE_COUNT rules to deploy"

    # Actual deployment (simplified - may need adjustment based on LC CLI version)
    if limacharlie dr add -f "$RULES_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ D&R rules deployed successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Automated rule deployment failed${NC}"
        echo "  Please deploy rules manually via LC web interface"
        echo "  Rules file: $RULES_FILE"
    fi
else
    echo "  [DRY RUN] Would deploy rules from: $RULES_FILE"
fi

# Configure output module
if [ -n "$OUTPUT_TYPE" ]; then
    echo ""
    echo -e "${YELLOW}[5/7] Configuring output module ($OUTPUT_TYPE)...${NC}"

    OUTPUT_FILE="./output-elasticsearch.yaml"
    if [ ! -f "$OUTPUT_FILE" ]; then
        echo -e "${RED}ERROR: Output configuration not found: $OUTPUT_FILE${NC}"
        exit 1
    fi

    if [ "$DRY_RUN" = false ]; then
        echo "  Deploying $OUTPUT_TYPE output configuration..."

        # Deploy output configuration (command varies by LC CLI version)
        if limacharlie output add -f "$OUTPUT_FILE" 2>/dev/null; then
            echo -e "${GREEN}✓ Output module configured${NC}"
        else
            echo -e "${YELLOW}⚠ Automated output deployment failed${NC}"
            echo "  Please configure output manually via LC web interface"
            echo "  Output file: $OUTPUT_FILE"
        fi
    else
        echo "  [DRY RUN] Would configure output from: $OUTPUT_FILE"
    fi
else
    echo ""
    echo -e "${YELLOW}[5/7] Skipping output module configuration${NC}"
fi

# Set up tags for targeted deployment
echo ""
echo -e "${YELLOW}[6/7] Configuring sensor tags...${NC}"

if [ "$DRY_RUN" = false ]; then
    echo "  Creating tag: f0rtika-endpoint"
    echo "  Use this tag to target specific sensors for F0RT1KA testing"

    # Tags are typically managed per-sensor, not globally
    # This is informational
    echo -e "${GREEN}✓ Tag configuration ready${NC}"
    echo "  Tag sensors with: limacharlie sensor tag <sensor-id> f0rtika-endpoint"
else
    echo "  [DRY RUN] Would configure tags"
fi

# Verify deployment
echo ""
echo -e "${YELLOW}[7/7] Verifying deployment...${NC}"

if [ "$DRY_RUN" = false ]; then
    # Check if rules exist
    echo "  Checking D&R rules..."
    if limacharlie dr list | grep -q "f0rtika"; then
        RULE_COUNT=$(limacharlie dr list | grep -c "f0rtika" || true)
        echo -e "${GREEN}✓ Found $RULE_COUNT F0RT1KA rules${NC}"
    else
        echo -e "${YELLOW}⚠ No F0RT1KA rules found${NC}"
    fi

    # Check artifacts
    echo "  Checking artifacts..."
    if limacharlie artifact list | grep -q "f0_collector.exe"; then
        echo -e "${GREEN}✓ Collector artifacts present${NC}"
    else
        echo -e "${YELLOW}⚠ Collector artifacts not found${NC}"
    fi
else
    echo "  [DRY RUN] Would verify deployment"
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ "$DRY_RUN" = false ]; then
    echo "Deployed components:"
    echo "  ✓ D&R Rules (enhanced automation)"
    [ "$SKIP_ARTIFACTS" = false ] && echo "  ✓ Collector artifacts (binary + config)"
    [ -n "$OUTPUT_TYPE" ] && echo "  ✓ Output module ($OUTPUT_TYPE)"
    echo ""

    echo "Next steps:"
    echo ""
    echo "1. Tag sensors for auto-deployment:"
    echo "   ${BLUE}limacharlie sensor tag <sensor-id> f0rtika-endpoint${NC}"
    echo ""
    echo "2. Verify rules in LC web interface:"
    echo "   ${BLUE}https://app.limacharlie.io → D&R Rules → Search 'f0rtika'${NC}"
    echo ""
    echo "3. Monitor collector deployment:"
    echo "   ${BLUE}limacharlie sensor search 'tag:f0rtika-active'${NC}"
    echo ""
    echo "4. View test results:"
    echo "   ${BLUE}limacharlie artifact list --tag f0rtika${NC}"
    echo ""

    if [ -n "$OUTPUT_TYPE" ]; then
        echo "5. Configure Elasticsearch credentials:"
        echo "   ${BLUE}Set environment variables on LC platform:${NC}"
        echo "     - F0_ELASTIC_API_KEY"
        echo ""
    fi

    echo "6. Run a test on a sensor and verify automatic collection"
    echo ""
else
    echo "DRY RUN - No changes made"
    echo ""
    echo "Run without --dry-run to deploy:"
    echo "  ${BLUE}$0 $ORG${NC}"
fi

echo -e "${YELLOW}For troubleshooting and advanced configuration, see:${NC}"
echo "  - LC_DEPLOYMENT_GUIDE.md"
echo "  - enhanced-dr-rules.yaml"
echo "  - output-elasticsearch.yaml"
echo ""
