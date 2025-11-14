#!/bin/bash
# Deploy F0RT1KA Results Collector D&R rules to LimaCharlie
#
# Usage:
#   ./deploy-limacharlie-rules.sh <organization>
#
# Example:
#   ./deploy-limacharlie-rules.sh sb

set -e

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <organization>"
    echo "Example: $0 sb"
    exit 1
fi

ORG=$1

echo "========================================"
echo "F0RT1KA Collector - LimaCharlie Deployment"
echo "========================================"
echo ""
echo "Organization: $ORG"
echo ""

# Check if limacharlie CLI is installed
if ! command -v limacharlie &> /dev/null; then
    echo "ERROR: limacharlie CLI not found"
    echo "Install with: pip install limacharlie"
    exit 1
fi

# Check if rules file exists
RULES_FILE="$(dirname "$0")/limacharlie-dr-rules.yaml"
if [ ! -f "$RULES_FILE" ]; then
    echo "ERROR: Rules file not found: $RULES_FILE"
    exit 1
fi

echo "[1/3] Checking LimaCharlie authentication..."
if ! limacharlie org use "$ORG" 2>/dev/null; then
    echo "ERROR: Failed to select organization '$ORG'"
    echo "Make sure you're authenticated: limacharlie login"
    exit 1
fi
echo "✓ Authenticated to organization: $ORG"

echo ""
echo "[2/3] Validating D&R rules..."
# Basic YAML validation
if ! python3 -c "import yaml; yaml.safe_load(open('$RULES_FILE'))" 2>/dev/null; then
    echo "ERROR: Invalid YAML in rules file"
    exit 1
fi
echo "✓ Rules file validated"

echo ""
echo "[3/3] Deploying D&R rules..."

# Parse YAML and deploy each rule
# Note: This is a simplified approach. You may need to adjust based on your LC CLI version

# Deploy using limacharlie dr add
limacharlie dr add -f "$RULES_FILE" || {
    echo "ERROR: Failed to deploy rules"
    echo "You may need to deploy rules manually through the LimaCharlie web interface"
    exit 1
}

echo "✓ D&R rules deployed successfully"

echo ""
echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo ""
echo "Deployed rules:"
echo "  1. f0rtika-test-result-created    - Auto-trigger collection on new results"
echo "  2. f0rtika-collector-monitor      - Monitor collector execution"
echo "  3. f0rtika-collector-failure-alert - Alert on collector failures"
echo "  4. f0rtika-periodic-collection    - Optional periodic trigger (disabled by default)"
echo ""
echo "Next steps:"
echo "  1. Verify rules in LimaCharlie web interface"
echo "  2. Deploy f0_collector.exe to target endpoints"
echo "  3. Run a test to verify automatic collection"
echo ""
echo "To enable periodic collection via LimaCharlie (instead of Windows Task):"
echo "  limacharlie dr enable f0rtika-periodic-collection"
echo ""
