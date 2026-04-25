#!/bin/bash
# F0RT1KA Organization Registry Helper
# Provides functions to resolve organization identifiers to certificate files
#
# Usage:
#   source utils/resolve_org.sh
#   CERT_FILE=$(resolve_org_to_cert "sb")
#   CERT_FILE=$(resolve_org_to_cert "09b59276-9efb-4d3d-bbdd-4b4663ef0c42")

# Registry file location — anchored to THIS script's directory so it works
# regardless of the caller's cwd. (Bug surfaced 2026-04-25: build_all.sh cd's
# into the test directory before sourcing this file, which caused the legacy
# cwd-relative path to silently fail. Stage binaries then shipped unsigned,
# triggering Defender static-AV signatures on unsigned-PE heuristics.)
#
# Resolution order:
#   1. $F0_REGISTRY_FILE env var (explicit override)
#   2. <script-dir>/../signing-certs/organization-registry.json (canonical layout)
#   3. signing-certs/organization-registry.json (cwd-relative legacy fallback)
_RESOLVE_ORG_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${F0_REGISTRY_FILE:-}" ]; then
    REGISTRY_FILE="${F0_REGISTRY_FILE}"
elif [ -f "${_RESOLVE_ORG_SCRIPT_DIR}/../signing-certs/organization-registry.json" ]; then
    REGISTRY_FILE="${_RESOLVE_ORG_SCRIPT_DIR}/../signing-certs/organization-registry.json"
else
    REGISTRY_FILE="signing-certs/organization-registry.json"
fi

# Check if jq is available for JSON parsing
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not found. Using fallback JSON parsing." >&2
    JQ_AVAILABLE=false
else
    JQ_AVAILABLE=true
fi

# Load registry and cache in memory
_REGISTRY_CACHE=""
_REGISTRY_LOADED=false

load_registry() {
    if [ "$_REGISTRY_LOADED" = true ]; then
        return 0
    fi

    if [ ! -f "$REGISTRY_FILE" ]; then
        echo "Error: Organization registry not found: $REGISTRY_FILE" >&2
        return 1
    fi

    _REGISTRY_CACHE=$(cat "$REGISTRY_FILE")
    _REGISTRY_LOADED=true
    return 0
}

# Check if string is a valid UUID format
is_valid_uuid() {
    local input="$1"
    if [[ "$input" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Get organization by UUID
get_org_by_uuid() {
    local uuid="$1"

    if ! load_registry; then
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$_REGISTRY_CACHE" | jq -r ".organizations[] | select(.uuid == \"$uuid\")"
    else
        # Fallback: grep-based parsing
        echo "$_REGISTRY_CACHE" | grep -A 8 "\"uuid\": \"$uuid\"" | head -9
    fi
}

# Get organization by short name
get_org_by_shortname() {
    local shortname="$1"

    if ! load_registry; then
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$_REGISTRY_CACHE" | jq -r ".organizations[] | select(.shortName == \"$shortname\")"
    else
        # Fallback: grep-based parsing
        echo "$_REGISTRY_CACHE" | grep -A 8 "\"shortName\": \"$shortname\"" | head -9
    fi
}

# Get default organization from registry
get_default_org() {
    if ! load_registry; then
        return 1
    fi

    # Check autoDetectSingleOrg setting
    if [ "$JQ_AVAILABLE" = true ]; then
        local auto_detect=$(echo "$_REGISTRY_CACHE" | jq -r '.autoDetectSingleOrg // false')
        local org_count=$(echo "$_REGISTRY_CACHE" | jq -r '.organizations | length')

        if [ "$auto_detect" = "true" ] && [ "$org_count" = "1" ]; then
            # Return the only organization's short name
            echo "$_REGISTRY_CACHE" | jq -r '.organizations[0].shortName'
            return 0
        fi

        # Return defaultOrganization if set
        local default_org=$(echo "$_REGISTRY_CACHE" | jq -r '.defaultOrganization // empty')
        if [ -n "$default_org" ]; then
            echo "$default_org"
            return 0
        fi

        # Return organization marked as default
        local default_marked=$(echo "$_REGISTRY_CACHE" | jq -r '.organizations[] | select(.default == true) | .shortName')
        if [ -n "$default_marked" ]; then
            echo "$default_marked"
            return 0
        fi
    else
        # Fallback: grep for defaultOrganization
        local default_org=$(echo "$_REGISTRY_CACHE" | grep '"defaultOrganization"' | sed 's/.*: "\(.*\)".*/\1/')
        if [ -n "$default_org" ]; then
            echo "$default_org"
            return 0
        fi
    fi

    return 1
}

# Extract certificate file from organization JSON object
extract_cert_file() {
    local org_json="$1"

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$org_json" | jq -r '.certificateFile // empty'
    else
        # Fallback: grep for certificateFile
        echo "$org_json" | grep '"certificateFile"' | sed 's/.*: "\(.*\)".*/\1/' | tr -d ','
    fi
}

# Main function: Resolve organization identifier to certificate file path
# Accepts: UUID, short name, or empty (uses default)
# Returns: Certificate file name (not full path)
resolve_org_to_cert() {
    local org_identifier="$1"

    # If empty, get default
    if [ -z "$org_identifier" ]; then
        org_identifier=$(get_default_org)
        if [ -z "$org_identifier" ]; then
            echo "Error: No organization specified and no default configured" >&2
            return 1
        fi
    fi

    local org_json=""
    local cert_file=""

    # Check if input is UUID format
    if is_valid_uuid "$org_identifier"; then
        # Lookup by UUID
        org_json=$(get_org_by_uuid "$org_identifier")
        if [ -z "$org_json" ]; then
            echo "Error: Organization UUID not found in registry: $org_identifier" >&2
            return 1
        fi
        cert_file=$(extract_cert_file "$org_json")
    else
        # Lookup by short name
        org_json=$(get_org_by_shortname "$org_identifier")
        if [ -z "$org_json" ]; then
            echo "Error: Organization short name not found in registry: $org_identifier" >&2
            return 1
        fi
        cert_file=$(extract_cert_file "$org_json")
    fi

    if [ -z "$cert_file" ]; then
        echo "Error: Could not extract certificate file from registry" >&2
        return 1
    fi

    echo "$cert_file"
    return 0
}

# Resolve organization to UUID (for test code)
# Accepts: UUID or short name
# Returns: UUID
resolve_org_to_uuid() {
    local org_identifier="$1"

    if [ -z "$org_identifier" ]; then
        org_identifier=$(get_default_org)
    fi

    # If already UUID, return as-is
    if is_valid_uuid "$org_identifier"; then
        echo "$org_identifier"
        return 0
    fi

    # Lookup by short name
    local org_json=$(get_org_by_shortname "$org_identifier")
    if [ -z "$org_json" ]; then
        echo "Error: Organization short name not found in registry: $org_identifier" >&2
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$org_json" | jq -r '.uuid // empty'
    else
        echo "$org_json" | grep '"uuid"' | sed 's/.*: "\(.*\)".*/\1/' | tr -d ','
    fi
}

# Get organization short name from UUID
resolve_uuid_to_shortname() {
    local uuid="$1"

    local org_json=$(get_org_by_uuid "$uuid")
    if [ -z "$org_json" ]; then
        echo "Error: Organization UUID not found in registry: $uuid" >&2
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$org_json" | jq -r '.shortName // empty'
    else
        echo "$org_json" | grep '"shortName"' | sed 's/.*: "\(.*\)".*/\1/' | tr -d ','
    fi
}

# Get organization full name
resolve_org_to_fullname() {
    local org_identifier="$1"

    local org_json=""
    if is_valid_uuid "$org_identifier"; then
        org_json=$(get_org_by_uuid "$org_identifier")
    else
        org_json=$(get_org_by_shortname "$org_identifier")
    fi

    if [ -z "$org_json" ]; then
        return 1
    fi

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$org_json" | jq -r '.fullName // empty'
    else
        echo "$org_json" | grep '"fullName"' | sed 's/.*: "\(.*\)".*/\1/' | tr -d ','
    fi
}

# List all organizations in registry
list_organizations() {
    if ! load_registry; then
        return 1
    fi

    echo "Available organizations:"

    if [ "$JQ_AVAILABLE" = true ]; then
        echo "$_REGISTRY_CACHE" | jq -r '.organizations[] | "  \(.shortName) (\(.fullName)) - UUID: \(.uuid)"'
    else
        echo "$_REGISTRY_CACHE" | grep -E '"(uuid|shortName|fullName)"' | \
        awk 'BEGIN {RS=""; FS="\n"} {print}' | \
        sed 's/.*"shortName": "\(.*\)".*/Short: \1/' | \
        sed 's/.*"fullName": "\(.*\)".*/Full: \1/' | \
        sed 's/.*"uuid": "\(.*\)".*/UUID: \1/' | \
        paste -d' ' - - -
    fi
}

# Validate organization identifier format
validate_org_format() {
    local org_identifier="$1"

    # Empty is allowed (will use default)
    if [ -z "$org_identifier" ]; then
        return 0
    fi

    # Check if UUID format
    if is_valid_uuid "$org_identifier"; then
        return 0
    fi

    # Check if valid short name (alphanumeric, dash, underscore)
    if [[ "$org_identifier" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 0
    fi

    echo "Error: Invalid organization identifier format: $org_identifier" >&2
    echo "Expected: UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) or short name (alphanumeric)" >&2
    return 1
}

# Example usage (when script is run directly)
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "F0RT1KA Organization Registry Helper"
    echo "======================================"
    echo ""

    list_organizations

    echo ""
    echo "Example usage:"
    echo "  source utils/resolve_org.sh"
    echo "  CERT=\$(resolve_org_to_cert \"sb\")"
    echo "  CERT=\$(resolve_org_to_cert \"09b59276-9efb-4d3d-bbdd-4b4663ef0c42\")"
    echo "  UUID=\$(resolve_org_to_uuid \"sb\")"
fi
