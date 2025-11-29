#!/bin/bash
# F0RT1KA Elasticsearch Registry Helper
# Provides functions to resolve ES profile identifiers to endpoints and config
#
# Usage:
#   source utils/resolve_es.sh
#   ES_ENDPOINT=$(resolve_es_to_endpoint "prod")
#   ES_INDEX=$(resolve_es_to_index "prod")
#   ES_APIKEY=$(resolve_es_to_apikey "prod")

# Registry file location (relative to repo root)
ES_REGISTRY_FILE="signing-certs/elasticsearch-registry.json"

# Check if jq is available for JSON parsing
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not found. Using fallback JSON parsing." >&2
    ES_JQ_AVAILABLE=false
else
    ES_JQ_AVAILABLE=true
fi

# Load registry and cache in memory
_ES_REGISTRY_CACHE=""
_ES_REGISTRY_LOADED=false

load_es_registry() {
    if [ "$_ES_REGISTRY_LOADED" = true ]; then
        return 0
    fi

    if [ ! -f "$ES_REGISTRY_FILE" ]; then
        echo "Error: Elasticsearch registry not found: $ES_REGISTRY_FILE" >&2
        return 1
    fi

    _ES_REGISTRY_CACHE=$(cat "$ES_REGISTRY_FILE")
    _ES_REGISTRY_LOADED=true
    return 0
}

# Check if string is a valid UUID format
es_is_valid_uuid() {
    local input="$1"
    if [[ "$input" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Get profile by UUID
get_es_profile_by_uuid() {
    local uuid="$1"

    if ! load_es_registry; then
        return 1
    fi

    if [ "$ES_JQ_AVAILABLE" = true ]; then
        echo "$_ES_REGISTRY_CACHE" | jq -r ".profiles[] | select(.uuid == \"$uuid\")"
    else
        # Fallback: grep-based parsing
        echo "$_ES_REGISTRY_CACHE" | grep -A 10 "\"uuid\": \"$uuid\"" | head -11
    fi
}

# Get profile by short name
get_es_profile_by_shortname() {
    local shortname="$1"

    if ! load_es_registry; then
        return 1
    fi

    if [ "$ES_JQ_AVAILABLE" = true ]; then
        echo "$_ES_REGISTRY_CACHE" | jq -r ".profiles[] | select(.shortName == \"$shortname\")"
    else
        # Fallback: grep-based parsing
        echo "$_ES_REGISTRY_CACHE" | grep -A 10 "\"shortName\": \"$shortname\"" | head -11
    fi
}

# Get default ES profile from registry
get_default_es_profile() {
    if ! load_es_registry; then
        return 1
    fi

    if [ "$ES_JQ_AVAILABLE" = true ]; then
        # Check autoDetectSingleProfile setting
        local auto_detect=$(echo "$_ES_REGISTRY_CACHE" | jq -r '.autoDetectSingleProfile // false')
        local profile_count=$(echo "$_ES_REGISTRY_CACHE" | jq -r '.profiles | length')

        if [ "$auto_detect" = "true" ] && [ "$profile_count" = "1" ]; then
            # Return the only profile's short name
            echo "$_ES_REGISTRY_CACHE" | jq -r '.profiles[0].shortName'
            return 0
        fi

        # Return defaultProfile if set
        local default_profile=$(echo "$_ES_REGISTRY_CACHE" | jq -r '.defaultProfile // empty')
        if [ -n "$default_profile" ]; then
            echo "$default_profile"
            return 0
        fi

        # Return profile marked as default
        local default_marked=$(echo "$_ES_REGISTRY_CACHE" | jq -r '.profiles[] | select(.default == true) | .shortName')
        if [ -n "$default_marked" ]; then
            echo "$default_marked"
            return 0
        fi
    else
        # Fallback: grep for defaultProfile
        local default_profile=$(echo "$_ES_REGISTRY_CACHE" | grep '"defaultProfile"' | sed 's/.*: "\(.*\)".*/\1/')
        if [ -n "$default_profile" ]; then
            echo "$default_profile"
            return 0
        fi
    fi

    return 1
}

# Get profile JSON by identifier (UUID or short name)
get_es_profile() {
    local identifier="$1"

    # If empty, get default
    if [ -z "$identifier" ]; then
        identifier=$(get_default_es_profile)
        if [ -z "$identifier" ]; then
            echo "Error: No ES profile specified and no default configured" >&2
            return 1
        fi
    fi

    local profile_json=""

    # Check if input is UUID format
    if es_is_valid_uuid "$identifier"; then
        profile_json=$(get_es_profile_by_uuid "$identifier")
    else
        profile_json=$(get_es_profile_by_shortname "$identifier")
    fi

    if [ -z "$profile_json" ]; then
        echo "Error: Elasticsearch profile not found in registry: $identifier" >&2
        return 1
    fi

    echo "$profile_json"
    return 0
}

# Extract field from profile JSON
extract_es_field() {
    local profile_json="$1"
    local field="$2"

    if [ "$ES_JQ_AVAILABLE" = true ]; then
        echo "$profile_json" | jq -r ".$field // empty"
    else
        # Fallback: grep for field
        echo "$profile_json" | grep "\"$field\"" | sed 's/.*: "\(.*\)".*/\1/' | tr -d ','
    fi
}

# Main function: Resolve ES profile identifier to endpoint URL
# Accepts: UUID, short name, or empty (uses default)
# Returns: Endpoint URL (e.g., https://es.example.com:9200)
resolve_es_to_endpoint() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local endpoint=$(extract_es_field "$profile_json" "endpoint")
    if [ -z "$endpoint" ]; then
        echo "Error: Could not extract endpoint from ES profile" >&2
        return 1
    fi

    echo "$endpoint"
    return 0
}

# Resolve ES profile identifier to index name
resolve_es_to_index() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local index=$(extract_es_field "$profile_json" "index")
    if [ -z "$index" ]; then
        echo "Error: Could not extract index from ES profile" >&2
        return 1
    fi

    echo "$index"
    return 0
}

# Resolve ES profile identifier to API key (reads from env var)
# Returns the actual API key value, NOT the env var name
resolve_es_to_apikey() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local apikey_env_var=$(extract_es_field "$profile_json" "apiKeyEnvVar")
    if [ -z "$apikey_env_var" ]; then
        echo "Error: Could not extract apiKeyEnvVar from ES profile" >&2
        return 1
    fi

    # Read the actual API key from the environment variable
    local apikey_value="${!apikey_env_var}"
    if [ -z "$apikey_value" ]; then
        echo "Error: Environment variable $apikey_env_var is not set or empty" >&2
        echo "Set it with: export $apikey_env_var='your-api-key'" >&2
        return 1
    fi

    echo "$apikey_value"
    return 0
}

# Get the env var name for the API key (useful for error messages)
resolve_es_to_apikey_envvar() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local apikey_env_var=$(extract_es_field "$profile_json" "apiKeyEnvVar")
    echo "$apikey_env_var"
    return 0
}

# Resolve ES profile to full name (for display purposes)
resolve_es_to_fullname() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local fullname=$(extract_es_field "$profile_json" "fullName")
    echo "$fullname"
    return 0
}

# List all ES profiles in registry
list_es_profiles() {
    if ! load_es_registry; then
        return 1
    fi

    echo "Available Elasticsearch profiles:"

    if [ "$ES_JQ_AVAILABLE" = true ]; then
        echo "$_ES_REGISTRY_CACHE" | jq -r '.profiles[] | "  \(.shortName) (\(.fullName)) - \(.endpoint)"'
    else
        echo "$_ES_REGISTRY_CACHE" | grep -E '"(shortName|fullName|endpoint)"' | \
        awk 'BEGIN {RS=""; FS="\n"} {print}' | \
        sed 's/.*"shortName": "\(.*\)".*/Short: \1/' | \
        sed 's/.*"fullName": "\(.*\)".*/Full: \1/' | \
        sed 's/.*"endpoint": "\(.*\)".*/Endpoint: \1/' | \
        paste -d' ' - - -
    fi
}

# Validate ES profile identifier format
validate_es_profile_format() {
    local es_identifier="$1"

    # Empty is allowed (will use default)
    if [ -z "$es_identifier" ]; then
        return 0
    fi

    # Check if UUID format
    if es_is_valid_uuid "$es_identifier"; then
        return 0
    fi

    # Check if valid short name (alphanumeric, dash, underscore)
    if [[ "$es_identifier" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 0
    fi

    echo "Error: Invalid ES profile identifier format: $es_identifier" >&2
    echo "Expected: UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) or short name (alphanumeric)" >&2
    return 1
}

# Check if ES profile is enabled
is_es_profile_enabled() {
    local es_identifier="$1"

    local profile_json=$(get_es_profile "$es_identifier")
    if [ $? -ne 0 ]; then
        return 1
    fi

    local enabled=$(extract_es_field "$profile_json" "enabled")
    if [ "$enabled" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Example usage (when script is run directly)
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "F0RT1KA Elasticsearch Registry Helper"
    echo "========================================"
    echo ""

    list_es_profiles

    echo ""
    echo "Example usage:"
    echo "  source utils/resolve_es.sh"
    echo "  ES_ENDPOINT=\$(resolve_es_to_endpoint \"prod\")"
    echo "  ES_INDEX=\$(resolve_es_to_index \"prod\")"
    echo "  ES_APIKEY=\$(resolve_es_to_apikey \"prod\")"
    echo ""
    echo "Before building with ES export, set the API key env var:"
    echo "  export F0_ES_PROD_APIKEY='your-api-key-here'"
fi
