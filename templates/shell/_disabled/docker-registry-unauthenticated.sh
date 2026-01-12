#!/bin/bash
# @id: docker-registry-unauthenticated
# @name: Docker Registry Unauthenticated Access Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects Docker Registry instances accessible without authentication
# @tags: docker, registry, container, unauthenticated, devops
# @cwe: CWE-306
# @confidence: 95

set -euo pipefail

# Template metadata
TEMPLATE_ID="docker-registry-unauthenticated"
TEMPLATE_NAME="Docker Registry Unauthenticated Access Detection"
SEVERITY="high"
CONFIDENCE=95

# Get target from environment or args
TARGET="${CERT_X_GEN_TARGET_HOST:-${1:-}}"
PORT="${CERT_X_GEN_TARGET_PORT:-${2:-5000}}"
ENGINE_MODE="${CERT_X_GEN_MODE:-}"

# Escape string for JSON
escape_json() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Create finding JSON with all required fields
create_finding() {
    local title="$1"
    local description="$2"
    local evidence="$3"
    local severity="$4"
    local confidence="$5"
    local matched_at="${TARGET}:${PORT}"
    
    cat <<EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${confidence},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","evidence":${evidence},"matched_at":"${matched_at}","cwe":"CWE-306","remediation":"Enable authentication with htpasswd or token-based auth"}
EOF
}

# Output wrapper with findings and metadata
output_json() {
    local findings_array="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF
{"findings":${findings_array},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","timestamp":"${timestamp}","target":"${TARGET}","port":${PORT}}}
EOF
}

# Test Docker Registry
test_docker_registry() {
    local host="$1"
    local port="$2"
    local base_url="http://${host}:${port}"
    local findings=()
    
    # Test 1: Version endpoint /v2/
    local response
    response=$(curl -s -w "\n%{http_code}" -m 10 "${base_url}/v2/" 2>/dev/null) || true
    
    local status_code="${response##*$'\n'}"
    local body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]]; then
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/v2/","status":"accessible"}'
        findings+=("$(create_finding \
            "Docker Registry v2 Accessible Without Auth" \
            "Docker Registry API at ${host}:${port} is accessible without authentication" \
            "$evidence" \
            "critical" \
            "95")")
    fi
    
    # Test 2: Catalog enumeration
    response=$(curl -s -w "\n%{http_code}" -m 10 "${base_url}/v2/_catalog" 2>/dev/null) || true
    status_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -q "repositories"; then
        # Count repositories
        local repo_count
        repo_count=$(echo "$body" | grep -o '"[^"]*"' | grep -v "repositories" | wc -l | tr -d ' ')
        
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/_catalog","repository_count":'"${repo_count}"'}'
        findings+=("$(create_finding \
            "Docker Registry Catalog Enumeration" \
            "Successfully enumerated ${repo_count} repositories without authentication" \
            "$evidence" \
            "high" \
            "95")")
        
        # Get first repository name for further testing
        local first_repo
        first_repo=$(echo "$body" | grep -o '"[^"]*"' | grep -v "repositories" | head -1 | tr -d '"')
        
        if [[ -n "$first_repo" ]]; then
            # Test 3: Tags enumeration
            response=$(curl -s -w "\n%{http_code}" -m 10 "${base_url}/v2/${first_repo}/tags/list" 2>/dev/null) || true
            status_code="${response##*$'\n'}"
            body="${response%$'\n'*}"
            
            if [[ "$status_code" == "200" ]] && echo "$body" | grep -q "tags"; then
                local evidence='{"host":"'"${host}"'","port":'"${port}"',"repository":"'"${first_repo}"'","tags_accessible":true}'
                findings+=("$(create_finding \
                    "Docker Image Tags Enumeration" \
                    "Successfully enumerated tags for repository '${first_repo}'" \
                    "$evidence" \
                    "high" \
                    "90")")
                
                # Get first tag for manifest test
                local first_tag
                first_tag=$(echo "$body" | grep -o '"tags":\[[^]]*\]' | grep -o '"[^"]*"' | grep -v "tags" | head -1 | tr -d '"')
                
                if [[ -n "$first_tag" ]]; then
                    # Test 4: Manifest access
                    response=$(curl -s -w "\n%{http_code}" -m 10 \
                        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
                        "${base_url}/v2/${first_repo}/manifests/${first_tag}" 2>/dev/null) || true
                    status_code="${response##*$'\n'}"
                    body="${response%$'\n'*}"
                    
                    if [[ "$status_code" == "200" ]] && echo "$body" | grep -q "schemaVersion"; then
                        local evidence='{"host":"'"${host}"'","port":'"${port}"',"image":"'"${first_repo}:${first_tag}"'","manifest_accessible":true}'
                        findings+=("$(create_finding \
                            "Docker Image Manifest Accessible" \
                            "Can access manifest for ${first_repo}:${first_tag} - image can be pulled" \
                            "$evidence" \
                            "critical" \
                            "95")")
                    fi
                fi
            fi
        fi
    fi
    
    # Build findings array
    local json="["
    for i in "${!findings[@]}"; do
        [[ $i -gt 0 ]] && json+=","
        json+="${findings[$i]}"
    done
    json+="]"
    echo "$json"
}

# Main
main() {
    if [[ -z "$TARGET" ]]; then
        echo "Error: No target specified" >&2
        echo "Usage: $0 <target> [port]" >&2
        echo "Or set CERT_X_GEN_TARGET_HOST environment variable" >&2
        output_json "[]"
        exit 1
    fi
    
    if ! command -v curl &>/dev/null; then
        echo "Error: curl is required" >&2
        output_json "[]"
        exit 1
    fi
    
    local findings_array
    findings_array=$(test_docker_registry "$TARGET" "$PORT")
    
    # Output with wrapper
    local output
    output=$(output_json "$findings_array")
    
    if [[ "$ENGINE_MODE" == "engine" ]]; then
        echo "[CERT-X-GEN-JSON]${output}[/CERT-X-GEN-JSON]"
    else
        echo "$output"
    fi
}

main
