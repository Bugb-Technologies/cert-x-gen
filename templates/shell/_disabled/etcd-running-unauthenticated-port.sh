#!/bin/bash
# @id: etcd-running-unauthenticated-port
# @name: Unauthenticated etcd Service Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects unauthenticated etcd services exposing sensitive cluster data
# @tags: etcd, kubernetes, unauthenticated, key-value-store
# @cwe: CWE-306
# @confidence: 95

set -euo pipefail

# Template metadata
TEMPLATE_ID="etcd-running-unauthenticated-port"
TEMPLATE_NAME="Unauthenticated etcd Service Detection"
SEVERITY="critical"
CONFIDENCE=95

# Get target from environment or args
TARGET="${CERT_X_GEN_TARGET_HOST:-${1:-}}"
PORT="${CERT_X_GEN_TARGET_PORT:-${2:-2379}}"
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
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${confidence},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","evidence":${evidence},"matched_at":"${matched_at}","cwe":"CWE-306","remediation":"Enable etcd authentication with client certificates and TLS"}
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

# Test etcd using curl (HTTP API)
test_etcd_curl() {
    local host="$1"
    local port="$2"
    local base_url="http://${host}:${port}"
    local findings=()
    
    # Test 1: Health endpoint
    local response
    response=$(curl -s -w "\n%{http_code}" -m 5 "${base_url}/health" 2>/dev/null) || true
    
    local status_code="${response##*$'\n'}"
    local body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -qi '"health"'; then
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/health","healthy":true}'
        findings+=("$(create_finding \
            "etcd Health Endpoint Accessible" \
            "etcd health endpoint accessible without authentication on ${host}:${port}" \
            "$evidence" \
            "medium" \
            "90")")
    fi
    
    # Test 2: Version endpoint
    response=$(curl -s -w "\n%{http_code}" -m 5 "${base_url}/version" 2>/dev/null) || true
    status_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -qi "etcdserver\|etcdcluster"; then
        local version
        version=$(echo "$body" | grep -o '"etcdserver":"[^"]*"' | cut -d'"' -f4)
        
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/version","etcd_version":"'"${version}"'"}'
        findings+=("$(create_finding \
            "etcd Version Disclosure" \
            "etcd version ${version} detected on ${host}:${port} without authentication" \
            "$evidence" \
            "medium" \
            "95")")
    fi
    
    # Test 3: Keys/v2 API (etcd v2)
    response=$(curl -s -w "\n%{http_code}" -m 5 "${base_url}/v2/keys/" 2>/dev/null) || true
    status_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -qi '"node"\|"key"'; then
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/v2/keys/","api_version":"v2","data_accessible":true}'
        findings+=("$(create_finding \
            "etcd v2 API Unauthenticated Access" \
            "etcd v2 keys API accessible without authentication - data can be read/written" \
            "$evidence" \
            "critical" \
            "95")")
    fi
    
    # Test 4: v3 API member list (via gRPC gateway)
    response=$(curl -s -w "\n%{http_code}" -m 5 \
        -X POST "${base_url}/v3/cluster/member/list" \
        -d '{}' 2>/dev/null) || true
    status_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -qi '"members"'; then
        local member_count
        member_count=$(echo "$body" | grep -o '"name"' | wc -l | tr -d ' ')
        
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/v3/cluster/member/list","api_version":"v3","member_count":'"${member_count}"'}'
        findings+=("$(create_finding \
            "etcd v3 API Unauthenticated Access" \
            "etcd v3 cluster API accessible - found ${member_count} cluster members" \
            "$evidence" \
            "critical" \
            "95")")
    fi
    
    # Test 5: Try to read keys via v3 API
    response=$(curl -s -w "\n%{http_code}" -m 5 \
        -X POST "${base_url}/v3/kv/range" \
        -d '{"key":"AA=="}' 2>/dev/null) || true
    status_code="${response##*$'\n'}"
    body="${response%$'\n'*}"
    
    if [[ "$status_code" == "200" ]] && echo "$body" | grep -qi '"kvs"\|"count"'; then
        local evidence='{"host":"'"${host}"'","port":'"${port}"',"endpoint":"/v3/kv/range","data_accessible":true}'
        findings+=("$(create_finding \
            "etcd Key-Value Data Accessible" \
            "Can read key-value data from etcd without authentication on ${host}:${port}" \
            "$evidence" \
            "critical" \
            "95")")
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
    findings_array=$(test_etcd_curl "$TARGET" "$PORT")
    
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
