#!/bin/bash
#
# CERT-X-GEN Shell Template Skeleton
#
# @id: shell-template-skeleton
# @name: Shell Template Skeleton
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Skeleton template for writing security scanning templates in Bash/Shell
# @tags: skeleton, example, template, shell, bash
# @cwe: CWE-1008
# @confidence: 90
# @references: https://cwe.mitre.org/data/definitions/1008.html
#
# Execution:
#   ./template.sh --target example.com --port 80 --json
#
# When run by CERT-X-GEN engine, environment variables are set:
#   CERT_X_GEN_TARGET_HOST - Target host/IP
#   CERT_X_GEN_TARGET_PORT - Target port
#   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
################################################################################

set -euo pipefail

# ========================================
# TEMPLATE CONFIGURATION
# ========================================
TEMPLATE_ID="shell-template-skeleton"
TEMPLATE_NAME="Shell Template Skeleton"
TEMPLATE_AUTHOR="CERT-X-GEN Security Team"
SEVERITY="info"
CONFIDENCE=90
CWE="CWE-1008"

# ========================================
# LOGGING (stderr only - never stdout)
# ========================================
log_info() {
    echo "[INFO] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
}

# ========================================
# JSON HELPERS
# ========================================

# Escape string for JSON
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

# Create a finding object
create_finding() {
    local title="$1"
    local description="$2"
    local evidence="$3"
    local host="$4"
    local port="$5"
    local severity="${6:-$SEVERITY}"
    local remediation="${7:-Apply security best practices}"
    
    cat << EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${CONFIDENCE},"title":"$(json_escape "$title")","description":"$(json_escape "$description")","host":"${host}","port":${port},"matched_at":"${host}:${port}","evidence":{"response":"$(json_escape "$evidence")"},"cwe":"${CWE}","remediation":"$(json_escape "$remediation")"}
EOF
}

# Output findings in required format
output_json() {
    local findings="$1"
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    cat << EOF
{"findings":${findings},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","author":"${TEMPLATE_AUTHOR}","severity":"${SEVERITY}","scan_time":"${timestamp}"}}
EOF
}

# ========================================
# SCANNING LOGIC
# ========================================

# Check if port is open
check_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-3}"
    
    if command -v nc &>/dev/null; then
        nc -z -w "$timeout" "$host" "$port" 2>/dev/null
        return $?
    elif command -v timeout &>/dev/null; then
        timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
        return $?
    else
        bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
        return $?
    fi
}

# Send data and receive response
send_receive() {
    local host="$1"
    local port="$2"
    local data="$3"
    local timeout="${4:-5}"
    
    if command -v nc &>/dev/null; then
        echo -e "$data" | nc -w "$timeout" "$host" "$port" 2>/dev/null
    else
        exec 3<>/dev/tcp/"$host"/"$port"
        echo -e "$data" >&3
        timeout "$timeout" cat <&3 2>/dev/null
        exec 3>&-
    fi
}

# Main vulnerability check - CUSTOMIZE THIS FUNCTION
check_vulnerability() {
    local host="$1"
    local port="$2"
    
    log_info "Checking ${host}:${port}"
    
    # Check if port is open
    if ! check_port_open "$host" "$port"; then
        log_info "Port ${port} is not open on ${host}"
        return 1
    fi
    
    # Send probe and get response
    local response
    response=$(send_receive "$host" "$port" "PROBE\r\n" 5) || true
    
    if [ -z "$response" ]; then
        log_info "No response received"
        return 1
    fi
    
    # Check for vulnerability indicators - CUSTOMIZE THIS
    if echo "$response" | grep -qi "vulnerable_indicator"; then
        echo "$response"
        return 0
    fi
    
    return 1
}

# ========================================
# MAIN FUNCTION
# ========================================
main() {
    local target=""
    local port="80"
    local json_output=false
    
    # Get from environment first (engine mode)
    target="${CERT_X_GEN_TARGET_HOST:-}"
    port="${CERT_X_GEN_TARGET_PORT:-80}"
    
    # Check if running in engine mode
    if [ "${CERT_X_GEN_MODE:-}" = "engine" ]; then
        json_output=true
    fi
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            --json)
                json_output=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 --target HOST [--port PORT] [--json]" >&2
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # Validate target
    if [ -z "$target" ]; then
        log_error "No target specified"
        if $json_output; then
            output_json "[]"
        fi
        exit 1
    fi
    
    # Run the vulnerability check
    local findings="[]"
    local response
    
    if response=$(check_vulnerability "$target" "$port"); then
        # Vulnerability found - create finding
        local finding
        finding=$(create_finding \
            "Vulnerability Detected" \
            "Found vulnerability on ${target}:${port}" \
            "$response" \
            "$target" \
            "$port" \
            "$SEVERITY" \
            "Apply appropriate security controls")
        findings="[${finding}]"
    fi
    
    # Output results
    if $json_output || [ "${CERT_X_GEN_MODE:-}" = "engine" ]; then
        output_json "$findings"
    else
        # Human-readable output to stderr
        if [ "$findings" = "[]" ]; then
            log_info "No vulnerabilities found on ${target}:${port}"
        else
            log_info "Vulnerability found on ${target}:${port}"
            echo "$findings" | jq '.' 2>/dev/null || echo "$findings"
        fi
    fi
}

# Run main
main "$@"
