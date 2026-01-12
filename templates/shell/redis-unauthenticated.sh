#!/bin/bash
# @id: redis-unauthenticated-shell
# @name: Redis Unauthenticated Access Detection (Shell)
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Redis instances exposed without authentication using shell commands
# @tags: redis, unauthenticated, database, nosql, cwe-306
# @cwe: CWE-306
# @cvss: 9.8
# @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
# @confidence: 95
# @version: 1.0.0

set -e

# Template metadata
TEMPLATE_ID="redis-unauthenticated-shell"
TEMPLATE_NAME="Redis Unauthenticated Access Detection (Shell)"
SEVERITY="critical"
CONFIDENCE=95

# Support both CLI args and environment variables (for engine mode)
if [ "$CERT_X_GEN_MODE" = "engine" ]; then
    # Engine mode - read from environment variables
    HOST="$CERT_X_GEN_TARGET_HOST"
    PORT="${CERT_X_GEN_TARGET_PORT:-6379}"
    if [ -z "$HOST" ]; then
        echo '{"error": "CERT_X_GEN_TARGET_HOST not set"}'
        exit 1
    fi
else
    # CLI mode - read from command-line arguments
    if [ $# -lt 1 ]; then
        echo '{"error": "Usage: redis-unauthenticated.sh <host> [port]"}'
        exit 1
    fi
    HOST="$1"
    PORT="${2:-6379}"
fi

TIMEOUT=10

# Function to test Redis
test_redis() {
    local host="$1"
    local port="$2"
    local response=""
    
    # Try to connect and send commands using nc (netcat)
    if command -v nc >/dev/null 2>&1; then
        # Use netcat
        response=$(timeout "$TIMEOUT" sh -c "
            printf 'INFO\r\nPING\r\n' | nc -w 2 $host $port 2>/dev/null
        " 2>/dev/null || echo "")
    elif command -v telnet >/dev/null 2>&1; then
        # Fallback to telnet
        response=$(timeout "$TIMEOUT" sh -c "
            (echo 'INFO'; echo 'PING'; sleep 1) | telnet $host $port 2>/dev/null
        " 2>/dev/null || echo "")
    else
        # Try /dev/tcp as last resort
        response=$(timeout "$TIMEOUT" bash -c "
            exec 3<>/dev/tcp/$host/$port 2>/dev/null || exit 1
            echo -e 'INFO\r' >&3
            echo -e 'PING\r' >&3
            timeout 2 cat <&3
        " 2>/dev/null || echo "")
    fi
    
    if [ -z "$response" ]; then
        return 1
    fi
    
    # Check for Redis indicators
    local matched_patterns=()
    
    if echo "$response" | grep -q "redis_version"; then
        matched_patterns+=("redis_version")
    fi
    if echo "$response" | grep -q "redis_mode"; then
        matched_patterns+=("redis_mode")
    fi
    if echo "$response" | grep -q "used_memory"; then
        matched_patterns+=("used_memory")
    fi
    if echo "$response" | grep -q "connected_clients"; then
        matched_patterns+=("connected_clients")
    fi
    if echo "$response" | grep -q "role:master"; then
        matched_patterns+=("role:master")
    fi
    if echo "$response" | grep -q "+PONG"; then
        matched_patterns+=("'+PONG'")
    fi
    
    if [ ${#matched_patterns[@]} -gt 0 ]; then
        # Use jq to properly escape the response
        local escaped_response=$(echo "$response" | head -c 1000 | jq -Rs .)
        local patterns_json=$(printf '%s\n' "${matched_patterns[@]}" | jq -R . | jq -s .)
        
        # Build JSON using jq for proper escaping
        jq -n \
          --arg target "$host:$port" \
          --arg template_id "$TEMPLATE_ID" \
          --arg severity "$SEVERITY" \
          --argjson confidence "$CONFIDENCE" \
          --arg title "$TEMPLATE_NAME" \
          --arg description "Detects Redis instances exposed without authentication using Shell" \
          --arg request "INFO\\r\\nPING\\r\\n" \
          --argjson response "$escaped_response" \
          --argjson patterns "$patterns_json" \
          --argjson port "$port" \
          --argjson response_length "${#response}" \
          --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")" \
          '{
            "findings": [{
              "target": $target,
              "template_id": $template_id,
              "severity": $severity,
              "confidence": $confidence,
              "title": $title,
              "description": $description,
              "evidence": {
                "request": $request,
                "response": $response,
                "matched_patterns": $patterns,
                "data": {
                  "protocol": "tcp",
                  "port": $port,
                  "response_length": $response_length
                }
              },
              "cwe_ids": ["CWE-306"],
              "tags": ["redis", "unauthenticated", "database", "nosql", "shell"],
              "timestamp": $timestamp
            }],
            "metadata": {
              "id": $template_id,
              "name": $title,
              "severity": $severity,
              "language": "shell",
              "confidence": $confidence
            }
          }'
        return 0
    fi
    
    return 1
}

# Main execution
if test_redis "$HOST" "$PORT"; then
    exit 0
else
    echo '{"findings": [], "metadata": {"id": "'"$TEMPLATE_ID"'", "name": "'"$TEMPLATE_NAME"'", "language": "shell"}}'
    exit 0
fi
