#!/bin/bash
# @id: kafka-unauthenticated
# @name: Apache Kafka Unauthenticated Access Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects Apache Kafka brokers accessible without authentication, exposing message streams and topics
# @tags: kafka, apache, messaging, unauthenticated, streaming, cwe-306
# @cwe: CWE-306
# @cvss: 8.6
# @references: https://cwe.mitre.org/data/definitions/306.html, https://kafka.apache.org/documentation/#security
# @confidence: 90
# @version: 1.0.0
################################################################################

set -e

# ========================================
# TEMPLATE METADATA
# ========================================
TEMPLATE_ID="kafka-unauthenticated-access"
TEMPLATE_NAME="Apache Kafka Unauthenticated Access Detection"
SEVERITY="critical"
CONFIDENCE=90
TAGS="kafka,apache,messaging,unauthenticated"
CWE="CWE-306"

# Get target from environment
TARGET_HOST="${CERT_X_GEN_TARGET_HOST:-}"
TARGET_PORT="${CERT_X_GEN_TARGET_PORT:-9092}"

# Initialize findings array
FINDINGS="[]"

# ========================================
# HELPER FUNCTIONS
# ========================================

calculate_cvss_score() {
    local severity=$1
    case "$severity" in
        critical) echo "9.0" ;;
        high) echo "7.5" ;;
        medium) echo "5.0" ;;
        low) echo "3.0" ;;
        info) echo "0.0" ;;
        *) echo "5.0" ;;
    esac
}

add_finding() {
    local title=$1
    local description=$2
    local evidence=$3
    local severity=${4:-$SEVERITY}
    local remediation=${5:-"Enable Kafka authentication and authorization"}
    
    local cvss_score=$(calculate_cvss_score "$severity")
    
    local finding_json=$(cat << EOF
{
    "template_id": "${TEMPLATE_ID}",
    "severity": "${severity}",
    "confidence": ${CONFIDENCE},
    "title": "${title}",
    "description": "${description}",
    "evidence": ${evidence},
    "cwe": "${CWE}",
    "cvss_score": ${cvss_score},
    "remediation": "${remediation}",
    "references": [
        "https://cwe.mitre.org/data/definitions/306.html",
        "https://kafka.apache.org/documentation/#security"
    ]
}
EOF
)
    
    FINDINGS=$(echo "$FINDINGS" | jq ". += [$finding_json]")
}

check_dependencies() {
    local missing=0
    
    if ! command -v kafkacat &> /dev/null && ! command -v kcat &> /dev/null; then
        missing=1
    fi
    
    if ! command -v nc &> /dev/null; then
        missing=1
    fi
    
    return $missing
}

test_broker_connectivity() {
    local host=$1
    local port=$2
    
    if nc -zv -w 3 "$host" "$port" 2>&1 | grep -q "succeeded\|open"; then
        local evidence=$(jq -n --arg host "$host" --arg port "$port" '{
            "host": $host,
            "port": $port,
            "accessible": true
        }')
        add_finding \
            "Kafka Broker Port Open" \
            "Kafka broker at ${host}:${port} is accessible and may be exposed without authentication" \
            "$evidence" \
            "info"
        return 0
    else
        return 1
    fi
}

test_metadata_query() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        return 1
    fi
    
    local metadata=$(timeout 5 $kafkacat_cmd -L -b "${host}:${port}" 2>&1 || true)
    
    if [[ $? -eq 0 ]] && [[ ! -z "$metadata" ]]; then
        local broker_count=$(echo "$metadata" | grep -c "broker" || true)
        local topic_count=$(echo "$metadata" | grep -c "topic" || true)
        
        local evidence=$(jq -n --arg host "$host" --arg port "$port" --argjson broker_count "$broker_count" --argjson topic_count "$topic_count" '{
            "host": $host,
            "port": $port,
            "broker_count": $broker_count,
            "topic_count": $topic_count,
            "metadata_accessible": true
        }')
        
        add_finding \
            "Kafka Metadata Accessible Without Authentication" \
            "Successfully retrieved cluster metadata from ${host}:${port} without authentication" \
            "$evidence" \
            "critical"
        
        return 0
    fi
    
    return 1
}

test_topic_listing() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        return 1
    fi
    
    local topics=$(timeout 5 $kafkacat_cmd -L -b "${host}:${port}" 2>&1 | grep "topic" | grep -v "^$" || true)
    
    if [[ ! -z "$topics" ]]; then
        local topic_list=$(echo "$topics" | head -10 | jq -R -s -c 'split("\n") | map(select(. != ""))')
        local sensitive_topics=$(echo "$topics" | grep -iE "(password|secret|credential|key|token|auth|admin|prod|production)" || true)
        local has_sensitive_topics=false
        
        if [[ ! -z "$sensitive_topics" ]]; then
            has_sensitive_topics=true
        fi
        
        local evidence=$(jq -n --arg host "$host" --arg port "$port" --argjson topics "$topic_list" --argjson has_sensitive "$has_sensitive_topics" '{
            "host": $host,
            "port": $port,
            "topics_found": $topics,
            "has_sensitive_topics": $has_sensitive
        }')
        
        add_finding \
            "Kafka Topic Enumeration Without Authentication" \
            "Successfully enumerated Kafka topics from ${host}:${port} without authentication" \
            "$evidence" \
            "high"
        
        if [[ "$has_sensitive_topics" == "true" ]]; then
            local sensitive_evidence=$(jq -n --arg host "$host" --arg port "$port" '{
                "host": $host,
                "port": $port,
                "sensitive_topics_detected": true
            }')
            
            add_finding \
                "Sensitive Kafka Topics Exposed" \
                "Topics with potentially sensitive names are accessible without authentication" \
                "$sensitive_evidence" \
                "critical"
        fi
        
        return 0
    fi
    
    return 1
}

test_consume_messages() {
    local host=$1
    local port=$2
    local kafkacat_cmd=""
    
    if command -v kcat &> /dev/null; then
        kafkacat_cmd="kcat"
    elif command -v kafkacat &> /dev/null; then
        kafkacat_cmd="kafkacat"
    else
        return 1
    fi
    
    local messages=$(timeout 3 $kafkacat_cmd -C -b "${host}:${port}" -t __consumer_offsets -c 1 2>&1 || true)
    
    if [[ $? -eq 0 ]] || ([[ ! -z "$messages" ]] && ! echo "$messages" | grep -q "error\|Error"); then
        local evidence=$(jq -n --arg host "$host" --arg port "$port" '{
            "host": $host,
            "port": $port,
            "message_consumption_successful": true
        }')
        
        add_finding \
            "Kafka Message Consumption Without Authentication" \
            "Successfully consumed messages from Kafka topics on ${host}:${port} without authentication" \
            "$evidence" \
            "critical"
        
        return 0
    fi
    
    return 1
}

test_jmx_port() {
    local host=$1
    local jmx_port=9999
    
    if nc -zv -w 3 "$host" "$jmx_port" 2>&1 | grep -q "succeeded\|open"; then
        local evidence=$(jq -n --arg host "$host" --arg port "$jmx_port" '{
            "host": $host,
            "jmx_port": $port,
            "accessible": true
        }')
        
        add_finding \
            "Kafka JMX Port Exposed" \
            "JMX port ${jmx_port} is accessible on ${host} - may allow remote code execution if not properly secured" \
            "$evidence" \
            "high"
        
        return 0
    fi
    
    return 1
}

# ========================================
# MAIN SCANNING LOGIC
# ========================================

scan_target() {
    local host=$1
    local port=$2
    
    test_broker_connectivity "$host" "$port" || return 1
    test_metadata_query "$host" "$port"
    test_topic_listing "$host" "$port"
    test_consume_messages "$host" "$port"
    test_jmx_port "$host"
}

# ========================================
# MAIN EXECUTION
# ========================================

main() {
    local target=""
    local port=9092
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                exit 0
                ;;
            *)
                if [ -z "$target" ]; then
                    target=$1
                elif [ "$port" = "9092" ]; then
                    port=$1
                fi
                shift
                ;;
        esac
    done
    
    # Get target from environment if not provided
    if [ -z "$target" ] && [ -n "$TARGET_HOST" ]; then
        target="$TARGET_HOST"
    fi
    
    if [ -z "$target" ]; then
        cat << EOF
{"error": "No target specified", "usage": "Provide target as argument or set CERT_X_GEN_TARGET_HOST environment variable"}
EOF
        exit 1
    fi
    
    # Get port from environment if available
    if [ -n "$TARGET_PORT" ]; then
        port="$TARGET_PORT"
    fi
    
    # Check for jq dependency
    if ! command -v jq &> /dev/null; then
        cat << EOF
{"error": "jq is required for JSON processing"}
EOF
        exit 1
    fi
    
    # Run the scan
    scan_target "$target" "$port"
    
    # Output JSON results
    cat << EOF
{
    "findings": $FINDINGS,
    "metadata": {
        "template_id": "$TEMPLATE_ID",
        "template_name": "$TEMPLATE_NAME",
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "target_host": "$target",
        "target_port": "$port",
        "findings_count": $(echo "$FINDINGS" | jq '. | length')
    }
}
EOF
}

main "$@"