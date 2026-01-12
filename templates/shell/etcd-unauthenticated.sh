#!/bin/bash
# @id: etcd-unauthenticated
# @name: Etcd Unauthenticated Member List Detection
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects etcd clusters accessible without authentication using etcdctl member list
# @tags: etcd, kubernetes, unauthenticated, key-value-store, cwe-306
# @cwe: CWE-306
# @cvss: 8.6
# @references: https://cwe.mitre.org/data/definitions/306.html, https://etcd.io/docs/
# @confidence: 90
# @version: 1.0.0

set -e

# Template metadata
TEMPLATE_ID="etcd-unauthenticated"
TEMPLATE_NAME="Etcd Unauthenticated Member List Detection (Shell)"
SEVERITY="high"
CONFIDENCE=90

# Determine target host and port
if [ "$CERT_X_GEN_MODE" = "engine" ]; then
    HOST="$CERT_X_GEN_TARGET_HOST"
    PORT="${CERT_X_GEN_TARGET_PORT:-2379}"
else
    if [ $# -lt 1 ]; then
        echo '{"findings": [], "metadata": {"id": "etcd-unauthenticated", "name": "Etcd Unauthenticated Member List Detection (Shell)", "language": "shell"}}'
        exit 0
    fi
    HOST="$1"
    PORT="${2:-2379}"
fi

if [ -z "$HOST" ]; then
    echo '{"findings": [], "metadata": {"id": "etcd-unauthenticated", "name": "Etcd Unauthenticated Member List Detection (Shell)", "language": "shell", "error": "No target host provided"}}'
    exit 0
fi

# Check for etcdctl dependency
if ! command -v etcdctl >/dev/null 2>&1; then
    echo '{"findings": [], "metadata": {"id": "etcd-unauthenticated", "name": "Etcd Unauthenticated Member List Detection (Shell)", "language": "shell", "note": "etcdctl not installed"}}'
    exit 0
fi

ENDPOINT="http://${HOST}:${PORT}"
TIMEOUT=10

# Run etcdctl member list, with timeout if available
if command -v timeout >/dev/null 2>&1; then
    RESPONSE=$(timeout "$TIMEOUT" etcdctl --endpoints="${ENDPOINT}" member list 2>/dev/null || true)
else
    RESPONSE=$(etcdctl --endpoints="${ENDPOINT}" member list 2>/dev/null || true)
fi

# No response means either closed/filtered or not etcd
if [ -z "$RESPONSE" ]; then
    echo '{"findings": [], "metadata": {"id": "etcd-unauthenticated", "name": "Etcd Unauthenticated Member List Detection (Shell)", "language": "shell"}}'
    exit 0
fi

# Look for indicators of a real member list
MATCHED=()

if echo "$RESPONSE" | grep -qi "started"; then
    MATCHED+=("started")
fi
if echo "$RESPONSE" | grep -qi "etcd"; then
    MATCHED+=("etcd")
fi
if echo "$RESPONSE" | grep -qi "name="; then
    MATCHED+=("name=")
fi

if [ ${#MATCHED[@]} -eq 0 ]; then
    echo '{"findings": [], "metadata": {"id": "etcd-unauthenticated", "name": "Etcd Unauthenticated Member List Detection (Shell)", "language": "shell"}}'
    exit 0
fi

# Build matched_patterns JSON array
PATTERNS_JSON="["
for i in "${!MATCHED[@]}"; do
    if [ "$i" -gt 0 ]; then
        PATTERNS_JSON+="," 
    fi
    PATTERNS_JSON+="\"${MATCHED[$i]}\""
done
PATTERNS_JSON+="]"

# Base64 encode response to avoid JSON escaping issues
RESP_BASE64=$(printf "%s" "$RESPONSE" | head -c 4000 | base64 | tr -d '\n')

REQUEST_STR="etcdctl --endpoints=${ENDPOINT} member list"

# Output findings in CERT-X-GEN shell JSON contract
cat <<EOF
{
  "findings": [
    {
      "template_id": "${TEMPLATE_ID}",
      "severity": "${SEVERITY}",
      "confidence": ${CONFIDENCE},
      "title": "Etcd member list exposed without authentication",
      "description": "The etcd member list could be retrieved via etcdctl without authentication at ${ENDPOINT}.",
      "evidence": {
        "request": "${REQUEST_STR}",
        "response": "${RESP_BASE64}",
        "matched_patterns": ${PATTERNS_JSON},
        "data": {
          "protocol": "http",
          "port": ${PORT},
          "encoding": "base64",
          "endpoint": "${ENDPOINT}"
        }
      },
      "cwe": "CWE-306",
      "cvss_score": 7.5,
      "remediation": "Restrict access to etcd, require authentication/TLS, and avoid exposing the member list endpoint publicly.",
      "references": [
        "https://etcd.io/docs/",
        "https://cwe.mitre.org/data/definitions/306.html"
      ]
    }
  ],
  "metadata": {
    "id": "${TEMPLATE_ID}",
    "name": "${TEMPLATE_NAME}",
    "severity": "${SEVERITY}",
    "language": "shell",
    "confidence": ${CONFIDENCE}
  }
}
EOF

exit 0
