# CERT-X-GEN Shell Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Shell/Bash security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```bash
#!/bin/bash
#
# @id: my-vulnerability-check
# @name: My Vulnerability Check
# @author: Your Name
# @severity: high
# @description: Detects XYZ vulnerability in ABC service
# @tags: web, injection, cve-2024-xxxx
# @cwe: CWE-89
# @confidence: 85
# @references: https://example.com/advisory
```

### Required Fields
| Field | Format | Example |
|-------|--------|---------|
| `@id` | lowercase-with-dashes | `redis-unauth-access` |
| `@name` | Human readable | `Redis Unauthenticated Access` |
| `@author` | Name or handle | `Security Team` |
| `@severity` | critical/high/medium/low/info | `high` |
| `@description` | Single line description | `Detects Redis without auth` |
| `@tags` | Comma-separated, lowercase | `redis, database, unauth` |

### Optional Fields
| Field | Format | Example |
|-------|--------|---------|
| `@cwe` | CWE-NNN | `CWE-306` |
| `@confidence` | 0-100 | `90` |
| `@references` | Comma-separated URLs | `https://cve.org/...` |

## Runtime Contract

### Environment Variables (Set by Engine)
```
CERT_X_GEN_TARGET_HOST  - Target hostname or IP
CERT_X_GEN_TARGET_PORT  - Target port number
CERT_X_GEN_MODE         - "engine" when run by CLI
CERT_X_GEN_CONTEXT      - Optional JSON context
```

### Single Target Rule
- **ONE target per execution** - the engine handles multi-target scanning
- Do NOT implement target list parsing or port scanning loops
- Do NOT expand `ADD_PORTS` or `OVERRIDE_PORTS` into scan loops

## Output Format (CRITICAL)

### JSON Output Structure
Shell templates MUST output JSON with `findings` and `metadata` wrapper:

```json
{
  "findings": [
    {
      "template_id": "my-vulnerability-check",
      "template_name": "My Vulnerability Check",
      "severity": "high",
      "confidence": 85,
      "title": "Vulnerability Found",
      "description": "Detailed description of the finding",
      "matched_at": "target.com:8080",
      "evidence": {
        "response": "banner data..."
      },
      "cwe": "CWE-89",
      "remediation": "Steps to fix"
    }
  ],
  "metadata": {
    "template_id": "my-vulnerability-check",
    "template_name": "My Vulnerability Check",
    "timestamp": "2024-01-15T12:00:00Z",
    "target": "target.com",
    "port": 8080
  }
}
```

### Required Finding Fields
- `template_id` - Must match `@id` from metadata
- `template_name` - Must match `@name` from metadata
- `severity` - critical/high/medium/low/info (literal values, not variables)
- `title` - Short finding title
- `description` - Detailed description
- `matched_at` - Target identifier (host:port)

### Output Rules
- JSON goes to **stdout** only
- Logs/errors go to **stderr** only
- Empty findings: `{"findings":[],"metadata":{...}}`
- When `CERT_X_GEN_MODE=engine`, wrap output: `[CERT-X-GEN-JSON]...[/CERT-X-GEN-JSON]`

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. JSON Escape Function
Always escape strings for JSON:
```bash
escape_json() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}
```

### 2. Error Handling
Use `set -euo pipefail` and handle errors:
```bash
set -euo pipefail

check_target() {
    local response
    response=$(curl -s -m 5 "http://${host}:${port}/" 2>/dev/null) || {
        echo "Error: Connection failed" >&2
        return 1
    }
    echo "$response"
}
```

### 3. Timeout Handling
Always use timeouts on network operations:
```bash
# curl with timeout
curl -s -m 10 -k "http://${host}:${port}/"

# netcat with timeout
nc -z -w 5 "$host" "$port"

# timeout command wrapper
timeout 5 bash -c "echo >/dev/tcp/$host/$port"
```

### 4. Finding JSON Construction
Build findings with all required fields:
```bash
create_finding() {
    local title="$1"
    local description="$2"
    local evidence="$3"
    local severity="$4"
    local matched_at="${TARGET}:${PORT}"
    
    cat <<EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${CONFIDENCE},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","matched_at":"${matched_at}","evidence":${evidence},"cwe":"${CWE}","remediation":"Apply security patch"}
EOF
}
```

### 5. Output Wrapper Function
Wrap findings with metadata:
```bash
output_json() {
    local findings_array="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF
{"findings":${findings_array},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","timestamp":"${timestamp}","target":"${TARGET}","port":${PORT}}}
EOF
}
```

## Code Structure

```bash
#!/bin/bash
# @id: template-id
# @name: Template Name
# ... (metadata)

set -euo pipefail

# Template metadata (must match @ annotations)
TEMPLATE_ID="template-id"
TEMPLATE_NAME="Template Name"
SEVERITY="high"
CONFIDENCE=90
CWE="CWE-XXX"

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

# Create finding JSON
create_finding() {
    local title="$1"
    local description="$2"
    local evidence="$3"
    local severity="$4"
    local matched_at="${TARGET}:${PORT}"
    
    cat <<EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${CONFIDENCE},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","matched_at":"${matched_at}","evidence":${evidence},"cwe":"${CWE}","remediation":"Apply fix"}
EOF
}

# Output wrapper
output_json() {
    local findings_array="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF
{"findings":${findings_array},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","timestamp":"${timestamp}","target":"${TARGET}","port":${PORT}}}
EOF
}

# Vulnerability check function
check_vulnerability() {
    local host="$1"
    local port="$2"
    
    # Your detection logic here
    local response
    response=$(curl -s -m 5 "http://${host}:${port}/" 2>/dev/null) || return 1
    
    if echo "$response" | grep -qi "vulnerable_indicator"; then
        echo "$response"
        return 0
    fi
    return 1
}

# Main
main() {
    if [[ -z "$TARGET" ]]; then
        echo "Error: No target specified" >&2
        output_json "[]"
        exit 1
    fi
    
    local findings=()
    
    if response=$(check_vulnerability "$TARGET" "$PORT"); then
        local evidence='{"response":"'"$(escape_json "$response")"'"}'
        findings+=("$(create_finding \
            "Vulnerability Detected" \
            "Found issue on ${TARGET}:${PORT}" \
            "$evidence" \
            "high")")
    fi
    
    # Build findings array
    local json="["
    for i in "${!findings[@]}"; do
        [[ $i -gt 0 ]] && json+=","
        json+="${findings[$i]}"
    done
    json+="]"
    
    # Output with wrapper
    local output
    output=$(output_json "$json")
    
    if [[ "$ENGINE_MODE" == "engine" ]]; then
        echo "[CERT-X-GEN-JSON]${output}[/CERT-X-GEN-JSON]"
    else
        echo "$output"
    fi
}

main
```

## Things to AVOID

1. **No echo for JSON output** - use `cat <<EOF` for multi-line JSON
2. **No variable expansion in severity** - use literal values like `"high"` not `"${sev}"`
3. **No jq dependency** - use manual JSON construction
4. **No stdout for debugging** - use `echo "msg" >&2`
5. **No hardcoded targets** - always use environment/args
6. **No multi-target loops** - engine handles this
7. **No missing findings wrapper** - must have `{"findings":[...],"metadata":{...}}`

## Example: IMAP Banner Grab

```bash
#!/bin/bash
# @id: imap-banner-check
# @name: IMAP Banner Information Disclosure
# @author: Security Team
# @severity: low
# @description: Grabs IMAP banner for service identification
# @tags: imap, banner, enumeration, email
# @cwe: CWE-200
# @confidence: 95

set -euo pipefail

TEMPLATE_ID="imap-banner-check"
TEMPLATE_NAME="IMAP Banner Information Disclosure"
SEVERITY="low"
CONFIDENCE=95
CWE="CWE-200"

TARGET="${CERT_X_GEN_TARGET_HOST:-${1:-}}"
PORT="${CERT_X_GEN_TARGET_PORT:-${2:-143}}"
ENGINE_MODE="${CERT_X_GEN_MODE:-}"

escape_json() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

create_finding() {
    local title="$1"
    local description="$2"
    local evidence="$3"
    local severity="$4"
    local matched_at="${TARGET}:${PORT}"
    
    cat <<EOF
{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","severity":"${severity}","confidence":${CONFIDENCE},"title":"$(escape_json "$title")","description":"$(escape_json "$description")","matched_at":"${matched_at}","evidence":${evidence},"cwe":"${CWE}","remediation":"Consider hiding IMAP version information"}
EOF
}

output_json() {
    local findings_array="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF
{"findings":${findings_array},"metadata":{"template_id":"${TEMPLATE_ID}","template_name":"${TEMPLATE_NAME}","timestamp":"${timestamp}","target":"${TARGET}","port":${PORT}}}
EOF
}

check_imap() {
    local host="$1"
    local port="$2"
    
    # Connect and read banner
    local banner
    banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/${host}/${port} && head -1 <&3" 2>/dev/null) || return 1
    
    if [[ "$banner" == *"OK"* ]] || [[ "$banner" == *"IMAP"* ]]; then
        echo "$banner"
        return 0
    fi
    return 1
}

main() {
    if [[ -z "$TARGET" ]]; then
        echo "Error: No target specified" >&2
        output_json "[]"
        exit 1
    fi
    
    local findings=()
    
    if banner=$(check_imap "$TARGET" "$PORT"); then
        local evidence='{"response":"'"$(escape_json "$banner")"'"}'
        findings+=("$(create_finding \
            "IMAP Banner Detected" \
            "IMAP service on ${TARGET}:${PORT} disclosed banner" \
            "$evidence" \
            "low")")
    fi
    
    local json="["
    for i in "${!findings[@]}"; do
        [[ $i -gt 0 ]] && json+=","
        json+="${findings[$i]}"
    done
    json+="]"
    
    local output
    output=$(output_json "$json")
    
    if [[ "$ENGINE_MODE" == "engine" ]]; then
        echo "[CERT-X-GEN-JSON]${output}[/CERT-X-GEN-JSON]"
    else
        echo "$output"
    fi
}

main
```
