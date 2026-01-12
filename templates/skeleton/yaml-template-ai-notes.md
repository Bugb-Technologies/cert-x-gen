# CERT-X-GEN YAML Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating YAML security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include both header annotations AND top-level fields. The CLI parser extracts metadata from both sources.

```yaml
# @id: my-vulnerability-check
# @name: My Vulnerability Check
# @author: Your Name
# @severity: high
# @description: Detects XYZ vulnerability in ABC service
# @tags: web, injection, cve-2024-xxxx
# @references: https://example.com/advisory

id: my-vulnerability-check
name: "My Vulnerability Check"
author: Your Name
severity: high
description: |
  Detects XYZ vulnerability in ABC service.
  Supports multiple lines for detailed descriptions.
tags:
  - web
  - injection
references:
  - https://example.com/advisory

language: yaml
```

### Required Fields (Top-Level)
| Field | Format | Example |
|-------|--------|---------|
| `id` | lowercase-with-dashes | `redis-unauth-access` |
| `name` | Human readable string | `Redis Unauthenticated Access` |
| `author` | Name, email, or mapping | `Security Team` |
| `severity` | critical/high/medium/low/info | `high` |
| `description` | String or multi-line | `Detects Redis without auth` |

### Optional Fields
| Field | Format | Example |
|-------|--------|---------|
| `tags` | List of strings | `[redis, database, unauth]` |
| `references` | List of URLs | `[https://cve.org/...]` |
| `cwe` | List or string | `[CWE-306]` |
| `language` | Must be `yaml` | `yaml` |
| `remediation` | String | `Enable authentication` |

## Execution Blocks

Templates must include at least one of: `http`, `network`, `dns`, or `flows`.

### HTTP Block
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/api/health"
    
    headers:
      User-Agent: "cert-x-gen/1.0"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "vulnerable"
        part: body
```

### Network Block
```yaml
network:
  - protocol: tcp
    port: 6379
    
    payloads:
      - "INFO\r\n"
    
    matchers:
      - type: word
        words:
          - "redis_version"
```

## Matcher Types (CRITICAL)

Only these matcher types are valid:

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `word` | Substring match | `words` (list) |
| `regex` | Regular expression | `regex` (list) |
| `binary` | Hex-encoded bytes | `binary` (list) |
| `status` | HTTP status codes | `status` (list) |
| `size` | Response length | Use DSL instead |
| `dsl` | Expression-based | `dsl` (list) |
| `xpath` | XML/HTML path | `xpath` (list) |

### ❌ INVALID Matcher Types
- `time` - Use DSL: `duration >= 5`
- `response_time` - Use DSL: `duration > 3`
- `content_length` - Use DSL: `content_length > 1000`

### Matcher Options
```yaml
matchers:
  - type: word
    words:
      - "admin"
      - "root"
    condition: or       # Valid: and, or
    part: body          # Valid: body, header, all, raw
    negative: false     # Invert match
```

### DSL Expressions
For timing and size checks, use DSL:
```yaml
matchers:
  # Response time check
  - type: dsl
    dsl:
      - "duration >= 5"
  
  # Size check
  - type: dsl
    dsl:
      - "content_length > 100000"
  
  # Complex conditions
  - type: dsl
    dsl:
      - "status_code == 200 && contains(body, 'admin')"
```

## Extractor Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `regex` | Regex capture | `regex`, optional `group` |
| `kval` | Key-value header | `kval` (list of keys) |
| `json` | JSON path | `json` (list of paths) |
| `xpath` | XML/HTML path | `xpath` (list) |
| `dsl` | Expression | `dsl` (list) |

### Extractor Example
```yaml
extractors:
  - type: regex
    name: version
    regex:
      - "Version:\\s*(\\d+\\.\\d+)"
    group: 1
  
  - type: kval
    name: server
    kval:
      - Server
```

## Variable References

Use `{{variable}}` syntax for:
- `{{BaseURL}}` - Full target URL
- `{{Hostname}}` - Target hostname
- `{{Host}}` - Host without port
- `{{Port}}` - Target port
- `{{Path}}` - URL path
- `{{Scheme}}` - http or https
- Extracted values by name

## Validation Requirements

### 1. ID Must Match Filename
```yaml
# File: redis-unauth-check.yaml
id: redis-unauth-check  # Must match!
```

### 2. Valid Severity Values
Only: `critical`, `high`, `medium`, `low`, `info`

### 3. Matchers-Condition
Only: `and`, `or`

### 4. Port Range
For network templates: 1-65535 or `{{Port}}`

## Complete Example: MySQL Unauth Check

```yaml
# @id: mysql-unauth-check
# @name: MySQL Unauthenticated Access
# @author: Security Team
# @severity: critical
# @description: Detects MySQL instances accessible without authentication
# @tags: mysql, database, unauth
# @cwe: CWE-306

id: mysql-unauth-check
name: "MySQL Unauthenticated Access"
author: Security Team
severity: critical
description: |
  Detects MySQL instances that allow connections without authentication.
  This is a critical security misconfiguration.
tags:
  - mysql
  - database
  - unauth
  - cwe-306
references:
  - https://cwe.mitre.org/data/definitions/306.html
  - https://dev.mysql.com/doc/refman/8.0/en/security.html

language: yaml

network:
  - protocol: tcp
    port: 3306
    
    # MySQL protocol handshake (simplified)
    payloads:
      - ""
    
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "mysql"
          - "MariaDB"
        condition: or
        part: body
      
      - type: regex
        regex:
          - "[0-9]+\\.[0-9]+\\.[0-9]+"
    
    extractors:
      - type: regex
        name: mysql_version
        regex:
          - "([0-9]+\\.[0-9]+\\.[0-9]+)"
        group: 1

remediation: |
  1. Set strong root password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_password';
  2. Remove anonymous users: DELETE FROM mysql.user WHERE User='';
  3. Bind to localhost: bind-address = 127.0.0.1
  4. Enable authentication plugin
  5. Use firewall to restrict access
```

## Things to AVOID

1. **No `type: time`** - Use `type: dsl` with `duration >= N`
2. **No `type: size`** - Use `type: dsl` with `content_length > N`
3. **No `condition: greater`** - Invalid, use DSL expressions
4. **No `info:` wrapper** - Use top-level fields directly
5. **No id/filename mismatch** - Keep them aligned
6. **No invalid severity** - Only critical/high/medium/low/info
7. **No multi-target scanning** - Engine handles this
