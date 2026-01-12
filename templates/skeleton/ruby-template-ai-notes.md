# CERT-X-GEN Ruby Template – AI Generation Guide

## Purpose
This document provides authoritative guidance for AI systems generating Ruby security templates for CERT-X-GEN. Follow these rules exactly to ensure templates pass validation and execute correctly.

## Metadata Format (CRITICAL)

Templates MUST include metadata in the header using `@field:` annotations. The CLI parser extracts metadata from the first 50 lines.

```ruby
#!/usr/bin/env ruby
# frozen_string_literal: true
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

require 'socket'
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

### JSON Output to stdout
When `CERT_X_GEN_MODE=engine` or `--json` flag is used, output MUST be valid JSON:

```json
[
  {
    "template_id": "my-vulnerability-check",
    "severity": "high",
    "confidence": 85,
    "title": "Vulnerability Found",
    "description": "Detailed description of the finding",
    "evidence": {
      "response": "banner data..."
    },
    "cwe": "CWE-89",
    "remediation": "Steps to fix"
  }
]
```

### Required Finding Fields
- `template_id` - Must match `@id` from metadata
- `severity` - critical/high/medium/low/info
- `title` - Short finding title
- `description` - Detailed description

### Output Rules
- JSON goes to **stdout** via `puts` only
- Logs/errors go to **stderr** via `warn` or `$stderr.puts` only
- Empty findings array `[]` is valid (no vulnerability found)
- Do NOT mix human-readable text with JSON output

## Validation Requirements

Templates are validated before execution. Ensure:

### 1. Network/Socket Code
Include proper requires for network operations:
```ruby
require 'socket'
require 'net/http'
require 'uri'
```

### 2. Error Handling
Use begin/rescue blocks:
```ruby
begin
  socket = TCPSocket.new(host, port)
rescue SocketError, Errno::ECONNREFUSED => e
  warn "Error: #{e.message}"
end
```

### 3. Timeout Handling
Use Timeout module:
```ruby
require 'timeout'

Timeout.timeout(5) do
  socket = TCPSocket.new(host, port)
end
```

### 4. JSON Output
Use JSON library for output:
```ruby
require 'json'
puts JSON.generate(findings)
```

### 5. Entry Point
Use standard Ruby idiom:
```ruby
if __FILE__ == $PROGRAM_NAME
  main
end
```

## Code Structure

```ruby
#!/usr/bin/env ruby
# frozen_string_literal: true
#
# @id: template-id
# @name: Template Name
# ... (metadata)

require 'socket'
require 'json'
require 'timeout'

TIMEOUT_SEC = 5

def check_vulnerability(host, port)
  Timeout.timeout(TIMEOUT_SEC) do
    socket = TCPSocket.new(host, port)
    
    # Send probe
    socket.write("PROBE\r\n")
    
    # Read response
    response = socket.read_nonblock(4096)
    socket.close
    
    if vulnerable?(response)
      return {
        template_id: 'template-id',
        severity: 'high',
        confidence: 90,
        title: 'Vulnerability Found',
        description: "Found issue on #{host}:#{port}",
        evidence: { response: response[0, 500] },
        cwe: 'CWE-XXX',
        remediation: 'Apply security patch'
      }
    end
  rescue IO::WaitReadable
    # No data available
  end
  nil
rescue Timeout::Error
  warn "Error: Connection timeout"
  nil
rescue SocketError, Errno::ECONNREFUSED => e
  warn "Error: #{e.message}"
  nil
end

def vulnerable?(response)
  # Your detection logic here
  response&.include?('VULNERABLE_INDICATOR')
end

def main
  target = ENV['CERT_X_GEN_TARGET_HOST'] || ARGV[0]
  port = (ENV['CERT_X_GEN_TARGET_PORT'] || '80').to_i
  
  if target.nil? || target.empty?
    warn 'Error: No target specified'
    puts '[]'
    return
  end
  
  findings = []
  
  finding = check_vulnerability(target, port)
  findings << finding if finding
  
  puts JSON.generate(findings)
end

main if __FILE__ == $PROGRAM_NAME
```

## Things to AVOID

1. **No puts for debugging** - use warn or $stderr.puts instead
2. **No backticks for commands** - avoid command injection
3. **No eval()** - dangerous code execution
4. **No bare rescue** - always specify exception type
5. **No system() with user input** - command injection risk
6. **No hardcoded targets** - always use environment/args
7. **No multi-target loops** - engine handles this

## Example: POP3 Banner Grab

```ruby
#!/usr/bin/env ruby
# frozen_string_literal: true
#
# @id: pop3-banner-check
# @name: POP3 Banner Information Disclosure
# @author: Security Team
# @severity: low
# @description: Grabs POP3 banner for service identification
# @tags: pop3, banner, enumeration, email
# @cwe: CWE-200
# @confidence: 95

require 'socket'
require 'json'
require 'timeout'

TIMEOUT_SEC = 5

def escape_json_string(str)
  str.to_s.gsub(/[\x00-\x1f"\\]/) do |char|
    case char
    when '"' then '\\"'
    when '\\' then '\\\\'
    when "\n" then '\\n'
    when "\r" then '\\r'
    when "\t" then '\\t'
    else ''
    end
  end
end

def check_pop3(host, port)
  Timeout.timeout(TIMEOUT_SEC) do
    socket = TCPSocket.new(host, port)
    banner = socket.gets
    
    # Send QUIT
    socket.write("QUIT\r\n")
    socket.close
    
    if banner&.start_with?('+OK')
      return {
        template_id: 'pop3-banner-check',
        severity: 'low',
        confidence: 95,
        title: 'POP3 Banner Detected',
        description: "POP3 service on #{host}:#{port} disclosed banner",
        evidence: { response: escape_json_string(banner.strip) },
        cwe: 'CWE-200',
        remediation: 'Consider hiding POP3 version information'
      }
    end
  end
  nil
rescue Timeout::Error
  warn 'Error: Connection timeout'
  nil
rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
  warn "Error: #{e.message}"
  nil
end

def main
  target = ENV['CERT_X_GEN_TARGET_HOST'] || ARGV[0]
  port = (ENV['CERT_X_GEN_TARGET_PORT'] || '110').to_i
  
  if target.nil? || target.empty?
    warn 'Error: No target specified'
    puts '[]'
    return
  end
  
  findings = []
  
  finding = check_pop3(target, port)
  findings << finding if finding
  
  puts JSON.generate(findings)
end

main if __FILE__ == $PROGRAM_NAME
```
