# YAML Template Engine

The YAML template engine provides support for declarative security templates written in YAML format.

## Features

- **HTTP/HTTPS Protocol Support**: Execute HTTP requests with custom methods, headers, and bodies
- **Network/TCP Protocol Support**: Direct TCP socket connections with payload sending
- **Multi-step Flows**: Chain multiple requests with dependencies
- **Powerful Matchers**: Word, regex, status code, and custom matchers
- **Extractors**: Extract data from responses for use in subsequent requests

## Supported Protocols

- `http` - HTTP requests
- `https` - HTTPS requests  
- `tcp` - TCP socket connections
- `udp` - UDP socket connections (planned)

## Template Structure

```yaml
id: template-id
name: "Template Name"
severity: critical|high|medium|low|info
description: |
  Template description

# HTTP requests
http:
  - method: GET
    path:
      - "/"
      - "/admin"
    matchers:
      - type: word
        words: ["success"]

# Network/TCP requests
network:
  - protocol: tcp
    port: 6379
    payloads:
      - "INFO\r\n"
    matchers:
      - type: word
        words: ["redis_version"]

# Multi-step flows
flows:
  - id: step1
    http:
      method: POST
      path: "/login"
    extractors:
      - type: regex
        name: token
        regex: ["token=([a-zA-Z0-9]+)"]
```

## Files

- `mod.rs` - Main engine implementation

## Future Enhancements

- UDP protocol support
- WebSocket support
- gRPC support
- Custom protocol handlers
