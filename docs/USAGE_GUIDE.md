# CERT-X-GEN Usage Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Scanning](#basic-scanning)
3. [Port Configuration](#port-configuration)
4. [Target Types](#target-types)
5. [Template Selection](#template-selection)
6. [Template Search](#template-search)
7. [Output Formats](#output-formats)
8. [Advanced Configuration](#advanced-configuration)
9. [Use Cases](#use-cases)
10. [Troubleshooting](#troubleshooting)
11. [Examples](#examples)

## Quick Start

### Installation
```bash
# Build from source
cargo build --release

# The binary will be available at target/release/cert-x-gen
```

### Basic Scan
```bash
# Scan a single target
./target/release/cxg scan --target example.com

# Scan with specific port
./target/release/cxg scan --target example.com --port 8080

# Scan with multiple ports
./target/release/cxg scan --target example.com --ports 80,443,8080,9090
```

## Basic Scanning

### Single Target Scanning
```bash
# Scan a single IP address
cxg scan --target 192.168.1.100

# Scan a single domain
cxg scan --target example.com

# Scan with hostname resolution
cxg scan --target example.com --domain example.com
```

### Multiple Target Scanning
```bash
# Scan multiple targets (comma-separated)
cxg scan --targets 192.168.1.100,192.168.1.101,example.com

# Scan targets from file
cxg scan --target-file targets.txt

# Scan multiple domains
cxg scan --domains example.com,test.com,demo.com
```

### Target File Format
Create a `targets.txt` file:
```
192.168.1.100
192.168.1.101
example.com
test.com:8080
demo.com:443,8080,9090
```

## Port Configuration

### Single Port
```bash
# Scan specific port
cxg scan --target example.com --port 8080

# Scan HTTPS
cxg scan --target example.com --port 443
```

### Multiple Ports
```bash
# Comma-separated ports
cxg scan --target example.com --ports 80,443,8080,9090

# Port ranges (if supported)
cxg scan --target example.com --ports 8000-8010

# Common web ports
cxg scan --target example.com --ports 80,443,8080,8443,9000,9090
```

### Port Configuration in Templates
Templates can specify additional ports to scan using environment variables:

```bash
# Templates can add ports via environment variables
CERT_X_GEN_ADD_PORTS="8080,9090" cxg scan --target example.com

# Override default ports
CERT_X_GEN_OVERRIDE_PORTS="8080,9090,3000" cxg scan --target example.com
```

### Common Port Combinations

#### Web Application Ports
```bash
# Standard web ports
cxg scan --target example.com --ports 80,443,8080,8443,8000,8008,8888,9000,9090

# Development ports
cxg scan --target example.com --ports 3000,3001,4000,5000,6000,7000,8000,9000
```

#### Database Ports
```bash
# Database services
cxg scan --target example.com --ports 3306,5432,27017,6379,11211,9200,5601
```

#### Container & Orchestration Ports
```bash
# Docker & Kubernetes
cxg scan --target example.com --ports 2375,2376,6443,8080,9090,10250,10255
```

#### Monitoring & Observability Ports
```bash
# Monitoring services
cxg scan --target example.com --ports 9090,3000,5601,8080,15672,9092
```

## Target Types

### IP Addresses
```bash
# Single IP
cxg scan --target 192.168.1.100

# Multiple IPs
cxg scan --targets 192.168.1.100,192.168.1.101,192.168.1.102

# IP with specific port
cxg scan --target 192.168.1.100 --port 8080
```

### Domains
```bash
# Single domain
cxg scan --target example.com

# Multiple domains
cxg scan --domains example.com,test.com,demo.com

# Domain with specific port
cxg scan --target example.com --port 8080
```

### CIDR Ranges
```bash
# Network range
cxg scan --target 192.168.1.0/24

# Large network
cxg scan --target 10.0.0.0/8
```

### URLs
```bash
# Full URL
cxg scan --target https://example.com:8080/api

# HTTP URL
cxg scan --target http://example.com:3000
```

## Template Selection

### By Language
```bash
# C templates only
cxg scan --target example.com --template-language c

# Go templates only
cxg scan --target example.com --template-language go

# Python templates only
cxg scan --target example.com --template-language python

# Multiple languages (run separately)
cxg scan --target example.com --template-language c
cxg scan --target example.com --template-language go
cxg scan --target example.com --template-language python
```

### By Tags
```bash
# Database templates
cxg scan --target example.com --tags database

# Web application templates
cxg scan --target example.com --tags web

# Network service templates
cxg scan --target example.com --tags network
```

### By Severity
```bash
# High severity only
cxg scan --target example.com --severity high

# Critical and high severity
cxg scan --target example.com --severity critical,high
```

### Specific Templates
```bash
# Include specific templates
cxg scan --target example.com --include-templates redis-unauthenticated,mongodb-unauthenticated

# Exclude specific templates
cxg scan --target example.com --exclude-templates sql-injection-detection
```

## Template Search

CERT-X-GEN includes a powerful template search feature that allows you to discover and explore available templates across all supported languages.

### Basic Search

```bash
# Search for templates containing "redis"
cxg search --query "redis"

# Search with case sensitivity
cxg search --query "Redis" --case-sensitive

# Use regex for advanced pattern matching
cxg search --query "redis|mysql|postgres" --regex
```

### Filtering by Language

```bash
# Search only C templates
cxg search --query "injection" --language c

# Search only Python templates
cxg search --query "database" --language python

# Search only Go templates
cxg search --query "kubernetes" --language go
```

### Filtering by Severity

```bash
# Find critical severity templates
cxg search --severity critical

# Find high and critical severity templates
cxg search --severity critical,high

# Find medium severity templates
cxg search --severity medium
```

### Filtering by Tags

```bash
# Search templates with specific tags
cxg search --tags "database,unauthenticated"

# Search for web application templates
cxg search --tags "web,injection"

# Search for network service templates
cxg search --tags "network,service"
```

### Advanced Search Options

```bash
# Search in template content (slower but comprehensive)
cxg search --query "curl" --content

# Filter by author
cxg search --author "CERT-X-GEN"

# Filter by CWE ID
cxg search --cwe "CWE-89"

# Limit number of results
cxg search --query "injection" --limit 10
```

### Search Output Formats

```bash
# Table format (default)
cxg search --query "redis" --format table

# JSON format for automation
cxg search --query "redis" --format json

# YAML format
cxg search --query "redis" --format yaml

# CSV format for spreadsheet analysis
cxg search --query "redis" --format csv

# Simple list format
cxg search --query "redis" --format list

# Detailed format with full information
cxg search --query "redis" --format detailed
```

### Sorting and Ordering

```bash
# Sort by relevance (default)
cxg search --query "injection" --sort relevance

# Sort by name alphabetically
cxg search --query "injection" --sort name

# Sort by language
cxg search --query "injection" --sort language

# Sort by severity
cxg search --query "injection" --sort severity

# Sort by author
cxg search --query "injection" --sort author

# Sort by date (newest first)
cxg search --query "injection" --sort date

# Reverse sort order
cxg search --query "injection" --sort name --reverse
```

### Search Statistics

```bash
# Show search statistics
cxg search --query "injection" --stats

# Show only template IDs
cxg search --query "injection" --ids-only

# Show detailed information
cxg search --query "injection" --detailed
```

### Output to File

```bash
# Save search results to file
cxg search --query "redis" --output redis-templates.json --format json

# Save as CSV for analysis
cxg search --query "database" --output database-templates.csv --format csv

# Save detailed results
cxg search --query "injection" --output injection-templates.yaml --format yaml --detailed
```

### Search Examples

#### Find Database Templates
```bash
# Find all database-related templates
cxg search --query "database" --format table

# Find unauthenticated database templates
cxg search --tags "database,unauthenticated" --severity critical

# Find SQL injection templates
cxg search --query "sql injection" --content
```

#### Find Web Application Templates
```bash
# Find XSS templates
cxg search --query "xss" --language python

# Find CSRF templates
cxg search --query "csrf" --language cpp

# Find file inclusion templates
cxg search --query "file inclusion" --language php
```

#### Find Network Service Templates
```bash
# Find Redis templates
cxg search --query "redis" --format json

# Find Kubernetes templates
cxg search --query "kubernetes" --language go

# Find Docker templates
cxg search --query "docker" --language python
```

#### Find Templates by Language
```bash
# Find all C templates
cxg search --language c --format list

# Find all Go templates
cxg search --language go --format table

# Find all Python templates
cxg search --language python --format json
```

#### Find Templates by Severity
```bash
# Find critical templates
cxg search --severity critical --format detailed

# Find high severity templates
cxg search --severity high --format table

# Find medium severity templates
cxg search --severity medium --format list
```

### Search Performance Tips

1. **Use specific queries**: More specific queries are faster than broad ones
2. **Filter by language**: Use `--language` to limit search scope
3. **Use tags**: Tag-based filtering is faster than content search
4. **Limit results**: Use `--limit` to reduce output size
5. **Avoid content search**: Use `--content` only when necessary

### Search Integration

```bash
# Use search results in scanning
TEMPLATES=$(cxg search --query "redis" --ids-only | tr '\n' ',')
cxg scan --target example.com --templates "$TEMPLATES"

# Find templates for specific use case
cxg search --tags "database,unauthenticated" --severity critical --format json | jq -r '.results[].id' | xargs -I {} cxg scan --target example.com --template {}
```

## Output Formats

### JSON Output
```bash
# JSON format (default)
cxg scan --target example.com --output-format json

# JSON to file
cxg scan --target example.com --output results.json --output-format json
```

### HTML Report
```bash
# HTML report
cxg scan --target example.com --output-format html

# HTML with custom output
cxg scan --target example.com --output report.html --output-format html
```

### SARIF Format
```bash
# SARIF for security tools integration
cxg scan --target example.com --output-format sarif
```

### CSV Format
```bash
# CSV for spreadsheet analysis
cxg scan --target example.com --output-format csv
```

### Multiple Formats
```bash
# Multiple output formats
cxg scan --target example.com --output-format json,html,sarif
```

## Advanced Configuration

### Configuration File
Create a `config.yaml` file:
```yaml
# config.yaml
targets:
  - "example.com"
  - "192.168.1.100"

ports:
  - 80
  - 443
  - 8080
  - 9090

template_language: "python"
output_format: "json"
output_file: "scan-results.json"

timeout: "30s"
retry_count: 3
max_concurrent_targets: 10
max_concurrent_templates: 5

headers:
  User-Agent: "CERT-X-GEN/1.0"
  X-Custom-Header: "value"

follow_redirects: true
max_redirects: 5
verify_ssl: false
```

Use configuration file:
```bash
cxg scan --config config.yaml
```

### Environment Variables
```bash
# Set environment variables
export CERT_X_GEN_TARGET_HOST="example.com"
export CERT_X_GEN_TARGET_PORT="8080"
export CERT_X_GEN_ADD_PORTS="9090,3000"
export CERT_X_GEN_OUTPUT_FORMAT="json"

# Run scan
cxg scan
```

### Performance Tuning
```bash
# Increase concurrency
cxg scan --target example.com --parallel-targets 20 --parallel-templates 10

# Adjust timeouts
cxg scan --target example.com --timeout 60s --retry 5

# Limit threads
cxg scan --target example.com --threads 8
```

## Use Cases

### 1. Web Application Security Testing
```bash
# Comprehensive web app scan
cxg scan --target example.com --ports 80,443,8080,8443,8000,9000 \
  --template-language python --tags web --severity high,critical \
  --output-format json,html
```

### 2. Database Security Assessment
```bash
# Database services scan
cxg scan --target 192.168.1.100 --ports 3306,5432,27017,6379,9200 \
  --template-language c,go --tags database \
  --output-format json
```

### 3. Container & Kubernetes Security
```bash
# Container orchestration scan
cxg scan --target 192.168.1.100 --ports 2375,2376,6443,8080,9090,10250 \
  --template-language go,python --tags container \
  --output-format json,sarif
```

### 4. Network Infrastructure Assessment
```bash
# Network services scan
cxg scan --target 192.168.1.0/24 --ports 22,23,25,53,80,443,993,995 \
  --template-language c,cpp --tags network \
  --output-format csv
```

### 5. Cloud Service Discovery
```bash
# Cloud metadata endpoints
cxg scan --target 169.254.169.254 --ports 80,443 \
  --template-language python --tags cloud \
  --output-format json
```

### 6. Development Environment Testing
```bash
# Development services
cxg scan --target localhost --ports 3000,4000,5000,6000,8000,9000 \
  --template-language python,javascript --tags development \
  --output-format json
```

### 7. CI/CD Pipeline Integration
```bash
# Automated scanning in CI/CD
cxg scan --target $TARGET_HOST --ports $TARGET_PORTS \
  --template-language python --severity high,critical \
  --output-format sarif --output ci-results.sarif
```

### 8. Compliance Scanning
```bash
# Compliance-focused scan
cxg scan --target example.com --ports 80,443,8080,8443 \
  --template-language yaml --tags compliance \
  --output-format json,html
```

## Troubleshooting

### Common Issues

#### 1. Template Compilation Errors
```bash
# C templates failing due to missing dependencies
# Install required libraries
brew install json-c curl  # macOS
apt-get install libjson-c-dev libcurl4-openssl-dev  # Ubuntu

# Check dependencies
make check-deps
```

#### 2. Language Runtime Not Found
```bash
# Check available runtimes
make check-deps

# Install missing runtimes
# Go
brew install go

# Java
brew install openjdk

# PHP
brew install php
```

#### 3. Network Connectivity Issues
```bash
# Test connectivity
ping example.com
telnet example.com 80

# Use verbose output for debugging
cxg scan --target example.com --verbose
```

#### 4. Permission Issues
```bash
# Ensure binary is executable
chmod +x target/release/cert-x-gen

# Check file permissions
ls -la target/release/cert-x-gen
```

#### 5. Template Loading Errors
```bash
# Check template directory
ls -la templates/

# Verify template syntax
cxg scan --target example.com --template-language yaml --verbose
```

### Debug Mode
```bash
# Enable debug logging
RUST_LOG=debug cxg scan --target example.com --verbose

# Check template loading
cxg scan --target example.com --verbose --template-language python
```

### Performance Issues
```bash
# Reduce concurrency
cxg scan --target example.com --parallel-targets 5 --parallel-templates 3

# Increase timeout
cxg scan --target example.com --timeout 120s

# Limit templates
cxg scan --target example.com --template-language python --severity high
```

## Examples

### Example 1: Complete Web Application Scan
```bash
#!/bin/bash
# Complete web application security scan

TARGET="example.com"
PORTS="80,443,8080,8443,8000,9000"
OUTPUT_DIR="scan-results-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "Starting comprehensive web application scan..."
echo "Target: $TARGET"
echo "Ports: $PORTS"
echo "Output: $OUTPUT_DIR"

# Run scans for different languages
for lang in python javascript yaml; do
    echo "Scanning with $lang templates..."
    cxg scan \
        --target "$TARGET" \
        --ports "$PORTS" \
        --template-language "$lang" \
        --output "$OUTPUT_DIR/${lang}-results" \
        --output-format json,html \
        --verbose
done

echo "Scan completed. Results in $OUTPUT_DIR"
```

### Example 2: Database Security Assessment
```bash
#!/bin/bash
# Database security assessment

TARGET="192.168.1.100"
DB_PORTS="3306,5432,27017,6379,9200,5601"
OUTPUT="db-assessment-$(date +%Y%m%d).json"

echo "Starting database security assessment..."
echo "Target: $TARGET"
echo "Ports: $DB_PORTS"

cxg scan \
    --target "$TARGET" \
    --ports "$DB_PORTS" \
    --template-language c,go \
    --tags database \
    --output "$OUTPUT" \
    --output-format json \
    --severity high,critical \
    --verbose

echo "Database assessment completed. Results: $OUTPUT"
```

### Example 3: Container Security Scan
```bash
#!/bin/bash
# Container and Kubernetes security scan

TARGET="192.168.1.100"
CONTAINER_PORTS="2375,2376,6443,8080,9090,10250,10255"
OUTPUT="container-scan-$(date +%Y%m%d).json"

echo "Starting container security scan..."
echo "Target: $TARGET"
echo "Ports: $CONTAINER_PORTS"

cxg scan \
    --target "$TARGET" \
    --ports "$CONTAINER_PORTS" \
    --template-language go,python \
    --tags container,kubernetes \
    --output "$OUTPUT" \
    --output-format json,sarif \
    --verbose

echo "Container scan completed. Results: $OUTPUT"
```

### Example 4: Network Range Scan
```bash
#!/bin/bash
# Network range security scan

NETWORK="192.168.1.0/24"
COMMON_PORTS="22,23,25,53,80,443,993,995,3306,5432,6379"
OUTPUT="network-scan-$(date +%Y%m%d).json"

echo "Starting network range scan..."
echo "Network: $NETWORK"
echo "Ports: $COMMON_PORTS"

cxg scan \
    --target "$NETWORK" \
    --ports "$COMMON_PORTS" \
    --template-language c,cpp \
    --tags network \
    --output "$OUTPUT" \
    --output-format json,csv \
    --parallel-targets 20 \
    --parallel-templates 5 \
    --timeout 30s

echo "Network scan completed. Results: $OUTPUT"
```

### Example 5: CI/CD Integration
```bash
#!/bin/bash
# CI/CD pipeline integration

TARGET="${TARGET_HOST:-localhost}"
PORTS="${TARGET_PORTS:-80,443,8080}"
SEVERITY="${SCAN_SEVERITY:-high,critical}"
OUTPUT="ci-scan-results.sarif"

echo "Starting CI/CD security scan..."
echo "Target: $TARGET"
echo "Ports: $PORTS"
echo "Severity: $SEVERITY"

cxg scan \
    --target "$TARGET" \
    --ports "$PORTS" \
    --template-language python \
    --severity "$SEVERITY" \
    --output "$OUTPUT" \
    --output-format sarif \
    --quiet

# Check for critical findings
CRITICAL_COUNT=$(jq '.runs[0].results | map(select(.level == "error")) | length' "$OUTPUT")

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "❌ Found $CRITICAL_COUNT critical security issues"
    exit 1
else
    echo "✅ No critical security issues found"
    exit 0
fi
```

### Example 6: Multi-Language Template Testing
```bash
#!/bin/bash
# Test all template languages

TARGET="127.0.0.1"
OUTPUT_DIR="multi-lang-test-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "Testing all template languages..."
echo "Target: $TARGET"
echo "Output: $OUTPUT_DIR"

# Test each language
for lang in c cpp java go python javascript rust shell ruby perl php yaml; do
    echo "Testing $lang templates..."
    cxg scan \
        --target "$TARGET" \
        --template-language "$lang" \
        --output "$OUTPUT_DIR/${lang}-results" \
        --output-format json \
        --quiet
done

echo "Multi-language testing completed. Results in $OUTPUT_DIR"
```

## Best Practices

### 1. Target Selection
- Start with specific targets before scanning ranges
- Use appropriate port combinations for your use case
- Consider network segmentation and firewall rules

### 2. Template Selection
- Use language-specific templates for optimal performance
- Filter by severity to focus on critical issues
- Use tags to target specific vulnerability types

### 3. Performance Optimization
- Adjust concurrency based on network capacity
- Use appropriate timeouts for your environment
- Consider rate limiting for production systems

### 4. Output Management
- Use structured formats (JSON, SARIF) for automation
- Generate HTML reports for human review
- Store results with timestamps for tracking

### 5. Security Considerations
- Be mindful of network policies and permissions
- Use appropriate authentication when required
- Consider the impact on target systems

### 6. Integration
- Integrate with CI/CD pipelines for automated scanning
- Use SARIF format for security tool integration
- Set up monitoring and alerting for critical findings

## Support

For additional help:
- Check the [Template Registry](templates/TEMPLATE_REGISTRY.md)
- Review the [Engine Architecture](ENGINE_ARCHITECTURE.md)
- Run `make help` for available commands
- Use `cxg scan --help` for CLI options
- Check `make check-deps` for dependency issues
