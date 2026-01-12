# 🚀 CERT-X-GEN Template Engines

**Welcome to the CERT-X-GEN Template Engine documentation!**

This guide explains how our polyglot architecture allows you to write security scanning templates in **12 different programming languages**, giving you the flexibility to use the tools and libraries you're most comfortable with.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Supported Languages](#supported-languages)
- [How It Works](#how-it-works)
- [Engine Details](#engine-details)
- [Writing Templates](#writing-templates)
- [Environment Variables](#environment-variables)
- [Template Search](#template-search)
- [Best Practices](#best-practices)

---

## 🎯 Overview

CERT-X-GEN is built on a **polyglot template engine architecture** that supports multiple programming languages. This means you can write security scanning templates in Python, JavaScript, Rust, Shell scripts, C, C++, Java, Go, Ruby, Perl, PHP, or YAML - whatever works best for your use case!

### Why Multiple Languages?

- **Flexibility** - Use the language that best fits the task
- **Leverage Existing Libraries** - Use Python's requests, Node's HTTP, C's libcurl, etc.
- **Performance Options** - Use Rust/C/Go for speed-critical templates
- **Quick Prototyping** - Use Python/Shell for rapid development
- **System Integration** - Use Shell scripts for system-level operations
- **Declarative Configuration** - Use YAML for simple, readable templates

---

## 🌐 Supported Languages

### Interpreted Languages (6)
- **🐍 Python** - Great for HTTP requests and data processing
- **🟨 JavaScript/Node.js** - Perfect for web-based scanning
- **💎 Ruby** - Excellent for rapid development
- **🐪 Perl** - Powerful for text processing and system integration
- **🐘 PHP** - Ideal for web application testing
- **🐚 Shell/Bash** - Perfect for system-level operations

### Compiled Languages (5)
- **🦀 Rust** - Maximum performance and memory safety
- **⚡ C** - Ultimate performance and system-level access
- **⚡ C++** - High performance with modern features
- **☕ Java** - Enterprise-grade reliability and libraries
- **🐹 Go** - Fast compilation and excellent concurrency

### Declarative (1)
- **📄 YAML** - Simple, readable configuration-based templates

---

## ⚙️ How It Works

### 1. Template Discovery
CERT-X-GEN automatically discovers templates in the `templates/` directory based on file extensions.

### 2. Engine Selection
Each template is processed by the appropriate engine based on its file extension.

### 3. Execution
- **Interpreted languages**: Direct execution with environment variables
- **Compiled languages**: Compilation → caching → execution
- **YAML**: Native parsing and execution

### 4. Output Processing
All templates output JSON findings that are automatically converted to the unified `Finding` structure.

---

## 🔧 Engine Details

### Interpreted Language Engines

#### 🐍 Python Engine
```bash
# Requirements
python3 (or python)

# Libraries commonly used
requests, urllib, json, socket, ssl
```

**Best for:**
- HTTP-based scanning
- Data processing and analysis
- Rapid prototyping
- Integration with existing Python tools

**Example:**
```python
import requests
import json
import os

def main():
    target = os.getenv('CERT_X_GEN_TARGET_HOST')
    port = os.getenv('CERT_X_GEN_TARGET_PORT')
    
    try:
        response = requests.get(f"http://{target}:{port}/", timeout=10)
        if response.status_code == 200:
            finding = {
                "id": "http-service-detected",
                "name": "HTTP Service Detected",
                "severity": "info",
                "description": f"HTTP service responding on port {port}",
                "evidence": {"type": "http_response", "data": response.text[:100]}
            }
            print(json.dumps({"findings": [finding]}))
    except Exception as e:
        pass

if __name__ == "__main__":
    main()
```

#### 🟨 JavaScript Engine
```bash
# Requirements
node
```

**Best for:**
- Web application testing
- JSON processing
- Integration with Node.js ecosystem

**Example:**
```javascript
const http = require('http');
const https = require('https');

const target = process.env.CERT_X_GEN_TARGET_HOST;
const port = process.env.CERT_X_GEN_TARGET_PORT;

const options = {
    hostname: target,
    port: port,
    path: '/',
    method: 'GET',
    timeout: 10000
};

const req = http.request(options, (res) => {
    if (res.statusCode === 200) {
        const finding = {
            id: "http-service-detected",
            name: "HTTP Service Detected",
            severity: "info",
            description: `HTTP service responding on port ${port}`,
            evidence: { type: "http_response", data: "Service responding" }
        };
        console.log(JSON.stringify({ findings: [finding] }));
    }
});

req.on('error', () => {});
req.end();
```

#### 💎 Ruby Engine
```bash
# Requirements
ruby
```

**Best for:**
- Rapid development
- Text processing
- Integration with Ruby gems

**Example:**
```ruby
require 'net/http'
require 'json'
require 'uri'

target = ENV['CERT_X_GEN_TARGET_HOST']
port = ENV['CERT_X_GEN_TARGET_PORT']

begin
    uri = URI("http://#{target}:#{port}/")
    response = Net::HTTP.get_response(uri)
    
    if response.code == '200'
        finding = {
            id: "http-service-detected",
            name: "HTTP Service Detected",
            severity: "info",
            description: "HTTP service responding on port #{port}",
            evidence: { type: "http_response", data: response.body[0..100] }
        }
        puts JSON.generate({ findings: [finding] })
    end
rescue => e
    # Handle error silently
end
```

#### 🐪 Perl Engine
```bash
# Requirements
perl
```

**Best for:**
- Text processing
- System integration
- Legacy system compatibility

**Example:**
```perl
use LWP::UserAgent;
use JSON;
use strict;

my $target = $ENV{'CERT_X_GEN_TARGET_HOST'};
my $port = $ENV{'CERT_X_GEN_TARGET_PORT'};

my $ua = LWP::UserAgent->new(timeout => 10);
my $response = $ua->get("http://$target:$port/");

if ($response->is_success) {
    my $finding = {
        id => "http-service-detected",
        name => "HTTP Service Detected",
        severity => "info",
        description => "HTTP service responding on port $port",
        evidence => { type => "http_response", data => substr($response->content, 0, 100) }
    };
    print encode_json({ findings => [$finding] });
}
```

#### 🐘 PHP Engine
```bash
# Requirements
php
```

**Best for:**
- Web application testing
- Integration with PHP frameworks
- Quick HTTP requests

**Example:**
```php
<?php
$target = getenv('CERT_X_GEN_TARGET_HOST');
$port = getenv('CERT_X_GEN_TARGET_PORT');

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://$target:$port/");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode == 200) {
    $finding = [
        'id' => 'http-service-detected',
        'name' => 'HTTP Service Detected',
        'severity' => 'info',
        'description' => "HTTP service responding on port $port",
        'evidence' => ['type' => 'http_response', 'data' => substr($response, 0, 100)]
    ];
    echo json_encode(['findings' => [$finding]]);
}
?>
```

#### 🐚 Shell Engine
```bash
# Requirements
bash (or sh)
```

**Best for:**
- System-level operations
- Command execution
- Integration with system tools

**Example:**
```bash
#!/bin/bash

TARGET="$CERT_X_GEN_TARGET_HOST"
PORT="$CERT_X_GEN_TARGET_PORT"

# Test HTTP connection
if curl -s --connect-timeout 10 "http://$TARGET:$PORT/" > /dev/null 2>&1; then
    cat << EOF
{
  "findings": [
    {
      "id": "http-service-detected",
      "name": "HTTP Service Detected",
      "severity": "info",
      "description": "HTTP service responding on port $PORT",
      "evidence": {
        "type": "http_response",
        "data": "Service responding"
      }
    }
  ]
}
EOF
fi
```

### Compiled Language Engines

#### 🦀 Rust Engine
```bash
# Requirements
rustc, cargo
```

**Best for:**
- Maximum performance
- Memory safety
- Complex network operations

**Example:**
```rust
use std::env;
use std::process::Command;
use serde_json::{json, Value};

fn main() {
    let target = env::var("CERT_X_GEN_TARGET_HOST").unwrap_or_default();
    let port = env::var("CERT_X_GEN_TARGET_PORT").unwrap_or_default();
    
    // Your scanning logic here
    let finding = json!({
        "id": "rust-template-example",
        "name": "Rust Template Example",
        "severity": "info",
        "description": "Example Rust template",
        "evidence": {
            "type": "custom",
            "data": "Rust template executed successfully"
        }
    });
    
    println!("{}", json!({"findings": [finding]}));
}
```

#### ⚡ C Engine
```bash
# Requirements
gcc (or clang)
```

**Best for:**
- Ultimate performance
- System-level access
- Low-level network operations

**Example:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

int main() {
    const char* target = getenv("CERT_X_GEN_TARGET_HOST");
    const char* port = getenv("CERT_X_GEN_TARGET_PORT");
    
    // Your scanning logic here
    json_object* finding = json_object_new_object();
    json_object_object_add(finding, "id", json_object_new_string("c-template-example"));
    json_object_object_add(finding, "name", json_object_new_string("C Template Example"));
    json_object_object_add(finding, "severity", json_object_new_string("info"));
    json_object_object_add(finding, "description", json_object_new_string("Example C template"));
    
    json_object* evidence = json_object_new_object();
    json_object_object_add(evidence, "type", json_object_new_string("custom"));
    json_object_object_add(evidence, "data", json_object_new_string("C template executed successfully"));
    json_object_object_add(finding, "evidence", evidence);
    
    json_object* findings = json_object_new_array();
    json_object_array_add(findings, finding);
    
    json_object* result = json_object_new_object();
    json_object_object_add(result, "findings", findings);
    
    printf("%s\n", json_object_to_json_string(result));
    
    json_object_put(result);
    return 0;
}
```

#### ⚡ C++ Engine
```bash
# Requirements
g++ (or clang++)
```

**Best for:**
- High performance
- Modern C++ features
- Complex data structures

**Example:**
```cpp
#include <iostream>
#include <string>
#include <cstdlib>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

int main() {
    const char* target = std::getenv("CERT_X_GEN_TARGET_HOST");
    const char* port = std::getenv("CERT_X_GEN_TARGET_PORT");
    
    // Your scanning logic here
    nlohmann::json finding = {
        {"id", "cpp-template-example"},
        {"name", "C++ Template Example"},
        {"severity", "info"},
        {"description", "Example C++ template"},
        {"evidence", {
            {"type", "custom"},
            {"data", "C++ template executed successfully"}
        }}
    };
    
    nlohmann::json result = {
        {"findings", {finding}}
    };
    
    std::cout << result.dump() << std::endl;
    return 0;
}
```

#### ☕ Java Engine
```bash
# Requirements
javac, java
```

**Best for:**
- Enterprise applications
- Cross-platform compatibility
- Rich library ecosystem

**Example:**
```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

public class JavaTemplate {
    public static void main(String[] args) {
        String target = System.getenv("CERT_X_GEN_TARGET_HOST");
        String port = System.getenv("CERT_X_GEN_TARGET_PORT");
        
        // Your scanning logic here
        JsonObject finding = new JsonObject();
        finding.addProperty("id", "java-template-example");
        finding.addProperty("name", "Java Template Example");
        finding.addProperty("severity", "info");
        finding.addProperty("description", "Example Java template");
        
        JsonObject evidence = new JsonObject();
        evidence.addProperty("type", "custom");
        evidence.addProperty("data", "Java template executed successfully");
        finding.add("evidence", evidence);
        
        JsonArray findings = new JsonArray();
        findings.add(finding);
        
        JsonObject result = new JsonObject();
        result.add("findings", findings);
        
        System.out.println(new Gson().toJson(result));
    }
}
```

#### 🐹 Go Engine
```bash
# Requirements
go
```

**Best for:**
- Fast compilation
- Excellent concurrency
- Simple deployment

**Example:**
```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"
)

type Finding struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Severity    string `json:"severity"`
    Description string `json:"description"`
    Evidence    struct {
        Type string `json:"type"`
        Data string `json:"data"`
    } `json:"evidence"`
}

type Result struct {
    Findings []Finding `json:"findings"`
}

func main() {
    target := os.Getenv("CERT_X_GEN_TARGET_HOST")
    port := os.Getenv("CERT_X_GEN_TARGET_PORT")
    
    // Your scanning logic here
    finding := Finding{
        ID:          "go-template-example",
        Name:        "Go Template Example",
        Severity:    "info",
        Description: "Example Go template",
    }
    finding.Evidence.Type = "custom"
    finding.Evidence.Data = "Go template executed successfully"
    
    result := Result{
        Findings: []Finding{finding},
    }
    
    jsonData, _ := json.Marshal(result)
    fmt.Println(string(jsonData))
}
```

### Declarative Engine

#### 📄 YAML Engine
```bash
# Requirements
None (built-in)
```

**Best for:**
- Simple HTTP requests
- Configuration-based scanning
- Readable templates

**Example:**
```yaml
id: yaml-template-example
name: YAML Template Example
author: CERT-X-GEN Team
severity: info
description: Example YAML template
tags: [example, yaml]

http:
  - method: GET
    path: /
    matchers:
      - type: status
        status: [200]
        part: response
      - type: word
        words: ["<html>", "<body>"]
        part: body
        condition: and
```

---

## 📝 Writing Templates

### Template Structure

All templates should follow this basic structure:

1. **Metadata** - Template information (ID, name, author, severity)
2. **Environment Variables** - Read configuration from environment
3. **Scanning Logic** - Perform the actual security checks
4. **JSON Output** - Output findings in the required format

### Skeleton Templates

Use the provided skeleton templates as starting points:

```bash
# Copy skeleton for your preferred language
cp templates/skeleton/python-template-skeleton.py my-template.py
cp templates/skeleton/rust-template-skeleton.rs my-template.rs
cp templates/skeleton/c-template-skeleton.c my-template.c
# ... etc for all languages
```

### Template Metadata

Each template should include metadata:

```python
# Python example
TEMPLATE_ID = "my-custom-template"
TEMPLATE_NAME = "My Custom Template"
TEMPLATE_AUTHOR = "Your Name"
TEMPLATE_SEVERITY = "medium"
TEMPLATE_DESCRIPTION = "Description of what this template does"
TEMPLATE_TAGS = ["web", "injection", "custom"]
```

---

## 🔧 Environment Variables

Templates receive configuration via environment variables:

### Target Configuration
```bash
CERT_X_GEN_TARGET_HOST=example.com
CERT_X_GEN_TARGET_PORT=80
CERT_X_GEN_ADD_PORTS=8080,9090,3000
CERT_X_GEN_OVERRIDE_PORTS=80,443
```

### Template Information
```bash
CERT_X_GEN_TEMPLATE_ID=my-template
CERT_X_GEN_TEMPLATE_NAME="My Template"
CERT_X_GEN_TEMPLATE_AUTHOR="Author Name"
```

### Execution Context
```bash
CERT_X_GEN_MODE=scan
CERT_X_GEN_TIMEOUT=30
CERT_X_GEN_RETRY_COUNT=3
CERT_X_GEN_USER_AGENT="CERT-X-GEN/1.0"
```

---

## 🔍 Template Search

CERT-X-GEN includes a powerful search feature to discover templates:

### Basic Search
```bash
# Search for templates containing "redis"
cxg search --query "redis"

# Search by language
cxg search --language python

# Search by severity
cxg search --severity critical

# Search by tags
cxg search --tags "database,unauthenticated"
```

### Advanced Search
```bash
# Search with regex
cxg search --query "redis|mysql|postgres" --regex

# Search in template content
cxg search --query "curl" --content

# Multiple filters
cxg search --language c --severity high --tags "injection"

# Output formats
cxg search --query "redis" --format json
cxg search --query "redis" --format csv
cxg search --query "redis" --format table
```

### Search Integration
```bash
# Use search results in scanning
TEMPLATES=$(cxg search --query "redis" --ids-only | tr '\n' ',')
cxg scan --target example.com --templates "$TEMPLATES"
```

---

## 🎯 Best Practices

### Language Selection

**Choose the right language for your use case:**

- **Simple HTTP requests** → YAML or Python
- **Complex logic** → Python or JavaScript
- **Performance critical** → Rust, C, or Go
- **System integration** → Shell scripts
- **Rapid prototyping** → Python or Shell
- **Enterprise applications** → Java
- **Web application testing** → JavaScript or PHP
- **Text processing** → Perl or Ruby

### Template Development

1. **Start with skeletons** - Use provided skeleton templates
2. **Handle errors gracefully** - Always check for failures
3. **Output valid JSON** - Ensure proper JSON formatting
4. **Use environment variables** - Don't hardcode configuration
5. **Test thoroughly** - Verify your template works correctly

### Performance Tips

1. **Use appropriate timeouts** - Don't hang on slow responses
2. **Limit output size** - Don't output massive amounts of data
3. **Handle network errors** - Gracefully handle connection failures
4. **Use compiled languages** - For frequently executed templates
5. **Minimize dependencies** - Reduce compilation time

### Security Considerations

1. **Validate input** - Sanitize environment variables
2. **Avoid command injection** - Use safe system calls
3. **Handle sensitive data** - Don't log credentials
4. **Use secure defaults** - Implement secure configurations
5. **Test thoroughly** - Verify security of your templates

---

## 🚀 Getting Started

### 1. Choose Your Language
Pick the language that best fits your needs from the 12 supported options.

### 2. Copy a Skeleton
```bash
cp templates/skeleton/{language}-template-skeleton.{ext} my-template.{ext}
```

### 3. Implement Your Logic
Add your security scanning logic to the template.

### 4. Test Your Template
```bash
# Test with a specific target
cxg scan --target example.com --template my-template
```

### 5. Share Your Template
Add your template to the appropriate language directory in `templates/`.

---

## 📚 Additional Resources

- **[ENGINE_ARCHITECTURE.md](ENGINE_ARCHITECTURE.md)** - Detailed technical architecture
- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Complete usage guide
- **[TEMPLATE_REGISTRY.md](templates/TEMPLATE_REGISTRY.md)** - Template catalog
- **[Skeleton Templates](templates/skeleton/)** - Starting points for all languages

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**
3. **Add your template** to the appropriate language directory
4. **Test thoroughly**
5. **Submit a pull request**

### Template Guidelines

- Follow the skeleton template structure
- Include comprehensive metadata
- Handle errors gracefully
- Output valid JSON
- Add appropriate tags
- Include documentation

---

## 🎉 Conclusion

With 12 supported programming languages, CERT-X-GEN provides unprecedented flexibility in security scanning template development. Whether you prefer the simplicity of YAML, the power of Python, the performance of Rust, or the system integration of Shell scripts, there's a language that fits your needs.

The polyglot architecture ensures that you can leverage the strengths of each language while maintaining a unified interface and communication protocol. This makes CERT-X-GEN the most flexible and powerful security scanning framework available.

Happy scanning! 🚀