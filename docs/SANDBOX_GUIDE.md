# Sandbox Environment Guide

## Overview

CERT-X-GEN features a **unified sandboxed environment** that isolates all language runtimes and their dependencies from the host system. This provides:

- **Dependency Isolation**: Each language runtime has its own package directory
- **Security**: Templates execute in a controlled environment
- **Reproducibility**: Consistent package versions across installations
- **Cleanliness**: No pollution of system-wide package managers
- **Flexibility**: Easy to add, remove, or update packages

## Supported Languages

The sandbox supports **8 programming languages**:

| Language | Package Manager | Virtual Environment | Ready to Use |
|----------|----------------|---------------------|--------------|
| **Python** | pip | venv | ✅ |
| **JavaScript** | npm | node_modules | ✅ |
| **Ruby** | gem | GEM_HOME | ✅ |
| **Perl** | cpanm | local::lib | ✅ |
| **PHP** | composer | vendor | ✅ |
| **Rust** | cargo | CARGO_TARGET_DIR | ✅ |
| **Go** | go mod | GOPATH | ✅ |
| **Java** | maven/gradle | classpath | ✅ |

## Quick Start

### 1. Initialize Sandbox

Initialize all language environments:

```bash
cxg sandbox init
```

Initialize specific languages only:

```bash
cxg sandbox init --languages python,javascript,ruby
```

### 2. Check Status

View sandbox status and ready languages:

```bash
cxg sandbox status
```

Output:
```
Sandbox Status
═══════════════════════════════════════════════════════════════
Location: /Users/username/Library/Application Support/cert-x-gen/sandbox
Initialized: Yes

Language Runtimes:
  Python:     ✓
  JavaScript: ✓
  Ruby:       ✓
  Perl:       ✓
  PHP:        ✓
  Rust:       ✓
  Go:         ✓
  Java:       ✓
```

### 3. Install Packages

Install additional packages for any language:

```bash
# Python packages
cxg sandbox install python requests beautifulsoup4 selenium

# JavaScript/Node packages
cxg sandbox install javascript axios cheerio puppeteer

# Ruby gems
cxg sandbox install ruby rest-client nokogiri

# Perl modules
cxg sandbox install perl LWP::UserAgent JSON::XS

# PHP packages
cxg sandbox install php guzzlehttp/guzzle symfony/yaml
```

### 4. Access Sandbox Shell

Open a shell in the sandbox environment:

```bash
cxg sandbox shell
```

This opens a bash shell with all sandbox environment variables set.

### 5. Get Sandbox Location

```bash
cxg sandbox path
```

## Directory Structure

The sandbox creates the following directory structure:

```
~/.local/share/cert-x-gen/sandbox/     # Default location (Linux/macOS)
├── config.yaml                         # Sandbox configuration
├── bin/                                # Executable scripts
├── tmp/                                # Temporary files
├── logs/                               # Log files
│
├── python/
│   ├── venv/                          # Python virtual environment
│   │   ├── bin/python                 # Python executable
│   │   ├── lib/                       # Installed packages
│   │   └── ...
│   └── packages/                       # Additional packages
│
├── javascript/
│   ├── node_modules/                   # npm packages
│   ├── package.json                    # npm configuration
│   └── packages/                       # Additional packages
│
├── ruby/
│   ├── gems/                           # Ruby gems
│   └── packages/                       # Additional packages
│
├── perl/
│   ├── local/                          # Perl local::lib
│   └── packages/                       # Additional packages
│
├── php/
│   ├── vendor/                         # Composer packages
│   ├── composer.json                   # Composer configuration
│   └── packages/                       # Additional packages
│
├── rust/
│   ├── target/                         # Cargo build artifacts
│   └── packages/                       # Additional packages
│
├── go/
│   ├── pkg/                            # Go packages
│   └── packages/                       # Additional packages
│
└── java/
    ├── lib/                            # Java libraries
    └── packages/                       # Additional packages
```

## Pre-installed Packages

The sandbox automatically installs common security testing packages during initialization:

### Python
- `requests` - HTTP library
- `urllib3` - HTTP client
- `pyyaml` - YAML parser
- `jinja2` - Templating engine
- `beautifulsoup4` - HTML parser
- `lxml` - XML/HTML parser
- `cryptography` - Cryptographic recipes
- `python-nmap` - Nmap integration
- `scapy` - Packet manipulation

### JavaScript/Node.js
- `axios` - HTTP client
- `node-fetch` - Fetch API
- `cheerio` - HTML parser (jQuery-like)
- `jsdom` - DOM implementation
- `puppeteer-core` - Headless browser
- `ws` - WebSocket client
- `yaml` - YAML parser

### Ruby
- `rest-client` - HTTP client
- `nokogiri` - HTML/XML parser
- `json` - JSON parser
- `yaml` - YAML parser

### Perl
- `LWP::UserAgent` - HTTP client
- `HTTP::Request` - HTTP requests
- `JSON` - JSON parser
- `YAML` - YAML parser

### PHP
- `guzzlehttp/guzzle` - HTTP client
- `symfony/yaml` - YAML parser

## Environment Variables

The sandbox sets the following environment variables:

### Python
```bash
VIRTUAL_ENV=/path/to/sandbox/python/venv
PYTHONUSERBASE=/path/to/sandbox/python/packages
```

### JavaScript/Node
```bash
NODE_PATH=/path/to/sandbox/javascript/node_modules
```

### Ruby
```bash
GEM_HOME=/path/to/sandbox/ruby/gems
```

### Perl
```bash
PERL_LOCAL_LIB_ROOT=/path/to/sandbox/perl/local
```

### PHP
```bash
PHP_USER_INI=/path/to/sandbox/php
```

### Rust
```bash
CARGO_TARGET_DIR=/path/to/sandbox/rust/target
```

### Go
```bash
GOPATH=/path/to/sandbox/go
```

### Java
```bash
JAVA_HOME=/path/to/sandbox/java
```

## CLI Commands

### Initialize Sandbox

```bash
# Initialize all languages
cxg sandbox init

# Initialize specific languages
cxg sandbox init --languages python,javascript

# Force re-initialization
cxg sandbox init --force

# Use custom directory
cxg sandbox init --directory /custom/path
```

### Check Status

```bash
cxg sandbox status
```

### Install Packages

```bash
# Syntax: cxg sandbox install <language> <package1> [package2] [...]

# Python
cxg sandbox install python requests beautifulsoup4

# JavaScript
cxg sandbox install javascript axios cheerio

# Ruby
cxg sandbox install ruby nokogiri

# Perl
cxg sandbox install perl JSON::XS

# PHP
cxg sandbox install php guzzlehttp/guzzle
```

### Clean Sandbox

```bash
# Prompt for confirmation
cxg sandbox clean

# Force clean without confirmation
cxg sandbox clean --force

# Clean specific language only
cxg sandbox clean --language python --force
```

### Access Shell

```bash
# Open default shell (bash)
cxg sandbox shell

# Open specific shell
cxg sandbox shell --language python
```

### Get Path

```bash
cxg sandbox path
```

### Update Packages

```bash
# Update all languages
cxg sandbox update

# Update specific language
cxg sandbox update --language python
```

## Configuration

The sandbox configuration is stored in `<sandbox_root>/config.yaml`:

```yaml
root_dir: /Users/username/Library/Application Support/cert-x-gen/sandbox
enable_python: true
enable_javascript: true
enable_ruby: true
enable_perl: true
enable_php: true
enable_rust: true
enable_go: true
enable_java: true
auto_init: true
```

### Customization

You can customize the sandbox by editing the configuration file:

1. Get sandbox path:
   ```bash
   cxg sandbox path
   ```

2. Edit config file:
   ```bash
   vim $(cxg sandbox path)/config.yaml
   ```

3. Reinitialize:
   ```bash
   cxg sandbox init --force
   ```

## Usage in Templates

Templates automatically execute in the sandbox environment. No code changes required!

### Python Template Example

```python
"""
id: example-python-template
name: Example Python Template
severity: medium
"""

# All imports use sandboxed packages
import requests
from bs4 import BeautifulSoup

def execute(target, context):
    # Your code here
    response = requests.get(target.url())
    soup = BeautifulSoup(response.text, 'html.parser')
    
    findings = []
    # Detection logic...
    
    return findings
```

### JavaScript Template Example

```javascript
/**
 * id: example-javascript-template
 * name: Example JavaScript Template
 * severity: medium
 */

// All requires use sandboxed packages
const axios = require('axios');
const cheerio = require('cheerio');

async function execute(target, context) {
    const response = await axios.get(target.url());
    const $ = cheerio.load(response.data);
    
    const findings = [];
    // Detection logic...
    
    return findings;
}

module.exports = { execute };
```

## Advanced Features

### 1. Custom Package Installation

Install packages not in the default set:

```bash
# Python: ML libraries
cxg sandbox install python tensorflow scikit-learn

# JavaScript: Testing frameworks
cxg sandbox install javascript jest mocha chai

# Ruby: Rails
cxg sandbox install ruby rails

# Go: Testing tools
# (Go modules are installed automatically when templates are executed)
```

### 2. Package Version Management

Specify package versions:

```bash
# Python
cxg sandbox install python "requests==2.31.0" "beautifulsoup4>=4.12.0"

# JavaScript
cxg sandbox install javascript "axios@^1.6.0" "cheerio@~1.0.0"
```

### 3. Development Mode

For template development, you can work directly in the sandbox:

```bash
# Open sandbox shell
cxg sandbox shell

# Navigate to your templates directory
cd /path/to/templates

# Install dev dependencies
pip install ipython pytest  # For Python
npm install --save-dev jest  # For JavaScript

# Run/test your templates
python my_template.py
node my_template.js
```

### 4. Debugging

Enable debug logging for sandbox operations:

```bash
cxg -vvv sandbox init
cxg -vvv sandbox install python requests
```

## Troubleshooting

### Sandbox Not Initialized

```
Error: Sandbox not initialized. Run 'cxg sandbox init' first.
```

**Solution**: Initialize the sandbox:
```bash
cxg sandbox init
```

### Language Runtime Not Found

```
Warning: Python3 not found, skipping Python sandbox initialization
```

**Solution**: Install the missing language runtime:
```bash
# macOS
brew install python3 node ruby perl php go rust

# Ubuntu/Debian
sudo apt-get install python3 nodejs ruby perl php golang rust

# Fedora
sudo dnf install python3 nodejs ruby perl php golang rust
```

### Package Installation Failed

```
Warning: Some packages failed to install
```

**Solution**: Check the specific error message and:
1. Ensure the package name is correct
2. Check internet connectivity
3. Try installing manually in sandbox shell

### Permission Denied

```
Error: Permission denied: /path/to/sandbox
```

**Solution**: The sandbox directory should be in your user directory. If using a custom location, ensure you have write permissions:
```bash
cxg sandbox init --directory ~/my-sandbox
```

### Out of Disk Space

```
Error: No space left on device
```

**Solution**: Clean the sandbox to free up space:
```bash
cxg sandbox clean --force
```

## Best Practices

### 1. Initialize Early

Initialize the sandbox when first installing cert-x-gen:
```bash
cxg sandbox init
```

### 2. Keep Packages Minimal

Only install packages you actually need:
```bash
# Good: Install specific packages
cxg sandbox install python requests beautifulsoup4

# Avoid: Installing everything
# cxg sandbox install python `pip list | awk '{print $1}'`
```

### 3. Use Version Pins

Pin critical package versions in your templates:
```bash
cxg sandbox install python "requests==2.31.0"
```

### 4. Regular Updates

Update packages periodically:
```bash
cxg sandbox update
```

### 5. Clean Unused Languages

If you don't use certain languages, disable them:
```bash
cxg sandbox init --languages python,javascript
```

## Security Considerations

### Isolation

The sandbox provides **process-level isolation** but not complete system-level isolation. For maximum security:

1. **Run in containers**: Use Docker/Podman for additional isolation
2. **Limit permissions**: Run cxg as a non-privileged user
3. **Network isolation**: Use firewall rules or network namespaces
4. **Resource limits**: Use cgroups to limit CPU/memory usage

### Template Security

Templates execute with full sandbox access. Only use trusted templates:

1. **Review templates**: Check template code before execution
2. **Use official templates**: Prefer templates from trusted sources
3. **Sandbox untrusted templates**: Run in containers or VMs
4. **Monitor execution**: Watch for suspicious behavior

### Dependency Security

Keep dependencies updated:

```bash
# Update all packages
cxg sandbox update

# Or manually update critical packages
cxg sandbox install python --upgrade requests
```

## Performance Tips

### 1. Warm Up Sandbox

Initialize sandbox before scanning:
```bash
cxg sandbox init && cxg scan --target example.com
```

### 2. Parallel Installation

Install packages for multiple languages in parallel:
```bash
cxg sandbox install python requests & \
cxg sandbox install javascript axios & \
wait
```

### 3. Cache Management

The sandbox caches packages. Clean periodically:
```bash
cxg sandbox clean --force
cxg sandbox init
```

## FAQ

### Q: Where is the sandbox located?

**A**: By default:
- **Linux**: `~/.local/share/cert-x-gen/sandbox`
- **macOS**: `~/Library/Application Support/cert-x-gen/sandbox`
- **Windows**: `%APPDATA%\cert-x-gen\sandbox`

Get the exact path:
```bash
cxg sandbox path
```

### Q: Can I use my system packages?

**A**: No, the sandbox intentionally isolates from system packages for consistency and security. However, you can install any package in the sandbox.

### Q: How much disk space does the sandbox use?

**A**: Varies by languages enabled:
- **Minimal** (Python + JavaScript): ~500 MB
- **Full** (all languages): ~2-3 GB

### Q: Can I have multiple sandboxes?

**A**: Yes, use different directories:
```bash
cxg sandbox init --directory ~/sandbox1
cxg sandbox init --directory ~/sandbox2
```

### Q: How do I backup my sandbox?

**A**: Simply copy the sandbox directory:
```bash
cp -r $(cxg sandbox path) ~/sandbox-backup
```

### Q: Can I share sandboxes between users?

**A**: Not recommended. Each user should have their own sandbox for security and isolation.

## Related Documentation

- [Template Development Guide](TEMPLATE_GUIDE.md)
- [Engine Architecture](src/engine/README.md)
- [CLI Reference](CLI_REFERENCE.md)

## Support

For issues or questions:
- GitHub Issues: https://github.com/cert-x-gen/cert-x-gen/issues
- Documentation: https://docs.cert-x-gen.io
- Discord: https://discord.gg/cert-x-gen
