//! Command-line interface for CERT-X-GEN

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cert-x-gen",
    version,
    about = "Advanced Multi-Language Security Scanning Engine",
    long_about = "CERT-X-GEN is a next-generation security scanning engine that supports \
                  12 programming languages for template creation. Write security scanning \
                  templates in Python, JavaScript, Rust, Shell, YAML, C, C++, Java, Go, Ruby, \
                  Perl, or PHP - whatever works best for your use case!",
    after_help = "KEY FEATURES:
  🎯 12 Programming Languages: Python, JavaScript, Rust, C, C++, Java, Go, Ruby, Perl, PHP, Shell, YAML
  🔧 Flexible Port Configuration: Add or override ports per scan
  🔍 Powerful Template Search: Full-text search, regex, content search, multiple filters
  ⚡ High Performance: Parallel execution, compilation caching for compiled languages
  📊 Multiple Output Formats: JSON, CSV, SARIF, HTML, Markdown
  🔌 Extensible: Plugin system, custom templates in any supported language

EXAMPLES:
  # Basic scanning
  cert-x-gen scan --scope example.com
  cert-x-gen scan --scope https://api.example.com:8443 --ports 80,443,8080
  cert-x-gen scan --scope 192.168.1.0/24 --top-ports 1000

  # Bulk input
  cert-x-gen scan --scope @targets.txt
  cert-x-gen scan --scope file://scopes/internal.txt

  # Advanced scanning with filters
  cert-x-gen scan --scope example.com --template-language python,rust
  cert-x-gen scan --scope example.com --severity critical,high
  cert-x-gen scan --scope example.com --tags database,unauthenticated

  # Template search
  cert-x-gen search --query \"redis\"
  cert-x-gen search --language python --severity high
  cert-x-gen search --query \"injection\" --content --regex
  cert-x-gen search --tags \"database,unauthenticated\" --format json

  # Template management
  cert-x-gen template list
  cert-x-gen template list --language c --severity critical
  cert-x-gen template info redis-unauthenticated

  # Template search
  cert-x-gen search --query \"redis\"
  cert-x-gen search --language python --severity high
  cert-x-gen search --tags \"injection,sql\" --format json

  # Configuration
  cert-x-gen config generate --output config.yaml
  cert-x-gen scan --config config.yaml --scope example.com

  # Output formats
  cert-x-gen scan --scope example.com --output-format json,csv,sarif
  cert-x-gen scan --scope example.com --output results --output-format json

  # Performance tuning
  cert-x-gen scan --scope example.com --threads 20 --parallel-targets 100
  cert-x-gen scan --scope example.com --timeout 60s --retry 5

  # Stealth and safety
  cert-x-gen scan --scope example.com --stealth --rate-limit 10
  cert-x-gen scan --scope example.com --safe --passive

  For detailed help on any command, use: cert-x-gen <command> --help"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output (-v: info+warn, -vv: +trace, -vvv: +debug)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Configuration file path
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Auto-update templates before running (like Nuclei's behavior)
    #[arg(
        long,
        global = true,
        help = "Automatically update templates before running scan"
    )]
    pub auto_update_templates: bool,

    /// Disable automatic template update check (like Nuclei's -duc flag)
    #[arg(
        long,
        global = true,
        help = "Disable automatic template update check on startup"
    )]
    pub disable_update_check: bool,

    /// Update templates on every startup (aggressive mode)
    #[arg(
        long,
        global = true,
        conflicts_with = "disable_update_check",
        help = "Force template update on every startup (aggressive)"
    )]
    pub update_templates_on_startup: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a security scan
    Scan(ScanArgs),

    /// Manage templates
    Template(TemplateCommand),

    /// AI-powered template generation
    Ai(AiCommand),

    /// Search templates
    Search(SearchArgs),

    /// Run as API server
    Server(ServerArgs),

    /// Generate configuration file
    Config(ConfigCommand),

    /// Manage sandbox environment
    Sandbox(SandboxCommand),

    /// Display version information
    Version,
}

#[derive(Parser, Debug)]
#[command(
    about = "Run a security scan against targets using vulnerability detection templates",
    long_about = "Execute comprehensive security scans against one or more targets using the multi-language \
                  template engine. CERT-X-GEN supports scanning single targets, multiple targets, CIDR ranges, \
                  and domains with advanced filtering, performance tuning, and output customization.\n\n\
                  The scan command orchestrates template execution across targets, manages concurrency, \
                  filtered by language, severity, tags, and custom criteria to focus on specific \
                  vulnerability classes or compliance requirements.",
    after_help = "DETAILED USAGE GUIDE:

TARGET SPECIFICATION:
  Define scope once and let the engine figure out the rest.

  --scope <SCOPE>
    Smart selector that accepts:
      • Single host or URL (example.com, https://api.example.com:8443)
      • Comma-separated lists (example.com,test.com,192.168.1.1)
      • Files via @targets.txt or file://path/to/targets.txt (one entry per line, # for comments)
      • CIDR ranges (192.168.1.0/24, 10.0.0.0/8)
      • Domains and subdomains (example.com, api.example.com)
      • Mixed entries in a single invocation

    Legacy flags (--target, --targets, --target-file, --domain, --domains, --domain-file, --cidr) remain as aliases.
    The scanner automatically deduplicates and expands entries from files.

PORT SELECTION:
  Customize which ports to scan.

  --ports <PORT>
    Smart selector that adds ports to template defaults. Supports:
      • Single ports (8080)
      • Ranges (8000-8100)
      • Comma lists (80,443,8443)
      • Files via @ports.txt or file://ports.txt (one per line, # for comments)
      • Mixed entries in a single invocation
    Adds to template default ports; combine with --override-ports to replace defaults entirely.
    Example:
      cert-x-gen scan --scope example.com --ports 80,443,8000-8010,@extra-ports.txt
  
  --top-ports <N>
    Add the top N most common ports (based on curated frequency data).
    Example:
      cert-x-gen scan --scope example.com --top-ports 100
  
  --override-ports <PORTS>
    Replace template default ports entirely with your custom list (same formats as --ports).
    Example:
      cert-x-gen scan --scope example.com --override-ports 80,443

PROTOCOL SPECIFICATION:
  Define which protocols to use for scanning (http, https, tcp, udp, etc.).
  
  --protocol <PROTOCOL>
    Use a single protocol for all scans.
    Example:
      cert-x-gen scan --scope example.com --protocol https
  
  --protocols <PROTOCOLS>
    Test multiple protocols (comma-separated). Engine tries each protocol.
    Example:
      cert-x-gen scan --scope example.com --protocols http,https

TEMPLATE FILTERING:
  Control which vulnerability templates are executed. Filter by ID, language, severity, or tags.
  
  --templates <TEMPLATE>
    Smart selector that understands template IDs, filenames, or file paths. Supports:
      • Direct template IDs (redis-unauthenticated)
      • File names or paths (templates/network/redis.yaml)
      • Files containing template lists via @templates.txt or file://templates.txt (one per line, # for comments)
      • Mixed entries in a single invocation
    Legacy flags (--template, --template-file) remain as aliases.
    Examples:
      cert-x-gen scan --scope example.com --templates redis-unauthenticated
      cert-x-gen scan --scope example.com --templates redis-unauthenticated,templates/network/redis.yaml
      cert-x-gen scan --scope example.com --templates @compliance-templates.txt
  
  --template-dir <DIR>
    Use templates from a custom directory instead of the default location.
    Example:
      cert-x-gen scan --scope example.com --template-dir ./custom-templates
  
  --template-language <LANGUAGES>
    Filter templates by programming language. Useful for testing specific engine types.
    Available: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    Example:
      cert-x-gen scan --scope example.com --template-language python --template-language rust
  
  --severity <SEVERITIES>
    Filter by severity level. Run only critical/high severity checks for quick assessments.
    Available: critical, high, medium, low, info
    Example:
      cert-x-gen scan --scope example.com --severity critical,high
  
  --tags <TAGS>
    Filter templates by tags (comma-separated). Tags categorize vulnerabilities.
    Common tags: database, injection, xss, authentication, authorization, rce, lfi, ssrf
    Example:
      cert-x-gen scan --scope example.com --tags database,unauthenticated
  
  --exclude-templates <PATTERN>
    Exclude templates matching a pattern. Supports wildcards.
    Example:
      cert-x-gen scan --scope example.com --exclude-templates test-*,experimental-*

OUTPUT AND REPORTING:
  Customize how scan results are saved and displayed.
  
  --output <BASENAME>
    Set the output file basename. Extensions are added based on format.
    Default: scan-results
    Example:
      cert-x-gen scan --scope example.com --output my-scan
      # Creates: my-scan.json, my-scan.csv, etc.
  
  --output-format <FORMATS>
    Specify output formats (comma-separated). Multiple formats can be generated simultaneously.
    Available: json, csv, sarif, html, xml
    - json: Machine-readable, ideal for automation and APIs
    - csv: Spreadsheet-friendly, good for reporting and analysis
    - sarif: Static Analysis Results Interchange Format (for CI/CD integration)
    - html: Human-readable report with visualizations
    - xml: Structured format for enterprise tools
    Example:
      cert-x-gen scan --scope example.com --output-format json,html,sarif
  
  --stream
    Enable real-time streaming output. Results are displayed as they're found.
    Useful for long-running scans where you want immediate feedback.
    Example:
      cert-x-gen scan --scope example.com --stream
  
  --quiet
    Suppress non-essential output. Only show critical information and errors.
    Ideal for scripting and automation where you want minimal noise.
    Example:
      cert-x-gen scan --scope example.com --quiet --output-format json

PERFORMANCE AND CONCURRENCY:
  Tune scan performance based on your resources and target infrastructure.
  
  --threads <N>
    Number of worker threads for parallel execution. Higher = faster but more resource-intensive.
    Default: Number of CPU cores
    Recommendation: Start with default, increase if targets can handle load
    Example:
      cert-x-gen scan --scope example.com --threads 20
  
  --parallel-targets <N>
    How many targets to scan simultaneously. Higher = faster but may trigger rate limits.
    Default: 50
    Recommendation: Lower for production systems (10-25), higher for internal scans (50-100)
    Example:
      cert-x-gen scan --scope example.com,test.com --parallel-targets 10
  
  --parallel-templates <N>
    How many templates to run concurrently per target. Balances speed vs. target load.
    Default: 10
    Recommendation: Lower for fragile targets (5), higher for robust systems (20)
    Example:
      cert-x-gen scan --scope example.com --parallel-templates 5

TIMEOUTS AND RETRIES:
  Configure how the scanner handles slow responses and failures.
  
  --timeout <DURATION>
    Maximum time to wait for a response. Supports: s (seconds), m (minutes), h (hours)
    Default: 30s
    Recommendation: Increase for slow networks or complex checks
    Example:
      cert-x-gen scan --scope example.com --timeout 60s
      cert-x-gen scan --scope example.com --timeout 2m
  
  --retry <N>
    Number of retry attempts for failed requests. Helps with transient network issues.
    Default: 1
    Recommendation: Increase for unreliable networks, decrease for fast scans
    Example:
      cert-x-gen scan --scope example.com --retry 5
  
  --rate-limit <N>
    Maximum requests per second. Prevents overwhelming targets and triggering WAF/IPS.
    Default: None (unlimited)
    Recommendation: Use 10-50 for production, 100+ for internal testing
    Example:
      cert-x-gen scan --scope example.com --rate-limit 10

SCANNING MODES:
  Different modes for various scanning scenarios and requirements.
  
  --aggressive
    Enable aggressive scanning mode. Uses more intrusive checks and higher concurrency.
    WARNING: May trigger security alerts or cause service disruption.
    Use only with explicit permission on systems you control.
    Example:
      cert-x-gen scan --scope test-env.internal --aggressive
  
  --stealth
    Enable stealth mode. Reduces scan footprint, randomizes timing, and mimics normal traffic.
    Slower but less likely to trigger detection systems (IDS/IPS/WAF).
    Automatically reduces concurrency and adds random delays.
    Example:
      cert-x-gen scan --scope example.com --stealth
  
  --safe
    Safe mode - excludes potentially harmful checks (DoS, resource exhaustion, etc.).
    Recommended for production systems where availability is critical.
    Example:
      cert-x-gen scan --scope production.example.com --safe
  
  --passive
    Passive mode - no active probing. Only analyzes responses from normal requests.
    Safest option but limited detection capabilities. Good for initial reconnaissance.
    Example:
      cert-x-gen scan --scope example.com --passive

NETWORK CONFIGURATION:
  Configure network-level settings for scanning through proxies, with custom headers, etc.
  
  --proxy <URL>
    Route all traffic through a proxy. Supports HTTP, HTTPS, and SOCKS5 proxies.
    Useful for scanning from different geographic locations or through corporate proxies.
    Examples:
      cert-x-gen scan --scope example.com --proxy http://proxy.corp.com:8080
      cert-x-gen scan --scope example.com --proxy socks5://127.0.0.1:1080
  
  --user-agent <STRING>
    Custom User-Agent header. Useful for mimicking specific browsers or tools.
    Default: cert-x-gen/<version>
    Example:
      cert-x-gen scan --scope example.com --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  
  --header <KEY:VALUE>
    Add custom HTTP headers. Can be specified multiple times for multiple headers.
    Useful for authentication, API keys, or custom application headers.
    Examples:
      cert-x-gen scan --scope api.example.com --header 'Authorization: Bearer token123'
      cert-x-gen scan --scope example.com --header 'X-API-Key: abc' --header 'X-Custom: value'
  
  --cookie <KEY=VALUE>
    Add cookies to requests. Can be specified multiple times. Useful for authenticated scans.
    Example:
      cert-x-gen scan --scope example.com --cookie 'session=abc123' --cookie 'user=admin'
  
  --follow-redirects
    Follow HTTP redirects automatically. Useful for discovering redirect chains.
    Default: Enabled
    Example:
      cert-x-gen scan --scope example.com --follow-redirects --max-redirects 10
  
  --max-redirects <N>
    Maximum number of redirects to follow. Prevents infinite redirect loops.
    Default: 5
    Example:
      cert-x-gen scan --scope example.com --max-redirects 3

ADVANCED FEATURES:
  Advanced capabilities for complex scanning scenarios.
  
  --resume <SCAN-ID>
    Resume a previously interrupted scan from where it left off.
    Scan state is automatically saved, allowing recovery from crashes or interruptions.
    Example:
      cert-x-gen scan --scope example.com --resume a1b2c3d4-e5f6-7890-abcd-ef1234567890
  
  --distributed
    Enable distributed scanning mode. Coordinates with other scanner instances.
    Allows horizontal scaling across multiple machines for massive scans.
    Example:
      cert-x-gen scan --scope @10000-targets.txt --distributed --coordinator http://coordinator:8080
  
  --coordinator <URL>
    URL of the distributed scan coordinator. Required when using --distributed.
    The coordinator manages work distribution and result aggregation.
    Example:
      cert-x-gen scan --scope example.com --distributed --coordinator http://192.168.1.100:8080
  
  --worker-id <ID>
    Unique identifier for this worker in distributed mode. Auto-generated if not specified.
    Example:
      cert-x-gen scan --scope @targets.txt --distributed --coordinator http://coordinator:8080 --worker-id scanner-01

CONFIGURATION FILES:
  Use configuration files for complex setups and reusable scan profiles.
  
  --config <FILE>
    Load settings from a configuration file (YAML, TOML, or JSON).
    CLI arguments override config file settings.
    Example:
      cert-x-gen scan --config production-scan.yaml --scope example.com
  
  --profile <NAME>
    Use a named configuration profile from your config file.
    Profiles allow quick switching between different scanning scenarios.
    Example:
      cert-x-gen scan --profile production --scope example.com

COMMON SCANNING SCENARIOS:

1. Quick Vulnerability Assessment (Fast, High-Severity Only):
   cert-x-gen scan --scope example.com --severity critical,high --threads 20

2. Comprehensive Security Audit (All Templates, All Severities):
   cert-x-gen scan --scope example.com --output-format json,html,sarif

3. Stealth Penetration Test (Low Detection Risk):
   cert-x-gen scan --scope example.com --stealth --rate-limit 5 --timeout 60s

4. Production System Scan (Safe, Non-Disruptive):
   cert-x-gen scan --scope production.example.com --safe --parallel-templates 3 --rate-limit 10

5. Database Security Scan (Specific Vulnerability Class):
   cert-x-gen scan --scope db.example.com --tags database,injection --severity high,critical

6. Authenticated Web Application Scan:
   cert-x-gen scan --scope app.example.com --cookie 'session=xyz' --header 'Authorization: Bearer token'

7. Large-Scale Network Scan (Multiple Targets):
   cert-x-gen scan --scope @targets.txt --parallel-targets 100 --output-format csv,json

8. API Security Testing:
   cert-x-gen scan --scope api.example.com --template-language python --tags api,authentication

9. Compliance Scan (OWASP Top 10):
   cert-x-gen scan --scope example.com --templates @owasp-top10.txt --output-format sarif

10. Internal Network Reconnaissance:
    cert-x-gen scan --scope 10.0.0.0/24 --passive --top-ports 100 --quiet

For more information, visit: https://cert-x-gen.io/docs"
)]
pub struct ScanArgs {
    // Target specification
    /// Unified scope definition (IP, domain, URL, lists, CIDR, files)
    #[arg(
        long = "scope",
        short = 's',
        short_alias = 't',
        aliases = [
            "target",
            "targets",
            "target-file",
            "domain",
            "domains",
            "domain-file",
            "cidr"
        ],
        value_name = "SCOPE",
        value_delimiter = ',',
        help = "Smart target selector. Accepts single host, comma lists, files (@file.txt), CIDR blocks (192.168.1.0/24), domains, URLs, or mixed entries"
    )]
    pub scope: Vec<String>,

    // Port specification
    /// Smart port selector that adds to template defaults
    #[arg(
        long = "ports",
        short = 'p',
        aliases = ["port", "port-file", "add-ports"],
        value_name = "PORT",
        value_delimiter = ',',
        help = "Smart port selector. Accepts single ports, ranges (80-90), comma lists, files (@ports.txt), or mixed entries. Adds to template defaults"
    )]
    pub ports: Vec<String>,

    /// Scan top N most common ports (based on frequency data)
    #[arg(long, help = "Scan most common ports. Example: --top-ports 1000")]
    pub top_ports: Option<u16>,

    /// Override template default ports completely (comma-separated)
    #[arg(
        long,
        help = "Replace template ports entirely. Use for complete control over port selection"
    )]
    pub override_ports: Option<String>,

    // Protocol specification
    /// Protocol to use for scanning
    #[arg(long, help = "Specify protocol: http, https, tcp, udp, etc.")]
    pub protocol: Option<String>,

    /// Multiple protocols to test (comma-separated)
    #[arg(long, help = "Test multiple protocols. Example: http,https")]
    pub protocols: Option<String>,

    // Template selection
    /// Smart template selector (IDs, file paths, or @file)
    #[arg(
        long = "templates",
        value_name = "TEMPLATE",
        value_delimiter = ',',
        aliases = ["template", "template-file"],
        help = "Smart template selector. Accepts template IDs, file names/paths, or @file references (one per line). Supports mixed entries"
    )]
    pub templates: Vec<String>,

    /// Custom template directory path
    #[arg(
        long,
        help = "Use templates from custom directory instead of default location"
    )]
    pub template_dir: Option<PathBuf>,

    /// Filter by vulnerability tags (comma-separated)
    #[arg(
        long,
        help = "Filter by tags. Common: database,injection,xss,rce,lfi,ssrf,auth"
    )]
    pub tags: Option<String>,

    /// Filter by severity level (critical, high, medium, low, info)
    #[arg(
        long,
        value_enum,
        help = "Filter by severity. Example: critical,high for quick assessment"
    )]
    pub severity: Option<Vec<SeverityArg>>,

    /// Exclude templates matching pattern (supports wildcards)
    #[arg(long, help = "Exclude templates. Example: test-*,experimental-*")]
    pub exclude_templates: Option<String>,

    /// Filter templates by programming language
    #[arg(
        long,
        value_enum,
        value_name = "LANG",
        help = "Filter by language (e.g., python,rust,c)"
    )]
    pub template_language: Option<Vec<LanguageArg>>,

    // Execution options
    /// Number of worker threads (default: CPU cores)
    ///
    /// Note: In async/await context, this is informational and doesn't directly control
    /// thread count. The actual concurrency is controlled by --parallel-targets and
    /// --parallel-templates. This option is kept for compatibility and may be used
    /// for future thread pool configuration.
    #[arg(long, default_value_t = num_cpus::get(), help = "Worker threads for parallel execution. Higher = faster but more CPU usage. Note: In async context, concurrency is controlled by --parallel-targets and --parallel-templates")]
    pub threads: usize,

    /// Number of targets to scan simultaneously
    #[arg(
        long,
        default_value_t = 50,
        help = "Concurrent target scans. Lower for production (10-25), higher for internal (50-100)"
    )]
    pub parallel_targets: usize,

    /// Number of templates to run concurrently per target
    #[arg(
        long,
        default_value_t = 10,
        help = "Concurrent templates per target. Balance between speed and target load"
    )]
    pub parallel_templates: usize,

    /// Timeout duration (supports: s=seconds, m=minutes, h=hours)
    #[arg(
        long,
        default_value = "30s",
        help = "Max wait time for responses. Examples: 30s, 2m, 1h. Increase for slow networks"
    )]
    pub timeout: String,

    /// Number of retry attempts for failed requests
    #[arg(
        long,
        default_value_t = 1,
        help = "Retry attempts for transient failures. Higher for unreliable networks"
    )]
    pub retry: u32,

    /// Rate limit in requests per second (prevents overwhelming targets)
    #[arg(
        long,
        help = "Max requests/sec. Use 10-50 for production, 100+ for internal. Prevents WAF/IPS triggers"
    )]
    pub rate_limit: Option<u32>,

    // Scanning modes
    /// Enable aggressive mode (WARNING: intrusive, may cause disruption)
    #[arg(
        long,
        help = "Aggressive scanning with intrusive checks. Use only with permission on controlled systems"
    )]
    pub aggressive: bool,

    /// Enable stealth mode (slower, harder to detect)
    #[arg(
        long,
        help = "Stealth mode: randomized timing, reduced footprint. Evades IDS/IPS/WAF detection"
    )]
    pub stealth: bool,

    /// Passive mode (no active probing, safest option)
    #[arg(
        long,
        help = "Passive scanning: analyze responses only, no active probes. Limited detection but safest"
    )]
    pub passive: bool,

    /// Safe mode (excludes potentially harmful checks like DoS)
    #[arg(
        long,
        help = "Safe mode: no DoS or resource exhaustion checks. Recommended for production systems"
    )]
    pub safe: bool,

    // Network options
    /// Proxy URL (supports HTTP, HTTPS, SOCKS5)
    #[arg(
        long,
        help = "Route traffic through proxy. Examples: http://proxy:8080, socks5://127.0.0.1:1080"
    )]
    pub proxy: Option<String>,

    /// Custom User-Agent header (default: cert-x-gen/<version>)
    #[arg(
        long,
        help = "Custom User-Agent for mimicking browsers/tools. Example: \"Mozilla/5.0...\""
    )]
    pub user_agent: Option<String>,

    /// Custom HTTP headers (key:value, repeatable for multiple headers)
    #[arg(
        long,
        help = "Add custom headers. Example: \"Authorization: Bearer token\". Use multiple times for multiple headers"
    )]
    pub header: Option<Vec<String>>,

    /// Cookies (key=value, repeatable for multiple cookies)
    #[arg(
        long,
        help = "Add cookies for authenticated scans. Example: \"session=abc123\". Use multiple times"
    )]
    pub cookie: Option<Vec<String>>,

    /// Follow HTTP redirects automatically (enabled by default)
    #[arg(
        long,
        help = "Follow HTTP redirects. Useful for discovering redirect chains and final destinations"
    )]
    pub follow_redirects: bool,

    /// Maximum number of redirects to follow (prevents infinite loops)
    #[arg(
        long,
        default_value_t = 5,
        help = "Max redirect hops. Prevents infinite redirect loops"
    )]
    pub max_redirects: usize,

    // Output options
    /// Output file basename (extensions added automatically)
    #[arg(
        short,
        long,
        default_value = "scan-results",
        help = "Output basename. Creates: <basename>.json, <basename>.csv, etc."
    )]
    pub output: String,

    /// Output formats (comma-separated: json,html,sarif,csv,xml)
    #[arg(
        long,
        default_value = "json",
        help = "Output formats. json=automation, csv=spreadsheet, sarif=CI/CD, html=visual, xml=enterprise"
    )]
    pub output_format: String,

    /// Enable real-time streaming output (results shown as found)
    #[arg(
        long,
        help = "Stream results in real-time. Useful for long scans where you want immediate feedback"
    )]
    pub stream: bool,

    /// Quiet mode (suppress non-essential output)
    #[arg(
        short,
        long,
        help = "Minimal output: only critical info and errors. Ideal for scripting and automation"
    )]
    pub quiet: bool,

    // Advanced options
    /// Resume previously interrupted scan by scan ID
    #[arg(
        long,
        help = "Resume scan from where it stopped. Scan state is auto-saved for recovery from crashes"
    )]
    pub resume: Option<String>,

    /// Enable distributed scanning mode (horizontal scaling)
    #[arg(
        long,
        help = "Distributed mode: coordinate with other scanners for massive scans across multiple machines"
    )]
    pub distributed: bool,

    /// Coordinator URL for distributed scanning (required with --distributed)
    #[arg(
        long,
        help = "Coordinator manages work distribution. Example: http://coordinator:8080"
    )]
    pub coordinator: Option<String>,

    /// Unique worker ID for distributed scanning (auto-generated if not set)
    #[arg(
        long,
        help = "Worker identifier in distributed mode. Example: scanner-01, worker-east-1"
    )]
    pub worker_id: Option<String>,

    /// Configuration profile name from config file
    #[arg(
        long,
        help = "Use named profile from config. Allows quick switching between scan scenarios"
    )]
    pub profile: Option<String>,
}

#[derive(Parser, Debug)]
#[command(
    about = "Manage security scanning templates",
    long_about = "List, validate, update, create, and manage security scanning templates. \
                  Templates define vulnerability detection logic in 12 supported languages.",
    after_help = "TEMPLATE LANGUAGES:
  Interpreted: Python, JavaScript, Ruby, Perl, PHP, Shell
  Compiled: Rust, C, C++, Java, Go
  Declarative: YAML

EXAMPLES:
  # List all templates
  cert-x-gen template list

  # Filter templates
  cert-x-gen template list --language python
  cert-x-gen template list --language c --severity critical
  cert-x-gen template list --tags database,unauthenticated

  # Get template information
  cert-x-gen template info redis-unauthenticated
  cert-x-gen template info sql-injection-detection

  # Validate templates
  cert-x-gen template validate templates/
  cert-x-gen template validate templates/python/ --recursive
  cert-x-gen template validate templates/c/redis-check.c

  # Update templates from repository
  cert-x-gen template update
  cert-x-gen template update --force

  # Create new template from skeleton
  cert-x-gen template create --id my-check --language python --name \"My Check\"
  cert-x-gen template create --id redis-test --language c --output ./templates/

  # Test a template
  cert-x-gen template test --template templates/c/redis.c --target 192.168.1.100
  cert-x-gen template test --template redis-unauthenticated --target localhost --debug"
)]
pub struct TemplateCommand {
    #[command(subcommand)]
    pub action: TemplateAction,
}

#[derive(Subcommand, Debug)]
pub enum TemplateAction {
    /// List available templates
    List {
        /// Filter by programming language
        #[arg(long, value_enum, value_name = "LANG")]
        language: Option<LanguageArg>,

        /// Filter by severity level
        #[arg(long, value_enum, value_name = "LEVEL")]
        severity: Option<SeverityArg>,

        /// Filter by tags (comma-separated)
        #[arg(long, value_name = "TAG,TAG,...")]
        tags: Option<String>,
    },

    /// Validate template files
    Validate {
        /// Template file or directory to validate
        path: PathBuf,

        /// Recursively validate all templates in subdirectories
        #[arg(short, long)]
        recursive: bool,

        /// Output validation results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Update templates from remote repository
    Update {
        /// Force update (overwrite local changes)
        #[arg(short, long)]
        force: bool,
    },

    /// Show detailed information about a template
    Info {
        /// Template ID to show information for
        template_id: String,
    },

    /// Create a new template from skeleton/scaffold
    Create {
        /// Unique template ID
        #[arg(long, value_name = "ID")]
        id: String,

        /// Programming language for the template
        #[arg(long, value_enum, value_name = "LANG")]
        language: LanguageArg,

        /// Human-readable template name
        #[arg(long, value_name = "NAME")]
        name: String,

        /// Output directory for the new template
        #[arg(short, long, default_value = ".", value_name = "DIR")]
        output: PathBuf,
    },

    /// Test a template against a target
    Test {
        /// Path to template file or template ID
        template: PathBuf,

        /// Target to test against
        #[arg(long, value_name = "HOST")]
        target: String,

        /// Enable debug output
        #[arg(long)]
        debug: bool,
    },
}

#[derive(Parser, Debug)]
#[command(
    about = "Search and discover security scanning templates",
    long_about = "Search through available templates using text queries, filters, and advanced options. \
                  Supports full-text search, regex patterns, content search, and multiple output formats.",
    after_help = "SEARCH CAPABILITIES:
  • Full-text search in names, descriptions, and tags
  • Regex pattern matching
  • Content search (searches inside template code)
  • Multiple filters (language, severity, tags, author, CWE)
  • Multiple output formats (table, json, yaml, csv, list, detailed)
  • Sorting and pagination

EXAMPLES:
  # Basic text search
  cert-x-gen search --query \"redis\"
  cert-x-gen search --query \"sql injection\"
  cert-x-gen search --query \"unauthenticated access\"

  # Language-specific search
  cert-x-gen search --language python
  cert-x-gen search --language c --query \"buffer overflow\"
  cert-x-gen search --language rust --severity critical

  # Severity filtering
  cert-x-gen search --severity critical
  cert-x-gen search --severity high --language python
  cert-x-gen search --severity critical,high

  # Tag-based search
  cert-x-gen search --tags database
  cert-x-gen search --tags \"database,unauthenticated\"
  cert-x-gen search --tags injection --language c

  # Author and CWE filtering
  cert-x-gen search --author \"CERT-X-GEN\"
  cert-x-gen search --cwe \"CWE-89\"
  cert-x-gen search --cwe \"CWE-306\" --severity critical

  # Advanced search with regex
  cert-x-gen search --query \"redis|mysql|postgres\" --regex
  cert-x-gen search --query \"SQL.*injection\" --regex --case-sensitive

  # Content search (slower but comprehensive)
  cert-x-gen search --query \"curl\" --content
  cert-x-gen search --query \"SELECT.*FROM\" --content --regex

  # Output formats
  cert-x-gen search --query \"redis\" --format table        # Default
  cert-x-gen search --query \"redis\" --format json
  cert-x-gen search --query \"redis\" --format csv
  cert-x-gen search --query \"redis\" --format yaml
  cert-x-gen search --query \"redis\" --format detailed

  # Sorting and limiting
  cert-x-gen search --query \"injection\" --sort name
  cert-x-gen search --query \"injection\" --sort severity --reverse
  cert-x-gen search --query \"injection\" --limit 10

  # Get only template IDs (useful for piping to scan)
  cert-x-gen search --query \"redis\" --ids-only
  TEMPLATES=$(cert-x-gen search --query \"redis\" --ids-only | tr '\\n' ',')
  cert-x-gen scan --target example.com --templates \"$TEMPLATES\"

  # Show statistics
  cert-x-gen search --query \"redis\" --stats
  cert-x-gen search --language python --stats

  # Save results to file
  cert-x-gen search --query \"redis\" --output results.json --format json
  cert-x-gen search --language c --output c-templates.csv --format csv

  # Complex queries
  cert-x-gen search --language python --severity high --tags database --format json
  cert-x-gen search --query \"authentication\" --content --case-sensitive --regex
  cert-x-gen search --author \"CERT-X-GEN\" --severity critical --sort date --reverse"
)]
pub struct SearchArgs {
    /// Search query (searches in name, description, tags, and optionally content)
    #[arg(short, long, value_name = "TEXT")]
    pub query: Option<String>,

    /// Filter by programming language
    #[arg(long, value_enum, value_name = "LANG")]
    pub language: Option<LanguageArg>,

    /// Filter by severity level
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub severity: Option<SeverityArg>,

    /// Filter by tags (comma-separated)
    #[arg(long, value_name = "TAG,TAG,...")]
    pub tags: Option<String>,

    /// Filter by template author
    #[arg(long, value_name = "NAME")]
    pub author: Option<String>,

    /// Filter by CWE ID (e.g., CWE-89)
    #[arg(long, value_name = "CWE-ID")]
    pub cwe: Option<String>,

    /// Search in template content/code (slower but more comprehensive)
    #[arg(long)]
    pub content: bool,

    /// Use case-sensitive search
    #[arg(long)]
    pub case_sensitive: bool,

    /// Treat query as regex pattern
    #[arg(long)]
    pub regex: bool,

    /// Maximum number of results to return
    #[arg(long, default_value_t = 50, value_name = "N")]
    pub limit: usize,

    /// Output format for search results
    #[arg(long, default_value = "table", value_enum, value_name = "FORMAT")]
    pub format: SearchFormat,

    /// Output file for results (default: print to stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Show detailed information for each result
    #[arg(long)]
    pub detailed: bool,

    /// Sort results by field
    #[arg(long, default_value = "relevance", value_enum, value_name = "FIELD")]
    pub sort: SearchSort,

    /// Reverse sort order
    #[arg(long)]
    pub reverse: bool,

    /// Show only template IDs (useful for piping to other commands)
    #[arg(long)]
    pub ids_only: bool,

    /// Show search statistics and summary
    #[arg(long)]
    pub stats: bool,
}

#[derive(Parser, Debug)]
#[command(
    about = "Run CERT-X-GEN as an API server",
    long_about = "Start CERT-X-GEN as a REST API server for remote scanning capabilities, \
                  web-based management, and integration with other security tools.",
    after_help = "EXAMPLES:
  # Start server with defaults
  cert-x-gen server

  # Custom port and bind address
  cert-x-gen server --port 8080
  cert-x-gen server --bind 0.0.0.0 --port 3000

  # Enable TLS/HTTPS
  cert-x-gen server --tls --tls-cert server.crt --tls-key server.key

  # With authentication
  cert-x-gen server --auth-token my-secret-token"
)]
pub struct ServerArgs {
    /// Server port
    #[arg(short, long, default_value_t = 8080, value_name = "PORT")]
    pub port: u16,

    /// Bind address (use 0.0.0.0 to listen on all interfaces)
    #[arg(short, long, default_value = "127.0.0.1", value_name = "ADDRESS")]
    pub bind: String,

    /// Authentication token for API requests
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// Enable TLS/HTTPS
    #[arg(long)]
    pub tls: bool,

    /// TLS certificate file path
    #[arg(long, value_name = "FILE", requires = "tls")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file path
    #[arg(long, value_name = "FILE", requires = "tls")]
    pub tls_key: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(
    about = "Generate and manage configuration files",
    long_about = "Create, validate, and manage CERT-X-GEN configuration files for reusable \
                  scan configurations and automation.",
    after_help = "EXAMPLES:
  # Generate default configuration
  cert-x-gen config generate
  cert-x-gen config generate --output config.yaml
  cert-x-gen config generate --format toml --output config.toml

  # Validate configuration
  cert-x-gen config validate config.yaml
  cert-x-gen config validate production.toml

  # Show current/default configuration
  cert-x-gen config show"
)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Generate a default configuration file
    Generate {
        /// Output file path
        #[arg(short, long, default_value = "cert-x-gen.yaml", value_name = "FILE")]
        output: PathBuf,

        /// Configuration format
        #[arg(short, long, value_enum, default_value = "yaml", value_name = "FORMAT")]
        format: ConfigFormat,
    },

    /// Validate a configuration file
    Validate {
        /// Configuration file to validate
        config: PathBuf,
    },

    /// Show current/default configuration
    Show,
}

/// Sandbox management commands
#[derive(Parser, Debug)]
#[command(
    about = "Manage sandboxed language environments",
    long_about = "Initialize, manage, and configure isolated runtime environments for all supported \
                  programming languages. The sandbox provides dependency isolation and security for \
                  template execution across Python, JavaScript, Ruby, Perl, PHP, Rust, Go, and Java.",
    after_help = "EXAMPLES:
  # Initialize sandbox with all languages
  cert-x-gen sandbox init

  # Initialize specific languages only
  cert-x-gen sandbox init --languages python,javascript,ruby

  # Check sandbox status
  cert-x-gen sandbox status

  # Install additional packages
  cert-x-gen sandbox install python requests beautifulsoup4
  cert-x-gen sandbox install javascript axios cheerio

  # Clean sandbox environment
  cert-x-gen sandbox clean

  # Access sandbox shell
  cert-x-gen sandbox shell

  # Show sandbox location
  cert-x-gen sandbox path"
)]
pub struct SandboxCommand {
    #[command(subcommand)]
    pub action: SandboxAction,
}

/// Sandbox environment management
///
/// CERT-X-GEN supports two types of sandboxes:
///
/// 1. Docker Sandbox (RECOMMENDED - True Isolation):
///    - Complete OS-level isolation using Docker containers
///    - Fresh Python, Ruby, Node, Go, Java, etc. inside container
///    - Named environments (dev, test, prod)
///    - Auto-enter on CLI start
///    - Access to local network and files
///    - Commands: create, enter, delete, set-default, info
///
/// 2. Package Sandbox (Legacy - Package-Level Isolation):
///    - Python venv, npm node_modules, gem isolation
///    - Uses host system's language runtimes
///    - Simple directory-based isolation
///    - Commands: init, status, install, clean
///
/// Use 'cert-x-gen sandbox info' to check Docker availability.
/// Use 'cert-x-gen sandbox create <name>' to create a Docker sandbox.
#[derive(Debug, Clone, Subcommand)]
pub enum SandboxAction {
    /// Initialize package-level sandbox (legacy mode)
    ///
    /// Creates isolated package directories for Python (venv), JavaScript (node_modules),
    /// Ruby (gems), etc. This mode uses your host system's language runtimes.
    ///
    /// Note: This is a lightweight alternative to Docker sandboxes. For true isolation,
    /// use 'cert-x-gen sandbox create <name>' to create a Docker-based sandbox.
    ///
    /// The init command is smart:
    /// - First run: Sets up all language environments and installs packages
    /// - Subsequent runs: Only adds new languages or packages (skips existing)
    /// - Use --force to rebuild everything from scratch
    Init {
        /// Force re-initialization (rebuild everything from scratch)
        #[arg(short, long)]
        force: bool,

        /// Specific languages to initialize (comma-separated: python,node,ruby,go,etc.)
        #[arg(short, long)]
        languages: Option<String>,

        /// Custom sandbox directory (default: OS-specific data directory)
        #[arg(short, long)]
        directory: Option<PathBuf>,
    },

    /// Check sandbox status
    Status,

    /// Install packages in sandbox
    Install {
        /// Language runtime
        language: String,

        /// Packages to install
        packages: Vec<String>,
    },

    /// Clean sandbox environment
    Clean {
        /// Clean specific language only
        #[arg(short, long)]
        language: Option<String>,

        /// Force clean without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Open sandbox shell
    Shell {
        /// Language environment to use
        #[arg(short, long, default_value = "bash")]
        language: String,
    },

    /// Show sandbox path
    Path,

    /// Update sandbox packages
    Update {
        /// Update specific language only
        #[arg(short, long)]
        language: Option<String>,
    },

    /// Export sandbox configuration
    Export {
        /// Output file
        #[arg(short, long, default_value = "sandbox-export.yaml")]
        output: PathBuf,

        /// Description
        #[arg(short, long)]
        description: Option<String>,

        /// Author
        #[arg(short, long)]
        author: Option<String>,
    },

    /// Import sandbox configuration
    Import {
        /// Import file
        file: PathBuf,

        /// Force overwrite existing sandbox
        #[arg(short, long)]
        force: bool,
    },

    /// List available sandbox templates
    Templates,

    /// Use a pre-configured sandbox template
    UseTemplate {
        /// Template name (web-security, network-security, api-testing)
        template: String,
    },

    /// List installed packages
    List {
        /// Language to list packages for
        language: String,
    },

    /// Create a new Docker-based sandbox
    Create {
        /// Sandbox name
        name: String,

        /// Languages to install
        #[arg(short, long, value_delimiter = ',')]
        languages: Option<Vec<String>>,

        /// Persist container between runs
        #[arg(short, long, default_value = "true")]
        persist: bool,

        /// Auto-start on CLI launch
        #[arg(short, long, default_value = "true")]
        auto_start: bool,
    },

    /// Delete a sandbox
    Delete {
        /// Sandbox name
        name: String,

        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Enter sandbox shell
    Enter {
        /// Sandbox name (uses default if not specified)
        name: Option<String>,
    },

    /// Set default sandbox
    SetDefault {
        /// Sandbox name (clear default if not specified)
        name: Option<String>,
    },

    /// Show Docker sandbox information
    Info,

    /// Build Docker image
    Build {
        /// Dockerfile path
        #[arg(short, long)]
        dockerfile: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum SeverityArg {
    /// Critical severity (highest priority)
    Critical,
    /// High severity
    High,
    /// Medium severity
    Medium,
    /// Low severity
    Low,
    /// Informational (lowest priority)
    Info,
}

impl From<SeverityArg> for cert_x_gen::types::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Critical => cert_x_gen::types::Severity::Critical,
            SeverityArg::High => cert_x_gen::types::Severity::High,
            SeverityArg::Medium => cert_x_gen::types::Severity::Medium,
            SeverityArg::Low => cert_x_gen::types::Severity::Low,
            SeverityArg::Info => cert_x_gen::types::Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LanguageArg {
    /// YAML declarative templates
    Yaml,
    /// Python interpreted templates
    Python,
    /// Rust compiled templates
    Rust,
    /// Shell/Bash script templates
    Shell,
    /// JavaScript/Node.js templates
    JavaScript,
    /// C compiled templates
    C,
    /// C++ compiled templates
    Cpp,
    /// Java compiled templates
    Java,
    /// Go compiled templates
    Go,
    /// Ruby interpreted templates
    Ruby,
    /// Perl interpreted templates
    Perl,
    /// PHP interpreted templates
    Php,
}

impl From<LanguageArg> for cert_x_gen::types::TemplateLanguage {
    fn from(arg: LanguageArg) -> Self {
        match arg {
            LanguageArg::Yaml => cert_x_gen::types::TemplateLanguage::Yaml,
            LanguageArg::Python => cert_x_gen::types::TemplateLanguage::Python,
            LanguageArg::Rust => cert_x_gen::types::TemplateLanguage::Rust,
            LanguageArg::Shell => cert_x_gen::types::TemplateLanguage::Shell,
            LanguageArg::JavaScript => cert_x_gen::types::TemplateLanguage::JavaScript,
            LanguageArg::C => cert_x_gen::types::TemplateLanguage::C,
            LanguageArg::Cpp => cert_x_gen::types::TemplateLanguage::Cpp,
            LanguageArg::Java => cert_x_gen::types::TemplateLanguage::Java,
            LanguageArg::Go => cert_x_gen::types::TemplateLanguage::Go,
            LanguageArg::Ruby => cert_x_gen::types::TemplateLanguage::Ruby,
            LanguageArg::Perl => cert_x_gen::types::TemplateLanguage::Perl,
            LanguageArg::Php => cert_x_gen::types::TemplateLanguage::Php,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConfigFormat {
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
    /// JSON format
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SearchFormat {
    /// Table format (human-readable, default)
    Table,
    /// JSON format (machine-readable)
    Json,
    /// YAML format
    Yaml,
    /// CSV format (spreadsheet-compatible)
    Csv,
    /// Simple list format (template IDs only)
    List,
    /// Detailed format (all information)
    Detailed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SearchSort {
    /// Sort by relevance score (default)
    Relevance,
    /// Sort by template name
    Name,
    /// Sort by programming language
    Language,
    /// Sort by severity level
    Severity,
    /// Sort by author name
    Author,
    /// Sort by creation/update date
    Date,
    /// Sort by popularity/usage
    Popularity,
}

// ============================================================================
// AI COMMAND
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    about = "AI-powered security template generation",
    long_about = "Generate security scanning templates using AI/LLM providers. Supports local models \
                  (Ollama) and cloud providers (OpenAI, Anthropic, DeepSeek). No API key required \
                  for local generation with Ollama.",
    after_help = "FEATURES:
  • Generate templates from natural language descriptions
  • Support for all 12 programming languages (YAML, Python, JavaScript, Rust, C, C++, Java, Go, Ruby, Perl, PHP, Shell)
  • Multiple LLM providers (Ollama, OpenAI, Anthropic, DeepSeek)
  • Local-first with Ollama (no API key needed, works offline)
  • Automatic validation before saving
  • Unlimited generations (you control your own LLM)

EXAMPLES:
  # Generate with default provider (Ollama, local)
  cert-x-gen ai generate \"detect Redis without authentication\"
  cert-x-gen ai generate \"find SQL injection in login forms\"
  cert-x-gen ai generate \"check for exposed Memcached\"

  # Specify programming language
  cert-x-gen ai generate \"detect Redis unauth\" --language python
  cert-x-gen ai generate \"find XSS vulnerabilities\" --language javascript
  cert-x-gen ai generate \"check SSL certificates\" --language rust

  # Use specific provider
  cert-x-gen ai generate \"detect RCE\" --provider openai --model gpt-4
  cert-x-gen ai generate \"find SSRF\" --provider anthropic --model claude-3-5-sonnet-20241022
  cert-x-gen ai generate \"check headers\" --provider ollama --model codellama:13b

  # Save to specific location
  cert-x-gen ai generate \"Redis check\" --language yaml --output templates/redis-test.yaml
  cert-x-gen ai generate \"MySQL scan\" --output mysql-check.py

  # List available providers
  cert-x-gen ai providers list
  cert-x-gen ai providers list --detailed

  # Test provider connection
  cert-x-gen ai providers test ollama
  cert-x-gen ai providers test openai

  # Show provider status
  cert-x-gen ai providers status

GETTING STARTED WITH OLLAMA (FREE, LOCAL):
  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh
  2. Download model: ollama pull codellama:13b
  3. Start Ollama: ollama serve
  4. Generate: cert-x-gen ai generate \"your security check description\"

PROVIDER CONFIGURATION:
  Configure providers in ~/.cert-x-gen/ai-config.yaml or use environment variables:
  - OPENAI_API_KEY for OpenAI
  - ANTHROPIC_API_KEY for Anthropic
  - DEEPSEEK_API_KEY for DeepSeek

For more information: https://github.com/cert-x-gen/cert-x-gen/docs/ai-features"
)]
pub struct AiCommand {
    #[command(subcommand)]
    pub action: AiAction,
}

#[derive(Subcommand, Debug)]
pub enum AiAction {
    /// Generate a new template from natural language
    Generate {
        /// Natural language description of what to detect
        ///
        /// Examples:
        ///   "detect Redis without authentication"
        ///   "find SQL injection vulnerabilities"
        ///   "check for exposed Memcached instances"
        ///   "scan for XSS in forms"
        prompt: String,

        /// Programming language for the template
        #[arg(
            short = 'l',
            long,
            value_enum,
            default_value = "yaml",
            value_name = "LANG",
            help = "Template language (yaml, python, javascript, rust, etc.)"
        )]
        language: LanguageArg,

        /// LLM provider to use
        #[arg(
            short = 'p',
            long,
            value_name = "PROVIDER",
            help = "LLM provider (ollama, openai, anthropic, deepseek)"
        )]
        provider: Option<String>,

        /// Model name to use
        #[arg(
            short = 'm',
            long,
            value_name = "MODEL",
            help = "Model name (e.g., codellama:13b, gpt-4, claude-3-5-sonnet-20241022)"
        )]
        model: Option<String>,

        /// Output file path (auto-generated if not specified)
        #[arg(
            short = 'o',
            long,
            value_name = "FILE",
            help = "Output file path (default: ~/.cert-x-gen/templates/ai-generated/<name>.<ext>)"
        )]
        output: Option<PathBuf>,

        /// Test the generated template immediately
        #[arg(long, help = "Test the generated template after creation")]
        test: bool,

        /// Target to test against (requires --test)
        #[arg(
            long,
            requires = "test",
            value_name = "HOST",
            help = "Target host for testing (e.g., localhost, 192.168.1.1)"
        )]
        test_target: Option<String>,

        /// Force overwrite if file exists
        #[arg(short = 'f', long, help = "Overwrite output file if it already exists")]
        force: bool,

        /// Show generation cost estimate (for cloud providers)
        #[arg(
            long,
            help = "Estimate and show cost before generating (cloud providers only)"
        )]
        estimate_cost: bool,
    },

    /// Manage LLM providers
    #[command(after_help = "EXAMPLES:
  # List all configured providers
  cert-x-gen ai providers list
  cert-x-gen ai providers list --detailed
  
  # Test specific provider (comprehensive health check)
  cert-x-gen ai providers test ollama
  cert-x-gen ai providers test openai
  cert-x-gen ai providers test anthropic
  cert-x-gen ai providers test deepseek
  
  # Check status of all enabled providers
  cert-x-gen ai providers status

HEALTH CHECK DETAILS:
  The 'test' command performs comprehensive diagnostics:
  • Connection testing (can we reach the endpoint?)
  • Authentication verification (is the API key valid?)
  • Response time measurement (how fast is the provider?)
  • Model availability check (what models can we use?)
  • Helpful hints for common issues

  The 'status' command tests all enabled providers at once,
  giving you a quick overview of your AI setup.

TROUBLESHOOTING:
  If a provider test fails, the output will include:
  • Clear error messages explaining what went wrong
  • Helpful hints for fixing the issue
  • Setup instructions for unconfigured providers
  
  Common issues:
  • Ollama: Make sure it's running (ollama serve)
  • Cloud providers: Check your API key environment variable
  • Network: Verify your internet connection for cloud providers")]
    Providers {
        #[command(subcommand)]
        action: ProviderAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProviderAction {
    /// List all available providers
    ///
    /// Shows which providers are configured and available.
    /// Use --detailed to see more information about each provider.
    List {
        /// Show detailed information about each provider
        #[arg(short = 'd', long, help = "Show detailed provider information")]
        detailed: bool,
    },

    /// Test connection to a specific provider
    ///
    /// Performs comprehensive health checks including:
    /// - Connection testing
    /// - Authentication verification  
    /// - Response time measurement
    /// - Model availability check
    ///
    /// Provides helpful diagnostic information if issues are found.
    Test {
        /// Provider name to test (ollama, openai, anthropic, deepseek)
        provider: String,
    },

    /// Show status of all configured providers
    ///
    /// Tests all enabled providers and displays their health status.
    /// Quick way to see which providers are ready to use.
    Status,
}
