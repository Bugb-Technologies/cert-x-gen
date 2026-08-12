//! Command-line interface for CERT-X-GEN

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cxg",
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
  cxg scan --scope example.com
  cxg scan --scope https://api.example.com:8443 --ports 80,443,8080
  cxg scan --scope 192.168.1.0/24 --top-ports 1000

  # Bulk input
  cxg scan --scope @targets.txt
  cxg scan --scope file://scopes/internal.txt

  # Advanced scanning with filters
  cxg scan --scope example.com --template-language python,rust
  cxg scan --scope example.com --severity critical,high
  cxg scan --scope example.com --tags database,unauthenticated

  # Template search
  cxg search --query \"redis\"
  cxg search --language python --severity high
  cxg search --query \"injection\" --content --regex
  cxg search --tags \"database,unauthenticated\" --format json

  # Template management
  cxg template list
  cxg template list --language c --severity critical
  cxg template info redis-unauthenticated

  # Template search
  cxg search --query \"redis\"
  cxg search --language python --severity high
  cxg search --tags \"injection,sql\" --format json

  # Configuration
  cxg config generate --output config.yaml
  cxg scan --config config.yaml --scope example.com

  # Output formats
  cxg scan --scope example.com --output-format json,csv,sarif
  cxg scan --scope example.com --output results --output-format json

  # Performance tuning
  cxg scan --scope example.com --threads 20 --parallel-targets 100
  cxg scan --scope example.com --timeout 60s --retry 5

  # Stealth and safety
  cxg scan --scope example.com --stealth --rate-limit 10
  cxg scan --scope example.com --safe --passive

  For detailed help on any command, use: cxg <command> --help"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable verbose output (-v: info+warn, -vv: +trace, -vvv: +debug)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Configuration file path
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Update templates (shorthand for 'cxg template update')
    #[arg(
        long = "ut",
        visible_alias = "update-templates",
        global = true,
        help = "Update templates from repository (shorthand for 'cxg template update')"
    )]
    pub update_templates: bool,

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

    /// MCP (Model Context Protocol) server for AI agent integration
    Mcp(McpCommand),

    /// AI-driven whitebox pentest pipeline (guardlink source code → authenticated browser execution)
    ///
    /// Reads `whitebox/findings.sarif` produced by guardlink, ranks threats against an
    /// operator goal, and asks your local AI CLI (claude / codex / gemini) to write
    /// JavaScript probe templates that read the target's source to craft code-aware
    /// payloads. Those templates execute in N parallel authenticated Chromium contexts,
    /// emitting confirmed/refuted/ambiguous findings to a JSON report plus a JSONL audit
    /// log of every HTTP request.
    ///
    /// Capabilities:
    ///   • Interactive auth capture for SSO/MFA flows (no need to script logins)
    ///   • Chained-auth probes (IDOR cross-user) via `--auth-numbers 2+`
    ///   • Pre-flight identity inspection — landing-test based, no /me-path required
    ///   • Goal-driven LLM ranking of guardlink hypotheses
    ///   • Validator-guarded code-generation with hard 240s timeout per AI call
    ///   • Retry-with-mutation on AMBIGUOUS triage (max N retries, env-bound skip)
    ///   • Scope enforcement (URL/method allowlist, per-endpoint budget, 5xx hard-kill)
    ///   • Cookie-jar primitives in templates (HttpOnly-aware via Playwright)
    ///   • Out-of-band callbacks in two modes: inject a canary cxg cannot read
    ///     (`--oast`), or register one cxg owns and polls (`--oast-interactsh`) —
    ///     only the second yields an in-band blind-vuln confirmation
    ///   • Per-profile custom headers (WAF bypass, internal-test headers)
    ///   • Split report: confirmed_findings vs mitigation_verifications vs ambiguous
    Pentest(PentestCommand),

    /// Update cxg to the latest released build
    Update(UpdateCommand),

    /// Display version information
    Version,
}

/// `cxg update` — self-update the binary from the latest GitHub release.
// @g.comment -- "CLI options for the self-update command; downloads a release binary and replaces the running executable"
#[derive(Parser, Debug, Clone)]
pub struct UpdateCommand {
    /// Only check whether a newer version exists; don't download or install
    #[arg(long)]
    pub check: bool,

    /// Install a specific release tag (e.g. v1.2.0) instead of the latest
    #[arg(long)]
    pub version: Option<String>,

    /// Skip the confirmation prompt before replacing the binary
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct PentestCommand {
    #[command(subcommand)]
    pub action: PentestAction,
}

#[derive(Subcommand, Debug, Clone)]
// @g.comment -- "clippy::large_enum_variant, allowed deliberately. Run already carries ~35 operator flags and sat just under the lint's 200-byte spread; adding --oast-interactsh pushed it over. The lint's remedy is to box the variant's payload, which here would mean a Box around a clap-derived struct that main.rs destructures field-by-field — a churn of every pentest call site, and an allocation on a path that parses one command line and exits, to save bytes on a value that exists once per process. The size is a true statement about a subcommand with this many flags, not a defect."
#[allow(clippy::large_enum_variant)]
pub enum PentestAction {
    /// Install the Python orchestrator into ~/.cert-x-gen/pentest/
    ///
    /// One-time setup. Copies the Python orchestrator bundled with the cxg source tree
    /// to `~/.cert-x-gen/pentest/`, then verifies the required Python deps (playwright,
    /// anthropic) are installed. Must be run before `cxg pentest auth` or `cxg pentest run`.
    ///
    /// Examples:
    ///     cxg pentest install
    ///     cxg pentest install --force     # reinstall after pulling new cxg source
    Install {
        /// Reinstall even if `~/.cert-x-gen/pentest/` already exists. Use after
        /// updating the cxg source tree or pulling new Python modules.
        #[arg(long)]
        force: bool,
    },

    /// Capture — or, via a subcommand, import/verify — an authenticated session profile
    ///
    /// With no subcommand this captures interactively: it spawns a real headed Chromium
    /// window. You log in by ANY means — username/password, SSO redirect, MFA prompt,
    /// hardware key, magic link, OAuth popup. When the app dashboard is showing, press
    /// ENTER in the terminal (or close the browser) and cxg snapshots cookies +
    /// localStorage + sessionStorage from every origin the browser touched. The profile
    /// is saved at `~/.cert-x-gen/auth/<profile>.json` plus metadata at
    /// `<profile>.meta.json`.
    ///
    /// A post-capture landing-test verifies the session works: it re-opens a fresh
    /// browser context with the saved state, navigates to --target, and checks whether
    /// the final URL/page looks like a login or the app dashboard.
    ///
    /// Use `--auth-numbers N` for chained-auth scenarios (e.g. IDOR testing needs two
    /// different identities). cxg prompts for a human-readable label for each capture.
    ///
    /// For CI, where no human can drive a browser, use the subcommands instead:
    ///   `cxg pentest auth import` replays a session captured once and exported as a
    ///   Playwright storage_state, with no browser; `cxg pentest auth verify` checks a
    ///   saved session is still alive (exit 0 alive / non-zero dead) before a run spends
    ///   any AI budget.
    ///
    /// Examples:
    ///     # Single interactive capture (no subcommand)
    ///     cxg pentest auth --target https://app.example.com --profile admin
    ///
    ///     # Two identities for chained-auth (e.g. IDOR victim + attacker)
    ///     cxg pentest auth --target https://app.example.com --profile pentest --auth-numbers 2
    ///
    ///     # Scripted login (no browser pop-up)
    ///     cxg pentest auth --target https://app.example.com --profile bot \
    ///       --creds 'user@example.com:hunter2' --login-path /api/auth/login
    ///
    ///     # Capture a profile that sends a WAF-bypass header on every request
    ///     cxg pentest auth --target https://app.example.com --profile pentest \
    ///       --header "x-test-automation:abc123xyz"
    ///
    ///     # CI: import a session captured once, then verify it before a run
    ///     cxg pentest auth import --profile pentest --target https://staging.app \
    ///       --storage-state ./pentest.storage.json
    ///     cxg pentest auth verify --profile pentest
    // @g.comment -- "auth carries the interactive-capture flags AND hosts the CI subcommands (import/verify). args_conflicts_with_subcommands keeps the two modes from being mixed on one line. This mirrors the Python surface, where cxg_pentest.py forwards `auth <rest>` verbatim to auth.py's own login|import|verify|list subparsers; bare `cxg pentest auth ...` maps to `auth login` exactly as before. --target/--profile are Option here rather than required-at-clap ONLY because clap's derive does not honour subcommand_negates_reqs (the builder method works, the #[command(...)] attribute is a no-op in clap 4.5), so a required --target would wrongly be demanded of `auth import`/`auth verify` too. Their required-ness for the capture path is enforced in main.rs's None branch, so the capture happy path and its errors are unchanged."
    #[command(args_conflicts_with_subcommands = true)]
    Auth {
        /// Target URL where login happens (e.g. https://app.example.com).
        /// After capture, the landing-test verifier opens this URL with the saved
        /// cookies; if it doesn't bounce to a login page, the session is alive.
        ///
        /// Required for interactive capture (no subcommand). The `import`/`verify`
        /// subcommands take their own `--target` instead.
        #[arg(long)]
        target: Option<String>,

        /// Profile name. If --auth-numbers > 1, this is the PREFIX and final profiles
        /// are named `<profile>-1`, `<profile>-2`, etc. Use a stable name so subsequent
        /// `cxg pentest run --auth <profile>` invocations can reload it.
        ///
        /// Required for interactive capture (no subcommand).
        #[arg(long)]
        profile: Option<String>,

        /// Number of profiles to capture in sequence. Each capture opens its own
        /// Chromium window and prompts for a label (e.g. "victim", "attacker", "admin").
        /// Required ≥2 for chained-auth probes like IDOR cross-user tests.
        #[arg(long, default_value = "1")]
        auth_numbers: usize,

        /// Inline credentials `email:password` for scripted login (skips browser pop-up).
        /// Only works for password-based auth — SSO/MFA flows MUST use interactive capture.
        #[arg(long)]
        creds: Option<String>,

        /// File with `profile:email:password[:label]` per line for scripted batch capture.
        /// Useful for re-auth between scans of password-only test apps.
        #[arg(long)]
        creds_file: Option<PathBuf>,

        /// Endpoint path for scripted login POST. Only used with `--creds` or `--creds-file`.
        /// The captured browser will POST {email, password} as JSON to <target><login-path>.
        #[arg(long, default_value = "/api/auth/login")]
        login_path: String,

        /// Human-readable label for the profile (e.g. "admin", "low-priv-user").
        /// Shown in scan output to make findings readable. Does not affect behavior.
        #[arg(long)]
        label: Option<String>,

        /// Optional URL probed after capture as a secondary identity check. The landing
        /// test is the primary signal regardless. Default: empty (landing test only).
        /// Pass an empty string to skip the secondary probe entirely.
        #[arg(long)]
        verify_url: Option<String>,

        /// Custom HTTP header `NAME:VALUE` sent on every outbound request from this
        /// profile's browser context — including login, every scan probe, every health
        /// check. Repeatable for multiple headers. Saved with the profile so future
        /// `cxg pentest run --auth <profile>` invocations reuse them automatically.
        ///
        /// Use case: WAF-bypass tokens granted by infra (e.g. `x-test-automation`),
        /// internal-test headers, custom forwarding hints.
        ///
        /// SECURITY: header values are stored in plaintext under
        /// `~/.cert-x-gen/auth/<profile>.meta.json`. Treat the file like a credential.
        /// `chmod 600` if your machine has multiple users. Delete the profile when
        /// the engagement ends. Header values are sent to EVERY origin the browser
        /// touches, including IDPs — keep this in mind for SSO flows.
        #[arg(long = "header", value_name = "NAME:VALUE")]
        headers: Vec<String>,

        /// Explicit privilege rank for this identity: an integer 0-100 or an alias
        /// high/medium/low (= 90/50/10). Overrides the role-based heuristic and is fed to
        /// the AI ranker so it selects the right identity per probe (lowest tier for
        /// privesc, etc.). Omit to auto-derive from the app's role. In multi-capture
        /// (--auth-numbers > 1) this pre-fills the per-identity prompt.
        #[arg(long)]
        tier: Option<String>,

        /// Semantic role hint (e.g. "billing-analyst") passed to the AI as extra context —
        /// useful when the app's /me endpoint exposes no clear role field.
        #[arg(long)]
        persona: Option<String>,

        /// Peer-group name (e.g. "analyst-team-a"). Give two SAME-permission, DIFFERENT-user
        /// sessions the same cohort so the AI treats them as peers and targets horizontal
        /// IDOR / cross-tenant access between them.
        #[arg(long)]
        cohort: Option<String>,

        /// Free-form `NAME=VALUE` context attached to the profile and shown to the AI.
        /// Repeatable.
        #[arg(long = "tag", value_name = "NAME=VALUE")]
        tags: Vec<String>,

        /// Target type to capture auth for.
        ///
        /// `web` (default): the existing authenticated-browser capture against an HTTP
        /// application. `electron`: launch the Electron desktop app and capture its
        /// session state instead of a browser's.
        ///
        /// Tauri is not supported — it exposes no CDP endpoint on macOS or Linux.
        // @g.comment -- "selects which substrate auth capture launches against; an unknown value is rejected by clap so a typo can never silently downgrade a desktop capture to a web capture"
        // requires_if (not required_if_eq on app_cmd) is deliberate: clap's required_if_eq/
        // required_unless validation path skips the conflicts_with escape hatch, so pairing it
        // with app_cmd's conflicts_with would wrongly demand --app-cmd even when --app-binary
        // alone was supplied. requires_if instead feeds the required-arg resolution path that
        // does consult conflicts_with. See desktop_flag_tests::auth_electron_with_app_binary_alone_parses.
        #[arg(long, default_value = "web", value_parser = ["web", "electron"], requires_if("electron", "app_cmd"))]
        target_type: String,

        /// Command that launches the desktop app, e.g. "npm run electron:dev".
        ///
        /// Required with `--target-type electron` unless `--app-binary` is given.
        /// cxg appends `--remote-debugging-port` and a per-identity `--user-data-dir`.
        // @g.comment -- "operator-supplied launch command forwarded to the orchestrator, which splits and executes it as a child process per identity"
        // @g.source (#operator_app_cmd) -- "command string supplied by the operator on the command line"
        #[arg(long, conflicts_with = "app_binary")]
        app_cmd: Option<String>,

        /// Path to a built desktop app, e.g. /Applications/Foo.app.
        ///
        /// Alternative to `--app-cmd`; the two are mutually exclusive.
        // @g.comment -- "operator-supplied path to a packaged application, executed directly instead of via a launch command"
        #[arg(long, conflicts_with = "app_cmd")]
        app_binary: Option<String>,

        /// Non-interactive CI subcommand (`import` or `verify`). Absent = interactive
        /// capture using the flags above.
        // @g.comment -- "optional so bare `cxg pentest auth --target ... --profile ...` still means interactive capture; present it routes to the browser-free import/verify paths auth.py exposes for CI"
        #[command(subcommand)]
        auth_sub: Option<AuthSubcommand>,
    },

    /// List saved auth profiles under ~/.cert-x-gen/auth/
    ///
    /// Shows profile name, label, target URL, and whether extra_headers are present.
    /// Useful before running `cxg pentest run --auth <name>` to confirm which profile
    /// you'll be scanning as.
    AuthList,

    /// Write an example scope.yaml the operator can edit
    ///
    /// scope.yaml controls the safety rails for a scan: method allowlist (default
    /// GET/POST/HEAD/OPTIONS — DELETE/PUT/PATCH require `--destructive-ok`), URL
    /// allow/blocklist regexes, per-endpoint and total request budgets, 5xx-streak
    /// hard-kill threshold, and the `authorization_attestation` field that's recorded
    /// in the audit log header.
    ///
    /// Example:
    ///     cxg pentest scope-init -o my-engagement-scope.yaml
    ScopeInit {
        /// Output file path. Default: scope.yaml in the current directory.
        #[arg(short, long, default_value = "scope.yaml")]
        output: PathBuf,
    },

    /// Run the full end-to-end pentest pipeline against a target
    ///
    /// Pipeline steps:
    ///   [1]  Load guardlink hypotheses from `<codebase>/whitebox/findings.sarif`
    ///   [1b] Inspect captured auth profiles via landing-test
    ///        (`profile_inspect.inspect_profiles_async`)
    ///   [2]  LLM-rank hypotheses against --goal + profile coverage; AI generates JS
    ///        templates that read source via Claude/Codex/Gemini's own Read/Grep tools
    ///   [3]  Load + statically validate templates (`validator.py`)
    ///   [4]  Open N parallel authenticated Chromium contexts; inject the cxg JS bridge
    ///   [5]  Run each template; triage findings (CONFIRMED / REFUTED / AMBIGUOUS);
    ///        mutate-and-retry on payload-fixable AMBIGUOUS, skip environment-bound
    ///   [6]  Write `report.json` and `audit.jsonl` to --session-dir
    ///
    /// The full set of probes available to templates is documented in
    /// `pentest/docs/TEMPLATES.md`. The runtime intelligence layer (validator, scope,
    /// session health, mutation, triage, audit) is in `pentest/docs/ARCHITECTURE.md`.
    ///
    /// Examples:
    ///     # Single-profile read-only scan with default settings
    ///     cxg pentest run --codebase ./repo --target http://localhost:8000 \
    ///       --auth admin --ai --ai-provider claude
    ///
    ///     # Two identities for IDOR/chained-auth, AI off → built-in probes only
    ///     cxg pentest run --codebase ./repo --target http://localhost:8000 \
    ///       --auth victim,attacker
    ///
    ///     # Verify mitigations only (skips unmitigated threats so you can confirm
    ///     # declared defenses hold at runtime). Useful for well-annotated codebases.
    ///     cxg pentest run --codebase ./repo --target https://staging.app \
    ///       --auth pentest --ai --ai-provider claude \
    ///       --mitigation-mode mitigated --max-templates 16
    ///
    ///     # SSRF testing against a canary cxg OWNS — it registers the interactsh
    ///     # session and polls it, so a callback becomes a confirmed finding
    ///     cxg pentest run --codebase ./repo --target https://staging.app \
    ///       --auth pentest --ai --ai-provider claude \
    ///       --oast-interactsh \
    ///       --goal "verify SSRF on /slack/proxy via OAST callback"
    ///
    ///     # Same probes, but against a canary cxg can only inject into (e.g. a Burp
    ///     # Collaborator host). Templates build the URL; YOU read the hit in
    ///     # Collaborator. Findings stay unconfirmed as far as cxg is concerned.
    ///     cxg pentest run --codebase ./repo --target https://staging.app \
    ///       --auth pentest --ai --ai-provider claude \
    ///       --oast c4ca4238a0b92.oastify.com \
    ///       --goal "test SSRF on /slack/proxy; check Collaborator for callbacks"
    ///
    /// Exit codes:
    ///   0 → no confirmed findings (clean scan)
    ///   1 → no templates available (guardlink output missing or empty)
    ///   2 → confirmed findings present
    ///   3 → scan was hard-killed (5xx streak, scope violation, etc.)
    ///   5 → CI mode (`--ci` / CXG_CI=1): an auth session was dead/expired at
    ///       pre-flight, so the run stopped before spending any AI calls rather
    ///       than silently probing UNAUTHENTICATED
    Run {
        /// Source codebase root. MUST contain `whitebox/findings.sarif` produced by
        /// `guardlink sarif <codebase> -o whitebox/findings.sarif`. The codebase is also
        /// the working directory of the AI CLI during template generation, so the AI
        /// can read source via its own Read/Grep tools to craft code-aware payloads.
        #[arg(long)]
        codebase: PathBuf,

        /// Running target app URL. Both `http://` and `https://` are supported.
        /// Multi-tenant note: pass the URL where the SESSION cookies live, not a marketing
        /// host. The landing test verifies you arrive at a non-login page from this URL.
        #[arg(long)]
        target: String,

        /// Comma-separated auth profile names previously captured via `cxg pentest auth`.
        /// Probes that need multiple identities (IDOR cross-user, session-replay-against-
        /// victim) require ≥2 profiles. The lowest-privilege identity is auto-selected as
        /// the actor for privesc-class probes.
        ///
        /// Leave empty if you're using --interactive-auth to capture fresh profiles inline.
        #[arg(long, default_value = "")]
        auth: String,

        /// Open N headed browser windows for interactive login at scan start, then run
        /// the pipeline with the resulting fresh profiles. Each capture prompts you for
        /// a per-identity label. Use this when your captured profiles have expired or
        /// when you don't want to manage profile lifecycle separately.
        ///
        /// Profiles are saved as `<--auth-profile>-1`, `<--auth-profile>-2`, etc.
        #[arg(long, default_value = "0")]
        interactive_auth: usize,

        /// Name prefix for `--interactive-auth` captures. The final profile names are
        /// `<auth_profile>-1`, `<auth_profile>-2`, etc.
        #[arg(long, default_value = "pentest")]
        auth_profile: String,

        /// Minimum auth contexts the scan requires. If you pass `--auth a,b` but
        /// `--auth-numbers 3`, chained-auth templates that need 3 contexts will be
        /// skipped with a warning. Pure usability check — engine doesn't fabricate
        /// extra contexts.
        #[arg(long)]
        auth_numbers: Option<usize>,

        /// File of `profile:email:password[:label]` lines used to AUTO RE-AUTH a
        /// dead session mid-scan (the session-health monitor detects death via the
        /// landing test). Without this, a probe that kills its own session — e.g.
        /// session_replay's logout — leaves remaining probes unable to run.
        ///
        /// Recommended for any scan with `--mutation-retries > 0` or scans with
        /// SessionReplay / Csrf class templates.
        #[arg(long)]
        creds_file: Option<PathBuf>,

        /// Template language. `js` (default): AI generates copy-paste-runnable JS
        /// templates that drive the cxg JS bridge — recommended for all interactive
        /// pentests. `py`: Python probe path (legacy) — only built-in probes in
        /// `pentest/payloads/`, no AI generation.
        #[arg(long, default_value = "js")]
        template_lang: String,

        /// Natural-language pentest goal. Used as context for both LLM-based hypothesis
        /// ranking AND template generation. Be specific about which vuln classes,
        /// endpoints, or claims you want tested.
        ///
        /// Examples:
        ///   "test for IDOR in records and transactions APIs"
        ///   "verify each declared @mitigates actually holds at runtime"
        ///   "find unguarded admin endpoints accessible to non-admin tokens"
        #[arg(long)]
        goal: Option<String>,

        /// Reuse JS templates from a previously-generated session directory. Skips the
        /// AI generation step entirely. Useful for re-running the same templates against
        /// different targets, or after fixing engine bugs that affected template execution.
        ///
        /// Template directories are at `~/.cert-x-gen/templates/session-<timestamp>/`.
        #[arg(long)]
        template_dir: Option<PathBuf>,

        /// Maximum number of templates the LLM ranker is allowed to select per scan.
        /// Each template = one AI generation call (~60-180s with claude/codex). Lower for
        /// fast feedback loops; higher for engagement-grade coverage.
        #[arg(long, default_value = "8")]
        max_templates: usize,

        /// Maximum times the AI is allowed to mutate a template after AMBIGUOUS triage.
        /// Environment-bound AMBIGUOUS (missing role, missing primitive) skip mutation
        /// automatically; only payload-fixable ones consume retries.
        /// 0 disables the loop entirely.
        #[arg(long, default_value = "2")]
        mutation_retries: usize,

        /// AI provider. `auto` picks the first available CLI tool (claude > codex > gemini),
        /// falling back to ANTHROPIC_API_KEY / OPENAI_API_KEY HTTP APIs. Otherwise specify
        /// explicitly. CLI providers don't need API keys — they use your existing CLI auth.
        ///
        /// Options: auto | claude | codex | gemini | anthropic | openai
        #[arg(long, default_value = "claude")]
        ai_provider: String,

        /// Enable AI-driven template generation. Without `--ai`, only built-in probes
        /// from `pentest/payloads/` run. With `--ai`, the orchestrator invokes the
        /// chosen `--ai-provider` to read the codebase and synthesize code-aware
        /// templates per guardlink hypothesis.
        #[arg(long)]
        ai: bool,

        /// Show Chromium windows during scan instead of running headless. Useful for
        /// debugging probes, watching auth flows, or when WAF bot-detection is blocking
        /// headless requests (real Chromium has a stronger fingerprint than headless).
        #[arg(long)]
        headed: bool,

        /// Path to scope.yaml. Default: safe permissive defaults (any URL, GET/POST/HEAD/
        /// OPTIONS, 30 reqs/endpoint, 1500 reqs total, kill on 8-streak 5xx).
        /// Generate one with `cxg pentest scope-init`.
        #[arg(long)]
        scope_file: Option<PathBuf>,

        /// Allow DELETE/PUT/PATCH methods AND paths matching destructive regexes
        /// (`/wipe`, `/delete-all`, `/factory-reset`, etc.) in scope.yaml.
        /// Default OFF. Required for templates that test destructive-action authz.
        ///
        /// USE WITH CARE on production targets. The engine emits a warning at startup
        /// and every blocked request is still recorded in the audit log.
        #[arg(long)]
        destructive_ok: bool,

        /// Free-text written authorization statement recorded in the audit log header.
        /// Include engagement ID, operator name, change-management ticket, etc.
        ///
        /// Example: "Engagement PT-2026-003, operator J. Doe, ticket CHG-1234"
        ///
        /// Strongly recommended for any non-local scan. The audit log header is the
        /// dispute-ready record of "I had authorization to do this scan."
        #[arg(long)]
        attestation: Option<String>,

        /// Session directory where this scan's artifacts (audit.jsonl, report.json,
        /// any captured screenshots) are written.
        /// Default: ~/.cert-x-gen/sessions/pentest-<YYYYMMDD-HHMMSS>/
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// JSON report output path. Default: `report.json` under --session-dir.
        /// The report contains: target, codebase, auth_profiles, goal, scope_stats,
        /// confirmed_findings, ambiguous, mitigation_verifications, dead_profiles,
        /// rejected_templates, retried_then_resolved.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Hypothesis filter by declared-mitigation status from guardlink:
        ///   `any`         — all HTTP-testable hypotheses (default)
        ///   `unmitigated` — only threats WITHOUT a declared @mitigates
        ///                   (find unguarded holes)
        ///   `mitigated`   — only threats WITH @mitigates declared
        ///                   (verify defenses actually hold at runtime)
        #[arg(long, default_value = "any")]
        mitigation_mode: String,

        /// Optional identity endpoint hit during pre-flight inspection to extract
        /// role/email/id from a JSON response. Failure here does NOT mark the profile
        /// dead — the landing test is the source of truth. Override only when you
        /// want role-tier-based probe selection AND the app has a stable /me endpoint.
        ///
        /// Default `/api/me`. Set to empty string to skip the secondary probe.
        #[arg(long, default_value = "/api/me")]
        me_path: String,

        /// Hard wall-clock timeout per AI generation call. The whole process tree is
        /// killed if exceeded. Default 240s.
        ///
        /// Claude CLI typically takes 60-170s per template; Codex 90-220s; Gemini 30-180s.
        /// Bump to 600+ for very large codebases the AI has to grep through.
        #[arg(long, default_value = "240")]
        generation_timeout: u64,

        /// Skip the pre-flight session health check entirely. Use when:
        ///   • Multi-tenant app where the session lives at a subdomain different from --target
        ///   • App has no stable /me-style endpoint
        ///   • You know the session is fresh and want to skip the verification roundtrip
        ///
        /// Per-template health checks still run during the scan unless you also configure
        /// scope.yaml to disable them.
        #[arg(long)]
        skip_health_check: bool,

        /// An external out-of-band callback host cxg can INJECT INTO but cannot read
        /// back (Burp Collaborator, a canary you host, an interactsh domain you
        /// generated yourself). Exposed to templates as `cxg.oast.url(label, scheme?)`
        /// so payloads carry a callback URL — but cxg never learns whether it fired,
        /// so nothing here confirms anything: blind probes (SSRF, blind SQLi, blind
        /// XXE, blind cmd-injection) still fall back to status-code heuristics and
        /// timing, and the AI prompt is instructed to mark them `confirmed=false`.
        /// Reading the callback is the operator's job, in their own tooling.
        ///
        /// Want cxg to do the confirming? Use `--oast-interactsh` instead.
        ///
        /// Example: `--oast c4ca4238a0b923820dcc.oastify.com`
        ///
        /// If the host is an interactsh domain rather than a Collaborator one, run
        /// `interactsh-client` in another terminal first and paste the hostname it
        /// prints — that terminal is the only place these callbacks become visible.
        ///
        /// (With `--oast-interactsh` there is no second terminal: cxg is the client.)
        // @g.comment -- "operator-supplied callback host injected into payloads; kept exactly as it was, value and all, because every existing invocation and every template calling cxg.oast.url() depends on it"
        // @g.comment -- "help text deliberately no longer claims 'definitive blind-vuln confirmation': cxg holds no session for a host it was merely handed, so it cannot poll it, and an operator who read the old wording would take an unconfirmed finding for a confirmed one"
        #[arg(long, value_name = "HOST")]
        oast: Option<String>,

        /// Register an interactsh session cxg OWNS and poll it — the mode that can
        /// actually confirm a blind vulnerability. Because cxg registered the session
        /// it holds the correlation id, so templates can call `cxg.oast.poll(label)`,
        /// read the interactions back in-band, and a callback becomes a genuine
        /// `confirmed=true` finding with the interaction recorded as evidence. cxg is
        /// the interactsh client here; you do not run one alongside it.
        ///
        /// The optional value is the interactsh server to register against; omit it to
        /// use interactsh's default public servers.
        ///
        /// Mutually exclusive with `--oast`. Two canaries would split payloads between
        /// a host cxg can poll and one it cannot, so "was this confirmed?" would have
        /// no single answer per finding.
        ///
        /// Examples: `--oast-interactsh` (default servers), or
        /// `--oast-interactsh https://oast.example.internal` (your own instance).
        // @g.comment -- "selects the OAST mode in which cxg registers and therefore can read the canary; the server URL, when given, is the interactsh instance the session is registered against"
        // @g.comment -- "conflicts_with rather than a runtime if-both check, matching --app-cmd/--app-binary above: clap then rejects the pair during parse with the standard usage error, before any scan work, and the constraint is visible in --help instead of hiding in main()"
        // @g.comment -- "num_args = 0..=1 with an empty default_missing_value keeps the value optional and distinguishes the three states the mode needs — absent (None, no session), bare (Some(\"\"), default servers), explicit (Some(url)). An Option<Option<String>> would encode the same thing while making every downstream match arm nested for no gain"
        // @g.source (#operator_oast_server) -- "interactsh server URL supplied by the operator on the command line"
        #[arg(
            long,
            value_name = "SERVER_URL",
            num_args = 0..=1,
            default_missing_value = "",
            conflicts_with = "oast"
        )]
        oast_interactsh: Option<String>,

        /// Target type to pentest.
        ///
        /// `web` (default): the existing authenticated-browser pipeline against an HTTP
        /// application. `electron`: launch N isolated instances of an Electron desktop
        /// app, drive their renderers over CDP, and additionally probe IPC channels,
        /// renderer configuration, and local data at rest.
        ///
        /// Tauri is not supported — it exposes no CDP endpoint on macOS or Linux.
        ///
        /// EXAMPLES:
        ///
        ///     cxg pentest run --target-type electron --app-cmd "npm run electron:dev" \
        ///       --codebase ./app-repo --target https://api.example.com --auth desk-1,desk-2
        // @g.comment -- "selects which substrate the orchestrator uses; an unknown value is rejected by clap so a typo can never silently downgrade a desktop scan to a web scan"
        // requires_if (not required_if_eq on app_cmd) is deliberate: clap's required_if_eq/
        // required_unless validation path skips the conflicts_with escape hatch, so pairing it
        // with app_cmd's conflicts_with would wrongly demand --app-cmd even when --app-binary
        // alone was supplied. requires_if instead feeds the required-arg resolution path that
        // does consult conflicts_with. See desktop_flag_tests::electron_with_app_binary_alone_parses.
        #[arg(long, default_value = "web", value_parser = ["web", "electron"], requires_if("electron", "app_cmd"))]
        target_type: String,

        /// Command that launches the desktop app, e.g. "npm run electron:dev".
        ///
        /// Required with `--target-type electron` unless `--app-binary` is given.
        /// cxg appends `--remote-debugging-port` and a per-identity `--user-data-dir`.
        // @g.comment -- "operator-supplied launch command forwarded to the orchestrator, which splits and executes it as a child process per identity"
        // @g.source (#operator_app_cmd) -- "command string supplied by the operator on the command line"
        #[arg(long, conflicts_with = "app_binary")]
        app_cmd: Option<String>,

        /// Path to a built desktop app, e.g. /Applications/Foo.app.
        ///
        /// Alternative to `--app-cmd`; the two are mutually exclusive.
        // @g.comment -- "operator-supplied path to a packaged application, executed directly instead of via a launch command"
        #[arg(long, conflicts_with = "app_cmd")]
        app_binary: Option<String>,

        /// Additionally scan a real installation directory for data at rest.
        ///
        /// By default host probes read only the isolated user-data directories cxg
        /// created itself. Pass this to opt in to scanning an existing install.
        // @g.comment -- "opt-in expansion of host-probe scan scope beyond cxg-created directories, since reading an operator's real install is host-level access"
        #[arg(long)]
        host_scan_path: Option<String>,

        /// Absolute ceiling on one template's dispatch before it is abandoned and
        /// treated as a dead target. Default 900s. This is a BACKSTOP only —
        /// `--stall-timeout` is what actually catches a frozen app. 0 disables it,
        /// which lets a wedged app hang the scan indefinitely.
        // @g.comment -- "forwards the per-template ceiling to the orchestrator; without this the flag existed in Python only and was unreachable from the cxg binary, so an operator could not raise or disable the backstop at all"
        #[arg(long)]
        template_timeout: Option<f64>,

        /// How long the run may go with NO completed dispatch before the surface is
        /// corroborated against the other instances and, if it alone is silent,
        /// treated as stalled. This is IDLE time, not template runtime: a probe that
        /// keeps getting answers is never killed however long it runs. Default 90s,
        /// 0 disables. Applies to `--target-type electron` only.
        // @g.comment -- "forwards the stall threshold to the orchestrator; the measured freeze (a native modal blocking Electron's main process) produces no exception at all, so this is the only bound that ends such a run, and it was unreachable from the binary until now"
        #[arg(long)]
        stall_timeout: Option<f64>,

        /// Do NOT relaunch a desktop target that dies mid-scan.
        ///
        /// Default is to restart it (max 2 per instance, 3 per run), report the crash
        /// as a `denial_of_service` finding, re-probe the suspected IPC channel once
        /// and then quarantine it. With this flag a dead target ends the scan with a
        /// truncation caveat and exit 3 — the pre-recovery behaviour.
        // @g.comment -- "operator opt-out of crash recovery, because recovery lets cxg's own probes restart the application under test repeatedly and that side effect is an availability decision the operator owns, not cxg"
        #[arg(long)]
        no_restart: bool,

        /// Read auth profiles from this directory instead of ~/.cert-x-gen/auth.
        ///
        /// A CI pipeline restores a bundle of profiles (imported via
        /// `cxg pentest auth import --auth-dir <dir>`) into its own directory and
        /// points the run at the same directory here, so pre-flight, the engine, and
        /// the health monitor all read the restored bundle rather than the operator's
        /// home store.
        // @g.comment -- "forwards the auth-store redirect to the orchestrator, which reassigns auth.AUTH_DIR before any profile is loaded; every profile consumer reaches the store only through auth.load_profile, so this one flag moves all of them. Forwarded only when set, so an unset flag leaves the orchestrator's ~/.cert-x-gen/auth default in force — one default, in one place the two CLIs cannot drift apart on."
        #[arg(long)]
        auth_dir: Option<PathBuf>,

        /// Non-interactive CI mode: fail loud instead of warning.
        ///
        /// A dead or expired auth session becomes a HARD FAIL (exit 5) at pre-flight
        /// rather than today's warn-and-continue, so a pipeline never silently probes
        /// UNAUTHENTICATED and refutes real findings; and a world-accessible
        /// `--auth-dir` is refused rather than trusted. Without this flag the current
        /// warn behaviour is unchanged. `--skip-health-check` remains the documented
        /// escape hatch (it force-marks profiles alive, so the gate cannot trip).
        ///
        /// Also enabled by the environment variable CXG_CI=1, for pipelines that
        /// cannot add the flag to the invocation.
        // @g.comment -- "forwards the CI-mode selector as a flag when set; the hard-fail-on-dead-session and world-readable-auth-dir refusal both live in the Python orchestrator (cxg_pentest.py, auth.py), which also honours CXG_CI=1 on its own, so leaving the flag off here still lets the env var reach the orchestrator through the inherited environment"
        #[arg(long)]
        ci: bool,
    },
}

/// Non-interactive auth subcommands for CI — mirrors `pentest/auth.py`'s
/// `import`/`verify` subparsers exactly.
// @g.comment -- "the CI-replay half of the auth surface: a human captures a session once (SSO/MFA and all) and exports its Playwright storage_state; import writes a profile from that state with no browser, and verify gates on whether the saved session is still alive. Both were reachable only via `python3 cxg_pentest.py auth ...` until this surface was wired into clap; the defaults here are copied from auth.py's argparse, which is the specification."
#[derive(Subcommand, Debug, Clone)]
pub enum AuthSubcommand {
    /// Import a saved Playwright storage_state as a profile (no browser)
    ///
    /// The CI-replay primitive: a human captures a session once locally (SSO, MFA and
    /// all), exports the Playwright storage_state, and every pipeline run injects it
    /// here without a display or a human. The written profile is byte-for-byte what an
    /// interactive capture produces, so a later `cxg pentest run --auth <profile>`
    /// cannot tell an imported profile from a captured one.
    ///
    /// Examples:
    ///     # From a file on disk
    ///     cxg pentest auth import --profile pentest --target https://staging.app \
    ///       --storage-state ./pentest.storage.json
    ///
    ///     # From stdin (a CI secret piped straight in, never written to disk in the clear)
    ///     cat "$SESSION_SECRET" | cxg pentest auth import --profile pentest \
    ///       --target https://staging.app --storage-state -
    ///
    ///     # From the base64 env var, into a restored bundle dir, CI-strict
    ///     cxg pentest auth import --profile pentest --target https://staging.app \
    ///       --auth-dir ./ci-auth --ci
    Import {
        /// Profile name. A subsequent `cxg pentest run --auth <profile>` loads it
        /// exactly like a captured one.
        #[arg(long)]
        profile: String,

        /// Target URL this session authenticates against. Recorded in the profile and
        /// used by `auth verify` / run pre-flight as the landing-test URL.
        #[arg(long)]
        target: String,

        /// Path to a Playwright storage_state JSON, or `-` to read it from stdin (a CI
        /// secret pipes straight in, never touching disk in plaintext beyond the profile
        /// dir). Omit to materialise it from the base64 env var CXG_AUTH_STATE_<NAME>
        /// instead (NAME is the profile name uppercased with non-alphanumerics folded to
        /// underscore — e.g. profile `pentest-alice` reads `CXG_AUTH_STATE_PENTEST_ALICE`).
        // @g.source (#operator_storage_state) -- "storage_state source (path, '-' for stdin, or env fallback) supplied by the operator; forwarded verbatim to auth.py which resolves and redacts it — cxg never echoes its contents"
        #[arg(long, value_name = "PATH|-")]
        storage_state: Option<String>,

        /// Human-readable label (e.g. 'admin'), shown in scan output.
        #[arg(long)]
        label: Option<String>,

        /// Explicit privilege rank: an integer 0-100 or an alias high/medium/low. Same
        /// meaning as on capture.
        #[arg(long)]
        tier: Option<String>,

        /// Semantic role hint passed to the AI as extra context.
        #[arg(long)]
        persona: Option<String>,

        /// Peer-group name for horizontal IDOR / cross-tenant tests.
        #[arg(long)]
        cohort: Option<String>,

        /// Free-form `NAME=VALUE` context attached to the profile. Repeatable.
        #[arg(long = "tag", value_name = "NAME=VALUE")]
        tags: Vec<String>,

        /// Custom HTTP header `NAME:VALUE` sent on every request from this profile
        /// (e.g. a WAF-bypass token). Repeatable. Stored as a credential; values are
        /// never echoed.
        #[arg(long = "header", value_name = "NAME:VALUE")]
        headers: Vec<String>,

        /// Write into this auth directory instead of ~/.cert-x-gen/auth. A pipeline
        /// restores a bundle of profiles into one dir and points the run at it with the
        /// same flag.
        #[arg(long)]
        auth_dir: Option<PathBuf>,

        /// Non-interactive CI mode: refuse a world-accessible `--auth-dir` rather than
        /// write a credential a fellow user could read. Also enabled by CXG_CI=1.
        // @g.comment -- "forwards CI-strictness to auth.py, which refuses a world-readable --auth-dir before persisting a session; the refusal lives in Python (assert_auth_dir_not_world_readable), honoured here and via CXG_CI=1 in the inherited environment"
        #[arg(long)]
        ci: bool,
    },

    /// Check a saved web session is still alive (exit 0 alive / non-zero dead)
    ///
    /// An out-of-band liveness gate for a saved session, reusing the same landing-page
    /// test scan-time pre-flight uses. A pipeline runs this before spending a whole run,
    /// and re-captures (or re-imports) when it fails.
    ///
    /// Example:
    ///     cxg pentest auth verify --profile pentest || echo "session expired, re-import"
    Verify {
        /// Profile name to verify.
        #[arg(long)]
        profile: String,

        /// Override the profile's saved target for the landing test.
        #[arg(long)]
        target: Option<String>,

        /// Secondary identity endpoint probed for role/email; the landing test is the
        /// source of truth. Default /api/me.
        #[arg(long, default_value = "/api/me")]
        me_path: String,

        /// Read the profile from this auth directory instead of ~/.cert-x-gen/auth.
        #[arg(long)]
        auth_dir: Option<PathBuf>,
    },
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
      cxg scan --scope example.com --ports 80,443,8000-8010,@extra-ports.txt
  
  --top-ports <N>
    Add the top N most common ports (based on curated frequency data).
    Example:
      cxg scan --scope example.com --top-ports 100
  
  --override-ports <PORTS>
    Replace template default ports entirely with your custom list (same formats as --ports).
    Example:
      cxg scan --scope example.com --override-ports 80,443

PROTOCOL SPECIFICATION:
  Define which protocols to use for scanning (http, https, tcp, udp, etc.).
  
  --protocol <PROTOCOL>
    Use a single protocol for all scans.
    Example:
      cxg scan --scope example.com --protocol https
  
  --protocols <PROTOCOLS>
    Test multiple protocols (comma-separated). Engine tries each protocol.
    Example:
      cxg scan --scope example.com --protocols http,https

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
      cxg scan --scope example.com --templates redis-unauthenticated
      cxg scan --scope example.com --templates redis-unauthenticated,templates/network/redis.yaml
      cxg scan --scope example.com --templates @compliance-templates.txt
  
  --template-dir <DIR>
    Use templates from a custom directory instead of the default location.
    Example:
      cxg scan --scope example.com --template-dir ./custom-templates
  
  --template-language <LANGUAGES>
    Filter templates by programming language. Useful for testing specific engine types.
    Available: yaml, python, rust, shell, javascript, c, cpp, java, go, ruby, perl, php
    Example:
      cxg scan --scope example.com --template-language python --template-language rust
  
  --severity <SEVERITIES>
    Filter by severity level. Run only critical/high severity checks for quick assessments.
    Available: critical, high, medium, low, info
    Example:
      cxg scan --scope example.com --severity critical,high
  
  --tags <TAGS>
    Filter templates by tags (comma-separated). Tags categorize vulnerabilities.
    Common tags: database, injection, xss, authentication, authorization, rce, lfi, ssrf
    Example:
      cxg scan --scope example.com --tags database,unauthenticated
  
  --exclude-templates <PATTERN>
    Exclude templates matching a pattern. Supports wildcards.
    Example:
      cxg scan --scope example.com --exclude-templates test-*,experimental-*

OUTPUT AND REPORTING:
  Customize how scan results are saved and displayed.
  
  --output <BASENAME>
    Set the output file basename. Extensions are added based on format.
    Default: scan-results
    Example:
      cxg scan --scope example.com --output my-scan
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
      cxg scan --scope example.com --output-format json,html,sarif
  
  --stream
    Enable real-time streaming output. Results are displayed as they're found.
    Useful for long-running scans where you want immediate feedback.
    Example:
      cxg scan --scope example.com --stream
  
  --quiet
    Suppress non-essential output. Only show critical information and errors.
    Ideal for scripting and automation where you want minimal noise.
    Example:
      cxg scan --scope example.com --quiet --output-format json

PERFORMANCE AND CONCURRENCY:
  Tune scan performance based on your resources and target infrastructure.
  
  --threads <N>
    Number of worker threads for parallel execution. Higher = faster but more resource-intensive.
    Default: Number of CPU cores
    Recommendation: Start with default, increase if targets can handle load
    Example:
      cxg scan --scope example.com --threads 20
  
  --parallel-targets <N>
    How many targets to scan simultaneously. Higher = faster but may trigger rate limits.
    Default: 50
    Recommendation: Lower for production systems (10-25), higher for internal scans (50-100)
    Example:
      cxg scan --scope example.com,test.com --parallel-targets 10
  
  --parallel-templates <N>
    How many templates to run concurrently per target. Balances speed vs. target load.
    Default: 10
    Recommendation: Lower for fragile targets (5), higher for robust systems (20)
    Example:
      cxg scan --scope example.com --parallel-templates 5

TIMEOUTS AND RETRIES:
  Configure how the scanner handles slow responses and failures.
  
  --timeout <DURATION>
    Maximum time to wait for a response. Supports: s (seconds), m (minutes), h (hours)
    Default: 30s
    Recommendation: Increase for slow networks or complex checks
    Example:
      cxg scan --scope example.com --timeout 60s
      cxg scan --scope example.com --timeout 2m
  
  --retry <N>
    Number of retry attempts for failed requests. Helps with transient network issues.
    Default: 1
    Recommendation: Increase for unreliable networks, decrease for fast scans
    Example:
      cxg scan --scope example.com --retry 5
  
  --rate-limit <N>
    Maximum requests per second. Prevents overwhelming targets and triggering WAF/IPS.
    Default: None (unlimited)
    Recommendation: Use 10-50 for production, 100+ for internal testing
    Example:
      cxg scan --scope example.com --rate-limit 10

SCANNING MODES:
  Different modes for various scanning scenarios and requirements.
  
  --aggressive
    Enable aggressive scanning mode. Uses more intrusive checks and higher concurrency.
    WARNING: May trigger security alerts or cause service disruption.
    Use only with explicit permission on systems you control.
    Example:
      cxg scan --scope test-env.internal --aggressive
  
  --stealth
    Enable stealth mode. Reduces scan footprint, randomizes timing, and mimics normal traffic.
    Slower but less likely to trigger detection systems (IDS/IPS/WAF).
    Automatically reduces concurrency and adds random delays.
    Example:
      cxg scan --scope example.com --stealth
  
  --safe
    Safe mode - excludes potentially harmful checks (DoS, resource exhaustion, etc.).
    Recommended for production systems where availability is critical.
    Example:
      cxg scan --scope production.example.com --safe
  
  --passive
    Passive mode - no active probing. Only analyzes responses from normal requests.
    Safest option but limited detection capabilities. Good for initial reconnaissance.
    Example:
      cxg scan --scope example.com --passive

NETWORK CONFIGURATION:
  Configure network-level settings for scanning through proxies, with custom headers, etc.
  
  --proxy <URL>
    Route all traffic through a proxy. Supports HTTP, HTTPS, and SOCKS5 proxies.
    Useful for scanning from different geographic locations or through corporate proxies.
    Examples:
      cxg scan --scope example.com --proxy http://proxy.corp.com:8080
      cxg scan --scope example.com --proxy socks5://127.0.0.1:1080
  
  --user-agent <STRING>
    Custom User-Agent header. Useful for mimicking specific browsers or tools.
    Default: cert-x-gen/<version>
    Example:
      cxg scan --scope example.com --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  
  --header <KEY:VALUE>
    Add custom HTTP headers. Can be specified multiple times for multiple headers.
    Useful for authentication, API keys, or custom application headers.
    Examples:
      cxg scan --scope api.example.com --header 'Authorization: Bearer token123'
      cxg scan --scope example.com --header 'X-API-Key: abc' --header 'X-Custom: value'
  
  --cookie <KEY=VALUE>
    Add cookies to requests. Can be specified multiple times. Useful for authenticated scans.
    Example:
      cxg scan --scope example.com --cookie 'session=abc123' --cookie 'user=admin'
  
  --follow-redirects
    Follow HTTP redirects automatically. Useful for discovering redirect chains.
    Default: Enabled
    Example:
      cxg scan --scope example.com --follow-redirects --max-redirects 10
  
  --max-redirects <N>
    Maximum number of redirects to follow. Prevents infinite redirect loops.
    Default: 5
    Example:
      cxg scan --scope example.com --max-redirects 3

ADVANCED FEATURES:
  Advanced capabilities for complex scanning scenarios.
  
  --resume <SCAN-ID>
    Resume a previously interrupted scan from where it left off.
    Scan state is automatically saved, allowing recovery from crashes or interruptions.
    Example:
      cxg scan --scope example.com --resume a1b2c3d4-e5f6-7890-abcd-ef1234567890
  
  --distributed
    Enable distributed scanning mode. Coordinates with other scanner instances.
    Allows horizontal scaling across multiple machines for massive scans.
    Example:
      cxg scan --scope @10000-targets.txt --distributed --coordinator http://coordinator:8080
  
  --coordinator <URL>
    URL of the distributed scan coordinator. Required when using --distributed.
    The coordinator manages work distribution and result aggregation.
    Example:
      cxg scan --scope example.com --distributed --coordinator http://192.168.1.100:8080
  
  --worker-id <ID>
    Unique identifier for this worker in distributed mode. Auto-generated if not specified.
    Example:
      cxg scan --scope @targets.txt --distributed --coordinator http://coordinator:8080 --worker-id scanner-01

CONFIGURATION FILES:
  Use configuration files for complex setups and reusable scan profiles.
  
  --config <FILE>
    Load settings from a configuration file (YAML, TOML, or JSON).
    CLI arguments override config file settings.
    Example:
      cxg scan --config production-scan.yaml --scope example.com
  
  --profile <NAME>
    Use a named configuration profile from your config file.
    Profiles allow quick switching between different scanning scenarios.
    Example:
      cxg scan --profile production --scope example.com

COMMON SCANNING SCENARIOS:

1. Quick Vulnerability Assessment (Fast, High-Severity Only):
   cxg scan --scope example.com --severity critical,high --threads 20

2. Comprehensive Security Audit (All Templates, All Severities):
   cxg scan --scope example.com --output-format json,html,sarif

3. Stealth Penetration Test (Low Detection Risk):
   cxg scan --scope example.com --stealth --rate-limit 5 --timeout 60s

4. Production System Scan (Safe, Non-Disruptive):
   cxg scan --scope production.example.com --safe --parallel-templates 3 --rate-limit 10

5. Database Security Scan (Specific Vulnerability Class):
   cxg scan --scope db.example.com --tags database,injection --severity high,critical

6. Authenticated Web Application Scan:
   cxg scan --scope app.example.com --cookie 'session=xyz' --header 'Authorization: Bearer token'

7. Large-Scale Network Scan (Multiple Targets):
   cxg scan --scope @targets.txt --parallel-targets 100 --output-format csv,json

8. API Security Testing:
   cxg scan --scope api.example.com --template-language python --tags api,authentication

9. Compliance Scan (OWASP Top 10):
   cxg scan --scope example.com --templates @owasp-top10.txt --output-format sarif

10. Internal Network Reconnaissance:
    cxg scan --scope 10.0.0.0/24 --passive --top-ports 100 --quiet

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

    /// JSON context passed to templates via CERT_X_GEN_CONTEXT environment variable.
    ///
    /// Templates read this context to receive parameterized input (target URLs,
    /// parameter names, HTTP methods, baselines, etc.) without hardcoding values.
    /// This enables reusable parameterized templates driven by external automation.
    #[arg(
        long,
        value_name = "JSON",
        help = "JSON context for parameterized templates. Passed as CERT_X_GEN_CONTEXT env var. Example: '{\"param_name\":\"username\",\"method\":\"POST\"}'"
    )]
    pub context: Option<String>,

    /// Run only templates belonging to this batch group.
    ///
    /// Batch groups let you execute a cohort of templates that share the same
    /// context shape in a single invocation.
    ///
    /// Common groups: auth-context, endpoint-params, service-ports, full-surface
    #[arg(
        long,
        value_name = "GROUP",
        help = "Run templates in batch group. Example: --batch-group auth-context"
    )]
    pub batch_group: Option<String>,
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
  cxg template list

  # Filter templates
  cxg template list --language python
  cxg template list --language c --severity critical
  cxg template list --tags database,unauthenticated

  # Search templates
  cxg template search redis
  cxg template search \"sql injection\" --language python
  cxg template search unauthenticated --detailed

  # Get template information
  cxg template info redis-unauthenticated
  cxg template info sql-injection-detection

  # Show template directories
  cxg template pwd

  # View skeleton template for a language
  cxg template skeleton python
  cxg template skeleton c

  # Add a local template to cxg
  cxg template add ./my-redis-check.py
  cxg template add ./custom-check.c custom/network

  # Validate templates
  cxg template validate ~/.cert-x-gen/templates/
  cxg template validate ./my-templates/ --recursive
  cxg template validate ./redis-check.c

  # Update templates from repository
  cxg template update
  cxg template update --force

  # Create new template from skeleton
  cxg template create --id my-check --language python --name \"My Check\"
  cxg template create --id redis-test --language c --output ./my-templates/

  # Test a template
  cxg template test --template ./my-template.c --target 192.168.1.100
  cxg template test --template redis-unauthenticated --target localhost --debug"
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

        /// Filter by batch group (e.g. auth-context, endpoint-params)
        #[arg(long, value_name = "GROUP")]
        batch_group: Option<String>,
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

    /// Search templates (shortcut for `cxg search`)
    Search {
        /// Search query
        query: String,

        /// Filter by programming language
        #[arg(long, value_enum, value_name = "LANG")]
        language: Option<LanguageArg>,

        /// Filter by severity level
        #[arg(long, value_enum, value_name = "LEVEL")]
        severity: Option<SeverityArg>,

        /// Filter by tags (comma-separated)
        #[arg(long, value_name = "TAG,TAG,...")]
        tags: Option<String>,

        /// Search in template content/code
        #[arg(long)]
        content: bool,

        /// Show detailed results
        #[arg(long)]
        detailed: bool,

        /// Maximum number of results
        #[arg(long, default_value_t = 50, value_name = "N")]
        limit: usize,
    },

    /// Show the template directories used by cxg
    Pwd,

    /// Display the skeleton/scaffold template for a language
    Skeleton {
        /// Programming language for the skeleton
        #[arg(value_enum, value_name = "LANG")]
        language: LanguageArg,
    },

    /// Add a local template file into the cxg template directory
    Add {
        /// Path to the template file to add
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Destination subdirectory within the user template folder (e.g. "custom/redis")
        #[arg(value_name = "DEST")]
        dest: Option<String>,
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
  cxg search --query \"redis\"
  cxg search --query \"sql injection\"
  cxg search --query \"unauthenticated access\"

  # Language-specific search
  cxg search --language python
  cxg search --language c --query \"buffer overflow\"
  cxg search --language rust --severity critical

  # Severity filtering
  cxg search --severity critical
  cxg search --severity high --language python
  cxg search --severity critical,high

  # Tag-based search
  cxg search --tags database
  cxg search --tags \"database,unauthenticated\"
  cxg search --tags injection --language c

  # Author and CWE filtering
  cxg search --author \"CERT-X-GEN\"
  cxg search --cwe \"CWE-89\"
  cxg search --cwe \"CWE-306\" --severity critical

  # Advanced search with regex
  cxg search --query \"redis|mysql|postgres\" --regex
  cxg search --query \"SQL.*injection\" --regex --case-sensitive

  # Content search (slower but comprehensive)
  cxg search --query \"curl\" --content
  cxg search --query \"SELECT.*FROM\" --content --regex

  # Output formats
  cxg search --query \"redis\" --format table        # Default
  cxg search --query \"redis\" --format json
  cxg search --query \"redis\" --format csv
  cxg search --query \"redis\" --format yaml
  cxg search --query \"redis\" --format detailed

  # Sorting and limiting
  cxg search --query \"injection\" --sort name
  cxg search --query \"injection\" --sort severity --reverse
  cxg search --query \"injection\" --limit 10

  # Get only template IDs (useful for piping to scan)
  cxg search --query \"redis\" --ids-only
  TEMPLATES=$(cxg search --query \"redis\" --ids-only | tr '\\n' ',')
  cxg scan --target example.com --templates \"$TEMPLATES\"

  # Show statistics
  cxg search --query \"redis\" --stats
  cxg search --language python --stats

  # Save results to file
  cxg search --query \"redis\" --output results.json --format json
  cxg search --language c --output c-templates.csv --format csv

  # Complex queries
  cxg search --language python --severity high --tags database --format json
  cxg search --query \"authentication\" --content --case-sensitive --regex
  cxg search --author \"CERT-X-GEN\" --severity critical --sort date --reverse"
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
  cxg server

  # Custom port and bind address
  cxg server --port 8080
  cxg server --bind 0.0.0.0 --port 3000

  # Enable TLS/HTTPS
  cxg server --tls --tls-cert server.crt --tls-key server.key

  # With authentication
  cxg server --auth-token my-secret-token"
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
  cxg config generate
  cxg config generate --output config.yaml
  cxg config generate --format toml --output config.toml

  # Validate configuration
  cxg config validate config.yaml
  cxg config validate production.toml

  # Show current/default configuration
  cxg config show"
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
  cxg sandbox init

  # Initialize specific languages only
  cxg sandbox init --languages python,javascript,ruby

  # Check sandbox status
  cxg sandbox status

  # Install additional packages
  cxg sandbox install python requests beautifulsoup4
  cxg sandbox install javascript axios cheerio

  # Clean sandbox environment
  cxg sandbox clean

  # Access sandbox shell
  cxg sandbox shell

  # Show sandbox location
  cxg sandbox path"
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
/// Use 'cxg sandbox info' to check Docker availability.
/// Use 'cxg sandbox create <name>' to create a Docker sandbox.
#[derive(Debug, Clone, Subcommand)]
pub enum SandboxAction {
    /// Initialize package-level sandbox (legacy mode)
    ///
    /// Creates isolated package directories for Python (venv), JavaScript (node_modules),
    /// Ruby (gems), etc. This mode uses your host system's language runtimes.
    ///
    /// Note: This is a lightweight alternative to Docker sandboxes. For true isolation,
    /// use 'cxg sandbox create <name>' to create a Docker-based sandbox.
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

// ─── MCP Command ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Parser)]
#[command(about = "MCP (Model Context Protocol) server for AI agent integration")]
pub struct McpCommand {
    #[command(subcommand)]
    pub action: Option<McpAction>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum McpAction {
    /// Configure MCP server for AI coding agents (Claude Desktop, Claude Code, Cursor, etc.)
    Install {
        /// Specific clients to configure (comma-separated: claude-desktop,claude-code,cursor,windsurf,vscode,zed)
        #[arg(long)]
        client: Option<String>,
    },
    /// Remove MCP server configuration from AI coding agents
    Uninstall {
        /// Specific clients to unconfigure
        #[arg(long)]
        client: Option<String>,
    },
    /// Show current MCP configuration status across all detected clients
    Status,
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
  cxg ai generate \"detect Redis without authentication\"
  cxg ai generate \"find SQL injection in login forms\"
  cxg ai generate \"check for exposed Memcached\"

  # Specify programming language
  cxg ai generate \"detect Redis unauth\" --language python
  cxg ai generate \"find XSS vulnerabilities\" --language javascript
  cxg ai generate \"check SSL certificates\" --language rust

  # Use specific provider
  cxg ai generate \"detect RCE\" --provider openai --model gpt-4
  cxg ai generate \"find SSRF\" --provider anthropic --model claude-3-5-sonnet-20241022
  cxg ai generate \"check headers\" --provider ollama --model codellama:13b

  # Save to specific location
  cxg ai generate \"Redis check\" --language yaml --output templates/redis-test.yaml
  cxg ai generate \"MySQL scan\" --output mysql-check.py

  # List available providers
  cxg ai providers list
  cxg ai providers list --detailed

  # Test provider connection
  cxg ai providers test ollama
  cxg ai providers test openai

  # Show provider status
  cxg ai providers status

GETTING STARTED WITH OLLAMA (FREE, LOCAL):
  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh
  2. Download model: ollama pull codellama:13b
  3. Start Ollama: ollama serve
  4. Generate: cxg ai generate \"your security check description\"

PROVIDER CONFIGURATION:
  Configure providers in ~/.cert-x-gen/ai-config.yaml or use environment variables:
  - OPENAI_API_KEY for OpenAI
  - ANTHROPIC_API_KEY for Anthropic
  - DEEPSEEK_API_KEY for DeepSeek

For more information: https://github.com/Bugb-Technologies/cert-x-gen/docs/ai-features"
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

        /// API key for the LLM provider (session-only, not persisted to config).
        /// Overrides environment variables and stored config for this invocation.
        /// Use with --provider to specify which provider the key belongs to.
        #[arg(
            long,
            value_name = "KEY",
            help = "API key for the LLM provider (not saved). E.g. --provider anthropic --api-key sk-ant-..."
        )]
        api_key: Option<String>,
    },

    /// Manage LLM providers
    #[command(after_help = "EXAMPLES:
  # List all configured providers
  cxg ai providers list
  cxg ai providers list --detailed
  
  # Test specific provider (comprehensive health check)
  cxg ai providers test ollama
  cxg ai providers test openai
  cxg ai providers test anthropic
  cxg ai providers test deepseek
  
  # Check status of all enabled providers
  cxg ai providers status

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

// @g.comment -- "unit tests for the desktop-target CLI flags (--target-type/--app-cmd/--app-binary), verifying clap's default, validation, and conflicts_with/required_if_eq resolution before wiring them into the orchestrator forwarding"
#[cfg(test)]
mod desktop_flag_tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn target_type_defaults_to_web() {
        let cli = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
        ])
        .expect("should parse");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Run { target_type, .. } = p.action {
                assert_eq!(target_type, "web");
                return;
            }
        }
        panic!("expected pentest run");
    }

    #[test]
    fn electron_requires_a_launch_mechanism() {
        let err = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "electron",
        ]);
        assert!(
            err.is_err(),
            "electron without --app-cmd/--app-binary must fail"
        );
    }

    #[test]
    fn app_cmd_and_app_binary_conflict() {
        let err = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "electron",
            "--app-cmd",
            "npm start",
            "--app-binary",
            "/tmp/a",
        ]);
        assert!(
            err.is_err(),
            "--app-cmd and --app-binary are mutually exclusive"
        );
    }

    #[test]
    fn electron_with_app_cmd_parses() {
        let cli = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "electron",
            "--app-cmd",
            "npm run electron:dev",
        ])
        .expect("should parse");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Run { app_cmd, .. } = p.action {
                assert_eq!(app_cmd.as_deref(), Some("npm run electron:dev"));
                return;
            }
        }
        panic!("expected pentest run");
    }

    // The two dispatch bounds and the recovery opt-out existed in the Python
    // orchestrator only, so they were unreachable from the `cxg` binary: an operator
    // could not raise the per-template ceiling, could not disable the stall watchdog,
    // and could not decline having their application relaunched mid-engagement. This
    // pins that all three now parse and that leaving them off yields None/false, so
    // main.rs forwards nothing and the orchestrator's own defaults stay in force.
    #[test]
    fn timeout_and_restart_flags_parse_and_default_to_unset() {
        let cli = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "electron",
            "--app-cmd",
            "npm start",
            "--template-timeout",
            "1200",
            "--stall-timeout",
            "45",
            "--no-restart",
        ])
        .expect("should parse");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Run {
                template_timeout,
                stall_timeout,
                no_restart,
                ..
            } = p.action
            {
                assert_eq!(template_timeout, Some(1200.0));
                assert_eq!(stall_timeout, Some(45.0));
                assert!(no_restart);
            } else {
                panic!("expected pentest run");
            }
        } else {
            panic!("expected pentest run");
        }

        let bare = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
        ])
        .expect("should parse");
        if let Some(Commands::Pentest(p)) = bare.command {
            if let PentestAction::Run {
                template_timeout,
                stall_timeout,
                no_restart,
                ..
            } = p.action
            {
                assert_eq!(template_timeout, None);
                assert_eq!(stall_timeout, None);
                assert!(!no_restart);
                return;
            }
        }
        panic!("expected pentest run");
    }

    #[test]
    fn rejects_unknown_target_type() {
        assert!(parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "tauri"
        ])
        .is_err());
    }

    #[test]
    fn electron_with_app_binary_alone_parses() {
        // The task brief asserted clap resolves conflicts_with vs required_if_eq
        // correctly for this case. It does not: clap's r_ifs/r_unless validation path
        // (which required_if_eq feeds) never consults conflicts_with, so pairing
        // `conflicts_with = "app_binary"` with `required_if_eq("target_type", "electron")`
        // on app_cmd wrongly demanded --app-cmd even when --app-binary alone was given.
        // Fixed by moving the conditional requirement to a `requires_if("electron",
        // "app_cmd")` on `target_type`, which clap resolves through the ArgGroup-style
        // "is_missing_required_ok" path that DOES check conflicts_with of present args.
        let cli = parse(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
            "--target-type",
            "electron",
            "--app-binary",
            "/tmp/a",
        ])
        .expect("--app-binary alone with --target-type electron should parse");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Run {
                app_binary,
                app_cmd,
                ..
            } = p.action
            {
                assert_eq!(app_binary.as_deref(), Some("/tmp/a"));
                assert_eq!(app_cmd, None);
                return;
            }
        }
        panic!("expected pentest run");
    }

    #[test]
    fn auth_electron_requires_a_launch_mechanism() {
        // Same requires_if wiring was applied to PentestAction::Auth; verify it holds there too.
        let err = parse(&[
            "cxg",
            "pentest",
            "auth",
            "--target",
            "http://x",
            "--profile",
            "p1",
            "--target-type",
            "electron",
        ]);
        assert!(
            err.is_err(),
            "electron without --app-cmd/--app-binary must fail"
        );
    }

    #[test]
    fn auth_electron_with_app_binary_alone_parses() {
        let cli = parse(&[
            "cxg",
            "pentest",
            "auth",
            "--target",
            "http://x",
            "--profile",
            "p1",
            "--target-type",
            "electron",
            "--app-binary",
            "/tmp/a",
        ])
        .expect("--app-binary alone with --target-type electron should parse for auth too");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Auth {
                app_binary,
                app_cmd,
                ..
            } = p.action
            {
                assert_eq!(app_binary.as_deref(), Some("/tmp/a"));
                assert_eq!(app_cmd, None);
                return;
            }
        }
        panic!("expected pentest auth");
    }

    #[test]
    fn auth_electron_with_app_cmd_parses() {
        let cli = parse(&[
            "cxg",
            "pentest",
            "auth",
            "--target",
            "http://x",
            "--profile",
            "p1",
            "--target-type",
            "electron",
            "--app-cmd",
            "npm run electron:dev",
        ])
        .expect("should parse");
        if let Some(Commands::Pentest(p)) = cli.command {
            if let PentestAction::Auth {
                app_cmd,
                app_binary,
                ..
            } = p.action
            {
                assert_eq!(app_cmd.as_deref(), Some("npm run electron:dev"));
                assert_eq!(app_binary, None);
                return;
            }
        }
        panic!("expected pentest auth");
    }

    #[test]
    fn auth_app_cmd_and_app_binary_conflict() {
        let err = parse(&[
            "cxg",
            "pentest",
            "auth",
            "--target",
            "http://x",
            "--profile",
            "p1",
            "--target-type",
            "electron",
            "--app-cmd",
            "npm start",
            "--app-binary",
            "/tmp/a",
        ]);
        assert!(
            err.is_err(),
            "--app-cmd and --app-binary are mutually exclusive for auth too"
        );
    }
}

// @g.comment -- "unit tests for the two OAST modes: that the pollable one parses in both its bare and explicit forms, that clap rejects the pair (a split canary), and — the one that guards backward compatibility — that a lone --oast still parses to exactly what it always did"
#[cfg(test)]
mod oast_flag_tests {
    use super::*;
    use clap::Parser;

    fn run_action(args: &[&str]) -> PentestAction {
        let cli = Cli::try_parse_from(args).expect("should parse");
        match cli.command {
            Some(Commands::Pentest(p)) => p.action,
            _ => panic!("expected pentest"),
        }
    }

    fn base() -> Vec<&'static str> {
        vec![
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "http://x",
        ]
    }

    // Backward compatibility is the whole point of this one: an engagement script
    // that has been passing `--oast <host>` since before the pollable mode existed
    // must still parse to Some(host) with the new flag absent, so main.rs forwards
    // the identical `--oast <host>` and nothing about that run changes.
    #[test]
    fn oast_alone_is_unchanged_and_leaves_interactsh_unset() {
        let mut argv = base();
        argv.extend(["--oast", "c4ca4238a0b92.oastify.com"]);
        if let PentestAction::Run {
            oast,
            oast_interactsh,
            ..
        } = run_action(&argv)
        {
            assert_eq!(oast.as_deref(), Some("c4ca4238a0b92.oastify.com"));
            assert_eq!(oast_interactsh, None);
            return;
        }
        panic!("expected pentest run");
    }

    // The bare form must be distinguishable from absence, not merely falsy: it means
    // "register against interactsh's default servers", which is a request for a
    // canary, whereas None means no canary at all. Some("") vs None is what carries
    // that difference across to the orchestrator.
    #[test]
    fn bare_interactsh_yields_empty_string_not_none() {
        let mut argv = base();
        argv.push("--oast-interactsh");
        if let PentestAction::Run {
            oast,
            oast_interactsh,
            ..
        } = run_action(&argv)
        {
            assert_eq!(oast_interactsh.as_deref(), Some(""));
            assert_eq!(oast, None);
            return;
        }
        panic!("expected pentest run");
    }

    #[test]
    fn interactsh_takes_an_explicit_server_url() {
        let mut argv = base();
        argv.extend(["--oast-interactsh", "https://oast.example.internal"]);
        if let PentestAction::Run {
            oast_interactsh, ..
        } = run_action(&argv)
        {
            assert_eq!(
                oast_interactsh.as_deref(),
                Some("https://oast.example.internal")
            );
            return;
        }
        panic!("expected pentest run");
    }

    // Two canaries would split payloads between a pollable host and an unpollable
    // one, so a blind finding could no longer be said to be confirmed or not.
    // Enforced by clap's conflicts_with, so it fails during parse rather than after
    // AI generation has already spent minutes and API budget.
    #[test]
    fn oast_and_oast_interactsh_conflict() {
        let mut argv = base();
        argv.extend([
            "--oast",
            "c4ca4238a0b92.oastify.com",
            "--oast-interactsh",
            "https://oast.example.internal",
        ]);
        assert!(
            Cli::try_parse_from(&argv).is_err(),
            "--oast and --oast-interactsh are mutually exclusive"
        );

        // Also in the bare form, where the conflict is easiest to write by accident.
        let mut bare = base();
        bare.extend(["--oast", "c4ca4238a0b92.oastify.com", "--oast-interactsh"]);
        assert!(
            Cli::try_parse_from(&bare).is_err(),
            "bare --oast-interactsh must conflict with --oast too"
        );
    }

    // An optional-value flag placed before another flag must not swallow it.
    #[test]
    fn bare_interactsh_does_not_consume_a_following_flag() {
        let mut argv = base();
        argv.extend(["--oast-interactsh", "--headed"]);
        if let PentestAction::Run {
            oast_interactsh,
            headed,
            ..
        } = run_action(&argv)
        {
            assert_eq!(oast_interactsh.as_deref(), Some(""));
            assert!(headed, "--headed must survive the optional-value flag");
            return;
        }
        panic!("expected pentest run");
    }

    #[test]
    fn neither_flag_leaves_both_unset() {
        if let PentestAction::Run {
            oast,
            oast_interactsh,
            ..
        } = run_action(&base())
        {
            assert_eq!(oast, None);
            assert_eq!(oast_interactsh, None);
            return;
        }
        panic!("expected pentest run");
    }
}

// @g.comment -- "unit tests for the Track B CI-auth surface (auth import / auth verify subcommands, and run's --ci/--auth-dir). Track B shipped to the Python orchestrator's argparse only; src/cli.rs was never updated, so the cxg binary rejected the whole surface with 'unexpected argument'. These pin that each subcommand and flag now parses, that the auth capture path is unchanged when no subcommand is given, that the import/verify subcommands do NOT demand the capture path's --target/--profile (the reason those two are Option at the parent), and that the mutually-exclusive capture-args-vs-subcommand constraint holds."
#[cfg(test)]
mod track_b_auth_tests {
    use super::*;
    use clap::Parser;

    fn action(args: &[&str]) -> PentestAction {
        let cli = Cli::try_parse_from(args).expect("should parse");
        match cli.command {
            Some(Commands::Pentest(p)) => p.action,
            _ => panic!("expected pentest"),
        }
    }

    fn err(args: &[&str]) -> bool {
        Cli::try_parse_from(args).is_err()
    }

    // ---- auth import ----

    #[test]
    fn auth_import_parses_full_surface() {
        let a = action(&[
            "cxg",
            "pentest",
            "auth",
            "import",
            "--profile",
            "pentest",
            "--target",
            "https://staging.app",
            "--storage-state",
            "./s.json",
            "--label",
            "admin",
            "--tier",
            "high",
            "--persona",
            "billing",
            "--cohort",
            "team-a",
            "--tag",
            "k1=v1",
            "--tag",
            "k2=v2",
            "--header",
            "x-a:1",
            "--header",
            "x-b:2",
            "--auth-dir",
            "./ci-auth",
            "--ci",
        ]);
        match a {
            PentestAction::Auth {
                auth_sub:
                    Some(AuthSubcommand::Import {
                        profile,
                        target,
                        storage_state,
                        label,
                        tier,
                        persona,
                        cohort,
                        tags,
                        headers,
                        auth_dir,
                        ci,
                    }),
                ..
            } => {
                assert_eq!(profile, "pentest");
                assert_eq!(target, "https://staging.app");
                assert_eq!(storage_state.as_deref(), Some("./s.json"));
                assert_eq!(label.as_deref(), Some("admin"));
                assert_eq!(tier.as_deref(), Some("high"));
                assert_eq!(persona.as_deref(), Some("billing"));
                assert_eq!(cohort.as_deref(), Some("team-a"));
                assert_eq!(tags, vec!["k1=v1", "k2=v2"]);
                assert_eq!(headers, vec!["x-a:1", "x-b:2"]);
                assert_eq!(auth_dir.as_deref(), Some(std::path::Path::new("./ci-auth")));
                assert!(ci);
            }
            _ => panic!("expected auth import"),
        }
    }

    // The whole point of Option-typed parent --target/--profile: `auth import`
    // must NOT inherit the capture path's requirements, only its own.
    #[test]
    fn auth_import_does_not_require_parent_target_or_profile() {
        // import supplies its own --profile/--target and nothing at the parent level.
        let a = action(&[
            "cxg",
            "pentest",
            "auth",
            "import",
            "--profile",
            "p",
            "--target",
            "https://x",
        ]);
        match a {
            PentestAction::Auth {
                target,
                profile,
                auth_sub:
                    Some(AuthSubcommand::Import {
                        storage_state, ci, ..
                    }),
                ..
            } => {
                // parent capture fields stay unset
                assert_eq!(target, None);
                assert_eq!(profile, None);
                // omitting --storage-state is valid (env-var fallback on the Python side)
                assert_eq!(storage_state, None);
                assert!(!ci);
            }
            _ => panic!("expected auth import"),
        }
    }

    #[test]
    fn auth_import_stdin_marker_is_a_value() {
        let a = action(&[
            "cxg",
            "pentest",
            "auth",
            "import",
            "--profile",
            "p",
            "--target",
            "https://x",
            "--storage-state",
            "-",
        ]);
        match a {
            PentestAction::Auth {
                auth_sub: Some(AuthSubcommand::Import { storage_state, .. }),
                ..
            } => assert_eq!(storage_state.as_deref(), Some("-")),
            _ => panic!("expected auth import"),
        }
    }

    #[test]
    fn auth_import_requires_profile_and_target() {
        assert!(
            err(&["cxg", "pentest", "auth", "import", "--target", "https://x"]),
            "import without --profile must fail"
        );
        assert!(
            err(&["cxg", "pentest", "auth", "import", "--profile", "p"]),
            "import without --target must fail"
        );
    }

    // ---- auth verify ----

    #[test]
    fn auth_verify_parses_with_defaults() {
        let a = action(&["cxg", "pentest", "auth", "verify", "--profile", "pentest"]);
        match a {
            PentestAction::Auth {
                auth_sub:
                    Some(AuthSubcommand::Verify {
                        profile,
                        target,
                        me_path,
                        auth_dir,
                    }),
                ..
            } => {
                assert_eq!(profile, "pentest");
                assert_eq!(target, None);
                assert_eq!(me_path, "/api/me"); // mirrors auth.py's default
                assert_eq!(auth_dir, None);
            }
            _ => panic!("expected auth verify"),
        }
    }

    #[test]
    fn auth_verify_accepts_overrides() {
        let a = action(&[
            "cxg",
            "pentest",
            "auth",
            "verify",
            "--profile",
            "p",
            "--target",
            "https://y",
            "--me-path",
            "/whoami",
            "--auth-dir",
            "./ci-auth",
        ]);
        match a {
            PentestAction::Auth {
                auth_sub:
                    Some(AuthSubcommand::Verify {
                        target,
                        me_path,
                        auth_dir,
                        ..
                    }),
                ..
            } => {
                assert_eq!(target.as_deref(), Some("https://y"));
                assert_eq!(me_path, "/whoami");
                assert_eq!(auth_dir.as_deref(), Some(std::path::Path::new("./ci-auth")));
            }
            _ => panic!("expected auth verify"),
        }
    }

    #[test]
    fn auth_verify_requires_profile() {
        assert!(
            err(&["cxg", "pentest", "auth", "verify"]),
            "verify without --profile must fail"
        );
    }

    // ---- interactive capture path is unchanged (no subcommand) ----

    #[test]
    fn bare_auth_capture_still_parses_and_leaves_sub_none() {
        let a = action(&[
            "cxg",
            "pentest",
            "auth",
            "--target",
            "https://x",
            "--profile",
            "p",
        ]);
        match a {
            PentestAction::Auth {
                target,
                profile,
                auth_sub,
                ..
            } => {
                assert_eq!(target.as_deref(), Some("https://x"));
                assert_eq!(profile.as_deref(), Some("p"));
                assert!(auth_sub.is_none(), "no subcommand => interactive capture");
            }
            _ => panic!("expected auth capture"),
        }
    }

    // Capture args and a subcommand are mutually exclusive on one invocation
    // (args_conflicts_with_subcommands): you either capture, or import/verify.
    #[test]
    fn capture_args_conflict_with_subcommand() {
        assert!(
            err(&[
                "cxg",
                "pentest",
                "auth",
                "--target",
                "https://x",
                "import",
                "--profile",
                "p",
                "--target",
                "https://x",
            ]),
            "parent capture args must conflict with a subcommand"
        );
    }

    // ---- run --ci / --auth-dir ----

    #[test]
    fn run_ci_and_auth_dir_parse() {
        let a = action(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "https://x",
            "--ci",
            "--auth-dir",
            "./ci-auth",
        ]);
        match a {
            PentestAction::Run { ci, auth_dir, .. } => {
                assert!(ci);
                assert_eq!(auth_dir.as_deref(), Some(std::path::Path::new("./ci-auth")));
            }
            _ => panic!("expected pentest run"),
        }
    }

    #[test]
    fn run_defaults_leave_ci_false_and_auth_dir_none() {
        let a = action(&[
            "cxg",
            "pentest",
            "run",
            "--codebase",
            ".",
            "--target",
            "https://x",
        ]);
        match a {
            PentestAction::Run { ci, auth_dir, .. } => {
                assert!(!ci, "--ci defaults off, so main.rs forwards nothing");
                assert_eq!(auth_dir, None);
            }
            _ => panic!("expected pentest run"),
        }
    }
}
