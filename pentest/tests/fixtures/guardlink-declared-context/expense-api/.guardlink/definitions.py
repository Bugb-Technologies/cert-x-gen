# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GuardLink Shared Definitions — expense-api
#
# ALL @asset, @threat, and @control declarations live here.
# Source files reference by #id only (e.g. @mitigates X against #sqli).
# Never redeclare an ID that exists in this file.
# Before adding: read this file to check for duplicates.
#
# Run: guardlink validate .
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ─── Examples (uncomment and customize for your project) ────────
#
#   # @asset App.API (#api) -- "Main REST endpoint"
#   # @asset App.Database (#db) -- "Primary data store"
#
#   # @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Unsanitized input reaches SQL query"
#   # @threat Cross_Site_Scripting (#xss) [high] cwe:CWE-79 -- "Unsanitized input rendered in browser"
#   # @threat Broken_Access_Control (#bac) [critical] cwe:CWE-284 -- "Missing or bypassable authorization"
#
#   # @control Parameterized_Queries (#prepared-stmts) -- "SQL queries use bound parameters"
#   # @control Input_Validation (#input-validation) -- "Input validated against schema/allowlist"
#   # @control RBAC (#rbac) -- "Role-based access control"
#
# ─── Your Definitions ──────────────────────────────────────────


# ─── ASSETS ────────────────────────────────────────────────────
# Components that process data, handle user input, or reach external systems.

# @asset Expense.API (#api) -- "Flask HTTP surface — login, expense list/create, receipt download"
# @asset Expense.Auth (#auth) -- "Password hashing, session token minting and verification"
# @asset Expense.DB (#db) -- "SQLite access for users and expenses"
# @asset Expense.Storage (#receipts) -- "Reads and writes receipt files under the upload root"
# @asset Expense.Notify (#notify) -- "Outbound HTTP: team webhooks and the exchange-rate API"
# @asset Expense.Config (#config) -- "Environment-derived configuration, including the token signing secret"

# ─── THREATS ───────────────────────────────────────────────────

# @threat SQL_Injection (#sqli) [critical] cwe:CWE-89 -- "Request values concatenated into a SQL statement instead of bound"
# @threat Path_Traversal (#path-traversal) [high] cwe:CWE-22 -- "A request-supplied filename escapes the upload root"
# @threat Server_Side_Request_Forgery (#ssrf) [high] cwe:CWE-918 -- "A request-supplied URL is fetched by the server"
# @threat Weak_Default_Secret (#weak-secret) [high] cwe:CWE-1188 -- "Signing key falls back to a shipped default when unset"
# @threat Credential_Stuffing (#cred-stuffing) [medium] cwe:CWE-307 -- "Unlimited login attempts against a known username"
# @threat Timing_Disclosure (#timing) [low] cwe:CWE-208 -- "Comparison time varies with how much of a secret matched"
# @threat Rendered_Content_Injection (#xss-by-render) [medium] cwe:CWE-79 -- "Stored file bytes rendered in the application origin instead of downloaded"
# @threat Malformed_Input_Crash (#malformed-input) [low] cwe:CWE-248 -- "Missing or wrong-typed request fields raise, returning a 500"

# ─── CONTROLS ──────────────────────────────────────────────────

# @control Parameterized_Queries (#prepared-stmts) -- "SQL written with ? placeholders and a parameter tuple"
# @control Password_Key_Derivation (#pbkdf2) -- "PBKDF2-HMAC-SHA256, per-user salt, 200,000 iterations"
# @control Constant_Time_Compare (#constant-time) -- "hmac.compare_digest instead of =="
# @control Signed_Session_Token (#hmac-token) -- "HMAC-SHA256 over user id and expiry, verified before use"
# @control Authentication_Required (#auth-required) -- "Route rejects the request with 401 unless a token verifies"
# @control Outbound_Timeout (#http-timeout) -- "Every outbound request carries an explicit timeout"
# @control Non_Rendered_Response (#octet-stream) -- "Bytes returned as application/octet-stream so a browser never renders them"
