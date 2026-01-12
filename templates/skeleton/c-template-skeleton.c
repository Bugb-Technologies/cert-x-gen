// CERT-X-GEN C Template Skeleton
//
// @id: c-template-skeleton
// @name: C Template Skeleton
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Skeleton template for writing security scanning templates in C. Copy this file and customize it for your specific security check.
// @tags: skeleton, example, template, c
// @cwe: CWE-1008
// @confidence: 90
// @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//
// Compilation:
//   gcc template.c -o template -O2 -std=c11
//   ./template --target example.com --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//

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
static char context_raw[1024] = {0};
static char context_add_ports[512] = {0};
static char context_override_ports[512] = {0};

// ========================================
// HELPER FUNCTIONS
// ========================================

// Get environment variable
char* get_env_var(const char* name) {
    return getenv(name);
}

// Parse ports from environment
int parse_ports(const char* ports_str, int* ports, int max_ports) {
    if (!ports_str) return 0;
    
    int count = 0;
    char* str = strdup(ports_str);
    char* token = strtok(str, ",");
    
    while (token && count < max_ports) {
        ports[count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    
    free(str);
    return count;
}

// Get ports to scan
int get_ports_to_scan(int* ports, int max_ports) {
    char* override_ports = get_env_var("CERT_X_GEN_OVERRIDE_PORTS");
    if (override_ports) {
        return parse_ports(override_ports, ports, max_ports);
    }
    
    // Default ports
    ports[0] = 80;
    ports[1] = 443;
    int count = 2;
    
    // Add additional ports
    char* add_ports = get_env_var("CERT_X_GEN_ADD_PORTS");
    if (add_ports) {
        int additional[64];
        int add_count = parse_ports(add_ports, additional, 64);
        for (int i = 0; i < add_count && count < max_ports; i++) {
            ports[count++] = additional[i];
        }
    }
    
    return count;
}

// HTTP response callback for libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* response = (char*)userp;
    strncat(response, (char*)contents, realsize);
    return realsize;
}

// Test HTTP endpoint
int test_http_endpoint(const char* host, int port, char* response, size_t response_size) {
    CURL* curl;
    CURLcode res;
    char url[512];
    
    snprintf(url, sizeof(url), "http://%s:%d/", host, port);
    
    curl = curl_easy_init();
    if (!curl) {
        return 0;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 1 : 0;
}

// Check for vulnerability indicators
int check_vulnerability(const char* response) {
    if (!response) return 0;
    
    // Check for common vulnerability indicators
    if (strstr(response, "vulnerable") || 
        strstr(response, "exposed") ||
        strstr(response, "admin") ||
        strstr(response, "debug")) {
        return 1;
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
    
    // Calculate CVSS score based on severity
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
    
    strncpy(finding->remediation, "Review the identified issue and apply security patches", 
            sizeof(finding->remediation) - 1);
    strncpy(finding->references, "https://cwe.mitre.org/,https://nvd.nist.gov/", 
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

// ========================================
// MAIN SCANNING LOGIC
// ========================================

int execute_scan() {
    Finding findings[64];
    int finding_count = 0;
    
    int port = target_port;
    char response[8192] = {0};
    
    // Test HTTP endpoint
    if (test_http_endpoint(target_host, port, response, sizeof(response))) {
        if (check_vulnerability(response)) {
            char evidence[2048];
            char title[512];
            char description[1024];
            
            snprintf(evidence, sizeof(evidence), 
                    "{\"endpoint\": \"http://%s:%d\", \"response_size\": %zu}", 
                    target_host, port, strlen(response));
            
            snprintf(title, sizeof(title), "Potential Vulnerability on %s:%d", 
                    target_host, port);
            
            snprintf(description, sizeof(description), 
                    "Found potential vulnerability indicators on %s:%d", 
                    target_host, port);
            
            create_finding(&findings[finding_count], title, description, evidence, "high");
            finding_count++;
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
            printf("\n[+] Found %d issue(s):\n\n", finding_count);
            for (int i = 0; i < finding_count; i++) {
                printf("[%s] %s\n", findings[i].severity, findings[i].title);
                printf("    %s\n", findings[i].description);
                printf("\n");
            }
        } else {
            printf("\n[-] No issues found\n");
        }
    }
    
    return finding_count;
}

// ========================================
// CLI AND EXECUTION
// ========================================

void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS] <target>\n\n", program_name);
    printf("%s\n", config.name);
    printf("\nOptions:\n");
    printf("  --target <HOST>  Target host or IP address\n");
    printf("  --port <PORT>    Target port (default: 80)\n");
    printf("  --json           Output findings as JSON\n");
    printf("  --help           Show this help message\n");
    printf("\nExample:\n");
    printf("  %s --target example.com --port 443 --json\n", program_name);
}

int parse_args(int argc, char* argv[]) {
    // Initialize default config
    strncpy(config.id, "template-skeleton", sizeof(config.id) - 1);
    strncpy(config.name, "C Template Skeleton", sizeof(config.name) - 1);
    strncpy(config.author, "Your Name", sizeof(config.author) - 1);
    strncpy(config.severity, "high", sizeof(config.severity) - 1);
    config.confidence = 90;
    strncpy(config.tags, "skeleton,example", sizeof(config.tags) - 1);
    strncpy(config.cwe, "CWE-XXX", sizeof(config.cwe) - 1);
    
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
            print_usage(argv[0]);
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

    char* ctx = get_env_var("CERT_X_GEN_CONTEXT");
    if (ctx) {
        strncpy(context_raw, ctx, sizeof(context_raw) - 1);
    }

    char* add_ports = get_env_var("CERT_X_GEN_ADD_PORTS");
    if (add_ports) {
        strncpy(context_add_ports, add_ports, sizeof(context_add_ports) - 1);
    }

    char* override_ports = get_env_var("CERT_X_GEN_OVERRIDE_PORTS");
    if (override_ports) {
        strncpy(context_override_ports, override_ports, sizeof(context_override_ports) - 1);
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
