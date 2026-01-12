// CERT-X-GEN C++ Template Skeleton
//
// @id: cpp-template-skeleton
// @name: C++ Template Skeleton
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Skeleton template for writing security scanning templates in C++. Copy this file and customize it for your specific security check.
// @tags: skeleton, example, template, cpp
// @cwe: CWE-1008
// @confidence: 90
// @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//
// Compilation:
//   g++ template.cpp -o template -O2 -std=c++17
//   ./template --target example.com --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>
#include <curl/curl.h>
#include <json/json.h>

// Template configuration
struct TemplateConfig {
    std::string id = "template-skeleton";
    std::string name = "C++ Template Skeleton";
    std::string author = "Your Name";
    std::string severity = "high";
    int confidence = 90;
    std::vector<std::string> tags = {"skeleton", "example"};
    std::string cwe = "CWE-XXX";
};

// Finding structure
struct Finding {
    std::string template_id;
    std::string severity;
    int confidence;
    std::string title;
    std::string description;
    std::map<std::string, std::string> evidence;
    std::string cwe;
    float cvss_score;
    std::string remediation;
    std::vector<std::string> references;
    
    Finding() : confidence(90), cvss_score(5.0) {}
};

// Global variables
static TemplateConfig config;
static std::string target_host;
static int target_port = 80;
static bool json_output = false;
static std::map<std::string, std::string> context_data;

// ========================================
// HELPER FUNCTIONS
// ========================================

// Get environment variable
std::string get_env_var(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : "";
}

// Parse ports from string
std::vector<int> parse_ports(const std::string& ports_str) {
    std::vector<int> ports;
    std::stringstream ss(ports_str);
    std::string token;
    
    while (std::getline(ss, token, ',')) {
        try {
            ports.push_back(std::stoi(token));
        } catch (const std::exception&) {
            // Skip invalid ports
        }
    }
    
    return ports;
}

// Get ports to scan
std::vector<int> get_ports_to_scan() {
    std::string override_ports = get_env_var("CERT_X_GEN_OVERRIDE_PORTS");
    if (!override_ports.empty()) {
        return parse_ports(override_ports);
    }
    
    // Default ports
    std::vector<int> ports = {80, 443};
    
    // Add additional ports
    std::string add_ports = get_env_var("CERT_X_GEN_ADD_PORTS");
    if (!add_ports.empty()) {
        std::vector<int> additional = parse_ports(add_ports);
        ports.insert(ports.end(), additional.begin(), additional.end());
    }
    
    // Remove duplicates and sort
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    
    return ports;
}

// HTTP response callback for libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t realsize = size * nmemb;
    response->append((char*)contents, realsize);
    return realsize;
}

// Test HTTP endpoint
bool test_http_endpoint(const std::string& host, int port, std::string& response) {
    CURL* curl;
    CURLcode res;
    std::string url = "http://" + host + ":" + std::to_string(port) + "/";
    
    curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK);
}

// Check for vulnerability indicators
bool check_vulnerability(const std::string& response) {
    if (response.empty()) return false;
    
    // Convert to lowercase for case-insensitive search
    std::string lower_response = response;
    std::transform(lower_response.begin(), lower_response.end(), lower_response.begin(), ::tolower);
    
    // Check for common vulnerability indicators
    std::vector<std::string> indicators = {
        "vulnerable", "exposed", "admin", "debug", "test", "demo"
    };
    
    for (const auto& indicator : indicators) {
        if (lower_response.find(indicator) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Create a finding
Finding create_finding(const std::string& title, const std::string& description, 
                      const std::map<std::string, std::string>& evidence, 
                      const std::string& severity = "") {
    Finding finding;
    finding.template_id = config.id;
    finding.severity = severity.empty() ? config.severity : severity;
    finding.confidence = config.confidence;
    finding.title = title;
    finding.description = description;
    finding.evidence = evidence;
    finding.cwe = config.cwe;
    
    // Calculate CVSS score based on severity
    if (finding.severity == "critical") {
        finding.cvss_score = 9.0;
    } else if (finding.severity == "high") {
        finding.cvss_score = 7.5;
    } else if (finding.severity == "medium") {
        finding.cvss_score = 5.0;
    } else if (finding.severity == "low") {
        finding.cvss_score = 3.0;
    } else {
        finding.cvss_score = 0.0;
    }
    
    finding.remediation = "Review the identified issue and apply security patches";
    finding.references = {"https://cwe.mitre.org/", "https://nvd.nist.gov/"};
    
    return finding;
}

// Output finding as JSON
void output_finding_json(const Finding& finding) {
    std::cout << "  {\n";
    std::cout << "    \"template_id\": \"" << finding.template_id << "\",\n";
    std::cout << "    \"severity\": \"" << finding.severity << "\",\n";
    std::cout << "    \"confidence\": " << finding.confidence << ",\n";
    std::cout << "    \"title\": \"" << finding.title << "\",\n";
    std::cout << "    \"description\": \"" << finding.description << "\",\n";
    
    // Output evidence as JSON object
    std::cout << "    \"evidence\": {\n";
    bool first = true;
    for (const auto& pair : finding.evidence) {
        if (!first) std::cout << ",\n";
        std::cout << "      \"" << pair.first << "\": \"" << pair.second << "\"";
        first = false;
    }
    std::cout << "\n    },\n";
    
    std::cout << "    \"cwe\": \"" << finding.cwe << "\",\n";
    std::cout << "    \"cvss_score\": " << finding.cvss_score << ",\n";
    std::cout << "    \"remediation\": \"" << finding.remediation << "\",\n";
    
    // Output references as JSON array
    std::cout << "    \"references\": [";
    for (size_t i = 0; i < finding.references.size(); i++) {
        if (i > 0) std::cout << ", ";
        std::cout << "\"" << finding.references[i] << "\"";
    }
    std::cout << "]\n";
    std::cout << "  }";
}

// ========================================
// MAIN SCANNING LOGIC
// ========================================

std::vector<Finding> execute_scan() {
    std::vector<Finding> findings;
    int port = target_port;
    std::string response;
    
    // Test HTTP endpoint
    if (test_http_endpoint(target_host, port, response)) {
        if (check_vulnerability(response)) {
            std::map<std::string, std::string> evidence;
            evidence["endpoint"] = "http://" + target_host + ":" + std::to_string(port);
            evidence["response_size"] = std::to_string(response.length());
            evidence["status"] = "vulnerable";
            
            std::string title = "Potential Vulnerability on " + target_host + ":" + std::to_string(port);
            std::string description = "Found potential vulnerability indicators on " + target_host + ":" + std::to_string(port);
            
            findings.push_back(create_finding(title, description, evidence, "high"));
        }
    }
    
    return findings;
}

// ========================================
// CLI AND EXECUTION
// ========================================

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS] <target>\n\n";
    std::cout << config.name << "\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --target <HOST>  Target host or IP address\n";
    std::cout << "  --port <PORT>    Target port (default: 80)\n";
    std::cout << "  --json           Output findings as JSON\n";
    std::cout << "  --help           Show this help message\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " --target example.com --port 443 --json\n";
}

bool parse_args(int argc, char* argv[]) {
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--target") {
            if (i + 1 < argc) {
                target_host = argv[++i];
            } else {
                std::cerr << "Error: --target requires an argument\n";
                return false;
            }
        } else if (arg == "--port") {
            if (i + 1 < argc) {
                target_port = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: --port requires an argument\n";
                return false;
            }
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            exit(0);
        } else if (target_host.empty() && arg[0] != '-') {
            target_host = arg;
        }
    }
    
    // Check environment variables (for CERT-X-GEN engine integration)
    if (target_host.empty()) {
        target_host = get_env_var("CERT_X_GEN_TARGET_HOST");
    }
    
    std::string port_str = get_env_var("CERT_X_GEN_TARGET_PORT");
    if (!port_str.empty()) {
        try {
            target_port = std::stoi(port_str);
        } catch (const std::exception&) {
            // Keep default port
        }
    }
    
    if (!get_env_var("CERT_X_GEN_MODE").empty()) {
        json_output = true;
    }

    std::string ctx = get_env_var("CERT_X_GEN_CONTEXT");
    if (!ctx.empty()) {
        context_data["raw_context"] = ctx;
    }
    std::string add_ports = get_env_var("CERT_X_GEN_ADD_PORTS");
    if (!add_ports.empty()) {
        context_data["add_ports"] = add_ports;
    }
    std::string override_ports = get_env_var("CERT_X_GEN_OVERRIDE_PORTS");
    if (!override_ports.empty()) {
        context_data["override_ports"] = override_ports;
    }
    
    if (target_host.empty()) {
        std::cerr << "Error: No target specified" << std::endl;
        return false;
    }
    
    return true;
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
        std::cout << "\n╔════════════════════════════════════════════════════════════╗\n";
        std::cout << "║  " << std::left << std::setw(52) << config.name << " ║\n";
        std::cout << "║  CERT-X-GEN Security Template                              ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════╝\n\n";
        std::cout << "Target: " << target_host << ":" << target_port << "\n";
    }
    
    // Execute the scan
    std::vector<Finding> findings = execute_scan();
    
    // Output findings
    if (json_output) {
        std::cout << "[\n";
        for (size_t i = 0; i < findings.size(); i++) {
            if (i > 0) std::cout << ",\n";
            output_finding_json(findings[i]);
        }
        std::cout << "\n]\n";
    } else {
        if (findings.empty()) {
            std::cout << "\n[-] No issues found\n";
        } else {
            std::cout << "\n[+] Found " << findings.size() << " issue(s):\n\n";
            for (const auto& finding : findings) {
                std::cout << "[" << finding.severity << "] " << finding.title << "\n";
                std::cout << "    " << finding.description << "\n\n";
            }
        }
    }
    
    // Cleanup
    curl_global_cleanup();
    
    return 0;
}
