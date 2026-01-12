// @id: redis-unauthenticated-cpp
// @name: Redis Unauthenticated Access Detection (C++)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using C++
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>

struct Evidence {
    std::string request;
    std::string response;
    std::vector<std::string> matched_patterns;
    std::string protocol;
    int port;
    size_t response_length;
};

struct Finding {
    std::string target;
    std::string template_id;
    std::string severity;
    int confidence;
    std::string title;
    std::string description;
    Evidence evidence;
    std::vector<std::string> cwe_ids;
    std::vector<std::string> tags;
    std::string timestamp;
};

std::string get_timestamp() {
    time_t now = time(nullptr);
    struct tm* tm_info = gmtime(&now);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S.000Z", tm_info);
    return std::string(buffer);
}

std::string escape_json(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c < 32) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    escaped += buf;
                } else {
                    escaped += c;
                }
        }
    }
    return escaped;
}

std::vector<Finding> test_redis(const std::string& host, int port) {
    std::vector<Finding> findings;
    
    // Resolve hostname
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) {
        return findings;
    }
    
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return findings;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Connect
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return findings;
    }
    
    // Send test commands
    std::vector<std::string> commands = {
        "INFO\r\n",
        "PING\r\n",
        "*1\r\n$4\r\nINFO\r\n",
        "*1\r\n$4\r\nPING\r\n"
    };
    
    for (const auto& cmd : commands) {
        send(sockfd, cmd.c_str(), cmd.length(), 0);
    }
    
    // Wait for response
    usleep(300000); // 300ms
    
    // Read response
    char buffer[8192];
    std::string response_data;
    ssize_t n;
    
    while ((n = recv(sockfd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT)) > 0) {
        buffer[n] = '\0';
        response_data += buffer;
    }
    
    close(sockfd);
    
    if (response_data.empty()) {
        return findings;
    }
    
    // Check for Redis indicators
    std::vector<std::string> indicators = {
        "redis_version",
        "redis_mode",
        "used_memory",
        "connected_clients",
        "role:master",
        "role:slave",
        "+PONG"
    };
    
    std::vector<std::string> matched_patterns;
    for (const auto& indicator : indicators) {
        if (response_data.find(indicator) != std::string::npos) {
            matched_patterns.push_back(indicator);
        }
    }
    
    if (!matched_patterns.empty()) {
        Finding finding;
        finding.target = host + ":" + std::to_string(port);
        finding.template_id = "redis-unauthenticated-cpp";
        finding.severity = "critical";
        finding.confidence = 95;
        finding.title = "Redis Unauthenticated Access Detection (C++)";
        finding.description = "Detects Redis instances exposed without authentication using C++";
        
        finding.evidence.request = "INFO\\r\\nPING\\r\\n*1\\r\\n$4\\r\\nINFO\\r\\n*1\\r\\n$4\\r\\nPING\\r\\n";
        finding.evidence.response = response_data.substr(0, 1000);
        finding.evidence.matched_patterns = matched_patterns;
        finding.evidence.protocol = "tcp";
        finding.evidence.port = port;
        finding.evidence.response_length = response_data.length();
        
        finding.cwe_ids = {"CWE-306"};
        finding.tags = {"redis", "unauthenticated", "database", "nosql", "cpp"};
        finding.timestamp = get_timestamp();
        
        findings.push_back(finding);
    }
    
    return findings;
}

void print_json_output(const std::vector<Finding>& findings) {
    std::cout << "{\n";
    std::cout << "  \"findings\": [\n";
    
    for (size_t i = 0; i < findings.size(); i++) {
        const auto& f = findings[i];
        std::cout << "    {\n";
        std::cout << "      \"target\": \"" << f.target << "\",\n";
        std::cout << "      \"template_id\": \"" << f.template_id << "\",\n";
        std::cout << "      \"severity\": \"" << f.severity << "\",\n";
        std::cout << "      \"confidence\": " << f.confidence << ",\n";
        std::cout << "      \"title\": \"" << f.title << "\",\n";
        std::cout << "      \"description\": \"" << f.description << "\",\n";
        std::cout << "      \"evidence\": {\n";
        std::cout << "        \"request\": \"" << f.evidence.request << "\",\n";
        std::cout << "        \"response\": \"" << escape_json(f.evidence.response) << "\",\n";
        std::cout << "        \"matched_patterns\": [";
        for (size_t j = 0; j < f.evidence.matched_patterns.size(); j++) {
            std::cout << "\"" << f.evidence.matched_patterns[j] << "\"";
            if (j < f.evidence.matched_patterns.size() - 1) std::cout << ", ";
        }
        std::cout << "],\n";
        std::cout << "        \"data\": {\n";
        std::cout << "          \"protocol\": \"" << f.evidence.protocol << "\",\n";
        std::cout << "          \"port\": " << f.evidence.port << ",\n";
        std::cout << "          \"response_length\": " << f.evidence.response_length << "\n";
        std::cout << "        }\n";
        std::cout << "      },\n";
        std::cout << "      \"cwe_ids\": [";
        for (size_t j = 0; j < f.cwe_ids.size(); j++) {
            std::cout << "\"" << f.cwe_ids[j] << "\"";
            if (j < f.cwe_ids.size() - 1) std::cout << ", ";
        }
        std::cout << "],\n";
        std::cout << "      \"tags\": [";
        for (size_t j = 0; j < f.tags.size(); j++) {
            std::cout << "\"" << f.tags[j] << "\"";
            if (j < f.tags.size() - 1) std::cout << ", ";
        }
        std::cout << "],\n";
        std::cout << "      \"timestamp\": \"" << f.timestamp << "\"\n";
        std::cout << "    }";
        if (i < findings.size() - 1) std::cout << ",";
        std::cout << "\n";
    }
    
    std::cout << "  ],\n";
    std::cout << "  \"metadata\": {\n";
    std::cout << "    \"id\": \"redis-unauthenticated-cpp\",\n";
    std::cout << "    \"name\": \"Redis Unauthenticated Access Detection (C++)\",\n";
    std::cout << "    \"severity\": \"critical\",\n";
    std::cout << "    \"language\": \"cpp\",\n";
    std::cout << "    \"confidence\": 95\n";
    std::cout << "  }\n";
    std::cout << "}\n";
}

int main(int argc, char* argv[]) {
    std::string host;
    int port = 6379;
    
    // Support both CLI args and environment variables (for engine mode)
    const char* mode_env = std::getenv("CERT_X_GEN_MODE");
    if (mode_env && std::string(mode_env) == "engine") {
        // Engine mode - read from environment variables
        const char* host_env = std::getenv("CERT_X_GEN_TARGET_HOST");
        if (!host_env) {
            std::cerr << "{\"error\": \"CERT_X_GEN_TARGET_HOST not set\"}\n";
            return 1;
        }
        host = host_env;
        
        const char* port_env = std::getenv("CERT_X_GEN_TARGET_PORT");
        if (port_env) {
            port = std::atoi(port_env);
        }
    } else {
        // CLI mode - read from command-line arguments
        if (argc < 2) {
            std::cerr << "{\"error\": \"Usage: redis-unauthenticated <host> [port]\"}\n";
            return 1;
        }
        host = argv[1];
        if (argc > 2) {
            port = std::atoi(argv[2]);
        }
    }
    
    auto findings = test_redis(host, port);
    print_json_output(findings);
    
    return 0;
}
