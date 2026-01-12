// @id: redis-unauthenticated-c
// @name: Redis Unauthenticated Access Detection (C)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using C
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

// Escape JSON string
void escape_json(const char* input, char* output, size_t max_len) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < max_len - 10; i++) {
        switch (input[i]) {
            case '"':  output[j++] = '\\'; output[j++] = '"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:
                if (input[i] < 32) {
                    j += snprintf(output + j, max_len - j, "\\u%04x", (unsigned char)input[i]);
                } else {
                    output[j++] = input[i];
                }
        }
    }
    output[j] = '\0';
}

int test_redis(const char* host, int port) {
    struct hostent* server = gethostbyname(host);
    if (!server) return 0;
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;
    
    struct timeval timeout = {10, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return 0;
    }
    
    // Send commands
    const char* commands[] = {
        "INFO\r\n",
        "PING\r\n",
        "*1\r\n$4\r\nINFO\r\n",
        "*1\r\n$4\r\nPING\r\n"
    };
    
    for (int i = 0; i < 4; i++) {
        send(sockfd, commands[i], strlen(commands[i]), 0);
    }
    
    usleep(300000); // 300ms
    
    // Read response
    char buffer[8192];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    close(sockfd);
    
    if (n <= 0) return 0;
    buffer[n] = '\0';
    
    // Check indicators
    const char* indicators[] = {
        "redis_version", "redis_mode", "used_memory",
        "connected_clients", "role:master", "role:slave", "+PONG"
    };
    int matched[7] = {0};
    int match_count = 0;
    
    for (int i = 0; i < 7; i++) {
        if (strstr(buffer, indicators[i])) {
            matched[i] = 1;
            match_count++;
        }
    }
    
    if (match_count == 0) return 0;
    
    // Generate JSON output
    char escaped_response[2048];
    escape_json(buffer, escaped_response, sizeof(escaped_response));
    
    // Truncate response to 1000 chars
    if (strlen(escaped_response) > 1000) {
        escaped_response[1000] = '\0';
    }
    
    time_t now = time(NULL);
    struct tm* tm_info = gmtime(&now);
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S.000Z", tm_info);
    
    printf("{\n");
    printf("  \"findings\": [\n");
    printf("    {\n");
    printf("      \"target\": \"%s:%d\",\n", host, port);
    printf("      \"template_id\": \"redis-unauthenticated-c\",\n");
    printf("      \"severity\": \"critical\",\n");
    printf("      \"confidence\": 95,\n");
    printf("      \"title\": \"Redis Unauthenticated Access Detection (C)\",\n");
    printf("      \"description\": \"Detects Redis instances exposed without authentication using C\",\n");
    printf("      \"evidence\": {\n");
    printf("        \"request\": \"INFO\\\\r\\\\nPING\\\\r\\\\n*1\\\\r\\\\n$4\\\\r\\\\nINFO\\\\r\\\\n*1\\\\r\\\\n$4\\\\r\\\\nPING\\\\r\\\\n\",\n");
    printf("        \"response\": \"%s\",\n", escaped_response);
    printf("        \"matched_patterns\": [");
    int first = 1;
    for (int i = 0; i < 7; i++) {
        if (matched[i]) {
            if (!first) printf(", ");
            printf("\"%s\"", indicators[i]);
            first = 0;
        }
    }
    printf("],\n");
    printf("        \"data\": {\n");
    printf("          \"protocol\": \"tcp\",\n");
    printf("          \"port\": %d,\n", port);
    printf("          \"response_length\": %zd\n", n);
    printf("        }\n");
    printf("      },\n");
    printf("      \"cwe_ids\": [\"CWE-306\"],\n");
    printf("      \"tags\": [\"redis\", \"unauthenticated\", \"database\", \"nosql\", \"c\"],\n");
    printf("      \"timestamp\": \"%s\"\n", timestamp);
    printf("    }\n");
    printf("  ],\n");
    printf("  \"metadata\": {\n");
    printf("    \"id\": \"redis-unauthenticated-c\",\n");
    printf("    \"name\": \"Redis Unauthenticated Access Detection (C)\",\n");
    printf("    \"severity\": \"critical\",\n");
    printf("    \"language\": \"c\",\n");
    printf("    \"confidence\": 95\n");
    printf("  }\n");
    printf("}\n");
    
    return 1;
}

int main(int argc, char* argv[]) {
    char* host = NULL;
    int port = 6379;
    
    // Support both CLI args and environment variables (for engine mode)
    char* mode = getenv("CERT_X_GEN_MODE");
    if (mode && strcmp(mode, "engine") == 0) {
        // Engine mode
        host = getenv("CERT_X_GEN_TARGET_HOST");
        if (!host) {
            fprintf(stderr, "{\"error\": \"CERT_X_GEN_TARGET_HOST not set\"}\n");
            return 1;
        }
        char* port_str = getenv("CERT_X_GEN_TARGET_PORT");
        if (port_str) port = atoi(port_str);
    } else {
        // CLI mode
        if (argc < 2) {
            fprintf(stderr, "{\"error\": \"Usage: %s <host> [port]\"}\n", argv[0]);
            return 1;
        }
        host = argv[1];
        if (argc > 2) port = atoi(argv[2]);
    }
    
    if (!test_redis(host, port)) {
        // No findings
        printf("{\n");
        printf("  \"findings\": [],\n");
        printf("  \"metadata\": {\n");
        printf("    \"id\": \"redis-unauthenticated-c\",\n");
        printf("    \"name\": \"Redis Unauthenticated Access Detection (C)\",\n");
        printf("    \"severity\": \"critical\",\n");
        printf("    \"language\": \"c\",\n");
        printf("    \"confidence\": 95\n");
        printf("  }\n");
        printf("}\n");
    }
    
    return 0;
}
