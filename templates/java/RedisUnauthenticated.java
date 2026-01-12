// @id: redis-unauthenticated-java
// @name: Redis Unauthenticated Access Detection (Java)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using Java
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

import java.io.*;
import java.net.*;
import java.util.*;
import java.time.Instant;

class Evidence {
    String request;
    String response;
    List<String> matched_patterns;
    Map<String, Object> data;
    
    public Evidence(String request, String response, List<String> patterns, String protocol, int port, int responseLength) {
        this.request = request;
        this.response = response;
        this.matched_patterns = patterns;
        this.data = new HashMap<>();
        this.data.put("protocol", protocol);
        this.data.put("port", port);
        this.data.put("response_length", responseLength);
    }
}

class Finding {
    String target;
    String template_id;
    String severity;
    int confidence;
    String title;
    String description;
    Evidence evidence;
    List<String> cwe_ids;
    List<String> tags;
    String timestamp;
    
    public Finding(String target, String templateId, String severity, int confidence,
                   String title, String description, Evidence evidence,
                   List<String> cweIds, List<String> tags, String timestamp) {
        this.target = target;
        this.template_id = templateId;
        this.severity = severity;
        this.confidence = confidence;
        this.title = title;
        this.description = description;
        this.evidence = evidence;
        this.cwe_ids = cweIds;
        this.tags = tags;
        this.timestamp = timestamp;
    }
}

class Metadata {
    String id;
    String name;
    String severity;
    String language;
    int confidence;
    
    public Metadata(String id, String name, String severity, String language, int confidence) {
        this.id = id;
        this.name = name;
        this.severity = severity;
        this.language = language;
        this.confidence = confidence;
    }
}

class Output {
    List<Finding> findings;
    Metadata metadata;
    
    public Output(List<Finding> findings, Metadata metadata) {
        this.findings = findings;
        this.metadata = metadata;
    }
}

public class RedisUnauthenticated {
    
    private static List<Finding> testRedis(String host, int port) {
        List<Finding> findings = new ArrayList<>();
        
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), 10000);
            socket.setSoTimeout(2000);
            
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            
            // Send test commands
            String[] commands = {
                "INFO\r\n",
                "PING\r\n",
                "*1\r\n$4\r\nINFO\r\n",
                "*1\r\n$4\r\nPING\r\n"
            };
            
            for (String cmd : commands) {
                out.write(cmd.getBytes());
            }
            out.flush();
            
            // Wait for response
            Thread.sleep(300);
            
            // Read response
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            try {
                while ((bytesRead = in.read(buffer)) != -1) {
                    responseStream.write(buffer, 0, bytesRead);
                }
            } catch (SocketTimeoutException e) {
                // Timeout is ok, we have partial data
            }
            
            socket.close();
            
            String responseData = responseStream.toString("UTF-8");
            
            if (responseData.isEmpty()) {
                return findings;
            }
            
            // Check for Redis indicators
            String[] indicators = {
                "redis_version",
                "redis_mode",
                "used_memory",
                "connected_clients",
                "role:master",
                "role:slave",
                "+PONG"
            };
            
            List<String> matchedPatterns = new ArrayList<>();
            for (String indicator : indicators) {
                if (responseData.contains(indicator)) {
                    matchedPatterns.add(indicator);
                }
            }
            
            if (!matchedPatterns.isEmpty()) {
                String request = String.join("\\n", commands);
                String response = responseData.substring(0, Math.min(responseData.length(), 1000));
                
                Evidence evidence = new Evidence(
                    request,
                    response,
                    matchedPatterns,
                    "tcp",
                    port,
                    responseData.length()
                );
                
                Finding finding = new Finding(
                    host + ":" + port,
                    "redis-unauthenticated-java",
                    "critical",
                    95,
                    "Redis Unauthenticated Access Detection (Java)",
                    "Detects Redis instances exposed without authentication using Java",
                    evidence,
                    Arrays.asList("CWE-306"),
                    Arrays.asList("redis", "unauthenticated", "database", "nosql", "java"),
                    Instant.now().toString()
                );
                
                findings.add(finding);
            }
            
        } catch (Exception e) {
            // Connection failed, return empty findings
        }
        
        return findings;
    }
    
    public static void main(String[] args) {
        String host;
        int port = 6379;
        
        // Support both CLI args and environment variables (for engine mode)
        String mode = System.getenv("CERT_X_GEN_MODE");
        if ("engine".equals(mode)) {
            // Engine mode - read from environment variables
            host = System.getenv("CERT_X_GEN_TARGET_HOST");
            if (host == null) {
                System.err.println("{\"error\": \"CERT_X_GEN_TARGET_HOST not set\"}");
                System.exit(1);
            }
            
            String portEnv = System.getenv("CERT_X_GEN_TARGET_PORT");
            if (portEnv != null) {
                try {
                    port = Integer.parseInt(portEnv);
                } catch (NumberFormatException e) {
                    port = 6379;
                }
            }
        } else {
            // CLI mode - read from command-line arguments
            if (args.length < 1) {
                System.err.println("{\"error\": \"Usage: java RedisUnauthenticated <host> [port]\"}");
                System.exit(1);
            }
            host = args[0];
            if (args.length > 1) {
                try {
                    port = Integer.parseInt(args[1]);
                } catch (NumberFormatException e) {
                    port = 6379;
                }
            }
        }
        
        List<Finding> findings = testRedis(host, port);
        
        Metadata metadata = new Metadata(
            "redis-unauthenticated-java",
            "Redis Unauthenticated Access Detection (Java)",
            "critical",
            "java",
            95
        );
        
        // Manual JSON output (no Gson dependency)
        System.out.println("{");
        System.out.println("  \"findings\": [");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            System.out.println("    {");
            System.out.println("      \"target\": \"" + escapeJson(f.target) + "\",");
            System.out.println("      \"template_id\": \"" + escapeJson(f.template_id) + "\",");
            System.out.println("      \"severity\": \"" + escapeJson(f.severity) + "\",");
            System.out.println("      \"confidence\": " + f.confidence + ",");
            System.out.println("      \"title\": \"" + escapeJson(f.title) + "\",");
            System.out.println("      \"description\": \"" + escapeJson(f.description) + "\",");
            System.out.println("      \"evidence\": {");
            System.out.println("        \"request\": \"" + escapeJson(f.evidence.request) + "\",");
            System.out.println("        \"response\": \"" + escapeJson(f.evidence.response) + "\",");
            System.out.print("        \"matched_patterns\": [");
            for (int j = 0; j < f.evidence.matched_patterns.size(); j++) {
                System.out.print("\"" + escapeJson(f.evidence.matched_patterns.get(j)) + "\"");
                if (j < f.evidence.matched_patterns.size() - 1) System.out.print(", ");
            }
            System.out.println("],");
            System.out.println("        \"data\": {");
            System.out.println("          \"protocol\": \"" + f.evidence.data.get("protocol") + "\",");
            System.out.println("          \"port\": " + f.evidence.data.get("port") + ",");
            System.out.println("          \"response_length\": " + f.evidence.data.get("response_length"));
            System.out.println("        }");
            System.out.println("      },");
            System.out.print("      \"cwe_ids\": [");
            for (int j = 0; j < f.cwe_ids.size(); j++) {
                System.out.print("\"" + escapeJson(f.cwe_ids.get(j)) + "\"");
                if (j < f.cwe_ids.size() - 1) System.out.print(", ");
            }
            System.out.println("],");
            System.out.print("      \"tags\": [");
            for (int j = 0; j < f.tags.size(); j++) {
                System.out.print("\"" + escapeJson(f.tags.get(j)) + "\"");
                if (j < f.tags.size() - 1) System.out.print(", ");
            }
            System.out.println("],");
            System.out.println("      \"timestamp\": \"" + escapeJson(f.timestamp) + "\"");
            System.out.print("    }");
            if (i < findings.size() - 1) System.out.print(",");
            System.out.println();
        }
        System.out.println("  ],");
        System.out.println("  \"metadata\": {");
        System.out.println("    \"id\": \"" + escapeJson(metadata.id) + "\",");
        System.out.println("    \"name\": \"" + escapeJson(metadata.name) + "\",");
        System.out.println("    \"severity\": \"" + escapeJson(metadata.severity) + "\",");
        System.out.println("    \"language\": \"" + escapeJson(metadata.language) + "\",");
        System.out.println("    \"confidence\": " + metadata.confidence);
        System.out.println("  }");
        System.out.println("}");
    }
    
    private static String escapeJson(String str) {
        if (str == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
