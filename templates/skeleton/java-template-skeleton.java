// CERT-X-GEN Java Template Skeleton
//
// @id: java-template-skeleton
// @name: Java Template Skeleton
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Skeleton template for writing security scanning templates in Java. Copy this file and customize it for your specific security check.
// @tags: skeleton, example, template, java
// @cwe: CWE-1008
// @confidence: 90
// @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//
// Compilation:
//   javac Template.java
//   java Template --target example.com --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

public class Template {
    
    // Template configuration
    private static class TemplateConfig {
        String id = "template-skeleton";
        String name = "Java Template Skeleton";
        String author = "Your Name";
        String severity = "high";
        int confidence = 90;
        List<String> tags = Arrays.asList("skeleton", "example");
        String cwe = "CWE-XXX";
    }
    
    // Finding structure
    private static class Finding {
        String template_id;
        String severity;
        int confidence;
        String title;
        String description;
        Map<String, String> evidence;
        String cwe;
        double cvss_score;
        String remediation;
        List<String> references;
        
        Finding() {
            evidence = new HashMap<>();
            references = new ArrayList<>();
        }
    }
    
    // Global variables
    private static TemplateConfig config = new TemplateConfig();
    private static String targetHost = "";
    private static int targetPort = 80;
    private static boolean jsonOutput = false;
    private static Map<String, String> contextData = new HashMap<>();
    
    // ========================================
    // HELPER FUNCTIONS
    // ========================================
    
    // Get environment variable
    private static String getEnvVar(String name) {
        return System.getenv(name);
    }
    
    // Parse ports from string
    private static List<Integer> parsePorts(String portsStr) {
        List<Integer> ports = new ArrayList<>();
        if (portsStr == null || portsStr.isEmpty()) {
            return ports;
        }
        
        String[] parts = portsStr.split(",");
        for (String part : parts) {
            try {
                ports.add(Integer.parseInt(part.trim()));
            } catch (NumberFormatException e) {
                // Skip invalid ports
            }
        }
        return ports;
    }
    
    // Get ports to scan
    private static List<Integer> getPortsToScan() {
        String overridePorts = getEnvVar("CERT_X_GEN_OVERRIDE_PORTS");
        if (overridePorts != null && !overridePorts.isEmpty()) {
            return parsePorts(overridePorts);
        }
        
        // Default ports
        List<Integer> ports = new ArrayList<>(Arrays.asList(80, 443));
        
        // Add additional ports
        String addPorts = getEnvVar("CERT_X_GEN_ADD_PORTS");
        if (addPorts != null && !addPorts.isEmpty()) {
            List<Integer> additional = parsePorts(addPorts);
            ports.addAll(additional);
        }
        
        // Remove duplicates
        Set<Integer> uniquePorts = new LinkedHashSet<>(ports);
        return new ArrayList<>(uniquePorts);
    }
    
    // Test HTTP endpoint
    private static String testHttpEndpoint(String host, int port) {
        try {
            URL url = new URL("http://" + host + ":" + port + "/");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setInstanceFollowRedirects(true);
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                
                // Read first 1024 characters
                int count = 0;
                while ((line = reader.readLine()) != null && count < 1024) {
                    response.append(line);
                    count += line.length();
                }
                reader.close();
                
                return response.toString();
            }
        } catch (Exception e) {
            // Connection failed
        }
        return null;
    }
    
    // Check for vulnerability indicators
    private static boolean checkVulnerability(String response) {
        if (response == null || response.isEmpty()) {
            return false;
        }
        
        String lowerResponse = response.toLowerCase();
        String[] indicators = {"vulnerable", "exposed", "admin", "debug", "test", "demo"};
        
        for (String indicator : indicators) {
            if (lowerResponse.contains(indicator)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Create a finding
    private static Finding createFinding(String title, String description, 
                                       Map<String, String> evidence, String severity) {
        Finding finding = new Finding();
        finding.template_id = config.id;
        finding.severity = (severity != null && !severity.isEmpty()) ? severity : config.severity;
        finding.confidence = config.confidence;
        finding.title = title;
        finding.description = description;
        finding.evidence = evidence;
        finding.cwe = config.cwe;
        
        // Calculate CVSS score based on severity
        switch (finding.severity) {
            case "critical":
                finding.cvss_score = 9.0;
                break;
            case "high":
                finding.cvss_score = 7.5;
                break;
            case "medium":
                finding.cvss_score = 5.0;
                break;
            case "low":
                finding.cvss_score = 3.0;
                break;
            default:
                finding.cvss_score = 0.0;
        }
        
        finding.remediation = "Review the identified issue and apply security patches";
        finding.references = Arrays.asList("https://cwe.mitre.org/", "https://nvd.nist.gov/");
        
        return finding;
    }
    
    // Output finding as JSON
    private static void outputFindingJson(Finding finding) {
        System.out.println("  {");
        System.out.println("    \"template_id\": \"" + finding.template_id + "\",");
        System.out.println("    \"severity\": \"" + finding.severity + "\",");
        System.out.println("    \"confidence\": " + finding.confidence + ",");
        System.out.println("    \"title\": \"" + finding.title + "\",");
        System.out.println("    \"description\": \"" + finding.description + "\",");
        
        // Output evidence as JSON object
        System.out.println("    \"evidence\": {");
        boolean first = true;
        for (Map.Entry<String, String> entry : finding.evidence.entrySet()) {
            if (!first) System.out.println(",");
            System.out.print("      \"" + entry.getKey() + "\": \"" + entry.getValue() + "\"");
            first = false;
        }
        System.out.println("\n    },");
        
        System.out.println("    \"cwe\": \"" + finding.cwe + "\",");
        System.out.println("    \"cvss_score\": " + finding.cvss_score + ",");
        System.out.println("    \"remediation\": \"" + finding.remediation + "\",");
        
        // Output references as JSON array
        System.out.print("    \"references\": [");
        for (int i = 0; i < finding.references.size(); i++) {
            if (i > 0) System.out.print(", ");
            System.out.print("\"" + finding.references.get(i) + "\"");
        }
        System.out.println("]");
        System.out.println("  }");
    }
    
    // ========================================
    // MAIN SCANNING LOGIC
    // ========================================
    
    private static List<Finding> executeScan() {
        List<Finding> findings = new ArrayList<>();
        int port = targetPort;
        String response = testHttpEndpoint(targetHost, port);
        if (response != null && checkVulnerability(response)) {
            Map<String, String> evidence = new HashMap<>();
            evidence.put("endpoint", "http://" + targetHost + ":" + port);
            evidence.put("response_size", String.valueOf(response.length()));
            evidence.put("status", "vulnerable");
            
            String title = "Potential Vulnerability on " + targetHost + ":" + port;
            String description = "Found potential vulnerability indicators on " + targetHost + ":" + port;
            
            findings.add(createFinding(title, description, evidence, "high"));
        }
        
        return findings;
    }
    
    // ========================================
    // CLI AND EXECUTION
    // ========================================
    
    private static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " [OPTIONS] <target>");
        System.out.println();
        System.out.println(config.name);
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --target <HOST>  Target host or IP address");
        System.out.println("  --port <PORT>    Target port (default: 80)");
        System.out.println("  --json           Output findings as JSON");
        System.out.println("  --help           Show this help message");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  java " + programName + " --target example.com --port 443 --json");
    }
    
    private static boolean parseArgs(String[] args) {
        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            
            switch (arg) {
                case "--target":
                    if (i + 1 < args.length) {
                        targetHost = args[++i];
                    } else {
                        System.err.println("Error: --target requires an argument");
                        return false;
                    }
                    break;
                case "--port":
                    if (i + 1 < args.length) {
                        try {
                            targetPort = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Error: Invalid port number");
                            return false;
                        }
                    } else {
                        System.err.println("Error: --port requires an argument");
                        return false;
                    }
                    break;
                case "--json":
                    jsonOutput = true;
                    break;
                case "--help":
                case "-h":
                    printUsage("Template");
                    System.exit(0);
                    break;
                default:
                    if (targetHost.isEmpty() && !arg.startsWith("-")) {
                        targetHost = arg;
                    }
                    break;
            }
        }
        
        // Check environment variables (for CERT-X-GEN engine integration)
        if (targetHost.isEmpty()) {
            targetHost = getEnvVar("CERT_X_GEN_TARGET_HOST");
        }
        
        String portStr = getEnvVar("CERT_X_GEN_TARGET_PORT");
        if (portStr != null && !portStr.isEmpty()) {
            try {
                targetPort = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                // Keep default port
            }
        }
        
        if (getEnvVar("CERT_X_GEN_MODE") != null) {
            jsonOutput = true;
        }
        
        String ctx = getEnvVar("CERT_X_GEN_CONTEXT");
        if (ctx != null && !ctx.isEmpty()) {
            contextData.put("raw_context", ctx);
        }
        String addPorts = getEnvVar("CERT_X_GEN_ADD_PORTS");
        if (addPorts != null && !addPorts.isEmpty()) {
            contextData.put("add_ports", addPorts);
        }
        String overridePorts = getEnvVar("CERT_X_GEN_OVERRIDE_PORTS");
        if (overridePorts != null && !overridePorts.isEmpty()) {
            contextData.put("override_ports", overridePorts);
        }
        
        if (targetHost.isEmpty()) {
            System.err.println("Error: No target specified");
            return false;
        }
        
        return true;
    }
    
    public static void main(String[] args) {
        // Parse arguments
        if (!parseArgs(args)) {
            System.exit(1);
        }
        
        // Print banner (if not JSON output)
        if (!jsonOutput) {
            System.out.println("\n╔════════════════════════════════════════════════════════════╗");
            System.out.printf("║  %-52s ║%n", config.name);
            System.out.println("║  CERT-X-GEN Security Template                              ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝\n");
            System.out.println("Target: " + targetHost + ":" + targetPort);
        }
        
        // Execute the scan
        List<Finding> findings = executeScan();
        
        // Output findings
        if (jsonOutput) {
            System.out.println("[");
            for (int i = 0; i < findings.size(); i++) {
                if (i > 0) System.out.println(",");
                outputFindingJson(findings.get(i));
            }
            System.out.println("]");
        } else {
            if (findings.isEmpty()) {
                System.out.println("\n[-] No issues found");
            } else {
                System.out.println("\n[+] Found " + findings.size() + " issue(s):\n");
                for (Finding finding : findings) {
                    System.out.println("[" + finding.severity + "] " + finding.title);
                    System.out.println("    " + finding.description + "\n");
                }
            }
        }
    }
}
