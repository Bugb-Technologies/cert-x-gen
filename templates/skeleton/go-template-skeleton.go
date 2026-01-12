// CERT-X-GEN Go Template Skeleton
//
// @id: go-template-skeleton
// @name: Go Template Skeleton
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Skeleton template for writing security scanning templates in Go. Copy this file and customize it for your specific security check.
// @tags: skeleton, example, template, go
// @cwe: CWE-1008
// @confidence: 90
// @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//
// Compilation:
//   go build -o template template.go
//   ./template --target example.com --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Template configuration
type TemplateConfig struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Author     string   `json:"author"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Tags       []string `json:"tags"`
	CWE        string   `json:"cwe"`
}

// Finding structure
type Finding struct {
	TemplateID  string            `json:"template_id"`
	Severity    string            `json:"severity"`
	Confidence  int               `json:"confidence"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence"`
	CWE         string            `json:"cwe"`
	CVSSScore   float64           `json:"cvss_score"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
}

// Global variables
var config TemplateConfig
var targetHost string
var targetPort int = 80
var jsonOutput bool = false
var contextData map[string]interface{}

// ========================================
// HELPER FUNCTIONS
// ========================================

// Get environment variable
func getEnvVar(name string) string {
	return os.Getenv(name)
}

// Parse ports from string
func parsePorts(portsStr string) []int {
	var ports []int
	if portsStr == "" {
		return ports
	}

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		if port, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

// Get ports to scan
func getPortsToScan() []int {
	overridePorts := getEnvVar("CERT_X_GEN_OVERRIDE_PORTS")
	if overridePorts != "" {
		return parsePorts(overridePorts)
	}

	// Default ports
	ports := []int{80, 443}

	// Add additional ports
	addPorts := getEnvVar("CERT_X_GEN_ADD_PORTS")
	if addPorts != "" {
		additional := parsePorts(addPorts)
		ports = append(ports, additional...)
	}

	// Remove duplicates
	portMap := make(map[int]bool)
	var uniquePorts []int
	for _, port := range ports {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	return uniquePorts
}

// Test HTTP endpoint
func testHTTPEndpoint(host string, port int) (string, error) {
	url := fmt.Sprintf("http://%s:%d/", host, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body (first 1024 bytes)
	buffer := make([]byte, 1024)
	n, _ := resp.Body.Read(buffer)

	return string(buffer[:n]), nil
}

// Check for vulnerability indicators
func checkVulnerability(response string) bool {
	if response == "" {
		return false
	}

	response = strings.ToLower(response)
	indicators := []string{"vulnerable", "exposed", "admin", "debug", "test", "demo"}

	for _, indicator := range indicators {
		if strings.Contains(response, indicator) {
			return true
		}
	}

	return false
}

// Create a finding
func createFinding(title, description string, evidence map[string]string, severity string) Finding {
	if severity == "" {
		severity = config.Severity
	}

	// Calculate CVSS score based on severity
	var cvssScore float64
	switch severity {
	case "critical":
		cvssScore = 9.0
	case "high":
		cvssScore = 7.5
	case "medium":
		cvssScore = 5.0
	case "low":
		cvssScore = 3.0
	default:
		cvssScore = 0.0
	}

	return Finding{
		TemplateID:  config.ID,
		Severity:    severity,
		Confidence:  config.Confidence,
		Title:       title,
		Description: description,
		Evidence:    evidence,
		CWE:         config.CWE,
		CVSSScore:   cvssScore,
		Remediation: "Review the identified issue and apply security patches",
		References:  []string{"https://cwe.mitre.org/", "https://nvd.nist.gov/"},
	}
}

// ========================================
// MAIN SCANNING LOGIC
// ========================================

func executeScan() []Finding {
	var findings []Finding
	port := targetPort
	response, err := testHTTPEndpoint(targetHost, port)
	if err != nil {
		return findings
	}

	if checkVulnerability(response) {
		evidence := map[string]string{
			"endpoint":      fmt.Sprintf("http://%s:%d", targetHost, port),
			"response_size": fmt.Sprintf("%d", len(response)),
			"status":        "vulnerable",
		}

		title := fmt.Sprintf("Potential Vulnerability on %s:%d", targetHost, port)
		description := fmt.Sprintf("Found potential vulnerability indicators on %s:%d", targetHost, port)

		findings = append(findings, createFinding(title, description, evidence, "high"))
	}

	return findings
}

// ========================================
// CLI AND EXECUTION
// ========================================

func printUsage(programName string) {
	fmt.Printf("Usage: %s [OPTIONS] <target>\n\n", programName)
	fmt.Printf("%s\n", config.Name)
	fmt.Println("\nOptions:")
	fmt.Println("  --target <HOST>  Target host or IP address")
	fmt.Println("  --port <PORT>    Target port (default: 80)")
	fmt.Println("  --json           Output findings as JSON")
	fmt.Println("  --help           Show this help message")
	fmt.Printf("\nExample:\n")
	fmt.Printf("  %s --target example.com --port 443 --json\n", programName)
}

func parseArgs(args []string) bool {
	// Initialize default config
	config = TemplateConfig{
		ID:         "template-skeleton",
		Name:       "Go Template Skeleton",
		Author:     "Your Name",
		Severity:   "high",
		Confidence: 90,
		Tags:       []string{"skeleton", "example"},
		CWE:        "CWE-XXX",
	}

	// Parse command line arguments
	for i := 1; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--target":
			if i+1 < len(args) {
				targetHost = args[i+1]
				i++
			} else {
				fmt.Fprintf(os.Stderr, "Error: --target requires an argument\n")
				return false
			}
		case "--port":
			if i+1 < len(args) {
				if port, err := strconv.Atoi(args[i+1]); err == nil {
					targetPort = port
				} else {
					fmt.Fprintf(os.Stderr, "Error: Invalid port number\n")
					return false
				}
				i++
			} else {
				fmt.Fprintf(os.Stderr, "Error: --port requires an argument\n")
				return false
			}
		case "--json":
			jsonOutput = true
		case "--help", "-h":
			printUsage(args[0])
			os.Exit(0)
		default:
			if targetHost == "" && !strings.HasPrefix(arg, "-") {
				targetHost = arg
			}
		}
	}

	// Check environment variables (for CERT-X-GEN engine integration)
	if targetHost == "" {
		targetHost = getEnvVar("CERT_X_GEN_TARGET_HOST")
	}

	if portStr := getEnvVar("CERT_X_GEN_TARGET_PORT"); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			targetPort = port
		}
	}

	if getEnvVar("CERT_X_GEN_MODE") != "" {
		jsonOutput = true
	}

	if ctx := getEnvVar("CERT_X_GEN_CONTEXT"); ctx != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(ctx), &parsed); err == nil {
			contextData = parsed
		}
	}

	if add := getEnvVar("CERT_X_GEN_ADD_PORTS"); add != "" {
		if contextData == nil {
			contextData = make(map[string]interface{})
		}
		contextData["add_ports"] = add
	}

	if override := getEnvVar("CERT_X_GEN_OVERRIDE_PORTS"); override != "" {
		if contextData == nil {
			contextData = make(map[string]interface{})
		}
		contextData["override_ports"] = override
	}

	if targetHost == "" {
		fmt.Fprintf(os.Stderr, "Error: No target specified\n")
		return false
	}

	return true
}

func main() {
	// Parse arguments
	if !parseArgs(os.Args) {
		os.Exit(1)
	}

	// Print banner (if not JSON output)
	if !jsonOutput {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Printf("║  %-52s ║\n", config.Name)
		fmt.Println("║  CERT-X-GEN Security Template                              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝\n")
		fmt.Printf("Target: %s:%d\n", targetHost, targetPort)
	}

	// Execute the scan
	findings := executeScan()

	// Output findings
	if jsonOutput {
		jsonData, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		if len(findings) == 0 {
			fmt.Println("\n[-] No issues found")
		} else {
			fmt.Printf("\n[+] Found %d issue(s):\n\n", len(findings))
			for _, finding := range findings {
				fmt.Printf("[%s] %s\n", finding.Severity, finding.Title)
				fmt.Printf("    %s\n\n", finding.Description)
			}
		}
	}
}
