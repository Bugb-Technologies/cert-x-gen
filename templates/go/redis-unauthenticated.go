package main

// @id: redis-unauthenticated-go
// @name: Redis Unauthenticated Access Detection (Go)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using Go
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Metadata represents template metadata
type Metadata struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Language    string            `json:"language"`
	Confidence  int               `json:"confidence"`
	CWE         []string          `json:"cwe"`
	References  []string          `json:"references"`
	Author      map[string]string `json:"author"`
}

// Evidence represents finding evidence
type Evidence struct {
	Request         string                 `json:"request"`
	Response        string                 `json:"response"`
	MatchedPatterns []string               `json:"matched_patterns"`
	Data            map[string]interface{} `json:"data"`
}

// Finding represents a security finding
type Finding struct {
	Target      string   `json:"target"`
	TemplateID  string   `json:"template_id"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    Evidence `json:"evidence"`
	CWEIDs      []string `json:"cwe_ids"`
	Tags        []string `json:"tags"`
	Timestamp   string   `json:"timestamp"`
}

// Result represents the scan result
type Result struct {
	Findings []Finding `json:"findings"`
	Metadata Metadata  `json:"metadata"`
}

var metadata = Metadata{
	ID:          "redis-unauthenticated-go",
	Name:        "Redis Unauthenticated Access Detection (Go)",
	Severity:    "critical",
	Description: "Detects Redis instances exposed without authentication using Go",
	Tags:        []string{"redis", "unauthenticated", "database", "nosql", "go"},
	Language:    "go",
	Confidence:  95,
	CWE:         []string{"CWE-306"},
	References: []string{
		"https://redis.io/docs/management/security/",
		"https://cwe.mitre.org/data/definitions/306.html",
	},
	Author: map[string]string{
		"name":  "CERT-X-GEN Security Team",
		"email": "security@cert-x-gen.io",
	},
}

func testRedis(host string, port int, timeout time.Duration) []Finding {
	findings := []Finding{}

	// Use net.JoinHostPort for proper IPv6 support
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return findings
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Send test commands
	commands := []string{
		"INFO\r\n",
		"PING\r\n",
		"*1\r\n$4\r\nINFO\r\n",
		"*1\r\n$4\r\nPING\r\n",
	}

	for _, cmd := range commands {
		conn.Write([]byte(cmd))
	}

	// Read response
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil && n == 0 {
		return findings
	}

	responseData := string(buffer[:n])

	// Check for Redis indicators
	indicators := []string{
		"redis_version",
		"redis_mode",
		"used_memory",
		"connected_clients",
		"role:master",
		"role:slave",
		"+PONG",
	}

	matchedPatterns := []string{}
	for _, indicator := range indicators {
		if strings.Contains(responseData, indicator) {
			matchedPatterns = append(matchedPatterns, indicator)
		}
	}

	if len(matchedPatterns) > 0 {
		finding := Finding{
			Target:      address,
			TemplateID:  metadata.ID,
			Severity:    metadata.Severity,
			Confidence:  metadata.Confidence,
			Title:       metadata.Name,
			Description: metadata.Description,
			Evidence: Evidence{
				Request:         strings.Join(commands, "\\n"),
				Response:        responseData[:min(len(responseData), 1000)],
				MatchedPatterns: matchedPatterns,
				Data: map[string]interface{}{
					"protocol":        "tcp",
					"port":            port,
					"response_length": len(responseData),
				},
			},
			CWEIDs:    metadata.CWE,
			Tags:      metadata.Tags,
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		}
		findings = append(findings, finding)
	}

	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	// Support both CLI args and environment variables (for engine mode)
	var host string
	var port int
	
	if os.Getenv("CERT_X_GEN_MODE") == "engine" {
		// Engine mode - read from environment variables
		host = os.Getenv("CERT_X_GEN_TARGET_HOST")
		portStr := os.Getenv("CERT_X_GEN_TARGET_PORT")
		if portStr == "" {
			port = 6379
		} else {
			var err error
			port, err = strconv.Atoi(portStr)
			if err != nil {
				port = 6379
			}
		}
		if host == "" {
			result := map[string]string{"error": "CERT_X_GEN_TARGET_HOST not set"}
			json.NewEncoder(os.Stdout).Encode(result)
			os.Exit(1)
		}
	} else {
		// CLI mode - read from command-line arguments
		if len(os.Args) < 2 {
			result := map[string]string{"error": "Usage: redis-unauthenticated <host> [port]"}
			json.NewEncoder(os.Stdout).Encode(result)
			os.Exit(1)
		}
		host = os.Args[1]
		port = 6379
		if len(os.Args) > 2 {
			var err error
			port, err = strconv.Atoi(os.Args[2])
			if err != nil {
				port = 6379
			}
		}
	}

	findings := testRedis(host, port, 10*time.Second)

	result := Result{
		Findings: findings,
		Metadata: metadata,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(result)
}
