<?php
/**
 * CERT-X-GEN PHP Template Skeleton
 * 
 * This is a skeleton template for writing security scanning templates in PHP.
 * Copy this file and customize it for your specific security check.
 * 
 * Template Metadata:
 *   ID: template-skeleton
 *   Name: PHP Template Skeleton
 *   Author: Your Name
 *   Severity: high
 *   Tags: skeleton, example
 *   Language: php
 * 
 * Execution:
 *   php template.php --target example.com --json
 * 
 * Dependencies:
 *   - PHP standard library (cURL, JSON, etc.)
 */

// Template configuration
class TemplateConfig {
    public $id = 'template-skeleton';
    public $name = 'PHP Template Skeleton';
    public $author = 'Your Name';
    public $severity = 'high';
    public $confidence = 90;
    public $tags = ['skeleton', 'example'];
    public $cwe = 'CWE-XXX';
}

// Finding structure
class Finding {
    public $template_id;
    public $severity;
    public $confidence;
    public $title;
    public $description;
    public $evidence;
    public $cwe;
    public $cvss_score;
    public $remediation;
    public $references;
    
    public function __construct() {
        $this->evidence = [];
        $this->references = [];
    }
    
    public function toArray() {
        return [
            'template_id' => $this->template_id,
            'severity' => $this->severity,
            'confidence' => $this->confidence,
            'title' => $this->title,
            'description' => $this->description,
            'evidence' => $this->evidence,
            'cwe' => $this->cwe,
            'cvss_score' => $this->cvss_score,
            'remediation' => $this->remediation,
            'references' => $this->references
        ];
    }
}

// Main template class
class CertXGenTemplate {
    private $config;
    private $target_host;
    private $target_port;
    private $json_output;
    private $context;
    
    public function __construct() {
        $this->config = new TemplateConfig();
        $this->target_host = null;
        $this->target_port = 80;
        $this->json_output = false;
        $this->context = [];
    }
    
    // ========================================
    // HELPER FUNCTIONS
    // ========================================
    
    // Get environment variable
    private function getEnvVar($name) {
        return getenv($name) ?: null;
    }
    
    // Parse ports from string
    private function parsePorts($ports_str) {
        if (empty($ports_str)) {
            return [];
        }
        
        $parts = explode(',', $ports_str);
        $ports = [];
        
        foreach ($parts as $part) {
            $port = intval(trim($part));
            if ($port > 0) {
                $ports[] = $port;
            }
        }
        
        return $ports;
    }
    
    // Get ports to scan
    private function getPortsToScan() {
        $override_ports = $this->getEnvVar('CERT_X_GEN_OVERRIDE_PORTS');
        if ($override_ports) {
            return $this->parsePorts($override_ports);
        }
        
        // Default ports
        $ports = [80, 443];
        
        // Add additional ports
        $add_ports = $this->getEnvVar('CERT_X_GEN_ADD_PORTS');
        if ($add_ports) {
            $additional = $this->parsePorts($add_ports);
            $ports = array_merge($ports, $additional);
        }
        
        // Remove duplicates and sort
        $ports = array_unique($ports);
        sort($ports);
        
        return $ports;
    }
    
    // Test HTTP endpoint
    private function testHttpEndpoint($host, $port) {
        $url = "http://{$host}:{$port}/";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'CERT-X-GEN/1.0');
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($response !== false && $http_code == 200) {
            return substr($response, 0, 1024); // First 1024 characters
        }
        
        return null;
    }
    
    // Check for vulnerability indicators
    private function checkVulnerability($response) {
        if (empty($response)) {
            return false;
        }
        
        $response_lower = strtolower($response);
        $indicators = ['vulnerable', 'exposed', 'admin', 'debug', 'test', 'demo'];
        
        foreach ($indicators as $indicator) {
            if (strpos($response_lower, $indicator) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    // Create a finding
    private function createFinding($title, $description, $evidence, $severity = null) {
        $finding = new Finding();
        $finding->template_id = $this->config->id;
        $finding->severity = $severity ?: $this->config->severity;
        $finding->confidence = $this->config->confidence;
        $finding->title = $title;
        $finding->description = $description;
        $finding->evidence = $evidence;
        $finding->cwe = $this->config->cwe;
        
        // Calculate CVSS score based on severity
        switch ($finding->severity) {
            case 'critical':
                $finding->cvss_score = 9.0;
                break;
            case 'high':
                $finding->cvss_score = 7.5;
                break;
            case 'medium':
                $finding->cvss_score = 5.0;
                break;
            case 'low':
                $finding->cvss_score = 3.0;
                break;
            default:
                $finding->cvss_score = 0.0;
        }
        
        $finding->remediation = 'Review the identified issue and apply security patches';
        $finding->references = ['https://cwe.mitre.org/', 'https://nvd.nist.gov/'];
        
        return $finding;
    }
    
    // ========================================
    // MAIN SCANNING LOGIC
    // ========================================
    
    private function executeScan() {
        $findings = [];
        $port = $this->target_port;
        
        $response = $this->testHttpEndpoint($this->target_host, $port);
        if ($response && $this->checkVulnerability($response)) {
            $evidence = [
                'endpoint' => "http://{$this->target_host}:{$port}",
                'response_size' => strlen($response),
                'status' => 'vulnerable'
            ];
            
            $title = "Potential Vulnerability on {$this->target_host}:{$port}";
            $description = "Found potential vulnerability indicators on {$this->target_host}:{$port}";
            
            $findings[] = $this->createFinding($title, $description, $evidence, 'high');
        }
        
        return $findings;
    }
    
    // ========================================
    // CLI AND EXECUTION
    // ========================================
    
    private function printUsage($program_name) {
        echo "Usage: {$program_name} [OPTIONS] <target>\n\n";
        echo "{$this->config->name}\n\n";
        echo "Options:\n";
        echo "  --target <HOST>  Target host or IP address\n";
        echo "  --port <PORT>    Target port (default: 80)\n";
        echo "  --json           Output findings as JSON\n";
        echo "  --help           Show this help message\n\n";
        echo "Example:\n";
        echo "  {$program_name} --target example.com --port 443 --json\n";
    }
    
    private function parseArgs($args) {
        $options = getopt('', ['target:', 'port:', 'json', 'help']);
        
        if (isset($options['help'])) {
            $this->printUsage(basename($args[0]));
            exit(0);
        }
        
        if (isset($options['target'])) {
            $this->target_host = $options['target'];
        }
        
        if (isset($options['port'])) {
            $this->target_port = intval($options['port']);
        }
        
        if (isset($options['json'])) {
            $this->json_output = true;
        }
        
        // Get target from remaining arguments
        if (!$this->target_host) {
            foreach ($args as $arg) {
                if (!str_starts_with($arg, '-')) {
                    $this->target_host = $arg;
                    break;
                }
            }
        }
        
        // Check environment variables (for CERT-X-GEN engine integration)
        if (!$this->target_host) {
            $this->target_host = $this->getEnvVar('CERT_X_GEN_TARGET_HOST');
        }
        
        $port_str = $this->getEnvVar('CERT_X_GEN_TARGET_PORT');
        if ($port_str) {
            $this->target_port = intval($port_str);
        }
        
        if ($this->getEnvVar('CERT_X_GEN_MODE')) {
            $this->json_output = true;
        }

        if ($ctx = $this->getEnvVar('CERT_X_GEN_CONTEXT')) {
            $decoded = json_decode($ctx, true);
            if (is_array($decoded)) {
                $this->context = $decoded;
            }
        }

        if ($add = $this->getEnvVar('CERT_X_GEN_ADD_PORTS')) {
            if (!is_array($this->context)) {
                $this->context = [];
            }
            $this->context['add_ports'] = $add;
        }

        if ($override = $this->getEnvVar('CERT_X_GEN_OVERRIDE_PORTS')) {
            if (!is_array($this->context)) {
                $this->context = [];
            }
            $this->context['override_ports'] = $override;
        }
        
        if (!$this->target_host) {
            fwrite(STDERR, "Error: No target specified\n");
            return false;
        }
        
        return true;
    }
    
    public function run() {
        global $argv;
        
        // Parse arguments
        if (!$this->parseArgs($argv)) {
            return 1;
        }
        
        // Print banner (if not JSON output)
        if (!$this->json_output) {
            echo "\n╔════════════════════════════════════════════════════════════╗\n";
            printf("║  %-52s ║\n", $this->config->name);
            echo "║  CERT-X-GEN Security Template                              ║\n";
            echo "╚════════════════════════════════════════════════════════════╝\n\n";
            echo "Target: {$this->target_host}:{$this->target_port}\n";
        }
        
        // Execute the scan
        $findings = $this->executeScan();
        
        // Output findings
        if ($this->json_output) {
            echo json_encode($findings, JSON_PRETTY_PRINT);
        } else {
            if (empty($findings)) {
                echo "\n[-] No issues found\n";
            } else {
                echo "\n[+] Found " . count($findings) . " issue(s):\n\n";
                foreach ($findings as $finding) {
                    echo "[{$finding->severity}] {$finding->title}\n";
                    echo "    {$finding->description}\n\n";
                }
            }
        }
        
        return 0;
    }
}

// ========================================
// MAIN EXECUTION
// ========================================

if (php_sapi_name() === 'cli') {
    $template = new CertXGenTemplate();
    exit($template->run());
}
?>
