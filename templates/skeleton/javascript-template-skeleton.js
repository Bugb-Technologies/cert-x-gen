#!/usr/bin/env node
// CERT-X-GEN JavaScript/Node.js Template Skeleton
//
// @id: javascript-template-skeleton
// @name: JavaScript Template Skeleton
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Skeleton template for writing security scanning templates in JavaScript/Node.js. Copy this file and customize it for your specific security check.
// @tags: skeleton, example, template, javascript, nodejs
// @cwe: CWE-1008
// @confidence: 90
// @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
//
// Usage:
//   node template.js <target> [--port 80] [--json]
//   node template.js example.com --port 443 --json
//
// When run by CERT-X-GEN engine, environment variables are set:
//   CERT_X_GEN_TARGET_HOST - Target host/IP
//   CERT_X_GEN_TARGET_PORT - Target port
//   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
//

const http = require('http');
const https = require('https');
const net = require('net');
const { URL } = require('url');

// ========================================
// TEMPLATE CONFIGURATION
// ========================================

const TEMPLATE_CONFIG = {
    id: 'template-skeleton',
    name: 'JavaScript Template Skeleton',
    author: 'Your Name',
    severity: 'high', // critical, high, medium, low, info
    confidence: 90,
    tags: ['skeleton', 'example'],
    cwe: 'CWE-XXX',
};

// ========================================
// HELPER FUNCTIONS
// ========================================

/**
 * Calculate CVSS score from severity
 */
function calculateCVSSScore(severity) {
    const scores = {
        critical: 9.0,
        high: 7.5,
        medium: 5.0,
        low: 3.0,
        info: 0.0,
    };
    return scores[severity.toLowerCase()] || 5.0;
}

/**
 * Create a finding object
 */
function createFinding(title, description, evidence, severity = null, remediation = null) {
    return {
        template_id: TEMPLATE_CONFIG.id,
        severity: severity || TEMPLATE_CONFIG.severity,
        confidence: TEMPLATE_CONFIG.confidence,
        title: title,
        description: description,
        evidence: evidence || {},
        cwe: TEMPLATE_CONFIG.cwe,
        cvss_score: calculateCVSSScore(severity || TEMPLATE_CONFIG.severity),
        remediation: remediation || getDefaultRemediation(),
        references: getReferences(),
    };
}

/**
 * Get default remediation steps
 */
function getDefaultRemediation() {
    return `
1. Review the identified vulnerability
2. Apply appropriate security patches
3. Implement security best practices
4. Monitor for suspicious activity
`;
}

/**
 * Get references
 */
function getReferences() {
    return [
        'https://cwe.mitre.org/',
        'https://nvd.nist.gov/',
    ];
}

/**
 * Log message (only if not in JSON mode)
 */
function log(message, type = 'info') {
    if (!global.jsonOutput && process.env.CERT_X_GEN_MODE !== 'engine') {
        const colors = {
            info: '\x1b[34m[INFO]\x1b[0m',
            success: '\x1b[32m[+]\x1b[0m',
            warning: '\x1b[33m[!]\x1b[0m',
            error: '\x1b[31m[ERROR]\x1b[0m',
        };
        console.error(`${colors[type] || colors.info} ${message}`);
    }
}

// ========================================
// SCANNING FUNCTIONS
// ========================================

/**
 * Test HTTP/HTTPS endpoint
 */
async function testHttpEndpoint(host, port) {
    return new Promise((resolve) => {
        const protocol = port === 443 ? https : http;
        const options = {
            hostname: host,
            port: port,
            path: '/',
            method: 'GET',
            timeout: 5000,
            rejectUnauthorized: false, // Allow self-signed certs for testing
        };

        log(`Testing ${port === 443 ? 'https' : 'http'}://${host}:${port}/`);

        const req = protocol.request(options, (res) => {
            let body = '';

            res.on('data', (chunk) => {
                body += chunk;
            });

            res.on('end', () => {
                log('Endpoint accessible', 'success');

                // Check for vulnerability indicators
                if (body.toLowerCase().includes('vulnerable') || 
                    body.toLowerCase().includes('exposed')) {
                    resolve({
                        vulnerable: true,
                        status_code: res.statusCode,
                        headers: res.headers,
                        body: body.substring(0, 1000), // First 1000 chars
                    });
                } else {
                    resolve({
                        vulnerable: false,
                        status_code: res.statusCode,
                    });
                }
            });
        });

        req.on('error', (error) => {
            log(`HTTP request failed: ${error.message}`, 'warning');
            resolve(null);
        });

        req.on('timeout', () => {
            req.destroy();
            resolve(null);
        });

        req.end();
    });
}

/**
 * Test network service (TCP)
 */
async function testNetworkService(host, port) {
    return new Promise((resolve) => {
        log(`Testing network service on ${host}:${port}`);

        const client = new net.Socket();
        const timeout = setTimeout(() => {
            client.destroy();
            resolve(null);
        }, 5000);

        client.connect(port, host, () => {
            log(`Port ${port} is open`, 'success');

            // Send probe
            client.write('PROBE\r\n');

            // Wait for response
            client.on('data', (data) => {
                clearTimeout(timeout);
                client.destroy();
                resolve({
                    response: data.toString('utf8'),
                    port: port,
                });
            });
        });

        client.on('error', (error) => {
            clearTimeout(timeout);
            log(`Connection failed: ${error.message}`, 'warning');
            resolve(null);
        });

        client.on('timeout', () => {
            clearTimeout(timeout);
            client.destroy();
            resolve(null);
        });
    });
}

// ========================================
// MAIN SCANNING LOGIC
// ========================================

/**
 * Main template execution
 */
class CertXGenTemplate {
    constructor() {
        this.findings = [];
        this.target = null;
        this.port = 80;
        this.context = {};
    }

    /**
     * Execute the scan
     * 
     * CUSTOMIZE THIS METHOD WITH YOUR SCANNING LOGIC
     */
    async execute() {
        log(`Scanning ${this.target}:${this.port}`);

        // ========================================
        // CUSTOMIZE THIS SECTION
        // ========================================

        // Example: Test HTTP/HTTPS endpoint
        const httpResult = await testHttpEndpoint(this.target, this.port);
        if (httpResult && httpResult.vulnerable) {
            this.findings.push(createFinding(
                'Vulnerability Detected',
                `Found potential vulnerability on ${this.target}:${this.port}`,
                {
                    endpoint: `${this.port === 443 ? 'https' : 'http'}://${this.target}:${this.port}/`,
                    status_code: httpResult.status_code,
                    indicators: 'vulnerable keyword found',
                },
                'high',
                'Apply security patches and review configuration'
            ));
        }

        // Example: Test network service
        const serviceResult = await testNetworkService(this.target, this.port);
        if (serviceResult) {
            this.findings.push(createFinding(
                'Service Information Disclosure',
                `Service on ${this.target}:${this.port} responded to probe`,
                {
                    port: serviceResult.port,
                    response: Buffer.from(serviceResult.response).toString('base64'),
                },
                'medium'
            ));
        }

        // Add more scanning logic here
        // ...

        // ========================================
        // END CUSTOMIZATION
        // ========================================

        return this.findings;
    }

    /**
     * Parse command line arguments
     */
    parseArgs() {
        const args = process.argv.slice(2);
        let i = 0;

        while (i < args.length) {
            switch (args[i]) {
                case '--target':
                    this.target = args[++i];
                    break;
                case '--port':
                    this.port = parseInt(args[++i], 10);
                    break;
                case '--json':
                    global.jsonOutput = true;
                    break;
                case '--help':
                case '-h':
                    this.printUsage();
                    process.exit(0);
                default:
                    if (!this.target && !args[i].startsWith('-')) {
                        this.target = args[i];
                    }
                    break;
            }
            i++;
        }

        // Check environment variables (for CERT-X-GEN engine integration)
        if (!this.target && process.env.CERT_X_GEN_TARGET) {
            this.target = process.env.CERT_X_GEN_TARGET;
        }
        if (!this.target && process.env.CERT_X_GEN_TARGET_HOST) {
            this.target = process.env.CERT_X_GEN_TARGET_HOST;
        }
        if (process.env.CERT_X_GEN_PORT) {
            this.port = parseInt(process.env.CERT_X_GEN_PORT, 10);
        }
        if (process.env.CERT_X_GEN_TARGET_PORT) {
            this.port = parseInt(process.env.CERT_X_GEN_TARGET_PORT, 10);
        }
        if (process.env.CERT_X_GEN_MODE === 'engine') {
            global.jsonOutput = true;
        }

        if (process.env.CERT_X_GEN_CONTEXT) {
            try {
                this.context = JSON.parse(process.env.CERT_X_GEN_CONTEXT);
            } catch (e) {
                this.context = {};
            }
        }

        const addPortsEnv = process.env.CERT_X_GEN_ADD_PORTS;
        if (addPortsEnv) {
            this.context.add_ports = addPortsEnv;
        }

        const overridePortsEnv = process.env.CERT_X_GEN_OVERRIDE_PORTS;
        if (overridePortsEnv) {
            this.context.override_ports = overridePortsEnv;
        }

        if (!this.target) {
            console.error('Error: No target specified');
            this.printUsage();
            process.exit(1);
        }
    }

    /**
     * Print usage information
     */
    printUsage() {
        console.log(`
Usage: node ${process.argv[1]} [OPTIONS] <target>

${TEMPLATE_CONFIG.name}
CERT-X-GEN Security Template

Options:
  --target <HOST>  Target host or IP address
  --port <PORT>    Target port (default: 80)
  --json           Output findings as JSON
  --help           Show this help message

Environment Variables:
  CERT_X_GEN_MODE         Set to "engine" for integration mode
  CERT_X_GEN_TARGET       Target host
  CERT_X_GEN_PORT         Target port

Examples:
  node ${process.argv[1]} example.com
  node ${process.argv[1]} --target 192.168.1.100 --port 443 --json
`);
    }

    /**
     * Run the template
     */
    async run() {
        // Parse arguments
        this.parseArgs();

        // Print banner (if not JSON output)
        if (!global.jsonOutput) {
            console.log('\n╔════════════════════════════════════════════════════════════╗');
            console.log(`║  ${TEMPLATE_CONFIG.name.padEnd(58)}║`);
            console.log('║  CERT-X-GEN Security Template                              ║');
            console.log('╚════════════════════════════════════════════════════════════╝\n');
            console.log(`Target: ${this.target}:${this.port}`);
            console.log(`Started: ${new Date().toISOString()}\n`);
        }

        try {
            // Execute the scan
            await this.execute();

            // Output results
            if (global.jsonOutput || process.env.CERT_X_GEN_MODE === 'engine') {
                // JSON output for CERT-X-GEN engine
                if (process.env.CERT_X_GEN_MODE === 'engine') {
                    // Special marker for engine parsing
                    process.stdout.write('__CERT_X_GEN_FINDINGS__:');
                }
                console.log(JSON.stringify(this.findings, null, 2));
            } else {
                // Human-readable output
                if (this.findings.length === 0) {
                    console.log('[-] No issues found\n');
                } else {
                    console.log(`[+] Found ${this.findings.length} issue(s):\n`);

                    for (const finding of this.findings) {
                        const severityColor = {
                            critical: '\x1b[31m',
                            high: '\x1b[33m',
                            medium: '\x1b[33m',
                            low: '\x1b[36m',
                            info: '\x1b[34m',
                        }[finding.severity] || '\x1b[0m';

                        console.log(`${severityColor}[${finding.severity.toUpperCase()}]\x1b[0m ${finding.title}`);
                        console.log(`    ${finding.description}`);
                        if (Object.keys(finding.evidence).length > 0) {
                            console.log(`    Evidence: ${JSON.stringify(finding.evidence)}`);
                        }
                        console.log();
                    }
                }

                console.log(`Completed: ${new Date().toISOString()}`);
            }
        } catch (error) {
            console.error(`Error during scan: ${error.message}`);
            if (!global.jsonOutput) {
                console.error(error.stack);
            }
            process.exit(1);
        }
    }
}

// ========================================
// CUSTOMIZE THIS SECTION
// ========================================

/**
 * Custom template implementation
 * 
 * Extend or modify this class for your specific security check
 */
class MyCustomTemplate extends CertXGenTemplate {
    constructor() {
        super();
        
        // Update metadata for your template
        TEMPLATE_CONFIG.id = 'my-custom-check';
        TEMPLATE_CONFIG.name = 'My Custom Security Check';
        TEMPLATE_CONFIG.author = 'Security Researcher';
        TEMPLATE_CONFIG.severity = 'high';
        TEMPLATE_CONFIG.cwe = 'CWE-89'; // Example: SQL Injection
    }

    /**
     * Override execute() with your custom scanning logic
     */
    async execute() {
        // Call parent implementation or implement from scratch
        await super.execute();
        
        // Add your custom scanning logic here
        // ...
        
        return this.findings;
    }
}

// ========================================
// MAIN ENTRY POINT
// ========================================

if (require.main === module) {
    // Create and run template
    const template = new MyCustomTemplate();
    template.run().catch((error) => {
        console.error(`Fatal error: ${error.message}`);
        process.exit(1);
    });
}

// Export for testing or module use
module.exports = {
    CertXGenTemplate,
    MyCustomTemplate,
    TEMPLATE_CONFIG,
    createFinding,
};
