#!/usr/bin/env node
// @id: node-exporter-exposed
// @name: Node Exporter Exposed Without Authentication
// @author: CERT-X-GEN Security Team
// @severity: high
// @description: Detects exposed Prometheus Node Exporter instances revealing system metrics
// @tags: prometheus, node-exporter, system-metrics, cwe-200
// @cwe: CWE-200
// @cvss: 7.5
// @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/prometheus/node_exporter
// @confidence: 95
// @version: 1.0.0
/**
 * Detects exposed Prometheus Node Exporter instances that reveal
 * system metrics including CPU, memory, disk, and network statistics.
 */

const http = require('http');

const TEMPLATE_METADATA = {
    id: 'node-exporter-exposed',
    name: 'Node Exporter Exposed',
    author: 'CERT-X-GEN Security Team',
    severity: 'high',
    tags: ['prometheus', 'node-exporter', 'system-metrics']
};

function getPort() {
    if (process.env.CERT_X_GEN_OVERRIDE_PORTS) {
        const ports = process.env.CERT_X_GEN_OVERRIDE_PORTS.split(',');
        return parseInt(ports[0].trim());
    } else if (process.env.CERT_X_GEN_ADD_PORTS) {
        const ports = process.env.CERT_X_GEN_ADD_PORTS.split(',');
        return parseInt(ports[0].trim());
    }
    return 9100; // Default Node Exporter port
}

function checkNodeExporter(host, port) {
    return new Promise((resolve) => {
        const options = {
            hostname: host,
            port: port,
            path: '/metrics',
            method: 'GET',
            timeout: 5000,
            headers: {
                'User-Agent': 'CERT-X-GEN/1.0'
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            
            res.on('data', (chunk) => {
                body += chunk;
            });
            
            res.on('end', () => {
                // Check for Node Exporter signatures
                const signatures = ['node_exporter', 'node_cpu_seconds_total', 'node_memory_MemTotal_bytes'];
                const hasSignature = signatures.some(sig => body.includes(sig));
                
                if (hasSignature) {
                    const evidence = {
                        endpoint: `http://${host}:${port}/metrics`,
                        port: port,
                        status_code: res.statusCode,
                        response_size: body.length
                    };

                    // Detect exposed metrics
                    const sensitiveMetrics = [];
                    if (body.includes('node_filesystem')) {
                        sensitiveMetrics.push('filesystem information');
                    }
                    if (body.includes('node_network')) {
                        sensitiveMetrics.push('network statistics');
                    }
                    if (body.includes('node_memory')) {
                        sensitiveMetrics.push('memory usage');
                    }
                    if (body.includes('node_cpu')) {
                        sensitiveMetrics.push('CPU metrics');
                    }
                    if (body.includes('node_disk')) {
                        sensitiveMetrics.push('disk I/O statistics');
                    }

                    if (sensitiveMetrics.length > 0) {
                        evidence.exposed_metrics = sensitiveMetrics;
                    }

                    if (body.includes('node_exporter_build_info')) {
                        evidence.version_info_present = true;
                    }

                    const finding = {
                        severity: 'high',
                        confidence: 95,
                        title: 'Node Exporter Exposed Without Authentication',
                        description: `Node Exporter at ${host}:${port} is accessible without authentication, exposing sensitive system metrics including ${sensitiveMetrics.slice(0, 3).join(', ')}.`,
                        evidence: evidence,
                        cwe: 'CWE-200',
                        cvss_score: 7.5,
                        remediation: 'Secure Node Exporter by:\n1. Placing it behind a reverse proxy with authentication\n2. Using TLS client certificates\n3. Restricting access via firewall rules\n4. Using network segmentation',
                        references: [
                            'https://prometheus.io/docs/guides/node-exporter/',
                            'https://github.com/prometheus/node_exporter',
                            'https://cwe.mitre.org/data/definitions/200.html'
                        ],
                        tags: ['prometheus', 'node-exporter', 'system-metrics', 'information-disclosure']
                    };
                    resolve(finding);
                } else {
                    resolve(null);
                }
            });
        });

        req.on('error', () => {
            resolve(null);
        });

        req.on('timeout', () => {
            req.destroy();
            resolve(null);
        });

        req.end();
    });
}

async function main() {
    // Get target
    const target = process.argv[2] || process.env.CERT_X_GEN_TARGET_HOST;
    
    if (!target) {
        console.log(JSON.stringify([]));
        process.exit(0);
    }

    const port = getPort();
    const findings = [];

    const finding = await checkNodeExporter(target, port);
    if (finding) {
        findings.push(finding);
    }

    // Output findings
    if (process.env.CERT_X_GEN_MODE === 'engine') {
        process.stdout.write('__CERT_X_GEN_FINDINGS__:');
    }
    console.log(JSON.stringify(findings, null, 2));
}

main().catch(err => {
    console.error(err.message);
    process.exit(1);
});
