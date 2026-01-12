#!/usr/bin/env node
// @id: cadvisor-exposed
// @name: cAdvisor Exposed Without Authentication
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects exposed cAdvisor instances revealing container runtime metrics and infrastructure information
// @tags: cadvisor, container, docker, kubernetes, cwe-200
// @cwe: CWE-200
// @cvss: 8.6
// @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/google/cadvisor
// @confidence: 95
// @version: 1.0.0
/**
 * Detects exposed cAdvisor (Container Advisor) instances that reveal
 * container runtime metrics and infrastructure information.
 */

const http = require('http');

const TEMPLATE_METADATA = {
    id: 'cadvisor-exposed',
    name: 'cAdvisor Exposed',
    author: 'CERT-X-GEN Security Team',
    severity: 'critical',
    tags: ['cadvisor', 'container', 'docker', 'kubernetes']
};

// cAdvisor endpoints to check
const CADVISOR_ENDPOINTS = [
    { path: '/metrics', signature: 'cadvisor', desc: 'Metrics endpoint' },
    { path: '/containers/', signature: 'container', desc: 'Containers page' },
    { path: '/docker/', signature: 'docker', desc: 'Docker containers' },
    { path: '/api/v1.3/docker/', signature: 'Docker', desc: 'Docker API' }
];

function getPorts() {
    if (process.env.CERT_X_GEN_OVERRIDE_PORTS) {
        return process.env.CERT_X_GEN_OVERRIDE_PORTS.split(',').map(p => parseInt(p.trim()));
    } else if (process.env.CERT_X_GEN_ADD_PORTS) {
        const defaults = [8080, 8081, 4194];
        const additional = process.env.CERT_X_GEN_ADD_PORTS.split(',').map(p => parseInt(p.trim()));
        return [...new Set([...defaults, ...additional])];
    }
    return [8080, 8081, 4194]; // Common cAdvisor ports
}

function checkEndpoint(host, port, endpoint) {
    return new Promise((resolve) => {
        const options = {
            hostname: host,
            port: port,
            path: endpoint.path,
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
                if (body.includes(endpoint.signature)) {
                    const evidence = {
                        endpoint: `http://${host}:${port}${endpoint.path}`,
                        path: endpoint.path,
                        port: port,
                        status_code: res.statusCode,
                        endpoint_type: endpoint.desc
                    };

                    // Check for sensitive data
                    const sensitiveInfo = [];
                    if (body.includes('container_memory_usage_bytes')) {
                        sensitiveInfo.push('container memory usage');
                    }
                    if (body.includes('container_cpu_usage_seconds_total')) {
                        sensitiveInfo.push('container CPU usage');
                    }
                    if (body.includes('container_network_')) {
                        sensitiveInfo.push('container network stats');
                    }
                    if (body.toLowerCase().includes('docker')) {
                        sensitiveInfo.push('Docker runtime info');
                    }

                    if (sensitiveInfo.length > 0) {
                        evidence.exposed_data = sensitiveInfo;
                    }

                    const finding = {
                        severity: 'critical',
                        confidence: 95,
                        title: `cAdvisor ${endpoint.desc} Exposed Without Authentication`,
                        description: `cAdvisor at ${host}:${port} exposes ${endpoint.path} without authentication. This reveals sensitive container infrastructure information including ${sensitiveInfo.slice(0, 2).join(', ')}.`,
                        evidence: evidence,
                        cwe: 'CWE-200',
                        cvss_score: 9.1,
                        remediation: 'Secure cAdvisor by:\n1. Restricting access via firewall/iptables\n2. Using authentication proxy (nginx with auth)\n3. Running on internal network only\n4. Disabling HTTP interface if not needed',
                        references: [
                            'https://github.com/google/cadvisor',
                            'https://github.com/google/cadvisor/blob/master/docs/runtime_options.md',
                            'https://cwe.mitre.org/data/definitions/200.html'
                        ],
                        tags: ['cadvisor', 'container-metrics', 'docker', 'kubernetes', 'critical']
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

    const ports = getPorts();
    const findings = [];

    // Check each port
    for (const port of ports) {
        for (const endpoint of CADVISOR_ENDPOINTS) {
            const finding = await checkEndpoint(target, port, endpoint);
            if (finding) {
                findings.push(finding);
                // Found on this port, stop checking other endpoints
                break;
            }
        }
        if (findings.length > 0) {
            break; // Found on this port, stop checking other ports
        }
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
