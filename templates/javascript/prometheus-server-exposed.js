#!/usr/bin/env node
// @id: prometheus-server-exposed
// @name: Prometheus Server Exposed Without Authentication
// @author: CERT-X-GEN Security Team
// @severity: high
// @description: Detects exposed Prometheus server instances revealing targets, rules, alerts and metrics
// @tags: prometheus, monitoring, api, information-disclosure, cwe-200
// @cwe: CWE-200
// @cvss: 7.5
// @references: https://cwe.mitre.org/data/definitions/200.html, https://prometheus.io/docs/prometheus/latest/security/
// @confidence: 95
// @version: 1.0.0
/**
 * Detects exposed Prometheus server instances by checking multiple API endpoints:
 * - /api/v1/targets - Active targets configuration
 * - /api/v1/rules - Alert rules
 * - /api/v1/alerts - Active alerts
 * - /metrics - Metrics endpoint
 * - /graph - Web UI
 */

const http = require('http');
const https = require('https');

const TEMPLATE_METADATA = {
    id: 'prometheus-server-exposed',
    name: 'Prometheus Server Exposed',
    author: 'CERT-X-GEN Security Team',
    severity: 'high',
    tags: ['prometheus', 'monitoring', 'api', 'information-disclosure']
};

// Prometheus API endpoints to check
const PROMETHEUS_ENDPOINTS = [
    {
        path: '/api/v1/targets',
        signature: 'activeTargets',
        description: 'Active targets configuration exposed',
        severity: 'critical'
    },
    {
        path: '/api/v1/rules',
        signature: 'groups',
        description: 'Alert rules configuration exposed',
        severity: 'high'
    },
    {
        path: '/api/v1/alerts',
        signature: 'alerts',
        description: 'Active alerts exposed',
        severity: 'high'
    },
    {
        path: '/metrics',
        signature: 'prometheus_build_info',
        description: 'Prometheus metrics endpoint exposed',
        severity: 'high'
    },
    {
        path: '/graph',
        signature: '<title>Prometheus',
        description: 'Prometheus web UI accessible',
        severity: 'high'
    },
    {
        path: '/api/v1/query',
        signature: 'status',
        description: 'Query API accessible',
        severity: 'high'
    }
];

function getPort() {
    if (process.env.CERT_X_GEN_OVERRIDE_PORTS) {
        const ports = process.env.CERT_X_GEN_OVERRIDE_PORTS.split(',');
        return parseInt(ports[0].trim());
    } else if (process.env.CERT_X_GEN_ADD_PORTS) {
        const ports = process.env.CERT_X_GEN_ADD_PORTS.split(',');
        return parseInt(ports[0].trim());
    }
    return 9090; // Default Prometheus port
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
                    const finding = {
                        severity: endpoint.severity,
                        confidence: 95,
                        title: `Prometheus Server ${endpoint.description}`,
                        description: `Prometheus server at ${host}:${port} exposes ${endpoint.path} without authentication. This endpoint reveals sensitive monitoring infrastructure details.`,
                        evidence: {
                            endpoint: `http://${host}:${port}${endpoint.path}`,
                            path: endpoint.path,
                            port: port,
                            status_code: res.statusCode,
                            signature_found: endpoint.signature,
                            response_size: body.length
                        },
                        cwe: 'CWE-200',
                        cvss_score: endpoint.severity === 'critical' ? 9.0 : 7.5,
                        remediation: 'Enable authentication using:\n1. Reverse proxy with basic auth (nginx/apache)\n2. OAuth2 proxy\n3. Network-level restrictions (firewall/VPN)\n4. Prometheus web.yml configuration with TLS',
                        references: [
                            'https://prometheus.io/docs/guides/basic-auth/',
                            'https://prometheus.io/docs/prometheus/latest/configuration/https/',
                            'https://cwe.mitre.org/data/definitions/200.html'
                        ],
                        tags: ['prometheus', 'monitoring', 'information-disclosure', 'api']
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

    // Check each endpoint
    for (const endpoint of PROMETHEUS_ENDPOINTS) {
        const finding = await checkEndpoint(target, port, endpoint);
        if (finding) {
            findings.push(finding);
        }
    }

    // Output findings
    if (process.env.CERT_X_GEN_MODE === 'engine') {
        process.stdout.write('__CERT_X_GEN_FINDINGS__:');
    }
    console.log(JSON.stringify(findings, null, 2));
}

main().catch(err => {
    console.error(err.message, {}, 2);
    process.exit(1);
});
