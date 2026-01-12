#!/usr/bin/env node
// @id: redis-unauthenticated-javascript
// @name: Redis Unauthenticated Access Detection (JavaScript)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using JavaScript
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0
/**
 * Tests for Redis instances exposed without authentication.
 */

const net = require('net');

// Template metadata
const METADATA = {
    id: "redis-unauthenticated-javascript",
    name: "Redis Unauthenticated Access Detection (JavaScript)",
    author: {
        name: "CERT-X-GEN Security Team",
        email: "security@cert-x-gen.io"
    },
    severity: "critical",
    description: "Detects Redis instances exposed without authentication using JavaScript",
    tags: ["redis", "unauthenticated", "database", "nosql", "javascript"],
    language: "javascript",
    confidence: 95,
    cwe: ["CWE-306"],
    references: [
        "https://redis.io/docs/management/security/",
        "https://cwe.mitre.org/data/definitions/306.html"
    ]
};

async function testRedis(host, port = 6379, timeout = 10000) {
    return new Promise((resolve) => {
        const findings = [];
        const client = new net.Socket();
        let responseData = '';
        
        const timeoutId = setTimeout(() => {
            client.destroy();
            resolve(findings);
        }, timeout);
        
        client.connect(port, host, () => {
            // Send test commands
            const commands = [
                "INFO\r\n",
                "PING\r\n",
                "*1\r\n$4\r\nINFO\r\n",
                "*1\r\n$4\r\nPING\r\n"
            ];
            
            commands.forEach(cmd => {
                client.write(cmd);
            });
        });
        
        client.on('data', (data) => {
            responseData += data.toString();
        });
        
        client.on('end', () => {
            clearTimeout(timeoutId);
            processResponse();
        });
        
        client.on('error', () => {
            clearTimeout(timeoutId);
            resolve(findings);
        });
        
        // Process after a short delay to collect all data
        setTimeout(() => {
            client.end();
        }, 2000);
        
        function processResponse() {
            const indicators = [
                'redis_version',
                'redis_mode',
                'used_memory',
                'connected_clients',
                'role:master',
                'role:slave',
                '+PONG'
            ];
            
            const matchedPatterns = indicators.filter(ind => responseData.includes(ind));
            
            if (matchedPatterns.length > 0) {
                const finding = {
                    target: `${host}:${port}`,
                    template_id: METADATA.id,
                    severity: METADATA.severity,
                    confidence: METADATA.confidence,
                    title: METADATA.name,
                    description: METADATA.description,
                    evidence: {
                        request: "INFO\\r\\nPING\\r\\n*1\\r\\n$4\\r\\nINFO\\r\\n*1\\r\\n$4\\r\\nPING\\r\\n",
                        response: responseData.substring(0, 1000),
                        matched_patterns: matchedPatterns,
                        data: {
                            protocol: "tcp",
                            port: port,
                            response_length: responseData.length
                        }
                    },
                    cwe_ids: METADATA.cwe,
                    tags: METADATA.tags,
                    timestamp: new Date().toISOString()
                };
                findings.push(finding);
            }
            
            resolve(findings);
        }
    });
}

async function main() {
    // Support both CLI args and environment variables (for engine mode)
    let host, port;
    
    if (process.env.CERT_X_GEN_MODE === 'engine') {
        // Engine mode - read from environment variables
        host = process.env.CERT_X_GEN_TARGET_HOST;
        port = parseInt(process.env.CERT_X_GEN_TARGET_PORT || '6379');
        if (!host) {
            console.log(JSON.stringify({ error: "CERT_X_GEN_TARGET_HOST not set" }));
            process.exit(1);
        }
    } else {
        // CLI mode - read from command-line arguments
        const args = process.argv.slice(2);
        if (args.length < 1) {
            console.log(JSON.stringify({ error: "Usage: redis-unauthenticated.js <host> [port]" }));
            process.exit(1);
        }
        host = args[0];
        port = args[1] ? parseInt(args[1]) : 6379;
    }
    
    const findings = await testRedis(host, port);
    
    const result = {
        findings: findings,
        metadata: METADATA
    };
    
    console.log(JSON.stringify(result, null, 2));
}

main().catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
});
