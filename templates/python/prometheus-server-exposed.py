#!/usr/bin/env python3
# @id: prometheus-server-exposed
# @name: Prometheus Server Exposed
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects exposed Prometheus server instances accessible without authentication
# @tags: prometheus, monitoring, metrics, information-disclosure, time-series, cwe-306
# @cwe: CWE-306
# @cvss: 7.5
# @references: https://cwe.mitre.org/data/definitions/306.html, https://prometheus.io/docs/prometheus/latest/security/
# @confidence: 95
# @version: 1.0.0
"""
Detects exposed Prometheus server instances accessible without authentication,
revealing all collected metrics, targets, and monitoring configuration.
"""

import json
import sys
import os
import urllib.request

# Prometheus server endpoints to check
PROMETHEUS_ENDPOINTS = [
    {
        "path": "/api/v1/targets",
        "signature": "activeTargets",
        "description": "Active targets configuration exposed",
        "severity": "critical"
    },
    {
        "path": "/api/v1/rules",
        "signature": "groups",
        "description": "Alert rules configuration exposed",
        "severity": "high"
    },
    {
        "path": "/api/v1/alerts",
        "signature": "alerts",
        "description": "Active alerts exposed",
        "severity": "high"
    },
    {
        "path": "/metrics",
        "signature": "prometheus_build_info",
        "description": "Prometheus metrics endpoint exposed",
        "severity": "high"
    },
    {
        "path": "/graph",
        "signature": "<title>Prometheus",
        "description": "Prometheus web UI accessible",
        "severity": "high"
    },
    {
        "path": "/targets",
        "signature": "Targets",
        "description": "Targets page accessible",
        "severity": "high"
    }
]

def get_port():
    """Get port to scan from environment or use default"""
    if "CERT_X_GEN_OVERRIDE_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_OVERRIDE_PORTS"].split(',')
        return int(ports[0].strip())
    elif "CERT_X_GEN_ADD_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_ADD_PORTS"].split(',')
        return int(ports[0].strip())
    return 9090  # Default Prometheus port

def check_endpoint(host, port, endpoint):
    """Check if a specific Prometheus endpoint is accessible"""
    try:
        url = f"http://{host}:{port}{endpoint['path']}"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CERT-X-GEN/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            
            # Check if signature is present
            if endpoint['signature'] in body:
                return {
                    "severity": endpoint['severity'],
                    "confidence": 95,
                    "title": f"Prometheus Server {endpoint['description']}",
                    "description": f"Prometheus server at {host}:{port} exposes {endpoint['path']} without authentication. This endpoint reveals sensitive monitoring infrastructure details.",
                    "evidence": {
                        "endpoint": url,
                        "path": endpoint['path'],
                        "port": port,
                        "status_code": 200,
                        "signature_found": endpoint['signature'],
                        "response_size": len(body)
                    },
                    "cwe": "CWE-200",
                    "cvss_score": 7.5 if endpoint['severity'] == "high" else 9.0,
                    "remediation": "Enable authentication using:\n1. Reverse proxy with basic auth (nginx/apache)\n2. OAuth2 proxy\n3. Network-level restrictions (firewall/VPN)\n4. Prometheus web.yml configuration with TLS",
                    "references": [
                        "https://prometheus.io/docs/guides/basic-auth/",
                        "https://prometheus.io/docs/prometheus/latest/configuration/https/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    "tags": ["prometheus", "monitoring", "information-disclosure", "api"]
                }
    except urllib.error.HTTPError as e:
        # Some endpoints may return 401 if auth is enabled - that's good
        pass
    except Exception:
        pass
    
    return None

def main():
    # Get target
    target = None
    if len(sys.argv) > 1:
        target = sys.argv[1]
    elif "CERT_X_GEN_TARGET_HOST" in os.environ:
        target = os.environ["CERT_X_GEN_TARGET_HOST"]
    
    if not target:
        print(json.dumps([]))
        sys.exit(0)
    
    # Check if running in engine mode
    engine_mode = os.environ.get("CERT_X_GEN_MODE") == "engine" or "--json" in sys.argv
    
    port = get_port()
    findings = []
    
    if not engine_mode:
        print(f"\n[*] Scanning {target}:{port} for exposed Prometheus server...\n")
    
    # Check each endpoint
    for endpoint in PROMETHEUS_ENDPOINTS:
        if not engine_mode:
            print(f"[*] Checking {endpoint['path']}...")
        
        finding = check_endpoint(target, port, endpoint)
        if finding:
            findings.append(finding)
            if not engine_mode:
                print(f"    [+] VULNERABLE: {endpoint['description']}")
    
    # Output results
    print(json.dumps(findings, indent=2))
    
    if not engine_mode and findings:
        print(f"\n[!] Found {len(findings)} exposed endpoint(s)", file=sys.stderr)

if __name__ == "__main__":
    main()
