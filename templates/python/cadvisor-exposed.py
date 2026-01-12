#!/usr/bin/env python3
# @id: cadvisor-exposed
# @name: cAdvisor Metrics Exposed
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects exposed cAdvisor instances revealing container metrics and infrastructure information
# @tags: cadvisor, container, metrics, information-disclosure, kubernetes, docker, cwe-200
# @cwe: CWE-200
# @cvss: 5.3
# @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/google/cadvisor
# @confidence: 95
# @version: 1.0.0
"""
Detects exposed cAdvisor (Container Advisor) instances that reveal
container metrics, resource usage, and infrastructure information.
"""

import json
import sys
import os
import urllib.request

# cAdvisor endpoints to check
CADVISOR_ENDPOINTS = [
    {"path": "/metrics", "signature": "cadvisor", "desc": "Metrics endpoint"},
    {"path": "/containers/", "signature": "container", "desc": "Containers page"},
    {"path": "/docker/", "signature": "docker", "desc": "Docker containers"},
    {"path": "/api/v1.3/docker/", "signature": "Docker", "desc": "Docker API"}
]

def get_ports():
    """Get ports to scan from environment or use defaults"""
    if "CERT_X_GEN_OVERRIDE_PORTS" in os.environ:
        return [int(p.strip()) for p in os.environ["CERT_X_GEN_OVERRIDE_PORTS"].split(',')]
    elif "CERT_X_GEN_ADD_PORTS" in os.environ:
        default_ports = [8080, 8081, 4194]
        additional = [int(p.strip()) for p in os.environ["CERT_X_GEN_ADD_PORTS"].split(',')]
        return list(set(default_ports + additional))
    return [8080, 8081, 4194]  # Common cAdvisor ports

def check_cadvisor(host, port):
    """Check if cAdvisor is accessible"""
    findings = []
    
    for endpoint in CADVISOR_ENDPOINTS:
        try:
            url = f"http://{host}:{port}{endpoint['path']}"
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'CERT-X-GEN/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read().decode('utf-8', errors='ignore')
                
                if endpoint['signature'] in body:
                    # Extract container information if available
                    evidence_data = {
                        "endpoint": url,
                        "path": endpoint['path'],
                        "port": port,
                        "status_code": 200,
                        "endpoint_type": endpoint['desc']
                    }
                    
                    # Check for specific sensitive data
                    sensitive_info = []
                    if 'container_memory_usage_bytes' in body:
                        sensitive_info.append("container memory usage")
                    if 'container_cpu_usage_seconds_total' in body:
                        sensitive_info.append("container CPU usage")
                    if 'container_network_' in body:
                        sensitive_info.append("container network stats")
                    if 'docker' in body.lower():
                        sensitive_info.append("Docker runtime info")
                    
                    if sensitive_info:
                        evidence_data["exposed_data"] = sensitive_info
                    
                    findings.append({
                        "severity": "critical",
                        "confidence": 95,
                        "title": f"cAdvisor {endpoint['desc']} Exposed Without Authentication",
                        "description": f"cAdvisor at {host}:{port} exposes {endpoint['path']} without authentication. This reveals sensitive container infrastructure information including {', '.join(sensitive_info[:2])}.",
                        "evidence": evidence_data,
                        "cwe": "CWE-200",
                        "cvss_score": 9.1,
                        "remediation": "Secure cAdvisor by:\n1. Restricting access via firewall/iptables\n2. Using authentication proxy (nginx with auth)\n3. Running on internal network only\n4. Disabling HTTP interface if not needed",
                        "references": [
                            "https://github.com/google/cadvisor",
                            "https://github.com/google/cadvisor/blob/master/docs/runtime_options.md",
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ],
                        "tags": ["cadvisor", "container-metrics", "docker", "kubernetes", "critical"]
                    })
                    
                    # Only return first finding to avoid duplicates
                    return findings
                    
        except Exception:
            pass
    
    return findings

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
    
    ports = get_ports()
    all_findings = []
    
    # Check each port
    for port in ports:
        findings = check_cadvisor(target, port)
        all_findings.extend(findings)
        if findings:
            break  # Found on this port, no need to check others
    
    # Output results
    print(json.dumps(all_findings, indent=2))

if __name__ == "__main__":
    main()
