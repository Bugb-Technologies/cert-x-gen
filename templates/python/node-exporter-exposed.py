#!/usr/bin/env python3
# @id: node-exporter-exposed
# @name: Node Exporter Metrics Exposed
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects exposed Prometheus Node Exporter instances revealing system metrics and hardware information
# @tags: prometheus, node-exporter, metrics, system-info, information-disclosure, cwe-200
# @cwe: CWE-200
# @cvss: 5.3
# @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/prometheus/node_exporter
# @confidence: 95
# @version: 1.0.0
"""
Detects exposed Prometheus Node Exporter instances that reveal system
metrics, hardware information, and server configuration.
"""

import json
import sys
import os
import urllib.request

def get_port():
    """Get port to scan from environment or use default"""
    if "CERT_X_GEN_OVERRIDE_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_OVERRIDE_PORTS"].split(',')
        return int(ports[0].strip())
    elif "CERT_X_GEN_ADD_PORTS" in os.environ:
        ports = os.environ["CERT_X_GEN_ADD_PORTS"].split(',')
        return int(ports[0].strip())
    return 9100  # Default Node Exporter port

def check_node_exporter(host, port):
    """Check if Node Exporter is accessible"""
    try:
        url = f"http://{host}:{port}/metrics"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CERT-X-GEN/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            
            # Check for Node Exporter signatures
            signatures = ['node_exporter', 'node_cpu_seconds_total', 'node_memory_MemTotal_bytes']
            if any(sig in body for sig in signatures):
                # Extract some interesting metrics
                evidence_data = {
                    "endpoint": url,
                    "port": port,
                    "status_code": 200,
                    "response_size": len(body)
                }
                
                # Try to extract version
                if 'node_exporter_build_info' in body:
                    evidence_data["version_info_present"] = True
                
                # Check for sensitive metrics
                sensitive_metrics = []
                if 'node_filesystem' in body:
                    sensitive_metrics.append("filesystem information")
                if 'node_network' in body:
                    sensitive_metrics.append("network statistics")
                if 'node_memory' in body:
                    sensitive_metrics.append("memory usage")
                if 'node_cpu' in body:
                    sensitive_metrics.append("CPU metrics")
                
                if sensitive_metrics:
                    evidence_data["exposed_metrics"] = sensitive_metrics
                
                return {
                    "severity": "high",
                    "confidence": 95,
                    "title": "Node Exporter Exposed Without Authentication",
                    "description": f"Node Exporter at {host}:{port} is accessible without authentication, exposing sensitive system metrics including {', '.join(sensitive_metrics[:3])}.",
                    "evidence": evidence_data,
                    "cwe": "CWE-200",
                    "cvss_score": 7.5,
                    "remediation": "Secure Node Exporter by:\n1. Placing it behind a reverse proxy with authentication\n2. Using TLS client certificates\n3. Restricting access via firewall rules\n4. Using network segmentation",
                    "references": [
                        "https://prometheus.io/docs/guides/node-exporter/",
                        "https://github.com/prometheus/node_exporter",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    "tags": ["prometheus", "node-exporter", "system-metrics", "information-disclosure"]
                }
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
    
    port = get_port()
    findings = []
    
    finding = check_node_exporter(target, port)
    if finding:
        findings.append(finding)
    
    # Output results
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()
