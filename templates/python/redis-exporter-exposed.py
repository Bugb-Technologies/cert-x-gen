#!/usr/bin/env python3
# @id: redis-exporter-exposed
# @name: Redis Exporter Metrics Exposed
# @author: CERT-X-GEN Security Team
# @severity: high
# @description: Detects exposed Prometheus Redis Exporter instances revealing Redis metrics and configuration
# @tags: redis, prometheus, exporter, metrics, cache, information-disclosure, cwe-200
# @cwe: CWE-200
# @cvss: 7.5
# @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/oliver006/redis_exporter
# @confidence: 95
# @version: 1.0.0
"""
Detects exposed Prometheus Redis Exporter instances that reveal Redis
database metrics, memory usage, and configuration.
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
    return 9121  # Default Redis Exporter port

def check_redis_exporter(host, port):
    """Check if Redis Exporter is accessible"""
    try:
        url = f"http://{host}:{port}/metrics"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CERT-X-GEN/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            
            # Check for Redis Exporter signatures
            signatures = ['redis_up', 'redis_connected_clients', 'redis_exporter']
            if any(sig in body for sig in signatures):
                evidence_data = {
                    "endpoint": url,
                    "port": port,
                    "status_code": 200,
                    "response_size": len(body)
                }
                
                # Detect sensitive exposed data
                sensitive_info = []
                if 'redis_memory' in body:
                    sensitive_info.append("memory usage statistics")
                if 'redis_keyspace' in body:
                    sensitive_info.append("keyspace information")
                if 'redis_config' in body:
                    sensitive_info.append("Redis configuration")
                if 'redis_replication' in body:
                    sensitive_info.append("replication status")
                if 'redis_connected_clients' in body:
                    sensitive_info.append("client connections")
                
                if sensitive_info:
                    evidence_data["exposed_data"] = sensitive_info
                
                # Check if up
                is_up = 'redis_up 1' in body or 'redis_up{' in body
                if is_up:
                    evidence_data["redis_connection_active"] = True
                
                return {
                    "severity": "high",
                    "confidence": 95,
                    "title": "Redis Exporter Exposed Without Authentication",
                    "description": f"Redis Exporter at {host}:{port} is accessible without authentication, exposing sensitive cache metrics including {', '.join(sensitive_info[:3])}. This can reveal cache topology and usage patterns.",
                    "evidence": evidence_data,
                    "cwe": "CWE-200",
                    "cvss_score": 7.5,
                    "remediation": "Secure Redis Exporter by:\n1. Using authentication proxy\n2. Restricting access via firewall\n3. Running on internal network only\n4. Implementing network segmentation",
                    "references": [
                        "https://github.com/oliver006/redis_exporter",
                        "https://prometheus.io/docs/guides/basic-auth/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    "tags": ["redis", "cache", "exporter", "information-disclosure"]
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
    
    finding = check_redis_exporter(target, port)
    if finding:
        findings.append(finding)
    
    # Output results
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()
