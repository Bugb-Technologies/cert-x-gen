#!/usr/bin/env python3
# @id: postgresql-exporter-exposed
# @name: PostgreSQL Exporter Metrics Exposed
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects exposed Prometheus PostgreSQL Exporter instances revealing database metrics and configuration
# @tags: postgresql, prometheus, exporter, metrics, database, information-disclosure, cwe-200
# @cwe: CWE-200
# @cvss: 5.3
# @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/prometheus-community/postgres_exporter
# @confidence: 95
# @version: 1.0.0
"""
Detects exposed Prometheus PostgreSQL Exporter instances that reveal
database metrics, query statistics, and configuration information.
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
    return 9187  # Default PostgreSQL Exporter port

def check_postgresql_exporter(host, port):
    """Check if PostgreSQL Exporter is accessible"""
    try:
        url = f"http://{host}:{port}/metrics"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CERT-X-GEN/1.0'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            
            # Check for PostgreSQL Exporter signatures
            signatures = ['pg_up', 'pg_stat_', 'postgres_exporter']
            if any(sig in body for sig in signatures):
                evidence_data = {
                    "endpoint": url,
                    "port": port,
                    "status_code": 200,
                    "response_size": len(body)
                }
                
                # Detect sensitive exposed data
                sensitive_info = []
                if 'pg_stat_database' in body:
                    sensitive_info.append("database statistics")
                if 'pg_stat_replication' in body:
                    sensitive_info.append("replication status")
                if 'pg_settings' in body:
                    sensitive_info.append("PostgreSQL configuration")
                if 'pg_locks' in body:
                    sensitive_info.append("database locks information")
                if 'pg_stat_user_tables' in body:
                    sensitive_info.append("table statistics")
                
                if sensitive_info:
                    evidence_data["exposed_data"] = sensitive_info
                
                # Check if up
                is_up = 'pg_up 1' in body or 'pg_up{' in body
                if is_up:
                    evidence_data["postgresql_connection_active"] = True
                
                return {
                    "severity": "critical",
                    "confidence": 95,
                    "title": "PostgreSQL Exporter Exposed Without Authentication",
                    "description": f"PostgreSQL Exporter at {host}:{port} is accessible without authentication, exposing sensitive database metrics including {', '.join(sensitive_info[:3])}. This reveals database structure, performance, and replication topology.",
                    "evidence": evidence_data,
                    "cwe": "CWE-200",
                    "cvss_score": 8.6,
                    "remediation": "Secure PostgreSQL Exporter by:\n1. Implementing authentication proxy\n2. Restricting network access via firewall\n3. Using VPN for remote monitoring\n4. Placing in isolated monitoring network\n5. Enabling TLS with client certificates",
                    "references": [
                        "https://github.com/prometheus-community/postgres_exporter",
                        "https://prometheus.io/docs/guides/basic-auth/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    "tags": ["postgresql", "database", "exporter", "information-disclosure", "critical"]
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
    
    finding = check_postgresql_exporter(target, port)
    if finding:
        findings.append(finding)
    
    # Output results
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()
