#!/usr/bin/env python3
# @id: mysql-exporter-exposed
# @name: MySQL Exporter Metrics Exposed
# @author: CERT-X-GEN Security Team
# @severity: medium
# @description: Detects exposed Prometheus MySQL Exporter instances revealing database metrics and configuration without authentication
# @tags: mysql, prometheus, exporter, metrics, information-disclosure, database, cwe-200
# @cwe: CWE-200
# @cvss: 5.3
# @references: https://cwe.mitre.org/data/definitions/200.html, https://github.com/prometheus/mysqld_exporter
# @confidence: 95
# @version: 1.0.0
"""
CERT-X-GEN MySQL Exporter Metrics Exposed Template

Detects exposed Prometheus MySQL Exporter instances that reveal database
metrics, performance data, and configuration details without authentication.
"""

import json
import sys
import os
import argparse
import urllib.request
from typing import List, Dict, Any

class CertXGenTemplate:
    """Base class for CERT-X-GEN Python templates"""
    
    def __init__(self):
        self.id = "mysql-exporter-exposed"
        self.name = "MySQL Exporter Metrics Exposed"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "medium"
        self.tags = ["mysql", "prometheus", "exporter", "metrics", "information-disclosure", "database"]
        self.confidence = 95
        self.cwe = "CWE-200"
        self.target = None
        self.context = {}
    
    def get_port(self) -> int:
        """Get port to scan from environment or use default"""
        if "CERT_X_GEN_OVERRIDE_PORTS" in os.environ:
            ports = os.environ["CERT_X_GEN_OVERRIDE_PORTS"].split(',')
            return int(ports[0].strip())
        elif "CERT_X_GEN_ADD_PORTS" in os.environ:
            ports = os.environ["CERT_X_GEN_ADD_PORTS"].split(',')
            return int(ports[0].strip())
        return 9104  # Default MySQL Exporter port
    
    def check_mysql_exporter(self, host: str, port: int) -> Dict[str, Any]:
        """Check if MySQL Exporter is accessible"""
        try:
            url = f"http://{host}:{port}/metrics"
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'CERT-X-GEN/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read().decode('utf-8', errors='ignore')
                
                # Check for MySQL Exporter signatures
                signatures = ['mysql_up', 'mysql_global_status', 'mysqld_exporter']
                if any(sig in body for sig in signatures):
                    evidence_data = {
                        "endpoint": url,
                        "port": port,
                        "status_code": 200,
                        "response_size": len(body)
                    }
                    
                    # Detect sensitive exposed data
                    sensitive_info = []
                    if 'mysql_global_variables' in body:
                        sensitive_info.append("MySQL configuration variables")
                    if 'mysql_slave_status' in body:
                        sensitive_info.append("replication status")
                    if 'mysql_info_schema' in body:
                        sensitive_info.append("database schema information")
                    if 'mysql_perf_schema' in body:
                        sensitive_info.append("performance metrics")
                    if 'mysql_global_status_queries' in body:
                        sensitive_info.append("query statistics")
                    
                    if sensitive_info:
                        evidence_data["exposed_data"] = sensitive_info
                    
                    # Check if up
                    is_up = 'mysql_up 1' in body
                    if is_up:
                        evidence_data["mysql_connection_active"] = True
                    
                    return self.create_finding(
                        title="MySQL Exporter Exposed Without Authentication",
                        description=f"MySQL Exporter at {host}:{port} is accessible without authentication, exposing sensitive database metrics including {', '.join(sensitive_info[:3])}. This can reveal database topology, performance issues, and potential attack vectors.",
                        evidence=evidence_data,
                        severity="critical",
                        remediation="Secure MySQL Exporter by:\n1. Using authentication proxy (nginx with basic auth)\n2. Restricting access via firewall rules\n3. Running on internal network only\n4. Using VPN for remote access\n5. Configuring network-level ACLs"
                    )
        except Exception:
            pass
        
        return None
    
    def execute(self, target: str, port: int = 9104) -> List[Dict[str, Any]]:
        """Main execution method"""
        findings = []
        
        finding = self.check_mysql_exporter(target, port)
        if finding:
            findings.append(finding)
        
        return findings
    
    def create_finding(
        self,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        severity: str = None,
        remediation: str = None
    ) -> Dict[str, Any]:
        """Create a finding in CERT-X-GEN format"""
        return {
            "template_id": self.id,
            "severity": severity or self.severity,
            "confidence": self.confidence,
            "title": title,
            "description": description,
            "evidence": evidence,
            "cwe": self.cwe,
            "cvss_score": self.calculate_cvss_score(severity or self.severity),
            "remediation": remediation or self.get_remediation(),
            "references": self.get_references(),
            "tags": self.tags
        }
    
    def calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0
        }
        return scores.get(severity.lower(), 5.0)
    
    def get_remediation(self) -> str:
        """Get remediation steps"""
        return """Secure MySQL Exporter by:
1. Using authentication proxy (nginx with basic auth)
2. Restricting access via firewall rules
3. Running on internal network only
4. Using VPN for remote access
5. Configuring network-level ACLs"""
    
    def get_references(self) -> List[str]:
        """Get references and documentation"""
        return [
            "https://github.com/prometheus/mysqld_exporter",
            "https://prometheus.io/docs/guides/basic-auth/",
            "https://cwe.mitre.org/data/definitions/200.html"
        ]
    
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description=self.name,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.add_argument(
            "target",
            nargs="?",
            help="Target host or IP address"
        )
        
        parser.add_argument(
            "--target",
            dest="target_flag",
            help="Target host (alternative)"
        )
        
        parser.add_argument(
            "--port",
            type=int,
            default=9104,
            help="Target port (default: 9104)"
        )
        
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output findings as JSON"
        )
        
        return parser.parse_args()
    
    def run(self):
        """Main entry point for the template"""
        args = self.parse_arguments()
        
        # Get target from arguments or environment
        target = args.target or args.target_flag
        if not target and "CERT_X_GEN_TARGET_HOST" in os.environ:
            target = os.environ["CERT_X_GEN_TARGET_HOST"]
        
        if not target:
            print(json.dumps([]))
            sys.exit(0)
        
        # Get port
        port = args.port
        if "CERT_X_GEN_TARGET_PORT" in os.environ:
            port = int(os.environ["CERT_X_GEN_TARGET_PORT"])
        else:
            port = self.get_port()
        
        # Get context from environment
        if "CERT_X_GEN_CONTEXT" in os.environ:
            try:
                self.context = json.loads(os.environ["CERT_X_GEN_CONTEXT"])
            except json.JSONDecodeError:
                pass

        # Execute the template
        findings = self.execute(target, port)
        
        # Output results as JSON
        print(json.dumps(findings, indent=2))

class MySQLExporterExposedTemplate(CertXGenTemplate):
    """MySQL Exporter Metrics Exposed Template Implementation"""
    
    def __init__(self):
        super().__init__()

if __name__ == "__main__":
    template = MySQLExporterExposedTemplate()
    template.run()