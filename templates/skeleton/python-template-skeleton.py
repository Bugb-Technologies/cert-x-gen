#!/usr/bin/env python3
# CERT-X-GEN Python Template Skeleton
#
# @id: python-template-skeleton
# @name: Python Template Skeleton
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Skeleton template for writing security scanning templates in Python. Copy this file and customize it for your specific security check.
# @tags: skeleton, example, template, python
# @cwe: CWE-1008
# @confidence: 90
# @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
#
# Usage:
#   python3 template.py <target> [--port 80] [--json]
#   python3 template.py example.com --port 443 --json
#
# When run by CERT-X-GEN engine, environment variables are set:
#   CERT_X_GEN_TARGET_HOST - Target host/IP
#   CERT_X_GEN_TARGET_PORT - Target port
#   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
#

import json
import sys
import os
import argparse
import socket
import requests
from typing import List, Dict, Any

# CERT-X-GEN Template Base Class
class CertXGenTemplate:
    """Base class for CERT-X-GEN Python templates"""
    
    def __init__(self):
        # Template metadata
        self.id = "template-skeleton"
        self.name = "Python Template Skeleton"
        self.author = "Your Name"
        self.severity = "high"  # critical, high, medium, low, info
        self.tags = ["skeleton", "example"]
        self.confidence = 90  # 0-100
        self.cwe = "CWE-XXX"  # CWE ID if applicable
        
        # Target information (will be populated from command line)
        self.target = None
        self.context = {}
    
    def execute(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        """
        Main execution method for the template.
        
        Args:
            target: Target host/IP address
            port: Target port
            
        Returns:
            List of findings in CERT-X-GEN format
        """
        findings = []
        
        try:
            # ========================================
            # YOUR CUSTOM SCANNING LOGIC HERE
            # ========================================
            
            # Example: Test HTTP endpoint
            response = self.test_http_endpoint(target, port)
            
            if response and self.check_vulnerability(response):
                finding = self.create_finding(
                    title="Vulnerability Detected",
                    description=f"Found vulnerability on {target}:{port}",
                    evidence={"response": response}
                )
                findings.append(finding)
            
            # Example: Test network service
            result = self.test_network_service(target, port)
            if result:
                findings.append(result)
            
        except Exception as e:
            # Log error but don't fail the entire scan
            print(f"Error during scan: {e}", file=sys.stderr)
        
        return findings
    
    def test_http_endpoint(self, host: str, port: int) -> Dict[str, Any]:
        """
        Example: Test HTTP/HTTPS endpoint
        """
        try:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}/"
            
            response = requests.get(url, timeout=5, verify=False)
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000]  # First 1000 chars
            }
        except Exception:
            return None
    
    def test_network_service(self, host: str, port: int) -> Dict[str, Any]:
        """
        Example: Test raw TCP/UDP service
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send probe
            sock.send(b"PROBE\r\n")
            
            # Receive response
            response = sock.recv(1024)
            sock.close()
            
            if response:
                return self.create_finding(
                    title="Service Responded",
                    description=f"Service on {host}:{port} responded to probe",
                    evidence={"response": response.decode('utf-8', errors='ignore')}
                )
        except Exception:
            pass
        
        return None
    
    def check_vulnerability(self, response: Dict[str, Any]) -> bool:
        """
        Check if response indicates a vulnerability
        
        Override this method with your detection logic
        """
        # Example: Check for specific headers, status codes, content
        if response and response.get("status_code") == 200:
            body = response.get("body", "")
            # Check for indicators
            if "vulnerable" in body.lower():
                return True
        
        return False
    
    def create_finding(
        self,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        severity: str = None,
        remediation: str = None
    ) -> Dict[str, Any]:
        """
        Create a finding in CERT-X-GEN format
        """
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
            "references": self.get_references()
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
        """
        Get remediation steps
        
        Override this with specific remediation advice
        """
        return """
1. Review the identified vulnerability
2. Apply appropriate security patches
3. Implement security best practices
4. Monitor for suspicious activity
"""
    
    def get_references(self) -> List[str]:
        """
        Get references and documentation
        
        Override with relevant references
        """
        return [
            "https://cwe.mitre.org/",
            "https://nvd.nist.gov/"
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
            default=80,
            help="Target port (default: 80)"
        )
        
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output findings as JSON"
        )
        
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Verbose output"
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
            print("Error: No target specified", file=sys.stderr)
            sys.exit(1)
        
        # Get port
        port = args.port
        if "CERT_X_GEN_TARGET_PORT" in os.environ:
            port = int(os.environ["CERT_X_GEN_TARGET_PORT"])
        
        # Get context from environment
        if "CERT_X_GEN_CONTEXT" in os.environ:
            try:
                self.context = json.loads(os.environ["CERT_X_GEN_CONTEXT"])
            except json.JSONDecodeError:
                pass

        # Expose additional/override ports (advanced usage) via context
        add_ports = os.environ.get("CERT_X_GEN_ADD_PORTS")
        if add_ports:
            self.context["add_ports"] = add_ports

        override_ports = os.environ.get("CERT_X_GEN_OVERRIDE_PORTS")
        if override_ports:
            self.context["override_ports"] = override_ports
        
        # Execute the template
        findings = self.execute(target, port)
        
        # Output results
        if args.json or os.environ.get("CERT_X_GEN_MODE") == "engine":
            # JSON output for CERT-X-GEN engine integration
            print(json.dumps(findings, indent=2))
        else:
            # Human-readable output
            if findings:
                print(f"\n[+] Found {len(findings)} issue(s):\n")
                for finding in findings:
                    print(f"[{finding['severity'].upper()}] {finding['title']}")
                    print(f"    {finding['description']}")
                    if args.verbose:
                        print(f"    Evidence: {finding['evidence']}")
                    print()
            else:
                print("\n[-] No issues found")

# ========================================
# CUSTOMIZE THIS SECTION
# ========================================

class MyCustomTemplate(CertXGenTemplate):
    """
    Your custom template implementation
    
    Rename this class and customize the methods for your specific check
    """
    
    def __init__(self):
        super().__init__()
        # Update metadata for your template
        self.id = "my-custom-check"
        self.name = "My Custom Security Check"
        self.author = "Security Researcher"
        self.severity = "high"
        self.tags = ["custom", "security"]
        self.cwe = "CWE-89"  # Example: SQL Injection
    
    def execute(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        """
        Implement your custom scanning logic here
        """
        findings = []
        
        # Your scanning logic
        # ...
        
        return findings

# ========================================
# MAIN EXECUTION
# ========================================

if __name__ == "__main__":
    # Instantiate and run your template
    template = MyCustomTemplate()
    template.run()
