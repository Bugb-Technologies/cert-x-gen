#!/usr/bin/env python3
# @id: rabbitmq-default-credentials
# @name: RabbitMQ Default Credentials Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects RabbitMQ instances using default credentials (guest/guest), allowing unauthorized access to queues and messages
# @tags: rabbitmq, message-queue, default-credentials, authentication, amqp, cwe-798
# @cwe: CWE-798
# @cvss: 9.8
# @references: https://cwe.mitre.org/data/definitions/798.html, https://www.rabbitmq.com/access-control.html
# @confidence: 95
# @version: 1.0.0
"""
CERT-X-GEN RabbitMQ Default Credentials Template

Detects RabbitMQ message broker instances using default credentials (guest/guest),
allowing unauthorized access to queues, exchanges, and message data.
"""

import json
import sys
import os
import argparse
import requests
from typing import List, Dict, Any
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CERT-X-GEN Template Base Class
class CertXGenTemplate:
    """Base class for CERT-X-GEN Python templates"""
    
    def __init__(self):
        # Template metadata
        self.id = "rabbitmq-default-credentials"
        self.name = "RabbitMQ Default Credentials Detection"
        self.author = "CERT-X-GEN Security Team"
        self.severity = "critical"  # critical, high, medium, low, info
        self.tags = ["rabbitmq", "default-credentials", "authentication", "cwe-798"]
        self.confidence = 95  # 0-100
        self.cwe = "CWE-798"  # CWE ID if applicable
        
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
            # Log error as JSON finding for CERT-X-GEN engine
            error_finding = self.create_finding(
                title="Scan Error",
                description=f"Error during scan execution: {str(e)}",
                evidence={"error": str(e), "type": type(e).__name__},
                severity="info"
            )
            findings.append(error_finding)
        
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

class RabbitMQDefaultCredsTemplate(CertXGenTemplate):
    """Template for detecting RabbitMQ default/weak credentials"""
    
    def __init__(self):
        super().__init__()
        self.id = "rabbitmq-default-credentials"
        self.name = "RabbitMQ Default Credentials Detection"
        self.severity = "critical"
        self.tags = ["rabbitmq", "default-credentials", "authentication", "cwe-798"]
        self.confidence = 95
        self.cwe = "CWE-798"
        self.ports = [15672, 15671, 5672]  # Management UI, AMQPS, AMQP
        
        # Default and common credentials to test
        self.credentials = [
            ("guest", "guest"),         # Default RabbitMQ
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "rabbitmq"),
            ("rabbitmq", "rabbitmq"),
            ("user", "user"),
            ("test", "test"),
        ]
    
    def execute(self, target: str, port: int = 80) -> List[Dict[str, Any]]:
        """
        Execute template against target
        
        Args:
            target: Target hostname or IP
            port: Target port (not used directly, we test multiple ports)
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test Management API (HTTP)
        for port in [15672, 15671]:
            scheme = "https" if port == 15671 else "http"
            findings.extend(self._test_management_api(target, port, scheme))
        
        # Test AMQP protocol
        findings.extend(self._test_amqp_protocol(target))
        
        return findings
    
    def _test_management_api(self, target: str, port: int, scheme: str) -> List[Dict[str, Any]]:
        """Test RabbitMQ Management API with default credentials"""
        findings = []
        base_url = f"{scheme}://{target}:{port}"
        
        for username, password in self.credentials:
            try:
                # Test authentication on /api/whoami endpoint
                url = f"{base_url}/api/whoami"
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Authentication successful
                    user_info = response.json()
                    
                    findings.append(self.create_finding(
                        title=f"RabbitMQ Default/Weak Credentials: {username}:{password}",
                        description=f"RabbitMQ Management API accessible with credentials {username}:{password}",
                        evidence={
                            "username": username,
                            "password": password,
                            "endpoint": url,
                            "user_info": user_info,
                            "tags": user_info.get("tags", [])
                        },
                        severity="critical",
                        remediation=self._get_remediation()
                    ))
                    
                    # Try to enumerate more info
                    overview = self._get_cluster_overview(base_url, username, password)
                    if overview:
                        findings.append(self.create_finding(
                            title="RabbitMQ Cluster Information Exposed",
                            description="Successfully retrieved cluster configuration",
                            evidence={
                                "rabbitmq_version": overview.get("rabbitmq_version"),
                                "cluster_name": overview.get("cluster_name"),
                                "node": overview.get("node"),
                                "erlang_version": overview.get("erlang_version")
                            },
                            severity="high"
                        ))
                    
                    # Try to list vhosts
                    vhosts = self._list_vhosts(base_url, username, password)
                    if vhosts:
                        findings.append(self.create_finding(
                            title="RabbitMQ Virtual Hosts Enumeration",
                            description=f"Successfully enumerated {len(vhosts)} virtual hosts",
                            evidence={
                                "vhosts": [v.get("name") for v in vhosts]
                            },
                            severity="high"
                        ))
                    
                    # Try to list queues
                    queues = self._list_queues(base_url, username, password)
                    if queues:
                        findings.append(self.create_finding(
                            title="RabbitMQ Queues Enumeration",
                            description=f"Successfully enumerated {len(queues)} queues",
                            evidence={
                                "queue_count": len(queues),
                                "queue_names": [q.get("name") for q in queues[:10]]
                            },
                            severity="high"
                        ))
                    
                    # Only test first working credentials
                    break
                    
            except requests.exceptions.RequestException:
                # Connection failed, try next port
                continue
        
        return findings
    
    def _get_cluster_overview(self, base_url: str, username: str, password: str) -> Dict:
        """Get RabbitMQ cluster overview"""
        try:
            response = requests.get(
                f"{base_url}/api/overview",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}
    
    def _list_vhosts(self, base_url: str, username: str, password: str) -> List[Dict]:
        """List virtual hosts"""
        try:
            response = requests.get(
                f"{base_url}/api/vhosts",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []
    
    def _list_queues(self, base_url: str, username: str, password: str) -> List[Dict]:
        """List queues"""
        try:
            response = requests.get(
                f"{base_url}/api/queues",
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []
    
    def _test_amqp_protocol(self, target: str) -> List[Dict[str, Any]]:
        """Test AMQP protocol with default credentials"""
        findings = []
        
        try:
            # Try to connect using pika library if available
            import pika
            
            for username, password in self.credentials:
                try:
                    credentials = pika.PlainCredentials(username, password)
                    parameters = pika.ConnectionParameters(
                        host=target,
                        port=5672,
                        credentials=credentials,
                        connection_attempts=1,
                        socket_timeout=3
                    )
                    
                    connection = pika.BlockingConnection(parameters)
                    
                    findings.append(self.create_finding(
                        title=f"RabbitMQ AMQP Authentication with {username}:{password}",
                        description="Successfully authenticated to AMQP protocol",
                        evidence={
                            "username": username,
                            "password": password,
                            "protocol": "AMQP",
                            "port": 5672
                        },
                        severity="critical",
                        remediation=self._get_remediation()
                    ))
                    
                    connection.close()
                    break
                    
                except:
                    continue
                    
        except ImportError:
            # pika not available, skip AMQP test
            pass
        except Exception as e:
            pass
        
        return findings
    
    def _get_remediation(self) -> str:
        """Get remediation steps"""
        return """
1. Change default credentials immediately:
   rabbitmqctl change_password guest NEW_STRONG_PASSWORD
   
2. Delete guest user if not needed:
   rabbitmqctl delete_user guest

3. Create new admin user with strong password:
   rabbitmqctl add_user admin STRONG_PASSWORD
   rabbitmqctl set_user_tags admin administrator
   rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"

4. Disable guest user remote access (rabbitmq.config):
   {rabbit, [{loopback_users, [<<"guest">>]}]}

5. Enable TLS/SSL for Management API:
   management.ssl.port = 15671
   management.ssl.cacertfile = /path/to/ca_certificate.pem
   management.ssl.certfile = /path/to/server_certificate.pem
   management.ssl.keyfile = /path/to/server_key.pem

6. Use strong authentication mechanisms:
   - LDAP integration
   - OAuth 2.0
   - X.509 certificates

7. Implement network segmentation
8. Enable audit logging
9. Regular security audits
10. Keep RabbitMQ updated to latest version
"""
    
    def get_references(self) -> List[str]:
        """Get references and documentation"""
        return [
            "https://www.rabbitmq.com/access-control.html",
            "https://www.rabbitmq.com/management.html"
        ]
if __name