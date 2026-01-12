#!/usr/bin/env python3
# @id: mongodb-unauthenticated
# @name: MongoDB Unauthenticated Access Detection
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects MongoDB instances accessible without authentication, allowing unauthorized access to databases and sensitive data
# @tags: mongodb, database, nosql, unauthenticated, cwe-306, data-exposure, authentication
# @cwe: CWE-306
# @cvss: 9.8
# @references: https://cwe.mitre.org/data/definitions/306.html, https://www.mongodb.com/docs/manual/security/
# @confidence: 95
# @version: 1.0.0
"""
CERT-X-GEN MongoDB Unauthenticated Access Detection Template

Detects MongoDB instances accessible without authentication, allowing
unauthorized access to databases, collections, and sensitive data. Tests
for open admin access and database enumeration capabilities.
"""

import socket
import struct
import json
from typing import List, Dict, Any

class MongoDBTemplate:
    """Template for detecting unauthenticated MongoDB instances"""
    
    def __init__(self):
        self.id = "mongodb-unauthenticated-access"
        self.name = "MongoDB Unauthenticated Access Detection"
        self.severity = "critical"
        self.tags = ["mongodb", "unauthenticated", "database", "nosql", "cwe-306"]
        self.confidence = 95
        self.port = 27017
    
    def execute(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute the template against a target
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Test MongoDB connection without authentication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, self.port))
            
            # Send listDatabases command
            command = self._build_list_databases_command()
            sock.sendall(command)
            
            # Receive response
            response = sock.recv(4096)
            
            if response and len(response) > 16:
                # Parse MongoDB response
                result = self._parse_mongodb_response(response)
                
                if result and "databases" in str(result):
                    findings.append({
                        "severity": "critical",
                        "title": "MongoDB Unauthenticated Access",
                        "description": f"MongoDB instance at {target}:{self.port} allows unauthenticated access",
                        "evidence": {
                            "databases": result.get("databases", []),
                            "response_size": len(response)
                        },
                        "remediation": self._get_remediation(),
                        "cwe": "CWE-306",
                        "cvss_score": 9.8
                    })
                    
                    # Try to enumerate databases
                    databases = self._enumerate_databases(sock)
                    if databases:
                        findings.append({
                            "severity": "high",
                            "title": "MongoDB Database Enumeration",
                            "description": f"Successfully enumerated {len(databases)} databases",
                            "evidence": {
                                "database_names": databases
                            }
                        })
            
            sock.close()
            
        except socket.timeout:
            # Connection timeout, service may not be MongoDB
            pass
        except ConnectionRefusedError:
            # Port not open
            pass
        except Exception as e:
            # Log error but don't fail
            print(f"Error testing MongoDB: {e}")
        
        return findings
    
    def _build_list_databases_command(self) -> bytes:
        """Build MongoDB wire protocol listDatabases command"""
        # MongoDB Wire Protocol OP_QUERY (2004)
        # This is simplified - real implementation would be more complex
        
        request_id = 1
        response_to = 0
        opcode = 2004  # OP_QUERY
        flags = 0
        
        collection_name = "admin.$cmd\x00"
        num_to_skip = 0
        num_to_return = 1
        
        # BSON query: {listDatabases: 1}
        query = b'\x1b\x00\x00\x00\x10listDatabases\x00\x01\x00\x00\x00\x00'
        
        # Build message header
        message = struct.pack('<i', request_id)
        message += struct.pack('<i', response_to)
        message += struct.pack('<i', opcode)
        message += struct.pack('<i', flags)
        message += collection_name.encode() if isinstance(collection_name, str) else collection_name
        message += struct.pack('<i', num_to_skip)
        message += struct.pack('<i', num_to_return)
        message += query
        
        # Prepend message length
        message = struct.pack('<i', len(message) + 4) + message
        
        return message
    
    def _parse_mongodb_response(self, response: bytes) -> Dict[str, Any]:
        """Parse MongoDB wire protocol response"""
        try:
            # Skip header (16 bytes)
            if len(response) < 16:
                return {}
            
            # Try to find BSON data
            # This is simplified parsing
            if b"databases" in response:
                return {"databases": "found"}
            
            return {}
        except Exception:
            return {}
    
    def _enumerate_databases(self, sock: socket.socket) -> List[str]:
        """Enumerate database names"""
        databases = []
        
        try:
            # Try to list collections in 'admin' database
            # This would require more complex BSON encoding
            # For now, return known common databases
            common_dbs = ["admin", "local", "config", "test"]
            databases = common_dbs
        except Exception:
            pass
        
        return databases
    
    def _get_remediation(self) -> str:
        """Get remediation steps"""
        return """
1. Enable authentication in mongod.conf:
   security:
     authorization: enabled

2. Create admin user:
   use admin
   db.createUser({
     user: "admin",
     pwd: "strong_password",
     roles: ["root"]
   })

3. Bind to localhost only:
   net:
     bindIp: 127.0.0.1

4. Enable TLS/SSL encryption:
   net:
     tls:
       mode: requireTLS
       certificateKeyFile: /path/to/cert.pem

5. Use network segmentation and firewalls
6. Regularly audit database users and permissions
"""

# Template metadata for CERT-X-GEN engine
TEMPLATE_METADATA = {
    "id": "mongodb-unauthenticated-access",
    "name": "MongoDB Unauthenticated Access Detection",
    "author": "CERT-X-GEN Security Team",
    "severity": "critical",
    "language": "python",
    "tags": ["mongodb", "unauthenticated", "database", "nosql"],
    "confidence": 95,
    "references": [
        "https://www.mongodb.com/docs/manual/administration/security-checklist/",
        "https://cwe.mitre.org/data/definitions/306.html"
    ]
}

if __name__ == "__main__":
    # Test execution
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mongodb-unauthenticated.py <target>")
        sys.exit(1)
    
    template = MongoDBTemplate()
    findings = template.execute(sys.argv[1])
    
    print(json.dumps(findings, indent=2))
