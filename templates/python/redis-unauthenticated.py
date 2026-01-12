#!/usr/bin/env python3
# @id: redis-unauthenticated-python
# @name: Redis Unauthenticated Access Detection (Python)
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Redis instances exposed without authentication using Python
# @tags: redis, unauthenticated, database, nosql, cwe-306
# @cwe: CWE-306
# @cvss: 9.8
# @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
# @confidence: 95
# @version: 1.0.0
"""
Tests for Redis instances exposed without authentication.
"""

import socket
import sys
import json
from datetime import datetime

# Template metadata
METADATA = {
    "id": "redis-unauthenticated-python",
    "name": "Redis Unauthenticated Access Detection (Python)",
    "author": {
        "name": "CERT-X-GEN Security Team",
        "email": "security@cert-x-gen.io"
    },
    "severity": "critical",
    "description": "Detects Redis instances exposed without authentication using Python",
    "tags": ["redis", "unauthenticated", "database", "nosql", "python"],
    "language": "python",
    "confidence": 95,
    "cwe": ["CWE-306"],
    "references": [
        "https://redis.io/docs/management/security/",
        "https://cwe.mitre.org/data/definitions/306.html"
    ]
}

def test_redis(host, port=6379, timeout=10):
    """Test Redis for unauthenticated access"""
    findings = []
    
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Test commands
        commands = [
            b"INFO\r\n",
            b"PING\r\n",
            b"*1\r\n$4\r\nINFO\r\n",
            b"*1\r\n$4\r\nPING\r\n"
        ]
        
        responses = []
        for cmd in commands:
            try:
                sock.sendall(cmd)
                response = sock.recv(8192)
                if response:
                    responses.append(response.decode('utf-8', errors='ignore'))
            except Exception as e:
                continue
        
        sock.close()
        
        # Check for Redis indicators
        full_response = ''.join(responses)
        
        indicators = [
            'redis_version',
            'redis_mode',
            'used_memory',
            'connected_clients',
            'role:master',
            'role:slave',
            '+PONG'
        ]
        
        matched_patterns = [ind for ind in indicators if ind in full_response]
        
        if matched_patterns:
            finding = {
                "target": f"{host}:{port}",
                "template_id": METADATA["id"],
                "severity": METADATA["severity"],
                "confidence": METADATA["confidence"],
                "title": METADATA["name"],
                "description": METADATA["description"],
                "evidence": {
                    "request": "\\r\\n".join([cmd.decode('utf-8', errors='ignore').strip() for cmd in commands]),
                    "response": full_response[:1000],  # First 1000 chars
                    "matched_patterns": matched_patterns,
                    "data": {
                        "protocol": "tcp",
                        "port": port,
                        "response_length": len(full_response)
                    }
                },
                "cwe_ids": METADATA["cwe"],
                "tags": METADATA["tags"],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            findings.append(finding)
            
    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        pass
    
    return findings

def main():
    """Main execution"""
    # Support both CLI args and environment variables (for engine mode)
    import os
    
    if os.getenv('CERT_X_GEN_MODE') == 'engine':
        # Engine mode - read from environment variables
        host = os.getenv('CERT_X_GEN_TARGET_HOST')
        port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '6379'))
        if not host:
            print(json.dumps({"error": "CERT_X_GEN_TARGET_HOST not set"}))
            sys.exit(1)
    else:
        # CLI mode - read from command-line arguments
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: redis-unauthenticated.py <host> [port]"}))
            sys.exit(1)
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 6379
    
    findings = test_redis(host, port)
    
    result = {
        "findings": findings,
        "metadata": METADATA
    }
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
