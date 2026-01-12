#!/usr/bin/env php
<?php
// @id: redis-unauthenticated-php
// @name: Redis Unauthenticated Access Detection (PHP)
// @author: CERT-X-GEN Security Team
// @severity: critical
// @description: Detects Redis instances exposed without authentication using PHP
// @tags: redis, unauthenticated, database, nosql, cwe-306
// @cwe: CWE-306
// @cvss: 9.8
// @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
// @confidence: 95
// @version: 1.0.0

// Template metadata
$METADATA = [
    'id' => 'redis-unauthenticated-php',
    'name' => 'Redis Unauthenticated Access Detection (PHP)',
    'author' => [
        'name' => 'CERT-X-GEN Security Team',
        'email' => 'security@cert-x-gen.io'
    ],
    'severity' => 'critical',
    'description' => 'Detects Redis instances exposed without authentication using PHP',
    'tags' => ['redis', 'unauthenticated', 'database', 'nosql', 'php'],
    'language' => 'php',
    'confidence' => 95,
    'cwe' => ['CWE-306'],
    'references' => [
        'https://redis.io/docs/management/security/',
        'https://cwe.mitre.org/data/definitions/306.html'
    ]
];

function test_redis($host, $port = 6379, $timeout = 10) {
    $findings = [];
    
    try {
        $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
        
        if (!$socket) {
            return $findings;
        }
        
        stream_set_timeout($socket, $timeout);
        
        // Send test commands
        $commands = [
            "INFO\r\n",
            "PING\r\n",
            "*1\r\n$4\r\nINFO\r\n",
            "*1\r\n$4\r\nPING\r\n"
        ];
        
        $response_data = '';
        
        foreach ($commands as $cmd) {
            fwrite($socket, $cmd);
        }
        
        // Read response
        while (!feof($socket)) {
            $chunk = fread($socket, 8192);
            if ($chunk === false) break;
            $response_data .= $chunk;
            if (strlen($response_data) > 8192) break;
        }
        
        fclose($socket);
        
        // Check for Redis indicators
        $indicators = [
            'redis_version',
            'redis_mode',
            'used_memory',
            'connected_clients',
            'role:master',
            'role:slave',
            '+PONG'
        ];
        
        $matched_patterns = [];
        foreach ($indicators as $indicator) {
            if (strpos($response_data, $indicator) !== false) {
                $matched_patterns[] = $indicator;
            }
        }
        
        if (!empty($matched_patterns)) {
            global $METADATA;
            
            $finding = [
                'target' => "$host:$port",
                'template_id' => $METADATA['id'],
                'severity' => $METADATA['severity'],
                'confidence' => $METADATA['confidence'],
                'title' => $METADATA['name'],
                'description' => $METADATA['description'],
                'evidence' => [
                    'request' => implode("\\n", $commands),
                    'response' => substr($response_data, 0, 1000),
                    'matched_patterns' => $matched_patterns,
                    'data' => [
                        'protocol' => 'tcp',
                        'port' => $port,
                        'response_length' => strlen($response_data)
                    ]
                ],
                'cwe_ids' => $METADATA['cwe'],
                'tags' => $METADATA['tags'],
                'timestamp' => gmdate('Y-m-d\TH:i:s.000\Z')
            ];
            $findings[] = $finding;
        }
        
    } catch (Exception $e) {
        // Connection failed, no findings
    }
    
    return $findings;
}

function main() {
    global $argv, $METADATA;
    
    // Support both CLI args and environment variables (for engine mode)
    if (getenv('CERT_X_GEN_MODE') === 'engine') {
        // Engine mode - read from environment variables
        $host = getenv('CERT_X_GEN_TARGET_HOST');
        $port = getenv('CERT_X_GEN_TARGET_PORT') ?: 6379;
        if (!$host) {
            echo json_encode(['error' => 'CERT_X_GEN_TARGET_HOST not set']) . "\n";
            exit(1);
        }
    } else {
        // CLI mode - read from command-line arguments
        if (count($argv) < 2) {
            echo json_encode(['error' => 'Usage: redis-unauthenticated.php <host> [port]']) . "\n";
            exit(1);
        }
        $host = $argv[1];
        $port = isset($argv[2]) ? intval($argv[2]) : 6379;
    }
    
    $findings = test_redis($host, $port);
    
    $result = [
        'findings' => $findings,
        'metadata' => $METADATA
    ];
    
    echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
}

main();
?>
