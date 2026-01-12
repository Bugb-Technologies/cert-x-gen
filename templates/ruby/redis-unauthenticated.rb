#!/usr/bin/env ruby
# @id: redis-unauthenticated-ruby
# @name: Redis Unauthenticated Access Detection (Ruby)
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Redis instances exposed without authentication using Ruby
# @tags: redis, unauthenticated, database, nosql, cwe-306
# @cwe: CWE-306
# @cvss: 9.8
# @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
# @confidence: 95
# @version: 1.0.0

require 'socket'
require 'json'
require 'time'
require 'timeout'

# Template metadata
METADATA = {
  id: "redis-unauthenticated-ruby",
  name: "Redis Unauthenticated Access Detection (Ruby)",
  author: {
    name: "CERT-X-GEN Security Team",
    email: "security@cert-x-gen.io"
  },
  severity: "critical",
  description: "Detects Redis instances exposed without authentication using Ruby",
  tags: ["redis", "unauthenticated", "database", "nosql", "ruby"],
  language: "ruby",
  confidence: 95,
  cwe: ["CWE-306"],
  references: [
    "https://redis.io/docs/management/security/",
    "https://cwe.mitre.org/data/definitions/306.html"
  ]
}

def test_redis(host, port = 6379, timeout = 10)
  findings = []
  
  begin
    socket = Socket.tcp(host, port, connect_timeout: timeout)
    
    # Send test commands
    commands = [
      "INFO\r\n",
      "PING\r\n",
      "*1\r\n$4\r\nINFO\r\n",
      "*1\r\n$4\r\nPING\r\n"
    ]
    
    response_data = ""
    
    # Send all commands
    commands.each do |cmd|
      socket.write(cmd)
    end
    socket.flush
    
    # Wait a bit for response
    sleep(0.3)
    
    # Read available data with timeout
    begin
      Timeout.timeout(2) do
        # Set socket to non-blocking
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [1, 0].pack('l_2'))
        
        # Read in chunks until no more data
        loop do
          begin
            chunk = socket.recv(4096)
            break if chunk.nil? || chunk.empty?
            response_data += chunk
          rescue Errno::EAGAIN, Errno::EWOULDBLOCK
            # No more data available
            break
          end
        end
      end
    rescue Timeout::Error, Errno::ETIMEDOUT
      # Timeout is ok, use what we have
    end
    
    socket.close rescue nil
    
    # Check for Redis indicators
    indicators = [
      'redis_version',
      'redis_mode',
      'used_memory',
      'connected_clients',
      'role:master',
      'role:slave',
      '+PONG'
    ]
    
    matched_patterns = indicators.select { |ind| response_data.include?(ind) }
    
    if matched_patterns.any?
      finding = {
        target: "#{host}:#{port}",
        template_id: METADATA[:id],
        severity: METADATA[:severity],
        confidence: METADATA[:confidence],
        title: METADATA[:name],
        description: METADATA[:description],
        evidence: {
          request: commands.join("\\n"),
          response: response_data[0...1000],
          matched_patterns: matched_patterns,
          data: {
            protocol: "tcp",
            port: port,
            response_length: response_data.length
          }
        },
        cwe_ids: METADATA[:cwe],
        tags: METADATA[:tags],
        timestamp: Time.now.utc.iso8601
      }
      findings << finding
    end
    
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError => e
    # Connection failed, no findings
  rescue => e
    # Other errors, no findings
  end
  
  findings
end

def main
  # Support both CLI args and environment variables (for engine mode)
  if ENV['CERT_X_GEN_MODE'] == 'engine'
    # Engine mode - read from environment variables
    host = ENV['CERT_X_GEN_TARGET_HOST']
    port = (ENV['CERT_X_GEN_TARGET_PORT'] || '6379').to_i
    if host.nil? || host.empty?
      puts JSON.generate({ error: "CERT_X_GEN_TARGET_HOST not set" })
      exit 1
    end
  else
    # CLI mode - read from command-line arguments
    if ARGV.length < 1
      puts JSON.generate({ error: "Usage: redis-unauthenticated.rb <host> [port]" })
      exit 1
    end
    host = ARGV[0]
    port = ARGV[1] ? ARGV[1].to_i : 6379
  end
  
  findings = test_redis(host, port)
  
  result = {
    findings: findings,
    metadata: METADATA
  }
  
  puts JSON.pretty_generate(result)
end

main if __FILE__ == $PROGRAM_NAME
