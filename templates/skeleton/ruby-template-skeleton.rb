#!/usr/bin/env ruby
# frozen_string_literal: true
#
# CERT-X-GEN Ruby Template Skeleton
#
# @id: ruby-template-skeleton
# @name: Ruby Template Skeleton
# @author: CERT-X-GEN Security Team
# @severity: info
# @description: Skeleton template for writing security scanning templates in Ruby. Copy this file and customize it for your specific security check.
# @tags: skeleton, example, template, ruby
# @cwe: CWE-1008
# @confidence: 90
# @references: https://cwe.mitre.org/data/definitions/1008.html, https://github.com/cert-x-gen/templates
#
# Execution:
#   ruby template.rb --target example.com --json
#
# When run by CERT-X-GEN engine, environment variables are set:
#   CERT_X_GEN_TARGET_HOST - Target host/IP
#   CERT_X_GEN_TARGET_PORT - Target port
#   CERT_X_GEN_MODE=engine - Indicates engine mode (JSON output required)
#

require 'net/http'
require 'json'
require 'optparse'
require 'timeout'

# Template configuration
class TemplateConfig
  attr_accessor :id, :name, :author, :severity, :confidence, :tags, :cwe
  
  def initialize
    @id = 'template-skeleton'
    @name = 'Ruby Template Skeleton'
    @author = 'Your Name'
    @severity = 'high'
    @confidence = 90
    @tags = ['skeleton', 'example']
    @cwe = 'CWE-XXX'
  end
end

# Finding structure
class Finding
  attr_accessor :template_id, :severity, :confidence, :title, :description, 
                :evidence, :cwe, :cvss_score, :remediation, :references
  
  def initialize
    @evidence = {}
    @references = []
  end
  
  def to_hash
    {
      template_id: @template_id,
      severity: @severity,
      confidence: @confidence,
      title: @title,
      description: @description,
      evidence: @evidence,
      cwe: @cwe,
      cvss_score: @cvss_score,
      remediation: @remediation,
      references: @references
    }
  end
end

# Main template class
class CertXGenTemplate
  def initialize
    @config = TemplateConfig.new
    @target_host = nil
    @target_port = 80
    @json_output = false
    @context = {}
  end
  
  # ========================================
  # HELPER FUNCTIONS
  # ========================================
  
  # Get environment variable
  def get_env_var(name)
    ENV[name]
  end
  
  # Parse ports from string
  def parse_ports(ports_str)
    return [] if ports_str.nil? || ports_str.empty?
    
    ports_str.split(',').map { |p| p.strip.to_i }.reject(&:zero?)
  end
  
  # Get ports to scan
  def get_ports_to_scan
    override_ports = get_env_var('CERT_X_GEN_OVERRIDE_PORTS')
    if override_ports
      return parse_ports(override_ports)
    end
    
    # Default ports
    ports = [80, 443]
    
    # Add additional ports
    add_ports = get_env_var('CERT_X_GEN_ADD_PORTS')
    if add_ports
      additional = parse_ports(add_ports)
      ports.concat(additional)
    end
    
    ports.uniq.sort
  end
  
  # Test HTTP endpoint
  def test_http_endpoint(host, port)
    uri = URI("http://#{host}:#{port}/")
    
    begin
      Timeout.timeout(5) do
        response = Net::HTTP.get_response(uri)
        if response.code == '200'
          return response.body[0, 1024] # First 1024 characters
        end
      end
    rescue => e
      # Connection failed
    end
    
    nil
  end
  
  # Check for vulnerability indicators
  def check_vulnerability(response)
    return false if response.nil? || response.empty?
    
    response_lower = response.downcase
    indicators = %w[vulnerable exposed admin debug test demo]
    
    indicators.any? { |indicator| response_lower.include?(indicator) }
  end
  
  # Create a finding
  def create_finding(title, description, evidence, severity = nil)
    finding = Finding.new
    finding.template_id = @config.id
    finding.severity = severity || @config.severity
    finding.confidence = @config.confidence
    finding.title = title
    finding.description = description
    finding.evidence = evidence
    finding.cwe = @config.cwe
    
    # Calculate CVSS score based on severity
    finding.cvss_score = case finding.severity
                        when 'critical' then 9.0
                        when 'high' then 7.5
                        when 'medium' then 5.0
                        when 'low' then 3.0
                        else 0.0
                        end
    
    finding.remediation = 'Review the identified issue and apply security patches'
    finding.references = ['https://cwe.mitre.org/', 'https://nvd.nist.gov/']
    
    finding
  end
  
  # ========================================
  # MAIN SCANNING LOGIC
  # ========================================
  
  def execute_scan
    findings = []
    port = @target_port

    response = test_http_endpoint(@target_host, port)
    if response && check_vulnerability(response)
      evidence = {
        'endpoint' => "http://#{@target_host}:#{port}",
        'response_size' => response.length.to_s,
        'status' => 'vulnerable'
      }

      title = "Potential Vulnerability on #{@target_host}:#{port}"
      description = "Found potential vulnerability indicators on #{@target_host}:#{port}"

      findings << create_finding(title, description, evidence, 'high')
    end
    
    findings
  end
  
  # ========================================
  # CLI AND EXECUTION
  # ========================================
  
  def print_usage(program_name)
    puts "Usage: #{program_name} [OPTIONS] <target>"
    puts
    puts @config.name
    puts
    puts 'Options:'
    puts '  --target <HOST>  Target host or IP address'
    puts '  --port <PORT>    Target port (default: 80)'
    puts '  --json           Output findings as JSON'
    puts '  --help           Show this help message'
    puts
    puts 'Example:'
    puts "  #{program_name} --target example.com --port 443 --json"
  end
  
  def parse_args(args)
    OptionParser.new do |opts|
      opts.banner = "Usage: #{File.basename($0)} [OPTIONS] <target>"
      
      opts.on('--target HOST', 'Target host or IP address') do |host|
        @target_host = host
      end
      
      opts.on('--port PORT', Integer, 'Target port (default: 80)') do |port|
        @target_port = port
      end
      
      opts.on('--json', 'Output findings as JSON') do
        @json_output = true
      end
      
      opts.on('--help', 'Show this help message') do
        print_usage(File.basename($0))
        exit 0
      end
    end.parse!(args)
    
    # Get target from remaining arguments
    @target_host ||= args.first
    
    # Check environment variables (for CERT-X-GEN engine integration)
    @target_host ||= get_env_var('CERT_X_GEN_TARGET_HOST')
    
    port_str = get_env_var('CERT_X_GEN_TARGET_PORT')
    @target_port = port_str.to_i if port_str && !port_str.empty?
    
    @json_output = true if get_env_var('CERT_X_GEN_MODE')

    if (env = get_env_var('CERT_X_GEN_CONTEXT'))
      begin
        @context = JSON.parse(env)
      rescue JSON::ParserError
        @context = {}
      end
    end

    if (add = get_env_var('CERT_X_GEN_ADD_PORTS'))
      @context['add_ports'] = add
    end

    if (override_ports = get_env_var('CERT_X_GEN_OVERRIDE_PORTS'))
      @context['override_ports'] = override_ports
    end
    
    if @target_host.nil? || @target_host.empty?
      $stderr.puts 'Error: No target specified'
      return false
    end
    
    true
  end
  
  def run
    # Parse arguments
    return 1 unless parse_args(ARGV)
    
    # Print banner (if not JSON output)
    unless @json_output
      puts "\n╔════════════════════════════════════════════════════════════╗"
      printf "║  %-52s ║\n", @config.name
      puts '║  CERT-X-GEN Security Template                              ║'
      puts '╚════════════════════════════════════════════════════════════╝'
      puts
      puts "Target: #{@target_host}:#{@target_port}"
    end
    
    # Execute the scan
    findings = execute_scan
    
    # Output findings
    if @json_output
      puts JSON.pretty_generate(findings.map(&:to_hash))
    else
      if findings.empty?
        puts "\n[-] No issues found"
      else
        puts "\n[+] Found #{findings.length} issue(s):\n"
        findings.each do |finding|
          puts "[#{finding.severity}] #{finding.title}"
          puts "    #{finding.description}\n"
        end
      end
    end
    
    0
  end
end

# ========================================
# MAIN EXECUTION
# ========================================

if __FILE__ == $0
  template = CertXGenTemplate.new
  exit template.run
end
