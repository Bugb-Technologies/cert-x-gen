#!/usr/bin/env perl
#
# CERT-X-GEN Perl Template Skeleton
# 
# This is a skeleton template for writing security scanning templates in Perl.
# Copy this file and customize it for your specific security check.
# 
# Template Metadata:
#   ID: template-skeleton
#   Name: Perl Template Skeleton
#   Author: Your Name
#   Severity: high
#   Tags: skeleton, example
#   Language: perl
# 
# Execution:
#   perl template.pl --target example.com --json
# 
# Dependencies:
#   - Perl standard library (LWP::UserAgent, JSON, etc.)
#

use strict;
use warnings;
use LWP::UserAgent;
use JSON;
use Getopt::Long;
use Time::HiRes qw(time);

# Template configuration
my %config = (
    id => 'template-skeleton',
    name => 'Perl Template Skeleton',
    author => 'Your Name',
    severity => 'high',
    confidence => 90,
    tags => ['skeleton', 'example'],
    cwe => 'CWE-XXX'
);

# Global variables
my $target_host = '';
my $target_port = 80;
my $json_output = 0;
my %context_data;

# ========================================
# HELPER FUNCTIONS
# ========================================

# Get environment variable
sub get_env_var {
    my ($name) = @_;
    return $ENV{$name};
}

# Parse ports from string
sub parse_ports {
    my ($ports_str) = @_;
    return () unless $ports_str;
    
    my @ports = split(',', $ports_str);
    return map { int($_) } grep { /^\d+$/ } map { s/^\s+|\s+$//gr } @ports;
}

# Get ports to scan
sub get_ports_to_scan {
    my $override_ports = get_env_var('CERT_X_GEN_OVERRIDE_PORTS');
    if ($override_ports) {
        return parse_ports($override_ports);
    }
    
    # Default ports
    my @ports = (80, 443);
    
    # Add additional ports
    my $add_ports = get_env_var('CERT_X_GEN_ADD_PORTS');
    if ($add_ports) {
        my @additional = parse_ports($add_ports);
        push @ports, @additional;
    }
    
    # Remove duplicates and sort
    my %seen;
    @ports = sort grep { !$seen{$_}++ } @ports;
    
    return @ports;
}

# Test HTTP endpoint
sub test_http_endpoint {
    my ($host, $port) = @_;
    
    my $ua = LWP::UserAgent->new(
        timeout => 5,
        max_redirect => 3
    );
    
    my $url = "http://$host:$port/";
    my $response = $ua->get($url);
    
    if ($response->is_success) {
        my $content = $response->content;
        return substr($content, 0, 1024); # First 1024 characters
    }
    
    return undef;
}

# Check for vulnerability indicators
sub check_vulnerability {
    my ($response) = @_;
    return 0 unless $response;
    
    my $response_lower = lc($response);
    my @indicators = qw(vulnerable exposed admin debug test demo);
    
    for my $indicator (@indicators) {
        return 1 if index($response_lower, $indicator) != -1;
    }
    
    return 0;
}

# Create a finding
sub create_finding {
    my ($title, $description, $evidence, $severity) = @_;
    
    $severity ||= $config{severity};
    
    # Calculate CVSS score based on severity
    my $cvss_score;
    if ($severity eq 'critical') {
        $cvss_score = 9.0;
    } elsif ($severity eq 'high') {
        $cvss_score = 7.5;
    } elsif ($severity eq 'medium') {
        $cvss_score = 5.0;
    } elsif ($severity eq 'low') {
        $cvss_score = 3.0;
    } else {
        $cvss_score = 0.0;
    }
    
    return {
        template_id => $config{id},
        severity => $severity,
        confidence => $config{confidence},
        title => $title,
        description => $description,
        evidence => $evidence,
        cwe => $config{cwe},
        cvss_score => $cvss_score,
        remediation => 'Review the identified issue and apply security patches',
        references => ['https://cwe.mitre.org/', 'https://nvd.nist.gov/']
    };
}

# ========================================
# MAIN SCANNING LOGIC
# ========================================

sub execute_scan {
    my @findings;
    my $port = $target_port;

    my $response = test_http_endpoint($target_host, $port);
    if ($response && check_vulnerability($response)) {
        my $evidence = {
            endpoint => "http://$target_host:$port",
            response_size => length($response),
            status => 'vulnerable'
        };

        my $title = "Potential Vulnerability on $target_host:$port";
        my $description = "Found potential vulnerability indicators on $target_host:$port";

        push @findings, create_finding($title, $description, $evidence, 'high');
    }
    
    return @findings;
}

# ========================================
# CLI AND EXECUTION
# ========================================

sub print_usage {
    my ($program_name) = @_;
    print "Usage: $program_name [OPTIONS] <target>\n\n";
    print "$config{name}\n\n";
    print "Options:\n";
    print "  --target <HOST>  Target host or IP address\n";
    print "  --port <PORT>    Target port (default: 80)\n";
    print "  --json           Output findings as JSON\n";
    print "  --help           Show this help message\n\n";
    print "Example:\n";
    print "  $program_name --target example.com --port 443 --json\n";
}

sub parse_args {
    my @args = @_;
    
    GetOptions(
        'target=s' => \$target_host,
        'port=i' => \$target_port,
        'json' => \$json_output,
        'help' => sub { print_usage($0); exit 0; }
    ) or die "Error in command line arguments\n";
    
    # Get target from remaining arguments
    $target_host = $ARGV[0] unless $target_host;
    
    # Check environment variables (for CERT-X-GEN engine integration)
    $target_host = get_env_var('CERT_X_GEN_TARGET_HOST') unless $target_host;
    
    my $port_str = get_env_var('CERT_X_GEN_TARGET_PORT');
    $target_port = int($port_str) if $port_str && $port_str =~ /^\d+$/;
    
    $json_output = 1 if get_env_var('CERT_X_GEN_MODE');

    if (my $ctx = get_env_var('CERT_X_GEN_CONTEXT')) {
        $context_data{raw_context} = $ctx;
    }
    if (my $add = get_env_var('CERT_X_GEN_ADD_PORTS')) {
        $context_data{add_ports} = $add;
    }
    if (my $override = get_env_var('CERT_X_GEN_OVERRIDE_PORTS')) {
        $context_data{override_ports} = $override;
    }
    
    unless ($target_host) {
        print STDERR "Error: No target specified\n";
        return 0;
    }
    
    return 1;
}

sub run {
    # Parse arguments
    return 1 unless parse_args(@ARGV);
    
    # Print banner (if not JSON output)
    unless ($json_output) {
        print "\n╔════════════════════════════════════════════════════════════╗\n";
        printf "║  %-52s ║\n", $config{name};
        print "║  CERT-X-GEN Security Template                              ║\n";
        print "╚════════════════════════════════════════════════════════════╝\n\n";
        print "Target: $target_host:$target_port\n";
    }
    
    # Execute the scan
    my @findings = execute_scan();
    
    # Output findings
    if ($json_output) {
        my $json = JSON->new->pretty;
        print $json->encode(\@findings);
    } else {
        if (@findings == 0) {
            print "\n[-] No issues found\n";
        } else {
            print "\n[+] Found " . scalar(@findings) . " issue(s):\n\n";
            for my $finding (@findings) {
                print "[$finding->{severity}] $finding->{title}\n";
                print "    $finding->{description}\n\n";
            }
        }
    }
    
    return 0;
}

# ========================================
# MAIN EXECUTION
# ========================================

exit run();
