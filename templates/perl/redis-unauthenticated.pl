#!/usr/bin/env perl
# @id: redis-unauthenticated-perl
# @name: Redis Unauthenticated Access Detection (Perl)
# @author: CERT-X-GEN Security Team
# @severity: critical
# @description: Detects Redis instances exposed without authentication using Perl
# @tags: redis, unauthenticated, database, nosql, cwe-306
# @cwe: CWE-306
# @cvss: 9.8
# @references: https://redis.io/docs/management/security/, https://cwe.mitre.org/data/definitions/306.html
# @confidence: 95
# @version: 1.0.0

use strict;
use warnings;
use IO::Socket::INET;
use JSON;
use Time::HiRes qw(time);

# Template metadata
my $METADATA = {
    id => "redis-unauthenticated-perl",
    name => "Redis Unauthenticated Access Detection (Perl)",
    author => {
        name => "CERT-X-GEN Security Team",
        email => 'security@cert-x-gen.io'
    },
    severity => "critical",
    description => "Detects Redis instances exposed without authentication using Perl",
    tags => ["redis", "unauthenticated", "database", "nosql", "perl"],
    language => "perl",
    confidence => 95,
    cwe => ["CWE-306"],
    references => [
        "https://redis.io/docs/management/security/",
        "https://cwe.mitre.org/data/definitions/306.html"
    ]
};

sub test_redis {
    my ($host, $port, $timeout) = @_;
    $port ||= 6379;
    $timeout ||= 10;
    
    my @findings = ();
    
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;
        
        my $socket = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto    => 'tcp',
            Timeout  => $timeout
        );
        
        if (!$socket) {
            alarm 0;
            return @findings;
        }
        
        # Send test commands
        my @commands = (
            "INFO\r\n",
            "PING\r\n",
            "*1\r\n\$4\r\nINFO\r\n",
            "*1\r\n\$4\r\nPING\r\n"
        );
        
        my $response_data = "";
        
        foreach my $cmd (@commands) {
            print $socket $cmd;
        }
        
        # Read response
        my $buffer;
        while (my $bytes = sysread($socket, $buffer, 8192)) {
            $response_data .= $buffer;
            last if length($response_data) > 8192;
        }
        
        close($socket);
        alarm 0;
        
        # Check for Redis indicators
        my @indicators = (
            'redis_version',
            'redis_mode',
            'used_memory',
            'connected_clients',
            'role:master',
            'role:slave',
            '+PONG'
        );
        
        my @matched_patterns = grep { index($response_data, $_) != -1 } @indicators;
        
        if (@matched_patterns) {
            my $finding = {
                target => "$host:$port",
                template_id => $METADATA->{id},
                severity => $METADATA->{severity},
                confidence => $METADATA->{confidence},
                title => $METADATA->{name},
                description => $METADATA->{description},
                evidence => {
                    request => join("\\n", @commands),
                    response => substr($response_data, 0, 1000),
                    matched_patterns => \@matched_patterns,
                    data => {
                        protocol => "tcp",
                        port => $port,
                        response_length => length($response_data)
                    }
                },
                cwe_ids => $METADATA->{cwe},
                tags => $METADATA->{tags},
                timestamp => sprintf("%04d-%02d-%02dT%02d:%02d:%02d.000Z", 
                    (gmtime)[5]+1900, (gmtime)[4]+1, (gmtime)[3,2,1,0])
            };
            push @findings, $finding;
        }
    };
    
    return @findings;
}

sub main {
    # Support both CLI args and environment variables (for engine mode)
    my ($host, $port);
    
    if ($ENV{CERT_X_GEN_MODE} && $ENV{CERT_X_GEN_MODE} eq 'engine') {
        # Engine mode - read from environment variables
        $host = $ENV{CERT_X_GEN_TARGET_HOST};
        $port = $ENV{CERT_X_GEN_TARGET_PORT} || 6379;
        if (!$host) {
            print encode_json({ error => "CERT_X_GEN_TARGET_HOST not set" }) . "\n";
            exit 1;
        }
    } else {
        # CLI mode - read from command-line arguments
        if (@ARGV < 1) {
            print encode_json({ error => "Usage: redis-unauthenticated.pl <host> [port]" }) . "\n";
            exit 1;
        }
        $host = $ARGV[0];
        $port = $ARGV[1] || 6379;
    }
    
    my @findings = test_redis($host, $port);
    
    my $result = {
        findings => \@findings,
        metadata => $METADATA
    };
    
    print JSON->new->pretty->encode($result);
}

main();
