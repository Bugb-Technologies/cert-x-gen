# CERT-X-GEN Template Registry

This document provides a comprehensive registry of all available templates across all supported languages.

## Template Categories

### 1. Network Service Templates (Unauthenticated Access)

#### Database Services
- **Redis Unauthenticated** (`c/redis-unauthenticated.c`) - Port 6379
- **MongoDB Unauthenticated** (`go/mongodb-unauthenticated.go`) - Port 27017
- **MySQL Default Credentials** (`c/mysql-default-creds.c`) - Port 3306
- **PostgreSQL Unauthenticated** (`go/postgresql-unauthenticated.go`) - Port 5432
- **Elasticsearch Unauthenticated** (`python/elasticsearch-unauthenticated.py`) - Port 9200

#### Web Services & Dashboards
- **Jenkins Unauthenticated** (`python/jenkins-unauthenticated.py`) - Port 8080
- **Kibana Unauthenticated** (`python/kibana-unauthenticated.py`) - Port 5601
- **Grafana Unauthenticated** (`python/grafana-unauthenticated.py`) - Port 3000
- **Prometheus Unauthenticated** (`go/prometheus-unauthenticated.go`) - Port 9090

#### Container & Orchestration
- **Docker API Unauthenticated** (`python/docker-api-unauthenticated.py`) - Ports 2375, 2376
- **Kubernetes API Unauthenticated** (`go/kubernetes-api-unauthenticated.go`) - Ports 6443, 8080
- **Docker Registry Unauthenticated** (`python/docker-registry-unauthenticated.py`) - Ports 5000, 5001
- **Docker Swarm Unauthenticated** (`python/docker-swarm-unauthenticated.py`) - Ports 2377, 7946, 4789

#### Cloud Provider Metadata
- **AWS EC2 Metadata** (`python/aws-metadata-unauthenticated.py`) - Ports 80, 443
- **Google Cloud Metadata** (`python/gcp-metadata-unauthenticated.py`) - Ports 80, 443
- **Azure Instance Metadata** (`python/azure-metadata-unauthenticated.py`) - Ports 80, 443

#### Message Queues & Caching
- **RabbitMQ Management** (`python/rabbitmq-unauthenticated.py`) - Port 15672
- **Memcached Unauthenticated** (`c/memcached-unauthenticated.c`) - Port 11211
- **Apache Kafka Unauthenticated** (`java/kafka-unauthenticated.java`) - Port 9092

### 2. Web Application Vulnerabilities

#### Injection Attacks
- **SQL Injection Detection** (`c/sql-injection-detection.c`) - Comprehensive SQL injection testing
- **XSS Detection** (`c/xss-detection.c`) - Cross-site scripting detection
- **Command Injection** (`cpp/command-injection.cpp`) - OS command injection
- **LDAP Injection** (`cpp/ldap-injection.cpp`) - LDAP injection vulnerabilities
- **NoSQL Injection** (`python/nosql-injection.py`) - NoSQL injection testing

#### File System Attacks
- **Directory Traversal** (`c/directory-traversal.c`) - Path traversal vulnerabilities
- **File Inclusion** (`php/file-inclusion.php`) - Local/Remote file inclusion
- **Path Traversal** (`go/path-traversal.go`) - Path traversal in Go applications

#### Deserialization Vulnerabilities
- **Java Deserialization** (`java/java-deserialization.java`) - Java deserialization attacks
- **PHP Unsafe Deserialization** (`php/php-unsafe-deserialization.php`) - PHP deserialization
- **Ruby Unsafe Deserialization** (`ruby/ruby-unsafe-deserialization.rb`) - Ruby deserialization

#### Server-Side Attacks
- **SSRF Detection** (`go/ssrf-detection.go`) - Server-Side Request Forgery
- **XXE Detection** (`cpp/xxe-detection.cpp`) - XML External Entity attacks
- **CSRF Detection** (`cpp/csrf-detection.cpp`) - Cross-Site Request Forgery

### 3. Framework-Specific Vulnerabilities

#### Spring Framework
- **Spring Boot Actuator** (`java/spring-boot-actuator.java`) - Exposed actuator endpoints
- **Spring Security Bypass** (`java/spring-security-bypass.java`) - Security bypasses

#### Apache Struts
- **Struts2 RCE** (`java/struts2-rce.java`) - Remote code execution

#### Log4j
- **Log4j RCE** (`java/log4j-rce.java`) - Log4j remote code execution

#### Ruby on Rails
- **Rails Mass Assignment** (`ruby/rails-mass-assignment.rb`) - Mass assignment vulnerabilities
- **Rails Code Injection** (`ruby/rails-code-injection.rb`) - Code injection

### 4. Infrastructure & DevOps

#### CI/CD Platforms
- **GitLab Unauthenticated** (`python/gitlab-unauthenticated.py`) - GitLab access
- **Jenkins Unauthenticated** (`python/jenkins-unauthenticated.py`) - Jenkins access
- **SonarQube Unauthenticated** (`python/sonarqube-unauthenticated.py`) - SonarQube access
- **Nexus Repository** (`python/nexus-unauthenticated.py`) - Nexus access

#### Monitoring & Observability
- **Zabbix Unauthenticated** (`python/zabbix-unauthenticated.py`) - Zabbix monitoring
- **Splunk Unauthenticated** (`python/splunk-unauthenticated.py`) - Splunk logging
- **Nagios Unauthenticated** (`python/nagios-unauthenticated.py`) - Nagios monitoring

#### Service Mesh
- **Istio Pilot** (`go/istio-pilot-unauthenticated.go`) - Istio service mesh
- **Envoy Proxy** (`go/envoy-proxy-unauthenticated.go`) - Envoy proxy

## Language Distribution

### C Templates (Low-level protocols)
- `redis-unauthenticated.c`
- `mysql-default-creds.c`
- `memcached-unauthenticated.c`
- `sql-injection-detection.c`
- `xss-detection.c`
- `directory-traversal.c`

### C++ Templates (System-level operations)
- `command-injection.cpp`
- `ldap-injection.cpp`
- `xxe-detection.cpp`
- `csrf-detection.cpp`

### Java Templates (Enterprise applications)
- `kafka-unauthenticated.java`
- `java-deserialization.java`
- `spring-boot-actuator.java`
- `struts2-rce.java`
- `log4j-rce.java`

### Go Templates (Cloud-native services)
- `mongodb-unauthenticated.go`
- `postgresql-unauthenticated.go`
- `prometheus-unauthenticated.go`
- `kubernetes-api-unauthenticated.go`
- `ssrf-detection.go`
- `path-traversal.go`
- `istio-pilot-unauthenticated.go`
- `envoy-proxy-unauthenticated.go`

### Python Templates (Web services & APIs)
- `elasticsearch-unauthenticated.py`
- `jenkins-unauthenticated.py`
- `kibana-unauthenticated.py`
- `grafana-unauthenticated.py`
- `docker-api-unauthenticated.py`
- `docker-registry-unauthenticated.py`
- `docker-swarm-unauthenticated.py`
- `aws-metadata-unauthenticated.py`
- `gcp-metadata-unauthenticated.py`
- `azure-metadata-unauthenticated.py`
- `rabbitmq-unauthenticated.py`
- `gitlab-unauthenticated.py`
- `sonarqube-unauthenticated.py`
- `nexus-unauthenticated.py`
- `zabbix-unauthenticated.py`
- `splunk-unauthenticated.py`
- `nagios-unauthenticated.py`
- `nosql-injection.py`

### Ruby Templates (Ruby applications)
- `rails-mass-assignment.rb`
- `rails-code-injection.rb`
- `ruby-unsafe-deserialization.rb`

### Perl Templates (Legacy systems)
- `perl-command-injection.pl`
- `perl-path-traversal.pl`
- `perl-sql-injection.pl`

### PHP Templates (Web applications)
- `file-inclusion.php`
- `php-unsafe-deserialization.php`
- `php-command-injection.php`
- `php-sql-injection.php`

## Template Execution

### Running All Templates
```bash
# Test all templates across all languages
./test-all-templates.sh

# Test with specific target
./test-all-templates.sh -t 192.168.1.100 -p 8080

# Verbose output
./test-all-templates.sh -v

# JSON output
./test-all-templates.sh -j
```

### Running Templates by Language
```bash
# C templates only
cert-x-gen scan --target example.com --template-language c

# Go templates only
cert-x-gen scan --target example.com --template-language go

# Python templates only
cert-x-gen scan --target example.com --template-language python

# Multiple languages
cert-x-gen scan --target example.com --template-language c,go,python
```

### Running Templates by Category
```bash
# Database services
cert-x-gen scan --target example.com --tags database

# Web vulnerabilities
cert-x-gen scan --target example.com --tags injection

# Cloud services
cert-x-gen scan --target example.com --tags cloud

# Container services
cert-x-gen scan --target example.com --tags container
```

## Template Development

### Skeleton Templates
Each language has a skeleton template in `templates/skeleton/`:
- `c-template-skeleton.c`
- `cpp-template-skeleton.cpp`
- `java-template-skeleton.java`
- `go-template-skeleton.go`
- `python-template-skeleton.py`
- `javascript-template-skeleton.js`
- `rust-template-skeleton.rs`
- `shell-template-skeleton.sh`
- `ruby-template-skeleton.rb`
- `perl-template-skeleton.pl`
- `php-template-skeleton.php`

### Template Structure
All templates follow the same structure:
1. **Metadata**: Template ID, name, author, severity, tags, CWE
2. **Environment Variables**: CERT_X_GEN_* variables for configuration
3. **Port Configuration**: Support for ADD_PORTS and OVERRIDE_PORTS
4. **HTTP Requests**: Service-specific testing logic
5. **JSON Output**: Standardized finding format
6. **Error Handling**: Graceful failure handling

### Adding New Templates
1. Choose appropriate language based on service type
2. Copy skeleton template
3. Implement service-specific logic
4. Add to appropriate category directory
5. Update this registry
6. Test with `test-all-templates.sh`

## Quality Assurance

### Testing
- All templates are tested with `test-all-templates.sh`
- Compilation testing for compiled languages
- Runtime testing for all languages
- JSON output validation
- Error handling verification

### Validation
- Template metadata validation
- Port configuration testing
- Environment variable handling
- Output format compliance
- Performance testing

### Maintenance
- Regular template updates
- Security patch testing
- Performance optimization
- Documentation updates
- Community contributions

## Statistics

- **Total Templates**: 42+
- **Languages Supported**: 12
- **Categories**: 4
- **Vulnerability Types**: 20+
- **Services Covered**: 30+

## Contributing

1. Fork the repository
2. Create feature branch
3. Add new templates following the structure
4. Test with `test-all-templates.sh`
5. Update documentation
6. Submit pull request

## Support

For questions or issues:
- Check existing templates for examples
- Review skeleton templates
- Test with `test-all-templates.sh`
- Submit issues on GitHub
- Join the community discussions
