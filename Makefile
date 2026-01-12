# CERT-X-GEN Multi-Language Template Engine Makefile
# This Makefile provides comprehensive testing, execution, and installation of templates

# Installation Configuration
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SHAREDIR = $(PREFIX)/share/cert-x-gen
TEMPLATEDIR = $(SHAREDIR)/templates

# Binary name
BINARY = cert-x-gen

# Detect OS
UNAME_S := $(shell uname -s)

# Testing Configuration
TARGET_HOST ?= 127.0.0.1
TARGET_PORT ?= 80
TEST_TIMEOUT ?= 30
VERBOSE ?= false
JSON_OUTPUT ?= false
DESTDIR ?=
PREFIX ?= /usr/local

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Directories
TEMPLATES_DIR := templates
SKELETON_DIR := $(TEMPLATES_DIR)/skeleton
TEST_DIR := tests
TARGET_DIR := target
RELEASE_DIR := $(TARGET_DIR)/release

# Binary paths
BINARY_NAME := cert-x-gen
CERT_X_GEN := $(RELEASE_DIR)/$(BINARY_NAME)
INSTALL_BIN_DIR := $(DESTDIR)$(PREFIX)/bin
TEST_SCRIPT := test-all-templates.sh

# Language directories
LANGUAGE_DIRS := c cpp java go python javascript rust shell ruby perl php yaml

# Template file patterns
C_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.c" -type f)
CPP_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" -type f)
JAVA_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.java" -type f)
GO_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.go" -type f)
PYTHON_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.py" -type f)
JAVASCRIPT_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.js" -type f)
RUST_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.rs" -type f)
SHELL_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.sh" -type f)
RUBY_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.rb" -type f)
PERL_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.pl" -type f)
PHP_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.php" -type f)
YAML_TEMPLATES := $(shell find $(TEMPLATES_DIR) -name "*.yaml" -o -name "*.yml" -type f)

# All templates
ALL_TEMPLATES := $(C_TEMPLATES) $(CPP_TEMPLATES) $(JAVA_TEMPLATES) $(GO_TEMPLATES) \
                 $(PYTHON_TEMPLATES) $(JAVASCRIPT_TEMPLATES) $(RUST_TEMPLATES) \
                 $(SHELL_TEMPLATES) $(RUBY_TEMPLATES) $(PERL_TEMPLATES) \
                 $(PHP_TEMPLATES) $(YAML_TEMPLATES)

# Count templates by language
C_COUNT := $(words $(C_TEMPLATES))
CPP_COUNT := $(words $(CPP_TEMPLATES))
JAVA_COUNT := $(words $(JAVA_TEMPLATES))
GO_COUNT := $(words $(GO_TEMPLATES))
PYTHON_COUNT := $(words $(PYTHON_TEMPLATES))
JAVASCRIPT_COUNT := $(words $(JAVASCRIPT_TEMPLATES))
RUST_COUNT := $(words $(RUST_TEMPLATES))
SHELL_COUNT := $(words $(SHELL_TEMPLATES))
RUBY_COUNT := $(words $(RUBY_TEMPLATES))
PERL_COUNT := $(words $(PERL_TEMPLATES))
PHP_COUNT := $(words $(PHP_TEMPLATES))
YAML_COUNT := $(words $(YAML_TEMPLATES))
TOTAL_COUNT := $(words $(ALL_TEMPLATES))

# Default target
.PHONY: all
all: build test-all

# Help target
.PHONY: help
help:
	@echo "CERT-X-GEN Multi-Language Template Engine"
	@echo "=========================================="
	@echo ""
	@echo "Installation targets:"
	@echo "  install        - Install cert-x-gen and templates to $(PREFIX)"
	@echo "  uninstall      - Remove cert-x-gen from system"
	@echo "  install-system - Install to /usr instead of /usr/local"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build the cert-x-gen binary"
	@echo "  install        - Install the cert-x-gen binary globally (requires permissions)"
	@echo "  test-all       - Test all templates across all languages"
	@echo "  test-c         - Test C templates only"
	@echo "  test-cpp       - Test C++ templates only"
	@echo "  test-java      - Test Java templates only"
	@echo "  test-go        - Test Go templates only"
	@echo "  test-python    - Test Python templates only"
	@echo "  test-javascript - Test JavaScript templates only"
	@echo "  test-rust      - Test Rust templates only"
	@echo "  test-shell     - Test Shell templates only"
	@echo "  test-ruby      - Test Ruby templates only"
	@echo "  test-perl      - Test Perl templates only"
	@echo "  test-php       - Test PHP templates only"
	@echo "  test-yaml      - Test YAML templates only"
	@echo "  test-integration - Run integration tests"
	@echo "  test-unit      - Run unit tests"
	@echo "  scan-all       - Run all templates against a target"
	@echo "  scan-c         - Run C templates against a target"
	@echo "  scan-go        - Run Go templates against a target"
	@echo "  scan-python    - Run Python templates against a target"
	@echo "  clean          - Clean build artifacts"
	@echo "  stats          - Show template statistics"
	@echo "  check-deps     - Check language runtime dependencies"
	@echo ""
	@echo "Configuration:"
	@echo "  TARGET_HOST    - Target host (default: 127.0.0.1)"
	@echo "  TARGET_PORT    - Target port (default: 80)"
	@echo "  TEST_TIMEOUT   - Test timeout in seconds (default: 30)"
	@echo "  VERBOSE        - Verbose output (default: false)"
	@echo "  JSON_OUTPUT    - JSON output format (default: false)"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test-all"
	@echo "  make scan-all TARGET_HOST=192.168.1.100"
	@echo "  make test-c VERBOSE=true"
	@echo "  make stats"

# Build the cert-x-gen binary
.PHONY: build
build:
	@echo "$(BLUE)[INFO]$(NC) Building cert-x-gen..."
	@cargo build --release
	@echo "$(GREEN)[SUCCESS]$(NC) Build completed"

# Install binary and templates
.PHONY: install
install: build
	@echo "$(BLUE)[INFO]$(NC) Installing CERT-X-GEN to $(PREFIX)..."
	@echo ""
	
	# Create directories
	@mkdir -p $(BINDIR)
	@mkdir -p $(TEMPLATEDIR)
	@mkdir -p $(SHAREDIR)
	
	# Install binary
	@echo "$(BLUE)[INFO]$(NC) Installing binary to $(BINDIR)..."
	@install -m 755 target/release/$(BINARY) $(BINDIR)/$(BINARY)
	
	# Install templates if they exist
	@if [ -d "templates" ] && [ -n "$$(ls -A templates 2>/dev/null)" ]; then \
		echo "$(BLUE)[INFO]$(NC) Installing templates to $(TEMPLATEDIR)..."; \
		cp -r templates/* $(TEMPLATEDIR)/; \
		chmod -R 755 $(TEMPLATEDIR); \
	else \
		echo "$(YELLOW)[WARN]$(NC) No templates directory found, skipping template installation"; \
	fi
	
	# Create default repository config
	@echo "$(BLUE)[INFO]$(NC) Creating default repository configuration..."
	@echo "version: \"1.0\"" > $(SHAREDIR)/repositories.yaml
	@echo "default_branch: main" >> $(SHAREDIR)/repositories.yaml
	@echo "repositories:" >> $(SHAREDIR)/repositories.yaml
	@echo "  - name: official" >> $(SHAREDIR)/repositories.yaml
	@echo "    url: https://github.com/BugB-Tech/cert-x-gen-templates.git" >> $(SHAREDIR)/repositories.yaml
	@echo "    branch: main" >> $(SHAREDIR)/repositories.yaml
	@echo "    local_path: ~/.cert-x-gen/templates/official" >> $(SHAREDIR)/repositories.yaml
	@echo "    enabled: true" >> $(SHAREDIR)/repositories.yaml
	@echo "    trusted: true" >> $(SHAREDIR)/repositories.yaml
	
	@echo ""
	@echo "$(GREEN)✓ CERT-X-GEN installed successfully!$(NC)"
	@echo ""
	@echo "Binary:    $(BINDIR)/$(BINARY)"
	@echo "Templates: $(TEMPLATEDIR)"
	@echo "Config:    $(SHAREDIR)/repositories.yaml"
	@echo ""
	@echo "$(BLUE)Next steps:$(NC)"
	@echo "  1. Run '$(BINARY) template update' to download templates from GitHub"
	@echo "  2. Run '$(BINARY) --help' to see available commands"
	@echo "  3. Run '$(BINARY) scan --target example.com' to start scanning"
	@echo ""

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "$(BLUE)[INFO]$(NC) Uninstalling CERT-X-GEN from $(PREFIX)..."
	@rm -f $(BINDIR)/$(BINARY)
	@rm -rf $(SHAREDIR)
	@echo "$(GREEN)✓ Uninstalled successfully$(NC)"
	@echo ""
	@echo "$(YELLOW)Note:$(NC) User templates in ~/.cert-x-gen were not removed"
	@echo "To remove them: rm -rf ~/.cert-x-gen"

# Install to /usr instead of /usr/local (requires sudo)
.PHONY: install-system
install-system:
	@echo "$(BLUE)[INFO]$(NC) Installing to /usr (system-wide)..."
	@$(MAKE) install PREFIX=/usr

# Test all templates across all languages
.PHONY: test-all
test-all: build
	@echo "$(BLUE)[INFO]$(NC) Testing all templates across all languages..."
	@./$(TEST_SCRIPT) -t $(TARGET_HOST) -p $(TARGET_PORT) -T $(TEST_TIMEOUT) $(if $(filter true,$(VERBOSE)),-v) $(if $(filter true,$(JSON_OUTPUT)),-j)

# Test templates by language
.PHONY: test-c
test-c: build
	@echo "$(BLUE)[INFO]$(NC) Testing C templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language c --json

.PHONY: test-cpp
test-cpp: build
	@echo "$(BLUE)[INFO]$(NC) Testing C++ templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language cpp --json

.PHONY: test-java
test-java: build
	@echo "$(BLUE)[INFO]$(NC) Testing Java templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language java --json

.PHONY: test-go
test-go: build
	@echo "$(BLUE)[INFO]$(NC) Testing Go templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language go --json

.PHONY: test-python
test-python: build
	@echo "$(BLUE)[INFO]$(NC) Testing Python templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language python --json

.PHONY: test-javascript
test-javascript: build
	@echo "$(BLUE)[INFO]$(NC) Testing JavaScript templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language javascript --json

.PHONY: test-rust
test-rust: build
	@echo "$(BLUE)[INFO]$(NC) Testing Rust templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language rust --json

.PHONY: test-shell
test-shell: build
	@echo "$(BLUE)[INFO]$(NC) Testing Shell templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language shell --json

.PHONY: test-ruby
test-ruby: build
	@echo "$(BLUE)[INFO]$(NC) Testing Ruby templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language ruby --json

.PHONY: test-perl
test-perl: build
	@echo "$(BLUE)[INFO]$(NC) Testing Perl templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language perl --json

.PHONY: test-php
test-php: build
	@echo "$(BLUE)[INFO]$(NC) Testing PHP templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language php --json

.PHONY: test-yaml
test-yaml: build
	@echo "$(BLUE)[INFO]$(NC) Testing YAML templates..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language yaml --json

# Integration tests
.PHONY: test-integration
test-integration: build
	@echo "$(BLUE)[INFO]$(NC) Running integration tests..."
	@cargo test --test multi_language_integration_test -- --nocapture

# Unit tests
.PHONY: test-unit
test-unit: build
	@echo "$(BLUE)[INFO]$(NC) Running unit tests..."
	@cargo test --lib -- --nocapture

# Scan targets (run templates against a target)
.PHONY: scan-all
scan-all: build
	@echo "$(BLUE)[INFO]$(NC) Running all templates against $(TARGET_HOST):$(TARGET_PORT)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --port $(TARGET_PORT) --json

.PHONY: scan-c
scan-c: build
	@echo "$(BLUE)[INFO]$(NC) Running C templates against $(TARGET_HOST):$(TARGET_PORT)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --port $(TARGET_PORT) --template-language c --json

.PHONY: scan-go
scan-go: build
	@echo "$(BLUE)[INFO]$(NC) Running Go templates against $(TARGET_HOST):$(TARGET_PORT)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --port $(TARGET_PORT) --template-language go --json

.PHONY: scan-python
scan-python: build
	@echo "$(BLUE)[INFO]$(NC) Running Python templates against $(TARGET_HOST):$(TARGET_PORT)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --port $(TARGET_PORT) --template-language python --json

.PHONY: scan-mixed
scan-mixed: build
	@echo "$(BLUE)[INFO]$(NC) Running mixed language templates against $(TARGET_HOST):$(TARGET_PORT)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --port $(TARGET_PORT) --template-language c,go,python,java --json

# Template statistics
.PHONY: stats
stats:
	@echo "$(BLUE)[INFO]$(NC) Template Statistics"
	@echo "=================================="
	@echo "C Templates:        $(C_COUNT)"
	@echo "C++ Templates:      $(CPP_COUNT)"
	@echo "Java Templates:     $(JAVA_COUNT)"
	@echo "Go Templates:       $(GO_COUNT)"
	@echo "Python Templates:   $(PYTHON_COUNT)"
	@echo "JavaScript Templates: $(JAVASCRIPT_COUNT)"
	@echo "Rust Templates:     $(RUST_COUNT)"
	@echo "Shell Templates:    $(SHELL_COUNT)"
	@echo "Ruby Templates:     $(RUBY_COUNT)"
	@echo "Perl Templates:     $(PERL_COUNT)"
	@echo "PHP Templates:      $(PHP_COUNT)"
	@echo "YAML Templates:     $(YAML_COUNT)"
	@echo "----------------------------------"
	@echo "Total Templates:    $(TOTAL_COUNT)"
	@echo ""

# Check language runtime dependencies
.PHONY: check-deps
check-deps:
	@echo "$(BLUE)[INFO]$(NC) Checking language runtime dependencies..."
	@echo ""
	@echo "C/C++ Compilers:"
	@command -v gcc >/dev/null 2>&1 && echo "  ✅ gcc: $(shell gcc --version | head -n1)" || echo "  ❌ gcc: not found"
	@command -v g++ >/dev/null 2>&1 && echo "  ✅ g++: $(shell g++ --version | head -n1)" || echo "  ❌ g++: not found"
	@command -v clang >/dev/null 2>&1 && echo "  ✅ clang: $(shell clang --version | head -n1)" || echo "  ❌ clang: not found"
	@command -v clang++ >/dev/null 2>&1 && echo "  ✅ clang++: $(shell clang++ --version | head -n1)" || echo "  ❌ clang++: not found"
	@echo ""
	@echo "Java:"
	@command -v javac >/dev/null 2>&1 && echo "  ✅ javac: $(shell javac -version 2>&1)" || echo "  ❌ javac: not found"
	@command -v java >/dev/null 2>&1 && echo "  ✅ java: $(shell java -version 2>&1 | head -n1)" || echo "  ❌ java: not found"
	@echo ""
	@echo "Go:"
	@command -v go >/dev/null 2>&1 && echo "  ✅ go: $(shell go version)" || echo "  ❌ go: not found"
	@echo ""
	@echo "Python:"
	@command -v python3 >/dev/null 2>&1 && echo "  ✅ python3: $(shell python3 --version)" || echo "  ❌ python3: not found"
	@command -v python >/dev/null 2>&1 && echo "  ✅ python: $(shell python --version)" || echo "  ❌ python: not found"
	@echo ""
	@echo "JavaScript:"
	@command -v node >/dev/null 2>&1 && echo "  ✅ node: $(shell node --version)" || echo "  ❌ node: not found"
	@echo ""
	@echo "Rust:"
	@command -v rustc >/dev/null 2>&1 && echo "  ✅ rustc: $(shell rustc --version)" || echo "  ❌ rustc: not found"
	@command -v cargo >/dev/null 2>&1 && echo "  ✅ cargo: $(shell cargo --version)" || echo "  ❌ cargo: not found"
	@echo ""
	@echo "Ruby:"
	@command -v ruby >/dev/null 2>&1 && echo "  ✅ ruby: $(shell ruby --version)" || echo "  ❌ ruby: not found"
	@echo ""
	@echo "Perl:"
	@command -v perl >/dev/null 2>&1 && echo "  ✅ perl: $(shell perl --version | head -n1)" || echo "  ❌ perl: not found"
	@echo ""
	@echo "PHP:"
	@command -v php >/dev/null 2>&1 && echo "  ✅ php: $(shell php --version | head -n1)" || echo "  ❌ php: not found"
	@echo ""

# Create language directories
.PHONY: create-dirs
create-dirs:
	@echo "$(BLUE)[INFO]$(NC) Creating language directories..."
	@for dir in $(LANGUAGE_DIRS); do \
		mkdir -p $(TEMPLATES_DIR)/$$dir; \
		echo "  ✅ Created $(TEMPLATES_DIR)/$$dir"; \
	done

# List all templates
.PHONY: list-templates
list-templates:
	@echo "$(BLUE)[INFO]$(NC) All Templates"
	@echo "=================="
	@echo ""
	@echo "C Templates ($(C_COUNT)):"
	@for template in $(C_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "C++ Templates ($(CPP_COUNT)):"
	@for template in $(CPP_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Java Templates ($(JAVA_COUNT)):"
	@for template in $(JAVA_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Go Templates ($(GO_COUNT)):"
	@for template in $(GO_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Python Templates ($(PYTHON_COUNT)):"
	@for template in $(PYTHON_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "JavaScript Templates ($(JAVASCRIPT_COUNT)):"
	@for template in $(JAVASCRIPT_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Rust Templates ($(RUST_COUNT)):"
	@for template in $(RUST_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Shell Templates ($(SHELL_COUNT)):"
	@for template in $(SHELL_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Ruby Templates ($(RUBY_COUNT)):"
	@for template in $(RUBY_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "Perl Templates ($(PERL_COUNT)):"
	@for template in $(PERL_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "PHP Templates ($(PHP_COUNT)):"
	@for template in $(PHP_TEMPLATES); do echo "  - $$template"; done
	@echo ""
	@echo "YAML Templates ($(YAML_COUNT)):"
	@for template in $(YAML_TEMPLATES); do echo "  - $$template"; done

# Clean build artifacts
.PHONY: clean
clean:
	@echo "$(BLUE)[INFO]$(NC) Cleaning build artifacts..."
	@cargo clean
	@rm -rf $(TARGET_DIR)
	@echo "$(GREEN)[SUCCESS]$(NC) Clean completed"

# Install dependencies (for development)
.PHONY: install-deps
install-deps:
	@echo "$(BLUE)[INFO]$(NC) Installing development dependencies..."
	@echo "This is a placeholder for dependency installation"
	@echo "Please install the required language runtimes manually:"
	@echo "  - gcc/g++ or clang/clang++ for C/C++"
	@echo "  - openjdk for Java"
	@echo "  - go for Go"
	@echo "  - python3 for Python"
	@echo "  - node for JavaScript"
	@echo "  - rust for Rust"
	@echo "  - ruby for Ruby"
	@echo "  - perl for Perl"
	@echo "  - php for PHP"

# Continuous integration target
.PHONY: ci
ci: check-deps build test-unit test-integration
	@echo "$(GREEN)[SUCCESS]$(NC) CI pipeline completed successfully"

# Development target
.PHONY: dev
dev: build test-all
	@echo "$(GREEN)[SUCCESS]$(NC) Development testing completed"

# Production target
.PHONY: prod
prod: build test-integration
	@echo "$(GREEN)[SUCCESS]$(NC) Production build completed"

# Show current configuration
.PHONY: config
config:
	@echo "$(BLUE)[INFO]$(NC) Current Configuration"
	@echo "=========================="
	@echo "TARGET_HOST:    $(TARGET_HOST)"
	@echo "TARGET_PORT:    $(TARGET_PORT)"
	@echo "TEST_TIMEOUT:   $(TEST_TIMEOUT)"
	@echo "VERBOSE:        $(VERBOSE)"
	@echo "JSON_OUTPUT:    $(JSON_OUTPUT)"
	@echo ""

# Quick test (subset of templates)
.PHONY: quick-test
quick-test: build
	@echo "$(BLUE)[INFO]$(NC) Running quick test (subset of templates)..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language c,go,python --json

# Performance test
.PHONY: perf-test
perf-test: build
	@echo "$(BLUE)[INFO]$(NC) Running performance test..."
	@time $(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language c,go,python --json

# Memory test
.PHONY: mem-test
mem-test: build
	@echo "$(BLUE)[INFO]$(NC) Running memory test..."
	@valgrind --tool=memcheck --leak-check=full $(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language c --json

# Security test
.PHONY: security-test
security-test: build
	@echo "$(BLUE)[INFO]$(NC) Running security test..."
	@$(CERT_X_GEN) scan --target $(TARGET_HOST) --template-language c,go,python --json --output-format json

# Documentation
.PHONY: docs
docs:
	@echo "$(BLUE)[INFO]$(NC) Generating documentation..."
	@cargo doc --no-deps
	@echo "$(GREEN)[SUCCESS]$(NC) Documentation generated in target/doc/"

# Format code
.PHONY: fmt
fmt:
	@echo "$(BLUE)[INFO]$(NC) Formatting code..."
	@cargo fmt
	@echo "$(GREEN)[SUCCESS]$(NC) Code formatted"

# Lint code
.PHONY: lint
lint:
	@echo "$(BLUE)[INFO]$(NC) Linting code..."
	@cargo clippy -- -D warnings
	@echo "$(GREEN)[SUCCESS]$(NC) Linting completed"

# Check code
.PHONY: check
check: fmt lint
	@echo "$(GREEN)[SUCCESS]$(NC) Code check completed"

# Full test suite
.PHONY: test-full
test-full: check test-unit test-integration test-all
	@echo "$(GREEN)[SUCCESS]$(NC) Full test suite completed"

# Release preparation
.PHONY: release
release: check test-full
	@echo "$(BLUE)[INFO]$(NC) Preparing release..."
	@cargo build --release
	@echo "$(GREEN)[SUCCESS]$(NC) Release build completed"

# Show help by default
.DEFAULT_GOAL := help