#!/bin/bash
# CXG CLI Test Suite
# Run: ./tests/run_cli_tests.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Test binary
CXG="./target/release/cxg"

# Test target (safe public test server)
TEST_TARGET="scanme.nmap.org"
TEST_TARGET_HTTP="httpbin.org"

# Log file
LOG_FILE="tests/test_results_$(date +%Y%m%d_%H%M%S).log"

# Functions
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

test_pass() {
    log "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

test_fail() {
    log "${RED}✗ FAIL${NC}: $1"
    log "  Error: $2"
    ((FAILED++))
}

test_skip() {
    log "${YELLOW}○ SKIP${NC}: $1 - $2"
    ((SKIPPED++))
}

run_test() {
    local name="$1"
    local cmd="$2"
    local expected_exit="${3:-0}"
    
    log "\n${BLUE}Testing:${NC} $name"
    log "Command: $cmd"
    
    set +e
    output=$($cmd 2>&1)
    exit_code=$?
    set -e
    
    if [ "$exit_code" -eq "$expected_exit" ]; then
        test_pass "$name"
        return 0
    else
        test_fail "$name" "Exit code $exit_code (expected $expected_exit)"
        echo "$output" >> "$LOG_FILE"
        return 1
    fi
}

run_test_contains() {
    local name="$1"
    local cmd="$2"
    local expected_text="$3"
    
    log "\n${BLUE}Testing:${NC} $name"
    log "Command: $cmd"
    
    set +e
    output=$($cmd 2>&1)
    exit_code=$?
    set -e
    
    if echo "$output" | grep -q "$expected_text"; then
        test_pass "$name"
        return 0
    else
        test_fail "$name" "Output doesn't contain '$expected_text'"
        echo "$output" >> "$LOG_FILE"
        return 1
    fi
}

# Header
log "╔════════════════════════════════════════════════════════════════╗"
log "║               CXG CLI Test Suite                               ║"
log "║               $(date)                          ║"
log "╚════════════════════════════════════════════════════════════════╝"

# Check binary exists
if [ ! -f "$CXG" ]; then
    log "${RED}Error: Binary not found at $CXG${NC}"
    log "Run: cargo build --release"
    exit 1
fi

log "\nBinary: $CXG"
log "Test target: $TEST_TARGET"
log "Log file: $LOG_FILE"

# ============================================================================
# SECTION 1: Global Options
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 1: Global Options${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg --help" "$CXG --help"
run_test "cxg -h" "$CXG -h"
run_test "cxg --version" "$CXG --version"
run_test "cxg -V" "$CXG -V"
run_test "cxg version" "$CXG version"
run_test_contains "cxg --no-color" "$CXG --no-color --help" "Usage:"

# ============================================================================
# SECTION 2: Template Management
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 2: Template Management${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg template --help" "$CXG template --help"
run_test "cxg template list" "$CXG template list"
run_test "cxg template list --language python" "$CXG template list --language python"
run_test "cxg template list --language rust" "$CXG template list --language rust"
run_test "cxg template list --language yaml" "$CXG template list --language yaml"
run_test "cxg template list --language c" "$CXG template list --language c"
run_test "cxg template list --language shell" "$CXG template list --language shell"

# Template validation
TEMPLATE_DIR="$HOME/.cert-x-gen/templates/official/templates"
if [ -d "$TEMPLATE_DIR" ]; then
    run_test "cxg template validate (python)" "$CXG template validate $TEMPLATE_DIR/python/"
    run_test "cxg template validate (yaml)" "$CXG template validate $TEMPLATE_DIR/yaml/"
    run_test "cxg template validate (shell)" "$CXG template validate $TEMPLATE_DIR/shell/"
    run_test "cxg template validate (c)" "$CXG template validate $TEMPLATE_DIR/c/"
else
    test_skip "Template validation" "Template directory not found"
fi

# ============================================================================
# SECTION 3: Search
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 3: Search${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg search --help" "$CXG search --help"
run_test "cxg search --query redis" "$CXG search --query redis"
run_test "cxg search --language python" "$CXG search --language python"
run_test "cxg search --severity high" "$CXG search --severity high"
run_test "cxg search --tags database" "$CXG search --tags database"
run_test "cxg search --format json" "$CXG search --query redis --format json"
run_test "cxg search --ids-only" "$CXG search --query redis --ids-only"
run_test "cxg search --stats" "$CXG search --stats"

# ============================================================================
# SECTION 4: Scan (Basic - No Target)
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 4: Scan Help${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg scan --help" "$CXG scan --help"

# ============================================================================
# SECTION 5: AI Commands
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 5: AI Commands${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg ai --help" "$CXG ai --help"
run_test "cxg ai generate --help" "$CXG ai generate --help"

# ============================================================================
# SECTION 6: Config
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}SECTION 6: Config${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

run_test "cxg config --help" "$CXG config --help"
run_test "cxg config generate --help" "$CXG config generate --help"

# ============================================================================
# SUMMARY
# ============================================================================
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}TEST SUMMARY${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"

TOTAL=$((PASSED + FAILED + SKIPPED))
log "\n${GREEN}Passed:${NC}  $PASSED"
log "${RED}Failed:${NC}  $FAILED"
log "${YELLOW}Skipped:${NC} $SKIPPED"
log "─────────────────"
log "Total:   $TOTAL"

if [ "$FAILED" -eq 0 ]; then
    log "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    log "\n${RED}✗ Some tests failed. Check $LOG_FILE for details.${NC}"
    exit 1
fi
