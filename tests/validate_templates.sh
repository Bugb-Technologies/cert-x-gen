#!/bin/bash
# Template Validation Test Suite
# Tests that all templates can be validated and (optionally) executed

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CXG="./target/release/cxg"
TEMPLATE_DIR="$HOME/.cert-x-gen/templates/official/templates"

# Counters
VALID=0
INVALID=0
TOTAL=0

log() {
    echo -e "$1"
}

validate_template() {
    local file="$1"
    local lang="$2"
    
    ((TOTAL++))
    
    # Get relative path for display
    rel_path="${file#$TEMPLATE_DIR/}"
    
    # Validate using cxg
    if $CXG template validate "$file" > /dev/null 2>&1; then
        log "${GREEN}✓${NC} $rel_path"
        ((VALID++))
        return 0
    else
        log "${RED}✗${NC} $rel_path"
        ((INVALID++))
        return 1
    fi
}

# Header
log "╔════════════════════════════════════════════════════════════════╗"
log "║           Template Validation Suite                            ║"
log "╚════════════════════════════════════════════════════════════════╝"
log ""

if [ ! -d "$TEMPLATE_DIR" ]; then
    log "${RED}Error: Template directory not found: $TEMPLATE_DIR${NC}"
    log "Run: cxg --ut"
    exit 1
fi

# Validate by language
log "${YELLOW}═══ Python Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/python/*.py 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "python"
done

log "\n${YELLOW}═══ JavaScript Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/javascript/*.js 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "javascript"
done

log "\n${YELLOW}═══ Rust Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/rust/*.rs 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "rust"
done

log "\n${YELLOW}═══ C Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/c/*.c 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "c"
done

log "\n${YELLOW}═══ C++ Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/cpp/*.cpp 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "cpp"
done

log "\n${YELLOW}═══ Go Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/go/*.go 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "go"
done

log "\n${YELLOW}═══ Java Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/java/*.java 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "java"
done

log "\n${YELLOW}═══ Ruby Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/ruby/*.rb 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "ruby"
done

log "\n${YELLOW}═══ Perl Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/perl/*.pl 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "perl"
done

log "\n${YELLOW}═══ PHP Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/php/*.php 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "php"
done

log "\n${YELLOW}═══ Shell Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/shell/*.sh 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "shell"
done

log "\n${YELLOW}═══ YAML HTTP Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/yaml/http/*.yaml 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "yaml"
done

log "\n${YELLOW}═══ YAML Network Templates ═══${NC}"
for f in "$TEMPLATE_DIR"/yaml/network/*.yaml 2>/dev/null; do
    [ -f "$f" ] && validate_template "$f" "yaml"
done

# Summary
log "\n${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log "${YELLOW}VALIDATION SUMMARY${NC}"
log "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
log ""
log "${GREEN}Valid:${NC}   $VALID"
log "${RED}Invalid:${NC} $INVALID"
log "─────────────────"
log "Total:   $TOTAL"

if [ "$INVALID" -eq 0 ]; then
    log "\n${GREEN}✓ All templates validated successfully!${NC}"
    exit 0
else
    log "\n${RED}✗ Some templates failed validation${NC}"
    exit 1
fi
