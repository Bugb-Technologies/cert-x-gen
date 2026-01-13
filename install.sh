#!/bin/bash
# CERT-X-GEN Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Bugb-Technologies/cert-x-gen/main/install.sh | bash

set -e

REPO="Bugb-Technologies/cert-x-gen"
BINARY_NAME="cxg"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS and architecture
detect_platform() {
    local os arch
    
    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *) error "Unsupported operating system: $(uname -s)" ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
    
    echo "${os}-${arch}"
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and verify binary
download_binary() {
    local version="$1"
    local platform="$2"
    local url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-${platform}"
    local checksum_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS"
    
    if [[ "$platform" == *"windows"* ]]; then
        url="${url}.exe"
    fi
    
    info "Downloading ${BINARY_NAME} ${version} for ${platform}..."
    
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" EXIT
    
    # Download binary
    curl -fsSL -o "${tmpdir}/${BINARY_NAME}" "$url" || error "Failed to download binary"
    
    # Download and verify checksum
    info "Verifying checksum..."
    curl -fsSL -o "${tmpdir}/SHA256SUMS" "$checksum_url" || warn "Could not download checksums"
    
    if [[ -f "${tmpdir}/SHA256SUMS" ]]; then
        cd "${tmpdir}"
        if command -v sha256sum &> /dev/null; then
            grep "${BINARY_NAME}-${platform}" SHA256SUMS | sha256sum -c - || error "Checksum verification failed"
        elif command -v shasum &> /dev/null; then
            grep "${BINARY_NAME}-${platform}" SHA256SUMS | shasum -a 256 -c - || error "Checksum verification failed"
        else
            warn "No checksum tool available, skipping verification"
        fi
        cd - > /dev/null
    fi
    
    # Install binary
    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    
    if [[ -w "$INSTALL_DIR" ]]; then
        mv "${tmpdir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${tmpdir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi
}

# Main installation
main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║        CERT-X-GEN Installer           ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
    fi
    
    local platform version
    platform=$(detect_platform)
    info "Detected platform: ${platform}"
    
    # Get version (from argument or latest)
    if [[ -n "$1" ]]; then
        version="$1"
    else
        version=$(get_latest_version)
    fi
    
    if [[ -z "$version" ]]; then
        error "Could not determine version to install"
    fi
    
    info "Installing version: ${version}"
    
    download_binary "$version" "$platform"
    
    echo ""
    info "Installation complete!"
    echo ""
    echo "  Run 'cxg --version' to verify installation"
    echo "  Run 'cxg template update' to download templates"
    echo ""
    echo "  Documentation: https://github.com/${REPO}"
    echo ""
}

main "$@"
