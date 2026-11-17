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

# Every download is bounded: a stalled connection used to hang the installer for
# minutes after "Verifying checksum...". --max-time caps one attempt and --retry
# retries transient failures (timeouts, 5xx) a bounded number of times.
CURL_OPTS=(-fsSL --connect-timeout 15 --retry 2 --retry-delay 2)
SMALL_MAX_TIME=20    # release metadata and SHA256SUMS
# The binary is tens of MB, so a slow link gets a generous cap; a stalled one is
# cut off sooner by the speed floor (under 1 KB/s for 30 s aborts the attempt).
BINARY_MAX_TIME=900
BINARY_STALL_OPTS=(--speed-limit 1024 --speed-time 30)

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
    curl "${CURL_OPTS[@]}" --max-time "$SMALL_MAX_TIME" \
        "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and verify binary
download_binary() {
    local version="$1"
    local platform="$2"
    local binary_filename="${BINARY_NAME}-${platform}"
    local url="https://github.com/${REPO}/releases/download/${version}/${binary_filename}"
    local checksum_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS"
    
    if [[ "$platform" == *"windows"* ]]; then
        url="${url}.exe"
        binary_filename="${binary_filename}.exe"
    fi
    
    info "Downloading ${BINARY_NAME} ${version} for ${platform}..."
    
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" EXIT
    
    # Download binary (keep original filename for checksum verification)
    curl "${CURL_OPTS[@]}" --max-time "$BINARY_MAX_TIME" "${BINARY_STALL_OPTS[@]}" -o "${tmpdir}/${binary_filename}" "$url" \
        || error "Failed to download binary"
    
    # Download and verify checksum
    info "Verifying checksum..."
    if ! curl "${CURL_OPTS[@]}" --max-time "$SMALL_MAX_TIME" -o "${tmpdir}/SHA256SUMS" "$checksum_url"; then
        # A timed-out transfer can leave a partial file; never verify against it.
        rm -f "${tmpdir}/SHA256SUMS"
        warn "Could not download checksums"
    fi
    
    if [[ -f "${tmpdir}/SHA256SUMS" ]]; then
        cd "${tmpdir}"
        if command -v sha256sum &> /dev/null; then
            grep "${binary_filename}" SHA256SUMS | sha256sum -c - || error "Checksum verification failed"
        elif command -v shasum &> /dev/null; then
            grep "${binary_filename}" SHA256SUMS | shasum -a 256 -c - || error "Checksum verification failed"
        else
            warn "No checksum tool available, skipping verification"
        fi
        cd - > /dev/null
    fi
    
    # Install binary (rename to just 'cxg')
    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    
    if [[ -w "$INSTALL_DIR" ]]; then
        mv "${tmpdir}/${binary_filename}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${tmpdir}/${binary_filename}" "${INSTALL_DIR}/${BINARY_NAME}"
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
