# CERT-X-GEN Docker Image
# Multi-stage build for minimal image size

# Build stage (when building from source)
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /build
COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="CERT-X-GEN"
LABEL org.opencontainers.image.description="Polyglot Execution Engine"
LABEL org.opencontainers.image.source="https://github.com/Bugb-Technologies/cert-x-gen"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install runtime dependencies for template execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    nodejs \
    npm \
    gcc \
    golang-go \
    curl \
    bash \
    snmp \
    snmp-mibs-downloader \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages requests

# Create non-root user
RUN useradd -m -s /bin/bash cxg

# Copy binary from builder or use pre-built
COPY --from=builder /build/target/release/cxg /usr/local/bin/cxg
# Alternative: Copy pre-built binary for CI
# COPY cxg-linux-amd64 /usr/local/bin/cxg

RUN chmod +x /usr/local/bin/cxg

# Set up template directory
RUN mkdir -p /home/cxg/.cert-x-gen/templates && \
    chown -R cxg:cxg /home/cxg

USER cxg
WORKDIR /home/cxg

# Download templates on first run
RUN cxg template update || true

ENTRYPOINT ["cxg"]
CMD ["--help"]
