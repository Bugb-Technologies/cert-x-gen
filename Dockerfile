# CERT-X-GEN Docker Image
# Multi-architecture runtime image using pre-built binaries
# Supports: linux/amd64, linux/arm64

FROM debian:bookworm-slim

# These are automatically set by Docker buildx
ARG TARGETARCH

LABEL org.opencontainers.image.title="CERT-X-GEN"
LABEL org.opencontainers.image.description="Polyglot Execution Engine for Vulnerability Detection"
LABEL org.opencontainers.image.source="https://github.com/Bugb-Technologies/cert-x-gen"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash cxg

# Copy architecture-specific binary
# Files are named: cxg-linux-amd64, cxg-linux-arm64
COPY cxg-linux-${TARGETARCH} /usr/local/bin/cxg
RUN chmod +x /usr/local/bin/cxg

# Set up directories
RUN mkdir -p /home/cxg/.cert-x-gen/templates && \
    chown -R cxg:cxg /home/cxg

USER cxg
WORKDIR /home/cxg

# Download templates on first run
RUN cxg template update || true

ENTRYPOINT ["cxg"]
CMD ["--help"]
