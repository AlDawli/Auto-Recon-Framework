# ─────────────────────────────────────────────────────────────────────────────
# Auto Recon Framework - Dockerfile
# Multi-stage build: tool installer + slim runtime
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Tool Installer ──────────────────────────────────────────────────
FROM golang:1.22-bookworm AS tools

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       && \
    go install -v github.com/sensepost/gowitness@latest

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL maintainer="Auto Recon Framework"
LABEL description="Automated reconnaissance: nmap · subfinder · httpx · nuclei"
LABEL version="1.0.0"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap               \
    chromium           \
    chromium-driver    \
    ca-certificates    \
    curl               \
    wget               \
    git                \
    dnsutils           \
    iputils-ping       \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from builder stage
COPY --from=tools /go/bin/subfinder  /usr/local/bin/
COPY --from=tools /go/bin/httpx      /usr/local/bin/
COPY --from=tools /go/bin/nuclei     /usr/local/bin/
COPY --from=tools /go/bin/gowitness  /usr/local/bin/

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy framework source
COPY . .

# Create output directories
RUN mkdir -p output/reports output/screenshots output/json

# Update nuclei templates at build time
RUN nuclei -update-templates -silent || true

# Non-root user for security
RUN useradd -m -s /bin/bash recon && \
    chown -R recon:recon /app
USER recon

# Default output volume
VOLUME ["/app/output"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
