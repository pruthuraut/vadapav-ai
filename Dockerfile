# ══════════════════════════════════════════════════════════════════════════════
# bb-harness Dockerfile
# Complete self-contained container packaging:
# 1) All Go recon tools (subfinder, httpx, nuclei, katana, naabu, amass, etc.)
# 2) All Linux network tools (nmap, masscan, massdns, etc.)
# 3) All wordlists (SecLists common & subdomains, massdns resolvers)
# 4) Complete bb-harness Python orchestrator, SQLite database, and REPL
# ══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build Go Tools ───────────────────────────────────────────────────
FROM golang:latest AS builder

ENV GO111MODULE=on \
    GOTOOLCHAIN=auto \
    CGO_ENABLED=0

# Install ProjectDiscovery & community Go recon tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/owasp-amass/amass/v4/...@master && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Build massdns from source
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && cp bin/massdns /go/bin/massdns && rm -rf /tmp/massdns

# ── Stage 2: Final Runtime Image ──────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL maintainer="bb-harness team" \
      description="The Bug Hunter's Methodology (TBHM v4.02) Recon Orchestrator"

# Install system dependencies, network scanners, and Python environment
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    dnsutils \
    nmap \
    masscan \
    whois \
    openssl \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled Go binaries
COPY --from=builder /go/bin/* /usr/local/bin/

# Set up application workspace
WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages \
        dnsrecon \
        sublist3r \
        dirsearch \
        wafw00f

# Download essential SecLists and MassDNS resolvers wordlists
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    mkdir -p /usr/share/seclists/Discovery/DNS && \
    mkdir -p /usr/share/massdns/lists && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -o /usr/share/seclists/Discovery/Web-Content/common.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
        -o /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt && \
    curl -sL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt \
        -o /usr/share/massdns/lists/resolvers.txt

# Pre-populate nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Copy bb-harness codebase into container
COPY bb_harness/ /app/bb_harness/
COPY tests/ /app/tests/
COPY .env.example /app/.env.example
COPY security-checklist.txt /app/security-checklist.txt
COPY run_attack_phase.py /app/run_attack_phase.py
COPY run_hunt.py /app/run_hunt.py
COPY run_triage.py /app/run_triage.py
COPY run_validation.py /app/run_validation.py
COPY tools/ /app/tools/
COPY skills/ /app/skills/

# Create persistent output and data directories
RUN mkdir -p /app/output /app/data && chmod -R 777 /app/output /app/data

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"

# Default entrypoint runs the interactive REPL or accepts CLI flags
ENTRYPOINT ["python3", "-m", "bb_harness"]
CMD []
