FROM python:3.14-slim

LABEL description="ZeroFlaw Web — Multi-language security scanner"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps + Python security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    gnupg \
    nodejs \
    npm \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir bandit ruff semgrep pip-audit

# Install Trivy and pre-download its vulnerability database
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy image --download-db-only --quiet || true

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py zeroflaw.py auto_fix.py mcp_server.py b2_store.py app.py pyproject.toml ./
COPY templates/ templates/

# Install zeroflaw CLI command (non-fatal, web app works without it) and create uploads dir
RUN pip install --no-cache-dir -e . || echo "Warning: CLI install failed, continuing..."
RUN mkdir -p uploads && chmod 777 uploads

# Expose port
EXPOSE 8555

# Health check — uses PORT so it stays in sync with the runtime port
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",8555)}/health')" || exit 1

# Run web app — use PORT env var (Render sets this) with fallback to 8555
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8555}"]
