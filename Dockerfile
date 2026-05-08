FROM python:3.11-slim

LABEL description="ZeroFlaw Web — Multi-language security scanner"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system deps + security tools
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
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir bandit ruff semgrep pip-audit

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create app directory
WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY zeroflaw.py .
COPY auto_fix.py .
COPY mcp_server.py .
COPY app.py .
COPY templates/ templates/

# Create uploads directory
RUN mkdir -p uploads

# Install additional security tools
RUN echo "Installing additional security tools..." && \
    # This is a placeholder for additional tool installation
    echo "Additional tools installation would go here"

# Expose port
EXPOSE 8555

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8555/health')" || exit 1

# Run web app — use PORT env var (Render sets this) with fallback to 8555
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8555}"]
