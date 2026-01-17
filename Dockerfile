# ACIA - Autonomous Code Improvement Agent
# Production Docker Image

FROM python:3.11-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash acia

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional analyzers
RUN pip install --no-cache-dir \
    pylint \
    flake8 \
    bandit \
    radon \
    semgrep

# Copy application code
COPY --chown=acia:acia . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create directories for data
RUN mkdir -p /var/acia/repos /var/acia/logs \
    && chown -R acia:acia /var/acia

# Switch to non-root user
USER acia

# Health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 \
    CMD python -c "from acia import Orchestrator; print('healthy')"

# Default command - runs the infinite loop
CMD ["python", "-m", "acia.main", "run", "--config", "/app/config.yaml"]
