# Use Python 3.12 slim as base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Update certificate store
RUN update-ca-certificates

# Create non-root user for security
RUN groupadd -r npmscanner && useradd -r -g npmscanner npmscanner

# Set working directory
WORKDIR /app

# Copy requirements file first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies (with trusted hosts for corporate networks)
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt

# Copy application files
COPY multi_ecosystem_scanner.py .
COPY orchestrator.py .
COPY requirements.txt .

# Copy module directories
COPY core/ ./core/
COPY ecosystems/ ./ecosystems/
COPY notifications/ ./notifications/

# Copy utility scripts
COPY scripts/ ./scripts/

# Copy entrypoint script
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory for SQLite database - ensure correct ownership
RUN mkdir -p /data /app/data && chown npmscanner:npmscanner /data /app/data

# Create log directory  
RUN mkdir -p /logs /app/logs && chown npmscanner:npmscanner /logs /app/logs

# Create temp directory for processing
RUN mkdir -p /app/temp && chown npmscanner:npmscanner /app/temp

# Create diffs directory for analysis outputs
RUN mkdir -p /app/diffs && chown npmscanner:npmscanner /app/diffs

# Switch to non-root user
USER npmscanner

# Set volume for persistent database storage
VOLUME ["/data", "/logs"]

# Expose health check port
EXPOSE 8080

# Health check to ensure the container is working
HEALTHCHECK --interval=5m --timeout=30s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Use entrypoint script
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "/app/multi_ecosystem_scanner.py"]
