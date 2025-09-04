# Use Python 3.11 slim base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -s /bin/false appuser

# Set working directory
WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create writable /tmp directory and set read-only filesystem
RUN mkdir -p /tmp && chmod 1777 /tmp

# Change ownership to non-root user
RUN chown -R appuser:appuser /app && \
    chown -R appuser:appuser /tmp

# Switch to non-root user
USER appuser

# Health check (updated for HTTP MCP server)
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port 8000 (HTTP MCP server)
EXPOSE 8000

# Run the HTTP MCP server
CMD ["python", "mcp_http_server.py"]