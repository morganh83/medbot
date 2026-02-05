# Multi-stage build for smaller final image
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

# Create non-root user for security
RUN useradd -m -u 1000 medbot && \
    mkdir -p /app/data && \
    chown -R medbot:medbot /app

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder --chown=medbot:medbot /root/.local /home/medbot/.local

# Copy application code
COPY --chown=medbot:medbot medbot.py .

# Set PATH to include user-installed packages
ENV PATH=/home/medbot/.local/bin:$PATH

# Switch to non-root user
USER medbot

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

# Expose port
EXPOSE 8080

# Run the bot (unbuffered output for better logging)
CMD ["python", "-u", "medbot.py"]
