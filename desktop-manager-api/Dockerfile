FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser

# Copy project files
COPY pyproject.toml ./
COPY src ./src

# Install uv
RUN pip install --no-cache-dir uv

# Install Python dependencies using uv and pyproject.toml
RUN uv pip install --system .
RUN uv pip install --system flask[async] gunicorn

# Create a healthcheck script
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh && chown appuser:appuser /healthcheck.sh

# Set ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set environment variables
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=desktop_manager.main:app

# Build argument to determine the environment
ARG DEV_MODE=0
ENV DEV_MODE=${DEV_MODE}
ENV FLASK_DEBUG=${DEV_MODE}

# Expose port
EXPOSE 5000

# Use shell form to allow environment variable substitution
CMD if [ "$DEV_MODE" = "1" ]; then \
        flask run --host=0.0.0.0 --port=5000; \
    else \
        gunicorn --bind 0.0.0.0:5000 --workers 4 "desktop_manager.main:app"; \
    fi
