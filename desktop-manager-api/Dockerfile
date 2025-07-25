FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    pkg-config \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Helm
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && \
    rm kubectl

# Create non-root user
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser

# Copy project files
COPY pyproject.toml ./
COPY src ./src

# Install uv
RUN pip install --no-cache-dir uv

# Build argument to determine the environment
ARG FLASK_DEBUG=0
ENV FLASK_DEBUG=${FLASK_DEBUG}

# Install Python dependencies using uv and pyproject.toml
RUN uv pip install --system .
RUN uv pip install --system flask[async] gunicorn

# Install development dependencies if in dev mode
RUN if [ "$FLASK_DEBUG" = "1" ]; then \
        uv pip install --system ".[dev]"; \
    fi

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
ENV FLASK_APP=main:app

EXPOSE 5000

# Use shell form to allow environment variable substitution
CMD if [ "$FLASK_DEBUG" = "1" ]; then \
        python -m debugpy --listen 0.0.0.0:5679 -m flask run --host=0.0.0.0 --port=5000; \
    else \
        gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 180 "main:app"; \
    fi
