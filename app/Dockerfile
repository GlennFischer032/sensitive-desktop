FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml to leverage Docker cache
COPY pyproject.toml ./

# Install uv
RUN pip install --no-cache-dir uv

# Install Python dependencies using uv and pyproject.toml
RUN uv pip install --system .
RUN uv pip install --system gunicorn

# Copy application code
COPY . .

# Set ownership to non-root user
RUN chown -R 1000:1000 /app

# Switch to non-root user
USER 1000

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Build argument to determine the environment
ARG FLASK_DEBUG=0
ENV FLASK_DEBUG=${FLASK_DEBUG}

# Expose port
EXPOSE 5000

# Use shell form to allow environment variable substitution
CMD if [ "$FLASK_DEBUG" = "1" ]; then \
        flask run --host=0.0.0.0 --port=5000; \
    else \
        gunicorn --bind 0.0.0.0:5000 --workers 4 app:app; \
    fi
