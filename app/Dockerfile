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

# Build argument to determine the environment
ARG FLASK_DEBUG=0
ENV FLASK_DEBUG=${FLASK_DEBUG}

# Install additional dev dependencies if in debug mode
RUN if [ "$FLASK_DEBUG" = "1" ]; then \
        apt-get update && apt-get install -y \
        g++ \
        make \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Copy all application code first
COPY . .

# Install uv
RUN pip install --no-cache-dir uv

# Install Python dependencies using uv and pyproject.toml
RUN uv pip install --system .
# Install dev dependencies if in debug mode
RUN if [ "$FLASK_DEBUG" = "1" ]; then \
        uv pip install --system ".[dev]"; \
    fi
RUN uv pip install --system gunicorn

# Set ownership to non-root user
RUN chown -R 1000:1000 /app

# Switch to non-root user
USER 1000

# Set environment variables
ENV FLASK_APP=app:app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

# Expose port
EXPOSE 5000

# Use shell form to allow environment variable substitution
CMD if [ "$FLASK_DEBUG" = "1" ]; then \
        python -m debugpy --listen 0.0.0.0:5678 -m flask run --host=0.0.0.0 --port=5000; \
    else \
        gunicorn --bind 0.0.0.0:5000 --workers 4 app:app; \
    fi
