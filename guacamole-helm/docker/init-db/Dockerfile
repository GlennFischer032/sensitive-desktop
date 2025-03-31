FROM postgres:16-alpine

# Install necessary tools
USER root
RUN apk add --no-cache bash

# Copy initialization scripts
COPY sql/*.sql /docker-entrypoint-initdb.d/

# Switch to non-root user
USER 999
