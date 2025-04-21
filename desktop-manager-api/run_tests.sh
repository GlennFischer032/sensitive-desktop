#!/bin/bash
set -e

# Run pre-commit hooks
echo "Running pre-commit hooks..."
pre-commit run --all-files

# Run tests with coverage
echo "Running tests with coverage..."
python -m pytest --cov=desktop_manager --cov-report=term-missing

echo "Tests completed successfully!"
