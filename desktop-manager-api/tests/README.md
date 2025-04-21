# Testing Framework

This directory contains tests for the Desktop Manager API. The testing framework follows the guidelines from [TestDriven.io](https://testdriven.io/blog/flask-pytest/).

## Structure

```
tests/
├── conftest.py            # Shared pytest fixtures
├── functional/            # Functional/integration tests
│   ├── __init__.py
│   └── test_routes.py     # Tests for API routes/endpoints
└── unit/                  # Unit tests
    ├── __init__.py
    └── test_models.py     # Tests for data models
```

## Test Types

### Unit Tests

Unit tests focus on testing small components in isolation:
- Database models
- Utility functions
- Services

### Functional Tests

Functional tests focus on testing API endpoints:
- HTTP methods (GET, POST, etc.)
- Request validation
- Response status codes and content

## Running Tests

Run all tests with coverage:

```bash
python -m pytest --cov=desktop_manager --cov-report=term-missing
```

Run specific test types:

```bash
# Run only unit tests
python -m pytest tests/unit/

# Run only functional tests
python -m pytest tests/functional/

# Run a specific test file
python -m pytest tests/unit/test_models.py
```

## Pre-commit Integration

Tests can be run with pre-commit hooks using:

```bash
./run_tests.sh
```
