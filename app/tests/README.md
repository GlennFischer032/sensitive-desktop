# Testing Framework for Desktop Frontend

This directory contains tests for the Desktop Frontend application using pytest.

## Test Structure

The tests are organized as follows:

- **unit/**: Unit tests for individual components
- **functional/**: Functional tests for application routes and features
- **conftest.py**: Shared fixtures and test configuration
- **data/**: Test data files

## Running Tests

### Run all tests

```bash
python -m pytest
```

### Run with coverage report

```bash
python -m pytest --cov=app --cov-report=term-missing
```

### Run specific test types

```bash
# Run only unit tests
python -m pytest tests/unit/

# Run only functional tests
python -m pytest tests/functional/

# Run a specific test file
python -m pytest tests/unit/test_config.py
```

## Fixtures

The testing framework provides several fixtures in `conftest.py`:

- `app`: A Flask application instance configured for testing
- `client`: A test client for the app
- `runner`: A test CLI runner for the app
- `auth_token`: A valid JWT token for a regular user
- `admin_token`: A valid JWT token for an admin user
- `logged_in_client`: A test client with an active user session
- `admin_client`: A test client with an active admin session

## Test Categories

Tests are categorized by markers:

- `@pytest.mark.unit`: Unit tests
- `@pytest.mark.functional`: Functional tests
- `@pytest.mark.slow`: Slow tests
- `@pytest.mark.integration`: Tests requiring integration with backend services

You can run tests with a specific marker:

```bash
python -m pytest -m unit
```

## Pre-commit Integration

Tests are automatically run as part of the pre-commit hooks. To skip tests during development, you can use:

```bash
pre-commit run --hook-stage manual pytest-check
```
