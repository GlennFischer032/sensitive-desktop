# Flask App Testing Framework

This directory contains the tests for the Flask application.

## Structure

- `functional/`: Functional/integration tests that test entire views and endpoints
- `unit/`: Unit tests for individual components and functions
- `conftest.py`: Shared pytest fixtures
- `data/`: Test data files (if needed)

## Configuration

The pytest configuration is stored in the `pyproject.toml` file under the `[tool.pytest.ini_options]` section. Testing dependencies are also defined in the same file under `[project.optional-dependencies.test]`.

## Running Tests

### Using the Command Line

To run all tests:
```bash
python -m pytest app/tests/
```

To run unit tests only:
```bash
python -m pytest app/tests/unit/
```

To run functional tests only:
```bash
python -m pytest app/tests/functional/
```

To generate coverage report:
```bash
python -m pytest app/tests/ --cov=app --cov-report=term-missing:skip-covered
```

To generate HTML coverage report:
```bash
python -m pytest app/tests/ --cov=app --cov-report=html
```

### Using the Script

We also provide a convenient script to run tests:

```bash
python app/scripts/run_tests.py --type all --coverage
```

Options:
- `--type`: Test type to run (`unit`, `functional`, or `all`)
- `--verbose` or `-v`: Increase verbosity
- `--coverage` or `-c`: Generate coverage report
- `--html`: Generate HTML coverage report

### Pre-commit Hooks

Tests are automatically run as part of the pre-commit hooks. To manually run:

```bash
pre-commit run pytest-check
```

## Writing Tests

### Unit Tests

Unit tests should focus on testing individual functions and methods in isolation.
They should be fast, independent, and not require external services.

Follow this format:
```python
def test_something():
    """
    GIVEN a certain scenario
    WHEN a specific action is performed
    THEN a particular result is expected
    """
    # Arrange
    ...
    # Act
    ...
    # Assert
    ...
```

### Functional Tests

Functional tests should test entire views and endpoints, often using the Flask test client.
They may require mocking external dependencies like API calls.

## Mocking

For mocking external dependencies, use `pytest-mock` or `unittest.mock`. For example:

```python
@patch('app.services.auth.auth_bp.requests.post')
def test_login(mock_post, client):
    # Setup mock
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access_token": "test-token"}
    mock_post.return_value = mock_response

    # Test logic
    response = client.post('/auth/login', data={'username': 'test', 'password': 'test'})
    assert response.status_code == 302
```

## Redis Mocking

The Redis client is mocked using fakeredis. Use the `mock_redis_client` fixture in your tests.

## Fixtures

Common fixtures are defined in `conftest.py`. Use these fixtures in your tests to reduce duplication.
