# Code Formatting and Pre-commit Hooks

This project uses a variety of tools to maintain code quality and consistent formatting. The setup includes:

- **Ruff**: For linting and quick auto-fixes
- **Black**: For code formatting
- **isort**: For import sorting
- **pre-commit**: For automatic checks before committing

## Setup

### Installing Pre-commit Hooks

To install pre-commit hooks for the entire project, run:

```bash
./install_pre_commit.sh
```

This script will install pre-commit if it's not already installed and set up hooks for:
- The root level (run_tests.py)
- The desktop-manager-api component
- The app component

### Manual Formatting

If you want to manually format all code in the project, you can use:

```bash
./format_all.sh
```

This script will format:
- run_tests.py script
- All code in the app directory
- All code in the desktop-manager-api directory

## Component-Specific Formatting

### Desktop Manager API

To format only the desktop-manager-api code:

```bash
cd desktop-manager-api
./format_code.sh
```

### Frontend App

To format only the app code:

```bash
cd app
./format_code.sh
```

## Pre-commit Hooks

The pre-commit hooks run automatically when you commit changes. They include:

1. **Code Formatting**
   - Formats code using Black and Ruff formatter
   - Sorts imports using isort

2. **Linting**
   - Checks for common errors and style issues using Ruff
   - Ensures code follows PEP standards

3. **File Checks**
   - Checks for trailing whitespace
   - Ensures files end with a newline
   - Validates YAML and TOML files
   - Checks for merge conflicts

## Configuration Files

Each component has its own configuration files:

1. **Root Level**
   - `.pre-commit-config.yaml`: Configuration for root-level hooks
   - `pyproject.toml`: Configuration files for tools when running at root level

2. **Desktop Manager API**
   - `desktop-manager-api/.pre-commit-config.yaml`: API-specific hooks
   - `desktop-manager-api/pyproject.toml`: API-specific tool configuration

3. **Frontend App**
   - `app/.pre-commit-config.yaml`: App-specific hooks
   - `app/pyproject.toml`: App-specific tool configuration

## Test Files

Test files are excluded from linting and formatting to avoid excessive warnings for test-specific patterns:

- Test files can use hardcoded test data (`S105`, `S106`)
- Test files can use mock function arguments that aren't all used (`ARG001`)
- Test files can use more complex assertions and have longer functions (`PLR0911`, `PLR0915`)
- Test files don't need to follow the same docstring conventions (`D`)

This exclusion is configured in each component's `pyproject.toml` file and in the formatting scripts.

## Bypassing Pre-commit Hooks

If you need to bypass pre-commit hooks for a specific commit (not recommended for regular use):

```bash
git commit -m "Your message" --no-verify
```

## Troubleshooting

If you encounter issues with pre-commit hooks:

1. **Hook Installation Issues**
   - Run `pre-commit clean` to clean the cache
   - Run `./install_pre_commit.sh` to reinstall hooks

2. **Formatting Errors**
   - Run `./format_all.sh` to format all code manually
   - Check error messages for specific formatting issues

3. **Dependency Issues**
   - Ensure all dev dependencies are installed:
     ```bash
     pip install -e ".[test]"
     ```
     (Run this in both app and desktop-manager-api directories)
