#!/bin/bash

# Setup colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Running code formatting for entire project ===${NC}"

# Format run_tests.py (exclude test files)
echo -e "${YELLOW}Formatting run_tests.py...${NC}"
python -m ruff check --fix --unsafe-fixes run_tests.py
python -m ruff format run_tests.py
python -m black run_tests.py

# Format app code (exclude test files)
echo -e "${YELLOW}Formatting app code (excluding tests)...${NC}"
cd app
python -m ruff check --fix --unsafe-fixes --exclude "tests/" --exclude "**/test_*.py" .
python -m ruff format --exclude "tests/" --exclude "**/test_*.py" .
python -m black --exclude "tests/|test_" .
python -m isort --skip "tests/" .
cd ..

# Format desktop-manager-api code (exclude test files)
echo -e "${YELLOW}Formatting desktop-manager-api code (excluding tests)...${NC}"
cd desktop-manager-api
python -m ruff check --fix --unsafe-fixes --exclude "tests/" --exclude "**/test_*.py" src/
python -m ruff format --exclude "tests/" --exclude "**/test_*.py" src/
python -m black --exclude "tests/|test_" src/
python -m isort --skip "tests/" src/
cd ..

echo -e "${GREEN}=== All code formatting complete ===${NC}"
