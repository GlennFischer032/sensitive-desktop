#!/bin/bash

# Setup colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Running code formatting and linting tools ===${NC}"

# Run ruff to fix auto-fixable issues (excluding tests)
echo -e "${YELLOW}Running ruff fix (with unsafe fixes)...${NC}"
python -m ruff check --fix --unsafe-fixes --exclude "tests/" --exclude "**/test_*.py" src/

# Run ruff format (excluding tests)
echo -e "${YELLOW}Running ruff format...${NC}"
python -m ruff format --exclude "tests/" --exclude "**/test_*.py" src/

# Run black for code formatting (excluding tests)
echo -e "${YELLOW}Running black...${NC}"
python -m black --exclude "tests/|test_" src/

# Run isort to sort imports (excluding tests)
echo -e "${YELLOW}Running isort...${NC}"
python -m isort --skip "tests/" src/

# Check for remaining issues (excluding tests)
echo -e "${YELLOW}Checking for remaining issues...${NC}"
python -m ruff check --exclude "tests/" --exclude "**/test_*.py" src/

echo -e "${GREEN}=== Code formatting complete ===${NC}"
