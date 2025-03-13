#!/bin/bash

# Setup colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Installing pre-commit hooks for the entire project ===${NC}"

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo -e "${YELLOW}pre-commit not found. Installing...${NC}"
    pip install pre-commit
else
    echo -e "${GREEN}pre-commit is already installed${NC}"
fi

# Install root-level pre-commit hooks
echo -e "${YELLOW}Installing root-level pre-commit hooks...${NC}"
pre-commit install

# Install desktop-manager-api pre-commit hooks
echo -e "${YELLOW}Installing desktop-manager-api pre-commit hooks...${NC}"
cd desktop-manager-api
pre-commit install
cd ..

# Install app pre-commit hooks
echo -e "${YELLOW}Installing app pre-commit hooks...${NC}"
cd app
pre-commit install
cd ..

echo -e "${GREEN}=== All pre-commit hooks installed successfully ===${NC}"
