#!/bin/bash
cd "$(dirname "$0")/.."
echo "=== CHECKING FOR UNUSED DEPENDENCIES ==="
echo "This check will always pass even with issues. Showing both unused dependencies and imports."
echo ""
deptry . -i DEP001,DEP004 -ddg dev,test
exit_code=$?
echo ""
echo "=== END OF DEPENDENCY CHECK (Exit code: ${exit_code}) ==="
echo "This hook always passes, even with dependency issues"
exit 0
