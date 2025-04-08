#!/usr/bin/env python
"""
Script to run tests and generate coverage reports.

Dependencies are defined in pyproject.toml under [project.optional-dependencies.test].
Configuration is defined in pyproject.toml under [tool.pytest.ini_options].
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path


def run_tests(test_type=None, verbose=False, coverage=False, html=False):
    """Run the tests and optionally generate coverage reports.

    Args:
        test_type: Type of tests to run (unit, functional, or None for all)
        verbose: Whether to run tests in verbose mode
        coverage: Whether to generate coverage reports
        html: Whether to generate HTML coverage reports
    """
    # Ensure we're in the app directory
    os.chdir(Path(__file__).parent.parent)

    # Build the pytest command
    cmd = ["python", "-m", "pytest"]

    # Add test path based on test type
    if test_type == "unit":
        cmd.append("tests/unit/")
    elif test_type == "functional":
        cmd.append("tests/functional/")
    else:
        cmd.append("tests/")

    # Add verbosity
    if verbose:
        cmd.append("-v")

    # Add coverage
    if coverage:
        cmd.append("--cov=app")

        # Add HTML coverage report
        if html:
            cmd.append("--cov-report=html")
        else:
            cmd.append("--cov-report=term-missing:skip-covered")

    # Run the command
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False)

    return result.returncode


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run tests and generate coverage reports")
    parser.add_argument("--type", choices=["unit", "functional", "all"], default="all", help="Type of tests to run")
    parser.add_argument("--verbose", "-v", action="store_true", help="Run tests in verbose mode")
    parser.add_argument("--coverage", "-c", action="store_true", help="Generate coverage reports")
    parser.add_argument("--html", action="store_true", help="Generate HTML coverage reports")

    args = parser.parse_args()

    # Map "all" to None for test_type
    test_type = args.type if args.type != "all" else None

    return run_tests(test_type, args.verbose, args.coverage, args.html)


if __name__ == "__main__":
    sys.exit(main())
