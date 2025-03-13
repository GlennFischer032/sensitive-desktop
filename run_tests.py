#!/usr/bin/env python3
"""
Test runner script for the Desktop Manager project.

This script provides functionality to run tests for both the desktop-manager-api
and app components, either individually or together.
"""

import argparse
import os
import subprocess
import sys
from typing import List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Run tests for Desktop Manager components"
    )
    parser.add_argument(
        "--component",
        choices=["api", "app", "all"],
        default="all",
        help="Component to test (api, app, or all)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--failfast", "-f", action="store_true", help="Stop on first failure"
    )
    parser.add_argument(
        "--junit-xml",
        help="Generate JUnit XML report with the specified filename",
    )
    parser.add_argument(
        "--test-path",
        help="Specific test path to run (e.g., tests/unit/test_users.py::test_dashboard_success)",
    )
    parser.add_argument(
        "--coverage",
        "-c",
        action="store_true",
        help="Run tests with coverage reporting",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Run tests with debug logging enabled",
    )

    return parser.parse_args()


def run_tests(
    component: str,
    verbose: bool = False,
    failfast: bool = False,
    junit_xml: Optional[str] = None,
    test_path: Optional[str] = None,
    coverage: bool = False,
    debug: bool = False,
) -> Tuple[int, List[str]]:
    """
    Run tests for the specified component.

    Args:
        component: The component to test ('api' or 'app')
        verbose: Enable verbose output
        failfast: Stop on first failure
        junit_xml: Generate JUnit XML report with the specified filename
        test_path: Specific test path to run
        coverage: Run tests with coverage reporting
        debug: Run tests with debug logging enabled

    Returns:
        Tuple containing exit code and output lines
    """
    current_dir = os.getcwd()
    component_dir = "desktop-manager-api" if component == "api" else "app"
    os.chdir(os.path.join(current_dir, component_dir))

    cmd = ["python", "-m", "pytest"]

    if verbose:
        cmd.append("-v")

    if failfast:
        cmd.append("-x")

    if coverage:
        cmd.append("--cov")

    if junit_xml:
        xml_path = (
            f"{junit_xml}_{component}.xml"
            if junit_xml
            else f"test_results_{component}.xml"
        )
        cmd.extend(["--junitxml", xml_path])

    if test_path:
        cmd.append(test_path)

    if debug:
        cmd.append("--log-cli-level=DEBUG")

    # Set special environment variables for testing
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd() + ":" + env.get("PYTHONPATH", "")

    # Add debugging info only for app component
    if component == "app":
        print(f"\n{'=' * 80}")
        print(f"Running tests for {component_dir} with authentication patching")
        print(f"{'=' * 80}\n")

        # Make sure the JWT validation in decorators.py works with our test tokens
        # This is already handled by the updated mock_jwt fixture in app/tests/conftest.py
    else:
        print(f"\n{'=' * 80}")
        print(f"Running tests for {component_dir}")
        print(f"{'=' * 80}\n")

    process = subprocess.run(cmd, capture_output=True, text=True, env=env)
    output_lines = process.stdout.splitlines()
    error_lines = process.stderr.splitlines()

    # Print output
    for line in output_lines:
        print(line)

    if error_lines:
        print("\nERRORS:")
        for line in error_lines:
            print(line)

    # Change back to the original directory
    os.chdir(current_dir)

    return process.returncode, output_lines


def main() -> int:
    """Main function to run tests."""
    args = parse_args()

    exit_codes = []

    if args.component == "all" or args.component == "api":
        exit_code, _ = run_tests(
            "api",
            args.verbose,
            args.failfast,
            args.junit_xml,
            args.test_path,
            args.coverage,
            args.debug,
        )
        exit_codes.append(exit_code)

    if args.component == "all" or args.component == "app":
        exit_code, _ = run_tests(
            "app",
            args.verbose,
            args.failfast,
            args.junit_xml,
            args.test_path,
            args.coverage,
            args.debug,
        )
        exit_codes.append(exit_code)

    # Return non-zero if any component's tests failed
    return 1 if any(code != 0 for code in exit_codes) else 0


if __name__ == "__main__":
    sys.exit(main())
