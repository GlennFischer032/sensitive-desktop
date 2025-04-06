#!/usr/bin/env python3
"""
Test runner script for the Desktop Manager project.

This script provides functionality to run tests for both the desktop-manager-api
and app components, either individually or together.
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple


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
    parser.add_argument(
        "--parallel",
        "-p",
        action="store_true",
        help="Run tests for components in parallel",
    )
    parser.add_argument(
        "--last-failed",
        action="store_true",
        help="Run only tests that failed in the last run",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Run only tests affected by recent changes",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable pytest cache",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=os.cpu_count() or 2,
        help="Number of worker processes for pytest-xdist (if installed)",
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
    last_failed: bool = False,
    changed_only: bool = False,
    no_cache: bool = False,
    num_workers: int = 1,
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
        last_failed: Run only tests that failed in the last run
        changed_only: Run only tests affected by recent changes
        no_cache: Disable pytest cache
        num_workers: Number of worker processes for pytest-xdist

    Returns:
        Tuple containing exit code and output lines
    """
    current_dir = os.getcwd()
    component_dir = "desktop-manager-api" if component == "api" else "app"
    os.chdir(os.path.join(current_dir, component_dir))

    cmd = ["python", "-m", "pytest"]

    # Add performance optimizations
    if not no_cache:
        # Enable cache by default
        cmd.append("-p")
        cmd.append("cacheprovider")

    # Try to use pytest-xdist if available for parallel test execution within component
    try:
        import pkg_resources

        pkg_resources.get_distribution("pytest-xdist")
        if num_workers > 1:
            cmd.append(f"-n{num_workers}")
    except (pkg_resources.DistributionNotFound, ImportError):
        pass  # pytest-xdist not installed, continue without it

    if last_failed:
        cmd.append("--last-failed")

    if changed_only:
        cmd.append("--changed")

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
    print(f"\n{'=' * 80}")
    print(
        f"Running tests for {component_dir}"
        + (" with authentication patching" if component == "app" else "")
    )
    print(f"{'=' * 80}\n")
    print(f"Command: {' '.join(cmd)}")

    start_time = time.time()
    process = subprocess.run(cmd, capture_output=True, text=True, env=env)
    duration = time.time() - start_time

    output_lines = process.stdout.splitlines()
    error_lines = process.stderr.splitlines()

    # Print output
    for line in output_lines:
        print(line)

    if error_lines:
        print("\nERRORS:")
        for line in error_lines:
            print(line)

    print(f"\nTests for {component} completed in {duration:.2f} seconds")

    # Change back to the original directory
    os.chdir(current_dir)

    return process.returncode, output_lines


def run_tests_parallel(args: argparse.Namespace) -> Dict[str, Tuple[int, List[str]]]:
    """Run tests for multiple components in parallel."""
    components = []
    if args.component == "all":
        components = ["api", "app"]
    else:
        components = [args.component]

    results = {}

    with concurrent.futures.ProcessPoolExecutor(
        max_workers=len(components)
    ) as executor:
        future_to_component = {
            executor.submit(
                run_tests,
                component,
                args.verbose,
                args.failfast,
                args.junit_xml,
                args.test_path,
                args.coverage,
                args.debug,
                args.last_failed,
                args.changed_only,
                args.no_cache,
                args.num_workers,
            ): component
            for component in components
        }

        for future in concurrent.futures.as_completed(future_to_component):
            component = future_to_component[future]
            try:
                results[component] = future.result()
            except Exception as exc:
                print(f"Component {component} generated an exception: {exc}")
                results[component] = (1, [f"Error: {exc}"])

    return results


def main() -> int:
    """Main function to run tests."""
    args = parse_args()
    start_time = time.time()

    if args.component == "all" and args.parallel:
        # Run all components in parallel
        results = run_tests_parallel(args)
        exit_codes = [code for code, _ in results.values()]
    else:
        # Run components sequentially
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
                args.last_failed,
                args.changed_only,
                args.no_cache,
                args.num_workers,
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
                args.last_failed,
                args.changed_only,
                args.no_cache,
                args.num_workers,
            )
            exit_codes.append(exit_code)

    total_duration = time.time() - start_time
    print(f"\nAll tests completed in {total_duration:.2f} seconds")

    # Return non-zero if any component's tests failed
    return 1 if any(code != 0 for code in exit_codes) else 0


if __name__ == "__main__":
    sys.exit(main())
