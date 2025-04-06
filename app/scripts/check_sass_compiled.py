#!/usr/bin/env python
"""
A pre-commit hook to verify that SASS files have been compiled to CSS.
"""

import os
import sys
from pathlib import Path


def get_latest_modification_time(directory, pattern):
    """Get the latest modification time of any file matching pattern in directory."""
    latest = 0
    dir_path = Path(directory)

    if not dir_path.exists():
        print(f"Warning: Directory {directory} does not exist.")
        return latest

    for file_path in dir_path.glob(f"**/{pattern}"):
        if file_path.is_file():
            latest = max(latest, file_path.stat().st_mtime)

    return latest


def main():
    # Path configuration
    scss_dir = "app/scss"
    css_file = "app/static/style.css"

    # Check if CSS file exists
    if not os.path.exists(css_file):
        print(
            f"Error: CSS file {css_file} does not exist. "
            "Run 'pysassc app/scss/main.scss app/static/style.css' to generate it."
        )
        return 1

    # Get modification times
    scss_latest = get_latest_modification_time(scss_dir, "*.scss")
    css_time = os.path.getmtime(css_file) if os.path.exists(css_file) else 0

    # If SCSS files are newer than CSS file, compilation is needed
    if scss_latest > css_time:
        print(f"Error: SCSS files have been modified but {css_file} has not been regenerated.")
        print("Run 'pysassc app/scss/main.scss app/static/style.css' to compile SASS to CSS.")
        return 1

    print("✅ CSS files are up to date with SCSS files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
