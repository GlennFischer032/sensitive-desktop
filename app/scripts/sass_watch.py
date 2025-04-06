#!/usr/bin/env python
"""
A simple script to watch Sass files and compile on change.
Use: python app/scripts/sass_watch.py
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def compile_sass(source, target):
    """Compile Sass to CSS."""
    print(f"Compiling {source} to {target}...")
    # Find the full path to pysassc executable
    pysassc_path = shutil.which("pysassc")
    if not pysassc_path:
        print("❌ Error: pysassc not found in PATH. Please install it.")
        return False

    # Validate that the source and target are valid paths (security check)
    source_path = Path(source).resolve()
    target_path = Path(target).resolve()

    # Ensure paths are within the project directory
    cwd = Path.cwd().resolve()
    if not (str(source_path).startswith(str(cwd)) and str(target_path).startswith(str(cwd))):
        print("❌ Security Error: Source or target path is outside the project directory.")
        return False

    # We've validated the executable path and input paths, so this is safe
    result = subprocess.run(  # noqa: S603
        [pysassc_path, str(source_path), str(target_path)],
        capture_output=True,
        text=True,
        check=False,  # Explicitly set check to False and handle returncode ourselves
    )

    if result.returncode == 0:
        print("✅ Compilation successful")
        return True
    else:
        print("❌ Compilation failed:")
        print(result.stderr)
        return False


def get_modification_time(directory):
    """Get the latest modification time of any .scss file in directory."""
    latest = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".scss"):
                path = os.path.join(root, file)
                latest = max(latest, os.path.getmtime(path))
    return latest


def main():
    scss_dir = sys.argv[1] if len(sys.argv) > 1 else "app/scss"

    target_file = sys.argv[2] if len(sys.argv) > 2 else "app/static/style.css"  # noqa: PLR2004

    main_scss = os.path.join(scss_dir, "main.scss")

    if not os.path.exists(main_scss):
        print(f"Error: Main SCSS file not found at {main_scss}")
        return 1

    # Create target directory if it doesn't exist
    target_dir = os.path.dirname(target_file)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    print(f"Watching {scss_dir} for changes...")
    print("Press Ctrl+C to stop")

    # Initial compilation
    compile_sass(main_scss, target_file)

    last_mod_time = get_modification_time(scss_dir)

    try:
        while True:
            time.sleep(1)
            current_mod_time = get_modification_time(scss_dir)

            if current_mod_time > last_mod_time:
                print(f"\n📝 Changes detected at {time.strftime('%H:%M:%S')}")
                compile_sass(main_scss, target_file)
                last_mod_time = current_mod_time
    except KeyboardInterrupt:
        print("\nStopping watch process")
        return 0


if __name__ == "__main__":
    sys.exit(main())
