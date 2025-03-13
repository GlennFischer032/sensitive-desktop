"""Root conftest.py to set up test environment."""

import os
import sys
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent
sys.path.append(str(app_dir))
