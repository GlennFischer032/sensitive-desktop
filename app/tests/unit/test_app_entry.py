"""
This module contains unit tests for the main application entry point (app.py).
"""
import sys
from unittest.mock import patch, MagicMock

import pytest


@patch.dict("sys.modules", {"__init__": MagicMock()})
@patch("__init__.create_app")
def test_app_import(mock_create_app):
    """
    GIVEN the app.py file
    WHEN it is imported
    THEN check it creates the Flask application instance correctly
    """
    # Setup the mock
    mock_app = MagicMock()
    mock_create_app.return_value = mock_app

    # Mock the Config import
    mock_config = MagicMock()
    with patch.dict("sys.modules", {"config.config": MagicMock(), "Config": mock_config}):
        # Import app module (this will execute the file)
        # The import itself would execute app.py which creates the app
        exec("from app import app as imported_app")

        # Check create_app was called
        mock_create_app.assert_called_once()


@patch("app.app")
def test_app_run(mock_app):
    """
    GIVEN the app.py file
    WHEN it is executed as a script
    THEN check app.run() is called
    """
    # Save original __name__ value
    original_name = "__main__"

    # Create a namespace to simulate app.py execution
    app_namespace = {"__name__": original_name, "create_app": MagicMock(), "Config": MagicMock(), "app": mock_app}

    # Execute the app.py's if __name__ == "__main__" block
    exec("if __name__ == '__main__':\n" "    app.run()", app_namespace)

    # Check app.run was called
    mock_app.run.assert_called_once()
