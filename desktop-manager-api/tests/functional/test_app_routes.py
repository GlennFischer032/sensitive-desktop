import pytest
import sys
import os
from flask.testing import FlaskClient

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))


def test_health_endpoint(test_client: FlaskClient):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/health' endpoint is requested (GET)
    THEN check that the response is valid
    """
    response = test_client.get("/api/health")
    assert response.status_code == 200
    assert response.json["status"] == "healthy"
