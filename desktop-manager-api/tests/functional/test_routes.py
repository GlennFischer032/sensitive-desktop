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


# Example of a functional test with JSON payload
def test_api_endpoint_with_json(test_client: FlaskClient):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/api/example' endpoint is requested (POST) with JSON data
    THEN check the response (this test is expected to fail and should be updated)
    """
    # This is an example - modify with actual endpoints from your API
    response = test_client.post("/api/example", json={"key": "value"})
    # This test is expected to fail, updating print statement helps debug
    print(f"Response status: {response.status_code}, Response data: {response.data}")
    assert response.status_code in [404, 405]  # Either not found or method not allowed
