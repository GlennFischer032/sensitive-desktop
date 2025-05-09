from unittest.mock import patch, MagicMock
import sys

import pytest
from clients.connections import ConnectionsClient
from clients.base import APIError, ClientRequest


def test_connections_client_initialization():
    """
    GIVEN the ConnectionsClient class
    WHEN a new instance is created
    THEN check the client is initialized correctly
    """
    client = ConnectionsClient(base_url="http://test-api:5000")

    assert client.base_url == "http://test-api:5000"
    assert client.logger is not None


@patch("clients.base.BaseClient.get")
def test_connection_client_debug_call_args(mock_get):
    """
    Debug test to understand the mock call_args structure
    """
    # Setup mock response
    mock_response = {"connections": []}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    client.list_connections(token="test-auth-token")

    # Debug: print structure of call_args
    print("\nDEBUG CALL_ARGS STRUCTURE:", file=sys.stderr)
    print(f"mock_get.call_args: {mock_get.call_args}", file=sys.stderr)
    print(f"mock_get.call_args type: {type(mock_get.call_args)}", file=sys.stderr)

    if hasattr(mock_get.call_args, "args"):
        print(f"mock_get.call_args.args: {mock_get.call_args.args}", file=sys.stderr)
        if len(mock_get.call_args.args) > 0:
            print(f"First arg: {mock_get.call_args.args[0]}", file=sys.stderr)
            print(f"First arg type: {type(mock_get.call_args.args[0])}", file=sys.stderr)

    if hasattr(mock_get.call_args, "kwargs"):
        print(f"mock_get.call_args.kwargs: {mock_get.call_args.kwargs}", file=sys.stderr)

    # Always pass
    assert True


@patch("clients.base.BaseClient.get")
def test_list_connections_success(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN list_connections is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "connections": [
            {
                "id": "conn1",
                "name": "test-conn",
                "status": "Running",
                "created_at": "2023-01-01T00:00:00",
                "created_by": "test-user",
                "desktop_configuration": {"name": "Standard"},
                "external_pvc": "test-pvc",
            }
        ]
    }
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.list_connections(created_by="test-user", token="test-auth-token")

    # Check results
    assert result == mock_response.get("connections", [])
    assert len(result) == 1
    assert result[0]["name"] == "test-conn"
    assert result[0]["status"] == "Running"

    # Verify the request was correct
    mock_get.assert_called_once()
    # We will update this after we debug the structure
    request = mock_get.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/list"
    assert request.params == {"created_by": "test-user"}
    assert request.token == "test-auth-token"
    assert request.timeout == 10


@patch("clients.base.BaseClient.get")
def test_list_connections_error(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN list_connections encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("API error occurred", status_code=500)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.list_connections(token="test-auth-token")

    assert "API error occurred" in str(exc_info.value)

    # Verify the request was attempted
    mock_get.assert_called_once()


@patch("clients.base.BaseClient.post")
def test_add_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN add_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {
        "id": "conn1",
        "name": "test-conn",
        "status": "Creating",
    }
    mock_post.return_value = (mock_response, 201)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.add_connection(
        name="test-conn",
        persistent_home=True,
        desktop_configuration_id=1,
        external_pvc="test-pvc",
        token="test-auth-token",
    )

    # Check results
    assert result == mock_response
    assert result["name"] == "test-conn"

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/scaleup"
    assert request.token == "test-auth-token"
    assert request.timeout == 180
    assert request.data == {
        "name": "test-conn",
        "persistent_home": True,
        "desktop_configuration_id": 1,
        "external_pvc": "test-pvc",
    }


@patch("clients.base.BaseClient.post")
def test_add_connection_minimal_params(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN add_connection is called with minimal parameters
    THEN check it constructs the request correctly
    """
    # Setup mock response
    mock_post.return_value = ({"id": "conn1"}, 201)

    # Create client and call method with minimal params
    client = ConnectionsClient(base_url="http://test-api:5000")
    client.add_connection(name="test-conn", token="test-auth-token")

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.data == {"name": "test-conn", "persistent_home": True}


@patch("clients.base.BaseClient.post")
def test_add_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN add_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Invalid parameters", status_code=400)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.add_connection(name="test-conn", token="test-auth-token")

    assert "Invalid parameters" in str(exc_info.value)


@patch("clients.base.BaseClient.post")
def test_stop_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN stop_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Connection stopped successfully"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.stop_connection(name="test-conn", token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/scaledown"
    assert request.token == "test-auth-token"
    assert request.data == {"name": "test-conn"}
    assert request.timeout == 30


@patch("clients.base.BaseClient.post")
def test_stop_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN stop_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Connection not found", status_code=404)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.stop_connection(name="nonexistent-conn", token="test-auth-token")

    assert "Connection not found" in str(exc_info.value)


@patch("clients.base.BaseClient.get")
def test_get_connection_success(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN get_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"connection": {"id": "conn1", "name": "test-conn", "status": "Running"}}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.get_connection(name="test-conn", token="test-auth-token")

    # Check results
    assert result == mock_response.get("connection", {})

    # Verify the request was correct
    mock_get.assert_called_once()
    request = mock_get.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/test-conn"
    assert request.token == "test-auth-token"
    assert request.timeout == 10


@patch("clients.base.BaseClient.get")
def test_get_connection_error(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN get_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("Connection not found", status_code=404)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.get_connection(name="nonexistent-conn", token="test-auth-token")

    assert "Connection not found" in str(exc_info.value)


@patch("clients.base.BaseClient.post")
def test_resume_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN resume_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Connection resumed successfully"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.resume_connection(name="test-conn", token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/resume"
    assert request.token == "test-auth-token"
    assert request.data == {"name": "test-conn"}
    assert request.timeout == 60


@patch("clients.base.BaseClient.post")
def test_resume_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN resume_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Connection not found", status_code=404)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.resume_connection(name="nonexistent-conn", token="test-auth-token")

    assert "Connection not found" in str(exc_info.value)


@patch("clients.base.BaseClient.post")
def test_delete_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN delete_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "Connection deleted successfully"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.delete_connection(name="test-conn", token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/permanent-delete"
    assert request.token == "test-auth-token"
    assert request.data == {"name": "test-conn"}
    assert request.timeout == 30


@patch("clients.base.BaseClient.post")
def test_delete_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN delete_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Connection not found", status_code=404)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.delete_connection(name="nonexistent-conn", token="test-auth-token")

    assert "Connection not found" in str(exc_info.value)


@patch("clients.base.BaseClient.get")
def test_direct_connect_success(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN direct_connect is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"auth_url": "https://guacamole.example.com/guacamole/#/?token=test-token"}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.direct_connect(connection_id="conn1", token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "auth_url" in result
    assert "guacamole" in result["auth_url"]

    # Verify the request was correct
    mock_get.assert_called_once()
    request = mock_get.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/direct-connect/conn1"
    assert request.token == "test-auth-token"
    assert request.timeout == 10


@patch("clients.base.BaseClient.get")
def test_direct_connect_error(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN direct_connect encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("Failed to connect to desktop", status_code=400)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.direct_connect(connection_id="conn1", token="test-auth-token")

    assert "Failed to connect to desktop" in str(exc_info.value)


@patch("clients.base.BaseClient.get")
def test_guacamole_dashboard_success(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN guacamole_dashboard is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"auth_url": "https://guacamole.example.com/guacamole/#/?token=dashboard-token"}
    mock_get.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.guacamole_dashboard(token="test-auth-token")

    # Check results
    assert result == mock_response
    assert "auth_url" in result
    assert "guacamole" in result["auth_url"]
    assert "dashboard-token" in result["auth_url"]

    # Verify the request was correct
    mock_get.assert_called_once()
    request = mock_get.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/guacamole-dashboard"
    assert request.token == "test-auth-token"
    assert request.timeout == 10


@patch("clients.base.BaseClient.get")
def test_guacamole_dashboard_error(mock_get):
    """
    GIVEN a ConnectionsClient instance
    WHEN guacamole_dashboard encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_get.side_effect = APIError("Error getting Guacamole dashboard", status_code=500)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.guacamole_dashboard(token="test-auth-token")

    assert "Error getting Guacamole dashboard" in str(exc_info.value)


@patch("clients.base.BaseClient.post")
def test_attach_pvc_to_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN attach_pvc_to_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "PVC attached successfully"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.attach_pvc_to_connection(connection_id=1, pvc_id=2, token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/attach-pvc"
    assert request.token == "test-auth-token"
    assert request.data == {"connection_id": 1, "pvc_id": 2}
    assert request.timeout == 180


@patch("clients.base.BaseClient.post")
def test_attach_pvc_to_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN attach_pvc_to_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Invalid connection or PVC", status_code=400)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.attach_pvc_to_connection(connection_id=1, pvc_id=2, token="test-auth-token")

    assert "Invalid connection or PVC" in str(exc_info.value)


@patch("clients.base.BaseClient.post")
def test_detach_pvc_from_connection_success(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN detach_pvc_from_connection is called successfully
    THEN check it returns the expected response
    """
    # Setup mock response
    mock_response = {"message": "PVC detached successfully"}
    mock_post.return_value = (mock_response, 200)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")
    result = client.detach_pvc_from_connection(connection_id=1, token="test-auth-token")

    # Check results
    assert result == mock_response

    # Verify the request was correct
    mock_post.assert_called_once()
    request = mock_post.call_args.args[0]
    assert isinstance(request, ClientRequest)
    assert request.endpoint == "/api/connections/detach-pvc"
    assert request.token == "test-auth-token"
    assert request.data == {"connection_id": 1}
    assert request.timeout == 180


@patch("clients.base.BaseClient.post")
def test_detach_pvc_from_connection_error(mock_post):
    """
    GIVEN a ConnectionsClient instance
    WHEN detach_pvc_from_connection encounters an error
    THEN check it raises the APIError
    """
    # Setup mock to raise APIError
    mock_post.side_effect = APIError("Invalid connection", status_code=400)

    # Create client and call method
    client = ConnectionsClient(base_url="http://test-api:5000")

    # Check that APIError is raised
    with pytest.raises(APIError) as exc_info:
        client.detach_pvc_from_connection(connection_id=1, token="test-auth-token")

    assert "Invalid connection" in str(exc_info.value)
