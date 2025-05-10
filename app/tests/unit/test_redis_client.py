"""
This module contains unit tests for the RedisClient.
"""
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

import redis
from flask import Flask
from clients.redis_client import RedisClient


def test_redis_client_initialization():
    """
    GIVEN the RedisClient class
    WHEN a new instance is created
    THEN check the client is initialized correctly
    """
    # Initialize with URL
    client = RedisClient(redis_url="redis://localhost:6379/0", timeout=20)
    assert client._redis_url == "redis://localhost:6379/0"
    assert client.timeout == 20
    assert client._redis_connection is None
    assert client._app is None
    assert client.logger is not None

    # Initialize without URL
    client = RedisClient()
    assert client._redis_url is None
    assert client.timeout == 10  # Default timeout
    assert client._redis_connection is None


def test_configure_with_app():
    """
    GIVEN a RedisClient instance
    WHEN configure_with_app is called
    THEN check the app is stored and connection is reset
    """
    app = Flask("test_app")
    client = RedisClient(redis_url="redis://localhost:6379/0")

    # Set up connection before configuring with app
    with patch.object(client, "_get_connection") as mock_get_conn:
        mock_get_conn.return_value = MagicMock()
        client._redis_connection = MagicMock()

        # Configure with app
        client.configure_with_app(app)

        # Check app is stored and connection reset
        assert client._app is app
        assert client._redis_connection is None


@patch("redis.from_url")
def test_get_connection_with_url(mock_from_url):
    """
    GIVEN a RedisClient instance with a URL
    WHEN _get_connection is called
    THEN check the Redis connection is created with the URL
    """
    mock_redis = MagicMock()
    mock_from_url.return_value = mock_redis

    client = RedisClient(redis_url="redis://localhost:6379/0")
    conn = client._get_connection()

    # Check connection is created with URL
    assert conn is mock_redis
    mock_from_url.assert_called_once_with("redis://localhost:6379/0")

    # Check connection is cached
    assert client._redis_connection is mock_redis

    # Second call should return cached connection
    conn2 = client._get_connection()
    assert conn2 is mock_redis
    mock_from_url.assert_called_once()  # Still only called once


def test_get_connection_from_app_config():
    """
    GIVEN a RedisClient instance with an app
    WHEN _get_connection is called
    THEN check the Redis connection is created from app config
    """
    app = Flask("test_app")
    app.config["SESSION_REDIS"] = "redis://app-config:6379/0"

    with patch("redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis

        client = RedisClient()
        client._app = app

        # Use app context to avoid Flask errors
        with app.app_context():
            conn = client._get_connection()

            # Check connection is created with URL from app config
            assert conn is mock_redis
            mock_from_url.assert_called_once_with("redis://app-config:6379/0")


def test_get_connection_from_current_app():
    """
    GIVEN a RedisClient instance in app context
    WHEN _get_connection is called
    THEN check the Redis connection is created from current_app config
    """
    app = Flask("test_app")
    app.config["SESSION_REDIS"] = "redis://current-app:6379/0"

    with patch("redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis

        client = RedisClient()

        # Use app context to properly mock current_app
        with app.app_context():
            conn = client._get_connection()

            # Check connection is created with URL from current_app config
            assert conn is mock_redis
            mock_from_url.assert_called_once_with("redis://current-app:6379/0")


def test_get_connection_error():
    """
    GIVEN a RedisClient instance without a URL or app context
    WHEN _get_connection is called
    THEN check a ValueError is raised
    """
    client = RedisClient()

    # Instead of patching flask.current_app which causes issues,
    # we'll test directly that accessing _get_connection without
    # an app context or URL raises ValueError
    with pytest.raises(ValueError) as excinfo:
        client._get_connection()

    # Check error message
    assert "Redis URL not provided" in str(excinfo.value)


def test_get_client_for_session():
    """
    GIVEN a RedisClient instance
    WHEN get_client_for_session is called
    THEN check it returns the Redis connection
    """
    client = RedisClient()
    mock_redis = MagicMock()

    with patch.object(client, "_get_connection", return_value=mock_redis):
        session_client = client.get_client_for_session()
        assert session_client is mock_redis


def test_zremrangebyscore_success():
    """
    GIVEN a RedisClient instance
    WHEN zremrangebyscore is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_redis.zremrangebyscore.return_value = 3

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        result = client.zremrangebyscore("test-key", 10, 20)

        # Check result
        assert result == 3

        # Verify redis call
        mock_redis.zremrangebyscore.assert_called_once_with("test-key", 10, 20)


def test_zremrangebyscore_error():
    """
    GIVEN a RedisClient instance
    WHEN zremrangebyscore encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.zremrangebyscore.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.zremrangebyscore("test-key", 10, 20)

        # Check error message
        assert "Redis error" in str(excinfo.value)


def test_zcard_success():
    """
    GIVEN a RedisClient instance
    WHEN zcard is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_redis.zcard.return_value = 5

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        result = client.zcard("test-key")

        # Check result
        assert result == 5

        # Verify redis call
        mock_redis.zcard.assert_called_once_with("test-key")


def test_zcard_error():
    """
    GIVEN a RedisClient instance
    WHEN zcard encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.zcard.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.zcard("test-key")

        # Check error message
        assert "Redis error" in str(excinfo.value)


def test_zrange_success():
    """
    GIVEN a RedisClient instance
    WHEN zrange is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_redis.zrange.return_value = ["item1", "item2", "item3"]

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        # Test without withscores
        result = client.zrange("test-key", 0, 2)

        # Check result
        assert result == ["item1", "item2", "item3"]

        # Verify redis call
        mock_redis.zrange.assert_called_once_with("test-key", 0, 2, withscores=False)

        # Test with withscores
        mock_redis.zrange.reset_mock()
        mock_redis.zrange.return_value = [("item1", 1.0), ("item2", 2.0), ("item3", 3.0)]

        result = client.zrange("test-key", 0, 2, withscores=True)

        # Check result
        assert result == [("item1", 1.0), ("item2", 2.0), ("item3", 3.0)]

        # Verify redis call
        mock_redis.zrange.assert_called_once_with("test-key", 0, 2, withscores=True)


def test_zrange_error():
    """
    GIVEN a RedisClient instance
    WHEN zrange encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.zrange.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.zrange("test-key", 0, 2)

        # Check error message
        assert "Redis error" in str(excinfo.value)


def test_zadd_success():
    """
    GIVEN a RedisClient instance
    WHEN zadd is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_redis.zadd.return_value = 2

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        result = client.zadd("test-key", {"item1": 1.0, "item2": 2.0})

        # Check result
        assert result == 2

        # Verify redis call
        mock_redis.zadd.assert_called_once_with("test-key", {"item1": 1.0, "item2": 2.0})


def test_zadd_error():
    """
    GIVEN a RedisClient instance
    WHEN zadd encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.zadd.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.zadd("test-key", {"item1": 1.0})

        # Check error message
        assert "Redis error" in str(excinfo.value)


def test_expire_success():
    """
    GIVEN a RedisClient instance
    WHEN expire is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_redis.expire.return_value = True

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        result = client.expire("test-key", 3600)

        # Check result
        assert result is True

        # Verify redis call
        mock_redis.expire.assert_called_once_with("test-key", 3600)


def test_expire_error():
    """
    GIVEN a RedisClient instance
    WHEN expire encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.expire.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.expire("test-key", 3600)

        # Check error message
        assert "Redis error" in str(excinfo.value)


def test_pipeline_success():
    """
    GIVEN a RedisClient instance
    WHEN pipeline is called successfully
    THEN check it returns the expected result
    """
    mock_redis = MagicMock()
    mock_pipeline = MagicMock()
    mock_redis.pipeline.return_value = mock_pipeline

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        result = client.pipeline()

        # Check result
        assert result is mock_pipeline

        # Verify redis call
        mock_redis.pipeline.assert_called_once()


def test_pipeline_error():
    """
    GIVEN a RedisClient instance
    WHEN pipeline encounters a Redis error
    THEN check the error is raised
    """
    mock_redis = MagicMock()
    mock_redis.pipeline.side_effect = redis.RedisError("Redis error")

    client = RedisClient()
    with patch.object(client, "_get_connection", return_value=mock_redis):
        with pytest.raises(redis.RedisError) as excinfo:
            client.pipeline()

        # Check error message
        assert "Redis error" in str(excinfo.value)
