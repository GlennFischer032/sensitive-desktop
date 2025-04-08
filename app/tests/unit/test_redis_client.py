"""
Unit tests for the Redis client.
"""

import pytest
from unittest.mock import MagicMock, patch
from flask import Flask

import redis
from app.clients.redis_client import RedisClient


def test_redis_client_initialization():
    """
    GIVEN a RedisClient class
    WHEN a new RedisClient is created
    THEN check the default values are set correctly
    """
    client = RedisClient()
    assert client._redis_url is None
    assert client.timeout == 10
    assert client._redis_connection is None
    assert client._app is None


def test_redis_client_with_url():
    """
    GIVEN a RedisClient class
    WHEN a new RedisClient is created with a URL
    THEN check the URL is stored correctly
    """
    redis_url = "redis://localhost:6379/0"
    client = RedisClient(redis_url=redis_url)
    assert client._redis_url == redis_url
    assert client.timeout == 10


def test_redis_client_with_custom_timeout():
    """
    GIVEN a RedisClient class
    WHEN a new RedisClient is created with a custom timeout
    THEN check the timeout is stored correctly
    """
    client = RedisClient(timeout=30)
    assert client._redis_url is None
    assert client.timeout == 30


def test_configure_with_app():
    """
    GIVEN a RedisClient and a Flask app
    WHEN configure_with_app is called
    THEN check the app is stored and connection is reset
    """
    client = RedisClient()
    app = Flask(__name__)

    # Set up connection first
    with patch.object(client, "_get_connection") as mock_get_connection:
        mock_connection = MagicMock()
        mock_get_connection.return_value = mock_connection

        # This should create a connection
        client.get_client_for_session()

        # Now configure with app, which should reset the connection
        client.configure_with_app(app)

        assert client._app == app
        assert client._redis_connection is None


@patch("redis.from_url")
def test_get_connection_with_direct_url(mock_from_url):
    """
    GIVEN a RedisClient initialized with a URL
    WHEN _get_connection is called
    THEN check it uses the provided URL
    """
    redis_url = "redis://localhost:6379/0"
    mock_connection = MagicMock()
    mock_from_url.return_value = mock_connection

    client = RedisClient(redis_url=redis_url)
    connection = client._get_connection()

    mock_from_url.assert_called_once_with(redis_url)
    assert connection == mock_connection


@patch("redis.from_url")
def test_get_connection_with_app_config(mock_from_url):
    """
    GIVEN a RedisClient with an app that has SESSION_REDIS configured
    WHEN _get_connection is called
    THEN check it uses the URL from app config
    """
    app = Flask(__name__)
    redis_url = "redis://localhost:6379/1"
    app.config["SESSION_REDIS"] = redis_url

    mock_connection = MagicMock()
    mock_from_url.return_value = mock_connection

    client = RedisClient()
    client.configure_with_app(app)
    connection = client._get_connection()

    mock_from_url.assert_called_once_with(redis_url)
    assert connection == mock_connection


def test_get_client_for_session():
    """
    GIVEN a RedisClient with a mock connection
    WHEN get_client_for_session is called
    THEN check it returns the right connection
    """
    client = RedisClient()

    # Create a mock for _get_connection and set it as the return value for get_client_for_session
    mock_connection = MagicMock()
    with patch.object(client, "_get_connection", return_value=mock_connection):
        session_client = client.get_client_for_session()
        assert session_client == mock_connection


@patch("redis.Redis.zremrangebyscore")
def test_zremrangebyscore_error(mock_zremrangebyscore):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the zremrangebyscore method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_zremrangebyscore.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.zremrangebyscore = mock_zremrangebyscore

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.zremrangebyscore("key", 0, 100)

        assert "Test error" in str(exc_info.value)


@patch("redis.Redis.zcard")
def test_zcard_error(mock_zcard):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the zcard method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_zcard.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.zcard = mock_zcard

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.zcard("key")

        assert "Test error" in str(exc_info.value)


@patch("redis.Redis.zrange")
def test_zrange_error(mock_zrange):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the zrange method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_zrange.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.zrange = mock_zrange

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.zrange("key", 0, 10)

        assert "Test error" in str(exc_info.value)


@patch("redis.Redis.zadd")
def test_zadd_error(mock_zadd):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the zadd method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_zadd.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.zadd = mock_zadd

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.zadd("key", {"item": 1})

        assert "Test error" in str(exc_info.value)


@patch("redis.Redis.expire")
def test_expire_error(mock_expire):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the expire method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_expire.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.expire = mock_expire

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.expire("key", 60)

        assert "Test error" in str(exc_info.value)


@patch("redis.Redis.pipeline")
def test_pipeline_error(mock_pipeline):
    """
    GIVEN a RedisClient with mock Redis that raises an error
    WHEN using the pipeline method
    THEN it should propagate the error
    """
    client = RedisClient()
    mock_pipeline.side_effect = redis.RedisError("Test error")

    # Mock the _get_connection method to return a Redis instance
    redis_instance = MagicMock()
    redis_instance.pipeline = mock_pipeline

    with patch.object(client, "_get_connection", return_value=redis_instance):
        with pytest.raises(redis.RedisError) as exc_info:
            client.pipeline()

        assert "Test error" in str(exc_info.value)
