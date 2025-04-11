"""Redis client for interacting with Redis."""

import logging
from typing import Any

import redis
from flask import Flask, current_app

logger = logging.getLogger(__name__)


class RedisClient:
    """Client for Redis operations."""

    def __init__(self, redis_url: str | None = None, timeout: int = 10):
        """Initialize the Redis client.

        Args:
            redis_url: URL to Redis server.
                If None, uses REDIS_URL from config when connection is needed.
            timeout: Timeout for Redis operations in seconds.
        """
        self._redis_url = redis_url
        self.timeout = timeout
        self._redis_connection = None
        self._app = None
        self.logger = logger

    def configure_with_app(self, app: Flask) -> None:
        """Configure the client with a Flask app instance.

        Args:
            app: Flask application instance
        """
        self._app = app
        # Reset connection to ensure it's recreated with the new configuration
        self._redis_connection = None

    def _get_connection(self) -> redis.Redis:
        """Get a Redis connection, creating one if needed.

        Returns:
            redis.Redis: Redis connection
        """
        if self._redis_connection is None:
            # First try to use the URL passed directly to the constructor
            redis_url = self._redis_url

            # If no URL was provided, try to get it from the app
            if redis_url is None and self._app is not None:
                redis_url = self._app.config.get("SESSION_REDIS")

            # If we still don't have a URL and we're in an app context, try current_app
            if redis_url is None:
                try:
                    redis_url = current_app.config.get("SESSION_REDIS")
                except RuntimeError as e:
                    # Not in application context
                    raise ValueError(
                        "Redis URL not provided and not in application context. "
                        "Either provide a redis_url to the constructor, call configure_with_app(), "
                        "or ensure you're in an application context."
                    ) from e

            # Now create the connection
            if isinstance(redis_url, str):
                self._redis_connection = redis.from_url(redis_url)
            else:
                # If it's already a redis client instance
                self._redis_connection = redis_url

        return self._redis_connection

    def get_client_for_session(self) -> redis.Redis:
        """Get Redis client for Flask sessions.

        Returns:
            redis.Redis: Redis client suitable for Flask sessions
        """
        return self._get_connection()

    def zremrangebyscore(self, key: str, min_score: int | float, max_score: int | float) -> int:
        """Remove items from a sorted set with scores between min and max.

        Args:
            key: Redis key
            min_score: Minimum score to remove
            max_score: Maximum score to remove

        Returns:
            int: Number of items removed
        """
        client = self._get_connection()
        try:
            return client.zremrangebyscore(key, min_score, max_score)
        except redis.RedisError as e:
            self.logger.error(f"Redis error in zremrangebyscore: {str(e)}")
            raise

    def zcard(self, key: str) -> int:
        """Get number of items in a sorted set.

        Args:
            key: Redis key

        Returns:
            int: Number of items in sorted set
        """
        client = self._get_connection()
        try:
            return client.zcard(key)
        except redis.RedisError as e:
            self.logger.error(f"Redis error in zcard: {str(e)}")
            raise

    def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> list[Any]:
        """Get items from a sorted set by range.

        Args:
            key: Redis key
            start: Start index
            end: End index
            withscores: Whether to include scores

        Returns:
            List[Any]: Range of items
        """
        client = self._get_connection()
        try:
            return client.zrange(key, start, end, withscores=withscores)
        except redis.RedisError as e:
            self.logger.error(f"Redis error in zrange: {str(e)}")
            raise

    def zadd(self, key: str, mapping: dict[str, int | float]) -> int:
        """Add item to sorted set.

        Args:
            key: Redis key
            mapping: Mapping of items to scores

        Returns:
            int: Number of items added
        """
        client = self._get_connection()
        try:
            return client.zadd(key, mapping)
        except redis.RedisError as e:
            self.logger.error(f"Redis error in zadd: {str(e)}")
            raise

    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on key.

        Args:
            key: Redis key
            seconds: Time to expire in seconds

        Returns:
            bool: True if successful
        """
        client = self._get_connection()
        try:
            return client.expire(key, seconds)
        except redis.RedisError as e:
            self.logger.error(f"Redis error in expire: {str(e)}")
            raise

    def pipeline(self) -> redis.client.Pipeline:
        """Get Redis pipeline for batched operations.

        Returns:
            redis.client.Pipeline: Redis pipeline
        """
        client = self._get_connection()
        try:
            return client.pipeline()
        except redis.RedisError as e:
            self.logger.error(f"Redis error in pipeline: {str(e)}")
            raise
