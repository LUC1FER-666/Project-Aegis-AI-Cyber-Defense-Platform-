import logging
import json
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self):
        self._client: Optional[aioredis.Redis] = None
        self.is_connected = False

    async def connect(self):
        try:
            self._client = aioredis.from_url(
                settings.REDIS_URL, decode_responses=True, socket_connect_timeout=3
            )
            await self._client.ping()
            self.is_connected = True
            logger.info("Redis connected")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")
            self._client = None
            self.is_connected = False

    async def disconnect(self):
        if self._client:
            await self._client.aclose()
        self.is_connected = False

    async def zadd(self, key: str, mapping: dict):
        if not self._client:
            return
        try:
            await self._client.zadd(key, mapping)
        except Exception as e:
            logger.debug(f"Redis zadd error: {e}")

    async def zrevrange(self, key: str, start: int, end: int) -> list[str]:
        if not self._client:
            return []
        try:
            return await self._client.zrevrange(key, start, end)
        except Exception as e:
            logger.debug(f"Redis zrevrange error: {e}")
            return []

    async def zcard(self, key: str) -> int:
        if not self._client:
            return 0
        try:
            return await self._client.zcard(key)
        except Exception:
            return 0

    async def zremrangebyrank(self, key: str, start: int, stop: int):
        if not self._client:
            return
        try:
            await self._client.zremrangebyrank(key, start, stop)
        except Exception as e:
            logger.debug(f"Redis zremrangebyrank error: {e}")

    async def sismember(self, key: str, value: str) -> bool:
        if not self._client:
            return False
        try:
            return await self._client.sismember(key, value)
        except Exception:
            return False

    async def sadd(self, key: str, *values: str):
        if not self._client:
            return
        try:
            await self._client.sadd(key, *values)
        except Exception as e:
            logger.debug(f"Redis sadd error: {e}")

    async def publish(self, channel: str, message: str):
        if not self._client:
            return
        try:
            await self._client.publish(channel, message)
        except Exception as e:
            logger.debug(f"Redis publish error: {e}")

    async def subscribe(self, channel: str):
        if not self._client:
            return None
        try:
            pubsub = self._client.pubsub()
            await pubsub.subscribe(channel)
            return pubsub
        except Exception as e:
            logger.debug(f"Redis subscribe error: {e}")
            return None


redis_client = RedisClient()
