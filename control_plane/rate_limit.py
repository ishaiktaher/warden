"""Distributed production rate limiting with a local database fallback."""

from __future__ import annotations

import time
from typing import cast
from uuid import uuid4

from .config import Settings


class RateLimiter:
    _LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return current
"""

    def __init__(self, database, settings: Settings):
        self.database = database
        self.redis = None
        if settings.production:
            try:
                import redis
                self.redis = redis.Redis.from_url(
                    cast(str, settings.redis_url), socket_connect_timeout=3,
                    socket_timeout=3, decode_responses=True,
                )
                self.redis.ping()
            except Exception as exc:
                raise RuntimeError("Production Redis rate limiter is unavailable") from exc

    def allow(self, connector_id: str, token_jti: str, limit: int) -> bool:
        if self.redis:
            bucket = int(time.time()) // 60
            key = f"warden:rate:{connector_id}:{token_jti}:{bucket}"
            count = int(self.redis.eval(self._LUA, 1, key, 120))
            return count <= limit
        cutoff = int(time.time()) - 60
        count = self.database.one(
            """SELECT COUNT(*) AS count FROM action_requests
            WHERE connector_id=? AND token_jti=? AND requested_at>=?""",
            (connector_id, token_jti, cutoff),
        )["count"]
        if int(count) >= limit:
            return False
        self.database.execute(
            "INSERT INTO action_requests VALUES(?,?,?,?)",
            (str(uuid4()), connector_id, token_jti, int(time.time())),
        )
        return True
