import json
import asyncio
import logging
from typing import List, Optional
from fastapi import WebSocket

logger = logging.getLogger(__name__)

BROADCAST_CHANNEL = "siem:ws:broadcast"


class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._redis = None
        self._pubsub = None
        self._listener_task: Optional[asyncio.Task] = None

    async def init_redis(self, redis_url: str):
        """Initialize Redis pub/sub for multi-instance WebSocket broadcasting."""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(redis_url, decode_responses=True)
            self._pubsub = self._redis.pubsub()
            await self._pubsub.subscribe(BROADCAST_CHANNEL)
            self._listener_task = asyncio.create_task(self._redis_listener())
            logger.info("WebSocket Redis pub/sub initialized on channel %s", BROADCAST_CHANNEL)
        except Exception as exc:
            logger.warning("Redis pub/sub unavailable, using in-memory broadcast: %s", exc)
            self._redis = None

    async def _redis_listener(self):
        """Relay Redis channel messages to all local WebSocket connections."""
        try:
            async for message in self._pubsub.listen():
                if message.get("type") == "message":
                    try:
                        data = json.loads(message["data"])
                        await self._broadcast_local(data)
                    except Exception as exc:
                        logger.debug("WS relay error: %s", exc)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Redis WS listener crashed: %s", exc, exc_info=True)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def _broadcast_local(self, message: dict):
        """Send to every connection on this process."""
        if not self.active_connections:
            return
        data = json.dumps(message, default=str)
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)

    async def broadcast(self, message: dict):
        """Publish via Redis (all instances) or fall back to local broadcast."""
        if self._redis:
            try:
                await self._redis.publish(BROADCAST_CHANNEL, json.dumps(message, default=str))
                return
            except Exception as exc:
                logger.warning("Redis publish failed, falling back to local: %s", exc)
        await self._broadcast_local(message)

    async def send_new_alert(self, alert_data: dict):
        await self.broadcast({"type": "new_alert", "data": alert_data})

    async def send_agent_offline(self, agent_id: str, hostname: str):
        await self.broadcast({
            "type": "agent_offline",
            "data": {"agent_id": agent_id, "hostname": hostname},
        })

    async def send_critical_log(self, log_data: dict):
        await self.broadcast({"type": "critical_log", "data": log_data})

    async def shutdown(self):
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        if self._pubsub:
            await self._pubsub.unsubscribe(BROADCAST_CHANNEL)
            await self._pubsub.close()
        if self._redis:
            await self._redis.aclose()

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


ws_manager = WebSocketManager()
