import json
from typing import Dict, List
from fastapi import WebSocket
import asyncio


class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
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

    async def send_new_alert(self, alert_data: dict):
        await self.broadcast({"type": "new_alert", "data": alert_data})

    async def send_agent_offline(self, agent_id: str, hostname: str):
        await self.broadcast({
            "type": "agent_offline",
            "data": {"agent_id": agent_id, "hostname": hostname}
        })

    async def send_critical_log(self, log_data: dict):
        await self.broadcast({"type": "critical_log", "data": log_data})

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


ws_manager = WebSocketManager()
