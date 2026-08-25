from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.services.database import Database


class OperationBusy(RuntimeError):
    pass


class ProcessManager:
    """Serializes state-changing operations while allowing status reads."""

    def __init__(self, database: Database | None = None) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._owners: dict[str, str] = {}
        self._database = database

    async def acquire(self, operation_type: str, resource: str, timeout: int | None = None) -> str:
        if resource in self._owners:
            raise OperationBusy(f"{resource} is owned by another operation")
        operation_id = str(uuid.uuid4())
        self._owners[resource] = operation_id
        if self._database:
            self._database.execute(
                "INSERT INTO operations(id,type,status,resource,started_at,timeout_seconds) VALUES(?,?,?,?,?,?)",
                (operation_id, operation_type, "running", resource, datetime.now(UTC).isoformat(), timeout),
            )
        return operation_id

    def attach_pid(self, operation_id: str, pid: int | None) -> None:
        if self._database:
            self._database.execute("UPDATE operations SET pid=? WHERE id=?", (pid, operation_id))

    def finish(self, operation_id: str, status: str = "completed", error: str = "") -> None:
        for resource, owner in list(self._owners.items()):
            if owner == operation_id:
                self._owners.pop(resource, None)
        if self._database:
            self._database.execute(
                "UPDATE operations SET status=?,finished_at=?,error_message=? WHERE id=?",
                (status, datetime.now(UTC).isoformat(), error[:1000], operation_id),
            )

    def history(self, limit: int = 20) -> list[dict]:
        if not self._database:
            return []
        return self._database.query("SELECT * FROM operations ORDER BY started_at DESC LIMIT ?", (min(limit, 100),))

    def recover(self) -> None:
        if self._database:
            self._database.execute(
                "UPDATE operations SET status='interrupted',finished_at=? WHERE status IN ('running','stopping')",
                (datetime.now(UTC).isoformat(),),
            )

    def restore(self, operation_id: str, resource: str) -> None:
        self._owners[resource] = operation_id
        if self._database:
            self._database.execute("UPDATE operations SET status='running',finished_at=NULL WHERE id=?", (operation_id,))

    async def run(self, name: str, operation: Callable[[], Awaitable[dict]]) -> dict:
        lock = self._locks.setdefault(name, asyncio.Lock())
        if lock.locked():
            raise OperationBusy(f"{name} operation already in progress")
        async with lock:
            return await operation()
