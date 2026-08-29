from __future__ import annotations

import asyncio
import json
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

    async def acquire(
        self,
        operation_type: str,
        resource: str,
        timeout: int | None = None,
        *,
        owner: str = "pinepi-web",
        adapter: str = "",
        target: dict | None = None,
    ) -> str:
        if resource in self._owners:
            raise OperationBusy(f"{resource} is owned by another operation")
        operation_id = str(uuid.uuid4())
        self._owners[resource] = operation_id
        if self._database:
            self._database.execute(
                "INSERT INTO operations(id,type,status,resource,started_at,timeout_seconds,owner,adapter,target_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    operation_id,
                    operation_type,
                    "running",
                    resource,
                    datetime.now(UTC).isoformat(),
                    timeout,
                    owner[:80],
                    adapter[:15],
                    json.dumps(target or {}, separators=(",", ":"))[:2000],
                ),
            )
        return operation_id

    def attach_pid(self, operation_id: str, pid: int | None) -> None:
        if self._database:
            self._database.execute("UPDATE operations SET pid=? WHERE id=?", (pid, operation_id))

    def attach_artifact(self, operation_id: str, artifact_id: str) -> None:
        if not self._database:
            return
        row = self._database.one("SELECT artifacts_json FROM operations WHERE id=?", (operation_id,))
        if not row:
            return
        try:
            artifacts = json.loads(row["artifacts_json"])
        except (json.JSONDecodeError, TypeError):
            artifacts = []
        if not isinstance(artifacts, list):
            artifacts = []
        value = str(artifact_id)[:256]
        if value not in artifacts:
            artifacts.append(value)
        self._database.execute(
            "UPDATE operations SET artifacts_json=? WHERE id=?",
            (json.dumps(artifacts[-50:], separators=(",", ":")), operation_id),
        )

    def finish(self, operation_id: str, status: str = "completed", error: str = "", exit_code: int | None = None) -> None:
        for resource, owner in list(self._owners.items()):
            if owner == operation_id:
                self._owners.pop(resource, None)
        if self._database:
            prefix, separator, _remainder = error.partition(":")
            error_code = prefix if separator and prefix.isupper() and len(prefix) <= 40 else ""
            self._database.execute(
                "UPDATE operations SET status=?,finished_at=?,error_code=?,error_message=?,exit_code=? WHERE id=?",
                (status, datetime.now(UTC).isoformat(), error_code, error[:1000], exit_code, operation_id),
            )

    def owner(self, resource: str) -> str | None:
        return self._owners.get(resource)

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
