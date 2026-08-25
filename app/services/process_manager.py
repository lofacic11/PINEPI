from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable


class OperationBusy(RuntimeError):
    pass


class ProcessManager:
    """Serializes state-changing operations while allowing status reads."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    async def run(self, name: str, operation: Callable[[], Awaitable[dict]]) -> dict:
        lock = self._locks.setdefault(name, asyncio.Lock())
        if lock.locked():
            raise OperationBusy(f"{name} operation already in progress")
        async with lock:
            return await operation()

