from __future__ import annotations

import asyncio


class AppState:
    def __init__(self) -> None:
        self._target: dict | None = None
        self._lock = asyncio.Lock()

    async def set_target(self, target: dict) -> dict:
        async with self._lock:
            self._target = target.copy()
            return self._target.copy()

    async def target(self) -> dict | None:
        async with self._lock:
            return self._target.copy() if self._target else None

