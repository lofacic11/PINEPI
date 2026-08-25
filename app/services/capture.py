from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


SAFE_CAPTURE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.pcapng$")


class CaptureService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes
        self._cache: tuple[float, dict] | None = None
        self._lock = asyncio.Lock()

    async def start(self, channel: int) -> dict:
        if not 1 <= channel <= 196:
            raise ValueError("Invalid channel")
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        self._cache = None
        return await self.processes.run(
            "capture",
            lambda: self.helper.call("capture-start", interface, str(channel), str(self.config.storage.max_capture_mb)),
        )

    async def stop(self) -> dict:
        self._cache = None
        return await self.processes.run("capture", lambda: self.helper.call("capture-stop"))

    async def status(self) -> dict:
        now = time.monotonic()
        if self._cache and now - self._cache[0] < self.config.status_cache_seconds:
            return self._cache[1]
        async with self._lock:
            status = await self.helper.call("capture-status", timeout=25)
            frames = int(status.get("eapol_frames", 0))
            status["handshake"] = (
                "Not detected" if frames == 0 else "EAPOL detected" if frames < 4 else "Likely complete"
            )
            status["handshake_note"] = "Frame count is only an indicator; it does not validate an M1-M4 exchange."
            self._cache = (time.monotonic(), status)
            return status

    def list_captures(self) -> list[dict]:
        root = self.config.storage.captures
        if not root.is_dir():
            return []
        result = []
        for path in root.glob("*.pcapng"):
            try:
                stat = path.stat()
                result.append({"filename": path.name, "size": stat.st_size, "created": stat.st_mtime})
            except OSError:
                continue
        return sorted(result, key=lambda item: item["created"], reverse=True)

    def resolve(self, filename: str) -> Path:
        if not SAFE_CAPTURE.fullmatch(filename):
            raise ValueError("Invalid capture filename")
        root = self.config.storage.captures.resolve()
        path = (root / filename).resolve()
        if path.parent != root or not path.is_file():
            raise FileNotFoundError(filename)
        return path

    async def delete(self, filename: str) -> dict:
        self.resolve(filename)
        return await self.helper.call("capture-delete", filename)

