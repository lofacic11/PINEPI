from __future__ import annotations

import asyncio
import re
import socket
import time
from pathlib import Path

import psutil

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters
from app.services.command import CommandError, run_command
from app.version import VERSION


class SystemService:
    def __init__(self, config: AppConfig):
        self.config = config
        self._cache: tuple[float, dict] | None = None
        self._lock = asyncio.Lock()

    async def status(self) -> dict:
        now = time.monotonic()
        if self._cache and now - self._cache[0] < self.config.status_cache_seconds:
            return self._cache[1]
        async with self._lock:
            now = time.monotonic()
            if self._cache and now - self._cache[0] < self.config.status_cache_seconds:
                return self._cache[1]
            adapters = await detect_adapters(self.config)
            await asyncio.gather(*(self._enrich(item) for item in adapters))
            root = psutil.disk_usage("/")
            result = {
                "version": VERSION,
                "hostname": socket.gethostname(),
                "cpu_percent": psutil.cpu_percent(interval=None),
                "cpu_temperature_c": self._temperature(),
                "ram_percent": psutil.virtual_memory().percent,
                "storage_percent": root.percent,
                "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
                "current_time": time.time(),
                "service_ready": True,
                "interfaces": adapters,
                "regulatory": await self._regulatory(),
            }
            self._cache = (now, result)
            return result

    @staticmethod
    def _temperature() -> float | None:
        for path in ("/sys/class/thermal/thermal_zone0/temp",):
            try:
                return round(int(Path(path).read_text().strip()) / 1000, 1)
            except (OSError, ValueError):
                continue
        return None

    async def _enrich(self, item: dict) -> None:
        item.update({"type": "unknown", "ssid": "", "channel": None, "tx_power_dbm": None})
        try:
            info, link = await asyncio.gather(
                run_command("iw", "dev", item["interface"], "info", timeout=3),
                run_command("iw", "dev", item["interface"], "link", timeout=3, check=False),
            )
        except CommandError:
            return
        type_match = re.search(r"\btype\s+(\S+)", info.stdout)
        channel_match = re.search(r"\bchannel\s+(\d+)", info.stdout)
        tx_match = re.search(r"\btxpower\s+([\d.]+)\s+dBm", info.stdout)
        ssid_match = re.search(r"^\s*SSID:\s*(.*)$", link.stdout, re.MULTILINE)
        item["type"] = type_match.group(1) if type_match else "unknown"
        item["channel"] = int(channel_match.group(1)) if channel_match else None
        item["tx_power_dbm"] = float(tx_match.group(1)) if tx_match else None
        item["ssid"] = ssid_match.group(1).strip() if ssid_match else ""

    @staticmethod
    async def _regulatory() -> dict:
        try:
            result = await run_command("iw", "reg", "get", timeout=4, check=False)
        except CommandError:
            return {"country": "Unknown", "available": False}
        countries = re.findall(r"^country\s+([A-Z0-9]{2}):", result.stdout, re.MULTILINE)
        return {"country": countries[0] if countries else "Unknown", "domains": countries, "available": result.returncode == 0}
