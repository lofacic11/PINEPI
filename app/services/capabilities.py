from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import re
import shutil
import time
from dataclasses import asdict, dataclass

from app.services.command import CommandError, run_command


AIRCRACK_BINARIES = (
    "aircrack-ng",
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "airdecap-ng",
    "packetforge-ng",
    "airolib-ng",
    "airserv-ng",
    "airtun-ng",
    "besside-ng",
    "buddy-ng",
    "easside-ng",
    "ivstools",
    "kstats",
    "makeivs-ng",
    "tkiptun-ng",
    "wesside-ng",
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    role: str
    required: bool = False
    classification: str = "passive"
    privileges: str = "none"
    adapter: str = "none"
    version_args: tuple[str, ...] = ("--version",)
    python_package: str = ""


TOOL_SPECS = tuple(
    ToolSpec(
        name,
        "Aircrack-ng",
        "Wireless suite component",
        required=name in {"airodump-ng", "aireplay-ng", "aircrack-ng"},
        classification="active" if name in {"aireplay-ng", "packetforge-ng", "besside-ng", "easside-ng", "tkiptun-ng", "wesside-ng"} else "passive",
        privileges="restricted helper" if name in {"airmon-ng", "airodump-ng", "aireplay-ng", "airserv-ng", "airtun-ng", "besside-ng", "easside-ng", "tkiptun-ng", "wesside-ng"} else "none",
        adapter="audit" if name in {"airmon-ng", "airodump-ng", "aireplay-ng", "airserv-ng", "airtun-ng", "besside-ng", "easside-ng", "tkiptun-ng", "wesside-ng"} else "none",
        version_args=("--help",),
    )
    for name in AIRCRACK_BINARIES
) + (
    ToolSpec("dumpcap", "Wireshark", "Low-privilege capture", True, "passive", "restricted helper", "audit", ("--version",)),
    ToolSpec("tshark", "Wireshark", "Offline protocol analysis", True, version_args=("--version",)),
    ToolSpec("kismet", "Kismet", "Optional Recon engine", adapter="audit", privileges="service/helper", version_args=("--version",)),
    ToolSpec("hcxdumptool", "HCX", "Advanced capture engine", classification="mixed", privileges="restricted helper", adapter="audit", version_args=("--version",)),
    ToolSpec("hcxpcapngtool", "HCX", "Handshake and PMKID validation", version_args=("--version",)),
    ToolSpec("scapy", "Scapy", "Bounded frame parsing", python_package="scapy"),
    ToolSpec("mdk4", "MDK4", "Advanced authorized active tests", classification="active", privileges="restricted helper", adapter="audit", version_args=("--help",)),
    ToolSpec("bettercap", "Bettercap", "Optional discovery engine", classification="mixed", privileges="service/helper", adapter="audit", version_args=("-version",)),
    ToolSpec("suricata", "Suricata", "Offline IDS analysis", version_args=("--build-info",)),
    ToolSpec("zeek", "Zeek", "Offline traffic analysis", version_args=("--version",)),
)


def parse_version(text: str) -> str:
    """Extract a conservative version token from bounded tool output."""
    match = re.search(r"(?i)(?:version\s*)?v?(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)", text[:4096])
    return match.group(1) if match else "Unknown"


class CapabilityRegistry:
    def __init__(self, cache_seconds: float = 300.0):
        self.cache_seconds = cache_seconds
        self._cache: tuple[float, dict] | None = None
        self._lock = asyncio.Lock()

    async def status(self, *, refresh: bool = False) -> dict:
        now = time.monotonic()
        if not refresh and self._cache and now - self._cache[0] < self.cache_seconds:
            return self._cache[1]
        async with self._lock:
            now = time.monotonic()
            if not refresh and self._cache and now - self._cache[0] < self.cache_seconds:
                return self._cache[1]
            aircrack_version = await self._aircrack_version()
            items = []
            for spec in TOOL_SPECS:
                item = asdict(spec)
                item.pop("version_args")
                item.pop("python_package")
                if spec.python_package:
                    available = importlib.util.find_spec(spec.python_package) is not None
                    version = self._python_version(spec.python_package) if available else ""
                    path = "Python package" if available else ""
                else:
                    path = shutil.which(spec.name) or ""
                    available = bool(path)
                    version = aircrack_version if available and spec.name in AIRCRACK_BINARIES else ""
                    if available and not version:
                        version = await self._binary_version(path, spec.version_args)
                item.update(
                    available=available,
                    version=version or ("Unknown" if available else ""),
                    path=path,
                    state="READY" if available else "MISSING",
                )
                items.append(item)
            result = {
                "items": items,
                "summary": {
                    "available": sum(1 for item in items if item["available"]),
                    "missing": sum(1 for item in items if not item["available"]),
                    "required_missing": [item["name"] for item in items if item["required"] and not item["available"]],
                },
                "refreshed_at": time.time(),
            }
            self._cache = (now, result)
            return result

    async def _aircrack_version(self) -> str:
        path = shutil.which("aircrack-ng")
        return await self._binary_version(path, ("--help",)) if path else ""

    @staticmethod
    async def _binary_version(path: str, arguments: tuple[str, ...]) -> str:
        try:
            result = await run_command(path, *arguments, timeout=3, check=False)
        except CommandError:
            return "Unknown"
        return parse_version(result.stdout or result.stderr)

    @staticmethod
    def _python_version(package: str) -> str:
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return "Unknown"

