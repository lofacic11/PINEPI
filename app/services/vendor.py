from __future__ import annotations

import re
from pathlib import Path

MAC = re.compile(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class VendorLookup:
    def __init__(self, paths: tuple[Path, ...]):
        self.paths = paths
        self._vendors: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        vendors: dict[str, str] = {}
        for path in self.paths:
            try:
                for line in path.read_text(errors="replace").splitlines():
                    match = re.match(r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})\s+(?:\(hex\)\s+)?(.+)$", line)
                    if match:
                        vendors["".join(match.group(i).upper() for i in range(1, 4))] = match.group(4).strip()
            except OSError:
                continue
            if vendors:
                break
        return vendors

    def lookup(self, mac: str) -> str:
        if not MAC.fullmatch(mac):
            return "Unknown"
        if int(mac[:2], 16) & 0x02:
            return "Randomized/local address"
        if self._vendors is None:
            self._vendors = self._load()
        return self._vendors.get(mac.replace(":", "").upper()[:6], "Unknown")
