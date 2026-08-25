from __future__ import annotations

import csv
from pathlib import Path

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


class ScannerService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes

    async def start(self) -> dict:
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        return await self.processes.run("scan", lambda: self.helper.call("scan-start", interface))

    async def stop(self) -> dict:
        return await self.processes.run("scan", lambda: self.helper.call("scan-stop"))

    async def status(self) -> dict:
        status = await self.helper.call("scan-status")
        status["networks"] = self.parse_csv(self.config.storage.scans / "current-01.csv")
        return status

    @staticmethod
    def parse_csv(path: Path) -> list[dict]:
        if not path.is_file():
            return []
        networks: list[dict] = []
        try:
            with path.open(newline="", errors="replace") as handle:
                rows = csv.reader(handle)
                for row in rows:
                    if not row or row[0].strip() == "BSSID":
                        continue
                    if row[0].strip() == "Station MAC":
                        break
                    if len(row) < 14:
                        continue
                    try:
                        networks.append({
                            "bssid": row[0].strip().upper(),
                            "channel": int(row[3].strip()),
                            "privacy": row[5].strip(),
                            "cipher": row[6].strip(),
                            "authentication": row[7].strip(),
                            "power": int(row[8].strip()),
                            "beacons": int(row[9].strip()),
                            "data_packets": int(row[10].strip()),
                            "ssid": row[13].strip(),
                        })
                    except ValueError:
                        continue
        except OSError:
            return []
        return sorted(networks, key=lambda item: item["power"], reverse=True)

