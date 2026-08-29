from __future__ import annotations

import shutil

from app.services.capabilities import CapabilityRegistry


def normalize_kismet_devices(devices: list[dict]) -> tuple[list[dict], list[dict]]:
    """Normalize bounded Kismet JSON device records without adopting its database."""
    access_points, clients = [], []
    for raw in devices[:5000]:
        common = raw.get("kismet.device.base", raw)
        mac = str(common.get("kismet.device.base.macaddr", common.get("macaddr", ""))).upper()
        if len(mac) != 17:
            continue
        device_type = str(common.get("kismet.device.base.type", common.get("type", ""))).lower()
        signal = common.get("kismet.device.base.signal", common.get("signal", {}))
        last_signal = signal.get("kismet.common.signal.last_signal", signal.get("last_signal")) if isinstance(signal, dict) else signal
        channel = common.get("kismet.device.base.channel", common.get("channel"))
        first_seen = common.get("kismet.device.base.first_time", common.get("first_seen"))
        last_seen = common.get("kismet.device.base.last_time", common.get("last_seen"))
        manufacturer = str(common.get("kismet.device.base.manuf", common.get("manufacturer", "Unknown")))[:160]
        names = common.get("kismet.device.base.name", common.get("name", ""))
        if "ap" in device_type or "access point" in device_type:
            access_points.append({
                "bssid": mac,
                "ssid": str(names)[:128],
                "channel": int(channel) if str(channel).isdigit() else None,
                "signal": int(last_signal) if str(last_signal).lstrip("-").isdigit() else None,
                "vendor": manufacturer,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "source": "kismet",
            })
        else:
            clients.append({
                "station_mac": mac,
                "signal": int(last_signal) if str(last_signal).lstrip("-").isdigit() else None,
                "vendor": manufacturer,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "relationship": "unknown",
                "source": "kismet",
            })
    return access_points, clients


class KismetService:
    def __init__(self, capabilities: CapabilityRegistry):
        self.capabilities = capabilities

    async def status(self) -> dict:
        registry = await self.capabilities.status()
        item = next(entry for entry in registry["items"] if entry["name"] == "kismet")
        return {
            **item,
            "configured": False,
            "api_available": False,
            "engine_selection": "PinePi/airodump",
            "explanation": (
                "Kismet is detected but API credentials/source configuration are not enabled."
                if shutil.which("kismet")
                else "Kismet is optional and is not installed; PinePi/airodump remains the deterministic Recon engine."
            ),
        }

