from __future__ import annotations

from app.config import AppConfig
from app.services.helper import HelperClient


class ManagementAPService:
    def __init__(self, config: AppConfig, helper: HelperClient):
        self.config = config
        self.helper = helper

    async def status(self) -> dict:
        status = await self.helper.call("management-status")
        for secret in ("password", "passphrase", "wpa_passphrase"):
            status.pop(secret, None)
        status.setdefault("enabled", self.config.management_ap.enabled)
        status.setdefault("ssid", self.config.management_ap.ssid)
        status.setdefault("channel", self.config.management_ap.channel)
        gateway = str(self.config.management_ap.address).split("/", 1)[0]
        status.setdefault("gateway", gateway)
        status.setdefault("web_url", f"http://{gateway}:8000")
        return status
