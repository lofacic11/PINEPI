from __future__ import annotations

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


class TrainingAPService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes

    async def start(self, ssid: str, password: str, channel: int) -> dict:
        adapters = await detect_adapters(self.config)
        interface = interface_for_role(adapters, "training_ap")
        excluded = excluded_uplink_interfaces(adapters, interface)
        return await self.processes.run(
            "training-ap",
            lambda: self.helper.call(
                "ap-start", interface, str(channel), ",".join(sorted(excluded)),
                payload={"ssid": ssid, "password": password},
            ),
        )

    async def stop(self) -> dict:
        return await self.processes.run("training-ap", lambda: self.helper.call("ap-stop"))

    async def status(self) -> dict:
        status = await self.helper.call("ap-status")
        for secret in ("password", "passphrase", "wpa_passphrase"):
            status.pop(secret, None)
        status.setdefault("gateway", self.config.ap.gateway)
        return status


def excluded_uplink_interfaces(adapters: list[dict], training_interface: str) -> set[str]:
    excluded_roles = {"management", "audit", "training_ap"}
    return {
        str(adapter["interface"])
        for adapter in adapters
        if adapter.get("role") in excluded_roles
    } | {training_interface}
