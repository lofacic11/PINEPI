from __future__ import annotations

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


class TrainingAPService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes
        self._operation_id: str | None = None

    async def start(self, ssid: str, password: str, channel: int) -> dict:
        adapters = await detect_adapters(self.config)
        interface = interface_for_role(adapters, "training_ap")
        excluded = excluded_uplink_interfaces(adapters, interface)
        async def operation() -> dict:
            operation_id = await self.processes.acquire("training_ap", "training_adapter")
            try:
                result = await self.helper.call(
                "ap-start", interface, str(channel), ",".join(sorted(excluded)),
                payload={"ssid": ssid, "password": password},
                )
                self._operation_id = operation_id
                self.processes.attach_pid(operation_id, result.get("hostapd_pid"))
                return result
            except Exception as exc:
                self.processes.finish(operation_id, "failed", str(exc))
                raise
        return await self.processes.run("training-ap-start", operation)

    async def stop(self) -> dict:
        async def operation() -> dict:
            result = await self.helper.call("ap-stop")
            if self._operation_id:
                self.processes.finish(self._operation_id)
                self._operation_id = None
            return result
        return await self.processes.run("training-ap-stop", operation)

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
