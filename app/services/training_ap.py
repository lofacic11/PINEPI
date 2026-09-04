from __future__ import annotations

import hmac
from contextlib import suppress

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import OperationBusy, ProcessManager


class TrainingAPService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes
        self._operation_id: str | None = None

    async def reconcile(self) -> None:
        """Reclaim ownership when both AP daemons are still validated by the helper."""
        try:
            status = await self.status()
        except Exception:
            return
        if status.get("running"):
            self._operation_id = await self.processes.acquire("training_ap", "training_adapter")
        elif status.get("stored_running"):
            with suppress(Exception):
                await self.helper.call("ap-stop")

    async def start(self, ssid: str, password: str, channel: int) -> dict:
        adapters = await detect_adapters(self.config)
        interface = interface_for_role(adapters, "training_ap")
        current = await self.status()
        if current.get("running"):
            credentials = await self.credentials()
            same_settings = (
                current.get("ssid") == ssid
                and int(current.get("channel", 0)) == channel
                and hmac.compare_digest(str(credentials.get("password", "")), password)
            )
            if same_settings:
                return {**current, "already_running": True}
            raise OperationBusy("Training AP is already running with different settings; stop it before changing settings")
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

    async def credentials(self) -> dict:
        """Return only the currently running PinePi-owned AP credential."""
        result = await self.helper.call("ap-credentials")
        return {
            "ssid": str(result.get("ssid", "")),
            "password": str(result.get("password", "")),
            "channel": result.get("channel"),
            "notice": "Lab AP password — this is not the original network password.",
        }


def excluded_uplink_interfaces(adapters: list[dict], training_interface: str) -> set[str]:
    excluded_roles = {"management", "audit", "training_ap"}
    return {
        str(adapter["interface"])
        for adapter in adapters
        if adapter.get("role") in excluded_roles
    } | {training_interface}
