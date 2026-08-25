from __future__ import annotations

from app.config import AppConfig
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


class TrainingAPService:
    def __init__(self, config: AppConfig, helper: HelperClient, processes: ProcessManager):
        self.config, self.helper, self.processes = config, helper, processes

    async def start(self, ssid: str, password: str, channel: int) -> dict:
        interface = interface_for_role(await detect_adapters(self.config), "training_ap")
        return await self.processes.run(
            "training-ap",
            lambda: self.helper.call(
                "ap-start", interface, str(channel), payload={"ssid": ssid, "password": password}
            ),
        )

    async def stop(self) -> dict:
        return await self.processes.run("training-ap", lambda: self.helper.call("ap-stop"))

    async def status(self) -> dict:
        status = await self.helper.call("ap-status")
        status.setdefault("gateway", self.config.ap.gateway)
        return status
