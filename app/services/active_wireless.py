from __future__ import annotations

import time

from app.config import AppConfig
from app.models import DeauthTestRequest, InjectionTestRequest, Mdk4DeauthTestRequest
from app.services.adapter_detection import detect_adapters, interface_for_role
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


class ActiveWirelessService:
    """Typed orchestration for deliberately targeted, bounded wireless tests."""

    def __init__(self, config: AppConfig, helper: HelperClient, operations: ProcessManager):
        self.config = config
        self.helper = helper
        self.operations = operations
        self._operation_id: str | None = None
        self._monitor_operation_id: str | None = None
        self._mock_state: dict = {"running": False, "type": "", "elapsed_seconds": 0}
        self._mock_monitor: dict = {"running": False}

    @staticmethod
    def require_selected_target(selected: dict | None, bssid: str, channel: int) -> None:
        if not selected:
            raise ValueError("NO_TARGET: select an access point in Recon before starting an active test")
        if str(selected.get("bssid", "")).upper() != bssid.upper() or int(selected.get("channel", 0)) != channel:
            raise ValueError("TARGET_MISMATCH: the confirmed BSSID/channel no longer matches the selected Recon target")

    async def start_deauth(self, request: DeauthTestRequest, selected: dict | None) -> dict:
        self.require_selected_target(selected, request.bssid, request.channel)
        if request.bursts > self.config.active_tests.max_deauth_bursts:
            raise ValueError("ACTIVE_LIMIT: burst count exceeds the configured PinePi limit")
        if request.runtime_seconds > self.config.active_tests.max_runtime_seconds:
            raise ValueError("ACTIVE_LIMIT: runtime exceeds the configured PinePi limit")
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        target = {
            "ssid": request.ssid,
            "bssid": request.bssid,
            "client": request.client or "",
            "channel": request.channel,
        }
        operation_id = await self.operations.acquire(
            "DEAUTH_TEST",
            "audit_adapter",
            request.runtime_seconds,
            adapter=interface,
            target=target,
        )
        try:
            if self.config.recon.mock_mode:
                result = {
                    "running": True,
                    "type": "DEAUTH_TEST",
                    "interface": interface,
                    **target,
                    "bursts": request.bursts,
                    "runtime_seconds": request.runtime_seconds,
                    "started_at": time.time(),
                    "simulated": True,
                }
                self._mock_state = result
            else:
                result = await self.helper.call(
                    "active-start",
                    "deauth",
                    interface,
                    str(request.channel),
                    request.bssid,
                    request.client or "-",
                    str(request.bursts),
                    str(request.runtime_seconds),
                )
            result.update(target=target, operation_id=operation_id, classification="ACTIVE")
            if result.get("running"):
                self._operation_id = operation_id
                self.operations.attach_pid(operation_id, result.get("pid"))
            else:
                self.operations.finish(operation_id, exit_code=result.get("exit_code"))
            return result
        except Exception as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def injection_test(self, request: InjectionTestRequest, selected: dict | None) -> dict:
        self.require_selected_target(selected, request.bssid, request.channel)
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        operation_id = await self.operations.acquire(
            "INJECTION_TEST",
            "audit_adapter",
            min(30, self.config.active_tests.max_runtime_seconds),
            adapter=interface,
            target={"ssid": request.ssid, "bssid": request.bssid, "channel": request.channel},
        )
        try:
            if self.config.recon.mock_mode:
                result = {
                    "supported": self.config.recon.mock_scenario != "failure",
                    "status": "INJECTION_SUPPORTED" if self.config.recon.mock_scenario != "failure" else "INJECTION_UNSUPPORTED",
                    "explanation": "Simulated injection diagnostic result",
                    "simulated": True,
                }
            else:
                result = await self.helper.call("injection-test", interface, str(request.channel), request.bssid, timeout=35)
            self.operations.finish(operation_id, "completed", exit_code=result.get("exit_code"))
            return {**result, "operation_id": operation_id, "classification": "ACTIVE", "interface": interface}
        except Exception as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def start_mdk4(self, request: Mdk4DeauthTestRequest, selected: dict | None) -> dict:
        self.require_selected_target(selected, request.bssid, request.channel)
        if request.runtime_seconds > self.config.active_tests.max_runtime_seconds:
            raise ValueError("ACTIVE_LIMIT: runtime exceeds the configured PinePi limit")
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        target = {"ssid": request.ssid, "bssid": request.bssid, "channel": request.channel}
        operation_id = await self.operations.acquire(
            "MDK4_TEST",
            "audit_adapter",
            request.runtime_seconds,
            adapter=interface,
            target=target,
        )
        try:
            if self.config.recon.mock_mode:
                result = {
                    "running": True,
                    "type": "MDK4_TEST",
                    "interface": interface,
                    **target,
                    "runtime_seconds": request.runtime_seconds,
                    "started_at": time.time(),
                    "simulated": True,
                }
                self._mock_state = result
            else:
                result = await self.helper.call(
                    "active-start",
                    "mdk4_deauth",
                    interface,
                    str(request.channel),
                    request.bssid,
                    "-",
                    "1",
                    str(request.runtime_seconds),
                )
            result.update(target=target, operation_id=operation_id, classification="ACTIVE")
            if result.get("running"):
                self._operation_id = operation_id
                self.operations.attach_pid(operation_id, result.get("pid"))
            else:
                self.operations.finish(operation_id, exit_code=result.get("exit_code"))
            return result
        except Exception as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def status(self) -> dict:
        if self.config.recon.mock_mode:
            state = self._mock_state.copy()
            if state.get("running"):
                elapsed = max(0, int(time.time() - float(state.get("started_at", time.time()))))
                state["elapsed_seconds"] = elapsed
                if elapsed >= int(state.get("runtime_seconds", 1)):
                    state.update(running=False, stop_reason="simulated runtime limit reached")
            result = state
        else:
            result = await self.helper.call("active-status")
        if not result.get("running") and self._operation_id:
            self.operations.finish(
                self._operation_id,
                "completed" if not result.get("last_error") else "failed",
                str(result.get("last_error", "")),
                result.get("exit_code"),
            )
            self._operation_id = None
        result["classification"] = "ACTIVE"
        return result

    async def stop(self) -> dict:
        if self.config.recon.mock_mode:
            self._mock_state.update(running=False, stopped_at=time.time(), stop_reason="stopped by user")
            result = self._mock_state.copy()
        else:
            result = await self.helper.call("active-stop")
        if self._operation_id:
            self.operations.finish(self._operation_id)
            self._operation_id = None
        return result

    async def monitor_enable(self, channel: int | None = None) -> dict:
        interface = interface_for_role(await detect_adapters(self.config), "audit")
        operation_id = await self.operations.acquire("MONITOR_MODE", "audit_adapter", adapter=interface)
        try:
            if self.config.recon.mock_mode:
                result = {"running": True, "interface": interface, "channel": channel, "simulated": True}
                self._mock_monitor = result
            else:
                result = await self.helper.call("monitor-enable", interface, str(channel) if channel else "")
            self._monitor_operation_id = operation_id
            return {**result, "operation_id": operation_id}
        except Exception as exc:
            self.operations.finish(operation_id, "failed", str(exc))
            raise

    async def monitor_disable(self) -> dict:
        if self.config.recon.mock_mode:
            self._mock_monitor.update(running=False, simulated=True)
            result = self._mock_monitor.copy()
        else:
            result = await self.helper.call("monitor-disable")
        if self._monitor_operation_id:
            self.operations.finish(self._monitor_operation_id)
            self._monitor_operation_id = None
        return result

    async def monitor_status(self) -> dict:
        return self._mock_monitor.copy() if self.config.recon.mock_mode else await self.helper.call("monitor-status")

    async def monitor_conflicts(self) -> dict:
        if self.config.recon.mock_mode:
            return {"available": True, "lines": ["SIMULATED: no conflicting processes"], "conflicts_detected": False, "action_taken": False, "note": "Simulated conflict check"}
        return await self.helper.call("monitor-conflicts")

    async def reconcile(self) -> None:
        if self.config.recon.mock_mode:
            return
        try:
            active = await self.helper.call("active-status")
            monitor = await self.helper.call("monitor-status")
        except Exception:
            return
        if active.get("running"):
            self._operation_id = await self.operations.acquire(
                "DEAUTH_TEST",
                "audit_adapter",
                int(active.get("runtime_seconds", self.config.active_tests.max_runtime_seconds)),
                adapter=str(active.get("interface", "")),
                target={key: active.get(key) for key in ("bssid", "client", "channel")},
            )
            self.operations.attach_pid(self._operation_id, active.get("pid"))
        elif monitor.get("running"):
            self._monitor_operation_id = await self.operations.acquire(
                "MONITOR_MODE", "audit_adapter", adapter=str(monitor.get("interface", ""))
            )
