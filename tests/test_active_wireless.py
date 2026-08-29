import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import httpx
from pydantic import ValidationError

from app.config import ActiveTestConfig, AppConfig, ReconConfig
from app.models import DeauthTestRequest, InjectionTestRequest, Mdk4DeauthTestRequest
from app.services.active_wireless import ActiveWirelessService
from app.services.process_manager import OperationBusy, ProcessManager
from app.main import app


TARGET = {"ssid": "Authorized Lab", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6}


def test_deauthentication_requires_authorization_and_valid_target_fields():
    with pytest.raises(ValidationError):
        DeauthTestRequest(ssid="Lab", bssid=TARGET["bssid"], channel=6, authorized=False)
    with pytest.raises(ValidationError):
        DeauthTestRequest(ssid="Lab", bssid="not-a-mac", channel=6, authorized=True)
    with pytest.raises(ValidationError):
        DeauthTestRequest(ssid="Lab", bssid=TARGET["bssid"], channel=6, authorized=True, bursts=129)
    with pytest.raises(ValidationError):
        DeauthTestRequest(ssid="Lab\nInjected", bssid=TARGET["bssid"], channel=6, authorized=True)


@pytest.mark.asyncio
async def test_deauthentication_requires_current_selected_target(monkeypatch):
    monkeypatch.setattr(
        "app.services.active_wireless.detect_adapters",
        AsyncMock(return_value=[{"interface": "wlan9", "role": "audit"}]),
    )
    service = ActiveWirelessService(AppConfig(), AsyncMock(), ProcessManager())
    body = DeauthTestRequest(**TARGET, authorized=True)
    with pytest.raises(ValueError, match="NO_TARGET"):
        await service.start_deauth(body, None)
    with pytest.raises(ValueError, match="TARGET_MISMATCH"):
        await service.start_deauth(body, {**TARGET, "channel": 11})


@pytest.mark.asyncio
async def test_bounded_mock_deauthentication_owns_adapter_and_can_stop(monkeypatch):
    monkeypatch.setattr(
        "app.services.active_wireless.detect_adapters",
        AsyncMock(return_value=[{"interface": "wlan9", "role": "audit"}]),
    )
    config = AppConfig(
        recon=ReconConfig(mock_mode=True),
        active_tests=ActiveTestConfig(max_runtime_seconds=20, max_deauth_bursts=10),
    )
    operations = ProcessManager()
    service = ActiveWirelessService(config, AsyncMock(), operations)
    body = DeauthTestRequest(**TARGET, authorized=True, bursts=10, runtime_seconds=20)
    result = await service.start_deauth(body, TARGET)
    assert result["running"] is True and result["simulated"] is True
    with pytest.raises(OperationBusy, match="audit_adapter"):
        await operations.acquire("PACKET_CAPTURE", "audit_adapter")
    stopped = await service.stop()
    assert stopped["running"] is False
    await operations.acquire("PACKET_CAPTURE", "audit_adapter")


@pytest.mark.asyncio
async def test_configured_bounds_are_enforced_before_helper(monkeypatch):
    monkeypatch.setattr(
        "app.services.active_wireless.detect_adapters",
        AsyncMock(return_value=[{"interface": "wlan9", "role": "audit"}]),
    )
    service = ActiveWirelessService(
        AppConfig(active_tests=ActiveTestConfig(max_runtime_seconds=5, max_deauth_bursts=4)),
        AsyncMock(),
        ProcessManager(),
    )
    with pytest.raises(ValueError, match="burst count"):
        await service.start_deauth(DeauthTestRequest(**TARGET, authorized=True, bursts=5), TARGET)


def test_injection_request_requires_authorization():
    with pytest.raises(ValidationError):
        InjectionTestRequest(**TARGET, authorized=False)


def test_mdk4_request_is_targeted_authorized_and_bounded():
    request = Mdk4DeauthTestRequest(**TARGET, authorized=True, runtime_seconds=10)
    assert request.bssid == TARGET["bssid"]
    with pytest.raises(ValidationError):
        Mdk4DeauthTestRequest(**TARGET, authorized=True, runtime_seconds=61)


def test_helper_constructs_fixed_deauthentication_arguments(monkeypatch, capsys):
    import runpy

    helper = runpy.run_path("scripts/pinepi-helper")
    globals_ = helper["active_start"].__globals__
    commands, saved = [], []
    monkeypatch.setitem(globals_, "validate_interface", lambda value: value)
    monkeypatch.setitem(globals_, "ensure_wireless_operation_idle", lambda: None)
    monkeypatch.setitem(globals_, "load_state", lambda name: {})
    monkeypatch.setitem(globals_, "set_monitor", lambda interface, channel: None)
    monkeypatch.setitem(globals_, "set_managed", lambda interface: None)
    monkeypatch.setitem(globals_, "executable", lambda name: f"/usr/bin/{name}")

    def active_process(argv, _path):
        commands.append(argv)
        return SimpleNamespace(pid=42, poll=lambda: None)

    monkeypatch.setitem(globals_, "_active_process", active_process)
    monkeypatch.setitem(globals_, "save_state", lambda name, state: saved.append((name, state.copy())))
    helper["active_start"]("deauth", "wlan9", "6", TARGET["bssid"], "-", "8", "15")
    result = json.loads(capsys.readouterr().out)
    assert commands[0] == [
        "/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "15s", "/usr/bin/aireplay-ng",
        "--deauth", "8", "-a", TARGET["bssid"], "wlan9",
    ]
    assert result["running"] is True
    assert saved[-1][1]["bssid"] == TARGET["bssid"]


@pytest.mark.parametrize("value", ["--help", "AA:BB:CC:DD:EE:FF;id", "../target"])
def test_helper_rejects_arbitrary_bssid_arguments(monkeypatch, value):
    import runpy

    helper = runpy.run_path("scripts/pinepi-helper")
    monkeypatch.setitem(helper["active_start"].__globals__, "validate_interface", lambda item: item)
    with pytest.raises(helper["HelperError"], match="Invalid target BSSID"):
        helper["active_start"]("deauth", "wlan9", "6", value, "-", "8", "15")


def test_unexpected_active_process_exit_restores_adapter(monkeypatch, capsys):
    import runpy

    helper = runpy.run_path("scripts/pinepi-helper")
    globals_ = helper["active_status"].__globals__
    state = {
        "running": True, "pid": 42, "executable": "aireplay-ng", "interface": "wlan9",
        "started_at": 1, "deadline": 99999999999,
    }
    managed, saved = [], []
    monkeypatch.setitem(globals_, "load_state", lambda name: state.copy())
    monkeypatch.setitem(globals_, "process_alive", lambda *args: False)
    monkeypatch.setitem(globals_, "set_managed", lambda interface: managed.append(interface))
    monkeypatch.setitem(globals_, "save_state", lambda name, value: saved.append(value.copy()))
    monkeypatch.setitem(globals_, "recent_log", lambda path: "bounded failure reason")
    helper["active_status"]()
    assert managed == ["wlan9"]
    assert saved[-1]["running"] is False
    assert saved[-1]["interface_restored"] is True
    capsys.readouterr()


def test_monitor_lifecycle_uses_native_iw_state_and_is_idempotent(monkeypatch, capsys):
    import runpy

    helper = runpy.run_path("scripts/pinepi-helper")
    globals_ = helper["monitor_enable"].__globals__
    state, calls = {}, []
    monkeypatch.setitem(globals_, "validate_interface", lambda value: value)
    monkeypatch.setitem(globals_, "ensure_wireless_operation_idle", lambda: None)
    monkeypatch.setitem(globals_, "load_state", lambda name: state.copy() if name == "monitor" else {})
    monkeypatch.setitem(globals_, "save_state", lambda name, value: state.update(value))
    monkeypatch.setitem(globals_, "set_monitor", lambda interface, channel: calls.append(("monitor", interface, channel)))
    monkeypatch.setitem(globals_, "set_managed", lambda interface: calls.append(("managed", interface)))
    helper["monitor_enable"]("wlan9", "6")
    helper["monitor_enable"]("wlan9", "6")
    helper["monitor_disable"]()
    assert calls.count(("monitor", "wlan9", 6)) == 1
    assert ("managed", "wlan9") in calls
    assert state["running"] is False
    capsys.readouterr()


def test_airmon_conflict_check_never_kills_processes(monkeypatch, capsys):
    import runpy

    helper = runpy.run_path("scripts/pinepi-helper")
    globals_ = helper["monitor_conflicts"].__globals__
    commands = []
    monkeypatch.setitem(globals_, "executable", lambda name: f"/usr/bin/{name}")
    monkeypatch.setitem(
        globals_,
        "run",
        lambda argv, **kwargs: commands.append(argv) or SimpleNamespace(stdout="PID Name\n123 NetworkManager", stderr="", returncode=0),
    )
    helper["monitor_conflicts"]()
    result = json.loads(capsys.readouterr().out)
    assert commands == [["/usr/bin/airmon-ng", "check"]]
    assert result["action_taken"] is False


@pytest.mark.asyncio
async def test_active_api_requires_management_peer_and_confirmation_header():
    class SelectedState:
        async def target(self):
            return TARGET

    class FakeActive:
        async def start_deauth(self, body, selected):
            return {"started": True, "bssid": body.bssid, "selected": selected["bssid"]}

    app.state.config = AppConfig()
    app.state.app_state = SelectedState()
    app.state.active_wireless = FakeActive()
    body = {**TARGET, "authorized": True, "bursts": 2, "runtime_seconds": 5}
    denied = httpx.ASGITransport(app=app, client=("10.42.0.20", 1234))
    allowed = httpx.ASGITransport(app=app, client=("10.43.0.20", 1234))
    async with httpx.AsyncClient(transport=denied, base_url="http://pinepi") as client:
        response = await client.post(
            "/api/wireless-tools/active/deauthentication",
            json=body,
            headers={"X-PinePi-Action": "confirmed", "X-Forwarded-For": "10.43.0.20"},
        )
        assert response.status_code == 403
    async with httpx.AsyncClient(transport=allowed, base_url="http://pinepi") as client:
        assert (await client.post("/api/wireless-tools/active/deauthentication", json=body)).status_code == 403
        response = await client.post(
            "/api/wireless-tools/active/deauthentication", json=body, headers={"X-PinePi-Action": "confirmed"}
        )
        assert response.status_code == 201
