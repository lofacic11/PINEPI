import pytest
from unittest.mock import AsyncMock

from app.config import AppConfig
from app.services.management_ap import ManagementAPService
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.training_ap import TrainingAPService, excluded_uplink_interfaces


class FakeHelper:
    async def call(self, action):
        assert action == "management-status"
        return {
            "running": True,
            "interface": "wlan7",
            "password": "must-not-leak",
            "wpa_passphrase": "must-not-leak-either",
        }


class FakeTrainingHelper:
    async def call(self, action):
        assert action == "ap-status"
        return {"running": False, "password": "must-not-leak", "passphrase": "must-not-leak"}


@pytest.mark.asyncio
async def test_management_status_never_returns_password():
    status = await ManagementAPService(AppConfig(), FakeHelper()).status()
    assert status["running"] is True
    assert "password" not in status
    assert "wpa_passphrase" not in status


@pytest.mark.asyncio
async def test_training_status_never_returns_password():
    service = TrainingAPService(AppConfig(), FakeTrainingHelper(), ProcessManager())
    status = await service.status()
    assert "password" not in status
    assert "passphrase" not in status


def test_training_uplink_excludes_all_wifi_roles():
    adapters = [
        {"interface": "wlan7", "role": "management"},
        {"interface": "wlan1", "role": "audit"},
        {"interface": "wlan9", "role": "training_ap"},
        {"interface": "wlan5", "role": "unassigned"},
    ]
    assert excluded_uplink_interfaces(adapters, "wlan9") == {"wlan7", "wlan1", "wlan9"}


@pytest.mark.asyncio
async def test_duplicate_training_start_is_idempotent_for_identical_settings(monkeypatch):
    helper = AsyncMock()
    helper.call.side_effect = lambda action, *args, **kwargs: {
        "ap-status": {"running": True, "ssid": "Lab", "channel": 6},
        "ap-credentials": {"ssid": "Lab", "channel": 6, "password": "safe-lab-password"},
    }[action]
    monkeypatch.setattr("app.services.training_ap.detect_adapters", AsyncMock(return_value=[{"interface": "wlan9", "role": "training_ap"}]))
    service = TrainingAPService(AppConfig(), helper, ProcessManager())
    result = await service.start("Lab", "safe-lab-password", 6)
    assert result["already_running"] is True
    assert all(call.args[0] != "ap-start" for call in helper.call.await_args_list)


@pytest.mark.asyncio
async def test_duplicate_training_start_rejects_different_settings(monkeypatch):
    helper = AsyncMock()
    helper.call.side_effect = lambda action, *args, **kwargs: {
        "ap-status": {"running": True, "ssid": "Lab", "channel": 6},
        "ap-credentials": {"ssid": "Lab", "channel": 6, "password": "safe-lab-password"},
    }[action]
    monkeypatch.setattr("app.services.training_ap.detect_adapters", AsyncMock(return_value=[{"interface": "wlan9", "role": "training_ap"}]))
    service = TrainingAPService(AppConfig(), helper, ProcessManager())
    with pytest.raises(OperationBusy, match="different settings"):
        await service.start("Another Lab", "another-safe-password", 11)


@pytest.mark.asyncio
async def test_live_training_ap_reclaims_adapter_ownership_after_restart():
    helper = AsyncMock()
    helper.call.return_value = {"running": True, "ssid": "Lab", "channel": 6}
    operations = ProcessManager()
    service = TrainingAPService(AppConfig(), helper, operations)
    await service.reconcile()
    with pytest.raises(OperationBusy, match="training_adapter"):
        await operations.acquire("another-training-ap", "training_adapter")


@pytest.mark.asyncio
async def test_stale_training_ap_is_cleaned_up_after_restart():
    class StaleTrainingHelper:
        def __init__(self):
            self.actions = []

        async def call(self, action):
            self.actions.append(action)
            if action == "ap-status":
                return {"running": False, "stored_running": True}
            if action == "ap-stop":
                return {"running": False}
            raise AssertionError(action)

    helper = StaleTrainingHelper()
    await TrainingAPService(AppConfig(), helper, ProcessManager()).reconcile()
    assert helper.actions == ["ap-status", "ap-stop"]
