import pytest

from app.config import AppConfig
from app.services.management_ap import ManagementAPService
from app.services.process_manager import ProcessManager
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
