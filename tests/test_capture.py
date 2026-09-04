import pytest

from app.config import AppConfig, StorageConfig
from app.services.capture import CaptureService
from app.services.helper import HelperClient
from app.services.process_manager import OperationBusy, ProcessManager


def service(tmp_path):
    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path, max_capture_mb=500))
    return CaptureService(config, HelperClient(config), ProcessManager())


def test_safe_capture_resolution(tmp_path):
    path = tmp_path / "capture-1.pcapng"
    path.write_bytes(b"test")
    assert service(tmp_path).resolve(path.name) == path


@pytest.mark.parametrize("name", ["../secret.pcapng", "capture.pcap", "/tmp/x.pcapng", "x pcapng"])
def test_unsafe_capture_names_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        service(tmp_path).resolve(name)


@pytest.mark.asyncio
async def test_live_capture_reclaims_adapter_ownership_after_restart(tmp_path):
    class RunningCaptureHelper:
        async def call(self, action, **_kwargs):
            assert action == "capture-status"
            return {"running": True, "pid": 321}

    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path))
    operations = ProcessManager()
    capture = CaptureService(config, RunningCaptureHelper(), operations)
    await capture.reconcile()
    with pytest.raises(OperationBusy, match="audit_adapter"):
        await operations.acquire("recon", "audit_adapter")


@pytest.mark.asyncio
async def test_stale_capture_is_cleaned_up_after_restart(tmp_path):
    class StaleCaptureHelper:
        def __init__(self):
            self.actions = []

        async def call(self, action, **_kwargs):
            self.actions.append(action)
            if action == "capture-status":
                return {"running": False, "stored_running": True}
            if action == "capture-stop":
                return {"running": False}
            raise AssertionError(action)

    helper = StaleCaptureHelper()
    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path))
    await CaptureService(config, helper, ProcessManager()).reconcile()
    assert helper.actions == ["capture-status", "capture-stop"]
