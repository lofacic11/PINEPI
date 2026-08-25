import pytest

from app.config import AppConfig, StorageConfig
from app.services.capture import CaptureService
from app.services.helper import HelperClient
from app.services.process_manager import ProcessManager


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

