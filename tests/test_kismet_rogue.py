from app.config import AppConfig, ReconConfig, StorageConfig
from app.services.database import Database
from app.services.kismet import normalize_kismet_devices
from app.services.mock_data import MOCK_APS, MOCK_CLIENTS
from app.services.process_manager import ProcessManager
from app.services.recon import ReconService
from app.services.rogue_detection import RogueDetectionService


class NoHelper:
    async def call(self, *_args):
        raise AssertionError("mock Recon must not invoke the helper")


def test_kismet_normalization_is_bounded_and_separates_aps_clients():
    devices = [
        {
            "kismet.device.base": {
                "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:ff",
                "kismet.device.base.type": "Wi-Fi AP",
                "kismet.device.base.name": "Lab <script>",
                "kismet.device.base.channel": "6",
                "kismet.device.base.manuf": "Example",
                "kismet.device.base.signal": {"kismet.common.signal.last_signal": -41},
            }
        },
        {"macaddr": "00:11:22:33:44:55", "type": "Wi-Fi Client", "signal": -60},
        {"macaddr": "invalid", "type": "Wi-Fi AP"},
    ]
    aps, clients = normalize_kismet_devices(devices)
    assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert aps[0]["ssid"] == "Lab <script>"
    assert clients[0]["station_mac"] == "00:11:22:33:44:55"
    assert len(aps) == len(clients) == 1


def test_rogue_detection_is_weighted_explainable_and_cautious(tmp_path):
    config = AppConfig(
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"),
        recon=ReconConfig(mock_mode=True),
    )
    database = Database(config.storage.database)
    database.initialize()
    recon = ReconService(config, NoHelper(), database, ProcessManager(database))
    database.execute("INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface) VALUES('s','now','completed','a','m')")
    altered = [dict(MOCK_APS[0], security="Open", privacy="OPN", vendor="Unexpected Vendor", channel=11)]
    recon._ingest("s", altered, MOCK_CLIENTS[:1])
    recon.add_trusted("PinePi Lab", ["00:11:22:33:44:55"], "WPA3", [1], "Example Networks")
    result = RogueDetectionService(database).analyze("s")
    assert result["items"][0]["risk"] == "HIGH"
    assert result["items"][0]["classification"] == "Potential anomaly"
    assert "not proof" in result["items"][0]["disclaimer"]
    assert sum(reason["weight"] for reason in result["items"][0]["reasons"]) >= 60
