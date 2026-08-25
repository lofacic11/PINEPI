import pytest

from app.config import AppConfig, ReconConfig, StorageConfig
from app.services.database import Database, SCHEMA_VERSION
from app.services.mock_data import MOCK_APS, MOCK_CLIENTS
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.recon import ReconService
from app.services.recon_parser import normalize_mac, parse_airodump
from app.services.vendor import VendorLookup


class NoHelper:
    async def call(self, *_args):
        raise AssertionError("mock Recon must not invoke the root helper")


def service(tmp_path, *, scenario="normal", samples=3):
    config = AppConfig(
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"),
        recon=ReconConfig(mock_mode=True, mock_scenario=scenario, max_signal_samples_per_ap=samples),
    )
    database = Database(config.storage.database)
    database.initialize()
    operations = ProcessManager(database)
    return ReconService(config, NoHelper(), database, operations), database, operations


def test_database_schema_and_parser_tolerate_malformed_rows(tmp_path):
    database = Database(tmp_path / "data" / "pinepi.db")
    database.initialize()
    assert database.one("SELECT version FROM schema_meta")["version"] == SCHEMA_VERSION
    scan = tmp_path / "scan.csv"
    scan.write_text(
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "bad,row\n"
        "aa:bb:cc:dd:ee:ff, now, later, 6, 54, WPA2, CCMP, PSK, -45, 10, 2, 0, 4, <img src=x onerror=1>\\x01,\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "02:00:00:00:00:01, now, later, -60, 3, (not associated), Cafe\n"
    )
    aps, clients = parse_airodump(scan, VendorLookup((tmp_path / "absent",)))
    assert len(aps) == 1 and aps[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert len(aps[0]["ssid"]) <= 32
    assert clients[0]["relationship"] == "unassociated"
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"


@pytest.mark.asyncio
async def test_mock_session_persistence_filters_relationships_and_idempotent_stop(tmp_path):
    recon, database, _ = service(tmp_path)
    session = await recon.start()
    assert session["status"] == "running"
    assert session["ap_count"] == len(MOCK_APS)
    assert database.one("SELECT COUNT(*) n FROM clients")["n"] == len(MOCK_CLIENTS)
    assert recon.access_points(session["id"], security="Open")["total"] == 2
    assert recon.access_points(session["id"], hidden=True)["total"] == 1
    assert recon.access_points(session["id"], pmf="enabled")["total"] == 1
    assert recon.access_points(session["id"], has_clients=True)["total"] == 1
    assert recon.access_points(session["id"], search="PinePi")["total"] == 2
    detail = recon.client("02:aa:bb:cc:dd:ee", session["id"])
    assert detail["relationship"] == "associated"
    first = await recon.stop(session["id"])
    second = await recon.stop(session["id"])
    assert first["status"] == second["status"] == "completed"


@pytest.mark.asyncio
async def test_operation_conflict_and_restart_recovery(tmp_path):
    recon, database, operations = service(tmp_path)
    session = await recon.start()
    with pytest.raises(OperationBusy):
        await operations.acquire("capture", "audit_adapter")
    replacement = ProcessManager(database)
    replacement.recover()
    assert database.one("SELECT status FROM operations WHERE id=?", (session["operation_id"],))["status"] == "interrupted"
    restarted = ReconService(recon.config, NoHelper(), database, replacement)
    await restarted.reconcile()
    assert restarted.session(session["id"])["status"] == "interrupted"


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario,count", [("empty", 0)])
async def test_mock_empty_scenario(tmp_path, scenario, count):
    recon, _, _ = service(tmp_path, scenario=scenario)
    session = await recon.start()
    assert session["ap_count"] == count


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario,message", [("failure", "monitor mode"), ("missing_adapter", "adapter is missing")])
async def test_mock_failure_scenarios_are_explicit(tmp_path, scenario, message):
    recon, database, _ = service(tmp_path, scenario=scenario)
    with pytest.raises(RuntimeError, match=message):
        await recon.start()
    assert database.one("SELECT status FROM scan_sessions")["status"] == "failed"


def test_trusted_indicators_are_cautious_and_channel_view_is_bounded(tmp_path):
    recon, database, _ = service(tmp_path)
    database.execute("INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface) VALUES('s','now','completed','a','m')")
    recon._ingest("s", MOCK_APS, MOCK_CLIENTS)
    recon.add_trusted("PinePi Lab", ["00:11:22:33:44:55"], "WPA3", [1], "Example Networks")
    rogue = recon.access_point("30:44:55:66:77:88", "s")
    text = " ".join(item["message"] for item in rogue["indicators"])
    assert "requires investigation" in text
    assert "not proof" in text.lower()
    assert any(item["type"] == "channel_change" for item in rogue["indicators"])
    assert any("recommended_for_owned_ap" in row for row in recon.channels("s"))


def test_vendor_lookup_known_unknown_randomized_and_missing(tmp_path):
    oui = tmp_path / "oui.txt"
    oui.write_text("00-11-22   (hex)        Example Networks\n")
    lookup = VendorLookup((oui,))
    assert lookup.lookup("00:11:22:AA:BB:CC") == "Example Networks"
    assert lookup.lookup("00:FF:FF:AA:BB:CC") == "Unknown"
    assert lookup.lookup("02:11:22:AA:BB:CC") == "Randomized/local address"
    assert VendorLookup((tmp_path / "missing",)).lookup("00:11:22:AA:BB:CC") == "Unknown"


def test_invalid_sort_and_signal_sample_retention(tmp_path):
    recon, database, _ = service(tmp_path, samples=2)
    database.execute("INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface) VALUES('s','now','running','a','m')")
    for _ in range(4):
        recon._ingest("s", MOCK_APS[:1], [])
    assert database.one("SELECT COUNT(*) n FROM signal_samples")["n"] == 2
    with pytest.raises(ValueError, match="sort"):
        recon.access_points("s", sort="signal; DROP TABLE access_points")
