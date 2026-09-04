import pytest
from unittest.mock import AsyncMock

from app.config import AppConfig, ReconConfig, StorageConfig
from app.services.database import Database, SCHEMA_VERSION
from app.services.mock_data import MOCK_APS, MOCK_CLIENTS
from app.services.process_manager import OperationBusy, ProcessManager
from app.services.recon import ReconService
from app.services.recon_parser import normalize_mac, parse_airodump, safe_wireless_text
from app.services.vendor import VendorLookup


class NoHelper:
    async def call(self, *_args):
        raise AssertionError("mock Recon must not invoke the root helper")


class StartedThenDatabaseFailureHelper:
    def __init__(self):
        self.actions = []

    async def call(self, action, *_args, **_kwargs):
        self.actions.append(action)
        if action == "scan-start":
            return {"running": True, "pid": 123, "interface": "wlan2"}
        if action == "scan-stop":
            return {"running": False}
        raise AssertionError(action)


class UnexpectedExitHelper:
    def __init__(self):
        self.actions = []

    async def call(self, action, *_args, **_kwargs):
        self.actions.append(action)
        if action == "scan-status":
            return {"running": False, "stored_running": True, "healthy": False, "pid": 123, "interface": "wlan2"}
        if action == "scan-stop":
            return {"running": False}
        raise AssertionError(action)


def service(tmp_path, *, scenario="normal", samples=3):
    config = AppConfig(
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"),
        recon=ReconConfig(mock_mode=True, mock_scenario=scenario, max_signal_samples_per_ap=samples),
    )
    database = Database(config.storage.database)
    database.initialize()
    operations = ProcessManager(database)
    return ReconService(config, NoHelper(), database, operations), database, operations


@pytest.mark.asyncio
async def test_real_start_rolls_back_helper_when_session_update_fails(tmp_path, monkeypatch):
    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"))
    database = Database(config.storage.database)
    database.initialize()
    operations = ProcessManager(database)
    helper = StartedThenDatabaseFailureHelper()
    recon = ReconService(config, helper, database, operations)
    monkeypatch.setattr("app.services.recon.detect_adapters", AsyncMock(return_value=[{"interface": "wlan2", "role": "audit"}]))

    original_execute = database.execute

    def fail_running_update(sql, parameters=()):
        if sql.startswith("UPDATE scan_sessions SET status='running'"):
            raise RuntimeError("database update failed")
        return original_execute(sql, parameters)

    monkeypatch.setattr(database, "execute", fail_running_update)
    with pytest.raises(RuntimeError, match="database update failed"):
        await recon.start()
    assert helper.actions == ["scan-start", "scan-stop"]
    assert operations.owner("audit_adapter") is None


@pytest.mark.asyncio
async def test_live_status_does_not_mutate_dead_session_and_stop_remains_available(tmp_path):
    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"))
    database = Database(config.storage.database)
    database.initialize()
    database.execute(
        "INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface,operation_id) VALUES(?,?,?,?,?,?)",
        ("dead", "2026-01-01T00:00:00+00:00", "running", "wlan2", "wlan2", "operation"),
    )
    helper = UnexpectedExitHelper()
    recon = ReconService(config, helper, database, ProcessManager(database))

    live = await recon.live_status()

    assert live["running"] is False
    assert live["healthy"] is False
    assert live["session"]["status"] == "running"
    assert database.one("SELECT status FROM scan_sessions WHERE id='dead'")["status"] == "running"
    assert helper.actions == ["scan-status"]


@pytest.mark.asyncio
async def test_reconcile_restores_adapter_after_scanner_exit(tmp_path):
    config = AppConfig(storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path / "captures", database=tmp_path / "pinepi.db"))
    database = Database(config.storage.database)
    database.initialize()
    database.execute(
        "INSERT INTO scan_sessions(id,started_at,status,audit_interface,monitor_interface,operation_id) VALUES(?,?,?,?,?,?)",
        ("stale", "2026-01-01T00:00:00+00:00", "running", "wlan2", "wlan2", "operation"),
    )
    helper = UnexpectedExitHelper()
    recon = ReconService(config, helper, database, ProcessManager(database))

    await recon.reconcile()

    assert helper.actions == ["scan-status", "scan-stop"]
    assert database.one("SELECT status FROM scan_sessions WHERE id='stale'")["status"] == "interrupted"


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


@pytest.mark.parametrize(
    "value",
    [
        "<script>alert(1)</script>",
        'quotes " and \' plus \\\\',
        "line\nbreak",
        "Café 📡 network",
        "x" * 500,
        "📡" * 40,
    ],
)
def test_hostile_wireless_text_is_control_free_and_utf8_bounded(value):
    result = safe_wireless_text(value, 32)
    assert len(result.encode("utf-8")) <= 32
    assert "\n" not in result


@pytest.mark.asyncio
async def test_mock_session_persistence_filters_relationships_and_idempotent_stop(tmp_path):
    recon, database, _ = service(tmp_path)
    session = await recon.start()
    assert session["status"] == "running"
    assert session["ap_count"] == len(MOCK_APS)
    assert session["associated_client_count"] + session["other_client_count"] == len(MOCK_CLIENTS)
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
