import pytest

from app.config import AnalysisConfig, AppConfig, StorageConfig
from app.services.capture import CaptureService
from app.services.capture_analysis import CaptureAnalysisService, parse_aircrack_summary, parse_hcx_summary, parse_tshark_rows
from app.services.database import Database
from app.services.process_manager import ProcessManager


def test_tshark_single_pass_parser_counts_frames_and_protocols():
    rows = "\n".join(
        (
            "wlan_radio:wlan\t0x0008\tAA:BB:CC:DD:EE:FF\tAA:BB:CC:DD:EE:FF\tFF:FF:FF:FF:FF:FF\tLab",
            "wlan_radio:wlan:eapol\t0x0020\tAA:BB:CC:DD:EE:FF\t00:11:22:33:44:55\tAA:BB:CC:DD:EE:FF\t",
            "wlan_radio:wlan:llc:ip:udp:bootp\t0x0020\tAA:BB:CC:DD:EE:FF\t00:11:22:33:44:55\tAA:BB:CC:DD:EE:FF\t",
            "wlan_radio:wlan\t0x000c\tAA:BB:CC:DD:EE:FF\tAA:BB:CC:DD:EE:FF\t00:11:22:33:44:55\t",
        )
    )
    result = parse_tshark_rows(rows, 100)
    assert result["packets"] == 4
    assert result["frame_types"] == {"management": 2, "control": 0, "data": 2}
    assert result["management_subtypes"]["beacon"] == 1
    assert result["management_subtypes"]["deauthentication"] == 1
    assert result["protocols"]["eapol"] == 1
    assert result["protocols"]["dhcp"] == 1


def test_hcx_validation_parser_never_returns_hash_material():
    hashes = [
        "WPA*01*secret-pmkid-material",
        "WPA*02*secret-eapol-material",
        "WPA*02*another-secret",
    ]
    result = parse_hcx_summary("", hashes)
    assert result["pmkid_count"] == 1
    assert result["eapol_pair_count"] == 2
    assert result["aircrack_compatible"] is True
    assert "secret" not in str(result)


def test_aircrack_summary_is_metadata_only():
    output = "1  AA:BB:CC:DD:EE:FF  Lab  WPA (1 handshake)\n2 PMKID"
    result = parse_aircrack_summary(output)
    assert result["compatible"] is True
    assert result["bssids"] == ["AA:BB:CC:DD:EE:FF"]
    assert "does not reveal or verify a password" in result["note"]
    assert "hash" not in result


def test_analysis_reuses_capture_safe_path_and_enforces_size(tmp_path):
    capture_path = tmp_path / "capture-1.pcapng"
    capture_path.write_bytes(b"small")
    oversized = tmp_path / "capture-large.pcapng"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    config = AppConfig(
        storage=StorageConfig(scans=tmp_path / "scans", captures=tmp_path, database=tmp_path / "data.db"),
        analysis=AnalysisConfig(max_input_mb=1, max_packets=100, max_result_rows=10),
    )
    database = Database(config.storage.database)
    database.initialize()
    captures = CaptureService(config, None, ProcessManager(), database)  # type: ignore[arg-type]
    analysis = CaptureAnalysisService(config, captures, database, ProcessManager())
    assert analysis.checked_capture(capture_path.name) == capture_path
    with pytest.raises(ValueError):
        analysis.checked_capture("../capture-1.pcapng")
    with pytest.raises(ValueError, match="ANALYSIS_LIMIT"):
        analysis.checked_capture(oversized.name)


def test_frame_explorer_reports_missing_scapy_without_parsing_payload(monkeypatch, tmp_path):
    capture_path = tmp_path / "capture-1.pcapng"
    capture_path.write_bytes(b"not-a-real-pcap")
    config = AppConfig(storage=StorageConfig(captures=tmp_path, database=tmp_path / "data.db"))
    database = Database(config.storage.database)
    database.initialize()
    captures = CaptureService(config, None, ProcessManager(), database)  # type: ignore[arg-type]
    analysis = CaptureAnalysisService(config, captures, database, ProcessManager())
    monkeypatch.setitem(__import__("sys").modules, "scapy", None)
    result = analysis.frame_explorer(capture_path.name)
    assert result["status"] == "TOOL_MISSING"
    assert result["items"] == []
