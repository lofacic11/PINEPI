import json

from app.services.offline_engines import bounded_json_lines, normalize_suricata, normalize_zeek


def test_bounded_json_log_parser_rejects_non_json_and_stops(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text('{"event_type":"alert","alert":{"signature":"one"}}\ninvalid\n{"event_type":"alert","alert":{"signature":"two"}}\n')
    rows, truncated = bounded_json_lines(path, 1)
    assert len(rows) == 1
    assert truncated is True
    assert bounded_json_lines(tmp_path / "missing", 10) == ([], False)


def test_suricata_normalization_whitelists_bounded_alert_fields():
    events = [{
        "event_type": "alert",
        "timestamp": "now",
        "src_ip": "10.0.0.2",
        "dest_ip": "10.0.0.3",
        "payload": "must-not-be-exposed",
        "alert": {"severity": 2, "signature": "Test alert", "category": "Lab"},
    }]
    result = normalize_suricata(events, 10)
    assert result[0]["signature"] == "Test alert"
    assert "payload" not in json.dumps(result)


def test_zeek_normalization_uses_known_views_and_fields_only():
    result = normalize_zeek({"dns": [{"query": "example.test", "answers": ["10.0.0.1"], "secret": "omit"}], "unknown": [{"x": 1}]}, 10)
    assert result["dns"][0]["query"] == "example.test"
    assert "secret" not in result["dns"][0]
    assert "unknown" not in result
