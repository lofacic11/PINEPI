import json
import runpy
from types import SimpleNamespace

HELPER = runpy.run_path("scripts/pinepi-helper")


def test_reserve_management_interface_disconnects_saved_client_and_sets_unmanaged(monkeypatch):
    calls = []
    globals_ = HELPER["reserve_management_interface"].__globals__
    monkeypatch.setitem(globals_, "shutil", SimpleNamespace(which=lambda name: "/usr/bin/nmcli"))
    monkeypatch.setitem(globals_, "run", lambda argv, **kwargs: calls.append((argv, kwargs)))

    HELPER["reserve_management_interface"]("wlan0")
    HELPER["reserve_management_interface"]("wlan0")

    assert calls == [
        (("/usr/bin/nmcli", "device", "disconnect", "wlan0"), {"check": False}),
        (("/usr/bin/nmcli", "device", "set", "wlan0", "managed", "no"), {"check": False}),
    ] * 2


def test_management_stop_releases_only_owned_interface(monkeypatch):
    globals_ = HELPER["management_stop"].__globals__
    calls = []
    monkeypatch.setitem(globals_, "load_state", lambda name: {"interface": "wlan0", "running": True})
    monkeypatch.setitem(globals_, "cleanup_ap_runtime", lambda state, kind: calls.append((state, kind)))
    monkeypatch.setitem(globals_, "save_state", lambda name, state: calls.append((name, state)))
    monkeypatch.setitem(globals_, "public_ap_state", lambda state, kind: {"running": False})
    monkeypatch.setitem(globals_, "reply", lambda **data: calls.append(data))

    HELPER["management_stop"]()
    assert calls[0] == ({"interface": "wlan0", "running": True}, "management")
    assert calls[1][1]["running"] is False


def test_management_start_retries_interface_and_does_not_select_external_adapter(monkeypatch):
    globals_ = HELPER["wait_for_management_interface"].__globals__
    attempts = iter([HELPER["HelperError"]("not ready"), "wlan0"])
    def detect():
        value = next(attempts)
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setitem(globals_, "detect_management_interface", detect)
    monkeypatch.setitem(globals_, "time", SimpleNamespace(sleep=lambda seconds: None))
    assert HELPER["wait_for_management_interface"]() == "wlan0"


def test_management_state_is_idempotent_when_both_daemons_are_alive(monkeypatch, capsys, tmp_path):
    globals_ = HELPER["management_start"].__globals__
    monkeypatch.setitem(globals_, "RUN_DIR", tmp_path)
    monkeypatch.setitem(globals_, "wait_for_management_interface", lambda: "wlan0")
    monkeypatch.setitem(globals_, "verify_ap_capability", lambda interface: None)
    monkeypatch.setitem(globals_, "reserve_management_interface", lambda interface: None)
    monkeypatch.setitem(globals_, "verify_ap_enabled", lambda interface, ssid: None)
    monkeypatch.setitem(globals_, "load_state", lambda name: {"running": True, "hostapd_pid": 1, "dnsmasq_pid": 2, "interface": "wlan0"})
    monkeypatch.setitem(globals_, "process_alive", lambda pid, expected: True)
    monkeypatch.setitem(globals_, "public_ap_state", lambda state, kind: {"running": True, "interface": "wlan0"})
    monkeypatch.setitem(globals_, "reply", lambda **data: print(json.dumps(data)))
    HELPER["management_start"]()
    assert json.loads(capsys.readouterr().out)["running"] is True


def test_management_status_is_read_only_even_when_daemon_is_stale(monkeypatch, capsys):
    globals_ = HELPER["management_status"].__globals__
    original = {"running": True, "hostapd_pid": 11, "dnsmasq_pid": 12, "interface": "wlan0"}
    calls = []
    monkeypatch.setitem(globals_, "load_state", lambda name: original.copy())
    monkeypatch.setitem(globals_, "process_alive", lambda pid, expected: pid == 11)
    monkeypatch.setitem(globals_, "clients", lambda interface: [])
    monkeypatch.setitem(globals_, "terminate", lambda *args: calls.append("terminate"))
    monkeypatch.setitem(globals_, "cleanup_ap_runtime", lambda *args: calls.append("cleanup"))
    monkeypatch.setitem(globals_, "set_managed", lambda *args: calls.append("managed"))
    monkeypatch.setitem(globals_, "save_state", lambda *args: calls.append("save"))

    HELPER["management_status"]()
    result = json.loads(capsys.readouterr().out)
    assert result["running"] is False
    assert result["healthy"] is False
    assert result["stored_running"] is True
    assert calls == []
    assert original["running"] is True
