import json
import runpy
import sys
from io import StringIO
from types import SimpleNamespace

import pytest


HELPER = runpy.run_path("scripts/pinepi-helper")


def test_default_uplink_excludes_ap_and_audit_interfaces():
    routes = "default via 10.43.0.1 dev wlan0 metric 100\ndefault via 192.168.1.1 dev eth0 metric 200\n"
    assert HELPER["select_default_uplink"](routes, {"wlan0", "wlan1", "wlan2"}) == "eth0"
    assert HELPER["select_default_uplink"](routes, {"wlan0", "eth0"}) == ""


def test_ap_configs_are_bound_and_isolated(tmp_path):
    globals_ = HELPER["write_ap_configs"].__globals__
    original = globals_["RUN_DIR"]
    globals_["RUN_DIR"] = tmp_path
    try:
        for kind, interface, address in (
            ("management", "wlan0", "10.43.0.1/24"),
            ("training", "wlan2", "10.42.0.1/24"),
        ):
            _, dnsmasq = HELPER["write_ap_configs"](
                kind, interface, "Lab", "safe-password", 1, "AT", address,
                address.split("/", 1)[0], address.replace(".1/24", ".20"), address.replace(".1/24", ".100"),
            )
            text = dnsmasq.read_text()
            assert f"interface={interface}\n" in text
            assert "bind-interfaces\n" in text
            assert f"listen-address={address.split('/', 1)[0]}\n" in text
            assert f"pid-file={tmp_path / kind / 'dnsmasq.pid'}\n" in text
            assert f"dhcp-leasefile={tmp_path / kind / 'dnsmasq.leases'}\n" in text
        assert (tmp_path / "management" / "dnsmasq.conf") != (tmp_path / "training" / "dnsmasq.conf")
    finally:
        globals_["RUN_DIR"] = original


def test_daemon_start_propagates_real_stderr(tmp_path):
    with pytest.raises(HELPER["HelperError"], match="failed to bind DNS port: Address already in use"):
        HELPER["start_daemon"](
            "dnsmasq",
            [sys.executable, "-c", "import sys; print('failed to bind DNS port: Address already in use'); sys.exit(2)"],
            tmp_path / "dnsmasq.log",
            0.05,
        )


def test_public_ap_state_removes_secrets():
    state = {"running": False, "password": "secret", "wpa_passphrase": "secret", "ssid": "Lab"}
    public = HELPER["public_ap_state"](state, "management")
    assert public["ssid"] == "Lab"
    assert "password" not in public
    assert "wpa_passphrase" not in public


def test_log_output_is_bounded_and_redacts_credentials():
    lines = HELPER["sanitize_log_lines"](
        'ok\nwpa_passphrase=do-not-show\npassword: hidden-value\n{"password":"json-secret","status":"failed"}\n'
    )
    assert lines == [
        "ok",
        "wpa_passphrase=[redacted]",
        "password: [redacted]",
        '{"password":[redacted],"status":"failed"}',
    ]


def test_helper_credentials_reads_only_running_training_config(monkeypatch, tmp_path, capsys):
    globals_ = HELPER["ap_credentials"].__globals__
    training = tmp_path / "training"
    training.mkdir()
    (training / "hostapd.conf").write_text("ssid=Lab\nwpa_passphrase=pinepi-owned-test-password\n")
    monkeypatch.setitem(globals_, "RUN_DIR", tmp_path)
    monkeypatch.setitem(globals_, "load_state", lambda name: {"running": True, "hostapd_pid": 10, "dnsmasq_pid": 11, "ssid": "Lab", "channel": 6})
    monkeypatch.setitem(globals_, "process_alive", lambda pid, expected: True)
    HELPER["ap_credentials"]()
    result = json.loads(capsys.readouterr().out)
    assert result["password"] == "pinepi-owned-test-password"


def test_helper_rejects_unregistered_log_source():
    with pytest.raises(HELPER["HelperError"], match="Unsupported log source"):
        HELPER["logs"]("/etc/shadow")


def test_helper_has_no_arbitrary_command_action():
    with pytest.raises(SystemExit):
        HELPER["parser"]().parse_args(["exec", "id"])
    source = __import__("pathlib").Path("scripts/pinepi-helper").read_text()
    assert "shell=True" not in source
    assert "os.system" not in source


def test_training_cleanup_restores_owned_resources(monkeypatch):
    globals_ = HELPER["cleanup_ap_runtime"].__globals__
    calls = []
    monkeypatch.setitem(globals_, "terminate", lambda pid, expected: calls.append(("terminate", pid, expected)))
    monkeypatch.setitem(globals_, "nft_cleanup", lambda: calls.append(("nft",)))
    monkeypatch.setitem(globals_, "executable", lambda name: name)
    monkeypatch.setitem(globals_, "run", lambda argv, **kwargs: calls.append(("run", argv)))
    monkeypatch.setitem(globals_, "set_managed", lambda interface: calls.append(("managed", interface)))
    monkeypatch.setitem(globals_, "remove_runtime_configs", lambda kind: calls.append(("remove", kind)))
    class ExistingPath:
        def __truediv__(self, _value):
            return self

        @staticmethod
        def exists():
            return True

    real_path = globals_["Path"]
    monkeypatch.setitem(globals_, "Path", lambda value: ExistingPath() if str(value).startswith("/sys/class/net") else real_path(value))
    HELPER["cleanup_ap_runtime"]({"dnsmasq_pid": 10, "hostapd_pid": 11, "interface": "wlan9", "previous_forward": "0"}, "training")
    assert ("nft",) in calls
    assert ("managed", "wlan9") in calls
    assert ("run", ["sysctl", "-w", "net.ipv4.ip_forward=0"]) in calls
    assert ("remove", "training") in calls


def test_training_start_rolls_back_after_hostapd_failure(monkeypatch, tmp_path):
    globals_ = HELPER["ap_start"].__globals__
    calls, saved = [], []
    monkeypatch.setattr(sys, "stdin", StringIO('{"ssid":"Lab","password":"safe-lab-password"}'))
    monkeypatch.setitem(globals_, "validate_interface", lambda value: value)
    monkeypatch.setitem(globals_, "validate_ap_network", lambda *args: None)
    monkeypatch.setitem(globals_, "load_state", lambda name: {})
    monkeypatch.setitem(globals_, "process_alive", lambda *args: False)
    monkeypatch.setitem(globals_, "default_uplink", lambda excluded: "eth0")
    monkeypatch.setitem(globals_, "write_ap_configs", lambda *args: (tmp_path / "hostapd.conf", tmp_path / "dnsmasq.conf"))
    monkeypatch.setitem(globals_, "configure_ap_interface", lambda *args: calls.append("configured"))
    monkeypatch.setitem(globals_, "nft_cleanup", lambda: calls.append("nft-cleanup"))
    monkeypatch.setitem(globals_, "executable", lambda name: name)
    monkeypatch.setitem(globals_, "run", lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setitem(globals_, "start_daemon", lambda *args: (_ for _ in ()).throw(HELPER["HelperError"]("hostapd failed to start: invalid channel")))
    monkeypatch.setitem(globals_, "set_managed", lambda interface: calls.append(["managed", interface]))
    monkeypatch.setitem(globals_, "remove_runtime_configs", lambda kind: calls.append(["remove", kind]))
    monkeypatch.setitem(globals_, "save_state", lambda name, value: saved.append((name, value)))
    real_path = globals_["Path"]
    monkeypatch.setitem(globals_, "Path", lambda value: SimpleNamespace(read_text=lambda: "0") if str(value) == "/proc/sys/net/ipv4/ip_forward" else real_path(value))
    with pytest.raises(HELPER["HelperError"], match="invalid channel"):
        HELPER["ap_start"]("wlan9", "6", "wlan0,wlan1")
    assert calls.count("nft-cleanup") == 2
    assert ["managed", "wlan9"] in calls
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in calls
    assert saved[-1][1]["running"] is False
    assert "invalid channel" in saved[-1][1]["last_error"]


def test_training_start_stops_hostapd_when_dnsmasq_fails(monkeypatch, tmp_path):
    globals_ = HELPER["ap_start"].__globals__
    calls, saved = [], []
    monkeypatch.setattr(sys, "stdin", StringIO('{"ssid":"Lab","password":"safe-lab-password"}'))
    monkeypatch.setitem(globals_, "validate_interface", lambda value: value)
    monkeypatch.setitem(globals_, "validate_ap_network", lambda *args: None)
    monkeypatch.setitem(globals_, "load_state", lambda name: {})
    monkeypatch.setitem(globals_, "process_alive", lambda *args: False)
    monkeypatch.setitem(globals_, "default_uplink", lambda excluded: "eth0")
    monkeypatch.setitem(globals_, "write_ap_configs", lambda *args: (tmp_path / "hostapd.conf", tmp_path / "dnsmasq.conf"))
    monkeypatch.setitem(globals_, "configure_ap_interface", lambda *args: calls.append("configured"))
    monkeypatch.setitem(globals_, "nft_cleanup", lambda: calls.append("nft-cleanup"))
    monkeypatch.setitem(globals_, "executable", lambda name: name)
    monkeypatch.setitem(globals_, "run", lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(returncode=0, stdout="", stderr=""))
    daemons = iter((SimpleNamespace(pid=123), HELPER["HelperError"]("dnsmasq failed to start: port 53 is busy")))

    def start_daemon(*_args):
        value = next(daemons)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setitem(globals_, "start_daemon", start_daemon)
    monkeypatch.setitem(globals_, "terminate", lambda pid, expected: calls.append(["terminate", pid, expected]))
    monkeypatch.setitem(globals_, "set_managed", lambda interface: calls.append(["managed", interface]))
    monkeypatch.setitem(globals_, "remove_runtime_configs", lambda kind: calls.append(["remove", kind]))
    monkeypatch.setitem(globals_, "save_state", lambda name, value: saved.append((name, value)))
    real_path = globals_["Path"]
    monkeypatch.setitem(globals_, "Path", lambda value: SimpleNamespace(read_text=lambda: "0") if str(value) == "/proc/sys/net/ipv4/ip_forward" else real_path(value))
    with pytest.raises(HELPER["HelperError"], match="port 53 is busy"):
        HELPER["ap_start"]("wlan9", "6", "wlan0,wlan1")
    assert ["terminate", 123, "hostapd"] in calls
    assert ["managed", "wlan9"] in calls
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in calls
    assert saved[-1][1]["running"] is False
    assert "port 53 is busy" in saved[-1][1]["last_error"]


def test_training_stop_is_idempotent(monkeypatch, capsys):
    globals_ = HELPER["ap_stop"].__globals__
    saved = []
    monkeypatch.setitem(globals_, "load_state", lambda name: {})
    monkeypatch.setitem(globals_, "cleanup_ap_runtime", lambda state, kind: None)
    monkeypatch.setitem(globals_, "save_state", lambda name, value: saved.append(value.copy()))
    monkeypatch.setitem(globals_, "process_alive", lambda *args: False)
    HELPER["ap_stop"]()
    HELPER["ap_stop"]()
    assert all(state["running"] is False and state["forwarding"] is False for state in saved)
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_unexpected_scanner_exit_restores_audit_adapter(monkeypatch, capsys):
    globals_ = HELPER["scan_status"].__globals__
    state = {"running": True, "pid": 42, "interface": "wlan9", "started_at": 1}
    managed, saved = [], []
    monkeypatch.setitem(globals_, "load_state", lambda name: state.copy())
    monkeypatch.setitem(globals_, "process_alive", lambda *args: False)
    monkeypatch.setitem(globals_, "set_managed", lambda interface: managed.append(interface))
    monkeypatch.setitem(globals_, "save_state", lambda name, value: saved.append(value.copy()))
    HELPER["scan_status"]()
    assert managed == ["wlan9"]
    assert saved[-1]["running"] is False
    assert "stopped_at" in saved[-1]
    capsys.readouterr()


def test_helper_validates_utf8_byte_lengths():
    with pytest.raises(HELPER["HelperError"], match="Invalid SSID"):
        HELPER["safe_text"]("é" * 32, "SSID", 1, 32)
