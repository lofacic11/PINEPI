import runpy
import sys

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
