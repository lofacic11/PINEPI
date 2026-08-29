from app.config import AppConfig
from app.services.adapter_detection import Adapter, _assign_roles, parse_phy_info


def test_internal_and_usb_adapters_receive_distinct_roles():
    adapters = [
        Adapter("wlan7", driver="brcmfmac", is_internal=True, supports_ap=True),
        Adapter("wlan1", driver="8814au", usb_id="0bda:8813", supports_monitor=True),
        Adapter("wlan9", driver="rt2800usb", usb_id="148f:5572", supports_ap=True),
    ]
    _assign_roles(adapters, AppConfig())
    assert {adapter.interface: adapter.role for adapter in adapters} == {
        "wlan7": "management",
        "wlan1": "audit",
        "wlan9": "training_ap",
    }


def test_usb_wlan0_is_not_assumed_to_be_internal():
    adapters = [Adapter("wlan0", usb_id="0bda:8813", supports_monitor=True)]
    _assign_roles(adapters, AppConfig())
    assert adapters[0].role == "audit"


def test_phy_capabilities_include_regulatory_channel_flags():
    output = """
Supported interface modes:
         * AP
         * monitor
Frequencies:
         * 2412 MHz [1] (20.0 dBm)
         * 2467 MHz [12] (disabled)
         * 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
"""
    ap, monitor, supported, disabled, no_ir, dfs = parse_phy_info(output)
    assert ap and monitor
    assert supported == (1, 52)
    assert disabled == (12,)
    assert no_ir == (52,)
    assert dfs == (52,)
