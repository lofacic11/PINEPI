from app.services.scanner import ScannerService


def test_parse_airodump_csv(tmp_path):
    path = tmp_path / "current-01.csv"
    path.write_text(
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, now, now, 6, 54, WPA2, CCMP, PSK, -41, 15, 7, 0.0.0.0, 7, TestNet,\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
    )
    assert ScannerService.parse_csv(path) == [{
        "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "privacy": "WPA2", "cipher": "CCMP",
        "authentication": "PSK", "power": -41, "beacons": 15, "data_packets": 7, "ssid": "TestNet",
    }]

