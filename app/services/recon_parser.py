from __future__ import annotations

import csv
import re
from pathlib import Path

from app.services.audit import classify_security
from app.services.vendor import VendorLookup

MAC = re.compile(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def safe_wireless_text(value: str, limit: int) -> str:
    """Keep radio metadata displayable and harmless in logs/JSON."""
    return "".join(char if ord(char) >= 32 and ord(char) != 127 else "�" for char in value).strip()[:limit]


def normalize_mac(value: str) -> str | None:
    value = value.strip().upper()
    return value if MAC.fullmatch(value) else None


def channel_details(channel: int | None) -> tuple[int | None, str]:
    if channel is None:
        return None, "unknown"
    if channel == 14:
        return 2484, "2.4 GHz"
    if 1 <= channel <= 13:
        return 2407 + channel * 5, "2.4 GHz"
    if 30 <= channel <= 196:
        return 5000 + channel * 5, "5 GHz"
    return None, "other"


def signal_quality(signal: int | None) -> str:
    if signal is None:
        return "Unknown"
    if signal >= -50:
        return "Excellent"
    if signal >= -60:
        return "Good"
    if signal >= -70:
        return "Fair"
    if signal >= -80:
        return "Weak"
    return "Very weak"


def parse_airodump(path: Path, vendors: VendorLookup) -> tuple[list[dict], list[dict]]:
    if not path.is_file():
        return [], []
    aps: list[dict] = []
    clients: list[dict] = []
    section = "aps"
    try:
        with path.open(newline="", errors="replace") as handle:
            for row in csv.reader(handle):
                if not row:
                    continue
                first = row[0].strip()
                if first == "BSSID":
                    section = "aps"
                    continue
                if first == "Station MAC":
                    section = "clients"
                    continue
                if section == "aps":
                    parsed = _parse_ap(row, vendors)
                    if parsed:
                        aps.append(parsed)
                else:
                    parsed = _parse_client(row, vendors)
                    if parsed:
                        clients.append(parsed)
    except OSError:
        return [], []
    return aps, clients


def _integer(row: list[str], index: int) -> int | None:
    try:
        return int(row[index].strip())
    except (IndexError, ValueError):
        return None


def _parse_ap(row: list[str], vendors: VendorLookup) -> dict | None:
    if len(row) < 14:
        return None
    bssid = normalize_mac(row[0])
    channel = _integer(row, 3)
    if not bssid or channel is None:
        return None
    ssid = safe_wireless_text(row[13], 32)
    privacy, cipher, authentication = (safe_wireless_text(row[index], 80) for index in (5, 6, 7))
    frequency, band = channel_details(channel)
    security = classify_security(privacy, authentication, cipher)
    signal = _integer(row, 8)
    return {
        "bssid": bssid, "ssid": ssid, "hidden": not bool(ssid), "channel": channel,
        "frequency": frequency, "band": band, "signal": signal, "signal_quality": signal_quality(signal),
        "privacy": privacy, "cipher": cipher, "authentication": authentication,
        "security": security["mode"], "security_detail": security, "pmf": "unknown",
        "beacons": _integer(row, 9) or 0, "data_packets": _integer(row, 10) or 0,
        "first_seen": row[1].strip()[:40], "last_seen": row[2].strip()[:40],
        "vendor": vendors.lookup(bssid), "visible": True,
    }


def _parse_client(row: list[str], vendors: VendorLookup) -> dict | None:
    if len(row) < 6:
        return None
    station = normalize_mac(row[0])
    if not station:
        return None
    raw_bssid = row[5].strip()
    bssid = normalize_mac(raw_bssid)
    probes = safe_wireless_text(", ".join(value.strip() for value in row[6:] if value.strip()), 512)
    return {
        "station_mac": station, "bssid": bssid,
        "relationship": "associated" if bssid else "unassociated" if "not associated" in raw_bssid.lower() or probes else "unknown",
        "probed_ssids": probes, "signal": _integer(row, 3), "packet_count": _integer(row, 4) or 0,
        "first_seen": row[1].strip()[:40], "last_seen": row[2].strip()[:40],
        "vendor": vendors.lookup(station),
    }
