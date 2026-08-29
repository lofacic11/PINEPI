import pytest

from app.services.capabilities import AIRCRACK_BINARIES, CapabilityRegistry, parse_version


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Aircrack-ng 1.7  - (C) 2006-2022", "1.7"),
        ("Kismet 2023.07.R1", "2023.07.R1"),
        ("Suricata version 7.0.3 RELEASE", "7.0.3"),
        ("no version here", "Unknown"),
    ],
)
def test_version_parsing(text, expected):
    assert parse_version(text) == expected


@pytest.mark.asyncio
async def test_registry_detects_each_aircrack_binary_and_missing_tools(monkeypatch):
    available = {"aircrack-ng": "/usr/bin/aircrack-ng", "airodump-ng": "/usr/bin/airodump-ng"}
    monkeypatch.setattr("app.services.capabilities.shutil.which", lambda name: available.get(name))

    async def version(_path, _arguments):
        return "1.7"

    monkeypatch.setattr(CapabilityRegistry, "_binary_version", staticmethod(version))
    result = await CapabilityRegistry(cache_seconds=0).status()
    indexed = {item["name"]: item for item in result["items"]}
    assert set(AIRCRACK_BINARIES) <= indexed.keys()
    assert indexed["aircrack-ng"]["available"] is True
    assert indexed["airodump-ng"]["version"] == "1.7"
    assert indexed["aireplay-ng"]["available"] is False
    assert "aireplay-ng" in result["summary"]["required_missing"]


@pytest.mark.asyncio
async def test_registry_cache_avoids_repeated_detection(monkeypatch):
    calls = []
    monkeypatch.setattr("app.services.capabilities.shutil.which", lambda name: calls.append(name) or None)
    registry = CapabilityRegistry(cache_seconds=300)
    assert await registry.status() is await registry.status()
    assert calls.count("aircrack-ng") == 2  # suite version probe plus its individual availability probe
