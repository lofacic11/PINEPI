from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from app.config import AppConfig
from app.services.command import CommandError, run_command


@dataclass
class Adapter:
    interface: str
    phy: str = ""
    driver: str = "unknown"
    usb_id: str = ""
    mac: str = ""
    device_path: str = ""
    is_internal: bool = False
    supports_ap: bool = False
    supports_monitor: bool = False
    role: str = "unassigned"
    role_reason: str = "No matching role rule"


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except (OSError, UnicodeError):
        return ""


def _usb_id(device: Path) -> str:
    current = device.resolve()
    for parent in (current, *current.parents):
        vendor = _read(parent / "idVendor").lower()
        product = _read(parent / "idProduct").lower()
        if re.fullmatch(r"[0-9a-f]{4}", vendor) and re.fullmatch(r"[0-9a-f]{4}", product):
            return f"{vendor}:{product}"
    return ""


def _driver(device: Path) -> str:
    try:
        return (device.resolve() / "driver").resolve().name
    except OSError:
        return "unknown"


def _device_path(device: Path) -> str:
    try:
        return str(device.resolve())
    except OSError:
        return ""


def _is_internal(device_path: str, driver: str, usb_id: str, config: AppConfig) -> bool:
    if usb_id:
        return False
    path = device_path.lower()
    return driver.lower() in config.adapters.management_drivers or any(
        marker in path for marker in ("/platform/", "/mmc", "/soc/")
    )


async def _capabilities(phy: str) -> tuple[bool, bool]:
    if not phy:
        return False, False
    try:
        result = await run_command("iw", "phy", phy, "info", timeout=4)
    except CommandError:
        return False, False
    modes = result.stdout.split("Supported interface modes:", 1)[-1]
    return bool(re.search(r"^\s*\*\s+AP\s*$", modes, re.MULTILINE)), bool(
        re.search(r"^\s*\*\s+monitor\s*$", modes, re.MULTILINE)
    )


def _assign_roles(adapters: list[Adapter], config: AppConfig) -> None:
    assigned: set[str] = set()
    internal = next((item for item in adapters if item.is_internal), None)
    named = next(
        (item for item in adapters if item.interface in config.adapters.management_interfaces and not item.usb_id),
        None,
    )
    management = internal or named
    if management:
        management.role = "management"
        management.role_reason = (
            "Detected internal non-USB WLAN" if internal else "Configured non-USB management interface"
        )
        assigned.add(management.interface)

    def choose(role: str, usb_ids: tuple[str, ...], capability: str) -> None:
        candidates = [item for item in adapters if item.interface not in assigned]
        preferred = next((item for item in candidates if item.usb_id in usb_ids), None)
        capable = next((item for item in candidates if getattr(item, capability)), None)
        selected = preferred or capable
        if selected:
            selected.role = role
            selected.role_reason = "Preferred USB ID" if preferred else f"Supports {role} mode"
            assigned.add(selected.interface)

    choose("audit", config.adapters.audit_usb_ids, "supports_monitor")
    choose("training_ap", config.adapters.ap_usb_ids, "supports_ap")


async def detect_adapters(config: AppConfig) -> list[dict]:
    net_root = Path("/sys/class/net")
    interfaces = sorted(path for path in net_root.glob("*") if (path / "wireless").exists())
    items: list[Adapter] = []
    for interface in interfaces:
        device = interface / "device"
        phy_link = device / "ieee80211"
        try:
            phys = list(phy_link.iterdir())
            phy = phys[0].name if phys else ""
        except OSError:
            phy = ""
        item = Adapter(
            interface=interface.name,
            phy=phy,
            driver=_driver(device),
            usb_id=_usb_id(device),
            mac=_read(interface / "address"),
            device_path=_device_path(device),
        )
        item.is_internal = _is_internal(item.device_path, item.driver, item.usb_id, config)
        item.supports_ap, item.supports_monitor = await _capabilities(phy)
        items.append(item)
    _assign_roles(items, config)
    return [asdict(item) for item in items]


def interface_for_role(adapters: list[dict], role: str) -> str:
    match = next((item["interface"] for item in adapters if item["role"] == role), None)
    if not match:
        raise RuntimeError(f"No Wi-Fi adapter is available for the {role} role")
    return str(match)
