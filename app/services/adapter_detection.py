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
    supported_channels: tuple[int, ...] = ()
    disabled_channels: tuple[int, ...] = ()
    no_ir_channels: tuple[int, ...] = ()
    dfs_channels: tuple[int, ...] = ()
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


def parse_phy_info(text: str) -> tuple[bool, bool, tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    modes = text.split("Supported interface modes:", 1)[-1]
    supports_ap = bool(re.search(r"^\s*\*\s+AP\s*$", modes, re.MULTILINE))
    supports_monitor = bool(re.search(r"^\s*\*\s+monitor\s*$", modes, re.MULTILINE))
    supported, disabled, no_ir, dfs = [], [], [], []
    for line in text.splitlines():
        match = re.search(r"\*\s+\d+\s+MHz\s+\[(\d+)\]", line)
        if not match:
            continue
        channel = int(match.group(1))
        lowered = line.lower()
        if "disabled" in lowered:
            disabled.append(channel)
        else:
            supported.append(channel)
        if "no ir" in lowered or "no-ir" in lowered:
            no_ir.append(channel)
        if "radar detection" in lowered or "dfs" in lowered:
            dfs.append(channel)
    return supports_ap, supports_monitor, tuple(supported), tuple(disabled), tuple(no_ir), tuple(dfs)


async def _capabilities(phy: str) -> tuple[bool, bool, tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    if not phy:
        return False, False, (), (), (), ()
    try:
        result = await run_command("iw", "phy", phy, "info", timeout=4)
    except CommandError:
        return False, False, (), (), (), ()
    return parse_phy_info(result.stdout)


def _assign_roles(adapters: list[Adapter], config: AppConfig) -> None:
    assigned: set[str] = set()
    internal = next((item for item in adapters if item.is_internal), None)
    named = next(
        (item for item in adapters if item.interface in config.adapters.management_interfaces and not item.usb_id),
        None,
    )
    # The configured interface wins so wlan0 remains the permanent management
    # adapter even when another internal WLAN appears first in sysfs.
    management = named or internal
    if management:
        management.role = "management"
        management.role_reason = (
            "Detected internal non-USB WLAN" if internal else "Configured non-USB management interface"
        )
        assigned.add(management.interface)

    def choose(role: str, usb_ids: tuple[str, ...], capability: str) -> None:
        candidates = [item for item in adapters if item.interface not in assigned]
        # A configured USB ID is only a preference. Do not assign an adapter
        # to a role when it does not advertise the capability that role needs.
        preferred = next(
            (item for item in candidates if item.usb_id in usb_ids and getattr(item, capability)),
            None,
        )
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
        (
            item.supports_ap,
            item.supports_monitor,
            item.supported_channels,
            item.disabled_channels,
            item.no_ir_channels,
            item.dfs_channels,
        ) = await _capabilities(phy)
        items.append(item)
    _assign_roles(items, config)
    return [asdict(item) for item in items]


def interface_for_role(adapters: list[dict], role: str) -> str:
    match = next((item["interface"] for item in adapters if item["role"] == role), None)
    if not match:
        raise RuntimeError(f"No Wi-Fi adapter is available for the {role} role")
    return str(match)
