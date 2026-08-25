from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StorageConfig:
    scans: Path = Path("/var/lib/pinepi/scans")
    captures: Path = Path("/var/lib/pinepi/captures")
    max_capture_mb: int = 1024


@dataclass(frozen=True)
class APConfig:
    subnet: str = "10.42.0.0/24"
    address: str = "10.42.0.1/24"
    gateway: str = "10.42.0.1"
    dhcp_start: str = "10.42.0.20"
    dhcp_end: str = "10.42.0.200"
    country: str = "AT"
    default_password: str = "pinepi-lab"


@dataclass(frozen=True)
class AdapterPreference:
    management_interfaces: tuple[str, ...] = ("wlan0",)
    audit_usb_ids: tuple[str, ...] = ("0bda:8813",)
    ap_usb_ids: tuple[str, ...] = ("148f:5572",)


@dataclass(frozen=True)
class AppConfig:
    storage: StorageConfig = field(default_factory=StorageConfig)
    ap: APConfig = field(default_factory=APConfig)
    adapters: AdapterPreference = field(default_factory=AdapterPreference)
    helper: str = "/usr/local/sbin/pinepi-helper"
    sudo: bool = True
    command_timeout: float = 12.0
    status_cache_seconds: float = 2.0


def _tuple(value: object, default: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(item).lower() for item in value) if isinstance(value, list) else default


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or os.getenv("PINEPI_CONFIG", "/etc/pinepi/pinepi.toml"))
    raw: dict = {}
    if config_path.is_file():
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)

    storage = raw.get("storage", {})
    ap = raw.get("training_ap", {})
    adapters = raw.get("adapters", {})
    runtime = raw.get("runtime", {})
    defaults = AppConfig()
    return AppConfig(
        storage=StorageConfig(
            scans=Path(storage.get("scan_path", defaults.storage.scans)),
            captures=Path(storage.get("capture_path", defaults.storage.captures)),
            max_capture_mb=max(1, int(storage.get("max_capture_mb", defaults.storage.max_capture_mb))),
        ),
        ap=APConfig(
            subnet=str(ap.get("subnet", defaults.ap.subnet)),
            address=str(ap.get("address", defaults.ap.address)),
            gateway=str(ap.get("gateway", defaults.ap.gateway)),
            dhcp_start=str(ap.get("dhcp_start", defaults.ap.dhcp_start)),
            dhcp_end=str(ap.get("dhcp_end", defaults.ap.dhcp_end)),
            country=str(ap.get("country", defaults.ap.country)).upper(),
            default_password=str(ap.get("default_password", defaults.ap.default_password)),
        ),
        adapters=AdapterPreference(
            management_interfaces=_tuple(adapters.get("management_interfaces"), defaults.adapters.management_interfaces),
            audit_usb_ids=_tuple(adapters.get("audit_usb_ids"), defaults.adapters.audit_usb_ids),
            ap_usb_ids=_tuple(adapters.get("ap_usb_ids"), defaults.adapters.ap_usb_ids),
        ),
        helper=str(runtime.get("helper", defaults.helper)),
        sudo=bool(runtime.get("sudo", defaults.sudo)),
        command_timeout=float(runtime.get("command_timeout", defaults.command_timeout)),
        status_cache_seconds=float(runtime.get("status_cache_seconds", defaults.status_cache_seconds)),
    )

