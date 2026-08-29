from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StorageConfig:
    scans: Path = Path("/var/lib/pinepi/scans")
    captures: Path = Path("/var/lib/pinepi/captures")
    max_capture_mb: int = 1024
    database: Path = Path("/var/lib/pinepi/data/pinepi.db")


@dataclass(frozen=True)
class ReconConfig:
    max_sessions: int = 50
    max_age_days: int = 90
    max_signal_samples_per_ap: int = 50
    oui_paths: tuple[Path, ...] = (
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/misc/oui.txt"),
    )
    mock_mode: bool = False
    mock_scenario: str = "normal"
    engine: str = "auto"


@dataclass(frozen=True)
class ActiveTestConfig:
    max_runtime_seconds: int = 30
    max_deauth_bursts: int = 32


@dataclass(frozen=True)
class AnalysisConfig:
    max_input_mb: int = 2048
    max_packets: int = 50000
    max_result_rows: int = 1000


@dataclass(frozen=True)
class APConfig:
    subnet: str = "10.42.0.0/24"
    address: str = "10.42.0.1/24"
    gateway: str = "10.42.0.1"
    dhcp_start: str = "10.42.0.20"
    dhcp_end: str = "10.42.0.200"
    country: str = "AT"
    default_password: str = "CHANGE-ME-BEFORE-USE"


@dataclass(frozen=True)
class ManagementAPConfig:
    enabled: bool = True
    ssid: str = "PinePi"
    password: str = "CHANGE-ME-BEFORE-USE"
    interface_role: str = "management"
    address: str = "10.43.0.1/24"
    dhcp_start: str = "10.43.0.20"
    dhcp_end: str = "10.43.0.100"
    channel: int = 1
    country_code: str = "AT"


@dataclass(frozen=True)
class AdapterPreference:
    management_interfaces: tuple[str, ...] = ("wlan0",)
    management_drivers: tuple[str, ...] = ("brcmfmac",)
    audit_usb_ids: tuple[str, ...] = ("0bda:8813",)
    ap_usb_ids: tuple[str, ...] = ("148f:5572",)


@dataclass(frozen=True)
class AppConfig:
    storage: StorageConfig = field(default_factory=StorageConfig)
    ap: APConfig = field(default_factory=APConfig)
    management_ap: ManagementAPConfig = field(default_factory=ManagementAPConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    active_tests: ActiveTestConfig = field(default_factory=ActiveTestConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
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
    management_ap = raw.get("management_ap", {})
    adapters = raw.get("adapters", {})
    runtime = raw.get("runtime", {})
    recon = raw.get("recon", {})
    active_tests = raw.get("active_tests", {})
    analysis = raw.get("analysis", {})
    defaults = AppConfig()
    result = AppConfig(
        storage=StorageConfig(
            scans=Path(storage.get("scan_path", defaults.storage.scans)),
            captures=Path(storage.get("capture_path", defaults.storage.captures)),
            max_capture_mb=max(1, int(storage.get("max_capture_mb", defaults.storage.max_capture_mb))),
            database=Path(storage.get("database_path", defaults.storage.database)),
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
        management_ap=ManagementAPConfig(
            enabled=bool(management_ap.get("enabled", defaults.management_ap.enabled)),
            ssid=str(management_ap.get("ssid", defaults.management_ap.ssid)),
            password=str(management_ap.get("password", defaults.management_ap.password)),
            interface_role=str(management_ap.get("interface_role", defaults.management_ap.interface_role)),
            address=str(management_ap.get("address", defaults.management_ap.address)),
            dhcp_start=str(management_ap.get("dhcp_start", defaults.management_ap.dhcp_start)),
            dhcp_end=str(management_ap.get("dhcp_end", defaults.management_ap.dhcp_end)),
            channel=int(management_ap.get("channel", defaults.management_ap.channel)),
            country_code=str(management_ap.get("country_code", defaults.management_ap.country_code)).upper(),
        ),
        recon=ReconConfig(
            max_sessions=max(1, int(recon.get("max_sessions", defaults.recon.max_sessions))),
            max_age_days=max(1, int(recon.get("max_age_days", defaults.recon.max_age_days))),
            max_signal_samples_per_ap=max(
                1, int(recon.get("max_signal_samples_per_ap", defaults.recon.max_signal_samples_per_ap))
            ),
            oui_paths=tuple(Path(item) for item in recon.get("oui_paths", defaults.recon.oui_paths)),
            mock_mode=bool(recon.get("mock_mode", defaults.recon.mock_mode)),
            mock_scenario=str(recon.get("mock_scenario", defaults.recon.mock_scenario)),
            engine=str(recon.get("engine", defaults.recon.engine)).lower(),
        ),
        active_tests=ActiveTestConfig(
            max_runtime_seconds=min(60, max(1, int(active_tests.get("max_runtime_seconds", defaults.active_tests.max_runtime_seconds)))),
            max_deauth_bursts=min(128, max(1, int(active_tests.get("max_deauth_bursts", defaults.active_tests.max_deauth_bursts)))),
        ),
        analysis=AnalysisConfig(
            max_input_mb=min(20480, max(1, int(analysis.get("max_input_mb", defaults.analysis.max_input_mb)))),
            max_packets=min(250000, max(100, int(analysis.get("max_packets", defaults.analysis.max_packets)))),
            max_result_rows=min(10000, max(10, int(analysis.get("max_result_rows", defaults.analysis.max_result_rows)))),
        ),
        adapters=AdapterPreference(
            management_interfaces=_tuple(adapters.get("management_interfaces"), defaults.adapters.management_interfaces),
            management_drivers=_tuple(adapters.get("management_drivers"), defaults.adapters.management_drivers),
            audit_usb_ids=_tuple(adapters.get("audit_usb_ids"), defaults.adapters.audit_usb_ids),
            ap_usb_ids=_tuple(adapters.get("ap_usb_ids"), defaults.adapters.ap_usb_ids),
        ),
        helper=str(runtime.get("helper", defaults.helper)),
        sudo=bool(runtime.get("sudo", defaults.sudo)),
        command_timeout=float(runtime.get("command_timeout", defaults.command_timeout)),
        status_cache_seconds=float(runtime.get("status_cache_seconds", defaults.status_cache_seconds)),
    )
    training_network = ipaddress.ip_interface(result.ap.address).network
    management_network = ipaddress.ip_interface(result.management_ap.address).network
    if training_network.overlaps(management_network):
        raise ValueError("Management AP and Training AP subnets must not overlap")
    if result.management_ap.interface_role != "management":
        raise ValueError("management_ap.interface_role must be 'management'")
    if not 1 <= result.management_ap.channel <= 13:
        raise ValueError("management_ap.channel must be between 1 and 13")
    if result.recon.mock_scenario not in {"normal", "empty", "failure", "missing_adapter"}:
        raise ValueError("recon.mock_scenario must be normal, empty, failure, or missing_adapter")
    if result.recon.engine not in {"auto", "airodump", "kismet"}:
        raise ValueError("recon.engine must be auto, airodump, or kismet")
    return result
