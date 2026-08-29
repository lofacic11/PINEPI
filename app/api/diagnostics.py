from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api", tags=["diagnostics"])

LogSource = Literal[
    "application",
    "management_service",
    "management_hostapd",
    "management_dnsmasq",
    "training_hostapd",
    "training_dnsmasq",
    "recon",
    "capture",
]


@router.get("/diagnostics/logs")
async def logs(request: Request, source: LogSource = "application") -> dict:
    result = await request.app.state.helper.call("logs", source)
    return {
        "source": source,
        "lines": [str(line)[:500] for line in result.get("lines", [])[:80]],
        "truncated": bool(result.get("truncated")),
    }


@router.get("/settings")
async def settings(request: Request) -> dict:
    config = request.app.state.config
    return {
        "general": {"ui_mode": "browser-local", "country": config.ap.country},
        "management": {
            "enabled": config.management_ap.enabled,
            "ssid": config.management_ap.ssid,
            "address": config.management_ap.address,
            "channel": config.management_ap.channel,
        },
        "training_ap": {
            "address": config.ap.address,
            "dhcp_start": config.ap.dhcp_start,
            "dhcp_end": config.ap.dhcp_end,
            "country": config.ap.country,
        },
        "recon": {
            "max_sessions": config.recon.max_sessions,
            "max_age_days": config.recon.max_age_days,
            "max_signal_samples_per_ap": config.recon.max_signal_samples_per_ap,
            "mock_mode": config.recon.mock_mode,
        },
        "capture": {"max_capture_mb": config.storage.max_capture_mb},
        "adapters": {
            "management_interfaces": config.adapters.management_interfaces,
            "audit_usb_ids": config.adapters.audit_usb_ids,
            "training_usb_ids": config.adapters.ap_usb_ids,
        },
    }


@router.get("/modules")
async def modules(request: Request) -> dict:
    config = request.app.state.config
    system = await request.app.state.system_service.status()
    roles = {item.get("role") for item in system.get("interfaces", [])}
    definitions = [
        ("Recon", "airodump-ng", "audit", True),
        ("Packet Capture", "dumpcap", "audit", True),
        ("Training AP", "hostapd", "training_ap", True),
        ("DHCP/DNS", "dnsmasq", "training_ap", True),
        ("Audit Engine", None, None, True),
        ("Vendor Lookup", None, None, any(Path(path).is_file() for path in config.recon.oui_paths)),
        ("Reports", None, None, False),
    ]
    items = []
    for name, dependency, role, implemented in definitions:
        dependency_ok = not dependency or shutil.which(dependency) is not None
        adapter_ok = not role or role in roles
        items.append({
            "name": name,
            "enabled": implemented,
            "available": implemented and dependency_ok and adapter_ok,
            "dependency": dependency or "Built in",
            "adapter_required": role or "None",
            "reason": "Ready" if implemented and dependency_ok and adapter_ok else "Planned" if not implemented else "Missing dependency or adapter",
        })
    return {"items": items}
