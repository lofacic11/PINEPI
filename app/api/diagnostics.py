from __future__ import annotations

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
    "active",
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
            "engine": config.recon.engine,
        },
        "capture": {"max_capture_mb": config.storage.max_capture_mb},
        "active_tests": {
            "max_runtime_seconds": config.active_tests.max_runtime_seconds,
            "max_deauth_bursts": config.active_tests.max_deauth_bursts,
        },
        "analysis": {
            "max_input_mb": config.analysis.max_input_mb,
            "max_packets": config.analysis.max_packets,
            "max_result_rows": config.analysis.max_result_rows,
        },
        "adapters": {
            "management_interfaces": config.adapters.management_interfaces,
            "audit_usb_ids": config.adapters.audit_usb_ids,
            "training_usb_ids": config.adapters.ap_usb_ids,
        },
    }


@router.get("/modules")
async def modules(request: Request, refresh: bool = False) -> dict:
    return await request.app.state.capabilities.status(refresh=refresh)
