from __future__ import annotations

import ipaddress

from fastapi import HTTPException, Request


def require_management_client(request: Request) -> None:
    """Authorize by direct peer only; forwarded headers are deliberately ignored."""
    peer = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError as exc:
        raise HTTPException(403, "This operation is available only from the Management network") from exc
    management_network = ipaddress.ip_interface(request.app.state.config.management_ap.address).network
    if not (address.is_loopback or address in management_network):
        raise HTTPException(403, "This operation is available only from the Management network")


def require_confirmed_action(request: Request) -> None:
    require_management_client(request)
    if request.headers.get("X-PinePi-Action") != "confirmed":
        raise HTTPException(403, "A confirmed PinePi browser action is required")
