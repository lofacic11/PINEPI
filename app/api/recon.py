from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request

from app.api.access_control import require_privileged_action
from app.models import TrustedProfileRequest

router = APIRouter(prefix="/api/recon", tags=["recon"])


@router.post("/sessions", status_code=201)
async def start_session(request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.recon.start()


@router.get("/sessions")
async def sessions(request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict:
    return request.app.state.recon.sessions(limit, offset)


@router.get("/sessions/{session_id}")
async def session(session_id: UUID, request: Request) -> dict:
    value = request.app.state.recon.session(str(session_id))
    if not value:
        raise FileNotFoundError(session_id)
    return value


@router.post("/sessions/{session_id}/stop")
async def stop_session(session_id: UUID, request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.recon.stop(str(session_id))


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: UUID, request: Request) -> dict:
    require_privileged_action(request)
    request.app.state.recon.delete_session(str(session_id))
    return {"deleted": session_id}


@router.get("/live")
async def live(request: Request) -> dict:
    return await request.app.state.recon.live_status()


@router.get("/access-points")
async def access_points(
    request: Request,
    session_id: UUID | None = None,
    search: str = Query("", max_length=128),
    band: Literal["2.4 GHz", "5 GHz", "other", "unknown"] | None = None,
    security: Literal["Open", "WEP", "WPA", "WPA2", "WPA3", "Unknown"] | None = None,
    pmf: Literal["enabled", "disabled", "unknown"] | None = None,
    hidden: bool | None = None,
    visible: bool | None = None,
    has_clients: bool | None = None,
    min_signal: int | None = Query(None, ge=-120, le=0),
    max_signal: int | None = Query(None, ge=-120, le=0),
    sort: Literal["signal_desc", "signal_asc", "ssid", "channel", "security", "clients", "first_seen", "last_seen"] = "signal_desc",
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> dict:
    return request.app.state.recon.access_points(str(session_id) if session_id else None, search, band, security, pmf, hidden, visible, has_clients, min_signal, max_signal, sort, limit, offset)


@router.get("/access-points/{bssid}")
async def access_point(bssid: str, request: Request, session_id: UUID) -> dict:
    return request.app.state.recon.access_point(bssid, str(session_id))


@router.get("/clients")
async def clients(request: Request, session_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict:
    return request.app.state.recon.clients(str(session_id), limit, offset)


@router.get("/clients/{station_mac}")
async def client(station_mac: str, request: Request, session_id: UUID) -> dict:
    return request.app.state.recon.client(station_mac, str(session_id))


@router.get("/channels")
async def channels(request: Request, session_id: UUID) -> dict:
    return {"items": request.app.state.recon.channels(str(session_id)), "measurement": "Observed nearby AP count, not spectrum utilization"}


@router.get("/trusted")
async def trusted(request: Request) -> dict:
    return {"items": request.app.state.recon.trusted()}


@router.post("/trusted", status_code=201)
async def create_trusted(body: TrustedProfileRequest, request: Request) -> dict:
    require_privileged_action(request)
    return request.app.state.recon.add_trusted(body.ssid, body.approved_bssids, body.expected_security, body.expected_channels, body.expected_vendor)


@router.delete("/trusted/{profile_id}")
async def delete_trusted(profile_id: int, request: Request) -> dict:
    require_privileged_action(request)
    request.app.state.recon.delete_trusted(profile_id)
    return {"deleted": profile_id}


@router.delete("/history")
async def clear_history(request: Request) -> dict:
    require_privileged_action(request)
    request.app.state.recon.clear_history()
    return {"cleared": True}
