from fastapi import APIRouter, Request

from app.api.access_control import require_privileged_action
from app.models import TargetRequest

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/start")
async def start_scan(request: Request) -> dict:
    require_privileged_action(request)
    return await request.app.state.recon.start()


@router.post("/stop")
async def stop_scan(request: Request) -> dict:
    require_privileged_action(request)
    session = request.app.state.recon.current_session()
    return await request.app.state.recon.stop(session["id"]) if session else {"running": False}


@router.get("/status")
async def scan_status(request: Request) -> dict:
    result = await request.app.state.recon.live_status()
    result["selected_target"] = await request.app.state.app_state.target()
    return result


@router.post("/target")
async def select_target(body: TargetRequest, request: Request) -> dict:
    require_privileged_action(request)
    return {"selected_target": await request.app.state.app_state.set_target(body.target.model_dump())}
