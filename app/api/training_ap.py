from fastapi import APIRouter, Request

from app.models import APStartRequest

router = APIRouter(prefix="/api/training-ap", tags=["training-ap"])


@router.post("/start")
async def start_ap(body: APStartRequest, request: Request) -> dict:
    return await request.app.state.training_ap.start(body.ssid, body.password, body.channel)


@router.post("/stop")
async def stop_ap(request: Request) -> dict:
    return await request.app.state.training_ap.stop()


@router.get("/status")
async def ap_status(request: Request) -> dict:
    result = await request.app.state.training_ap.status()
    result["selected_target"] = await request.app.state.app_state.target()
    return result

