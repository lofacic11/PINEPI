import ipaddress

from fastapi import APIRouter, HTTPException, Request

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


@router.get("/credentials")
async def ap_credentials(request: Request) -> dict:
    peer = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError as exc:
        raise HTTPException(403, "Lab AP credentials are available only from the Management network") from exc
    management_network = ipaddress.ip_interface(request.app.state.config.management_ap.address).network
    if not (address.is_loopback or address in management_network):
        raise HTTPException(403, "Lab AP credentials are available only from the Management network")
    return await request.app.state.training_ap.credentials()
