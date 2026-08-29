from fastapi import APIRouter, Request

from app.api.access_control import require_confirmed_action, require_management_client
from app.models import DeauthTestRequest, InjectionTestRequest, Mdk4DeauthTestRequest, MonitorModeRequest

router = APIRouter(prefix="/api/wireless-tools", tags=["wireless-tools"])


@router.post("/active/deauthentication", status_code=201)
async def start_deauthentication(body: DeauthTestRequest, request: Request) -> dict:
    require_confirmed_action(request)
    selected = await request.app.state.app_state.target()
    return await request.app.state.active_wireless.start_deauth(body, selected)


@router.get("/active/status")
async def active_status(request: Request) -> dict:
    require_management_client(request)
    return await request.app.state.active_wireless.status()


@router.post("/active/stop")
async def active_stop(request: Request) -> dict:
    require_confirmed_action(request)
    return await request.app.state.active_wireless.stop()


@router.post("/injection-test")
async def injection_test(body: InjectionTestRequest, request: Request) -> dict:
    require_confirmed_action(request)
    selected = await request.app.state.app_state.target()
    return await request.app.state.active_wireless.injection_test(body, selected)


@router.post("/active/mdk4-deauthentication", status_code=201)
async def start_mdk4_deauthentication(body: Mdk4DeauthTestRequest, request: Request) -> dict:
    require_confirmed_action(request)
    selected = await request.app.state.app_state.target()
    return await request.app.state.active_wireless.start_mdk4(body, selected)


@router.post("/monitor/enable")
async def monitor_enable(body: MonitorModeRequest, request: Request) -> dict:
    require_confirmed_action(request)
    return await request.app.state.active_wireless.monitor_enable(body.channel)


@router.post("/monitor/disable")
async def monitor_disable(request: Request) -> dict:
    require_confirmed_action(request)
    return await request.app.state.active_wireless.monitor_disable()


@router.get("/monitor/status")
async def monitor_status(request: Request) -> dict:
    require_management_client(request)
    return await request.app.state.active_wireless.monitor_status()


@router.get("/monitor/conflicts")
async def monitor_conflicts(request: Request) -> dict:
    require_management_client(request)
    return await request.app.state.active_wireless.monitor_conflicts()
