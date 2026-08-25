from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("")
async def system_status(request: Request) -> dict:
    return await request.app.state.system_service.status()


@router.get("/status")
async def detailed_system_status(request: Request) -> dict:
    return await request.app.state.system_service.status()


@router.get("/adapters")
async def adapters(request: Request) -> dict:
    return {"items": (await request.app.state.system_service.status())["interfaces"]}
