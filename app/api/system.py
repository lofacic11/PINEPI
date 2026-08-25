from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("")
async def system_status(request: Request) -> dict:
    return await request.app.state.system_service.status()

