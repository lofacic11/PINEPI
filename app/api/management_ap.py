from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/management-ap", tags=["management-ap"])


@router.get("/status")
async def management_status(request: Request) -> dict:
    return await request.app.state.management_ap.status()
