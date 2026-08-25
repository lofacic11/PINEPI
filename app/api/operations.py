from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/operations", tags=["operations"])


@router.get("")
async def operations(request: Request, limit: int = Query(20, ge=1, le=100)) -> dict:
    return {"items": request.app.state.processes.history(limit)}
