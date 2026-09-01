import httpx
import pytest

from app.config import AppConfig
from app.main import app


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/api/scan/start"),
        ("post", "/api/captures/stop"),
        ("post", "/api/training-ap/stop"),
        ("delete", "/api/recon/history"),
    ],
)
async def test_mutating_routes_reject_training_network_and_unconfirmed_management_requests(method, path):
    app.state.config = AppConfig()
    transport = httpx.ASGITransport(app=app, client=("10.42.0.20", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://pinepi") as client:
        response = await getattr(client, method)(path, headers={"X-PinePi-Action": "confirmed"})
    assert response.status_code == 403

    transport = httpx.ASGITransport(app=app, client=("10.43.0.20", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://pinepi") as client:
        response = await getattr(client, method)(path)
    assert response.status_code == 403
