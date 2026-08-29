import json

import httpx
import pytest
from pydantic import ValidationError

from app.config import AppConfig
from app.main import app
from app.models.schemas import APStartRequest


class CredentialService:
    async def credentials(self):
        return {
            "ssid": "PinePi Lab",
            "password": "pinepi-owned-test-password",
            "channel": 6,
            "notice": "Lab AP password — this is not the original network password.",
        }


@pytest.mark.asyncio
async def test_lab_credential_endpoint_is_limited_to_management_network():
    app.state.config = AppConfig()
    app.state.training_ap = CredentialService()
    allowed = httpx.ASGITransport(app=app, client=("10.43.0.20", 1234))
    denied = httpx.ASGITransport(app=app, client=("10.42.0.20", 1234))
    async with httpx.AsyncClient(transport=allowed, base_url="http://pinepi") as client:
        response = await client.get("/api/training-ap/credentials")
        assert response.status_code == 200
        assert response.json()["password"] == "pinepi-owned-test-password"
        assert "not the original" in response.json()["notice"]
    async with httpx.AsyncClient(transport=denied, base_url="http://pinepi") as client:
        response = await client.get("/api/training-ap/credentials", headers={"X-Forwarded-For": "10.43.0.20"})
        assert response.status_code == 403
        assert "password" not in response.text.lower()


@pytest.mark.asyncio
async def test_safe_settings_endpoint_never_returns_passwords():
    app.state.config = AppConfig()
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://pinepi") as client:
        response = await client.get("/api/settings")
        assert response.status_code == 200
        serialized = json.dumps(response.json()).lower()
        assert "password" not in serialized
        assert "change-me" not in serialized


def test_ap_request_validates_utf8_byte_lengths_and_controls():
    APStartRequest(ssid="Lab", password="safe-passphrase", channel=6)
    with pytest.raises(ValidationError):
        APStartRequest(ssid="é" * 32, password="safe-passphrase", channel=6)
    with pytest.raises(ValidationError):
        APStartRequest(ssid="Lab\nInjected", password="safe-passphrase", channel=6)
    with pytest.raises(ValidationError):
        APStartRequest(ssid="Lab", password="x" * 64, channel=6)
