from __future__ import annotations

from app.config import AppConfig
import json

from app.services.command import json_command


class HelperClient:
    def __init__(self, config: AppConfig):
        self.config = config

    def argv(self, action: str, *arguments: str) -> tuple[str, ...]:
        prefix = ("sudo", "-n") if self.config.sudo else ()
        return (*prefix, self.config.helper, action, *arguments)

    async def call(
        self, action: str, *arguments: str, timeout: float | None = None, payload: dict | None = None
    ) -> dict:
        return await json_command(
            *self.argv(action, *arguments),
            timeout=timeout or self.config.command_timeout,
            input_text=json.dumps(payload) if payload is not None else None,
        )
