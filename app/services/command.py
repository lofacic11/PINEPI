from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass


class CommandError(RuntimeError):
    pass


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


async def run_command(
    *argv: str, timeout: float = 10.0, check: bool = True, input_text: str | None = None
) -> CommandResult:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"Required executable not found: {argv[0]}") from exc
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input_text.encode() if input_text is not None else None), timeout
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise CommandError(f"Command timed out after {timeout:g}s") from exc
    result = CommandResult(stdout.decode(errors="replace"), stderr.decode(errors="replace"), process.returncode)
    if check and result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        try:
            error_payload = json.loads(message)
            if isinstance(error_payload, dict) and error_payload.get("error"):
                message = str(error_payload["error"])
        except json.JSONDecodeError:
            pass
        raise CommandError(message)
    return result


async def json_command(*argv: str, timeout: float = 10.0, input_text: str | None = None) -> dict:
    result = await run_command(*argv, timeout=timeout, input_text=input_text)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CommandError("Helper returned invalid JSON") from exc
