from pydantic import BaseModel, Field, field_validator


class ScanTarget(BaseModel):
    ssid: str = Field(max_length=32)
    bssid: str = Field(pattern=r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
    channel: int = Field(ge=1, le=196)
    privacy: str = Field(default="", max_length=80)
    cipher: str = Field(default="", max_length=80)
    authentication: str = Field(default="", max_length=80)


class TargetRequest(BaseModel):
    target: ScanTarget


class APStartRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=8, max_length=63)
    channel: int = Field(ge=1, le=13)

    @field_validator("ssid", "password")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("control characters are not allowed")
        return value

