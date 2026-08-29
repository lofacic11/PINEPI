from pydantic import BaseModel, Field, ValidationInfo, field_validator


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
    def no_control_characters(cls, value: str, info: ValidationInfo) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("control characters are not allowed")
        byte_length = len(value.encode("utf-8"))
        minimum, maximum = (1, 32) if info.field_name == "ssid" else (8, 63)
        if not minimum <= byte_length <= maximum:
            raise ValueError(f"{info.field_name} must be {minimum}–{maximum} UTF-8 bytes")
        return value


class TrustedProfileRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=128)
    approved_bssids: list[str] = Field(default_factory=list, max_length=64)
    expected_security: str = Field(default="", max_length=80)
    expected_channels: list[int] = Field(default_factory=list, max_length=64)
    expected_vendor: str = Field(default="", max_length=160)

    @field_validator("ssid", "expected_security", "expected_vendor")
    @classmethod
    def reject_controls(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("control characters are not allowed")
        return value
