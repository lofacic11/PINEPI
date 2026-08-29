from typing import Literal

from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator


MAC_PATTERN = r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$"


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


class AuthorizedWirelessRequest(BaseModel):
    ssid: str = Field(default="", max_length=32)
    bssid: str = Field(pattern=MAC_PATTERN)
    channel: int = Field(ge=1, le=196)
    authorized: Literal[True]

    @field_validator("ssid")
    @classmethod
    def safe_observed_ssid(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value) or len(value.encode("utf-8")) > 32:
            raise ValueError("SSID must be at most 32 UTF-8 bytes without control characters")
        return value


class DeauthTestRequest(AuthorizedWirelessRequest):
    client: str | None = Field(default=None, pattern=MAC_PATTERN)
    bursts: int = Field(default=8, ge=1, le=128)
    runtime_seconds: int = Field(default=15, ge=1, le=60)

    @model_validator(mode="after")
    def normalize_addresses(self):
        self.bssid = self.bssid.upper()
        if self.client:
            self.client = self.client.upper()
        return self


class InjectionTestRequest(AuthorizedWirelessRequest):
    @model_validator(mode="after")
    def normalize_bssid(self):
        self.bssid = self.bssid.upper()
        return self


class Mdk4DeauthTestRequest(AuthorizedWirelessRequest):
    runtime_seconds: int = Field(default=10, ge=1, le=60)

    @model_validator(mode="after")
    def normalize_bssid(self):
        self.bssid = self.bssid.upper()
        return self


class MonitorModeRequest(BaseModel):
    channel: int | None = Field(default=None, ge=1, le=196)
