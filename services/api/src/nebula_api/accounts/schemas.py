"""Strict, bounded HTTP contracts for account-request and activation flows."""

from datetime import datetime
from uuid import UUID

from pydantic import Field, SecretStr, field_validator

from nebula_api.auth.schemas import AuthModel, _bounded_password
from nebula_api.identity import normalize_username
from nebula_api.models.types import RequestState


class AccountRequestSubmitRequest(AuthModel):
    email: str = Field(min_length=3, max_length=320)
    username: str | None = Field(default=None, min_length=3, max_length=32)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            normalize_username(value)
        except ValueError as error:
            raise ValueError(str(error)) from error
        return value


class ActivationConfirmRequest(AuthModel):
    token: SecretStr = Field(min_length=10, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=1024)

    _password_size = field_validator("new_password")(_bounded_password)


class AccountRequestDecisionRequest(AuthModel):
    reason: str | None = Field(default=None, max_length=64)


class AccountRequestListItem(AuthModel):
    id: UUID
    email: str
    username: str | None
    state: RequestState
    created_at: datetime


class AccountRequestListResponse(AuthModel):
    items: list[AccountRequestListItem]
