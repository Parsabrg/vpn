"""Closed vocabularies shared by persistence and domain validation."""

from enum import StrEnum


class AccountState(StrEnum):
    PENDING_ACTIVATION = "pending_activation"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class AdminState(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class AdminRole(StrEnum):
    OWNER = "owner"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class DevicePlatform(StrEnum):
    ANDROID = "android"
    WINDOWS = "windows"


class LifecycleState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class TokenState(StrEnum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RequestState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ProtocolEngine(StrEnum):
    NATIVE_WIREGUARD = "native_wireguard"
    XRAY = "xray"


class ProfileState(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    IMPLEMENTED = "implemented"
    DEPRECATED = "deprecated"


class ServerState(StrEnum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DISABLED = "disabled"


class CapabilityState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class ProvisioningState(StrEnum):
    REQUESTED = "requested"
    APPLYING = "applying"
    ACTIVE = "active"
    REVOKING = "revoking"
    REVOKED = "revoked"
    FAILED = "failed"


class OperationState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


def values(enum_type: type[StrEnum]) -> tuple[str, ...]:
    """Return stable string values for SQL CHECK constraints."""

    return tuple(item.value for item in enum_type)
