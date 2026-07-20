"""Import every model so SQLAlchemy and Alembic see the complete schema."""

from nebula_api.models.approval import (
    AccountRequest,
    AccountRequestEvent,
    PasswordResetToken,
    UserActivation,
)
from nebula_api.models.identity import AdminUser, Device, RefreshToken, User, UserSession
from nebula_api.models.operations import (
    AgentOperation,
    AuditLog,
    EmailDelivery,
    ReconciliationRecord,
    ServerHealth,
    Setting,
)
from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ProtocolProfilePlatform,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)

__all__ = [
    "AccountRequest",
    "AccountRequestEvent",
    "AdminUser",
    "AgentOperation",
    "AuditLog",
    "Device",
    "DeviceProtocolCredential",
    "EmailDelivery",
    "PasswordResetToken",
    "Protocol",
    "ProtocolProfile",
    "ProtocolProfilePlatform",
    "ReconciliationRecord",
    "RefreshToken",
    "ServerHealth",
    "ServerProtocolCapability",
    "Setting",
    "User",
    "UserActivation",
    "UserProtocolPermission",
    "UserServerAssignment",
    "UserSession",
    "VPNServer",
    "WireGuardPeer",
    "XrayClient",
]
