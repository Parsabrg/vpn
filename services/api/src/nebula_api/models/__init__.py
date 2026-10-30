"""Import every model so SQLAlchemy and Alembic see the complete schema."""

from nebula_api.models.approval import (
    AccountRequest,
    AccountRequestEvent,
    PasswordResetToken,
    UserActivation,
)
from nebula_api.models.deployment import Deployment
from nebula_api.models.enrollment import NodeEnrollmentToken
from nebula_api.models.identity import (
    AdminMfaRecoveryCode,
    AdminTotpCredential,
    AdminUser,
    Device,
    RefreshToken,
    User,
    UserSession,
)
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
from nebula_api.models.usage import CredentialUsage

__all__ = [
    "AccountRequest",
    "AccountRequestEvent",
    "AdminMfaRecoveryCode",
    "AdminTotpCredential",
    "AdminUser",
    "AgentOperation",
    "AuditLog",
    "CredentialUsage",
    "Deployment",
    "Device",
    "DeviceProtocolCredential",
    "EmailDelivery",
    "NodeEnrollmentToken",
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
