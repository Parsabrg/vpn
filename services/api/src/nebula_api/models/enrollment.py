"""Tokens that let a new VPN node join this deployment, once.

A node cannot authenticate before it has an identity, and it cannot have an
identity before it authenticates. An enrollment token is the way out of that:
an administrator mints one, it travels to the new VPS by whatever means the
operator already trusts, and the node exchanges it for a certificate.

Everything about the shape here follows from that being a bearer credential
in transit:

  - stored as a keyed digest, never as the token. A database dump, a backup,
    or a stray query result must not contain something that can enrol a node.
    The same treatment every other opaque token in this system gets.
  - single use. The exchange that redeems it is the moment it stops working,
    so a token read from a shell history or a chat log afterwards is inert.
  - short-lived by default. An unused token is a standing invitation, and the
    window it is genuinely needed in is minutes.
  - revocable without being used, because the usual reason to revoke one is
    that it went somewhere it should not have.

It grants exactly one thing: a certificate for one node. It is not a
credential for the API, cannot read anything, and cannot be exchanged twice.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from nebula_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class NodeEnrollmentToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One invitation for one node to obtain its certificate."""

    __tablename__ = "node_enrollment_tokens"
    __table_args__ = (
        CheckConstraint("length(label) BETWEEN 1 AND 64", name="label_length"),
        CheckConstraint("expires_at > created_at", name="expiry_after_issue"),
        CheckConstraint("used_at IS NULL OR used_at >= created_at", name="use_after_issue"),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at", name="revocation_after_issue"
        ),
        # A token that was both used and revoked is not a state anything here
        # produces, and if one appeared it would mean the single-use check and
        # the revocation check disagree about what happened.
        CheckConstraint("used_at IS NULL OR revoked_at IS NULL", name="used_or_revoked_not_both"),
        # The lookup the enrollment endpoint makes on every attempt.
        Index("ix_node_enrollment_tokens_digest", "token_digest"),
    )

    # What this node will be called once it joins. Chosen when the token is
    # minted rather than by the node, so a node cannot name itself something
    # that already exists and take over that record.
    label: Mapped[str] = mapped_column(String(64), nullable=False)

    # HMAC of the token under the deployment's token pepper, exactly as every
    # other opaque token here is stored. The pepper is per-deployment, so a
    # token minted by one installation cannot verify against another even if
    # the databases were somehow merged.
    token_digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Set at the moment the token is exchanged. The row is kept rather than
    # deleted: an operator asking "was that token ever used, and when" is
    # asking a security question, and a missing row answers it ambiguously.
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Which server this token produced, once redeemed. Null while outstanding.
    vpn_server_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("vpn_servers.id", ondelete="SET NULL")
    )

    # Who minted it. Null when it came from the command line, which is how the
    # first node of a fresh installation is enrolled -- before there is
    # necessarily an administrator to attribute it to.
    created_by_admin_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("admin_users.id", ondelete="SET NULL")
    )

    def is_redeemable(self, *, now: datetime) -> bool:
        """Whether this token can still be exchanged.

        All three conditions in one place, because the endpoint must not be
        able to check two of them and forget the third -- and because each
        needs to be indistinguishable from the others to the caller. A
        response that said "expired" rather than "unknown" would tell somebody
        probing with guessed tokens that they had found a real one.
        """

        return self.used_at is None and self.revoked_at is None and self.expires_at > now
