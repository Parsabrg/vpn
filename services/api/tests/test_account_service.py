import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from nebula_api.account.service import (
    AccountService,
    DeviceRevocationRefused,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.models.operations import AuditLog
from nebula_api.models.provisioning import DeviceProtocolCredential, XrayClient
from nebula_api.models.types import (
    AccountState,
    DevicePlatform,
    LifecycleState,
    ProvisioningState,
)
from nebula_api.usage.service import AccountUsage, UsageService

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
THIS_DEVICE = UUID("22222222-2222-4222-8222-222222222222")
OTHER_DEVICE = UUID("33333333-3333-4333-8333-333333333333")


class ScriptedSession:
    """Queues answers in call order.

    Written here rather than reusing the one in `test_access_service` because
    that fake's `execute` returns mappings, and this service reads two-column
    rows it unpacks as tuples.
    """

    def __init__(
        self,
        *,
        scalars_results: Iterable[Iterable[object]] = (),
        scalar_values: Iterable[object] = (),
        execute_rows: Iterable[Iterable[tuple[object, ...]]] = (),
    ) -> None:
        self._scalars_results = [list(rows) for rows in scalars_results]
        self._scalar_values = list(scalar_values)
        self._execute_rows = [list(rows) for rows in execute_rows]
        self.added: list[object] = []
        self.commits = 0

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        return self._scalar_values.pop(0) if self._scalar_values else None

    async def scalars(self, _statement: object) -> Any:
        rows = self._scalars_results.pop(0) if self._scalars_results else []
        return _Scalars(rows)

    async def execute(self, _statement: object, _params: object = None) -> Any:
        rows = self._execute_rows.pop(0) if self._execute_rows else []
        return _Rows(rows)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1


class _Scalars:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


class _Rows:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[object, ...]]:
        return self._rows


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        return self.sessions.pop(0)


class StubUsage:
    """The account service asks usage for a total; these tests are about the
    account fields, so it answers a fixed, unmetered zero."""

    def __init__(self, usage: AccountUsage | None = None) -> None:
        self._usage = usage or AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=None)

    async def usage_for_user(self, _user_id: UUID) -> AccountUsage:
        return self._usage


def service(factory: ScriptedFactory, usage: AccountUsage | None = None) -> AccountService:
    return AccountService(cast(SessionFactory, factory), cast(UsageService, StubUsage(usage)))


def user(**overrides: object) -> User:
    defaults: dict[str, object] = dict(
        id=USER_ID,
        email="owner@example.org",
        email_normalized="owner@example.org",
        username="parsa",
        username_normalized="parsa",
        state=AccountState.ACTIVE,
        device_limit=5,
        expires_at=None,
        created_at=NOW,
    )
    defaults.update(overrides)
    return User(**defaults)


def device(**overrides: object) -> Device:
    defaults: dict[str, object] = dict(
        id=OTHER_DEVICE,
        user_id=USER_ID,
        name="Pixel 8",
        platform=DevicePlatform.ANDROID,
        client_version="0.1.6",
        state=LifecycleState.ACTIVE,
        created_at=NOW,
    )
    defaults.update(overrides)
    return Device(**defaults)


class TestGetAccount:
    def test_returns_the_account_with_its_device_count(self) -> None:
        session = ScriptedSession(scalar_values=[user(), 3])
        entry = asyncio.run(service(ScriptedFactory(session)).get_account(USER_ID))

        assert entry is not None
        assert entry.email == "owner@example.org"
        assert entry.username == "parsa"
        assert entry.device_limit == 5
        assert entry.devices_in_use == 3

    def test_absent_expiry_is_none_not_a_date(self) -> None:
        # The client must be able to tell "no expiry set" from "expired", and
        # a sentinel date would make those indistinguishable.
        session = ScriptedSession(scalar_values=[user(expires_at=None), 1])
        entry = asyncio.run(service(ScriptedFactory(session)).get_account(USER_ID))

        assert entry is not None
        assert entry.expires_at is None

    def test_a_missing_user_is_none_rather_than_an_empty_account(self) -> None:
        session = ScriptedSession(scalar_values=[None])
        assert asyncio.run(service(ScriptedFactory(session)).get_account(USER_ID)) is None


class TestListDevices:
    def test_marks_the_calling_device_as_current(self) -> None:
        session = ScriptedSession(
            scalars_results=[[device(id=THIS_DEVICE), device(id=OTHER_DEVICE)]],
            execute_rows=[[]],
        )
        entries = asyncio.run(service(ScriptedFactory(session)).list_devices(USER_ID, THIS_DEVICE))

        assert [entry.is_current for entry in entries] == [True, False]

    def test_reports_the_servers_a_device_holds_credentials_on(self) -> None:
        session = ScriptedSession(
            scalars_results=[[device(id=OTHER_DEVICE)]],
            execute_rows=[
                [
                    (OTHER_DEVICE, "nl-ams-1"),
                    (OTHER_DEVICE, "de-fra-1"),
                    # The same server twice, because a device can hold both a
                    # WireGuard peer and an Xray client there.
                    (OTHER_DEVICE, "de-fra-1"),
                ]
            ],
        )
        entries = asyncio.run(service(ScriptedFactory(session)).list_devices(USER_ID, THIS_DEVICE))

        assert entries[0].server_codes == ["de-fra-1", "nl-ams-1"]

    def test_a_device_with_no_credentials_reports_an_empty_list(self) -> None:
        # Registered but provisioned nothing is a real state, and the screen
        # says so rather than showing a server that is not there.
        session = ScriptedSession(scalars_results=[[device(id=OTHER_DEVICE)]], execute_rows=[[]])
        entries = asyncio.run(service(ScriptedFactory(session)).list_devices(USER_ID, THIS_DEVICE))

        assert entries[0].server_codes == []


class TestRevokeDevice:
    def test_refuses_the_device_making_the_request(self) -> None:
        # Revoking the device you are holding drops your own tunnel and leaves
        # you signed in against a device row that is gone. Refused before any
        # session is opened, so the factory is deliberately empty: touching
        # the database at all would be a bug.
        with pytest.raises(DeviceRevocationRefused) as refusal:
            asyncio.run(
                service(ScriptedFactory()).revoke_device(
                    user_id=USER_ID,
                    device_id=THIS_DEVICE,
                    current_device_id=THIS_DEVICE,
                    request_id=uuid4(),
                )
            )
        assert refusal.value.reason_code == "cannot_revoke_current_device"

    def test_another_users_device_is_not_found_rather_than_forbidden(self) -> None:
        # The query is scoped by user_id, so someone else's device id simply
        # misses. Reporting "forbidden" would confirm the id exists.
        session = ScriptedSession(scalar_values=[None])
        with pytest.raises(DeviceRevocationRefused) as refusal:
            asyncio.run(
                service(ScriptedFactory(session)).revoke_device(
                    user_id=USER_ID,
                    device_id=OTHER_DEVICE,
                    current_device_id=THIS_DEVICE,
                    request_id=uuid4(),
                )
            )
        assert refusal.value.reason_code == "not_found"
        assert session.commits == 0

    def test_revoking_twice_is_refused_rather_than_silently_repeated(self) -> None:
        session = ScriptedSession(scalar_values=[device(state=LifecycleState.REVOKED)])
        with pytest.raises(DeviceRevocationRefused) as refusal:
            asyncio.run(
                service(ScriptedFactory(session)).revoke_device(
                    user_id=USER_ID,
                    device_id=OTHER_DEVICE,
                    current_device_id=THIS_DEVICE,
                    request_id=uuid4(),
                )
            )
        assert refusal.value.reason_code == "already_revoked"
        assert session.commits == 0

    def test_revokes_the_device_and_its_live_credentials(self) -> None:
        # The credential is the part that matters. A device row marked revoked
        # while its Xray client keeps authenticating is exactly the bug the
        # admin-side revocation was fixed for.
        target = device(id=OTHER_DEVICE)
        profile_id = uuid4()
        server_id = uuid4()
        credential = DeviceProtocolCredential(
            id=uuid4(),
            device_id=OTHER_DEVICE,
            protocol_profile_id=profile_id,
            vpn_server_id=server_id,
            kind="xray_uuid",
            state=ProvisioningState.ACTIVE.value,
            issued_at=NOW,
            created_at=NOW,
        )
        client = XrayClient(
            id=uuid4(),
            credential_id=credential.id,
            device_id=OTHER_DEVICE,
            protocol_profile_id=profile_id,
            vpn_server_id=server_id,
            opaque_label="label",
            state=ProvisioningState.ACTIVE.value,
            created_at=NOW,
        )
        session = ScriptedSession(
            # device, then the credential looked up for the Xray client
            scalar_values=[target, credential],
            # WireGuard peers (none), then Xray clients (one)
            scalars_results=[[], [client]],
        )

        asyncio.run(
            service(ScriptedFactory(session)).revoke_device(
                user_id=USER_ID,
                device_id=OTHER_DEVICE,
                current_device_id=THIS_DEVICE,
                request_id=uuid4(),
            )
        )

        assert target.state == LifecycleState.REVOKED
        assert target.revoked_at is not None
        # REVOKING, not REVOKED: reconciliation drives it through the agent
        # and retries, so an unreachable agent delays revocation instead of
        # losing it.
        assert client.state == ProvisioningState.REVOKING.value
        assert credential.state == ProvisioningState.REVOKING.value
        assert session.commits == 1

    def test_writes_an_audit_event_naming_the_user_as_actor(self) -> None:
        target = device(id=OTHER_DEVICE)
        session = ScriptedSession(scalar_values=[target], scalars_results=[[], []])

        asyncio.run(
            service(ScriptedFactory(session)).revoke_device(
                user_id=USER_ID,
                device_id=OTHER_DEVICE,
                current_device_id=THIS_DEVICE,
                request_id=uuid4(),
            )
        )

        events = [item for item in session.added if isinstance(item, AuditLog)]
        assert len(events) == 1
        assert events[0].actor_kind == "user"
        assert events[0].actor_id == USER_ID
        assert events[0].target_kind == "device"
        assert events[0].target_id == OTHER_DEVICE
        assert events[0].event_code == "device_state_changed"


class TestAccountUsageFields:
    def test_reports_the_usage_the_service_returns(self) -> None:
        session = ScriptedSession(scalar_values=[user(), 1])
        entry = asyncio.run(
            service(
                ScriptedFactory(session),
                AccountUsage(rx_bytes=100, tx_bytes=200, quota_bytes=1000),
            ).get_account(USER_ID)
        )

        assert entry is not None
        assert entry.used_bytes == 300
        assert entry.quota_bytes == 1000
        assert entry.remaining_bytes == 700

    def test_lifetime_keeps_what_an_allowance_grant_started_over(self) -> None:
        # "Used" is measured from where the current allowance began; the
        # account screen's all-time figure must not be.
        session = ScriptedSession(scalar_values=[user(), 1])
        entry = asyncio.run(
            service(
                ScriptedFactory(session),
                AccountUsage(rx_bytes=600, tx_bytes=400, quota_bytes=None, baseline_bytes=900),
            ).get_account(USER_ID)
        )

        assert entry is not None
        assert entry.used_bytes == 100
        assert entry.lifetime_bytes == 1000

    def test_an_unmetered_account_reports_no_remainder(self) -> None:
        # Not zero, and not a huge number: the client renders "no limit"
        # differently from "none left".
        session = ScriptedSession(scalar_values=[user(), 1])
        entry = asyncio.run(
            service(
                ScriptedFactory(session),
                AccountUsage(rx_bytes=5, tx_bytes=5, quota_bytes=None),
            ).get_account(USER_ID)
        )

        assert entry is not None
        assert entry.used_bytes == 10
        assert entry.quota_bytes is None
        assert entry.remaining_bytes is None
