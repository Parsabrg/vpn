import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from nebula_api.auth.redis_state import (
    _CONSUME_PREAUTH_LUA,
    _GET_SESSION_LUA,
    _LOCKOUT_FAILURE_LUA,
    _LOCKOUT_STATUS_LUA,
    _RATE_LIMIT_LUA,
    _ROTATE_CSRF_LUA,
    _ROTATE_SESSION_LUA,
    _SET_HASH_WITH_TTL_LUA,
    AuthStateUnavailable,
    RateBucket,
    RedisAuthState,
    _datetime_from_ms,
    _decode_hash,
    _decode_text,
    _duration_ms,
    _session_record,
    _strict_integer,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ADMIN_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


class FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, int, tuple[object, ...]]] = []
        self.deleted: list[str] = []
        self.raise_error = False
        self.rate_result: object = 1
        self.lockout_status_result: object = 0
        self.lockout_failure_result: object = [0, 0]

    async def eval(self, script: str, numkeys: int, *values: object) -> Any:
        self.calls.append((script, numkeys, values))
        if self.raise_error:
            raise ConnectionError("canary redis unavailable")
        keys = [str(value) for value in values[:numkeys]]
        arguments = list(values[numkeys:])
        if script == _RATE_LIMIT_LUA:
            return self.rate_result
        if script == _LOCKOUT_STATUS_LUA:
            return self.lockout_status_result
        if script == _LOCKOUT_FAILURE_LUA:
            return self.lockout_failure_result
        if script == _SET_HASH_WITH_TTL_LUA:
            key = keys[0]
            if key in self.hashes:
                return 0
            fields = {
                str(arguments[index]): str(arguments[index + 1])
                for index in range(0, len(arguments) - 1, 2)
            }
            self.hashes[key] = fields
            return 1
        if script == _CONSUME_PREAUTH_LUA:
            fields = self.hashes.get(keys[0], {})
            if (
                fields.get("purpose") != arguments[0]
                or fields.get("context_digest") != arguments[1]
            ):
                return []
            self.hashes.pop(keys[0], None)
            return _flatten(fields)
        if script == _GET_SESSION_LUA:
            fields = self.hashes.get(keys[0], {})
            if fields:
                fields["last_seen_ms"] = str(arguments[0])
            return _flatten(fields)
        if script == _ROTATE_CSRF_LUA:
            fields = self.hashes.get(keys[0], {})
            if not fields or fields.get("csrf_digest") != arguments[2]:
                return 0
            fields["csrf_digest"] = str(arguments[3])
            return 1
        if script == _ROTATE_SESSION_LUA:
            try:
                fields = self.hashes.pop(keys[0])
            except KeyError:
                return []
            fields.update(
                session_id=str(arguments[2]),
                created_ms=str(arguments[0]),
                last_seen_ms=str(arguments[0]),
                step_up_ms=str(arguments[3]),
                csrf_digest=str(arguments[4]),
            )
            self.hashes[keys[1]] = fields
            return _flatten(fields)
        raise AssertionError("unexpected script")

    async def delete(self, *names: str) -> int:
        if self.raise_error:
            raise ConnectionError("canary redis unavailable")
        self.deleted.extend(names)
        return sum(self.hashes.pop(name, {}) != {} for name in names)


def _flatten(fields: dict[str, str]) -> list[bytes]:
    values: list[bytes] = []
    for key, value in fields.items():
        values.extend((key.encode(), value.encode()))
    return values


def make_state(client: FakeRedis) -> RedisAuthState:
    return RedisAuthState(client, key_ring={1: b"k" * 32}, current_key_version=1, clock=lambda: NOW)


def test_dual_bucket_rate_limit_uses_only_keyed_subjects() -> None:
    client = FakeRedis()
    state = make_state(client)

    allowed = asyncio.run(
        state.rate_limit(
            [
                RateBucket("admin-account", "owner@example.com"),
                RateBucket("network", "203.0.113.0/24"),
            ],
            limit=5,
            window_seconds=900,
        )
    )

    assert allowed
    _, number_of_keys, values = client.calls[-1]
    assert number_of_keys == 2
    rendered = " ".join(map(str, values))
    assert "owner@example.com" not in rendered
    assert "203.0.113.0" not in rendered


def test_rate_limit_and_lockout_fail_closed_on_bad_redis_results() -> None:
    client = FakeRedis()
    state = make_state(client)
    client.rate_result = b"corrupt"

    with pytest.raises(AuthStateUnavailable):
        asyncio.run(
            state.rate_limit([RateBucket("network", "unknown")], limit=1, window_seconds=60)
        )

    client.raise_error = True
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(state.lockout_status("admin-id"))


def test_preauth_is_context_bound_single_use_and_redacted() -> None:
    client = FakeRedis()
    state = make_state(client)
    challenge = asyncio.run(
        state.issue_preauth(
            admin_id=ADMIN_ID,
            purpose="login",
            context="203.0.113.0/24",
            ttl_seconds=300,
        )
    )

    assert challenge.token not in repr(challenge)
    assert (
        asyncio.run(
            state.consume_preauth(
                challenge.token,
                purpose="login",
                context="198.51.100.0/24",
            )
        )
        is None
    )
    consumed = asyncio.run(
        state.consume_preauth(
            challenge.token,
            purpose="login",
            context="203.0.113.0/24",
        )
    )
    assert consumed is not None and consumed.admin_id == ADMIN_ID
    assert (
        asyncio.run(
            state.consume_preauth(
                challenge.token,
                purpose="login",
                context="203.0.113.0/24",
            )
        )
        is None
    )


def test_admin_session_csrf_is_one_time_and_session_rotation_replaces_ids() -> None:
    client = FakeRedis()
    state = make_state(client)
    issued = asyncio.run(
        state.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="totp",
            idle_ttl=timedelta(minutes=30),
            absolute_ttl=timedelta(hours=8),
        )
    )

    assert issued.session_token not in repr(issued)
    assert issued.csrf_token not in repr(issued)
    loaded = asyncio.run(
        state.get_admin_session(
            issued.session_token,
            idle_ttl=timedelta(minutes=30),
        )
    )
    assert loaded is not None and loaded.session_id == issued.record.session_id

    replacement_csrf = asyncio.run(
        state.validate_and_rotate_csrf(
            issued.session_token,
            issued.csrf_token,
            idle_ttl=timedelta(minutes=30),
        )
    )
    assert replacement_csrf is not None
    assert (
        asyncio.run(
            state.validate_and_rotate_csrf(
                issued.session_token,
                issued.csrf_token,
                idle_ttl=timedelta(minutes=30),
            )
        )
        is None
    )

    rotated = asyncio.run(
        state.rotate_admin_session(
            issued.session_token,
            idle_ttl=timedelta(minutes=30),
            stepped_up=True,
        )
    )
    assert rotated is not None
    assert rotated.session_token != issued.session_token
    assert rotated.record.session_id != issued.record.session_id
    assert rotated.record.step_up_at == NOW
    assert (
        asyncio.run(state.get_admin_session(issued.session_token, idle_ttl=timedelta(minutes=30)))
        is None
    )


def test_admin_failure_lockout_boundaries_and_clear() -> None:
    client = FakeRedis()
    state = make_state(client)
    client.lockout_failure_result = [1, 15_000]

    result = asyncio.run(state.record_admin_failure("admin-id", threshold=5, lock_seconds=900))
    assert result.locked
    assert result.retry_after_seconds == 15

    asyncio.run(state.clear_admin_failures("admin-id"))
    assert client.deleted


def test_redis_state_rejects_invalid_keys_prefixes_and_policies() -> None:
    client = FakeRedis()
    with pytest.raises(ValueError, match="key ring"):
        RedisAuthState(client, key_ring={1: b"short"}, current_key_version=1)
    with pytest.raises(ValueError, match="prefix"):
        RedisAuthState(
            client,
            key_ring={1: b"k" * 32},
            current_key_version=1,
            prefix="bad prefix",
        )
    state = make_state(client)
    with pytest.raises(ValueError, match="rate-limit"):
        asyncio.run(state.rate_limit([], limit=1, window_seconds=60))
    with pytest.raises(ValueError, match="lockout"):
        asyncio.run(state.record_admin_failure("admin", threshold=1, lock_seconds=60))
    with pytest.raises(ValueError, match="pre-auth"):
        asyncio.run(
            state.issue_preauth(
                admin_id=ADMIN_ID,
                purpose="login",
                context="network",
                ttl_seconds=0,
            )
        )


def test_rate_limit_denial_and_redis_connection_errors_fail_closed() -> None:
    client = FakeRedis()
    state = make_state(client)
    client.rate_result = 0
    assert not asyncio.run(
        state.rate_limit([RateBucket("network", "unknown")], limit=1, window_seconds=60)
    )

    client.raise_error = True
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(
            state.rate_limit([RateBucket("network", "unknown")], limit=1, window_seconds=60)
        )
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(state.clear_admin_failures("admin"))


def test_lockout_status_and_corrupt_failure_results_are_bounded() -> None:
    client = FakeRedis()
    state = make_state(client)
    client.lockout_status_result = b"1001"
    status = asyncio.run(state.lockout_status("admin"))
    assert status.locked and status.retry_after_seconds == 2

    client.lockout_status_result = b"not-an-integer"
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.lockout_status("admin"))

    client.lockout_failure_result = [7, 10]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.record_admin_failure("admin", threshold=5, lock_seconds=60))
    client.lockout_failure_result = [1]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.record_admin_failure("admin", threshold=5, lock_seconds=60))


def test_malformed_tokens_do_not_reach_redis_and_session_errors_fail_closed() -> None:
    client = FakeRedis()
    state = make_state(client)

    assert asyncio.run(state.consume_preauth("bad", purpose="login", context="network")) is None
    assert asyncio.run(state.get_admin_session("bad", idle_ttl=timedelta(minutes=30))) is None
    assert (
        asyncio.run(state.validate_and_rotate_csrf("bad", "bad", idle_ttl=timedelta(minutes=30)))
        is None
    )
    assert (
        asyncio.run(
            state.rotate_admin_session("bad", idle_ttl=timedelta(minutes=30), stepped_up=False)
        )
        is None
    )
    asyncio.run(state.revoke_admin_session("bad"))

    issued = asyncio.run(
        state.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="recovery",
            idle_ttl=timedelta(minutes=30),
            absolute_ttl=timedelta(hours=8),
            stepped_up=True,
        )
    )
    client.raise_error = True
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(
            state.get_admin_session(
                issued.session_token,
                idle_ttl=timedelta(minutes=30),
            )
        )
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.revoke_admin_session(issued.session_token))


def test_session_policy_and_corrupt_script_results_are_rejected() -> None:
    client = FakeRedis()
    state = make_state(client)
    with pytest.raises(ValueError, match="duration"):
        asyncio.run(
            state.issue_admin_session(
                admin_id=ADMIN_ID,
                mfa_method="totp",
                idle_ttl=timedelta(0),
                absolute_ttl=timedelta(hours=1),
            )
        )
    with pytest.raises(ValueError, match="session policy"):
        asyncio.run(
            state.issue_admin_session(
                admin_id=ADMIN_ID,
                mfa_method="totp",
                idle_ttl=timedelta(hours=2),
                absolute_ttl=timedelta(hours=1),
            )
        )

    issued = asyncio.run(
        state.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="totp",
            idle_ttl=timedelta(minutes=30),
            absolute_ttl=timedelta(hours=1),
        )
    )
    original_eval = client.eval

    async def corrupt_csrf(script: str, numkeys: int, *values: object) -> Any:
        if script == _ROTATE_CSRF_LUA:
            return 7
        return await original_eval(script, numkeys, *values)

    client.eval = corrupt_csrf  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(
            state.validate_and_rotate_csrf(
                issued.session_token,
                issued.csrf_token,
                idle_ttl=timedelta(minutes=30),
            )
        )


def test_redis_decoders_reject_corruption_without_reflecting_values() -> None:
    assert _decode_hash(None) == {}
    assert _decode_hash(["key", "value"]) == {"key": "value"}
    assert _decode_text(b"text") == "text"
    assert _strict_integer(b"42") == 42
    assert _datetime_from_ms("0") == datetime.fromtimestamp(0, UTC)
    assert _duration_ms(timedelta(seconds=1)) == 1_000

    for value in (["odd"], 12):
        with pytest.raises(AuthStateUnavailable):
            _decode_hash(value)
    with pytest.raises(AuthStateUnavailable):
        _decode_text(b"\xff")
    with pytest.raises(AuthStateUnavailable):
        _decode_text(12)
    with pytest.raises(AuthStateUnavailable):
        _strict_integer(b"bad")
    with pytest.raises(ValueError):
        _datetime_from_ms("-1")
    with pytest.raises(ValueError, match="duration"):
        _duration_ms(timedelta(days=2))
    with pytest.raises(AuthStateUnavailable):
        _session_record({"mfa_method": "invalid"})


def test_preauth_rejects_corrupt_hashes_and_redis_errors() -> None:
    client = FakeRedis()
    state = make_state(client)
    challenge = asyncio.run(
        state.issue_preauth(
            admin_id=ADMIN_ID,
            purpose="login",
            context="network",
            ttl_seconds=300,
        )
    )
    original_eval = client.eval

    async def corrupt_preauth(script: str, numkeys: int, *values: object) -> Any:
        if script == _CONSUME_PREAUTH_LUA:
            return [b"admin_id", b"not-a-uuid", b"purpose", b"login"]
        return await original_eval(script, numkeys, *values)

    client.eval = corrupt_preauth  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.consume_preauth(challenge.token, purpose="login", context="network"))

    async def mismatched_preauth(script: str, numkeys: int, *values: object) -> Any:
        if script == _CONSUME_PREAUTH_LUA:
            return [b"admin_id", str(ADMIN_ID).encode(), b"purpose", b"enroll"]
        return await original_eval(script, numkeys, *values)

    client.eval = mismatched_preauth  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state.consume_preauth(challenge.token, purpose="login", context="network"))

    async def broken_preauth(script: str, numkeys: int, *values: object) -> Any:
        if script == _CONSUME_PREAUTH_LUA:
            raise ConnectionError("canary redis unavailable")
        return await original_eval(script, numkeys, *values)

    client.eval = broken_preauth  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(state.consume_preauth(challenge.token, purpose="login", context="network"))


def test_session_rotation_and_csrf_corruption_fail_closed() -> None:
    client = FakeRedis()
    state = make_state(client)
    issued = asyncio.run(
        state.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="totp",
            idle_ttl=timedelta(minutes=30),
            absolute_ttl=timedelta(hours=1),
        )
    )

    assert (
        asyncio.run(
            state.validate_and_rotate_csrf(
                issued.session_token,
                "malformed",
                idle_ttl=timedelta(minutes=30),
            )
        )
        is None
    )

    original_eval = client.eval

    async def corrupt_csrf(script: str, numkeys: int, *values: object) -> Any:
        if script == _ROTATE_CSRF_LUA:
            return b"not-an-integer"
        return await original_eval(script, numkeys, *values)

    client.eval = corrupt_csrf  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(
            state.validate_and_rotate_csrf(
                issued.session_token,
                issued.csrf_token,
                idle_ttl=timedelta(minutes=30),
            )
        )

    async def missing_rotation(script: str, numkeys: int, *values: object) -> Any:
        if script == _ROTATE_SESSION_LUA:
            return []
        return await original_eval(script, numkeys, *values)

    client.eval = missing_rotation  # type: ignore[method-assign]
    assert (
        asyncio.run(
            state.rotate_admin_session(
                issued.session_token,
                idle_ttl=timedelta(minutes=30),
                stepped_up=False,
            )
        )
        is None
    )

    async def corrupt_rotation(script: str, numkeys: int, *values: object) -> Any:
        if script == _ROTATE_SESSION_LUA:
            return [b"odd"]
        return await original_eval(script, numkeys, *values)

    client.eval = corrupt_rotation  # type: ignore[method-assign]
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(
            state.rotate_admin_session(
                issued.session_token,
                idle_ttl=timedelta(minutes=30),
                stepped_up=False,
            )
        )


def test_hash_creation_lockout_and_key_helpers_fail_closed() -> None:
    client = FakeRedis()
    state = make_state(client)

    asyncio.run(state._set_hash_once("fixed-key", {"field": "value"}, ttl_seconds=60))
    with pytest.raises(AuthStateUnavailable):
        asyncio.run(state._set_hash_once("fixed-key", {"field": "value"}, ttl_seconds=60))

    client.raise_error = True
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(state.record_admin_failure("admin", threshold=5, lock_seconds=60))
    with pytest.raises(AuthStateUnavailable, match="unavailable"):
        asyncio.run(state._set_hash_once("another-key", {"field": "value"}, ttl_seconds=60))

    with pytest.raises(ValueError, match="key input"):
        state._derived_key("INVALID", "subject")
    with pytest.raises(ValueError, match="key input"):
        state._derived_key("valid", "")
    with pytest.raises(ValueError, match="digest key"):
        state._digest_key("INVALID", b"d" * 32)
    with pytest.raises(ValueError, match="digest key"):
        state._digest_key("valid", b"short")

    naive_clock_state = RedisAuthState(
        FakeRedis(),
        key_ring={1: b"k" * 32},
        current_key_version=1,
        clock=lambda: datetime(2026, 7, 20, 12, 0),
    )
    with pytest.raises(ValueError, match="timezone aware"):
        naive_clock_state._now()

    with pytest.raises(AuthStateUnavailable):
        _strict_integer("42")
