"""Atomic, fail-closed Redis state for abuse controls and administrator sessions."""

import hashlib
import hmac
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid4

from nebula_api.auth.opaque_tokens import digest_opaque_token, issue_opaque_token

Clock = Callable[[], datetime]
Purpose = Literal["login", "enroll", "step-up"]

_NAMESPACE_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_PREFIX = "nebula:auth:v1"

_RATE_LIMIT_LUA = """
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local allowed = 1
for i, key in ipairs(KEYS) do
  local count = redis.call('INCR', key)
  local ttl = redis.call('PTTL', key)
  if count == 1 or ttl < 0 then redis.call('PEXPIRE', key, window) end
  if count > limit then allowed = 0 end
end
return allowed
"""

_LOCKOUT_STATUS_LUA = """
local until_ms = tonumber(redis.call('HGET', KEYS[1], 'locked_until_ms') or '0')
local now_ms = tonumber(ARGV[1])
if until_ms > now_ms then return until_ms - now_ms end
if until_ms > 0 then redis.call('DEL', KEYS[1]) end
return 0
"""

_LOCKOUT_FAILURE_LUA = """
local now_ms = tonumber(ARGV[1])
local threshold = tonumber(ARGV[2])
local lock_ms = tonumber(ARGV[3])
local until_ms = tonumber(redis.call('HGET', KEYS[1], 'locked_until_ms') or '0')
if until_ms > now_ms then return {1, until_ms - now_ms} end
local failures = tonumber(redis.call('HGET', KEYS[1], 'failures') or '0') + 1
if failures >= threshold then
  until_ms = now_ms + lock_ms
  redis.call('HSET', KEYS[1], 'failures', threshold, 'locked_until_ms', until_ms)
  redis.call('PEXPIRE', KEYS[1], lock_ms)
  return {1, lock_ms}
end
redis.call('HSET', KEYS[1], 'failures', failures, 'locked_until_ms', 0)
redis.call('PEXPIRE', KEYS[1], lock_ms)
return {0, 0}
"""

_SET_HASH_WITH_TTL_LUA = """
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
for i = 1, #ARGV - 1, 2 do redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1]) end
redis.call('PEXPIRE', KEYS[1], ARGV[#ARGV])
return 1
"""

_CONSUME_PREAUTH_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
if redis.call('HGET', KEYS[1], 'purpose') ~= ARGV[1] then return {} end
if redis.call('HGET', KEYS[1], 'context_digest') ~= ARGV[2] then return {} end
local values = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
return values
"""

_GET_SESSION_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local now_ms = tonumber(ARGV[1])
local idle_ms = tonumber(ARGV[2])
local absolute_ms = tonumber(redis.call('HGET', KEYS[1], 'absolute_expires_ms') or '0')
if absolute_ms <= now_ms then redis.call('DEL', KEYS[1]); return {} end
local ttl = math.min(idle_ms, absolute_ms - now_ms)
redis.call('HSET', KEYS[1], 'last_seen_ms', now_ms)
redis.call('PEXPIRE', KEYS[1], ttl)
return redis.call('HGETALL', KEYS[1])
"""

_ROTATE_CSRF_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local now_ms = tonumber(ARGV[1])
local idle_ms = tonumber(ARGV[2])
local absolute_ms = tonumber(redis.call('HGET', KEYS[1], 'absolute_expires_ms') or '0')
if absolute_ms <= now_ms then redis.call('DEL', KEYS[1]); return 0 end
if redis.call('HGET', KEYS[1], 'csrf_digest') ~= ARGV[3] then return 0 end
redis.call('HSET', KEYS[1], 'csrf_digest', ARGV[4], 'last_seen_ms', now_ms)
redis.call('PEXPIRE', KEYS[1], math.min(idle_ms, absolute_ms - now_ms))
return 1
"""

_ROTATE_SESSION_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 or redis.call('EXISTS', KEYS[2]) == 1 then return {} end
local now_ms = tonumber(ARGV[1])
local idle_ms = tonumber(ARGV[2])
local absolute_ms = tonumber(redis.call('HGET', KEYS[1], 'absolute_expires_ms') or '0')
if absolute_ms <= now_ms then redis.call('DEL', KEYS[1]); return {} end
local admin_id = redis.call('HGET', KEYS[1], 'admin_id')
local mfa_method = redis.call('HGET', KEYS[1], 'mfa_method')
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[2],
  'admin_id', admin_id,
  'session_id', ARGV[3],
  'created_ms', now_ms,
  'last_seen_ms', now_ms,
  'absolute_expires_ms', absolute_ms,
  'mfa_method', mfa_method,
  'step_up_ms', ARGV[4],
  'csrf_digest', ARGV[5])
redis.call('PEXPIRE', KEYS[2], math.min(idle_ms, absolute_ms - now_ms))
return redis.call('HGETALL', KEYS[2])
"""


class RedisClient(Protocol):
    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> Any: ...

    async def delete(self, *names: str) -> int: ...


class AuthStateUnavailable(RuntimeError):
    """Raised when abuse controls or privileged-session state cannot be trusted."""


@dataclass(frozen=True, slots=True)
class RateBucket:
    namespace: str
    subject: str


@dataclass(frozen=True, slots=True)
class LockoutState:
    locked: bool
    retry_after_seconds: int


@dataclass(frozen=True, slots=True, repr=False)
class PreAuthChallenge:
    token: str
    expires_in_seconds: int

    def __repr__(self) -> str:
        return "PreAuthChallenge(token=<redacted>)"


@dataclass(frozen=True, slots=True)
class ConsumedPreAuth:
    admin_id: UUID
    purpose: Purpose


@dataclass(frozen=True, slots=True)
class AdminSessionRecord:
    admin_id: UUID
    session_id: UUID
    mfa_method: Literal["totp", "recovery"]
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    step_up_at: datetime | None


@dataclass(frozen=True, slots=True, repr=False)
class IssuedAdminSession:
    session_token: str
    csrf_token: str
    record: AdminSessionRecord

    def __repr__(self) -> str:
        return "IssuedAdminSession(session_token=<redacted>, csrf_token=<redacted>)"


class RedisAuthState:
    """Single Redis boundary with atomic scripts and secret-safe keys."""

    def __init__(
        self,
        client: RedisClient,
        *,
        key_ring: Mapping[int, bytes],
        current_key_version: int,
        clock: Clock = lambda: datetime.now(UTC),
        prefix: str = _PREFIX,
    ) -> None:
        if current_key_version not in key_ring or len(key_ring[current_key_version]) < 32:
            raise ValueError("Redis authentication key ring is invalid")
        if not prefix or any(character.isspace() for character in prefix):
            raise ValueError("Redis authentication key prefix is invalid")
        self._client = client
        self._key_ring = key_ring
        self._current_key_version = current_key_version
        self._clock = clock
        self._prefix = prefix

    async def rate_limit(
        self,
        buckets: Sequence[RateBucket],
        *,
        limit: int,
        window_seconds: int,
    ) -> bool:
        if not buckets or not 1 <= limit <= 100_000 or not 1 <= window_seconds <= 86_400:
            raise ValueError("rate-limit policy is invalid")
        keys = [self._derived_key(f"rate-{item.namespace}", item.subject) for item in buckets]
        try:
            result = await self._client.eval(
                _RATE_LIMIT_LUA,
                len(keys),
                *keys,
                limit,
                window_seconds * 1_000,
            )
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        if type(result) is not int or result not in {0, 1}:
            raise AuthStateUnavailable("authentication state is unavailable")
        return result == 1

    async def lockout_status(self, account_key: str) -> LockoutState:
        now_ms = self._now_ms()
        try:
            result = await self._client.eval(
                _LOCKOUT_STATUS_LUA,
                1,
                self._derived_key("admin-lockout", account_key),
                now_ms,
            )
            remaining_ms = _strict_integer(result)
        except AuthStateUnavailable:
            raise
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        return LockoutState(remaining_ms > 0, _ceil_seconds(remaining_ms))

    async def record_admin_failure(
        self,
        account_key: str,
        *,
        threshold: int,
        lock_seconds: int,
    ) -> LockoutState:
        if not 2 <= threshold <= 100 or not 1 <= lock_seconds <= 86_400:
            raise ValueError("lockout policy is invalid")
        try:
            result = await self._client.eval(
                _LOCKOUT_FAILURE_LUA,
                1,
                self._derived_key("admin-lockout", account_key),
                self._now_ms(),
                threshold,
                lock_seconds * 1_000,
            )
            if not isinstance(result, (list, tuple)) or len(result) != 2:
                raise AuthStateUnavailable("authentication state is unavailable")
            locked = _strict_integer(result[0])
            remaining_ms = _strict_integer(result[1])
            if locked not in {0, 1}:
                raise AuthStateUnavailable("authentication state is unavailable")
        except AuthStateUnavailable:
            raise
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        return LockoutState(locked == 1, _ceil_seconds(remaining_ms))

    async def clear_admin_failures(self, account_key: str) -> None:
        try:
            await self._client.delete(self._derived_key("admin-lockout", account_key))
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error

    async def issue_preauth(
        self,
        *,
        admin_id: UUID,
        purpose: Purpose,
        context: str,
        ttl_seconds: int,
    ) -> PreAuthChallenge:
        if purpose not in {"login", "enroll", "step-up"} or not 1 <= ttl_seconds <= 3_600:
            raise ValueError("pre-auth challenge policy is invalid")
        token = issue_opaque_token(self._current_key_version)
        digest = digest_opaque_token(token, self._key_ring, namespace="admin-preauth")
        key = self._digest_key("preauth", digest.value)
        context_digest = self._derive("preauth-context", context).hex()
        await self._set_hash_once(
            key,
            {
                "admin_id": str(admin_id),
                "purpose": purpose,
                "context_digest": context_digest,
                "created_ms": str(self._now_ms()),
            },
            ttl_seconds=ttl_seconds,
        )
        return PreAuthChallenge(token=token, expires_in_seconds=ttl_seconds)

    async def consume_preauth(
        self,
        token: str,
        *,
        purpose: Purpose,
        context: str,
    ) -> ConsumedPreAuth | None:
        try:
            digest = digest_opaque_token(token, self._key_ring, namespace="admin-preauth")
        except ValueError:
            return None
        try:
            result = await self._client.eval(
                _CONSUME_PREAUTH_LUA,
                1,
                self._digest_key("preauth", digest.value),
                purpose,
                self._derive("preauth-context", context).hex(),
            )
            values = _decode_hash(result)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        if not values:
            return None
        try:
            admin_id = UUID(values["admin_id"])
            stored_purpose = values["purpose"]
        except (KeyError, ValueError):
            raise AuthStateUnavailable("authentication state is unavailable") from None
        if stored_purpose != purpose:
            raise AuthStateUnavailable("authentication state is unavailable")
        return ConsumedPreAuth(admin_id=admin_id, purpose=purpose)

    async def issue_admin_session(
        self,
        *,
        admin_id: UUID,
        mfa_method: Literal["totp", "recovery"],
        idle_ttl: timedelta,
        absolute_ttl: timedelta,
        stepped_up: bool = False,
    ) -> IssuedAdminSession:
        idle_ms = _duration_ms(idle_ttl)
        absolute_ms = _duration_ms(absolute_ttl)
        if idle_ms > absolute_ms or mfa_method not in {"totp", "recovery"}:
            raise ValueError("administrator session policy is invalid")
        now = self._now()
        now_ms = int(now.timestamp() * 1_000)
        session_token = issue_opaque_token(self._current_key_version)
        csrf_token = issue_opaque_token(self._current_key_version)
        session_digest = digest_opaque_token(
            session_token, self._key_ring, namespace="admin-session"
        )
        csrf_digest = digest_opaque_token(csrf_token, self._key_ring, namespace="admin-csrf")
        session_id = uuid4()
        absolute_expires_ms = now_ms + absolute_ms
        await self._set_hash_once(
            self._digest_key("session", session_digest.value),
            {
                "admin_id": str(admin_id),
                "session_id": str(session_id),
                "created_ms": str(now_ms),
                "last_seen_ms": str(now_ms),
                "absolute_expires_ms": str(absolute_expires_ms),
                "mfa_method": mfa_method,
                "step_up_ms": str(now_ms) if stepped_up else "",
                "csrf_digest": csrf_digest.value.hex(),
            },
            ttl_seconds=max(1, min(idle_ms, absolute_ms) // 1_000),
        )
        record = AdminSessionRecord(
            admin_id=admin_id,
            session_id=session_id,
            mfa_method=mfa_method,
            created_at=now,
            last_seen_at=now,
            absolute_expires_at=now + absolute_ttl,
            step_up_at=now if stepped_up else None,
        )
        return IssuedAdminSession(
            session_token=session_token,
            csrf_token=csrf_token,
            record=record,
        )

    async def get_admin_session(
        self,
        session_token: str,
        *,
        idle_ttl: timedelta,
    ) -> AdminSessionRecord | None:
        key = self._session_key(session_token)
        if key is None:
            return None
        try:
            result = await self._client.eval(
                _GET_SESSION_LUA,
                1,
                key,
                self._now_ms(),
                _duration_ms(idle_ttl),
            )
            values = _decode_hash(result)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        return _session_record(values) if values else None

    async def validate_and_rotate_csrf(
        self,
        session_token: str,
        csrf_token: str,
        *,
        idle_ttl: timedelta,
    ) -> str | None:
        session_key = self._session_key(session_token)
        if session_key is None:
            return None
        try:
            current = digest_opaque_token(csrf_token, self._key_ring, namespace="admin-csrf")
        except ValueError:
            return None
        replacement_token = issue_opaque_token(self._current_key_version)
        replacement = digest_opaque_token(replacement_token, self._key_ring, namespace="admin-csrf")
        try:
            result = await self._client.eval(
                _ROTATE_CSRF_LUA,
                1,
                session_key,
                self._now_ms(),
                _duration_ms(idle_ttl),
                current.value.hex(),
                replacement.value.hex(),
            )
            accepted = _strict_integer(result)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        if accepted not in {0, 1}:
            raise AuthStateUnavailable("authentication state is unavailable")
        return replacement_token if accepted == 1 else None

    async def rotate_admin_session(
        self,
        session_token: str,
        *,
        idle_ttl: timedelta,
        stepped_up: bool,
    ) -> IssuedAdminSession | None:
        old_key = self._session_key(session_token)
        if old_key is None:
            return None
        new_session_token = issue_opaque_token(self._current_key_version)
        new_csrf_token = issue_opaque_token(self._current_key_version)
        new_session_digest = digest_opaque_token(
            new_session_token, self._key_ring, namespace="admin-session"
        )
        new_csrf_digest = digest_opaque_token(
            new_csrf_token, self._key_ring, namespace="admin-csrf"
        )
        now = self._now()
        now_ms = int(now.timestamp() * 1_000)
        session_id = uuid4()
        try:
            result = await self._client.eval(
                _ROTATE_SESSION_LUA,
                2,
                old_key,
                self._digest_key("session", new_session_digest.value),
                now_ms,
                _duration_ms(idle_ttl),
                str(session_id),
                str(now_ms) if stepped_up else "",
                new_csrf_digest.value.hex(),
            )
            values = _decode_hash(result)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        if not values:
            return None
        record = _session_record(values)
        return IssuedAdminSession(
            session_token=new_session_token,
            csrf_token=new_csrf_token,
            record=record,
        )

    async def revoke_admin_session(self, session_token: str) -> None:
        key = self._session_key(session_token)
        if key is None:
            return
        try:
            await self._client.delete(key)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error

    def _session_key(self, token: str) -> str | None:
        try:
            digest = digest_opaque_token(token, self._key_ring, namespace="admin-session")
        except ValueError:
            return None
        return self._digest_key("session", digest.value)

    async def _set_hash_once(
        self,
        key: str,
        fields: Mapping[str, str],
        *,
        ttl_seconds: int,
    ) -> None:
        arguments: list[object] = []
        for name, value in fields.items():
            arguments.extend((name, value))
        arguments.append(ttl_seconds * 1_000)
        try:
            result = await self._client.eval(
                _SET_HASH_WITH_TTL_LUA,
                1,
                key,
                *arguments,
            )
            created = _strict_integer(result)
        except Exception as error:
            raise AuthStateUnavailable("authentication state is unavailable") from error
        if created != 1:
            raise AuthStateUnavailable("authentication state is unavailable")

    def _derived_key(self, namespace: str, subject: str) -> str:
        return f"{self._prefix}:{namespace}:{self._derive(namespace, subject).hex()}"

    def _derive(self, namespace: str, subject: str) -> bytes:
        if _NAMESPACE_PATTERN.fullmatch(namespace) is None or not subject:
            raise ValueError("authentication key input is invalid")
        key = self._key_ring[self._current_key_version]
        return hmac.new(
            key,
            b"nebula:redis-key:v1\x00" + namespace.encode("ascii") + b"\x00" + subject.encode(),
            hashlib.sha256,
        ).digest()

    def _digest_key(self, namespace: str, digest: bytes) -> str:
        if _NAMESPACE_PATTERN.fullmatch(namespace) is None or len(digest) != 32:
            raise ValueError("authentication digest key is invalid")
        return f"{self._prefix}:{namespace}:{digest.hex()}"

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authentication clock must be timezone aware")
        return value.astimezone(UTC)

    def _now_ms(self) -> int:
        return int(self._now().timestamp() * 1_000)


def _decode_hash(value: object) -> dict[str, str]:
    if value in (None, [], ()):
        return {}
    if not isinstance(value, (list, tuple)) or len(value) % 2:
        raise AuthStateUnavailable("authentication state is unavailable")
    decoded: dict[str, str] = {}
    for index in range(0, len(value), 2):
        key = _decode_text(value[index])
        item = _decode_text(value[index + 1])
        decoded[key] = item
    return decoded


def _decode_text(value: object) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            raise AuthStateUnavailable("authentication state is unavailable") from None
    if isinstance(value, str):
        return value
    raise AuthStateUnavailable("authentication state is unavailable")


def _session_record(values: Mapping[str, str]) -> AdminSessionRecord:
    try:
        method = values["mfa_method"]
        if method not in {"totp", "recovery"}:
            raise ValueError
        mfa_method = cast(Literal["totp", "recovery"], method)
        step_up_ms = values["step_up_ms"]
        return AdminSessionRecord(
            admin_id=UUID(values["admin_id"]),
            session_id=UUID(values["session_id"]),
            mfa_method=mfa_method,
            created_at=_datetime_from_ms(values["created_ms"]),
            last_seen_at=_datetime_from_ms(values["last_seen_ms"]),
            absolute_expires_at=_datetime_from_ms(values["absolute_expires_ms"]),
            step_up_at=_datetime_from_ms(step_up_ms) if step_up_ms else None,
        )
    except (KeyError, TypeError, ValueError):
        raise AuthStateUnavailable("authentication state is unavailable") from None


def _datetime_from_ms(value: str) -> datetime:
    milliseconds = int(value)
    if milliseconds < 0:
        raise ValueError
    return datetime.fromtimestamp(milliseconds / 1_000, UTC)


def _duration_ms(value: timedelta) -> int:
    milliseconds = int(value.total_seconds() * 1_000)
    if not 1_000 <= milliseconds <= 86_400_000:
        raise ValueError("authentication duration is invalid")
    return milliseconds


def _strict_integer(value: object) -> int:
    if type(value) is int:
        return value
    if isinstance(value, bytes):
        try:
            return int(value)
        except ValueError:
            pass
    raise AuthStateUnavailable("authentication state is unavailable")


def _ceil_seconds(milliseconds: int) -> int:
    return max(0, (milliseconds + 999) // 1_000)
