import base64
from typing import get_args
from uuid import uuid4

import pytest
from pydantic import ValidationError

from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    HealthRequest,
    HealthResponse,
    HealthState,
    OperationKind,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileOutcome,
    ReconcileRequest,
    ReconcileResponse,
    RevokeDeviceRequest,
    TargetKind,
)

# Pasted from services/api/src/nebula_api/models/operations.py -- these are
# live PostgreSQL CHECK constraints. Update both files if either changes.
_AUTHORITATIVE_OPERATION_KINDS = (
    "provision_device",
    "revoke_device",
    "enable_device",
    "disable_device",
    "health",
    "reconcile",
)
_AUTHORITATIVE_TARGET_KINDS = (
    "device_credential",
    "wireguard_peer",
    "xray_client",
    "server_capability",
    "vpn_server",
)
_AUTHORITATIVE_HEALTH_STATES = ("healthy", "degraded", "unreachable", "unknown")
_AUTHORITATIVE_RECONCILIATION_OUTCOMES = (
    "in_sync",
    "drift_detected",
    "repair_requested",
    "repair_succeeded",
    "repair_failed",
    "ambiguous",
)

VALID_PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()
ALL_ZERO_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_operation_kind_matches_the_authoritative_database_vocabulary() -> None:
    assert set(get_args(OperationKind)) == set(_AUTHORITATIVE_OPERATION_KINDS)


def test_target_kind_matches_the_authoritative_database_vocabulary() -> None:
    assert set(get_args(TargetKind)) == set(_AUTHORITATIVE_TARGET_KINDS)


def test_health_state_matches_the_authoritative_database_vocabulary() -> None:
    assert set(get_args(HealthState)) == set(_AUTHORITATIVE_HEALTH_STATES)


def test_reconcile_outcome_is_a_subset_of_the_authoritative_vocabulary() -> None:
    # The driver only ever reports in_sync/drift_detected/ambiguous; repair_*
    # outcomes are produced by the API-side reconciliation job, not the agent.
    assert set(get_args(ReconcileOutcome)) <= set(_AUTHORITATIVE_RECONCILIATION_OUTCOMES)


def _base_kwargs() -> dict[str, object]:
    return {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "wireguard_peer",
        "target_id": uuid4(),
        "desired_generation": 0,
        "public_key": VALID_PUBLIC_KEY,
        "assigned_address": "10.77.0.2",
    }


def test_provision_device_request_accepts_a_valid_public_key() -> None:
    request = ProvisionDeviceRequest(**_base_kwargs())
    assert request.public_key == VALID_PUBLIC_KEY


def test_provision_device_request_rejects_a_malformed_public_key() -> None:
    with pytest.raises(ValidationError, match="base64-encoded WireGuard public key"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "public_key": "; rm -rf /"})


def test_provision_device_request_rejects_the_all_zero_public_key() -> None:
    with pytest.raises(ValidationError, match="all-zero public key"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "public_key": ALL_ZERO_PUBLIC_KEY})


def test_revoke_device_request_rejects_a_malformed_public_key() -> None:
    with pytest.raises(ValidationError, match="base64-encoded WireGuard public key"):
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key="not-a-key",
            desired_generation=0,
        )


def test_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "shell_command": "rm -rf /"})


def test_request_is_frozen() -> None:
    request = ProvisionDeviceRequest(**_base_kwargs())
    with pytest.raises(ValidationError):
        request.public_key = VALID_PUBLIC_KEY  # type: ignore[misc]


def test_response_rejects_a_malformed_error_code() -> None:
    with pytest.raises(ValidationError, match="error_code format"):
        ProvisionDeviceResponse(
            state="failed",
            applied_generation=0,
            server_public_key=VALID_PUBLIC_KEY,
            listen_port=51820,
            public_endpoint="vpn.test:51820",
            client_dns="1.1.1.1",
            client_allowed_ips="0.0.0.0/0,::/0",
            persistent_keepalive_seconds=25,
            error_code="Not Valid!",
        )


def test_enable_device_request_accepts_a_valid_public_key() -> None:
    request = EnableDeviceRequest(
        idempotency_key=uuid4(),
        correlation_id=uuid4(),
        target_kind="wireguard_peer",
        target_id=uuid4(),
        public_key=VALID_PUBLIC_KEY,
        assigned_address="10.77.0.2",
        desired_generation=0,
    )
    assert request.public_key == VALID_PUBLIC_KEY


def test_enable_device_response_reports_its_state() -> None:
    response = EnableDeviceResponse(state="enabled", applied_generation=1)
    assert response.state == "enabled"


def test_disable_device_request_accepts_a_valid_public_key() -> None:
    request = DisableDeviceRequest(
        idempotency_key=uuid4(),
        correlation_id=uuid4(),
        target_kind="wireguard_peer",
        target_id=uuid4(),
        public_key=VALID_PUBLIC_KEY,
        desired_generation=0,
    )
    assert request.public_key == VALID_PUBLIC_KEY


def test_disable_device_response_reports_its_state() -> None:
    response = DisableDeviceResponse(state="disabled", applied_generation=1)
    assert response.state == "disabled"


def test_reconcile_request_accepts_a_valid_public_key() -> None:
    request = ReconcileRequest(
        correlation_id=uuid4(),
        target_kind="wireguard_peer",
        target_id=uuid4(),
        public_key=VALID_PUBLIC_KEY,
        assigned_address="10.77.0.2",
        desired_generation=0,
    )
    assert request.public_key == VALID_PUBLIC_KEY


def test_reconcile_response_reports_its_outcome() -> None:
    response = ReconcileResponse(outcome="in_sync", observed_generation=1)
    assert response.outcome == "in_sync"


def test_health_request_and_response_round_trip() -> None:
    HealthRequest(correlation_id=uuid4())
    response = HealthResponse(
        state="healthy",
        observed_at="2026-01-01T00:00:00Z",
        agent_version="0.1.0",
        interface_up=True,
        peer_count=0,
    )
    assert response.state == "healthy"


def test_response_accepts_a_well_formed_error_code() -> None:
    response = ProvisionDeviceResponse(
        state="failed",
        applied_generation=0,
        server_public_key=VALID_PUBLIC_KEY,
        listen_port=51820,
        public_endpoint="vpn.test:51820",
        client_dns="1.1.1.1",
        client_allowed_ips="0.0.0.0/0,::/0",
        persistent_keepalive_seconds=25,
        error_code="apply_failed",
    )
    assert response.error_code == "apply_failed"
