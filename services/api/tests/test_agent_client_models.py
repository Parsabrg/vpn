from typing import get_args
from uuid import uuid4

import pytest
from pydantic import ValidationError

from nebula_api.agent_client.models import (
    HealthState,
    OperationKind,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileOutcome,
    TargetKind,
)
from nebula_api.models.operations import (
    HEALTH_STATES,
    OPERATION_KINDS,
    PROVISIONING_TARGET_KINDS,
    RECONCILIATION_OUTCOMES,
)

VALID_PUBLIC_KEY = "MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMj0="
ALL_ZERO_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_operation_kind_matches_the_live_database_vocabulary() -> None:
    assert set(get_args(OperationKind)) == set(OPERATION_KINDS)


def test_target_kind_matches_the_live_database_vocabulary() -> None:
    assert set(get_args(TargetKind)) == set(PROVISIONING_TARGET_KINDS)


def test_health_state_matches_the_live_database_vocabulary() -> None:
    assert set(get_args(HealthState)) == set(HEALTH_STATES)


def test_reconcile_outcome_is_a_subset_of_the_live_database_vocabulary() -> None:
    assert set(get_args(ReconcileOutcome)) <= set(RECONCILIATION_OUTCOMES)


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


def test_provision_device_request_rejects_a_malformed_public_key() -> None:
    with pytest.raises(ValidationError, match="base64-encoded WireGuard public key"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "public_key": "; rm -rf /"})


def test_provision_device_request_rejects_the_all_zero_public_key() -> None:
    with pytest.raises(ValidationError, match="all-zero public key"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "public_key": ALL_ZERO_PUBLIC_KEY})


def test_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ProvisionDeviceRequest(**{**_base_kwargs(), "shell_command": "rm -rf /"})


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
