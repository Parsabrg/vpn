"""The autogenerate filter that keeps enum check constraints from being dropped.

Alembic 1.19 began comparing check constraints. It excludes type-bound ones --
those SQLAlchemy generates from a non-native `Enum` column -- from the metadata
side, but the database side reports them as ordinary named constraints, so
without a filter every one is reported as a constraint to drop.

These tests are static: no database, no Alembic run. What they pin down is the
part that can silently stop working, which is the recognition of type-bound
constraints via SQLAlchemy's private `_type_bound` attribute.
"""

from sqlalchemy import CheckConstraint, Column, Enum, Integer, MetaData, String, Table

import nebula_api.models  # noqa: F401  # registers every mapped table
from nebula_api.db.autogenerate import (
    build_include_object,
    type_bound_check_constraint_names,
)
from nebula_api.db.base import NAMING_CONVENTION, Base

# Recognising these is the whole mechanism. Naming them means a SQLAlchemy
# change that stops marking constraints type-bound fails here, rather than in a
# generated migration that drops the enum value checks.
EXPECTED_TYPE_BOUND = frozenset(
    {
        "ck_account_request_events_request_event_from_state",
        "ck_account_request_events_request_event_to_state",
        "ck_account_requests_request_state",
        "ck_admin_users_admin_role",
        "ck_admin_users_admin_state",
        "ck_devices_device_platform",
        "ck_devices_device_state",
        "ck_password_reset_tokens_password_reset_token_state",
        "ck_refresh_tokens_refresh_token_state",
        "ck_user_activations_activation_token_state",
        "ck_user_sessions_session_state",
        "ck_users_account_state",
    }
)


def test_every_type_bound_constraint_is_recognised() -> None:
    assert type_bound_check_constraint_names(Base.metadata) == EXPECTED_TYPE_BOUND


def test_the_set_is_never_silently_empty() -> None:
    """An empty set would disable the filter without failing anything else."""

    assert type_bound_check_constraint_names(Base.metadata)


def test_reflected_type_bound_constraints_are_not_reported_for_removal() -> None:
    include_object = build_include_object(Base.metadata)

    for name in sorted(EXPECTED_TYPE_BOUND):
        assert include_object(object(), name, "check_constraint", True, None) is False


def test_hand_written_constraints_are_still_compared() -> None:
    """The filter must not blunt the check that `alembic check` exists to make."""

    include_object = build_include_object(Base.metadata)
    hand_written = {
        constraint.name
        for table in Base.metadata.tables.values()
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
        and not getattr(constraint, "_type_bound", False)
        and isinstance(constraint.name, str)
    }

    assert hand_written
    assert not (hand_written & EXPECTED_TYPE_BOUND)
    for name in sorted(hand_written):
        assert include_object(object(), name, "check_constraint", True, None) is True


def test_other_object_types_are_untouched() -> None:
    include_object = build_include_object(Base.metadata)

    for type_ in ("table", "column", "index", "unique_constraint", "foreign_key_constraint"):
        assert include_object(object(), "ck_users_account_state", type_, True, None) is True


def test_metadata_side_constraints_are_not_suppressed() -> None:
    """Only the reflected side is filtered; a genuinely added one still shows."""

    include_object = build_include_object(Base.metadata)

    assert include_object(object(), "ck_users_account_state", "check_constraint", False, None)


def test_recognition_tracks_sqlalchemy_rather_than_a_hardcoded_list() -> None:
    """A fresh enum column is classified the same way the real models are.

    Built here rather than asserted only over this repo's current tables, so
    the filter is exercised against SQLAlchemy's behaviour: the enum's
    constraint is recognised as type-bound and the hand-written one on the same
    table is not. That distinction is the entire basis of the filter.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    Table(
        "widgets",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "state",
            Enum(
                "on",
                "off",
                name="widget_state",
                native_enum=False,
                # Defaults to False in SQLAlchemy 2.0; without it there is no
                # constraint to classify and the case is vacuous.
                create_constraint=True,
            ),
        ),
        Column("label", String(32)),
        CheckConstraint("length(label) > 0", name="label_not_empty"),
    )

    assert type_bound_check_constraint_names(metadata) == {"ck_widgets_widget_state"}

    include_object = build_include_object(metadata)
    assert (
        include_object(object(), "ck_widgets_widget_state", "check_constraint", True, None) is False
    )
    assert (
        include_object(object(), "ck_widgets_label_not_empty", "check_constraint", True, None)
        is True
    )
