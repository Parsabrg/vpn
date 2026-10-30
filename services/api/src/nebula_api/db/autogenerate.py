"""Autogenerate filters for Alembic comparisons.

Lives outside `alembic/env.py` because that module runs migrations as an
import side effect, so nothing there can be unit tested.
"""

from collections.abc import Callable
from itertools import chain
from typing import Any

from sqlalchemy import CheckConstraint, MetaData


def type_bound_check_constraint_names(metadata: MetaData) -> frozenset[str]:
    """Names of check constraints SQLAlchemy derives from a column's type.

    An `Enum(..., native_enum=False, create_constraint=True)` column carries
    its own CheckConstraint listing the permitted values. SQLAlchemy owns that
    constraint -- nothing in the models writes it -- and Alembic deliberately
    excludes type-bound constraints from the metadata side of autogenerate for
    exactly that reason.

    The database side has no such notion. `pg_constraint` reports an ordinary
    named check constraint, so from Alembic 1.19 onward -- the release that
    began comparing check constraints at all -- every one of these appears in
    the catalog and not in the metadata, and is reported as a constraint to
    drop. Applying those drops would delete the enum value checks; running
    autogenerate again would report them again, because the metadata still
    cannot supply them.

    `_type_bound` is private to SQLAlchemy, which is why
    `test_autogenerate_filters` asserts this set is non-empty and names the
    columns it covers: if the attribute is ever renamed the filter silently
    stops matching, and the failure mode is a migration that drops twelve
    constraints rather than an import error.
    """

    return frozenset(
        constraint.name
        for table in metadata.tables.values()
        # Both levels, matching Alembic's own traversal: where SQLAlchemy
        # attaches a type-bound constraint is its business, not ours.
        for constraint in chain(
            table.constraints, *(column.constraints for column in table.columns)
        )
        if isinstance(constraint, CheckConstraint)
        and getattr(constraint, "_type_bound", False)
        and isinstance(constraint.name, str)
    )


def build_include_object(metadata: MetaData) -> Callable[..., bool]:
    """Build the `include_object` hook for this metadata.

    Narrow on purpose: it suppresses only reflected check constraints whose
    names SQLAlchemy generates from a column type. A hand-written constraint
    that genuinely disappears from the models is still reported, which is the
    signal `alembic check` exists to give.
    """

    type_bound = type_bound_check_constraint_names(metadata)

    def include_object(
        object_: Any,
        name: str | None,
        type_: str,
        reflected: bool,
        compare_to: Any,
    ) -> bool:
        if type_ == "check_constraint" and reflected and name in type_bound:
            return False
        return True

    return include_object
