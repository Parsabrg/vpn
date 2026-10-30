"""Every audit event the code writes must be one the schema will accept.

`audit_logs` closes four of its columns to fixed vocabularies and pairs
`actor_kind` with the nullability of `actor_id`. None of that is visible to
the service tests, which drive scripted session doubles: a call can name an
actor kind that does not exist, pass the check in every test, and raise
`CheckViolation` the first time an operator runs it against the real
database. That is exactly what `reissue-activation` did.

So this reads the vocabularies out of the migrations and every
`add_audit_event` call out of the source, and checks them against each other.
No database, so it runs in the unit suite where the mistake is made.

Only literal keyword arguments are checked. A value passed as a variable is
skipped and counted -- see `test_almost_every_call_site_is_checkable`, which
keeps the skipping from quietly growing until the guard means nothing.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SOURCE = _REPO / "src" / "nebula_api"
_MIGRATIONS = _REPO / "alembic" / "versions"

# Kinds that name a row in a table, and so must carry its id; the rest are
# the system acting on its own behalf and must not. Mirrors
# `ck_audit_logs_actor_identity_shape`, which is asserted below.
_IDENTIFIED_ACTORS = frozenset({"user", "admin", "agent"})

# Three ways an audit row gets written: the shared helper, a duplicate of it
# private to `auth.user_service`, and the model constructed directly, which
# the seeding code does because it builds rows before there is a service to
# ask. `test_nothing_else_writes_an_audit_row` is what notices a fourth.
_WRITERS = frozenset({"add_audit_event", "_add_audit", "AuditLog"})


def _migrations_in_order() -> list[Path]:
    """Version files, oldest first.

    Sorted by filename, which the repository's naming makes equal to the
    `down_revision` chain -- `test_the_filename_order_is_the_revision_order`
    is what keeps that true.
    """

    return sorted(p for p in _MIGRATIONS.glob("*.py") if not p.name.startswith("__"))


def _constraint_sql(constraint: str) -> str:
    """The last definition any migration gives `constraint`.

    A constraint that is dropped and recreated -- several of these were --
    means only the final definition is live, so later files win.

    Only `upgrade` is read. `downgrade` restores the *previous* definition,
    and reading the whole module would take that as the newest one: the first
    version of this test did, and reported the vocabulary as it stood two
    migrations before the auth events were added to it.
    """

    found: str | None = None
    for path in _migrations_in_order():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        upgrade = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "upgrade"
            ),
            None,
        )
        if upgrade is None:  # pragma: no cover - every migration has one
            continue
        for node in ast.walk(upgrade):
            if not isinstance(node, ast.Call):
                continue
            name, sql = _check_constraint_parts(node)
            if name == constraint and sql is not None:
                found = sql
    if found is None:  # pragma: no cover - a typo in the test itself
        raise AssertionError(f"no migration defines {constraint}")
    return found


def _check_constraint_parts(node: ast.Call) -> tuple[str | None, str | None]:
    """The (name, SQL) a call defines, if it defines a check constraint.

    Two spellings appear: `op.create_check_constraint(op.f(name), table, sql)`
    for one added later, and `sa.CheckConstraint(sql, name=op.f(name))` for
    one declared inside the `create_table` that introduced it.
    """

    function = node.func
    attribute = function.attr if isinstance(function, ast.Attribute) else None

    if attribute == "create_check_constraint" and len(node.args) >= 3:
        return _literal(node.args[0]), _literal(node.args[2])

    if attribute == "CheckConstraint" and node.args:
        name = next((_literal(kw.value) for kw in node.keywords if kw.arg == "name"), None)
        return name, _literal(node.args[0])

    return None, None


def _literal(node: ast.expr) -> str | None:
    """The string a node evaluates to, seeing through `op.f(...)`."""

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "f"
        and node.args
    ):
        node = node.args[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _vocabulary(column: str) -> frozenset[str]:
    """The values `column`'s vocabulary constraint admits."""

    sql = _constraint_sql(f"ck_audit_logs_{column}_vocabulary")
    return frozenset(re.findall(r"'([^']+)'", sql))


@dataclass(frozen=True)
class _CallSite:
    """One `add_audit_event` call, with whatever it states literally."""

    where: str
    values: dict[str, str]
    # None when the argument is not a literal, so "passed None" and "passed a
    # variable" stay distinguishable.
    actor_id_is_null: bool | None

    def __str__(self) -> str:
        return self.where


def _called_name(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _call_sites() -> list[_CallSite]:
    sites: list[_CallSite] = []
    for path in sorted(_SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _called_name(node) not in _WRITERS:
                continue

            values: dict[str, str] = {}
            actor_id_is_null: bool | None = None
            for keyword in node.keywords:
                if keyword.arg is None:
                    continue
                if keyword.arg == "actor_id":
                    if isinstance(keyword.value, ast.Constant):
                        actor_id_is_null = keyword.value.value is None
                    continue
                literal = _literal(keyword.value)
                if literal is not None:
                    values[keyword.arg] = literal

            sites.append(
                _CallSite(
                    where=f"{path.relative_to(_SOURCE)}:{node.lineno}",
                    values=values,
                    actor_id_is_null=actor_id_is_null,
                )
            )
    return sites


_SITES = _call_sites()


def test_the_source_has_call_sites_to_check() -> None:
    # Guards against the walk silently matching nothing -- a guard that
    # checks an empty list passes forever.
    assert len(_SITES) >= 60


def test_nothing_else_writes_an_audit_row() -> None:
    """A fourth way to write one would slip past every check above.

    Anything naming both an actor kind and an event code is writing an audit
    row, whatever it is called. The read side names them too, but reads them
    off a row rather than stating them, so a literal pair is the giveaway.
    """

    strangers: list[str] = []
    for path in sorted(_SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _called_name(node) in _WRITERS:
                continue
            stated = {
                keyword.arg
                for keyword in node.keywords
                if keyword.arg in {"actor_kind", "event_code"}
                and _literal(keyword.value) is not None
            }
            if len(stated) == 2:
                strangers.append(
                    f"{path.relative_to(_SOURCE)}:{node.lineno} {_called_name(node)}()"
                )
    assert not strangers, (
        "these write audit rows without going through a known writer; add "
        "them to _WRITERS so their values are checked:\n  " + "\n  ".join(strangers)
    )


def test_the_filename_order_is_the_revision_order() -> None:
    # `_constraint_sql` takes the last definition by filename, which is only
    # the live one if the files are also in `down_revision` order.
    previous: str | None = None
    for path in _migrations_in_order():
        source = path.read_text(encoding="utf-8")
        revision = re.search(r"^revision(?::.*)? = [\"']([^\"']+)", source, re.M)
        down = re.search(r"^down_revision(?::.*)? = (.+)$", source, re.M)
        assert revision is not None, path.name
        assert down is not None, path.name
        expected = "None" if previous is None else f'"{previous}"'
        assert down.group(1).strip().strip("'\"") == expected.strip("\"'"), (
            f"{path.name} does not follow {previous}"
        )
        previous = revision.group(1)


@pytest.mark.parametrize("column", ["actor_kind", "target_kind", "event_code"])
def test_every_call_site_names_an_admitted_value(column: str) -> None:
    admitted = _vocabulary(column)
    offenders = [
        f"{site} passes {column}={site.values[column]!r}"
        for site in _SITES
        if column in site.values and site.values[column] not in admitted
    ]
    assert not offenders, (
        "the database will reject these; add the value in a migration or use "
        f"one of {sorted(admitted)}:\n  " + "\n  ".join(offenders)
    )


def test_every_call_site_names_an_admitted_outcome() -> None:
    admitted = _vocabulary("outcome")
    offenders = [
        f"{site} passes outcome={site.values['outcome']!r}"
        for site in _SITES
        if "outcome" in site.values and site.values["outcome"] not in admitted
    ]
    assert not offenders, "\n  ".join(offenders)


def test_the_actor_matches_the_shape_the_schema_pairs_it_with() -> None:
    # An anonymous actor with an id, or an admin without one, is rejected by
    # `ck_audit_logs_actor_identity_shape` however valid each half looks.
    offenders: list[str] = []
    for site in _SITES:
        kind = site.values.get("actor_kind")
        if kind is None or site.actor_id_is_null is None:
            continue
        needs_id = kind in _IDENTIFIED_ACTORS
        if needs_id and site.actor_id_is_null:
            offenders.append(f"{site} passes actor_kind={kind!r} with actor_id=None")
        if not needs_id and not site.actor_id_is_null:
            offenders.append(f"{site} passes actor_kind={kind!r} with an actor_id")
    assert not offenders, "\n  ".join(offenders)


def test_the_shape_constraint_still_pairs_the_kinds_this_test_assumes() -> None:
    # `_IDENTIFIED_ACTORS` is written here rather than parsed, so this is what
    # notices if a migration moves a kind from one side to the other.
    sql = _constraint_sql("ck_audit_logs_actor_identity_shape")
    with_id, without_id = (
        sql.split("actor_id IS NOT NULL")[0].split("actor_id IS NULL")[1],
        sql.split("actor_id IS NULL")[0],
    )
    assert set(re.findall(r"'([^']+)'", with_id)) == set(_IDENTIFIED_ACTORS)
    assert set(re.findall(r"'([^']+)'", without_id)) == _vocabulary("actor_kind") - set(
        _IDENTIFIED_ACTORS
    )


def test_every_literal_reason_code_matches_the_format_constraint() -> None:
    pattern = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    offenders = [
        f"{site} passes reason_code={site.values['reason_code']!r}"
        for site in _SITES
        if "reason_code" in site.values and not pattern.match(site.values["reason_code"])
    ]
    assert not offenders, "\n  ".join(offenders)


def test_almost_every_call_site_is_checkable() -> None:
    # Values built at runtime cannot be checked here, and a codebase that
    # drifted towards them would leave this guard passing while checking
    # nothing. Today only a handful pass a variable.
    unchecked = [str(site) for site in _SITES if "actor_kind" not in site.values]
    assert len(unchecked) <= 2, (
        "too many call sites build actor_kind at runtime for this guard to "
        "mean much:\n  " + "\n  ".join(unchecked)
    )
