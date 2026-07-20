import ast
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

import nebula_api.models  # noqa: F401
from nebula_api.db.base import Base
from nebula_api.db.schema import SCHEMA_HEAD

API_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = API_ROOT.parents[1]
VERSIONS = API_ROOT / "alembic" / "versions"


def migration_table_calls(function_name: str) -> list[str]:
    tables: list[str] = []
    for path in VERSIONS.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != function_name or not node.args:
                continue
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                tables.append(node.args[0].value)
    return tables


def test_migration_history_is_linear_and_matches_runtime_head() -> None:
    config = Config(str(API_ROOT / "alembic.ini"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_heads() == [SCHEMA_HEAD]
    assert [revision.revision for revision in scripts.walk_revisions()] == [
        "20260720_0003",
        "20260720_0002",
        "20260720_0001",
    ]


def test_every_metadata_table_is_created_and_dropped_once() -> None:
    expected = set(Base.metadata.tables)
    created = migration_table_calls("create_table")
    dropped = migration_table_calls("drop_table")

    assert len(created) == len(set(created)) == len(expected)
    assert len(dropped) == len(set(dropped)) == len(expected)
    assert set(created) == expected
    assert set(dropped) == expected


def test_deferred_request_user_foreign_key_is_emitted_explicitly() -> None:
    identity_revision = (VERSIONS / "20260720_0001_protocol-neutral.py").read_text(encoding="utf-8")

    assert "op.create_foreign_key(" in identity_revision
    assert "fk_account_requests_user_id_users" in identity_revision


def test_operations_revision_and_bootstraps_enforce_runtime_role_boundaries() -> None:
    operations = (VERSIONS / "20260720_0003_operations.py").read_text(encoding="utf-8")
    compose_bootstrap = (
        REPOSITORY_ROOT / "infrastructure" / "postgres" / "001-create-roles.sh"
    ).read_text(encoding="utf-8")
    ci_bootstrap = (
        REPOSITORY_ROOT / "infrastructure" / "postgres" / "bootstrap_ci_roles.py"
    ).read_text(encoding="utf-8")

    for source in (operations, compose_bootstrap, ci_bootstrap):
        assert "nebula_app_runtime" in source
    assert "--set=app_password" not in compose_bootstrap
    assert "--set=migrator_password" not in compose_bootstrap
    assert "\\getenv app_password NEBULA_DB_APP_PASSWORD" in compose_bootstrap
    assert "\\getenv migrator_password NEBULA_DB_MIGRATOR_PASSWORD" in compose_bootstrap
    assert "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY" in operations
    assert "FOR SELECT TO nebula_app_runtime" in operations
    assert "FOR INSERT TO nebula_app_runtime" in operations
    assert "REVOKE UPDATE, DELETE ON TABLE audit_logs" in operations
    assert "REVOKE INSERT, UPDATE, DELETE ON TABLE alembic_version" in operations


def test_runtime_database_url_uses_the_validated_nebula_setting_name() -> None:
    compose = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "python.yml").read_text(
        encoding="utf-8"
    )

    assert "NEBULA_DATABASE_URL:" in compose
    assert "NEBULA_DATABASE_URL:" in workflow
