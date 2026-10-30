import pytest

from nebula_worker.db import create_worker_engine


def test_create_worker_engine_accepts_a_valid_psycopg_url() -> None:
    engine = create_worker_engine("postgresql+psycopg://nebula_app:password@localhost:5432/nebula")

    assert engine.url.drivername == "postgresql+psycopg"


def test_create_worker_engine_rejects_other_drivers() -> None:
    with pytest.raises(ValueError, match="postgresql\\+psycopg"):
        create_worker_engine("postgresql+asyncpg://nebula:password@localhost/nebula")
