import os
import pathlib
import sys

# make `app` importable regardless of how pytest is invoked
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

os.environ.setdefault("DATABASE_URL", "sqlite://")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db import Base  # noqa: E402


@pytest.fixture()
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'test.db'}", future=True)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def factory(engine):
    return sessionmaker(engine, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def client(factory, engine, monkeypatch):
    import app.main as main_mod
    from app.db import get_session

    # lifespan must reuse the test engine instead of building one from DATABASE_URL
    monkeypatch.setattr(main_mod, "make_engine", lambda url=None: engine)

    app = main_mod.create_app()
    app.state.session_factory = factory

    def _override():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
