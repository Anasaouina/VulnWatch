import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

log = logging.getLogger("vulnwatch")


class Base(DeclarativeBase):
    pass


def make_engine(url: str | None = None):
    return create_engine(
        url or settings.database_url,
        pool_pre_ping=True,
        future=True,
    )


SessionLocal = sessionmaker(bind=make_engine(), autoflush=False, expire_on_commit=False)


def get_session():
    with SessionLocal() as session:
        yield session
