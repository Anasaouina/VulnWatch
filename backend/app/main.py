import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .db import make_engine
from .errors import install_error_handlers
from .seed import seed_watchlist
from .routes.vulns import router as vulns_router
from .routes.watchlist import router as watchlist_router
from .routes.sync import router as sync_router

log = logging.getLogger("vulnwatch.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = make_engine()
    factory = sessionmaker(engine, autoflush=False, expire_on_commit=False)
    app.state.session_factory = factory

    with factory() as session:  # type: Session
        session.execute(text("SELECT 1"))
        session.commit()
        seed_watchlist(session)

    log.info("API ready (db=%s)", engine.url.render_as_string(hide_password=True))
    yield
    engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="VulnWatch API", version="0.1.0", lifespan=lifespan)
    install_error_handlers(app)
    app.include_router(vulns_router)
    app.include_router(watchlist_router)
    app.include_router(sync_router)

    @app.get("/api/health")
    def health():
        status = {"status": "ok", "app": "vulnwatch", "version": "0.1.0", "database": "ok"}
        try:
            with app.state.session_factory() as session:  # type: Session
                session.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001
            log.exception("health check failed")
            status["status"] = "degraded"
            status["database"] = "error"
        status["time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return status

    return app


app = create_app()
