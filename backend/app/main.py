"""FastAPI application factory.

Run in dev:  uvicorn app.main:app --reload   (from the backend folder)
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import db
from app.config import Settings, get_settings

logger = logging.getLogger("netmap")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = db.create_client(settings)
        app.state.mongo = client
        app.state.db = client[settings.mongodb_db]
        try:
            await db.ensure_indexes(app.state.db)
        except Exception:
            # Start anyway so /health can report the problem; the details go to the server log only.
            logger.exception("Could not create MongoDB indexes at startup")
        try:
            yield
        finally:
            await client.close()

    # API docs reveal every route and schema, so they are switched off in production.
    docs_off = settings.is_production
    app = FastAPI(
        title="NetMap",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if docs_off else "/docs",
        redoc_url=None if docs_off else "/redoc",
        openapi_url=None if docs_off else "/openapi.json",
    )
    app.state.settings = settings

    @app.get("/health", tags=["system"])
    async def health(request: Request) -> JSONResponse:
        # Public on purpose (Render's health check calls it). It says only ok/unavailable and
        # never includes exception text, hostnames or versions.
        if await db.ping(request.app.state.mongo):
            return JSONResponse({"status": "ok", "database": "ok"})
        return JSONResponse({"status": "degraded", "database": "unavailable"}, status_code=503)

    return app


app = create_app()
