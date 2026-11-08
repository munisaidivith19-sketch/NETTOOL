"""FastAPI application factory.

Run in dev:  uvicorn app.main:app --reload   (from the backend folder)
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import db
from app.ai.llm import make_provider
from app.api import (
    agent_ai,
    agent_config,
    agent_ingest,
    agents,
    ai,
    alerts,
    audit,
    auth,
    changes,
    configs,
    dashboard,
    devices,
    ips,
    mfa,
    notifications,
    predictions,
    request_info,
    subnets,
    topology,
    users,
)
from app.config import Settings, get_settings
from app.frontend import mount_frontend
from app.security.agent_auth import KeyVault
from app.security.csrf import OriginAndContentTypeMiddleware
from app.security.http import BodySizeLimitMiddleware, SecurityMiddleware
from app.services.bootstrap import ensure_first_admin

logger = logging.getLogger("netmap")

# Every API router, in one place. tests/test_rbac.py checks each route in these for an access
# rule and also checks that no other /api route exists in the app.
API_ROUTERS = (
    auth.router, mfa.router, users.router, agents.router, audit.router, agent_ingest.router,
    subnets.router, ips.router, alerts.router, devices.router, dashboard.router,
    topology.router, notifications.router, configs.router, changes.router,
    agent_config.router, agent_ai.router, ai.router, predictions.router, request_info.router,
)


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default 422 body echoes the rejected input back, which could include a password.
    # Only the location, message and error type are returned.
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]
    return JSONResponse({"detail": errors}, status_code=422)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.agent_key_encryption_key is None:
            raise RuntimeError(
                "AGENT_KEY_ENCRYPTION_KEY is not set. Generate one with: python -c \"from "
                "cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        app.state.vault = KeyVault(settings.agent_key_encryption_key.get_secret_value())
        if settings.mfa_encryption_key is None:
            raise RuntimeError(
                "MFA_ENCRYPTION_KEY is not set. Generate one with: python -c \"from "
                "cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        app.state.mfa_vault = KeyVault(settings.mfa_encryption_key.get_secret_value(),
                                       name="MFA_ENCRYPTION_KEY")

        client = db.create_client(settings)
        app.state.mongo = client
        app.state.db = client[settings.mongodb_db]
        # Ask NetMap runs its queries through a read-only database user when one is set.
        ai_client = None
        if settings.ai_mongodb_uri is not None:
            ai_client = db.create_client(settings, settings.ai_mongodb_uri.get_secret_value(),
                                         appname="netmap-ai-readonly")
        app.state.ai_db = (ai_client or client)[settings.mongodb_db]
        app.state.ai_readonly_user = ai_client is not None
        if settings.is_production and ai_client is None:
            # CLAUDE.md 7.9: in production Ask NetMap runs only as the read-only user.
            logger.warning("AI_MONGODB_URI is not set: Ask NetMap is disabled in production")
        try:
            await db.ensure_indexes(app.state.db)
            await ensure_first_admin(app.state.db, settings)
        except Exception:
            # Start anyway so /health can report the problem; the details go to the server log only.
            logger.exception("MongoDB setup failed at startup")
        try:
            yield
        finally:
            await client.close()
            if ai_client is not None:
                await ai_client.close()

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
    # The language model for Ask NetMap and explanations (NoProvider when LLM_PROVIDER=none).
    app.state.llm = make_provider(settings)
    app.add_exception_handler(RequestValidationError, validation_error_handler)

    # Middleware runs outermost-last-added: SecurityMiddleware wraps everything, so even a 413 or
    # a 500 carries the security headers and a request ID.
    app.add_middleware(OriginAndContentTypeMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityMiddleware, production=settings.is_production)

    for router in API_ROUTERS:
        app.include_router(router)

    @app.get("/health", tags=["system"])
    async def health(request: Request) -> JSONResponse:
        # Public on purpose (Render's health check calls it). It says only ok/unavailable and
        # never includes exception text, hostnames or versions.
        if await db.ping(request.app.state.mongo):
            return JSONResponse({"status": "ok", "database": "ok"})
        return JSONResponse({"status": "degraded", "database": "unavailable"}, status_code=503)

    # Last, so its catch-all route never shadows /api, /health or /docs.
    if not mount_frontend(app, settings.frontend_dist):
        logger.info("No frontend build found; serving the API only")
    return app


app = create_app()
