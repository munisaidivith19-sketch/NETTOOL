"""HTTP hardening middleware: request IDs, security headers, safe 500s, body size limits.

These are plain ASGI middlewares (not BaseHTTPMiddleware) so they also cover streamed bodies and
responses produced by other middleware.
"""

import json
import logging
import uuid

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("netmap.http")

DEFAULT_BODY_LIMIT = 2 * 1024 * 1024
# Agent discovery reports can be large; only this path gets the bigger limit (CLAUDE.md 7.4).
LARGE_BODY_PATHS = {"/api/agent/report": 10 * 1024 * 1024,
                    "/api/agent/ai/predictions": 10 * 1024 * 1024}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
# Swagger UI (/docs, development only) loads its script and CSS from a CDN with inline code.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)
DOCS_PATHS = ("/docs", "/redoc")
PERMISSIONS_POLICY = b"camera=(), microphone=(), geolocation=(), usb=(), payment=()"


async def send_json(send: Send, status: int, body: dict, extra_headers=()) -> None:
    payload = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                *extra_headers,
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class SecurityMiddleware:
    """Outermost layer. Adds a request ID and security headers to every response, including
    errors, and turns any unhandled exception into a generic 500 with no internal details."""

    def __init__(self, app: ASGIApp, *, production: bool) -> None:
        self.app = app
        self.production = production

    def _headers(self, path: str, request_id: str) -> list[tuple[bytes, bytes]]:
        docs = not self.production and path.startswith(DOCS_PATHS)
        headers = [
            (b"x-request-id", request_id.encode()),
            (b"content-security-policy", (DOCS_CSP if docs else CSP).encode()),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"permissions-policy", PERMISSIONS_POLICY),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-origin"),
        ]
        if path.startswith("/api/"):
            headers.append((b"cache-control", b"no-store"))
        if self.production:
            headers.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
        return headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Always generated here, never taken from the client, so log entries can't be spoofed.
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        security_headers = self._headers(scope["path"], request_id)
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                names = {name for name, _ in security_headers}
                kept = [(n, v) for n, v in message.get("headers", []) if n.lower() not in names]
                message["headers"] = kept + security_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            logger.exception("Unhandled error (request_id=%s)", request_id)
            if started:
                raise
            await send_json(
                send,
                500,
                {"detail": "Internal server error", "request_id": request_id},
                security_headers,
            )


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = LARGE_BODY_PATHS.get(scope["path"], DEFAULT_BODY_LIMIT)
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await send_json(send, 400, {"detail": "Invalid Content-Length"})
                    return
                if declared > limit:
                    await send_json(send, 413, {"detail": "Request body too large"})
                    return

        # Content-Length can be missing (chunked upload) or wrong, so also count real bytes.
        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # An HTTPException, because FastAPI turns any other error raised while
                    # reading the body into a generic 400.
                    raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, counting_receive, send)
