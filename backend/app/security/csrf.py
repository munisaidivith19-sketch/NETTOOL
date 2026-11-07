"""CSRF protection (CLAUDE.md 7.7).

Three layers, because each one alone has gaps:
1. SameSite=Strict cookie: browsers don't attach it to requests started by other sites.
2. Origin + content type (middleware below): a state-changing /api request from a foreign
   Origin is refused, and its body must be JSON. A cross-site HTML form can't send JSON, and a
   cross-site script sending JSON triggers a CORS preflight, which we never approve.
3. Synchronizer token: each session has a random CSRF token, given to the frontend in the
   login/me response. Every POST/PUT/PATCH/DELETE must echo it in X-CSRF-Token. Another site
   can't read it, so it can't forge the header.
"""

import hmac
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Receive, Scope, Send

from app.security.http import send_json

HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def check_token(request: Request, expected: str) -> None:
    if request.method not in UNSAFE_METHODS:
        return
    supplied = request.headers.get(HEADER, "")
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")


class OriginAndContentTypeMiddleware:
    """Layer 2: refuse cross-site origins and non-JSON bodies on state-changing /api requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] not in UNSAFE_METHODS
            or not scope["path"].startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        origin = headers.get("origin")
        if origin is not None:
            # "null" (sandboxed frames, file://) and any other host are refused.
            if urlsplit(origin).netloc.lower() != headers.get("host", "").lower():
                await send_json(send, 403, {"detail": "Cross-origin request refused"})
                return

        has_body = headers.get("content-length", "0") != "0" or "transfer-encoding" in headers
        content_type = headers.get("content-type", "").split(";")[0].strip().lower()
        if has_body and content_type != "application/json":
            await send_json(send, 415, {"detail": "Content-Type must be application/json"})
            return

        await self.app(scope, receive, send)
