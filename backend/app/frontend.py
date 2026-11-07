"""Serve the built React app from the same origin as the API (CLAUDE.md section 2).

Same origin means the session cookie can be httpOnly + SameSite=Strict and no CORS is needed.
- /assets/*         hashed JS/CSS/font files from the Vite build, cached for a year
- top-level files   e.g. favicon.svg, only names that exist in dist at startup
- anything else     index.html, so React Router deep links like /subnets/abc work on reload
- /api/*            never the app: an unknown API path stays a JSON 404
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# The build output is immutable per file name (Vite puts a content hash in it).
ASSET_CACHE = "public, max-age=31536000, immutable"


class CachedStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["cache-control"] = ASSET_CACHE
        return response


def mount_frontend(app: FastAPI, dist: Path | None) -> bool:
    if dist is None or not (dist / "index.html").is_file():
        return False
    index = dist / "index.html"
    # A fixed allowlist of names read once: a request path is only ever compared against it,
    # never joined onto the folder, so "../" tricks can't reach other files.
    top_level = {p.name: p for p in dist.iterdir() if p.is_file() and p.name != "index.html"}
    if (dist / "assets").is_dir():
        app.mount("/assets", CachedStaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        if path in top_level:
            return FileResponse(top_level[path])
        # index.html is small and changes on every deploy: always revalidate it.
        return FileResponse(index, headers={"cache-control": "no-cache"})

    return True
