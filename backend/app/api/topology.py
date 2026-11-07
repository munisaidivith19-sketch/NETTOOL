"""Topology map and endpoint location (any role, read only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app.security.rbac import require_user
from app.security.sessions import utcnow
from app.services.topology import build_graph, locate

router = APIRouter(prefix="/api/topology", tags=["topology"], dependencies=[Depends(require_user)])

# An IP, a MAC (any common notation) or a host name. No "$", quotes, braces or regex
# characters; the service builds filters from the parsed value and escapes text.
LocateText = Annotated[str, Query(min_length=1, max_length=100,
                                  pattern=r"^[A-Za-z0-9.:_\-]+$")]


@router.get("")
async def topology(request: Request) -> dict:
    return await build_graph(request.app.state.db)


@router.get("/locate")
async def locate_endpoint(request: Request, q: LocateText) -> dict:
    """Which switch port is this IP / MAC / host name on?"""
    return await locate(request.app.state.db, q, utcnow())
