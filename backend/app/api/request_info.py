"""What the server sees of your request (admin only, Phase 9).

After deploying behind a proxy, open this page and compare `client_ip` with your real public
address (e.g. from a "what is my IP" site). If they differ, TRUSTED_PROXY_HOPS doesn't match
the proxy chain, and the rate limits and the audit log would use the wrong address.
It is also the live demo that a forged X-Forwarded-For entry is ignored.
"""

from fastapi import APIRouter, Depends, Request

from app.security import client_ip as proxy_ip
from app.security.rbac import require_admin

router = APIRouter(prefix="/api/admin/request-info", tags=["system"],
                   dependencies=[Depends(require_admin)])


@router.get("")
async def request_info(request: Request) -> dict:
    return proxy_ip.describe(request.client.host if request.client else None,
                             request.headers.getlist("x-forwarded-for"),
                             request.app.state.settings.trusted_proxy_hops)
