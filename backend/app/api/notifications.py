"""Notification settings status and a test message (admin only).

Channels are configured with environment variables on the server, never from the browser:
a bot token or SMTP password typed into a web form would end up in the database.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.security.rbac import CurrentUser, require_admin
from app.services import audit, notify

router = APIRouter(prefix="/api/admin/notifications", tags=["notifications"],
                   dependencies=[Depends(require_admin)])

RECENT = 20


@router.get("")
async def notification_status(request: Request) -> dict:
    settings = request.app.state.settings
    channels = notify.configured_channels(settings)
    recent = []
    async for doc in request.app.state.db.notifications.find({}).sort("at", -1).limit(RECENT):
        recent.append({"at": doc["at"], "type": doc.get("type"), "severity": doc.get("severity"),
                       "alert_key": doc.get("alert_key"), "status": doc.get("status"),
                       "reason": doc.get("reason"), "channels": doc.get("channels", {})})
    return {
        "channels": {"telegram": "telegram" in channels, "email": "email" in channels},
        "min_severity": settings.notify_min_severity,
        "cooldown_minutes": int(notify.COOLDOWN.total_seconds() // 60),
        "hourly_cap": notify.HOURLY_CAP,
        "recent": recent,
    }


@router.post("/test")
async def send_test(request: Request, admin: CurrentUser = Depends(require_admin)) -> dict:
    db = request.app.state.db
    settings = request.app.state.settings
    if not notify.configured_channels(settings):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "No notification channel is configured on the server")
    results = await notify.send_test(db, settings)
    if results.get("error") == "rate_limited":
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many test messages; try again in a few minutes")
    ok = any(r == "sent" for r in results.values())
    await audit.record(db, request, action="notify.test", result="success" if ok else "failure",
                       actor=audit.user_actor(admin), target={"type": "notifications"},
                       details={"channels": results})
    return {"channels": results}
