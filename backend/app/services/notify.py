"""Alert notifications by Telegram and e-mail, sent by the backend (owner decision 2026-11-07).

When a check opens or reopens an alert it sets notify_pending=True (services/alerts.py).
dispatch_pending() runs as a FastAPI background task after the response is sent, claims each
pending alert atomically (so two requests can't send the same alert twice) and sends it.

Safety rules:
- Plain text only. Telegram gets no parse_mode, so a device named "<b>" or "[x](evil)" can't
  inject formatting or links. E-mail headers contain only fixed text, never device data.
- Rate limits: one message per alert per COOLDOWN, at most HOURLY_CAP messages per hour in
  total, so a flapping link or a broadcast storm can't flood a phone. Every decision is
  recorded in the notifications collection (kept 7 days).
- Secrets: the Telegram bot token is part of the request URL, and httpx logs every request URL
  at INFO level, so the httpx loggers are raised to WARNING. Errors are reported by exception
  type and status code only, never by their text (which may contain the URL).
- Messages contain alert text only: never configs, credentials or community strings.
"""

import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage

import httpx
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.config import Settings
from app.security.sessions import utcnow

logger = logging.getLogger("netmap.notify")
for noisy in ("httpx", "httpcore"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
COOLDOWN = timedelta(minutes=30)
HOURLY_CAP = 20
TEST_CAP_PER_10_MIN = 5
TIMEOUT_SECONDS = 10
MAX_PER_DISPATCH = 100
MAX_MESSAGE = 1000
TYPE_LABELS = {
    "duplicate_ip": "Duplicate IP address",
    "subnet_usage": "Subnet almost full",
    "device_down": "Device down",
    "interface_down": "Uplink down",
    "new_mac": "New unknown device",
}


class NotifyError(Exception):
    """A channel failed. The message is a short reason that is safe to store and log."""


def configured_channels(settings: Settings) -> list[str]:
    channels = []
    if settings.telegram_bot_token and settings.telegram_chat_id:
        channels.append("telegram")
    if settings.smtp_host and settings.smtp_from and settings.smtp_to:
        channels.append("email")
    return channels


def format_alert(alert: dict) -> tuple[str, str]:
    """(subject, body). The subject is built from fixed words only."""
    severity = str(alert.get("severity", "warning")).upper()
    subject = f"[NetMap] {severity}: {TYPE_LABELS.get(alert.get('type'), 'Alert')}"
    message = str(alert.get("message", ""))[:MAX_MESSAGE]
    body = f"{subject}\n\n{message}\n"
    opened = alert.get("opened_at")
    if isinstance(opened, datetime):
        body += f"\nOpened: {opened:%Y-%m-%d %H:%M} UTC"
    if alert.get("occurrences", 1) > 1:
        body += f" (occurrence {alert['occurrences']})"
    return subject, body


async def send_telegram(settings: Settings, text: str) -> None:
    token = settings.telegram_bot_token.get_secret_value()  # type: ignore[union-attr]
    url = f"{settings.telegram_api_base.rstrip('/')}/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.post(url, json={
                "chat_id": settings.telegram_chat_id, "text": text,
                "disable_web_page_preview": True,
            })
    except Exception as exc:  # the exception text may contain the URL, so only its type
        raise NotifyError(type(exc).__name__) from None
    if response.status_code != 200:
        raise NotifyError(f"HTTP {response.status_code}")


def _send_email_sync(settings: Settings, subject: str, text: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(a.strip() for a in (settings.smtp_to or "").split(","))
    message.set_content(text)
    context = ssl.create_default_context()  # verifies the server certificate
    try:
        if settings.smtp_security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port,
                                                    timeout=TIMEOUT_SECONDS, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port,
                                  timeout=TIMEOUT_SECONDS)
        with server:
            if settings.smtp_security == "starttls":
                server.starttls(context=context)  # raises if the server can't do TLS
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(type(exc).__name__) from None


async def send_email(settings: Settings, subject: str, text: str) -> None:
    await asyncio.to_thread(_send_email_sync, settings, subject, text)  # smtplib blocks


async def deliver(settings: Settings, subject: str, text: str) -> dict[str, str]:
    """Send on every configured channel. Returns {"telegram": "sent" | "failed: <reason>"}."""
    results = {}
    for channel in configured_channels(settings):
        try:
            if channel == "telegram":
                await send_telegram(settings, text)
            else:
                await send_email(settings, subject, text)
            results[channel] = "sent"
        except NotifyError as exc:
            results[channel] = f"failed: {exc}"
            logger.warning("Notification by %s failed: %s", channel, exc)
    return results


async def _suppression(db: AsyncDatabase, alert_key: str, now: datetime) -> str | None:
    if await db.notifications.find_one({"alert_key": alert_key, "status": "sent",
                                        "at": {"$gte": now - COOLDOWN}}, {"_id": 1}):
        return "cooldown"
    sent_last_hour = await db.notifications.count_documents(
        {"status": "sent", "at": {"$gte": now - timedelta(hours=1)}})
    if sent_last_hour >= HOURLY_CAP:
        return "hourly_cap"
    return None


async def dispatch_pending(db: AsyncDatabase, settings: Settings) -> int:
    """Send every alert waiting for a notification. Returns how many were sent."""
    sent = 0
    try:
        channels = configured_channels(settings)
        minimum = SEVERITY_RANK[settings.notify_min_severity]
        for _ in range(MAX_PER_DISPATCH):
            alert = await db.alerts.find_one_and_update(
                {"notify_pending": True}, {"$unset": {"notify_pending": ""}},
                return_document=ReturnDocument.AFTER)
            if alert is None:
                break
            if (not channels or alert.get("status") != "open"
                    or SEVERITY_RANK.get(alert.get("severity"), 0) < minimum):
                continue  # nothing to send it with, already resolved, or below the threshold
            now = utcnow()
            record = {"alert_key": alert["key"], "alert_id": alert["_id"],
                      "type": alert.get("type"), "severity": alert.get("severity"), "at": now}
            reason = await _suppression(db, alert["key"], now)
            if reason:
                await db.notifications.insert_one({**record, "status": "suppressed",
                                                   "reason": reason})
                continue
            subject, text = format_alert(alert)
            results = await deliver(settings, subject, text)
            ok = any(r == "sent" for r in results.values())
            sent += ok
            await db.notifications.insert_one({**record, "status": "sent" if ok else "failed",
                                               "channels": results})
    except Exception:
        # A background task has no one to report to; log it (no secrets in it) and stop.
        logger.exception("Notification dispatch failed")
    return sent


async def send_test(db: AsyncDatabase, settings: Settings) -> dict[str, str]:
    now = utcnow()
    recent = await db.notifications.count_documents(
        {"type": "test", "at": {"$gte": now - timedelta(minutes=10)}})
    if recent >= TEST_CAP_PER_10_MIN:
        return {"error": "rate_limited"}
    subject = "[NetMap] Test notification"
    text = (f"{subject}\n\nIf you can read this, NetMap alert notifications work.\n"
            f"Sent: {now:%Y-%m-%d %H:%M} UTC")
    results = await deliver(settings, subject, text)
    await db.notifications.insert_one({
        "alert_key": "test", "type": "test", "severity": "info", "at": now, "channels": results,
        "status": "sent" if any(r == "sent" for r in results.values()) else "failed",
    })
    return results
