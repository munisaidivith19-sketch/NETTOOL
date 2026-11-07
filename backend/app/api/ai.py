"""Ask NetMap and plain-language explanations (user routes).

- POST /api/ai/ask      any role. The answer shows the exact query that ran.
- POST /api/ai/explain  any role for alerts and findings; config diffs need engineer or admin
                        (the same people who may read config text).
- GET  /api/ai/status   which model is configured and whether the read-only DB user is used.
Each user gets AI_CALLS_PER_10_MINUTES calls, which protects the free-tier model quota.
The audit log records each question's length and result size, not the question itself.
"""

import json
from datetime import timedelta

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.ai import explain as explainer
from app.ai import nlsearch
from app.ai.llm import LLMError
from app.ai.rules import EXAMPLES
from app.models.ai import AskRequest, ExplainRequest
from app.security.rbac import CurrentUser, require_user
from app.security.sessions import utcnow
from app.services import audit

router = APIRouter(prefix="/api/ai", tags=["ai"], dependencies=[Depends(require_user)])
RATE_WINDOW = timedelta(minutes=10)


async def _rate_limit(request: Request, user: CurrentUser) -> None:
    db = request.app.state.db
    limit = request.app.state.settings.ai_calls_per_10_minutes
    now = utcnow()
    used = await db.ai_calls.count_documents(
        {"user_id": user.id, "at": {"$gte": now - RATE_WINDOW}}, limit=limit)
    if used >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"AI limit reached ({limit} requests per 10 minutes). "
                            "Try again in a few minutes.")
    await db.ai_calls.insert_one({"user_id": user.id, "at": now})


@router.get("/status")
async def ai_status(request: Request) -> dict:
    llm = request.app.state.llm
    return {"provider": llm.name, "model": getattr(llm, "model", None),
            "readonly_user": request.app.state.ai_readonly_user,
            "calls_per_10_minutes": request.app.state.settings.ai_calls_per_10_minutes,
            "examples": EXAMPLES}


@router.post("/ask")
async def ask(body: AskRequest, request: Request,
              user: CurrentUser = Depends(require_user)) -> dict:
    await _rate_limit(request, user)
    db = request.app.state.db

    async def log(result: str, details: dict) -> None:
        await audit.record(db, request, action="ai.ask", result=result,
                           actor=audit.user_actor(user),
                           details={"question_length": len(body.question)} | details)

    try:
        answer = await nlsearch.ask(body.question, ai_db=request.app.state.ai_db,
                                    llm=request.app.state.llm, now=utcnow())
    except nlsearch.NotUnderstood as exc:
        await log("failure", {"reason": "not_understood"})
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            {"message": str(exc), "examples": EXAMPLES}) from None
    except nlsearch.QueryRejected as exc:
        proposal = getattr(exc, "proposal", None)
        await log("failure", {"reason": "rejected", "source": getattr(exc, "source", None)})
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, {
            "message": f"NetMap refused to run this query: {exc}",
            "query_text": json.dumps(proposal, indent=2, default=str)[:3000]
            if proposal is not None else None,
            "examples": EXAMPLES}) from None
    except LLMError as exc:
        await log("failure", {"reason": "llm_error"})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"message": str(exc)}) from None
    query = answer["query"]
    await log("success", {"source": answer["source"],
                          "collection": query.get("collection") or query.get("tool"),
                          "rows": answer["row_count"]})
    return answer | {"readonly_user": request.app.state.ai_readonly_user}


def _forbidden_diff(user: CurrentUser) -> None:
    if user.role not in ("admin", "engineer"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Config changes can only be explained to engineers and admins")


@router.post("/explain")
async def explain(body: ExplainRequest, request: Request,
                  user: CurrentUser = Depends(require_user)) -> dict:
    if body.kind == "diff":
        _forbidden_diff(user)
    db = request.app.state.db
    removed = 0
    if body.kind == "alert":
        alert = await db.alerts.find_one({"_id": ObjectId(body.id)})
        if alert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
        facts = explainer.alert_facts(alert)
        template = explainer.alert_template(alert)
    else:
        device = await db.devices.find_one(
            {"_id": ObjectId(body.id)},
            {"sys_name": 1, "mgmt_ip": 1, "vendor": 1, "config_vendor": 1, "compliance": 1})
        if device is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
        if body.kind == "finding":
            findings = (device.get("compliance") or {}).get("findings") or []
            finding = next((f for f in findings if f.get("rule") == body.rule), None)
            if body.rule is None or finding is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
            facts = explainer.finding_facts(device, finding)
            template = explainer.finding_template(finding)
        else:
            if body.from_version is None or body.to_version is None:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                    "from_version and to_version are required")
            versions = (body.from_version, body.to_version)
            docs = {c["version"]: c["text"] async for c in db.configs.find(
                {"device_id": device["_id"], "version": {"$in": list(versions)}},
                {"version": 1, "text": 1})}
            if any(v not in docs for v in versions):
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
            lines, _more = explainer.diff_lines(docs[versions[0]], docs[versions[1]])
            kept, removed = explainer.secret_free(lines)
            facts = [f"Device: {explainer._clean(device.get('sys_name') or device['mgmt_ip'])}",
                     f"Config version {versions[0]} -> {versions[1]}", *kept]
            template = explainer.diff_template(kept, removed, versions)
    await _rate_limit(request, user)
    result = await explainer.explain(db, request.app.state.llm, body.kind, facts, template,
                                     utcnow(), removed)
    if body.kind == "diff":
        await audit.record(db, request, action="ai.explain", result="success",
                           actor=audit.user_actor(user),
                           target={"type": "device", "id": body.id},
                           details={"kind": body.kind, "source": result["source"],
                                    "from": body.from_version, "to": body.to_version})
    return result
