import hashlib
import hmac
import json
import logging
import time

import httpx
import pytest

from netmap_agent.config import AgentSettings
from netmap_agent.uploader import MAX_ATTEMPTS, Uploader, UploadError

AGENT_ID = "agt_0123456789abcdef"
AGENT_KEY = "test-agent-key-0123456789"


def settings(**values) -> AgentSettings:
    base = {"api_url": "https://netmap.example.org", "agent_id": AGENT_ID, "agent_key": AGENT_KEY}
    return AgentSettings(_env_file=None, **(base | values))


def expected_signature(request: httpx.Request) -> str:
    """Written from the documented scheme (CLAUDE.md 7.3), not from uploader.py's code."""
    path = request.url.raw_path.decode()
    message = "\n".join([
        request.method,
        path,
        request.headers["X-Timestamp"],
        request.headers["X-Nonce"],
        hashlib.sha256(request.content).hexdigest(),
    ])
    return hmac.new(AGENT_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()


def make_uploader(handler, sleeps=None, **values) -> Uploader:
    sleeps = [] if sleeps is None else sleeps
    return Uploader(settings(**values), transport=httpx.MockTransport(handler), sleep=sleeps.append)


def test_signature_matches_independent_implementation():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"summary": {"devices": 1}})

    uploader = make_uploader(handler)
    assert uploader.send_report({"devices": []}) == {"summary": {"devices": 1}}
    request = seen[0]
    assert request.url == "https://netmap.example.org/api/agent/report"
    assert request.headers["X-Agent-Id"] == AGENT_ID
    assert request.headers["X-Signature"] == expected_signature(request)
    assert request.headers["Content-Type"] == "application/json"
    assert abs(int(request.headers["X-Timestamp"]) - time.time()) < 5
    assert 16 <= len(request.headers["X-Nonce"]) <= 64
    assert json.loads(request.content) == {"devices": []}


def test_key_is_never_sent():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"devices": []})

    make_uploader(handler).known_devices()
    raw = str(seen[0].headers) + seen[0].content.decode() + str(seen[0].url)
    assert AGENT_KEY not in raw


def test_known_devices_get_has_empty_body_signature():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"devices": [{"mgmt_ip": "10.0.0.1"}]})

    assert make_uploader(handler).known_devices() == [{"mgmt_ip": "10.0.0.1"}]
    assert seen[0].method == "GET" and seen[0].content == b""
    assert seen[0].headers["X-Signature"] == expected_signature(seen[0])


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_retries_retryable_statuses_with_fresh_nonce(status):
    responses = iter([httpx.Response(status), httpx.Response(status), httpx.Response(200, json={})])
    nonces, sleeps = [], []

    def handler(request):
        nonces.append(request.headers["X-Nonce"])
        return next(responses)

    make_uploader(handler, sleeps).send_report({})
    assert len(nonces) == 3 and len(set(nonces)) == 3  # a retry is a new signed request
    assert len(sleeps) == 2 and 1 <= sleeps[0] < 2 and 2 <= sleeps[1] < 3


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 415, 422])
def test_does_not_retry_client_errors(status):
    calls, sleeps = [], []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    with pytest.raises(UploadError, match=str(status)):
        make_uploader(handler, sleeps).send_report({})
    assert len(calls) == 1 and sleeps == []


def test_gives_up_after_max_attempts_on_connection_errors(caplog):
    sleeps = []

    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with caplog.at_level(logging.WARNING), pytest.raises(UploadError, match="ConnectError"):
        make_uploader(handler, sleeps).send_report({})
    assert len(sleeps) == MAX_ATTEMPTS - 1
    assert max(sleeps) <= 61  # backoff capped at 60 s plus up to 1 s jitter
    assert AGENT_KEY not in caplog.text


def test_refuses_plain_http_even_if_settings_were_bypassed():
    unsafe = AgentSettings.model_construct(
        api_url="http://netmap.example.org", agent_id=AGENT_ID, allow_insecure_local=True,
        agent_key=settings().agent_key)
    with pytest.raises(UploadError, match="plain HTTP"):
        Uploader(unsafe)


def test_local_http_allowed_with_flag():
    uploader = make_uploader(lambda r: httpx.Response(200, json={}),
                             api_url="http://127.0.0.1:8000", allow_insecure_local=True)
    assert uploader.send_report({}) == {}


def test_requires_credentials():
    with pytest.raises(UploadError, match="AGENT_ID"):
        Uploader(settings(agent_key=""))
