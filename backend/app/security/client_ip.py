"""The real client IP behind a reverse proxy (Phase 9).

On Render a request travels: client → Cloudflare → Render's proxy → NetMap. The app only sees
Render's proxy (a private 10.x address) as the connecting peer. Each proxy *appends* the
address it received the request from to X-Forwarded-For, so NetMap gets:

    X-Forwarded-For: <anything the client wrote>, <real client>, <Cloudflare edge>
                                                  ^ added by     ^ added by
                                                    Cloudflare     Render's proxy

The leftmost entries are whatever the client sent; Render doesn't remove them. Taking the
first entry (what `uvicorn --forwarded-allow-ips=*` does) would let anyone choose their own
IP and so walk around the per-IP sign-in limit and write fake addresses into the audit log.

So we count from the right instead: with TRUSTED_PROXY_HOPS=N trusted proxies in front of
the app, the client is the N-th entry from the right. A client can add entries on the left
but can't remove the ones the proxies append. The header is used only when the connecting
peer is a private or loopback address (Render's proxy); a request from a public address
didn't come through the proxy and its header is ignored.
"""

import ipaddress
import logging

logger = logging.getLogger("netmap.security")

MAX_HOPS = 5
# A forged header can be long; we only ever need the last few entries.
MAX_HEADER_CHARS = 2048


def _valid_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def _trusted_peer(peer: str) -> bool:
    ip = _valid_ip(peer)
    if ip is None:
        return False
    address = ipaddress.ip_address(ip)
    return address.is_private or address.is_loopback


def resolve(peer: str | None, forwarded_for: list[str], hops: int) -> tuple[str, str]:
    """Return (client IP, how it was chosen). `forwarded_for` holds every X-Forwarded-For
    header value in the order received."""
    peer = peer or "unknown"
    if hops <= 0:
        return peer, "peer"
    if not _trusted_peer(peer):
        return peer, "peer_not_a_proxy"
    joined = ",".join(forwarded_for)[-MAX_HEADER_CHARS:]
    entries = [e.strip() for e in joined.split(",") if e.strip()]
    if len(entries) < hops:
        # Every trusted proxy appends one entry, so a short list means the proxy chain isn't
        # what TRUSTED_PROXY_HOPS says. Fall back to the peer rather than guess.
        return peer, "chain_too_short"
    candidate = _valid_ip(entries[-hops])
    if candidate is None:
        return peer, "invalid_entry"
    return candidate, "forwarded"


def describe(peer: str | None, forwarded_for: list[str], hops: int) -> dict:
    """For the admin request-info page: what came in and what was chosen."""
    ip, how = resolve(peer, forwarded_for, hops)
    joined = ",".join(forwarded_for)[-MAX_HEADER_CHARS:]
    return {
        "peer": peer or "unknown",
        "forwarded_for": [e.strip()[:64] for e in joined.split(",") if e.strip()][-10:],
        "trusted_proxy_hops": hops,
        "client_ip": ip,
        "chosen_by": how,
    }


def warn_once(how: str) -> None:
    """A misconfigured proxy setting shows up in the log, not only as wrong audit IPs."""
    if how in ("chain_too_short", "invalid_entry") and how not in _warned:
        _warned.add(how)
        logger.warning("X-Forwarded-For didn't match TRUSTED_PROXY_HOPS (%s); "
                       "using the connecting address. Check /api/admin/request-info.", how)


_warned: set[str] = set()
