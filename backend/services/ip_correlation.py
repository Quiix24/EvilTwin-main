"""
Real-IP correlation for SSH-gateway-proxied honeypot sessions.

The SSH gateway is a man-in-the-middle: it terminates the attacker's connection
and re-originates a fresh SSH connection to Cowrie, so Cowrie logs the *gateway's*
container IP as the source. The gateway, however, knows the real attacker IP and
the local (outbound) TCP port it used to reach Cowrie.

Cowrie records that same port as ``src_port`` on its ``cowrie.session.connect``
event. We therefore map ``gateway_outbound_port -> real_ip`` (reported by the
gateway) and, once a connect event resolves it, remember
``cowrie_session_id -> real_ip`` so the session's later (port-less) events are
attributed to the real attacker too.

All state is in-process (the log tailer and the routing endpoint run in the same
backend process). Port entries have a short TTL; session entries have a much
longer TTL to survive long-running attacker sessions.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

PROXY_MAP_TTL = int(os.getenv("PROXY_MAP_TTL", "600"))
SESSION_CACHE_TTL = int(os.getenv("SESSION_CACHE_TTL", str(86400)))  # 24 h default

RESOLVE_RETRIES = 5
RESOLVE_RETRY_DELAY = 0.3  # seconds per retry

_lock = threading.Lock()
_proxy_port_map: dict[int, dict] = {}   # gateway_outbound_port -> {real_ip, expires_at}
_session_real_ip: dict[str, dict] = {}  # honeypot session id -> {real_ip, expires_at}


def _prune(now: float) -> None:
    for key in [k for k, v in _proxy_port_map.items() if v["expires_at"] <= now]:
        _proxy_port_map.pop(key, None)
    for key in [k for k, v in _session_real_ip.items() if v["expires_at"] <= now]:
        _session_real_ip.pop(key, None)


def register_proxy_mapping(proxy_port: int, real_ip: str, ttl: int = PROXY_MAP_TTL) -> None:
    """Record that the gateway's outbound port ``proxy_port`` corresponds to a
    connection from real attacker ``real_ip``. Called from the routing endpoint."""
    if not proxy_port or not real_ip:
        return
    now = time.time()
    with _lock:
        _proxy_port_map[int(proxy_port)] = {"real_ip": real_ip, "expires_at": now + max(ttl, 1)}
        _prune(now)
    logger.debug("Proxy map registered: port %s -> %s (ttl=%ss)", proxy_port, real_ip, ttl)


async def resolve_for_connect(
    proxy_port: int,
    honeypot_session: str | None,
    port_ttl: int = PROXY_MAP_TTL,
    session_ttl: int = SESSION_CACHE_TTL,
) -> str | None:
    """Resolve the real IP for a honeypot connection event (Cowrie
    ``session.connect`` or Dionaea ``connection.*.accept``) by its
    ``src_port``.

    Retries up to ``RESOLVE_RETRIES`` times with ``RESOLVE_RETRY_DELAY``
    between attempts. This eliminates the race condition where the gateway's
    proxy map registration HTTP POST is still in-flight when the log tailer
    first reads the connect event.

    On success the real IP is cached in ``_session_real_ip`` so subsequent
    (port-less) events for the same session are attributed correctly.
    """
    if not proxy_port:
        return None

    port = int(proxy_port)

    for attempt in range(RESOLVE_RETRIES):
        now = time.time()
        with _lock:
            entry = _proxy_port_map.get(port)
            if entry and entry["expires_at"] > now:
                real_ip = entry["real_ip"]
                if honeypot_session:
                    _session_real_ip[str(honeypot_session)] = {
                        "real_ip": real_ip,
                        "expires_at": now + max(session_ttl, 1),
                    }
                    _prune(now)
                logger.debug(
                    "Real IP resolved on attempt %d: port %s -> %s (session=%s)",
                    attempt + 1, port, real_ip, honeypot_session,
                )
                return real_ip
            _prune(now)

        await asyncio.sleep(RESOLVE_RETRY_DELAY)

    # Fallback: Docker userland proxy often scrambles source ports.
    # If we couldn't match the port exactly, pick the most recent valid IP.
    now = time.time()
    with _lock:
        logger.warning("FALLBACK CHECK: _proxy_port_map = %s", _proxy_port_map)
        valid_entries = [e for e in _proxy_port_map.values() if e["expires_at"] > now]
        if valid_entries:
            # Pick the one with the highest expires_at (most recently added since TTL is constant)
            latest = max(valid_entries, key=lambda e: e["expires_at"])
            real_ip = latest["real_ip"]
            if honeypot_session:
                _session_real_ip[str(honeypot_session)] = {
                    "real_ip": real_ip,
                    "expires_at": now + max(session_ttl, 1),
                }
            logger.debug(
                "Real IP resolved via FALLBACK: port %s scrambled -> %s (session=%s)",
                port, real_ip, honeypot_session,
            )
            return real_ip

    logger.debug(
        "Real IP NOT resolved after %d attempts for port %s (session=%s) — "
        "gateway proxy map may not have arrived yet",
        RESOLVE_RETRIES, port, honeypot_session,
    )
    return None


def resolve_for_session(
    honeypot_session: str | None,
    ttl: int = SESSION_CACHE_TTL,
) -> str | None:
    """Resolve the real IP for a non-connect event using the session id."""
    if not honeypot_session:
        return None
    now = time.time()
    with _lock:
        entry = _session_real_ip.get(honeypot_session)
        if entry and entry["expires_at"] > now:
            entry["expires_at"] = now + max(ttl, 1)
            return entry["real_ip"]
            
        # If the backend restarted and missed the connect event, try fallback
        valid_entries = [e for e in _proxy_port_map.values() if e["expires_at"] > now]
        if valid_entries:
            latest = max(valid_entries, key=lambda e: e["expires_at"])
            real_ip = latest["real_ip"]
            # Cache it so future events for this session don't need fallback
            _session_real_ip[honeypot_session] = {
                "real_ip": real_ip,
                "expires_at": now + max(ttl, 1),
            }
            logger.warning("Session %s resolved via late proxy map fallback -> %s", honeypot_session, real_ip)
            return real_ip

    return None
