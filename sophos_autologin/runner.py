"""The headless path. Runs silently from the scheduled task, does nothing
at all unless it is on a network with a captive portal."""

from __future__ import annotations

import json
import logging
import time
from logging.handlers import RotatingFileHandler

from . import config
from .portal import Portal, is_online

MAX_FAILURES = 3
BACKOFF_SECONDS = 900          # 15 min cooldown after repeated rejections
STATE_PATH = config.APP_DIR / "state.json"

# On a one-session-per-account portal, two machines both set to log in
# automatically will kick each other every few minutes forever. Repeated kicks
# in a short window are the signature of that, so stand down and let the other
# device keep the session.
MAX_KICKS = 3
KICK_WINDOW = 1800             # 30 minutes


def setup_logging() -> logging.Logger:
    config.APP_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("sophos")
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    handler = RotatingFileHandler(config.LOG_PATH, maxBytes=256_000,
                                  backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    log.addHandler(handler)
    return log


def _state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"failures": 0, "blocked_until": 0, "kicks": []}


def _save_state(state: dict) -> None:
    config.APP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def run_once() -> int:
    """0 = online (or already online), 1 = did not get online, 2 = nothing to do."""
    log = setup_logging()
    cfg = config.load()
    username = cfg.get("username", "")

    if not username:
        log.info("No username configured; nothing to do.")
        return 2

    state = _state()
    if time.time() < state.get("blocked_until", 0):
        remaining = int(state["blocked_until"] - time.time())
        log.info("In backoff for another %ds; skipping.", remaining)
        return 2

    portal = Portal(cfg)
    if not portal.found:
        log.debug("No captive portal on this network.")
        return 2

    if is_online():
        if cfg.get("keepalive", True):
            portal.keepalive(username)
        return 0

    password = config.get_password(username)
    if not password:
        log.error("No stored password for %s.", username)
        return 2

    kicks = [t for t in state.get("kicks", []) if time.time() - t < KICK_WINDOW]
    result = portal.login(username, password,
                          kick_other_session=cfg.get("kick_other_session", False))

    if result.kicked:
        kicks.append(time.time())
        if len(kicks) >= MAX_KICKS:
            log.warning(
                "Dropped an existing session %d times in %d minutes. Something "
                "else is logging in with this account — standing down for %d "
                "minutes so the two do not fight.",
                len(kicks), KICK_WINDOW // 60, BACKOFF_SECONDS // 60)
            _save_state({"failures": 0, "kicks": [],
                         "blocked_until": time.time() + BACKOFF_SECONDS})
            return 1

    if result.ok:
        log.info("Logged in via %s — %s", portal.address, result.message)
        _save_state({"failures": 0, "blocked_until": 0, "kicks": kicks})
        return 0

    failures = state.get("failures", 0) + 1
    log.warning("Login failed (%d/%d) — %s", failures, MAX_FAILURES, result.message)

    if failures >= MAX_FAILURES:
        # Repeated rejection usually means a changed or wrong password.
        # Hammering it from here on is how accounts get locked out.
        log.error("Backing off for %d minutes.", BACKOFF_SECONDS // 60)
        _save_state({"failures": 0, "kicks": kicks,
                     "blocked_until": time.time() + BACKOFF_SECONDS})
    else:
        _save_state({"failures": failures, "blocked_until": 0, "kicks": kicks})
    return 1
