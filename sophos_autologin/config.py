"""Settings live in %APPDATA%; the password lives in Windows Credential
Manager (DPAPI-protected, per-user). Never the two in the same place."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_NAME = "SophosAutoLogin"
KEYRING_SERVICE = "sophos-autologin"

APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "autologin.log"

DEFAULTS: dict[str, Any] = {
    "username": "",
    "portal_host": "",        # blank = auto-detect the default gateway
    "portal_port": 8090,
    "login_path": "/login.xml",
    "live_path": "/live",
    "check_interval": 180,    # seconds, used by the scheduled task
    "keepalive": True,
    # Off by default: on a one-session portal, dropping the existing session is
    # the user's call, not something to do behind their back.
    "kick_other_session": False,
}


def load() -> dict[str, Any]:
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass          # corrupt config should not brick the app
    return cfg


def save(cfg: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# --------------------------------------------------------------- password ---


def get_password(username: str) -> str | None:
    import keyring

    if not username:
        return None
    return keyring.get_password(KEYRING_SERVICE, username)


def set_password(username: str, password: str) -> None:
    import keyring

    keyring.set_password(KEYRING_SERVICE, username, password)


def delete_password(username: str) -> None:
    import keyring

    try:
        keyring.delete_password(KEYRING_SERVICE, username)
    except keyring.errors.PasswordDeleteError:
        pass
