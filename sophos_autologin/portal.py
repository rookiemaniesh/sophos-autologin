"""Talking to the Sophos captive portal, and working out where it is."""

from __future__ import annotations

import re
import socket
import subprocess
import time
from dataclasses import dataclass

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONNECTIVITY_URL = "http://connectivitycheck.gstatic.com/generate_204"
COMMON_PORTS = (8090, 8091, 80, 443)

# Portals capped at one session per account answer a second login with one of
# these instead of a credential error. The account is fine; an older session —
# usually this same machine before it dropped off the network — still holds the
# slot, so the fix is to drop that session and log in again.
# Fingerprint of a Sophos/Cyberoam portal page, used to tell one apart from a
# router's own web UI on port 80.
PORTAL_MARKERS = re.compile(
    r"sophos|cyberoam|login\.xml|httpclient|mode=191|"
    r"captive\s*portal|internet\s+access",
    re.I,
)

SESSION_LIMIT_PATTERNS = (
    r"max.{0,20}(login|user|session).{0,20}limit",
    r"(login|session).{0,20}limit.{0,20}(reach|exceed)",
    r"already\s+log(ged)?\s*.?in",
    r"concurrent",
    r"active\s+session",
)


@dataclass
class Result:
    ok: bool
    message: str
    kicked: bool = False      # an existing session had to be dropped first


def is_session_limit(message: str) -> bool:
    return any(re.search(p, message, re.I) for p in SESSION_LIMIT_PATTERNS)


# ------------------------------------------------------------- detection ---


def default_gateways() -> list[str]:
    """Every default gateway Windows currently knows about — covers the
    machine being on wifi and ethernet at the same time."""
    gateways: list[str] = []
    try:
        out = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return gateways

    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw = parts[2]
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", gw) and gw not in gateways:
                gateways.append(gw)
    return gateways


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _split_location(loc: str) -> tuple[str, int] | None:
    """'http://10.0.0.1:8090/httpclient.html' -> ('10.0.0.1', 8090)."""
    m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", loc)
    if not m:
        return None
    scheme, host, port = m.groups()
    return host, int(port) if port else (443 if scheme == "https" else 80)


def portal_from_redirect(timeout: float = 5.0) -> tuple[str, int] | None:
    """A captive portal answers the 204 probe with a redirect to itself. The
    Location header names the port as well, which is the only fully reliable
    source for it — everything else is guesswork."""
    try:
        r = requests.get(CONNECTIVITY_URL, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None

    if r.status_code in (301, 302, 303, 307, 308):
        return _split_location(r.headers.get("Location", ""))

    if r.status_code == 200 and r.text:
        # Some portals answer 200 with a meta-refresh or a JS jump instead.
        m = re.search(r"""(?:url=|location(?:\.href)?\s*=\s*)['"]?"""
                      r"""(https?://[^\s'"<>]+)""", r.text[:4000], re.I)
        if m:
            return _split_location(m.group(1))
    return None


def looks_like_portal(host: str, port: int, timeout: float = 4.0) -> bool:
    """An open port is not proof: every home router answers on 80, and this
    app running at home must not decide the router is a captive portal. Ask
    for the page and look for the portal's fingerprint."""
    try:
        r = requests.get(f"http://{host}:{port}/", timeout=timeout,
                         verify=False, allow_redirects=True)
    except requests.RequestException:
        return False
    return bool(PORTAL_MARKERS.search(r.text[:20000]))


def discover(configured_host: str = "",
             port: int = 8090) -> tuple[str, int] | None:
    """Where the portal is, host *and* port. Returning the port matters: the
    caller must talk to the port that actually answered, not the one in the
    config."""
    ports = tuple(dict.fromkeys((port, *COMMON_PORTS)))

    # Told where it is: believe it, but still find the live port.
    if configured_host:
        for p in ports:
            if port_open(configured_host, p):
                return configured_host, p
        return None

    # The redirect is the authoritative answer when there is one.
    hit = portal_from_redirect()
    if hit:
        host, p = hit
        if port_open(host, p):
            return host, p
        for alt in ports:
            if port_open(host, alt):
                return host, alt

    # Last resort: probe the gateways. 8090/8091 are portal ports and an open
    # one is signal enough; 80 and 443 belong to every router alive, so a
    # candidate found there has to prove what it is.
    for gw in default_gateways():
        for p in ports:
            if not port_open(gw, p):
                continue
            if p in (80, 443) and not looks_like_portal(gw, p):
                continue
            return gw, p
    return None


def diagnostics(cfg: dict) -> str:
    """What this network actually looks like. For when discovery gets it wrong
    and the answer has to come from the person standing on the network."""
    port = int(cfg.get("portal_port", 8090))
    ports = tuple(dict.fromkeys((port, *COMMON_PORTS)))
    lines = ["Sophos Auto Login — network report", ""]

    lines.append(f"Internet reachable: {'yes' if is_online() else 'no'}")

    hit = portal_from_redirect()
    lines.append(f"Captive-portal redirect: "
                 f"{hit[0] + ':' + str(hit[1]) if hit else 'none seen'}")

    configured = cfg.get("portal_host", "")
    lines.append(f"Portal host in settings: {configured or '(auto-detect)'}")
    lines.append("")

    hosts = [h for h in ([configured] if configured else []) + \
             ([hit[0]] if hit else []) + default_gateways() if h]
    seen: list[str] = []
    for host in hosts:
        if host in seen:
            continue
        seen.append(host)
        lines.append(f"{host}")
        for p in ports:
            if not port_open(host, p):
                lines.append(f"    :{p:<5} closed")
                continue
            marker = "looks like a portal" if looks_like_portal(host, p) \
                else "open, but no portal fingerprint"
            lines.append(f"    :{p:<5} OPEN — {marker}")
        lines.append("")

    found = discover(configured, port)
    lines.append(f"Discovery picked: {found[0] + ':' + str(found[1]) if found else 'nothing'}")
    lines.append("")
    lines.append("If your portal is listed above on a port discovery did not")
    lines.append("pick, put its address in Portal host and set portal_port in")
    lines.append(r"%APPDATA%\SophosAutoLogin\config.json to match.")
    return "\n".join(lines)


def is_online(timeout: float = 5.0) -> bool:
    try:
        r = requests.get(CONNECTIVITY_URL, timeout=timeout, allow_redirects=False)
        return r.status_code == 204
    except requests.RequestException:
        return False


# ---------------------------------------------------------------- actions ---


def _epoch_ms() -> str:
    return str(int(time.time() * 1000))


def _parse(xml: str) -> str:
    m = re.search(r"<message>(.*?)</message>", xml, re.S | re.I)
    text = m.group(1) if m else re.sub(r"<[^>]+>", " ", xml)
    return " ".join(text.split())[:300] or "(empty response)"


class Portal:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        configured_port = int(cfg.get("portal_port", 8090))
        found = discover(cfg.get("portal_host", ""), configured_port)
        self.host, self.port = found or (None, configured_port)

    @property
    def found(self) -> bool:
        return self.host is not None

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def _url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def _failure(self, exc: Exception) -> Result:
        """requests' own text is a wall of urllib3 internals; say the useful
        part instead."""
        if isinstance(exc, requests.ConnectionError):
            return Result(False, f"Nothing answered at {self.address}. The portal "
                                 f"may be on a different port, or this network "
                                 f"may not be the campus one.")
        if isinstance(exc, requests.Timeout):
            return Result(False, f"{self.address} did not respond in time.")
        return Result(False, f"Could not reach {self.address}: "
                             f"{type(exc).__name__}")

    def _attempt(self, username: str, password: str) -> Result:
        payload = {
            "mode": "191",
            "username": username,
            "password": password,
            "a": _epoch_ms(),
            "producttype": "0",
        }
        try:
            r = requests.post(self._url(self.cfg["login_path"]),
                              data=payload, timeout=10, verify=False)
        except requests.RequestException as e:
            return self._failure(e)

        msg = _parse(r.text)
        time.sleep(1.0)
        return Result(is_online(), msg)

    def login(self, username: str, password: str,
              kick_other_session: bool = True) -> Result:
        """One attempt; if the portal refuses because the account already holds
        a session, drop that session and try once more."""
        if not self.found:
            return Result(False, "No captive portal found on this network.")

        res = self._attempt(username, password)
        if res.ok or not kick_other_session or not is_session_limit(res.message):
            return res

        self.logout(username, password)
        time.sleep(1.5)
        retry = self._attempt(username, password)
        if retry.ok:
            return Result(True, f"Dropped the previous session, then logged in "
                                f"— {retry.message}", kicked=True)
        return Result(False, f"Account already has a session and it would not "
                             f"drop — {retry.message}", kicked=True)

    def logout(self, username: str, password: str = "") -> Result:
        if not self.found:
            return Result(False, "No captive portal found on this network.")
        payload = {"mode": "193", "username": username, "a": _epoch_ms()}
        if password:
            # Some builds only honour a logout for a session on another IP when
            # the request proves who it is.
            payload["password"] = password
        try:
            r = requests.post(self._url(self.cfg["login_path"]),
                              data=payload, timeout=10, verify=False)
        except requests.RequestException as e:
            return self._failure(e)
        return Result(True, _parse(r.text))

    def keepalive(self, username: str) -> None:
        if not self.found:
            return
        try:
            requests.get(self._url(self.cfg["live_path"]),
                         params={"mode": "192", "username": username, "a": _epoch_ms()},
                         timeout=8, verify=False)
        except requests.RequestException:
            pass
