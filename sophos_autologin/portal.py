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
SCAN_TIMEOUT = 0.7        # per TCP connect while hunting for the portal

# Probes used to make the network reveal the portal. The first needs DNS, which
# many portals block until you log in — so the rest are bare IPs, which an
# intercepting appliance still answers.
PROBE_URLS = (
    CONNECTIVITY_URL,
    "http://1.1.1.1/",
    "http://204.79.197.200/",     # msftconnecttest, by address
)

# Fingerprint of a Sophos/Cyberoam portal, used to tell one apart from a
# router's own web UI on port 80. Deliberately narrow: a false positive here
# sends someone's password to the wrong host.
PORTAL_MARKERS = re.compile(
    r"sophos|cyberoam|login\.xml|httpclient|mode=191|"
    r"<\s*(requestresponse|liveuser|status)\b",
    re.I,
)

# Portals capped at one session per account answer a second login with one of
# these instead of a credential error. The account is fine; an older session —
# usually this same machine before it dropped off the network — still holds the
# slot, so the fix is to drop that session and log in again.
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


def _is_private(ip: str) -> bool:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
        return False
    a, b = (int(x) for x in ip.split(".")[:2])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 100 and 64 <= b <= 127))


def infrastructure_hosts() -> list[str]:
    """DHCP and DNS servers handed out by this network. On a campus the Sophos
    appliance is usually one of them, and it is often not the gateway — which
    is the case discovery otherwise has no way to solve. Read from the registry
    rather than ipconfig, so the labels cannot change with the display
    language."""
    hosts: list[str] = []
    try:
        import winreg
    except ImportError:
        return hosts

    key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    except OSError:
        return hosts

    with root:
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                with winreg.OpenKey(root, winreg.EnumKey(root, i)) as iface:
                    for name in ("DhcpServer", "DhcpNameServer", "NameServer"):
                        try:
                            value = str(winreg.QueryValueEx(iface, name)[0])
                        except OSError:
                            continue
                        for ip in re.split(r"[ ,;]+", value):
                            if _is_private(ip) and ip not in hosts:
                                hosts.append(ip)
            except OSError:
                continue
    return hosts


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


def probe(url: str, timeout: float = 4.0) -> tuple[str, tuple[str, int] | None]:
    """Ask the network for a page it should not be able to serve. Returns a
    human-readable note and, if the answer named a portal, its address."""
    probe_host = re.sub(r"^https?://([^/:]+).*", r"\1", url)
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.exceptions.ConnectionError as e:
        if "NameResolutionError" in str(e) or "getaddrinfo" in str(e):
            return "DNS blocked (typical before you log in)", None
        return "unreachable", None
    except requests.RequestException:
        return "no answer", None

    if r.status_code == 204:
        return "got through — no interception here", None

    hit = None
    if r.status_code in (301, 302, 303, 307, 308):
        hit = _split_location(r.headers.get("Location", ""))
        if hit and hit[0] == probe_host:
            # http -> https on the same host is the site itself, not a portal.
            return f"redirected to itself ({r.status_code})", None
        if hit:
            return f"redirected to {hit[0]}:{hit[1]}", hit

    if r.status_code == 200 and r.text:
        # Some portals answer 200 with a meta-refresh or a JS jump instead.
        m = re.search(r"""(?:url=|location(?:\.href)?\s*=\s*)['"]?"""
                      r"""(https?://[^\s'"<>]+)""", r.text[:4000], re.I)
        hit = _split_location(m.group(1)) if m else None
        if hit and hit[0] != probe_host and looks_like_portal(*hit):
            return f"page points at {hit[0]}:{hit[1]}", hit
        return f"answered {r.status_code}, nothing portal-shaped in it", None

    return f"answered {r.status_code}", None


def portal_from_redirect(timeout: float = 4.0) -> tuple[str, int] | None:
    """Whatever the probes reveal. A Location header is the one fully reliable
    source for the portal's port — everything else is guesswork."""
    for url in PROBE_URLS:
        _, hit = probe(url, timeout)
        if hit:
            return hit
    return None


def looks_like_portal(host: str, port: int, timeout: float = 4.0,
                      login_path: str = "/login.xml") -> bool:
    """An open port is not proof: every home router answers on 80, and this
    app running at home must not decide the router is a captive portal. Ask
    the login endpoint first — a real portal answers it with XML — then fall
    back to the front page."""
    for path in (login_path, "/"):
        try:
            r = requests.get(f"http://{host}:{port}{path}", timeout=timeout,
                             verify=False, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code < 400 and PORTAL_MARKERS.search(r.text[:20000]):
            return True
    return False


def discover(configured_host: str = "",
             port: int = 8090,
             login_path: str = "/login.xml") -> tuple[str, int] | None:
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

    # Last resort: probe the gateways, then the DHCP/DNS servers. On a gateway,
    # an open 8090/8091 is signal enough; 80 and 443 belong to every router
    # alive. Anything else has to prove what it is on every port.
    # A dropped packet costs the full timeout, and this runs every few minutes
    # in the background, so keep the scan short: LAN hosts answer in
    # milliseconds, and on a DHCP/DNS server only the portal ports are worth
    # trying — its 80 and 443 are just an admin page.
    gateways = default_gateways()
    infra = [h for h in infrastructure_hosts() if h not in gateways]
    portal_ports = tuple(p for p in ports if p not in (80, 443))

    for host in gateways + infra:
        for p in (ports if host in gateways else portal_ports):
            if not port_open(host, p, timeout=SCAN_TIMEOUT):
                continue
            trusted = host in gateways and p not in (80, 443)
            if not trusted and not looks_like_portal(host, p,
                                                     login_path=login_path):
                continue
            return host, p
    return None


def diagnostics(cfg: dict) -> str:
    """What this network actually looks like. For when discovery gets it wrong
    and the answer has to come from the person standing on the network."""
    port = int(cfg.get("portal_port", 8090))
    login_path = cfg.get("login_path", "/login.xml")
    ports = tuple(dict.fromkeys((port, *COMMON_PORTS)))
    lines = ["Sophos Auto Login — network report", ""]

    lines.append(f"Internet reachable: {'yes' if is_online() else 'no'}")

    configured = cfg.get("portal_host", "")
    lines.append(f"Portal host in settings: {configured or '(auto-detect)'}")
    lines.append("")

    lines.append("Probes (does this network give the portal away?)")
    hit = None
    for url in PROBE_URLS:
        note, found = probe(url)
        lines.append(f"    {url}")
        lines.append(f"        {note}")
        hit = hit or found
    lines.append("")

    gateways = default_gateways()
    infra = infrastructure_hosts()
    hosts = [h for h in ([configured] if configured else []) +
             ([hit[0]] if hit else []) + gateways + infra if h]
    seen: list[str] = []
    for host in hosts:
        if host in seen:
            continue
        seen.append(host)
        role = ("configured" if host == configured else
                "from the redirect" if hit and host == hit[0] else
                "gateway" if host in gateways else "DHCP/DNS server")
        lines.append(f"{host}  ({role})")
        for p in ports:
            if not port_open(host, p, timeout=SCAN_TIMEOUT):
                lines.append(f"    :{p:<5} closed")
                continue
            marker = "looks like a portal" if looks_like_portal(
                host, p, login_path=login_path) else \
                "open, but no portal fingerprint"
            lines.append(f"    :{p:<5} OPEN — {marker}")
        lines.append("")

    found = discover(configured, port, login_path)
    lines.append(f"Discovery picked: "
                 f"{found[0] + ':' + str(found[1]) if found else 'nothing'}")
    lines.append("")
    lines.append("If nothing was found: the portal may live on a host this")
    lines.append("machine has no way to guess — it is often not the gateway.")
    lines.append("Open the portal in your browser, press F12, log in, and read")
    lines.append("the address of the login request in the Network tab. Put that")
    lines.append("host in Portal host, and its port in portal_port in")
    lines.append(r"%APPDATA%\SophosAutoLogin\config.json.")
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
        found = discover(cfg.get("portal_host", ""), configured_port,
                         cfg.get("login_path", "/login.xml"))
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
