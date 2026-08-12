"""Portal discovery, with the network faked. The bug these guard against: a
host was found by trying several ports, then the login went to the port in the
config instead of the one that answered."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sophos_autologin import portal as P  # noqa: E402

CFG = {"portal_host": "", "portal_port": 8090,
       "login_path": "/login.xml", "live_path": "/live"}


class Net:
    """open_ports: {host: [ports]}; pages: {(host, port): html}."""

    def __init__(self, open_ports=None, pages=None, redirect=None, gateways=()):
        self.open_ports = open_ports or {}
        self.pages = pages or {}
        self.redirect = redirect
        self.gateways = list(gateways)

    def install(self):
        P.port_open = lambda h, p, timeout=1.5: p in self.open_ports.get(h, [])
        P.default_gateways = lambda: self.gateways
        P.portal_from_redirect = lambda timeout=5.0: self.redirect
        P.looks_like_portal = lambda h, p, timeout=4.0: bool(
            P.PORTAL_MARKERS.search(self.pages.get((h, p), "")))


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    return cond


ok = True
SOPHOS = "<html><body>Sophos captive portal, redirecting to httpclient.html</body></html>"
ROUTER = "<html><title>TP-Link Wireless Router</title><body>Login</body></html>"

# The reported bug: gateway answers on 80, config says 8090. Discovery must
# report the port that answered, and must not claim a router is a portal.
Net(open_ports={"192.168.84.1": [80]},
    pages={("192.168.84.1", 80): ROUTER},
    gateways=["192.168.84.1"]).install()
ok &= check("router admin page on :80 is not mistaken for a portal",
            P.discover("", 8090) is None)

Net(open_ports={"192.168.84.1": [80]},
    pages={("192.168.84.1", 80): SOPHOS},
    gateways=["192.168.84.1"]).install()
ok &= check("a real portal on :80 is found, with its port",
            P.discover("", 8090) == ("192.168.84.1", 80))

Net(open_ports={"10.0.0.1": [8090]}, gateways=["10.0.0.1"]).install()
ok &= check("portal on the usual :8090 needs no page check",
            P.discover("", 8090) == ("10.0.0.1", 8090))

# Redirect wins and carries the port.
Net(open_ports={"172.16.1.1": [8090]}, redirect=("172.16.1.1", 8090),
    gateways=["10.0.0.1"]).install()
ok &= check("redirect target beats the gateway probe",
            P.discover("", 8090) == ("172.16.1.1", 8090))

Net(open_ports={"172.16.1.1": [8091]}, redirect=("172.16.1.1", 8090),
    gateways=[]).install()
ok &= check("redirect host with a dead port falls back to another port",
            P.discover("", 8090) == ("172.16.1.1", 8091))

# Configured host is trusted, but still needs a live port.
Net(open_ports={"10.5.5.5": [8091]}, gateways=["10.0.0.1"]).install()
ok &= check("configured host is used on whichever port is live",
            P.discover("10.5.5.5", 8090) == ("10.5.5.5", 8091))

Net(open_ports={}, gateways=["10.0.0.1"]).install()
ok &= check("configured host that is down yields nothing",
            P.discover("10.5.5.5", 8090) is None)

# Home network: nothing open anywhere.
Net(open_ports={}, gateways=["192.168.1.1"]).install()
ok &= check("no portal on this network", P.discover("", 8090) is None)

# Portal object must talk to the discovered port, not the configured one.
Net(open_ports={"192.168.84.1": [80]},
    pages={("192.168.84.1", 80): SOPHOS},
    gateways=["192.168.84.1"]).install()
p = P.Portal(dict(CFG))
ok &= check("Portal uses the discovered port for its URLs",
            p.found and p.port == 80
            and p._url("/login.xml") == "http://192.168.84.1:80/login.xml"
            and p.address == "192.168.84.1:80")

# Nothing found: still reports a sane address and refuses to act.
Net(open_ports={}, gateways=[]).install()
p = P.Portal(dict(CFG))
ok &= check("no portal found leaves Portal inert",
            not p.found and not p.login("u", "pw").ok)

# Location header parsing.
ok &= check("Location with an explicit port",
            P._split_location("http://10.0.0.1:8090/httpclient.html")
            == ("10.0.0.1", 8090))
ok &= check("Location without a port defaults by scheme",
            P._split_location("https://portal.campus.edu/login")
            == ("portal.campus.edu", 443))
ok &= check("garbage Location is ignored", P._split_location("") is None)

sys.exit(0 if ok else 1)
