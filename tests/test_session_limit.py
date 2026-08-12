"""The one-session-per-account path, with the network stubbed out."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sophos_autologin import portal as P  # noqa: E402


def make_portal(monkey_responses):
    """A Portal that never touches the network: `monkey_responses` is a list of
    (message, online_after) consumed one per login attempt."""
    p = P.Portal.__new__(P.Portal)
    p.cfg = {"login_path": "/login.xml", "live_path": "/live"}
    p.host = "10.0.0.1"
    p.port = 8090
    p.logouts = []

    attempts = list(monkey_responses)

    def _attempt(username, password):
        msg, online = attempts.pop(0)
        return P.Result(online, msg)

    def _logout(username, password=""):
        p.logouts.append((username, password))
        return P.Result(True, "logged out")

    p._attempt = _attempt
    p.logout = _logout
    return p


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    return cond


ok = True

ok &= check("detects 'maximum login limit reached'",
            P.is_session_limit("You have reached maximum login limit."))
ok &= check("detects 'already logged in'",
            P.is_session_limit("The user is already logged in."))
ok &= check("detects concurrent wording",
            P.is_session_limit("Concurrent login not allowed"))
ok &= check("leaves a real credential error alone",
            not P.is_session_limit("Invalid username or password."))
ok &= check("leaves an empty response alone",
            not P.is_session_limit("(empty response)"))

# Plain success: no logout should be sent.
p = make_portal([("You have successfully logged in", True)])
r = p.login("u", "pw")
ok &= check("clean login does not touch logout", r.ok and not r.kicked and not p.logouts)

# Session held by an old login: logout, then retry.
p = make_portal([("Maximum login limit reached", False),
                 ("You have successfully logged in", True)])
r = p.login("u", "pw")
ok &= check("session limit is kicked and retried",
            r.ok and r.kicked and p.logouts == [("u", "pw")])

# Wrong password must not trigger a logout.
p = make_portal([("Invalid username or password", False)])
r = p.login("u", "pw")
ok &= check("bad credentials are not treated as a session limit",
            not r.ok and not r.kicked and not p.logouts)

# Opting out leaves the session alone.
p = make_portal([("Maximum login limit reached", False)])
r = p.login("u", "pw", kick_other_session=False)
ok &= check("kick_other_session=False sends no logout",
            not r.ok and not r.kicked and not p.logouts)

# Kick that does not help is reported as a failure, still flagged kicked.
p = make_portal([("Maximum login limit reached", False),
                 ("Maximum login limit reached", False)])
r = p.login("u", "pw")
ok &= check("failed kick reports failure but flags the attempt",
            not r.ok and r.kicked)

sys.exit(0 if ok else 1)
