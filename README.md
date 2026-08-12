<div align="center">

# Sophos Auto Login

**Stop typing your campus wifi password ten times a day.**

Signs you in to a Sophos captive portal automatically, every time you connect —
wifi or ethernet, on wake, on logon, and whenever the portal times your session
out.

[![Download SophosAutoLogin.exe](https://img.shields.io/badge/⬇%20Download-SophosAutoLogin.exe-2ea44f?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/rookiemaniesh/sophos-autologin/releases/latest/download/SophosAutoLogin.exe)

[![Latest release](https://img.shields.io/github/v/release/rookiemaniesh/sophos-autologin?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/rookiemaniesh/sophos-autologin/total?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/rookiemaniesh/sophos-autologin/release.yml?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white)](#)

</div>

---

## Quick start

1. **[Download `SophosAutoLogin.exe`](https://github.com/rookiemaniesh/sophos-autologin/releases/latest/download/SophosAutoLogin.exe)** and run it. No installer, no admin rights.
2. Type your campus username and password.
3. Tick **Log in automatically when I connect**, then hit **Save**.

That is the whole setup. Close the window — it keeps working in the background.

> **SmartScreen warning on first run?** Expected. The exe is not code-signed,
> because a signing certificate costs a few hundred dollars a year. Click
> *More info* → *Run anyway*. If you would rather not trust a stranger's
> binary, [build it yourself](#building-from-source) — it takes one command.

---

## Is this safe? Where does my password go?

**Short answer: your password is stored the same way Chrome stores your saved
passwords, and it is never sent anywhere except your own campus portal.**

| | |
|---|---|
| **Where it is stored** | **Windows Credential Manager**, under the service name `sophos-autologin` |
| **How it is protected** | DPAPI — encrypted against your Windows user account, readable only when you are logged in as you |
| **Who else can read it** | Nobody. Not another user on the same PC, not a program running as someone else |
| **Where it is *not* stored** | Not in the config file, not in the logs, not in this repository, not in any cloud |
| **What is sent, and where** | Only your username and password, only to your campus portal's own IP address — the exact same request your browser makes when you log in on the portal page |
| **Telemetry, analytics, servers** | None. There is no backend. This app talks to your gateway and to a Google connectivity-check URL to see whether you are online, and nothing else |

This is the identical mechanism behind "Save password?" in Chrome and Edge:
[`keyring`](https://pypi.org/project/keyring/) → Windows Credential Manager →
DPAPI. You can see it yourself in *Control Panel → Credential Manager →
Windows Credentials*.

Settings that are **not** secret — your username, the portal host — live in
plain JSON at `%APPDATA%\SophosAutoLogin\config.json`.

**To remove every trace:** `SophosAutoLogin.exe --uninstall` deletes the
scheduled task and the stored password, then delete the
`%APPDATA%\SophosAutoLogin` folder.

### Being straight with you about the limits

Two things this cannot fix, and no tool of this kind can:

- **Sophos portals speak plain HTTP** (usually port 8090). Your password
  crosses the local network unencrypted — but that is equally true when you
  type it into the portal page in your browser. This app is no worse; it is
  also no better.
- **Anything running as *you* on your PC can ask Credential Manager for the
  password.** That is how the store works, in Chrome too. It protects against
  other people and other accounts, not against malware already running as you.

Every line of what happens to your credentials is in
[`config.py`](sophos_autologin/config.py) — under 70 lines, and half of it is
comments — and in [`portal.py`](sophos_autologin/portal.py). It is a short read.

---

## Features

- **Finds the portal by itself.** Follows the captive-portal redirect — using
  bare-IP probes too, since portals usually block DNS until you log in — then
  falls back to probing your gateways and the network's DHCP/DNS servers, which
  on a campus is very often the appliance itself. No SSID list to maintain,
  works the same on wifi and ethernet.
- **Knows a portal from a router.** An open port 80 is not enough to convince
  it — a candidate has to answer with a Sophos/Cyberoam fingerprint. So it does
  nothing at all on your home wifi.
- **Three triggers**: on network-connect, at logon, and every few minutes to
  catch session timeouts.
- **Handles one-session-per-account portals** — see below.
- **Backs off instead of locking you out.** Three rejected logins triggers a
  15-minute cooldown, so a changed password cannot get your account locked by a
  task retrying every three minutes forever.
- **Diagnose button** that tells you exactly what is on your network when
  something does not work.
- **No admin rights, no service, no installer, no background process.** Just a
  scheduled task that runs for a second and exits.

---

## One login per account

Plenty of campuses cap you to a single session per ID. When that cap is hit,
the portal rejects the login with *"maximum login limit reached"* or *"you are
already logged in"* — most often because your laptop dropped off the network
without logging out and the portal is still holding the dead session.

**By default, this app leaves that session alone.** It reports the refusal and
tries again later, so a session you are genuinely using on another device is
never pulled out from under you. The cost: a stranded session blocks you until
the portal times it out.

Tick **My account allows only one login at a time** to change that. The app
then logs the old session out and immediately logs back in. Nothing is
bypassed — your account, your credentials, one session at a time. You can also
do it by hand with **Log out** followed by **Test login**.

With that box ticked, three kicks in half an hour triggers a 15-minute pause.
That pattern means a *second* device is logging in with the same ID, and two
copies of this app on one account would otherwise kick each other off every few
minutes forever. Run it on one device, or expect whichever machine ran most
recently to hold the connection.

---

## When it cannot find the portal

Press **Diagnose**. It lists every gateway, which ports answer, which of those
look like a real portal rather than a router's admin page, and what discovery
settled on:

```
Sophos Auto Login — network report

Internet reachable: no
Portal host in settings: (auto-detect)

Probes (does this network give the portal away?)
    http://connectivitycheck.gstatic.com/generate_204
        DNS blocked (typical before you log in)
    http://1.1.1.1/
        redirected to 10.140.0.2:8090

192.168.84.1  (gateway)
    :8090  closed
    :80    OPEN — open, but no portal fingerprint

10.140.0.2  (from the redirect)
    :8090  OPEN — looks like a portal

Discovery picked: 10.140.0.2:8090
```

`SophosAutoLogin.exe --diagnose` does the same from the command line and writes
the report to `%APPDATA%\SophosAutoLogin\diagnose.txt`. It takes up to a minute
— it is knocking on every plausible door.

**If it finds nothing, your portal is on a host nothing can guess** — it is
frequently *not* your gateway. Open the portal in your browser, press F12, log
in, and read the address of the login request in the Network tab. It looks like
`http://10.140.0.2:8090/login.xml`. Put that host in **Portal host**; if the
port is not 8090, set `portal_port` in `config.json`. A configured host is
tried first, on whichever port answers.

---

## Troubleshooting

| Symptom | What it means |
|---|---|
| *"Nothing answered at `x.x.x.x:8090`"* | Discovery picked the wrong host or port. Run **Diagnose** and set **Portal host** / `portal_port` by hand. |
| *"No captive portal on this network"* | Nothing portal-shaped is reachable. Normal at home. On campus it usually means the portal is on a host that cannot be guessed — find it with F12 as described above and set **Portal host**. |
| Login fails with a credential error | Wrong username or password. Fix it in the window — three failures triggers a 15-minute cooldown, and saving a new password clears it on the next success. |
| It logs in, then drops a few minutes later | Another device is using the same ID. See [One login per account](#one-login-per-account). |
| Nothing happens automatically | Check the task exists: `schtasks /Query /TN SophosAutoLogin`. Re-tick the autostart box and Save to re-register it. |
| Want to see what it did | `%APPDATA%\SophosAutoLogin\autologin.log` |

---

## How it works

```
network connect / logon / every 3 min
            │
            ▼
  scheduled task  ──►  SophosAutoLogin.exe --run
            │
            ▼
     already online? ──yes──►  send keepalive, exit
            │ no
            ▼
     find the portal   (redirect → gateway probe → fingerprint check)
            │
            ▼
     POST mode=191 with credentials from Credential Manager
            │
            ▼
     verify by re-checking connectivity, log the result, exit
```

The whole run takes about a second and leaves nothing resident.

---

## Command line

| Command | What it does |
|---|---|
| *(no arguments)* | Opens the settings window |
| `--run` | Logs in if needed, then exits. This is what the scheduled task calls. |
| `--install` | Registers the scheduled task |
| `--uninstall` | Removes the task and the stored password |
| `--diagnose` | Writes a report on what is listening on this network |

---

## Configuration

`%APPDATA%\SophosAutoLogin\config.json` — created on first save.

| Key | Default | Meaning |
|---|---|---|
| `username` | `""` | Your campus login |
| `portal_host` | `""` | Blank means auto-detect |
| `portal_port` | `8090` | Starting point; discovery will try 8091, 80 and 443 too |
| `login_path` | `/login.xml` | Login endpoint |
| `live_path` | `/live` | Keepalive endpoint |
| `check_interval` | `180` | Seconds between scheduled runs |
| `keepalive` | `true` | Ping the portal while online to hold the session |
| `kick_other_session` | `false` | Drop an existing session when the portal says the account already has one |

---

## Building from source

```powershell
git clone https://github.com/rookiemaniesh/sophos-autologin
cd sophos-autologin
powershell -ExecutionPolicy Bypass -File build.ps1
```

Output: `dist\SophosAutoLogin.exe`. Needs Python 3.11+.

Running without packaging:

```powershell
pip install -r requirements.txt
python run.py              # settings window
python run.py --run        # headless login attempt
python run.py --diagnose   # network report
python run.py --uninstall  # remove task + credentials
```

Tests — no network required, everything is stubbed:

```powershell
python tests\test_discovery.py       # portal discovery: 18 checks
python tests\test_session_limit.py   # one-session handling: 10 checks
```

---

## Compatibility

Built against Sophos XG/UTM and Cyberoam portals using the `mode=191` login
form (`/login.xml`, usually port 8090).

If your campus runs a different build: open the portal in your browser, press
F12, log in, and read the Network tab for the real path and field names, then
set them in `config.json`. Issues about a portal that does not work are
welcome — include the **Diagnose** report.

---

## A note on using this

This automates *your own* login with *your own* credentials. It does not bypass
authentication, share sessions, crack anything, or circumvent access control —
it sends the same form your browser sends.

That said: plenty of institutions have an acceptable-use policy with a line
about scripted access, and some cap you to one concurrent session. Worth
reading yours before leaving it running. Use at your own risk.

---

## Licence

MIT — see [LICENSE](LICENSE). Do what you like with it.
