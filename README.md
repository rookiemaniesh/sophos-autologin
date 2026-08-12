<div align="center">

# Sophos Auto Login

**Stop typing your campus wifi password ten times a day.**

Signs you in to a Sophos captive portal automatically — when you connect, when
you log on, when the network comes back, and whenever the portal times your
session out.

[![Download SophosAutoLogin.exe](https://img.shields.io/badge/⬇%20Download-SophosAutoLogin.exe-2ea44f?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/rookiemaniesh/sophos-autologin/releases/latest/download/SophosAutoLogin.exe)

[![Latest release](https://img.shields.io/github/v/release/rookiemaniesh/sophos-autologin?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/rookiemaniesh/sophos-autologin/total?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/rookiemaniesh/sophos-autologin/release.yml?style=flat-square)](https://github.com/rookiemaniesh/sophos-autologin/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white)](#)

</div>

---

**Contents** · [Quick start](#quick-start) · [Is this safe?](#is-this-safe-where-does-my-password-go) ·
[Features](#features) · [One login per account](#one-login-per-account) ·
[When it cannot find the portal](#when-it-cannot-find-the-portal) ·
[Troubleshooting](#troubleshooting) · [FAQ](#faq) ·
[How it works](#how-it-works) · [Where everything lives](#where-everything-lives) ·
[Command line](#command-line) · [Configuration](#configuration) ·
[Building from source](#building-from-source) · [Compatibility](#compatibility)

---

## Quick start

1. **[Download `SophosAutoLogin.exe`](https://github.com/rookiemaniesh/sophos-autologin/releases/latest/download/SophosAutoLogin.exe)**, then **move it somewhere permanent** — `%LOCALAPPDATA%\Programs\SophosAutoLogin\` is a good spot. **Not Downloads:** the scheduled task remembers the exact path you registered it from, and Downloads is the folder that gets emptied. Delete the file later and auto-login stops with no visible error.
2. Run it. No installer, no admin rights. Type your campus username and password.
3. Tick **Log in automatically when I connect**, then hit **Save**.

That is the whole setup. Close the window — it keeps working in the background.

Moving the exe afterwards? Run it once from its new home and hit **Save** again
to re-point the task. Do *not* use `--uninstall` for that — it deletes your
stored password too.

> **SmartScreen warning on first run?** Expected. The exe is not code-signed,
> because a signing certificate costs a few hundred dollars a year. Click
> *More info* → *Run anyway*. If you would rather not trust a stranger's
> binary, [build it yourself](#building-from-source) — it takes one command.

---

## Is this safe? Where does my password go?

**Short answer: your password is stored exactly the way Chrome stores your
saved passwords, and it is never sent anywhere except your own campus portal.**

| | |
|---|---|
| **Where it is stored** | **Windows Credential Manager**, under the service name `sophos-autologin` |
| **How it is protected** | DPAPI — encrypted against your Windows user account, readable only when you are signed in as you |
| **Who else can read it** | Nobody. Not another user on the same PC, not a program running as someone else |
| **Where it is *not* stored** | Not in the config file, not in the logs, not in this repository, not in any cloud |
| **Where your credentials are sent** | Only to your campus portal, and only its IP address on your own network — byte for byte the same form your browser submits on the portal page |
| **What else it contacts** | Three connectivity probes, and nothing more: Google's `generate_204`, `1.1.1.1`, and a Microsoft connectivity-test IP. They carry no credentials and exist only to answer "am I online, or is something intercepting me?" |
| **Telemetry, analytics, servers** | None. There is no backend. Nobody receives a single byte about you |

This is the identical mechanism behind "Save password?" in Chrome and Edge:
[`keyring`](https://pypi.org/project/keyring/) → Windows Credential Manager →
DPAPI. See it yourself in *Control Panel → Credential Manager → Windows
Credentials*.

Settings that are **not** secret — your username, the portal host — live in
plain JSON at `%APPDATA%\SophosAutoLogin\config.json`.

**To remove every trace:** `SophosAutoLogin.exe --uninstall` deletes the
scheduled task and the stored password; then delete the
`%APPDATA%\SophosAutoLogin` folder and the exe.

### You do not have to take my word for the binary

The exe on the [Releases](https://github.com/rookiemaniesh/sophos-autologin/releases)
page is built by **GitHub Actions from this repository**, by
[`.github/workflows/release.yml`](.github/workflows/release.yml), on a runner
nobody can reach into. The build log is public, the tests run before it, and
`build.ps1` uses the same flags — so you can rebuild it yourself and compare.

### Being straight with you about the limits

Two things this cannot fix, and no tool of this kind can:

- **Sophos portals speak plain HTTP** (usually port 8090). Your password
  crosses the local network unencrypted — equally true when you type it into
  the portal page in your browser. This app is no worse; it is also no better.
- **Anything running as *you* on your PC can ask Credential Manager for the
  password.** That is how the store works, in Chrome too. It protects you from
  other people and other accounts, not from malware already running as you.

Everything that touches your credentials lives in
[`config.py`](sophos_autologin/config.py) — under 70 lines, half of them
comments — and [`portal.py`](sophos_autologin/portal.py). It is a short read.

---

## Features

- **Finds the portal by itself.** Follows the captive-portal redirect — probing
  bare IPs as well, since portals usually block DNS until you log in — then
  falls back to your gateways and the network's DHCP/DNS servers, which on a
  campus is very often the appliance itself. No SSID list to maintain; wifi and
  ethernet work the same way.
- **Knows a portal from a router.** An open port 80 convinces it of nothing —
  a candidate must answer with a Sophos/Cyberoam fingerprint before it is
  trusted with a login. So it does nothing at all on your home wifi.
- **Three triggers:** on network-connect, at logon, and every few minutes to
  catch session timeouts.
- **Handles one-session-per-account portals** — [see below](#one-login-per-account).
- **Backs off instead of locking you out.** Three rejected logins triggers a
  15-minute cooldown, so a changed password cannot get your account locked by a
  task retrying every three minutes forever.
- **Keeps the session alive** while you are online, so the portal is less
  likely to time you out in the first place.
- **Diagnose report** that tells you exactly what is on your network, and what
  to do next, when something does not work.
- **No admin rights, no installer, no service, nothing resident.** Just a
  scheduled task that runs for a moment and exits.

---

## One login per account

Plenty of campuses cap you to a single session per ID. When that cap is hit the
portal rejects the login with *"maximum login limit reached"* or *"you are
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

Press **Diagnose**. It reports what each probe returned, every candidate host
and where it came from, which ports answer, which of those look like a real
portal rather than a router's admin page, and what discovery settled on:

```
Sophos Auto Login — network report

Internet reachable: no
Portal host in settings: (auto-detect)

Probes (does this network give the portal away?)
    http://connectivitycheck.gstatic.com/generate_204
        DNS blocked (typical before you log in)
    http://1.1.1.1/
        redirected to 10.140.0.2:8090
    http://204.79.197.200/
        unreachable

192.168.84.1  (gateway)
    :8090  closed
    :8091  closed
    :80    OPEN — open, but no portal fingerprint
    :443   closed

10.140.0.2  (from the redirect)
    :8090  OPEN — looks like a portal

Discovery picked: 10.140.0.2:8090
```

`SophosAutoLogin.exe --diagnose` writes the same report to
`%APPDATA%\SophosAutoLogin\diagnose.txt` and opens it. Add `--quiet` to skip
opening it. Give it up to a minute — it is knocking on every plausible door,
and a firewall that drops packets costs a timeout per port.

**If it finds nothing, your portal is on a host nothing can guess.** It is
frequently *not* your gateway, and may not even be on your subnet. Open the
portal in your browser, press F12, log in, and read the address of the login
request in the Network tab. It looks like:

```
http://10.140.0.2:8090/login.xml
mode=191&username=you&password=...&a=1786559177940&producttype=0
```

Put that host in **Portal host** and Save. If the port is not 8090, set
`portal_port` in `config.json`. A configured host is tried first, on whichever
port answers.

---

## Troubleshooting

| Symptom | What it means |
|---|---|
| *"Nothing answered at `x.x.x.x:8090`"* | Discovery picked a host or port that is not listening. Run **Diagnose**, then set **Portal host** by hand. |
| *"No captive portal on this network"* | Nothing portal-shaped is reachable. Normal at home. On campus it usually means the portal is on a host that cannot be guessed — find it with F12 as described above. |
| Login rejected with a credential error | Wrong username or password. Fix it in the window. Three failures triggers a 15-minute cooldown; saving the right password clears it on the next success. |
| It logs in, then drops a few minutes later | Another device is using the same ID. See [One login per account](#one-login-per-account). |
| Worked for weeks, then silently stopped | The exe was moved or deleted — most often it was sitting in Downloads. Put it back somewhere permanent, run it, and hit **Save** to re-register the task. |
| Nothing happens automatically | `schtasks /Query /TN SophosAutoLogin /FO LIST /V` — check *Scheduled Task State* is Enabled, and that *Task To Run* points at a file that still exists. |
| Want to see what it actually did | `%APPDATA%\SophosAutoLogin\autologin.log` |
| Changed your campus password | Open the app, type the new one, Save. Do it before the task retries into the cooldown. |

---

## FAQ

**Does it slow my PC down?**
No. Nothing runs in the background. A scheduled task starts the exe, it works
for a moment, and it exits.

**Is it safe to leave enabled at home?**
Yes — that is the point of the fingerprint check. On a network with no Sophos
portal it finds nothing and exits without sending anything anywhere.

**Can I run it on two devices with the same ID?**
You can, but if your campus allows one session per account they will fight over
it. See [One login per account](#one-login-per-account).

**Does it work on ethernet?**
Yes. The network-connect trigger fires for a cable being plugged in just as it
does for wifi association.

**Do I need to keep the window open?**
No. Close it. The scheduled task is what does the work.

**What happens when the portal is down?**
The run fails, it logs why, and the next trigger tries again. Nothing breaks.

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
     find the portal
       probes (redirect, incl. bare IPs)
       → gateways
       → DHCP/DNS servers
       → fingerprint check before trusting any of them
            │
            ▼
     POST mode=191 with credentials from Credential Manager
            │
            ▼
     confirm by re-checking connectivity, log the result, exit
```

A run takes a second or two when the portal is where it was last time, and up
to about ten seconds when it has to hunt for it. The task is capped at two
minutes and runs hidden, as you, at normal privilege.

---

## Where everything lives

| What | Where |
|---|---|
| The program | Wherever you put it — `%LOCALAPPDATA%\Programs\SophosAutoLogin\` recommended |
| Your password | Windows Credential Manager, service `sophos-autologin` |
| Settings | `%APPDATA%\SophosAutoLogin\config.json` |
| Log | `%APPDATA%\SophosAutoLogin\autologin.log` (rotates at 256 KB, keeps 2) |
| Failure/backoff state | `%APPDATA%\SophosAutoLogin\state.json` |
| Diagnose report | `%APPDATA%\SophosAutoLogin\diagnose.txt` |
| Scheduled task | `\SophosAutoLogin` — see it in Task Scheduler |

---

## Command line

| Command | What it does |
|---|---|
| *(no arguments)* | Opens the settings window |
| `--run` | Logs in if needed, then exits. This is what the scheduled task calls. |
| `--install` | Registers the scheduled task, pointing at the exe you ran it from |
| `--uninstall` | Removes the task **and deletes the stored password** |
| `--diagnose` | Writes a network report and opens it |
| `--diagnose --quiet` | Same, without opening it |

Exit codes from `--run`: `0` online, `1` tried and failed, `2` nothing to do.

---

## Configuration

`%APPDATA%\SophosAutoLogin\config.json` — created on first save.

| Key | Default | Meaning |
|---|---|---|
| `username` | `""` | Your campus login |
| `portal_host` | `""` | Blank means auto-detect. Set it when auto-detect cannot find your portal |
| `portal_port` | `8090` | Tried first; discovery also tries 8091, 80 and 443 |
| `login_path` | `/login.xml` | Login endpoint |
| `live_path` | `/live` | Keepalive endpoint |
| `check_interval` | `180` | Seconds between scheduled runs. Re-save to apply |
| `keepalive` | `true` | Ping the portal while online to hold the session |
| `kick_other_session` | `false` | Drop an existing session when the portal says the account already has one |

---

## Building from source

```powershell
git clone https://github.com/rookiemaniesh/sophos-autologin
cd sophos-autologin
powershell -ExecutionPolicy Bypass -File build.ps1
```

Output: `dist\SophosAutoLogin.exe`. Needs Python 3.11 or newer.

Running without packaging:

```powershell
pip install -r requirements.txt
python run.py              # settings window
python run.py --run        # headless login attempt
python run.py --diagnose   # network report
python run.py --uninstall  # remove task + credentials
```

Tests — no network required, every socket and request is stubbed:

```powershell
python tests\test_discovery.py       # portal discovery: 18 checks
python tests\test_session_limit.py   # one-session handling: 10 checks
```

Layout:

```
run.py                       PyInstaller entry point
sophos_autologin/
    __main__.py              argument handling
    gui.py                   tkinter settings window (stdlib only)
    portal.py                discovery, fingerprinting, login/logout/keepalive
    runner.py                the headless --run path, backoff, logging
    scheduler.py             scheduled task XML and schtasks calls
    config.py                settings file and Credential Manager access
```

---

## Compatibility

Windows 10 and 11. Built against Sophos XG/UTM and Cyberoam portals using the
`mode=191` login form (`/login.xml`, usually port 8090). Verified end to end
against a live campus Cyberoam appliance.

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
