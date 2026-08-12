"""Registers a Windows scheduled task with two triggers: one on network
connect, one on a repeating interval. No admin rights needed — it is
registered under the current user only."""

from __future__ import annotations

import getpass
import subprocess
import sys
import tempfile
from pathlib import Path

TASK_NAME = "SophosAutoLogin"

# EventID 10000 = "Network connected" from NetworkProfile. Fires for wifi
# association and for an ethernet cable being plugged in.
#
# The LogonTrigger needs its own UserId: without one it means "when *any* user
# logs on", which Task Scheduler will only accept from an elevated process.
TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Logs in to the Sophos captive portal automatically.</Description>
    <URI>\\{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT5S</Delay>
    </EventTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
      <Delay>PT20S</Delay>
    </LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT{minutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True,
                          creationflags=_NO_WINDOW)


def _action() -> tuple[str, str]:
    """Frozen exe runs itself with --run; a .py script runs under pythonw."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--run"
    pyw = Path(sys.executable).with_name("pythonw.exe")
    exe = str(pyw if pyw.exists() else sys.executable)
    return exe, f'"{Path(sys.argv[0]).resolve()}" --run'


def is_installed() -> bool:
    return _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0


def install(interval_seconds: int = 180) -> tuple[bool, str]:
    command, arguments = _action()
    xml = TASK_XML.format(
        task_name=TASK_NAME,
        minutes=max(1, interval_seconds // 60),
        user=f"{getpass.getuser()}",
        command=command,
        arguments=arguments,
    )
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                     encoding="utf-16") as fh:
        fh.write(xml)
        path = fh.name

    proc = _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", path, "/F"])
    Path(path).unlink(missing_ok=True)

    if proc.returncode == 0:
        return True, "Scheduled task installed."
    return False, (proc.stderr or proc.stdout or "schtasks failed").strip()


def uninstall() -> tuple[bool, str]:
    proc = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if proc.returncode == 0:
        return True, "Scheduled task removed."
    return False, (proc.stderr or proc.stdout or "schtasks failed").strip()
