"""Entry point.

    (no args)   open the settings window
    --run       headless: log in if needed, then exit (used by the task)
    --install   register the scheduled task
    --uninstall remove the scheduled task and stored credentials
"""

import sys


def main() -> int:
    args = set(sys.argv[1:])

    if "--run" in args:
        from .runner import run_once
        return run_once()

    if "--diagnose" in args:
        import subprocess

        from . import config
        from .portal import diagnostics

        report = diagnostics(config.load())
        try:
            print(report)
        except UnicodeEncodeError:      # legacy console codepage
            print(report.encode("ascii", "replace").decode("ascii"))

        # The packaged exe is windowed and has no console, so write the report
        # somewhere it can actually be read, and open it.
        config.APP_DIR.mkdir(parents=True, exist_ok=True)
        path = config.APP_DIR / "diagnose.txt"
        # BOM so Notepad does not mangle the non-ASCII characters.
        path.write_text(report, encoding="utf-8-sig")
        if "--quiet" not in args:
            subprocess.Popen(
                ["notepad.exe", str(path)],
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
        return 0

    if "--install" in args:
        from . import config, scheduler
        ok, msg = scheduler.install(int(config.load().get("check_interval", 180)))
        print(msg)
        return 0 if ok else 1

    if "--uninstall" in args:
        from . import config, scheduler
        ok, msg = scheduler.uninstall()
        cfg = config.load()
        config.delete_password(cfg.get("username", ""))
        print(msg, "Stored password removed.")
        return 0 if ok else 1

    from .gui import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
