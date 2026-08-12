"""Tkinter settings window. Stdlib only — no extra dependency, and it keeps
the packaged exe small."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from . import config, scheduler
from .portal import Portal, diagnostics, is_online

PAD = {"padx": 12, "pady": 6}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Sophos Auto Login")
        self.resizable(False, False)
        self.cfg = config.load()

        self._build()
        self._refresh_status()

    # ------------------------------------------------------------ layout --

    def _build(self) -> None:
        frm = ttk.Frame(self)
        frm.grid(sticky="nsew")

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky="w", **PAD)
        self.user_var = tk.StringVar(value=self.cfg.get("username", ""))
        ttk.Entry(frm, textvariable=self.user_var, width=28).grid(
            row=0, column=1, **PAD)

        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky="w", **PAD)
        self.pass_var = tk.StringVar(
            value="********" if config.get_password(self.cfg.get("username", "")) else "")
        ttk.Entry(frm, textvariable=self.pass_var, show="\u2022", width=28).grid(
            row=1, column=1, **PAD)

        ttk.Label(frm, text="Portal host").grid(row=2, column=0, sticky="w", **PAD)
        self.host_var = tk.StringVar(value=self.cfg.get("portal_host", ""))
        ttk.Entry(frm, textvariable=self.host_var, width=28).grid(
            row=2, column=1, **PAD)
        ttk.Label(frm, text="leave blank to detect automatically",
                  foreground="#666").grid(row=3, column=1, sticky="w", padx=12)

        self.auto_var = tk.BooleanVar(value=scheduler.is_installed())
        ttk.Checkbutton(frm, text="Log in automatically when I connect",
                        variable=self.auto_var).grid(
            row=4, column=0, columnspan=2, sticky="w", **PAD)

        self.kick_var = tk.BooleanVar(
            value=bool(self.cfg.get("kick_other_session", False)))
        ttk.Checkbutton(frm, text="My account allows only one login at a time",
                        variable=self.kick_var).grid(
            row=5, column=0, columnspan=2, sticky="w", padx=12)
        ttk.Label(frm, text="drops my older session if the portal refuses",
                  foreground="#666").grid(row=6, column=0, columnspan=2,
                                          sticky="w", padx=34)

        btns = ttk.Frame(frm)
        btns.grid(row=7, column=0, columnspan=2, sticky="ew", **PAD)
        ttk.Button(btns, text="Save", command=self.on_save).pack(side="left")
        ttk.Button(btns, text="Test login", command=self.on_test).pack(
            side="left", padx=6)
        ttk.Button(btns, text="Log out", command=self.on_logout).pack(side="left")
        ttk.Button(btns, text="Diagnose", command=self.on_diagnose).pack(
            side="left", padx=6)

        self.status = ttk.Label(frm, text="", foreground="#444", wraplength=320,
                                justify="left")
        self.status.grid(row=8, column=0, columnspan=2, sticky="w", **PAD)

    # ------------------------------------------------------------ helpers --

    def _set_status(self, text: str, colour: str = "#444") -> None:
        self.status.after(0, lambda: self.status.config(text=text, foreground=colour))

    def _in_thread(self, fn) -> None:
        threading.Thread(target=fn, daemon=True).start()

    def _refresh_status(self) -> None:
        def work() -> None:
            self._set_status("Checking\u2026")
            portal = Portal(config.load())
            online = is_online()
            if online:
                self._set_status("Connected to the internet.", "#137333")
            elif portal.found:
                self._set_status(f"Captive portal found at {portal.address} \u2014 "
                                 "not logged in.", "#b06000")
            else:
                self._set_status("No captive portal on this network.", "#666")
        self._in_thread(work)

    def _current_password(self) -> str | None:
        entered = self.pass_var.get()
        if entered and entered != "********":
            return entered
        return config.get_password(self.user_var.get().strip())

    # ------------------------------------------------------------ actions --

    def on_save(self) -> None:
        username = self.user_var.get().strip()
        if not username:
            messagebox.showerror("Sophos Auto Login", "Enter your username.")
            return

        password = self.pass_var.get()
        if password and password != "********":
            config.set_password(username, password)
            self.pass_var.set("********")
        elif not config.get_password(username):
            messagebox.showerror("Sophos Auto Login", "Enter your password.")
            return

        self.cfg.update({
            "username": username,
            "portal_host": self.host_var.get().strip(),
            "kick_other_session": bool(self.kick_var.get()),
        })
        config.save(self.cfg)

        if self.auto_var.get():
            ok, msg = scheduler.install(int(self.cfg.get("check_interval", 180)))
        else:
            ok, msg = (scheduler.uninstall() if scheduler.is_installed()
                       else (True, "Autostart disabled."))

        if not ok:
            messagebox.showwarning("Sophos Auto Login",
                                   f"Settings saved, but: {msg}")
        else:
            self._set_status(f"Saved. {msg}", "#137333")

    def on_test(self) -> None:
        username = self.user_var.get().strip()
        password = self._current_password()
        if not (username and password):
            messagebox.showerror("Sophos Auto Login",
                                 "Enter a username and password first.")
            return

        def work() -> None:
            self._set_status("Logging in\u2026")
            portal = Portal(config.load() | {"portal_host": self.host_var.get().strip()})
            if not portal.found:
                self._set_status("No captive portal found on this network.", "#c5221f")
                return
            res = portal.login(username, password,
                               kick_other_session=bool(self.kick_var.get()))
            self._set_status(
                f"{'Logged in' if res.ok else 'Login failed'} \u2014 {res.message}",
                "#137333" if res.ok else "#c5221f")
        self._in_thread(work)

    def on_diagnose(self) -> None:
        def work() -> None:
            self._set_status("Scanning this network… (this can take a minute)")
            cfg = config.load() | {"portal_host": self.host_var.get().strip()}
            report = diagnostics(cfg)
            self.after(0, lambda: self._show_report(report))
            self._set_status("Network report ready.", "#444")
        self._in_thread(work)

    def _show_report(self, report: str) -> None:
        win = tk.Toplevel(self)
        win.title("Network report")
        text = tk.Text(win, width=62, height=24, wrap="none", font=("Consolas", 9))
        text.grid(row=0, column=0, sticky="nsew")
        text.insert("1.0", report)
        text.configure(state="disabled")
        ttk.Scrollbar(win, orient="vertical", command=text.yview).grid(
            row=0, column=1, sticky="ns")

        def copy() -> None:
            self.clipboard_clear()
            self.clipboard_append(report)
        ttk.Button(win, text="Copy", command=copy).grid(
            row=1, column=0, sticky="w", **PAD)

    def on_logout(self) -> None:
        username = self.user_var.get().strip()
        password = self._current_password() or ""

        def work() -> None:
            portal = Portal(config.load())
            res = portal.logout(username, password)
            self._set_status(res.message, "#444")
        self._in_thread(work)


def main() -> None:
    App().mainloop()
