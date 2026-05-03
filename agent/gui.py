"""
VulnWatch Agent — interfata grafica (Tkinter).

Doua moduri afisate dinamic, in functie de starea configului local:

1. **Enrollment** (cand nu exista config) — formular cu Email / Parola /
   API URL / UID device / Nume. La submit:
   - face login (sau register-then-login daca contul nu exista),
   - creeaza device-ul,
   - salveaza tokenul in `~/.vulnwatch/config.ini`,
   - ofera (default ON) inregistrare in autostart la logon.

2. **Status** (dupa enrollment) — afiseaza ID-ul, hostname-ul, log live al
   joburilor, butoane:
     [Scan now]  → cere o scanare imediata via push (`POST /scans`)
     [Pauza/Reia] → comuta starea daemon-ului
     [Inchide]   → opreste agent-ul (doar fereastra; daemon-ul ramane in tray)
     [Iesire complet] → opreste si daemon-ul si fereastra

Daemon-ul ruleaza pe thread separat. Mesajele de log curg printr-un
`queue.Queue` consumat de `after()` cu un interval de 100ms (Tk e
single-threaded — niciun update direct la widget-uri din alte threaduri).
"""

from __future__ import annotations

import platform
import queue
import socket
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import ttk, messagebox
from typing import Optional

from . import autostart, core


# ──────────────────────────────────────────────────────────────────────────────
# Daemon thread management
# ──────────────────────────────────────────────────────────────────────────────


class DaemonRunner:
    """Wrapper peste core.daemon_loop care ruleaza pe thread separat.

    Comunica cu UI prin `log_queue` (mesaje de log) si flag-uri thread-safe."""

    def __init__(self, log_queue: "queue.Queue[tuple[str, str]]"):
        self.log_queue = log_queue
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def is_paused(self) -> bool:
        return self._pause.is_set()

    def pause(self, paused: bool) -> None:
        if paused:
            self._pause.set()
        else:
            self._pause.clear()

    def start(self) -> bool:
        try:
            api_base, device_uid, device_token = core.get_enrollment()
        except RuntimeError:
            self._emit("Agent neinrolat — nu pot porni daemon-ul.", "error")
            return False
        self._stop.clear()
        self._pause.clear()
        self._thread = threading.Thread(
            target=self._run, args=(api_base, device_uid, device_token),
            daemon=True, name="vulnwatch-daemon",
        )
        self._thread.start()
        return True

    def _run(self, api_base: str, device_uid: str, device_token: str) -> None:
        self._emit(f"Daemon pornit (poll @3s) pentru {device_uid}.", "ok")
        try:
            core.daemon_loop(
                api_base, device_uid, device_token,
                poll_interval=3,
                auto_interval=0,
                log=self._emit,
                should_stop=self._stop.is_set,
                should_pause=self._pause.is_set,
            )
        finally:
            self._emit("Daemon oprit.", "info")

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float = 5.0) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    def _emit(self, msg: str, severity: str = "info") -> None:
        try:
            self.log_queue.put_nowait((msg, severity))
        except queue.Full:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Tema vizuala (paleta din frontend pentru consistenta)
# ──────────────────────────────────────────────────────────────────────────────

THEME = {
    "bg":          "#060d1a",
    "surface":     "#0d1526",
    "elevated":    "#111f35",
    "border":      "#1a2a44",
    "accent":      "#38bdf8",
    "accent_dim":  "#0d2438",
    "text":        "#e2e8f0",
    "text_dim":    "#94a3b8",
    "text_muted":  "#475569",
    "green":       "#4ade80",
    "amber":       "#fbbf24",
    "red":         "#f87171",
}

SEVERITY_COLOR = {
    "info":  THEME["text_dim"],
    "ok":    THEME["green"],
    "warn":  THEME["amber"],
    "error": THEME["red"],
}


# ──────────────────────────────────────────────────────────────────────────────
# Aplicatia principala
# ──────────────────────────────────────────────────────────────────────────────


class AgentApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("VulnWatch Agent")
        self.root.geometry("680x520")
        self.root.minsize(560, 420)
        self.root.configure(bg=THEME["bg"])
        try:
            self.root.iconbitmap(default="")  # icon-ul nativ se ataseaza la build
        except Exception:
            pass

        self.log_queue: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=1000)
        self.daemon = DaemonRunner(self.log_queue)
        self.tray = None  # initializat doar dupa enrollment, daca pystray e disponibil
        self._tray_started = False

        self._configure_styles()
        self._render_root()
        self._poll_log_queue()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close_window)

    # ── Stiluri ttk ──────────────────────────────────────────────────────────

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=THEME["bg"], foreground=THEME["text"],
                        fieldbackground=THEME["elevated"], borderwidth=0)
        style.configure("TFrame", background=THEME["bg"])
        style.configure("Surface.TFrame", background=THEME["surface"])
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["text"])
        style.configure("Dim.TLabel", background=THEME["bg"],
                        foreground=THEME["text_dim"], font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=THEME["bg"],
                        foreground=THEME["text"], font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", background=THEME["bg"],
                        foreground=THEME["text_dim"], font=("Segoe UI", 10))

        style.configure("TEntry", fieldbackground=THEME["elevated"],
                        foreground=THEME["text"], bordercolor=THEME["border"],
                        lightcolor=THEME["border"], darkcolor=THEME["border"],
                        padding=8)
        style.map("TEntry", bordercolor=[("focus", THEME["accent"])])

        style.configure("Accent.TButton", background=THEME["accent"],
                        foreground=THEME["bg"], font=("Segoe UI", 10, "bold"),
                        padding=(14, 8), borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", "#7dd3fc"), ("disabled", THEME["accent_dim"])])

        style.configure("Secondary.TButton", background=THEME["elevated"],
                        foreground=THEME["text"], padding=(12, 6), borderwidth=0)
        style.map("Secondary.TButton",
                  background=[("active", THEME["surface"])])

        style.configure("Danger.TButton", background=THEME["surface"],
                        foreground=THEME["red"], padding=(12, 6), borderwidth=0)

        style.configure("TCheckbutton", background=THEME["bg"],
                        foreground=THEME["text"])

    # ── Routing intre paginile UI ─────────────────────────────────────────────

    def _clear_root(self) -> None:
        for w in self.root.winfo_children():
            w.destroy()

    def _render_root(self) -> None:
        self._clear_root()
        if core.is_enrolled():
            self._render_status_page()
            # Pornire automata daemon dupa render (asa logul iese in widget)
            self.root.after(50, self._auto_start_daemon)
        else:
            self._render_enroll_page()

    # ── Pagina ENROLL ─────────────────────────────────────────────────────────

    def _render_enroll_page(self) -> None:
        wrap = ttk.Frame(self.root, style="TFrame", padding=24)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="Inrolare dispozitiv", style="Title.TLabel").pack(anchor="w")
        ttk.Label(wrap, text="Conecteaza-te cu acelasi cont folosit in dashboard. "
                  "Daca emailul nu exista, contul va fi creat.",
                  style="Subtitle.TLabel", wraplength=600).pack(anchor="w", pady=(4, 16))

        form = ttk.Frame(wrap, style="TFrame")
        form.pack(fill="x")

        def add_row(label: str, var: tk.StringVar, show: str = "", placeholder: str = "") -> ttk.Entry:
            ttk.Label(form, text=label, style="Dim.TLabel").pack(anchor="w", pady=(8, 2))
            entry = ttk.Entry(form, textvariable=var, show=show)
            entry.pack(fill="x")
            if placeholder and not var.get():
                var.set(placeholder)
            return entry

        self._var_email     = tk.StringVar()
        self._var_password  = tk.StringVar()
        self._var_api       = tk.StringVar(value=core.DEFAULT_API_BASE)
        self._var_uid       = tk.StringVar(value=socket.gethostname().lower())
        self._var_name      = tk.StringVar(value=f"{platform.system()} {socket.gethostname()}")
        self._var_autostart = tk.BooleanVar(value=True)

        e1 = add_row("Email",         self._var_email)
        e1.focus_set()
        add_row("Parola",            self._var_password, show="•")
        add_row("API URL",           self._var_api)
        add_row("Device UID",        self._var_uid)
        add_row("Nume afisat",       self._var_name)

        opts = ttk.Frame(wrap, style="TFrame")
        opts.pack(fill="x", pady=(16, 8))
        ttk.Checkbutton(opts, text="Porneste automat la logon (recomandat)",
                        variable=self._var_autostart).pack(anchor="w")

        # Mesaj de status / eroare
        self._enroll_msg = tk.StringVar()
        msg_label = ttk.Label(wrap, textvariable=self._enroll_msg,
                              foreground=THEME["amber"],
                              background=THEME["bg"], wraplength=600)
        msg_label.pack(anchor="w", pady=(8, 4))

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x", pady=(8, 0))

        self._enroll_btn = ttk.Button(actions, text="Inroleaza dispozitiv",
                                      style="Accent.TButton",
                                      command=self._submit_enrollment)
        self._enroll_btn.pack(side="left")

    def _submit_enrollment(self) -> None:
        email = self._var_email.get().strip().lower()
        password = self._var_password.get()
        api = self._var_api.get().strip().rstrip("/")
        uid = self._var_uid.get().strip()
        name = self._var_name.get().strip()

        if not email or not password:
            self._enroll_msg.set("Email si parola sunt obligatorii.")
            return
        if not uid or not name:
            self._enroll_msg.set("Device UID si numele afisat sunt obligatorii.")
            return
        if len(password) < 8:
            self._enroll_msg.set("Parola trebuie sa aiba minim 8 caractere.")
            return

        self._enroll_btn.configure(state="disabled")
        self._enroll_msg.set("Inrolare in curs... (poate dura cateva secunde)")

        # Inrolarea poate face mai multe cereri HTTP — o rulam pe thread
        # ca UI-ul sa nu se blocheze.
        def worker() -> None:
            try:
                core.perform_enrollment(api, email, password, uid, name,
                                        allow_create_account=True,
                                        log=lambda m, s="info": None)
                if self._var_autostart.get():
                    ok, msg = autostart.enable()
                    autostart_msg = f"Autostart: {msg}" if ok else f"Autostart esuat: {msg}"
                else:
                    autostart_msg = ""
                self.root.after(0, lambda: self._on_enroll_success(autostart_msg))
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_enroll_success(self, autostart_msg: str) -> None:
        if autostart_msg:
            self._enroll_msg.set(autostart_msg)
        # Render pagina principala
        self._render_root()

    def _on_enroll_failure(self, error: str) -> None:
        self._enroll_btn.configure(state="normal")
        self._enroll_msg.set(f"Eroare: {error}")

    # ── Pagina STATUS ─────────────────────────────────────────────────────────

    def _render_status_page(self) -> None:
        wrap = ttk.Frame(self.root, style="TFrame", padding=20)
        wrap.pack(fill="both", expand=True)

        try:
            api_base, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            self._render_enroll_page()
            return

        # Header
        header = ttk.Frame(wrap, style="TFrame")
        header.pack(fill="x")

        ttk.Label(header, text="VulnWatch Agent", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header,
                  text=f"Conectat ca {device_uid} • {api_base}",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(2, 12))

        # Bara de status (dot + text)
        status_bar = ttk.Frame(wrap, style="TFrame")
        status_bar.pack(fill="x", pady=(0, 12))
        self._status_dot = tk.Canvas(status_bar, width=12, height=12,
                                     bg=THEME["bg"], highlightthickness=0)
        self._status_dot.pack(side="left", padx=(0, 8))
        self._status_var = tk.StringVar(value="Pornesc daemon-ul...")
        ttk.Label(status_bar, textvariable=self._status_var,
                  background=THEME["bg"], foreground=THEME["text"]).pack(side="left")

        # Butoane actiuni
        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x", pady=(0, 12))

        self._scan_btn = ttk.Button(actions, text="Scan now",
                                    style="Accent.TButton",
                                    command=self._on_scan_now)
        self._scan_btn.pack(side="left", padx=(0, 6))

        self._pause_btn = ttk.Button(actions, text="Pauza",
                                     style="Secondary.TButton",
                                     command=self._on_toggle_pause)
        self._pause_btn.pack(side="left", padx=(0, 6))

        ttk.Button(actions, text="Deschide dashboard",
                   style="Secondary.TButton",
                   command=self._open_dashboard).pack(side="left", padx=(0, 6))

        ttk.Button(actions, text="Autostart",
                   style="Secondary.TButton",
                   command=self._on_toggle_autostart).pack(side="left", padx=(0, 6))

        ttk.Button(actions, text="Iesire",
                   style="Danger.TButton",
                   command=self._on_quit).pack(side="right")

        # Log live
        log_label = ttk.Label(wrap, text="Activitate", style="Dim.TLabel")
        log_label.pack(anchor="w", pady=(8, 4))

        log_frame = tk.Frame(wrap, bg=THEME["surface"], bd=0,
                             highlightthickness=1, highlightbackground=THEME["border"])
        log_frame.pack(fill="both", expand=True)

        self._log_text = tk.Text(log_frame, bg=THEME["surface"], fg=THEME["text"],
                                 insertbackground=THEME["text"],
                                 font=("Consolas", 9), bd=0, padx=10, pady=8,
                                 wrap="word", state="disabled")
        self._log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_frame, orient="vertical",
                               command=self._log_text.yview)
        scroll.pack(side="right", fill="y")
        self._log_text.configure(yscrollcommand=scroll.set)
        for sev, color in SEVERITY_COLOR.items():
            self._log_text.tag_configure(sev, foreground=color)

        self._set_status_indicator("starting")

    # ── Daemon control ────────────────────────────────────────────────────────

    def _auto_start_daemon(self) -> None:
        if self.daemon.is_running():
            return
        if self.daemon.start():
            self._set_status_indicator("running")
            self._maybe_start_tray()

    def _on_scan_now(self) -> None:
        """Push direct (fara coada). Mai rapid pentru testare."""
        try:
            api_base, device_uid, device_token = core.get_enrollment()
        except RuntimeError:
            self._append_log("Agent neinrolat.", "error")
            return

        self._scan_btn.configure(state="disabled")
        self._append_log(f"[{_ts()}] Scan now: colectez date locale...", "info")

        def worker() -> None:
            try:
                data = core.collect_system_data(device_uid)
                result = core.api_send_scan(api_base, device_token, data)
                msg = (f"[{_ts()}] Scan trimis. Scan #{result.get('scan_id')}, "
                       f"score {result.get('exposure_score')}/100.")
                self.root.after(0, lambda: self._append_log(msg, "ok"))
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e):
                    self._append_log(f"[{_ts()}] Scan now esuat: {err}", "error"))
            finally:
                self.root.after(0, lambda: self._scan_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_toggle_pause(self) -> None:
        new_paused = not self.daemon.is_paused()
        self.daemon.pause(new_paused)
        self._pause_btn.configure(text="Reia" if new_paused else "Pauza")
        self._set_status_indicator("paused" if new_paused else "running")
        self._append_log(
            "Daemon in pauza." if new_paused else "Daemon reluat.",
            "warn" if new_paused else "ok",
        )

    def _open_dashboard(self) -> None:
        try:
            api_base, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            return
        frontend = api_base.replace("/api/v1", "").replace(":8000", ":5173")
        webbrowser.open(f"{frontend}/dashboard?device={device_uid}")

    def _on_toggle_autostart(self) -> None:
        if autostart.is_enabled():
            ok, msg = autostart.disable()
        else:
            ok, msg = autostart.enable()
        self._append_log(msg, "ok" if ok else "error")

    def _on_quit(self) -> None:
        if not messagebox.askyesno("Iesire VulnWatch",
                                   "Opresti agentul si fereastra?\n\n"
                                   "Pentru ca scanarile sa functioneze din UI, agentul "
                                   "trebuie sa ruleze. Daca ai activat autostart, va "
                                   "porni la urmatorul logon."):
            return
        self._shutdown_and_exit()

    def _on_close_window(self) -> None:
        """User-ul a apasat X. Daca tray-ul e activ, ascundem fereastra
        (daemon ramane). Daca nu, intrebam ce vrea sa faca."""
        if self._tray_started:
            self.root.withdraw()
            return
        # Fara tray — comportament clasic: confirma iesirea
        self._on_quit()

    def _shutdown_and_exit(self) -> None:
        self.daemon.stop()
        if self.tray:
            self.tray.stop()
        self.daemon.join(timeout=2.0)
        self.root.destroy()

    # ── Log + indicator ───────────────────────────────────────────────────────

    def _poll_log_queue(self) -> None:
        try:
            while True:
                msg, sev = self.log_queue.get_nowait()
                self._append_log(msg, sev)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _append_log(self, msg: str, severity: str = "info") -> None:
        if not hasattr(self, "_log_text"):
            return
        if severity not in SEVERITY_COLOR:
            severity = "info"
        self._log_text.configure(state="normal")
        self._log_text.insert("end", msg + "\n", severity)
        # Trim daca devine prea mare (>5000 linii)
        line_count = int(self._log_text.index("end-1c").split(".")[0])
        if line_count > 5000:
            self._log_text.delete("1.0", f"{line_count-4000}.0")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _set_status_indicator(self, state: str) -> None:
        if not hasattr(self, "_status_dot"):
            return
        color = {
            "starting": THEME["amber"],
            "running":  THEME["green"],
            "paused":   THEME["text_muted"],
            "error":    THEME["red"],
        }.get(state, THEME["text_muted"])
        self._status_dot.delete("all")
        self._status_dot.create_oval(2, 2, 10, 10, fill=color, outline="")
        self._status_var.set({
            "starting": "Initializare...",
            "running":  "Daemon activ",
            "paused":   "In pauza",
            "error":    "Eroare",
        }.get(state, state))
        if hasattr(self, "tray") and self.tray:
            self.tray.update_tooltip(f"VulnWatch Agent — {self._status_var.get()}")

    # ── Tray (daca pystray e disponibil) ──────────────────────────────────────

    def _maybe_start_tray(self) -> None:
        from . import tray
        if not tray.is_available():
            return
        if self._tray_started:
            return
        state = tray.TrayState(
            tooltip="VulnWatch Agent",
            on_open_dashboard=lambda: self.root.after(0, self._open_dashboard),
            on_toggle_pause=lambda: self.root.after(0, self._on_toggle_pause),
            on_quit=lambda: self.root.after(0, self._shutdown_and_exit),
        )
        try:
            self.tray = tray.TrayController(state)
            self.tray.start()
            self._tray_started = True
        except Exception as e:
            self._append_log(f"Tray indisponibil: {e}", "warn")

    # ── Run ──────────────────────────────────────────────────────────────────

    def run(self) -> int:
        self.root.mainloop()
        return 0


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def run_gui() -> int:
    """Entry point apelat din scan.py."""
    try:
        return AgentApp().run()
    except tk.TclError as e:
        # Fara display (server, SSH fara X) — afisam in stdout si iesim curat
        print(f"GUI indisponibil ({e}). Foloseste CLI: python scan.py daemon")
        return 1
