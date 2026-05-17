"""
VulnWatch Agent — interfata grafica (Tkinter).

Trei pagini afisate dinamic, in functie de stare:

1. **Login** (cand nu exista config valid) — formular cu Email / Parola / API URL
   + link "Nu ai cont? Inregistreaza-te" (toggle inline).

2. **Enroll Device** (post-login, masina noua) — afiseaza UID detectat,
   nume editabil, bifa autostart. Submit → POST /devices → salveaza config →
   pagina Status.

   Subvarianta **Re-link** (post-login, device gasit): "Acest PC pare sa fie
   deja inrolat ca <Nume>. Refoloseste-l?" → POST /devices/{uid}/relink →
   salveaza config → pagina Status.

3. **Status** (config valid) — afiseaza email-ul user-ului + numele device-ului,
   indicator daemon, butoane Scan now / Pauza / Open dashboard / Logout.
   La pornire, daemon-ul porneste automat. Logout sterge configul local
   si revine la pagina de Login.

Tot codul UI ruleaza pe thread-ul principal Tk. Daemon-ul ruleaza pe thread
separat care comunica prin queue.Queue. Niciun update direct la widget-uri
din alte thread-uri.
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

from . import autostart, core, google_oauth


# ──────────────────────────────────────────────────────────────────────────────
# Daemon thread management
# ──────────────────────────────────────────────────────────────────────────────


class DaemonRunner:
    """Wrapper peste core.daemon_loop care ruleaza pe thread separat."""

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
                on_token_invalid=self._signal_token_invalid,
            )
        finally:
            self._emit("Daemon oprit.", "info")

    def _signal_token_invalid(self) -> None:
        """Apelat de daemon_loop pe thread-ul daemon cand backend a respins
        tokenul cu 401. Trimite un marker special pe queue ca UI-ul (pe Tk
        thread) sa reactioneze."""
        try:
            self.log_queue.put_nowait(("__TOKEN_INVALID__", "error"))
        except queue.Full:
            pass

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
# Tema vizuala
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
        self.root.geometry("680x560")
        self.root.minsize(560, 460)
        self.root.configure(bg=THEME["bg"])

        self.log_queue: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=1000)
        self.daemon = DaemonRunner(self.log_queue)
        self.tray = None
        self._tray_started = False

        # State pentru flow-ul de login → enroll
        self._session_token: str | None = None
        self._login_email: str = ""
        self._api_base: str = core.DEFAULT_API_BASE
        self._existing_device: dict | None = None

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
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["text"])
        style.configure("Dim.TLabel", background=THEME["bg"],
                        foreground=THEME["text_dim"], font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=THEME["bg"],
                        foreground=THEME["text"], font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", background=THEME["bg"],
                        foreground=THEME["text_dim"], font=("Segoe UI", 10))
        style.configure("Brand.TLabel", background=THEME["bg"],
                        foreground=THEME["accent"], font=("Segoe UI", 11, "bold"))

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

        style.configure("Link.TButton", background=THEME["bg"],
                        foreground=THEME["accent"], padding=0, borderwidth=0,
                        font=("Segoe UI", 9, "underline"))
        style.map("Link.TButton",
                  background=[("active", THEME["bg"])],
                  foreground=[("active", "#7dd3fc")])

        style.configure("TCheckbutton", background=THEME["bg"],
                        foreground=THEME["text"])

    # ── Routing ──────────────────────────────────────────────────────────────

    def _clear_root(self) -> None:
        for w in self.root.winfo_children():
            w.destroy()

    def _render_root(self) -> None:
        self._clear_root()
        if core.is_enrolled():
            self._render_status_page()
            self.root.after(50, self._auto_start_daemon)
        else:
            self._render_login_page()

    # ── Pagina LOGIN ─────────────────────────────────────────────────────────

    def _render_login_page(self) -> None:
        wrap = ttk.Frame(self.root, style="TFrame", padding=32)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="VULNWATCH AGENT", style="Brand.TLabel").pack(anchor="w")

        self._login_title = tk.StringVar(value="Autentificare")
        ttk.Label(wrap, textvariable=self._login_title, style="Title.TLabel").pack(anchor="w", pady=(8, 4))

        self._login_subtitle = tk.StringVar(
            value="Logheaza-te cu acelasi cont folosit in dashboard."
        )
        ttk.Label(wrap, textvariable=self._login_subtitle, style="Subtitle.TLabel",
                  wraplength=560).pack(anchor="w", pady=(0, 20))

        # ── Buton Continua cu Google ────────────────────────────────────────
        self._google_btn = ttk.Button(
            wrap, text="Continuă cu Google",
            style="Accent.TButton",
            command=self._on_google_login,
        )
        self._google_btn.pack(fill="x", pady=(0, 12))

        # Separator "sau"
        sep_frame = ttk.Frame(wrap, style="TFrame")
        sep_frame.pack(fill="x", pady=(0, 16))
        ttk.Separator(sep_frame, orient="horizontal").pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Label(sep_frame, text="sau", style="Dim.TLabel").pack(side="left")
        ttk.Separator(sep_frame, orient="horizontal").pack(side="left", fill="x", expand=True, padx=(8, 0))

        form = ttk.Frame(wrap, style="TFrame")
        form.pack(fill="x")

        self._var_email    = tk.StringVar()
        self._var_password = tk.StringVar()
        self._var_api      = tk.StringVar(value=core.DEFAULT_API_BASE)
        self._auth_mode    = tk.StringVar(value="login")

        ttk.Label(form, text="Email", style="Dim.TLabel").pack(anchor="w", pady=(0, 2))
        e_email = ttk.Entry(form, textvariable=self._var_email)
        e_email.pack(fill="x", pady=(0, 12))
        e_email.focus_set()

        ttk.Label(form, text="Parola", style="Dim.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Entry(form, textvariable=self._var_password, show="•").pack(fill="x", pady=(0, 12))

        ttk.Label(form, text="API URL", style="Dim.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Entry(form, textvariable=self._var_api).pack(fill="x", pady=(0, 8))

        self._login_msg = tk.StringVar()
        ttk.Label(wrap, textvariable=self._login_msg,
                  foreground=THEME["amber"], background=THEME["bg"],
                  wraplength=560).pack(anchor="w", pady=(8, 4))

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x", pady=(8, 0))

        self._login_submit_btn = ttk.Button(
            actions, text="Autentificare", style="Accent.TButton",
            command=self._submit_login,
        )
        self._login_submit_btn.pack(side="left")

        toggle_frame = ttk.Frame(wrap, style="TFrame")
        toggle_frame.pack(fill="x", pady=(20, 0))

        self._toggle_label = tk.StringVar(value="Nu ai cont?")
        ttk.Label(toggle_frame, textvariable=self._toggle_label,
                  style="Dim.TLabel").pack(side="left")

        self._toggle_btn_text = tk.StringVar(value="Inregistreaza-te")
        self._toggle_btn = ttk.Button(
            toggle_frame, textvariable=self._toggle_btn_text, style="Link.TButton",
            command=self._toggle_auth_mode,
        )
        self._toggle_btn.pack(side="left", padx=(4, 0))

    def _toggle_auth_mode(self) -> None:
        if self._auth_mode.get() == "login":
            self._auth_mode.set("register")
            self._login_title.set("Cont nou")
            self._login_subtitle.set("Creeaza un cont VulnWatch (vei putea folosi acelasi cont si in dashboard).")
            self._login_submit_btn.configure(text="Creeaza cont")
            self._toggle_label.set("Ai deja cont?")
            self._toggle_btn_text.set("Autentifica-te")
        else:
            self._auth_mode.set("login")
            self._login_title.set("Autentificare")
            self._login_subtitle.set("Logheaza-te cu acelasi cont folosit in dashboard.")
            self._login_submit_btn.configure(text="Autentificare")
            self._toggle_label.set("Nu ai cont?")
            self._toggle_btn_text.set("Inregistreaza-te")

    def _submit_login(self) -> None:
        email = self._var_email.get().strip().lower()
        password = self._var_password.get()
        api = self._var_api.get().strip().rstrip("/")
        mode = self._auth_mode.get()

        if not email or not password:
            self._login_msg.set("Email si parola sunt obligatorii.")
            return
        if len(password) < 8:
            self._login_msg.set("Parola trebuie sa aiba minim 8 caractere.")
            return

        self._login_submit_btn.configure(state="disabled")
        self._login_msg.set("Se autentifica..." if mode == "login" else "Se creeaza contul...")

        def worker() -> None:
            try:
                if mode == "register":
                    core.api_register(api, email, password)
                token = core.api_login(api, email, password)
                core.api_me(api, token)
                hostname = socket.gethostname().lower()
                existing = core.api_get_device_by_uid(api, token, hostname)
                self.root.after(0, lambda: self._on_login_success(api, token, email, existing))
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e): self._on_login_failure(err))
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda err=str(e): self._on_login_failure(err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_login_success(self, api: str, token: str, email: str,
                          existing: dict | None) -> None:
        self._session_token = token
        self._login_email = email
        self._api_base = api
        self._existing_device = existing
        self._render_enroll_page()

    def _on_login_failure(self, error: str) -> None:
        self._login_submit_btn.configure(state="normal")
        if "email already registered" in error.lower():
            self._login_msg.set("Acest email este deja inregistrat. Foloseste 'Autentifica-te'.")
        elif "invalid credentials" in error.lower():
            self._login_msg.set("Email sau parola incorecte.")
        else:
            self._login_msg.set(f"Eroare: {error}")

    # ── Login Google (loopback OAuth) ────────────────────────────────────────

    def _on_google_login(self) -> None:
        """Flow OAuth desktop: deschide browserul, primeste id_token, enroll."""
        if not google_oauth.is_configured():
            messagebox.showerror(
                "Google OAuth neconfigurat",
                "agent/google_config.py nu contine GOOGLE_CLIENT_ID.\n"
                "Vezi google_config.py.example pentru setup."
            )
            return

        self._google_btn.configure(state="disabled", text="Se deschide browserul...")
        self._login_msg.set("")

        def worker() -> None:
            try:
                id_tok = google_oauth.login_with_google()
                device_uid = socket.gethostname().lower()
                device_name = socket.gethostname()
                api_base = self._var_api.get().strip().rstrip("/") or core.DEFAULT_API_BASE

                # Generam tokenul local; backend primeste doar hash-ul.
                token_plain, token_hash = core.generate_device_token()
                result = core.api_google_enroll(
                    api_base, id_tok, device_uid, device_name,
                    token_hash=token_hash,
                )

                core.save_enrollment(
                    api_base=api_base,
                    device_uid=result["device_uid"],
                    device_token=token_plain,
                    device_name=result["device_name"],
                    user_email=result["user_email"],
                )
                self.root.after(0, self._on_google_login_success)
            except google_oauth.GoogleOAuthError as e:
                self.root.after(0, lambda err=str(e): self._on_google_login_error(err))
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e): self._on_google_login_error(err))
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda err=str(e): self._on_google_login_error(f"Eroare: {err}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_google_login_success(self) -> None:
        self._google_btn.configure(state="normal", text="Continuă cu Google")
        self._auto_start_daemon()
        self._render_status_page()

    def _on_google_login_error(self, error: str) -> None:
        self._google_btn.configure(state="normal", text="Continuă cu Google")
        self._login_msg.set(f"Google login esuat: {error}")

    # ── Pagina ENROLL DEVICE ─────────────────────────────────────────────────

    def _render_enroll_page(self) -> None:
        self._clear_root()
        wrap = ttk.Frame(self.root, style="TFrame", padding=32)
        wrap.pack(fill="both", expand=True)

        head = ttk.Frame(wrap, style="TFrame")
        head.pack(fill="x")
        ttk.Label(head, text="VULNWATCH AGENT", style="Brand.TLabel").pack(side="left")
        ttk.Label(head, text=f"  •  {self._login_email}",
                  style="Dim.TLabel").pack(side="left")

        if self._existing_device:
            self._render_relink_section(wrap)
        else:
            self._render_new_enroll_section(wrap)

    def _render_relink_section(self, wrap: ttk.Frame) -> None:
        existing = self._existing_device or {}
        ttk.Label(wrap, text="Refoloseste device existent",
                  style="Title.TLabel").pack(anchor="w", pady=(12, 4))
        ttk.Label(
            wrap,
            text=(f"Acest PC pare deja inrolat pe contul tau ca "
                  f"\"{existing.get('name', '?')}\". Cel mai probabil "
                  f"ai reinstalat sistemul sau ai sters configul local. "
                  f"Vrei sa reactivezi device-ul existent?"),
            style="Subtitle.TLabel", wraplength=580,
        ).pack(anchor="w", pady=(0, 20))

        card = tk.Frame(wrap, bg=THEME["surface"], bd=0,
                        highlightthickness=1, highlightbackground=THEME["border"])
        card.pack(fill="x", pady=(0, 16))
        for k, label in [("name", "Nume"), ("device_uid", "UID"), ("created_at", "Inregistrat")]:
            row = tk.Frame(card, bg=THEME["surface"])
            row.pack(fill="x", padx=12, pady=4)
            tk.Label(row, text=label, bg=THEME["surface"], fg=THEME["text_muted"],
                     font=("Segoe UI", 9), width=14, anchor="w").pack(side="left")
            tk.Label(row, text=str(existing.get(k, "?"))[:60], bg=THEME["surface"],
                     fg=THEME["text"], font=("Consolas", 10)).pack(side="left")

        self._enroll_msg = tk.StringVar()
        ttk.Label(wrap, textvariable=self._enroll_msg, foreground=THEME["amber"],
                  background=THEME["bg"], wraplength=580).pack(anchor="w", pady=(0, 8))

        self._var_autostart = tk.BooleanVar(value=True)
        ttk.Checkbutton(wrap, text="Porneste automat la logon (recomandat)",
                        variable=self._var_autostart).pack(anchor="w", pady=(8, 16))

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x")
        self._enroll_btn = ttk.Button(
            actions, text="Refoloseste device-ul",
            style="Accent.TButton", command=self._submit_relink,
        )
        self._enroll_btn.pack(side="left", padx=(0, 8))

        ttk.Button(actions, text="Inroleaza ca device nou",
                   style="Secondary.TButton",
                   command=self._switch_to_new_enroll).pack(side="left")

    def _switch_to_new_enroll(self) -> None:
        self._existing_device = None
        self._render_enroll_page()

    def _render_new_enroll_section(self, wrap: ttk.Frame) -> None:
        ttk.Label(wrap, text="Inroleaza acest PC", style="Title.TLabel").pack(anchor="w", pady=(12, 4))
        ttk.Label(
            wrap,
            text="Acest PC va trimite scanari de securitate catre contul tau. "
                 "Poti vedea rezultatele in dashboard, la /devices.",
            style="Subtitle.TLabel", wraplength=580,
        ).pack(anchor="w", pady=(0, 20))

        sysinfo = tk.Frame(wrap, bg=THEME["surface"], bd=0,
                           highlightthickness=1, highlightbackground=THEME["border"])
        sysinfo.pack(fill="x", pady=(0, 16))
        for label, value in [
            ("Sistem", f"{platform.system()} {platform.release()}"),
            ("Hostname", socket.gethostname()),
        ]:
            row = tk.Frame(sysinfo, bg=THEME["surface"])
            row.pack(fill="x", padx=12, pady=4)
            tk.Label(row, text=label, bg=THEME["surface"], fg=THEME["text_muted"],
                     font=("Segoe UI", 9), width=14, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=THEME["surface"], fg=THEME["text"],
                     font=("Consolas", 10)).pack(side="left")

        form = ttk.Frame(wrap, style="TFrame")
        form.pack(fill="x")

        self._var_uid  = tk.StringVar(value=socket.gethostname().lower())
        self._var_name = tk.StringVar(value=f"{platform.system()} {socket.gethostname()}")

        ttk.Label(form, text="Device UID (identificator tehnic)",
                  style="Dim.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Entry(form, textvariable=self._var_uid).pack(fill="x", pady=(0, 12))

        ttk.Label(form, text="Nume afisat (cum apare in dashboard)",
                  style="Dim.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Entry(form, textvariable=self._var_name).pack(fill="x", pady=(0, 12))

        self._enroll_msg = tk.StringVar()
        ttk.Label(wrap, textvariable=self._enroll_msg, foreground=THEME["amber"],
                  background=THEME["bg"], wraplength=580).pack(anchor="w", pady=(8, 4))

        self._var_autostart = tk.BooleanVar(value=True)
        ttk.Checkbutton(wrap, text="Porneste automat la logon (recomandat)",
                        variable=self._var_autostart).pack(anchor="w", pady=(4, 16))

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x")
        self._enroll_btn = ttk.Button(
            actions, text="Inroleaza acest PC",
            style="Accent.TButton", command=self._submit_enroll,
        )
        self._enroll_btn.pack(side="left", padx=(0, 8))

        ttk.Button(actions, text="Logout",
                   style="Secondary.TButton",
                   command=self._logout_from_enroll).pack(side="right")

    def _logout_from_enroll(self) -> None:
        if self._session_token:
            try:
                core.api_logout(self._api_base, self._session_token)
            except Exception:
                pass
        self._session_token = None
        self._login_email = ""
        self._existing_device = None
        self._render_login_page()

    def _submit_enroll(self) -> None:
        uid = self._var_uid.get().strip()
        name = self._var_name.get().strip()
        if not uid or not name:
            self._enroll_msg.set("UID si nume sunt obligatorii.")
            return

        self._enroll_btn.configure(state="disabled")
        self._enroll_msg.set("Se inregistreaza dispozitivul...")

        def worker() -> None:
            try:
                created = core.enroll_device_with_session(
                    self._api_base, self._session_token, uid, name,
                    relink_if_exists=False, log=lambda m, s="info": None,
                )
                self._finalize_enrollment(created)
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))

        threading.Thread(target=worker, daemon=True).start()

    def _submit_relink(self) -> None:
        uid = (self._existing_device or {}).get("device_uid", "")
        if not uid:
            self._enroll_msg.set("Lipseste UID-ul device-ului existent.")
            return

        self._enroll_btn.configure(state="disabled")
        self._enroll_msg.set("Se reactiveaza device-ul...")

        def worker() -> None:
            try:
                created = core.api_relink_device(self._api_base, self._session_token, uid)
                self._finalize_enrollment(created)
            except core.ApiError as e:
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))
            except Exception as e:  # noqa: BLE001
                self.root.after(0, lambda err=str(e): self._on_enroll_failure(err))

        threading.Thread(target=worker, daemon=True).start()

    def _finalize_enrollment(self, created: dict) -> None:
        device_token = created.get("device_token")
        if not device_token:
            self.root.after(0, lambda: self._on_enroll_failure(
                "Backend-ul nu a returnat device_token"))
            return

        device_uid = created.get("device_uid", "")
        device_name = created.get("name", device_uid)

        core.save_enrollment(
            self._api_base, device_uid, device_token,
            device_name=device_name, user_email=self._login_email,
        )

        if self._var_autostart.get():
            try:
                autostart.enable()
            except Exception:
                pass

        try:
            core.api_logout(self._api_base, self._session_token)
        except Exception:
            pass
        self._session_token = None

        self.root.after(0, self._render_root)

    def _on_enroll_failure(self, error: str) -> None:
        self._enroll_btn.configure(state="normal")
        if "already exists" in error.lower():
            self._enroll_msg.set(
                "Acest UID exista deja pe contul tau. Foloseste alt UID, "
                "sau reincarca pagina ca sa apara optiunea de re-link."
            )
        else:
            self._enroll_msg.set(f"Eroare: {error}")

    # ── Pagina STATUS ─────────────────────────────────────────────────────────

    def _render_status_page(self) -> None:
        self._clear_root()
        wrap = ttk.Frame(self.root, style="TFrame", padding=20)
        wrap.pack(fill="both", expand=True)

        try:
            api_base, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            self._render_login_page()
            return

        meta = core.get_enrollment_meta()
        device_name = meta.get("device_name") or device_uid
        user_email = meta.get("user_email") or "(unknown account)"

        header = ttk.Frame(wrap, style="TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="VULNWATCH AGENT", style="Brand.TLabel").pack(anchor="w")

        info = tk.Frame(wrap, bg=THEME["surface"], bd=0,
                        highlightthickness=1, highlightbackground=THEME["border"])
        info.pack(fill="x", pady=(12, 12))
        for label, value in [
            ("Cont", user_email),
            ("Device", f"{device_name}  ({device_uid})"),
            ("API", api_base),
        ]:
            row = tk.Frame(info, bg=THEME["surface"])
            row.pack(fill="x", padx=12, pady=4)
            tk.Label(row, text=label, bg=THEME["surface"], fg=THEME["text_muted"],
                     font=("Segoe UI", 9), width=8, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=THEME["surface"], fg=THEME["text"],
                     font=("Segoe UI", 10)).pack(side="left")

        status_bar = ttk.Frame(wrap, style="TFrame")
        status_bar.pack(fill="x", pady=(0, 12))
        self._status_dot = tk.Canvas(status_bar, width=12, height=12,
                                     bg=THEME["bg"], highlightthickness=0)
        self._status_dot.pack(side="left", padx=(0, 8))
        self._status_var = tk.StringVar(value="Pornesc daemon-ul...")
        ttk.Label(status_bar, textvariable=self._status_var,
                  background=THEME["bg"], foreground=THEME["text"]).pack(side="left")

        # Info despre niveluri suportate + hint platforma-centric
        levels_info = tk.Frame(wrap, bg=THEME["surface"], bd=0,
                               highlightthickness=1, highlightbackground=THEME["border"])
        levels_info.pack(fill="x", pady=(0, 12))
        tk.Label(levels_info,
                 text=f"Niveluri suportate: {' / '.join(s.title() for s in core.SCAN_PROFILES)}",
                 bg=THEME["surface"], fg=THEME["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
        tk.Label(levels_info,
                 text="ℹ Scanarea se initiaza din platforma web — agentul ruleaza in fundal.",
                 bg=THEME["surface"], fg=THEME["text_dim"],
                 font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(2, 8))

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x", pady=(0, 12))

        ttk.Button(actions, text="Deschide platforma",
                   style="Accent.TButton",
                   command=self._open_dashboard).pack(side="left", padx=(0, 6))

        self._pause_btn = ttk.Button(actions, text="Pauza",
                                     style="Secondary.TButton",
                                     command=self._on_toggle_pause)
        self._pause_btn.pack(side="left", padx=(0, 6))

        ttk.Button(actions, text="Logout",
                   style="Danger.TButton",
                   command=self._on_logout).pack(side="right")

        ttk.Label(wrap, text="Activitate", style="Dim.TLabel").pack(anchor="w", pady=(4, 4))

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

        autostart_state = autostart.is_enabled()
        self._autostart_var = tk.BooleanVar(value=autostart_state)
        bottom = ttk.Frame(wrap, style="TFrame")
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(bottom, text="Porneste automat la logon",
                        variable=self._autostart_var,
                        command=self._on_toggle_autostart).pack(side="left")

        self._set_status_indicator("starting")

    # ── Daemon control ────────────────────────────────────────────────────────

    def _auto_start_daemon(self) -> None:
        if self.daemon.is_running():
            return
        if self.daemon.start():
            self._set_status_indicator("running")
            self._maybe_start_tray()

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
        if self._autostart_var.get():
            ok, msg = autostart.enable()
        else:
            ok, msg = autostart.disable()
        self._append_log(msg, "ok" if ok else "error")

    def _on_logout(self) -> None:
        if not messagebox.askyesno(
            "Logout din acest PC",
            "Logout sterge configul local. Va trebui sa te logezi din nou ca "
            "sa ruleze scanari pe acest PC.\n\n"
            "Device-ul ramane pe contul tau in dashboard si poti sa-l "
            "reactivezi oricand cu acelasi cont.\n\n"
            "Continui?",
        ):
            return
        self.daemon.stop()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
            self.tray = None
            self._tray_started = False
        self.daemon.join(timeout=2.0)
        self.daemon = DaemonRunner(self.log_queue)
        core.clear_config()
        self._render_login_page()

    def _handle_token_invalid(self) -> None:
        """Daemon a primit 401 — token-ul nu mai e valid. Force re-login fara
        sa cracheze sau sa lase user-ul intr-o stare confuza."""
        self.daemon.stop()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
            self.tray = None
            self._tray_started = False
        self.daemon.join(timeout=2.0)
        self.daemon = DaemonRunner(self.log_queue)

        # Salveaza api_base pentru convenience inainte de clear config
        try:
            saved_api, _, _ = core.get_enrollment()
        except RuntimeError:
            saved_api = core.DEFAULT_API_BASE
        core.clear_config()

        # Re-render Login + mesaj clar
        self._render_login_page()
        self._var_api.set(saved_api)
        self._login_msg.set(
            "Conexiunea cu platforma a expirat (device-ul a fost sters sau "
            "tokenul invalidat). Reconecteaza-te pentru a continua sa primesti "
            "scanari."
        )

        # Reia polling-ul ca sa prinda eventuale evenimente viitoare
        self.root.after(100, self._poll_log_queue)

    def _on_close_window(self) -> None:
        if self._tray_started:
            self.root.withdraw()
            return
        if not messagebox.askyesno(
            "Iesire VulnWatch",
            "Opresti agentul si fereastra?\n\n"
            "Pentru ca scanarile sa functioneze din UI, agentul trebuie sa "
            "ruleze. Daca ai activat autostart, va porni la urmatorul logon.",
        ):
            return
        self._shutdown_and_exit()

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
                if msg == "__TOKEN_INVALID__":
                    self._handle_token_invalid()
                    return  # _handle_token_invalid reia polling-ul
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

    # ── Tray ──────────────────────────────────────────────────────────────────

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
        print(f"GUI indisponibil ({e}). Foloseste CLI: python scan.py daemon")
        return 1
