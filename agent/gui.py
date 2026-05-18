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
# Sistem de teme — Honey & Plum (dark + light)
# ──────────────────────────────────────────────────────────────────────────────

THEME_DARK = {
    "bg":            "#1a0e22",  # plum profund — fundal principal
    "surface":       "#2d1b3d",  # plum elevat — card-uri, input-uri
    "elevated":      "#3a2450",  # plum mai deschis — hover
    "border":        "#4a2d5f",
    "accent":        "#f4c95d",  # honey — primary
    "accent_hover":  "#f7d572",
    "text":          "#fff8e6",  # cream — text principal
    "text_dim":      "#b8a8b8",
    "text_muted":    "#6b5b6e",
    "green":         "#6fb96a",
    "amber":         "#f4c95d",
    "red":           "#e07090",  # rose in loc de rosu strident
}

THEME_LIGHT = {
    "bg":            "#fefaf2",  # cream — fundal principal
    "surface":       "#fff8e6",
    "elevated":      "#f4e8c8",
    "border":        "#e8dccd",
    "accent":        "#f4c95d",  # honey (constant cross-mode)
    "accent_hover":  "#e8b840",
    "text":          "#2d1b3d",  # plum text
    "text_dim":      "#6b5b6e",
    "text_muted":    "#b8a8b8",
    "green":         "#3d8a3a",
    "amber":         "#c18a30",
    "red":           "#8a3a52",
}


class ThemeManager:
    """Gestioneaza tema curenta + persistenta in config.ini sub [ui] theme."""

    def __init__(self):
        self._name = self._load_from_config()
        self._palette = THEME_DARK if self._name == "dark" else THEME_LIGHT

    @property
    def palette(self) -> dict:
        return self._palette

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_dark(self) -> bool:
        return self._name == "dark"

    def toggle(self) -> None:
        self._name = "light" if self._name == "dark" else "dark"
        self._palette = THEME_DARK if self._name == "dark" else THEME_LIGHT
        self._save_to_config()

    @staticmethod
    def _load_from_config() -> str:
        cfg = core.read_config()
        if not cfg.has_section("ui"):
            return "dark"
        val = cfg.get("ui", "theme", fallback="dark").strip().lower()
        return "light" if val == "light" else "dark"

    def _save_to_config(self) -> None:
        cfg = core.read_config()
        if not cfg.has_section("ui"):
            cfg.add_section("ui")
        cfg.set("ui", "theme", self._name)
        try:
            core.write_config(cfg)
        except OSError:
            pass


SEVERITY_COLOR_KEYS = {
    "info":  "text_dim",
    "ok":    "green",
    "warn":  "amber",
    "error": "red",
}


def severity_color(theme: ThemeManager, severity: str) -> str:
    """Returneaza culoarea de log pentru severity in tema curenta."""
    return theme.palette[SEVERITY_COLOR_KEYS.get(severity, "text_dim")]


# ──────────────────────────────────────────────────────────────────────────────
# Aplicatia principala
# ──────────────────────────────────────────────────────────────────────────────


class AgentApp:
    def __init__(self) -> None:
        self.theme = ThemeManager()

        self.root = tk.Tk()
        self.root.title("VulnWatch Agent")
        self.root.geometry("680x560")
        self.root.minsize(560, 460)
        self.root.configure(bg=self.theme.palette["bg"])

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
        p = self.theme.palette
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=p["bg"], foreground=p["text"],
                        fieldbackground=p["surface"], borderwidth=0)
        style.configure("TFrame", background=p["bg"])
        style.configure("TLabel", background=p["bg"], foreground=p["text"])
        style.configure("Dim.TLabel", background=p["bg"],
                        foreground=p["text_dim"], font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=p["bg"],
                        foreground=p["text"], font=("Cambria", 22, "bold"))
        style.configure("Subtitle.TLabel", background=p["bg"],
                        foreground=p["text_dim"], font=("Segoe UI", 11))
        style.configure("Brand.TLabel", background=p["bg"],
                        foreground=p["accent"], font=("Cambria", 11, "bold"))
        style.configure("Footer.TLabel", background=p["bg"],
                        foreground=p["text_muted"], font=("Segoe UI", 9))
        style.configure("Metric.TLabel", background=p["surface"],
                        foreground=p["accent"], font=("Cambria", 22, "bold"))
        style.configure("MetricLabel.TLabel", background=p["surface"],
                        foreground=p["text_dim"], font=("Segoe UI", 9))

        style.configure("TEntry", fieldbackground=p["surface"],
                        foreground=p["text"], bordercolor=p["border"],
                        lightcolor=p["border"], darkcolor=p["border"],
                        padding=10)
        style.map("TEntry", bordercolor=[("focus", p["accent"])])

        style.configure("Accent.TButton", background=p["accent"],
                        foreground=p["surface"] if self.theme.is_dark else "#2d1b3d",
                        font=("Segoe UI", 11, "bold"),
                        padding=(14, 10), borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", p["accent_hover"]),
                              ("disabled", p["elevated"])])

        style.configure("Secondary.TButton", background=p["surface"],
                        foreground=p["text"], padding=(12, 8), borderwidth=0)
        style.map("Secondary.TButton",
                  background=[("active", p["elevated"])])

        style.configure("Outlined.TButton", background=p["surface"],
                        foreground=p["text"], padding=(12, 10), borderwidth=1,
                        font=("Segoe UI", 11, "bold"))
        style.map("Outlined.TButton",
                  background=[("active", p["elevated"])])

        style.configure("Danger.TButton", background=p["surface"],
                        foreground=p["red"], padding=(12, 8), borderwidth=0)

        style.configure("Link.TButton", background=p["bg"],
                        foreground=p["accent"], padding=0, borderwidth=0,
                        font=("Segoe UI", 10, "underline"))
        style.map("Link.TButton",
                  background=[("active", p["bg"])],
                  foreground=[("active", p["accent_hover"])])

        style.configure("TCheckbutton", background=p["bg"],
                        foreground=p["text"])

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

    def _on_theme_toggle(self) -> None:
        """Comuta intre dark si light, persista in config, re-render pagina curenta."""
        self.theme.toggle()
        self._configure_styles()
        self.root.configure(bg=self.theme.palette["bg"])
        self._render_root()

    def _make_theme_toggle_button(self, parent) -> tk.Label:
        """Creeaza widget-ul circular toggle ☾/☀ (top-right pe fiecare pagina)."""
        p = self.theme.palette
        icon = "☀" if self.theme.is_dark else "☾"
        lbl = tk.Label(
            parent, text=icon,
            bg=p["surface"], fg=p["accent"],
            font=("Segoe UI", 14), width=2, cursor="hand2",
            relief="flat", bd=0, padx=4, pady=2,
        )
        lbl.bind("<Button-1>", lambda e: self._on_theme_toggle())
        lbl.bind("<Enter>", lambda e: lbl.configure(bg=p["elevated"]))
        lbl.bind("<Leave>", lambda e: lbl.configure(bg=p["surface"]))
        return lbl

    # ── Pagina LOGIN ─────────────────────────────────────────────────────────

    def _render_login_page(self) -> None:
        p = self.theme.palette

        # Container principal cu padding mare
        wrap = ttk.Frame(self.root, style="TFrame", padding=(48, 32))
        wrap.pack(fill="both", expand=True)

        # Theme toggle dreapta-sus (suprapus pe wrap prin place)
        toggle = self._make_theme_toggle_button(self.root)
        toggle.place(relx=1.0, x=-20, y=14, anchor="ne")

        # Brand
        ttk.Label(wrap, text="VULNWATCH AGENT", style="Brand.TLabel").pack(anchor="w")

        # Titlu + subtitlu
        self._login_title = tk.StringVar(value="Bun venit")
        ttk.Label(wrap, textvariable=self._login_title,
                  style="Title.TLabel").pack(anchor="w", pady=(8, 4))

        self._login_subtitle = tk.StringVar(
            value="Conectează acest PC la contul tău VulnWatch."
        )
        ttk.Label(wrap, textvariable=self._login_subtitle,
                  style="Subtitle.TLabel", wraplength=560).pack(anchor="w", pady=(0, 22))

        # Buton Google (outlined)
        self._google_btn = ttk.Button(
            wrap, text="G   Continuă cu Google",
            style="Outlined.TButton",
            command=self._on_google_login,
        )
        self._google_btn.pack(fill="x", pady=(0, 14))

        # Separator "SAU"
        sep_frame = ttk.Frame(wrap, style="TFrame")
        sep_frame.pack(fill="x", pady=(0, 16))
        ttk.Separator(sep_frame, orient="horizontal").pack(
            side="left", fill="x", expand=True, padx=(0, 12))
        ttk.Label(sep_frame, text="SAU", style="Dim.TLabel").pack(side="left")
        ttk.Separator(sep_frame, orient="horizontal").pack(
            side="left", fill="x", expand=True, padx=(12, 0))

        # Form
        form = ttk.Frame(wrap, style="TFrame")
        form.pack(fill="x")

        self._var_email    = tk.StringVar()
        self._var_password = tk.StringVar()
        self._var_api      = tk.StringVar(value=core.DEFAULT_API_BASE)
        self._auth_mode    = tk.StringVar(value="login")

        ttk.Label(form, text="EMAIL", style="Dim.TLabel").pack(anchor="w", pady=(0, 3))
        e_email = ttk.Entry(form, textvariable=self._var_email,
                            font=("Segoe UI", 11))
        e_email.pack(fill="x", pady=(0, 12))
        e_email.focus_set()

        ttk.Label(form, text="PAROLĂ", style="Dim.TLabel").pack(anchor="w", pady=(0, 3))
        e_pwd = ttk.Entry(form, textvariable=self._var_password, show="•",
                          font=("Segoe UI", 11))
        e_pwd.pack(fill="x", pady=(0, 16))

        # Mesaj eroare/info
        self._login_msg = tk.StringVar()
        ttk.Label(wrap, textvariable=self._login_msg,
                  foreground=p["amber"], background=p["bg"],
                  wraplength=560, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        # Buton submit principal (honey)
        self._login_submit_btn = ttk.Button(
            wrap, text="Autentificare", style="Accent.TButton",
            command=self._submit_login,
        )
        self._login_submit_btn.pack(fill="x", pady=(4, 14))

        # Bind Enter pe Entry pwd → submit
        e_pwd.bind("<Return>", lambda evt: self._submit_login())
        e_email.bind("<Return>", lambda evt: e_pwd.focus_set())

        # Toggle register inline
        toggle_frame = ttk.Frame(wrap, style="TFrame")
        toggle_frame.pack()

        self._toggle_label = tk.StringVar(value="Nu ai cont?")
        ttk.Label(toggle_frame, textvariable=self._toggle_label,
                  style="Dim.TLabel").pack(side="left")

        self._toggle_btn_text = tk.StringVar(value="Înregistrează-te")
        ttk.Button(toggle_frame, textvariable=self._toggle_btn_text,
                   style="Link.TButton",
                   command=self._toggle_auth_mode).pack(side="left", padx=(6, 0))

        # Footer cu API URL + iconita edit
        footer = ttk.Frame(self.root, style="TFrame")
        footer.place(relx=0.5, rely=1.0, y=-14, anchor="s")

        ttk.Label(footer, text=f"VulnWatch Agent v{core.AGENT_VERSION}  ·  API: ",
                  style="Footer.TLabel").pack(side="left")
        api_short = self._var_api.get().replace("http://", "").replace("/api/v1", "")
        self._api_short_var = tk.StringVar(value=api_short)
        ttk.Label(footer, textvariable=self._api_short_var,
                  style="Footer.TLabel").pack(side="left")
        edit_btn = tk.Label(footer, text=" ✎ ",
                            bg=p["bg"], fg=p["accent"],
                            font=("Segoe UI", 10), cursor="hand2")
        edit_btn.pack(side="left")
        edit_btn.bind("<Button-1>", lambda e: self._open_api_url_modal())

    def _toggle_auth_mode(self) -> None:
        if self._auth_mode.get() == "login":
            self._auth_mode.set("register")
            self._login_title.set("Cont nou")
            self._login_subtitle.set(
                "Creează un cont VulnWatch (același cont funcționează și în dashboard)."
            )
            self._login_submit_btn.configure(text="Creează cont")
            self._toggle_label.set("Ai deja cont?")
            self._toggle_btn_text.set("Autentifică-te")
        else:
            self._auth_mode.set("login")
            self._login_title.set("Bun venit")
            self._login_subtitle.set("Conectează acest PC la contul tău VulnWatch.")
            self._login_submit_btn.configure(text="Autentificare")
            self._toggle_label.set("Nu ai cont?")
            self._toggle_btn_text.set("Înregistrează-te")

    def _open_api_url_modal(self) -> None:
        """Modal pentru editare API URL — folosit din footer Login.
        Implementare completă in Task 6 (modale)."""
        from tkinter import simpledialog
        current = self._var_api.get()
        new_url = simpledialog.askstring(
            "Setări avansate API",
            "URL backend VulnWatch (avansat — modifică doar dacă știi ce faci):",
            initialvalue=current, parent=self.root,
        )
        if new_url and new_url.strip():
            self._var_api.set(new_url.strip().rstrip("/"))
            self._refresh_api_short()

    def _refresh_api_short(self) -> None:
        """Actualizeaza afisarea scurta a API URL in footer."""
        if hasattr(self, "_api_short_var"):
            api_short = self._var_api.get().replace("http://", "").replace("/api/v1", "")
            self._api_short_var.set(api_short)

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
        """Pagina enroll consolidata: sub-stare 'new device' sau 'relink'
        in functie de daca exista device cu acelasi UID pe cont."""
        p = self.theme.palette
        self._clear_root()

        wrap = ttk.Frame(self.root, style="TFrame", padding=(40, 24))
        wrap.pack(fill="both", expand=True)

        # Theme toggle
        toggle = self._make_theme_toggle_button(self.root)
        toggle.place(relx=1.0, x=-20, y=14, anchor="ne")

        # Brand bar cu email
        brand_bar = ttk.Frame(wrap, style="TFrame")
        brand_bar.pack(fill="x", pady=(0, 4))
        ttk.Label(brand_bar, text="VULNWATCH AGENT",
                  style="Brand.TLabel").pack(side="left")
        ttk.Label(brand_bar, text=f"  ·  {self._login_email}",
                  style="Dim.TLabel").pack(side="left")

        is_relink = self._existing_device is not None

        # Titlu + subtitlu (variabile)
        if is_relink:
            title = "Reconectează acest PC"
            subtitle = "Vom refolosi înregistrarea existentă — istoricul scanărilor rămâne."
        else:
            title = "Conectează acest PC"
            subtitle = "Vom asocia acest calculator cu contul tău."

        ttk.Label(wrap, text=title,
                  style="Title.TLabel").pack(anchor="w", pady=(8, 4))
        ttk.Label(wrap, text=subtitle,
                  style="Subtitle.TLabel", wraplength=560).pack(anchor="w", pady=(0, 18))

        # Device info card
        sys_name = platform.system()
        hostname = socket.gethostname()
        uid_default = hostname.lower()

        card = tk.Frame(wrap, bg=p["surface"], bd=0,
                        highlightthickness=1, highlightbackground=p["border"])
        card.pack(fill="x", pady=(0, 12))

        card_inner = tk.Frame(card, bg=p["surface"])
        card_inner.pack(fill="x", padx=14, pady=12)

        tk.Label(card_inner, text="\U0001f5a5",
                 bg=p["surface"], fg=p["accent"],
                 font=("Segoe UI Emoji", 22)).pack(side="left", padx=(0, 12))

        info_col = tk.Frame(card_inner, bg=p["surface"])
        info_col.pack(side="left", fill="x", expand=True)
        tk.Label(info_col, text=f"{sys_name} · {hostname}",
                 bg=p["surface"], fg=p["text"],
                 font=("Cambria", 13, "bold")).pack(anchor="w")

        uid_row = tk.Frame(info_col, bg=p["surface"])
        uid_row.pack(anchor="w", pady=(2, 0))
        tk.Label(uid_row, text=f"UID tehnic: {uid_default}",
                 bg=p["surface"], fg=p["text_dim"],
                 font=("Consolas", 10)).pack(side="left")

        if not is_relink:
            # Doar la new enroll, link mic 'Schimbă'
            change_btn = tk.Label(uid_row, text="  [Schimbă]",
                                  bg=p["surface"], fg=p["accent"],
                                  font=("Segoe UI", 9, "underline"),
                                  cursor="hand2")
            change_btn.pack(side="left")
            change_btn.bind("<Button-1>", lambda e: self._prompt_change_uid())

        # Banner re-link (doar in modul relink)
        if is_relink:
            existing_name = (self._existing_device or {}).get("name", "?")
            banner = tk.Frame(wrap, bg=p["surface"], bd=0,
                              highlightthickness=1, highlightbackground=p["accent"])
            banner.pack(fill="x", pady=(0, 12))
            tk.Label(banner,
                     text=f'⚠  Acest PC e deja înregistrat ca „{existing_name}”.',
                     bg=p["surface"], fg=p["accent"],
                     font=("Segoe UI", 10, "bold"),
                     wraplength=560, justify="left").pack(anchor="w", padx=12, pady=(10, 2))
            tk.Label(banner,
                     text="Probabil ai reinstalat OS-ul sau ai șters configul.",
                     bg=p["surface"], fg=p["text_dim"],
                     font=("Segoe UI", 9),
                     wraplength=560, justify="left").pack(anchor="w", padx=12, pady=(0, 10))

        # Câmp nume (editabil în ambele moduri)
        ttk.Label(wrap, text="CUM SĂ APARĂ ÎN DASHBOARD",
                  style="Dim.TLabel").pack(anchor="w", pady=(0, 3))

        if is_relink:
            default_name = (self._existing_device or {}).get("name", f"{sys_name} {hostname}")
        else:
            default_name = f"{sys_name} {hostname}"

        self._var_uid  = tk.StringVar(value=uid_default)
        self._var_name = tk.StringVar(value=default_name)

        ttk.Entry(wrap, textvariable=self._var_name,
                  font=("Segoe UI", 11)).pack(fill="x", pady=(0, 14))

        # Autostart checkbox
        self._var_autostart = tk.BooleanVar(value=True)
        ttk.Checkbutton(wrap, text="Pornește automat la pornirea Windows (recomandat)",
                        variable=self._var_autostart).pack(anchor="w", pady=(0, 18))

        # Mesaj eroare
        self._enroll_msg = tk.StringVar()
        ttk.Label(wrap, textvariable=self._enroll_msg,
                  foreground=p["amber"], background=p["bg"],
                  wraplength=560, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        # Butoane action
        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x")

        btn_label = "Refolosește înregistrarea" if is_relink else "Conectează"
        self._enroll_btn = ttk.Button(
            actions, text=btn_label, style="Accent.TButton",
            command=self._submit_relink if is_relink else self._submit_enroll,
        )
        self._enroll_btn.pack(side="left", padx=(0, 10), fill="x", expand=True)

        ttk.Button(actions, text="Anulează", style="Secondary.TButton",
                   command=self._logout_from_enroll).pack(side="left")

        # Footer: optiune 'Inregistreaza ca PC nou' doar in modul relink
        if is_relink:
            link_frame = ttk.Frame(wrap, style="TFrame")
            link_frame.pack(fill="x", pady=(16, 0))
            link = tk.Label(link_frame,
                            text="Vrei să-l înregistrezi ca PC nou? →",
                            bg=p["bg"], fg=p["accent"],
                            font=("Segoe UI", 9, "underline"),
                            cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", lambda e: self._switch_to_new_enroll())

    def _prompt_change_uid(self) -> None:
        """Permite editarea manuala a UID-ului tehnic (rar folosit)."""
        from tkinter import simpledialog
        new_uid = simpledialog.askstring(
            "Schimbă UID tehnic",
            "Modifică doar dacă știi ce faci.\nUID tehnic curent:",
            initialvalue=self._var_uid.get(), parent=self.root,
        )
        if new_uid and new_uid.strip():
            self._var_uid.set(new_uid.strip().lower())
            # Refresh pagina pentru a reflecta noul UID
            self._render_enroll_page()

    def _switch_to_new_enroll(self) -> None:
        """Forteaza enrollment ca PC nou chiar daca exista device cu acelasi UID."""
        self._existing_device = None
        # Sugereaza un UID diferit ca sa nu loveasca conflict
        base_uid = socket.gethostname().lower()
        self._var_uid = tk.StringVar(value=f"{base_uid}-2")
        self._render_enroll_page()

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

        info = tk.Frame(wrap, bg=self.theme.palette["surface"], bd=0,
                        highlightthickness=1, highlightbackground=self.theme.palette["border"])
        info.pack(fill="x", pady=(12, 12))
        for label, value in [
            ("Cont", user_email),
            ("Device", f"{device_name}  ({device_uid})"),
            ("API", api_base),
        ]:
            row = tk.Frame(info, bg=self.theme.palette["surface"])
            row.pack(fill="x", padx=12, pady=4)
            tk.Label(row, text=label, bg=self.theme.palette["surface"], fg=self.theme.palette["text_muted"],
                     font=("Segoe UI", 9), width=8, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=self.theme.palette["surface"], fg=self.theme.palette["text"],
                     font=("Segoe UI", 10)).pack(side="left")

        status_bar = ttk.Frame(wrap, style="TFrame")
        status_bar.pack(fill="x", pady=(0, 12))
        self._status_dot = tk.Canvas(status_bar, width=12, height=12,
                                     bg=self.theme.palette["bg"], highlightthickness=0)
        self._status_dot.pack(side="left", padx=(0, 8))
        self._status_var = tk.StringVar(value="Pornesc daemon-ul...")
        ttk.Label(status_bar, textvariable=self._status_var,
                  background=self.theme.palette["bg"], foreground=self.theme.palette["text"]).pack(side="left")

        # Info despre niveluri suportate + hint platforma-centric
        levels_info = tk.Frame(wrap, bg=self.theme.palette["surface"], bd=0,
                               highlightthickness=1, highlightbackground=self.theme.palette["border"])
        levels_info.pack(fill="x", pady=(0, 12))
        tk.Label(levels_info,
                 text=f"Niveluri suportate: {' / '.join(s.title() for s in core.SCAN_PROFILES)}",
                 bg=self.theme.palette["surface"], fg=self.theme.palette["accent"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
        tk.Label(levels_info,
                 text="ℹ Scanarea se initiaza din platforma web — agentul ruleaza in fundal.",
                 bg=self.theme.palette["surface"], fg=self.theme.palette["text_dim"],
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

        log_frame = tk.Frame(wrap, bg=self.theme.palette["surface"], bd=0,
                             highlightthickness=1, highlightbackground=self.theme.palette["border"])
        log_frame.pack(fill="both", expand=True)
        self._log_text = tk.Text(log_frame, bg=self.theme.palette["surface"], fg=self.theme.palette["text"],
                                 insertbackground=self.theme.palette["text"],
                                 font=("Consolas", 9), bd=0, padx=10, pady=8,
                                 wrap="word", state="disabled")
        self._log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_frame, orient="vertical",
                               command=self._log_text.yview)
        scroll.pack(side="right", fill="y")
        self._log_text.configure(yscrollcommand=scroll.set)
        for sev in SEVERITY_COLOR_KEYS:
            self._log_text.tag_configure(sev, foreground=severity_color(self.theme, sev))

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
        if severity not in SEVERITY_COLOR_KEYS:
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
            "starting": self.theme.palette["amber"],
            "running":  self.theme.palette["green"],
            "paused":   self.theme.palette["text_muted"],
            "error":    self.theme.palette["red"],
        }.get(state, self.theme.palette["text_muted"])
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
