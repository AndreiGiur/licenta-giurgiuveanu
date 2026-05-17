# Redesign GUI executabil agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite complet UI-ul executabilului agent (Tkinter) cu paletă Honey & Plum dark+light, 3 pagini regândite (Login / Enroll consolidat / Status cu metrici live), cache local pentru metrici și meniu setări consolidat.

**Architecture:** Păstrăm Tkinter; refactor exclusiv în `agent/gui.py` + adăugare clasă `MetricsTracker` în `agent/core.py`. Theme system cu 2 paletele (dark/light) și toggle persistat în config. Metrici cache în `~/.vulnwatch/metrics.json` cu scriere atomică. Zero modificări pe backend sau web.

**Tech Stack:** Python stdlib (Tkinter, json, configparser, pathlib), `psutil` pentru info sistem (existent), `pystray` pentru tray (existent). Fonturi Windows nativ: Cambria (serif), Segoe UI (sans), Consolas (mono).

**Spec:** `docs/superpowers/specs/2026-05-18-agent-gui-redesign-design.md` (commit `6193e1f`).

---

## File structure

| Fișier | Responsabilitate |
|---|---|
| `agent/core.py` | + clasa `MetricsTracker` (logică pură persistare metrici); fără alte modificări |
| `agent/gui.py` | Rewrite complet: paletă, layout, comportament butoane, modale, meniu ⚙ |
| `agent/tests/test_metrics_tracker.py` | NOU: 3 unit tests pentru `MetricsTracker` (logică pură, testabilă fără UI) |
| `agent/memory.md` | Update: paletă, structură pagini noi, cache metrici |
| `agent/tests/memory.md` | Update: adaugă mențiunea noului test |

Plan ordonat în 7 task-uri secvențiale, fiecare independent committable: cache → theme → Login → Enroll → Status → modale/meniu → docs/smoke.

---

## Task 1: MetricsTracker class + cache JSON + unit tests

**Files:**
- Modify: `agent/core.py` (add class după `is_admin()`, înainte de `collect_system_data`)
- Create: `agent/tests/test_metrics_tracker.py`

- [ ] **Step 1: Scrie testele care eșuează**

Creează `agent/tests/test_metrics_tracker.py`:

```python
"""Unit tests pentru MetricsTracker — logica de cache local pentru scanari."""
import json
from pathlib import Path

import pytest

from agent import core


def test_metrics_tracker_returns_empty_state_when_file_missing(tmp_path):
    """Daca metrics.json nu exista, state-ul e gol cu valori default."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    assert tracker.state["scans_total"] == 0
    assert tracker.state["last_exposure_score"] is None
    assert tracker.state["last_scan_at"] is None
    assert tracker.state["history"] == []
    assert tracker.state["version"] == 1


def test_metrics_tracker_records_scan_and_persists_atomically(tmp_path):
    """record_scan incrementeaza counters, adauga history entry, salveaza pe disk."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    tracker.record_scan(score=42, scan_type="standard", job_id=128)
    tracker.record_scan(score=37, scan_type="deep", job_id=129)

    assert tracker.state["scans_total"] == 2
    assert tracker.state["last_exposure_score"] == 37
    assert tracker.state["last_scan_at"] is not None
    assert len(tracker.state["history"]) == 2
    # Cele mai recente prime
    assert tracker.state["history"][0]["job_id"] == 129
    assert tracker.state["history"][1]["job_id"] == 128

    # Persistat pe disk + reluabil dintr-o instanta noua
    assert cache.exists()
    tracker2 = core.MetricsTracker(cache)
    assert tracker2.state["scans_total"] == 2
    assert tracker2.state["last_exposure_score"] == 37


def test_metrics_tracker_history_capped_at_20(tmp_path):
    """History tine doar ultimele 20 entries."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)

    for i in range(25):
        tracker.record_scan(score=i, scan_type="standard", job_id=i)

    assert tracker.state["scans_total"] == 25
    assert len(tracker.state["history"]) == 20
    # Cele mai recente prime — primul e job_id=24, ultimul e job_id=5
    assert tracker.state["history"][0]["job_id"] == 24
    assert tracker.state["history"][19]["job_id"] == 5


def test_metrics_tracker_corrupt_json_falls_back_to_empty(tmp_path):
    """JSON invalid → state gol, fara crash."""
    cache = tmp_path / "metrics.json"
    cache.write_text("{not valid json", encoding="utf-8")

    tracker = core.MetricsTracker(cache)
    assert tracker.state["scans_total"] == 0
    assert tracker.state["history"] == []


def test_metrics_tracker_reset_clears_disk(tmp_path):
    """reset() goleste state-ul si sterge fisierul."""
    cache = tmp_path / "metrics.json"
    tracker = core.MetricsTracker(cache)
    tracker.record_scan(score=50, scan_type="standard", job_id=1)
    assert cache.exists()

    tracker.reset()
    assert tracker.state["scans_total"] == 0
    assert not cache.exists()
```

- [ ] **Step 2: Run tests — must FAIL**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/test_metrics_tracker.py -v
```
Expected: FAIL — `AttributeError: module 'agent.core' has no attribute 'MetricsTracker'`

- [ ] **Step 3: Implementează `MetricsTracker` în `agent/core.py`**

Localizează linia cu `def is_admin()` (~linia 229) și adaugă DUPĂ end-ul funcției `is_admin`, înainte de `def collect_system_data`:

```python
# ── Metrics cache local (persistent intre restart-uri) ────────────────────────

METRICS_FILE = CONFIG_DIR / "metrics.json"
_METRICS_VERSION = 1
_HISTORY_MAX = 20


class MetricsTracker:
    """Persista counters de scanari local pentru afisare rapida in GUI.

    Sursa de adevar ramane backend-ul; cache-ul e doar pentru UX (responsivitate
    GUI fara polling backend pentru fiecare deschidere). Scriere atomica prin
    write-to-temp-then-rename. Citire defensiva: JSON corupt → state gol."""

    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.state = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            # Validare basic: cheile esentiale exista
            if not isinstance(data, dict) or "scans_total" not in data:
                raise ValueError("schema invalida")
            # Backfill chei lipsa pentru forward-compat
            data.setdefault("version", _METRICS_VERSION)
            data.setdefault("last_exposure_score", None)
            data.setdefault("last_scan_at", None)
            data.setdefault("history", [])
            return data
        except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
            return self._empty_state()

    @staticmethod
    def _empty_state() -> dict:
        return {
            "version": _METRICS_VERSION,
            "scans_total": 0,
            "last_exposure_score": None,
            "last_scan_at": None,
            "history": [],
        }

    def record_scan(self, score: int, scan_type: str, job_id: int) -> None:
        """Apelat din daemon thread dupa submit_job_result OK."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.state["scans_total"] = self.state.get("scans_total", 0) + 1
        self.state["last_exposure_score"] = int(score)
        self.state["last_scan_at"] = now
        entry = {
            "timestamp": now,
            "score": int(score),
            "scan_type": scan_type,
            "job_id": int(job_id),
        }
        self.state["history"].insert(0, entry)
        self.state["history"] = self.state["history"][:_HISTORY_MAX]
        self._save_atomic()

    def reset(self) -> None:
        """Apelat la 'Deconecteaza acest PC' — sterge cache-ul."""
        self.state = self._empty_state()
        try:
            self.cache_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _save_atomic(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        except OSError:
            pass  # best-effort; nu blocam daemon-ul daca disk-ul e plin
```

Adaugă în partea de sus a `core.py` (după imports existente, ~linia 27):

```python
import json
```

- [ ] **Step 4: Run tests — must PASS**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/test_metrics_tracker.py -v
```
Expected: PASS — 5 teste

- [ ] **Step 5: Run all agent tests — niciun regres**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/ -v 2>&1 | tail -5
```
Expected: PASS — 42 (existente) + 5 (noi) = 47 teste

- [ ] **Step 6: Commit**

```bash
git add agent/core.py agent/tests/test_metrics_tracker.py
git commit -m "feat(agent): MetricsTracker class pentru cache local scanari"
```

---

## Task 2: Theme system (palettes + manager + persist)

**Files:**
- Modify: `agent/gui.py` (înlocuiește dict-ul `THEME` cu sistem 2-tema + clasă `ThemeManager`)

- [ ] **Step 1: Înlocuiește block-ul `THEME = {...}` (liniile 125-138 în `agent/gui.py`)**

Înlocuiește block-ul curent cu:

```python
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
```

- [ ] **Step 2: Înlocuiește utilizările `THEME[...]` cu `self.theme.palette[...]` în `AgentApp`**

Modifică `AgentApp.__init__` să instanțieze `ThemeManager` chiar la început:

```python
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
```

- [ ] **Step 3: Înlocuiește `_configure_styles` să folosească `self.theme.palette`**

Linia 180+ — înlocuiește metoda complet:

```python
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
```

- [ ] **Step 4: Adaugă metodă `_on_theme_toggle` și widget toggle**

În `AgentApp`, după `_render_root`, adaugă:

```python
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
```

- [ ] **Step 5: Înlocuiește utilizările globale `THEME[...]` și `SEVERITY_COLOR[...]` cu palette local**

Caută toate `THEME[` în `gui.py`:
```bash
grep -n "THEME\[" agent/gui.py
```
Pentru fiecare instanță, înlocuiește `THEME["foo"]` cu `self.theme.palette["foo"]` (sau cu `p["foo"]` dacă deja există `p = self.theme.palette` în context-ul funcției).

Caută `SEVERITY_COLOR[`:
```bash
grep -n "SEVERITY_COLOR" agent/gui.py
```
Înlocuiește `SEVERITY_COLOR[sev]` cu `severity_color(self.theme, sev)`.

În metoda `_append_log` (~linia 832), schimbă:
```python
for sev, color in SEVERITY_COLOR.items():
    self._log_text.tag_configure(sev, foreground=color)
```
cu:
```python
for sev in SEVERITY_COLOR_KEYS:
    self._log_text.tag_configure(sev, foreground=severity_color(self.theme, sev))
```

În `_append_log`, ajustează `if severity not in SEVERITY_COLOR:` → `if severity not in SEVERITY_COLOR_KEYS:`.

- [ ] **Step 6: Smoke test — pornește GUI**

```bash
cd agent
PYTHONUTF8=1 ../server/.venv/Scripts/python scan.py gui
```
Expected: fereastra deschide, fundalul e plum #1a0e22, brand "VULNWATCH AGENT" e honey.

Închide cu Alt+F4.

- [ ] **Step 7: Run all agent tests — niciun regres**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/ -v 2>&1 | tail -3
```
Expected: PASS — 47 teste

- [ ] **Step 8: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): sistem de teme Honey & Plum dark + light cu toggle persistat"
```

---

## Task 3: Login regândit (footer ✎ API + theme toggle în colț)

**Files:**
- Modify: `agent/gui.py` — funcția `_render_login_page` (linia 246+)

- [ ] **Step 1: Înlocuiește `_render_login_page` complet**

Localizează `def _render_login_page(self) -> None:` (~linia 246) și înlocuiește TOATĂ metoda (până la `def _toggle_auth_mode`, exclusiv):

```python
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
```

- [ ] **Step 2: Înlocuiește `_toggle_auth_mode` cu copy-ul actualizat**

```python
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
```

- [ ] **Step 3: Adaugă stub pentru `_open_api_url_modal` (implementarea completă în Task 6)**

În `AgentApp`, undeva după `_toggle_auth_mode`, adaugă:

```python
    def _open_api_url_modal(self) -> None:
        """Modal pentru editare API URL — folosit din footer Login.
        Implementare completă în Task 6 (modale)."""
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
```

- [ ] **Step 4: Smoke test**

```bash
cd agent
PYTHONUTF8=1 ../server/.venv/Scripts/python scan.py gui
```
Expected: pagina Login afișează cu noua paletă; buton Google outlined; submit primary honey; toggle dreapta-sus comută între dark și light; footer arată versiunea + API short + ✎; click ✎ deschide popup pentru editare; toggle Register/Login funcționează.

Închide cu Alt+F4.

- [ ] **Step 5: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): Login regandit cu paleta Honey & Plum + footer API edit"
```

---

## Task 4: Enroll consolidat (new + re-link în aceeași pagină)

**Files:**
- Modify: `agent/gui.py` — funcțiile `_render_enroll_page`, `_render_relink_section`, `_render_new_enroll_section`, `_switch_to_new_enroll` (liniile ~426-558)

- [ ] **Step 1: Înlocuiește `_render_enroll_page` complet + scoate metodele separate de re-link/new**

Localizează `def _render_enroll_page(self) -> None:` (~linia 428) și înlocuiește metoda + următoarele 2-3 metode legate (`_render_relink_section`, `_render_new_enroll_section`, `_switch_to_new_enroll`) cu:

```python
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

        tk.Label(card_inner, text="🖥",
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
                     text=f"⚠  Acest PC e deja înregistrat ca „{existing_name}".",
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
```

- [ ] **Step 2: Asigură-te că `_submit_enroll`, `_submit_relink`, `_finalize_enrollment`, `_on_enroll_failure`, `_logout_from_enroll` rămân neschimbate**

Verifică că `grep -n "def _submit_enroll\|def _submit_relink\|def _finalize_enrollment\|def _on_enroll_failure\|def _logout_from_enroll" agent/gui.py` returnează liniile lor — ele NU se modifică în acest task.

- [ ] **Step 3: Smoke test**

```bash
cd agent
PYTHONUTF8=1 ../server/.venv/Scripts/python scan.py gui
```

Logare cu test@test.com / testtest123 (sau Google) → trebuie să vezi pagina Enroll cu hostname-ul tău + buton „Conectează" + checkbox autostart + buton „Anulează".

Dacă device cu acest UID nu există → mode „new device" cu link „[Schimbă]" lângă UID.

- [ ] **Step 4: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): Enroll consolidat — new + re-link in aceeasi pagina cu sub-stari"
```

---

## Task 5: Status regândit (dot 5 stări + metrici + Detalii expandabilă)

**Files:**
- Modify: `agent/gui.py` — funcția `_render_status_page` (~linia 647), adaugă state pentru metrici și dot status

- [ ] **Step 1: Adaugă atribute noi în `AgentApp.__init__`**

În metoda `__init__`, după `self.daemon = DaemonRunner(self.log_queue)`, adaugă:

```python
        # Metrics tracker (cache local)
        self.metrics = core.MetricsTracker(core.METRICS_FILE)

        # State Status page
        self._last_heartbeat_ts: float = 0.0  # timestamp ultimului heartbeat OK
        self._status_state: str = "starting"   # online | degraded | offline | paused | starting
        self._details_expanded: bool = self._load_details_expanded_pref()
```

- [ ] **Step 2: Adaugă metoda `_load_details_expanded_pref` și `_save_details_expanded_pref`**

În clasa `AgentApp`, undeva după `_make_theme_toggle_button`:

```python
    def _load_details_expanded_pref(self) -> bool:
        cfg = core.read_config()
        if not cfg.has_section("ui"):
            return False
        return cfg.getboolean("ui", "log_expanded", fallback=False)

    def _save_details_expanded_pref(self, expanded: bool) -> None:
        cfg = core.read_config()
        if not cfg.has_section("ui"):
            cfg.add_section("ui")
        cfg.set("ui", "log_expanded", "true" if expanded else "false")
        try:
            core.write_config(cfg)
        except OSError:
            pass
```

- [ ] **Step 3: Înlocuiește `_render_status_page` complet**

Localizează `def _render_status_page(self) -> None:` (~linia 647). Înlocuiește TOATĂ metoda + următoarele helpers (`_set_status_indicator`) cu:

```python
    def _render_status_page(self) -> None:
        p = self.theme.palette
        self._clear_root()

        wrap = ttk.Frame(self.root, style="TFrame", padding=(40, 20))
        wrap.pack(fill="both", expand=True)

        # Top-right: ⚙ + ☾
        toggle = self._make_theme_toggle_button(self.root)
        toggle.place(relx=1.0, x=-20, y=14, anchor="ne")

        settings = tk.Label(
            self.root, text="⚙",
            bg=p["surface"], fg=p["text_dim"],
            font=("Segoe UI", 13), width=2, cursor="hand2",
        )
        settings.place(relx=1.0, x=-56, y=14, anchor="ne")
        settings.bind("<Button-1>", lambda e: self._open_settings_menu(settings))
        settings.bind("<Enter>", lambda e: settings.configure(bg=p["elevated"]))
        settings.bind("<Leave>", lambda e: settings.configure(bg=p["surface"]))

        # Brand
        ttk.Label(wrap, text="VULNWATCH AGENT", style="Brand.TLabel").pack(anchor="w")

        # Status hero (dot + titlu + info-bar)
        try:
            api_base, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            self._render_login_page()
            return
        meta = core.get_enrollment_meta()
        device_name = meta.get("device_name") or device_uid
        user_email = meta.get("user_email") or "(unknown)"

        hero = ttk.Frame(wrap, style="TFrame")
        hero.pack(fill="x", pady=(10, 14))

        self._status_dot = tk.Canvas(hero, width=18, height=18,
                                     bg=p["bg"], highlightthickness=0)
        self._status_dot.pack(side="left", padx=(0, 14))

        hero_text = ttk.Frame(hero, style="TFrame")
        hero_text.pack(side="left", fill="x", expand=True)

        self._status_var = tk.StringVar(value="Pornesc daemon-ul...")
        ttk.Label(hero_text, textvariable=self._status_var,
                  style="Title.TLabel").pack(anchor="w")

        self._status_subline = tk.StringVar(
            value=f"{device_name}  ·  {user_email}  ·  ultim heartbeat —"
        )
        ttk.Label(hero_text, textvariable=self._status_subline,
                  style="Dim.TLabel", font=("Segoe UI", 10),
                  wraplength=540).pack(anchor="w", pady=(2, 0))

        # 3 metric cards
        metrics_row = tk.Frame(wrap, bg=p["bg"])
        metrics_row.pack(fill="x", pady=(0, 14))
        for col in range(3):
            metrics_row.columnconfigure(col, weight=1, uniform="metric")

        def metric_card(parent, value: str, label: str, col: int):
            card = tk.Frame(parent, bg=p["surface"], bd=0,
                            highlightthickness=1, highlightbackground=p["border"])
            card.grid(row=0, column=col, sticky="ew",
                      padx=(0 if col == 0 else 6, 6 if col < 2 else 0))
            tk.Label(card, text=value, bg=p["surface"], fg=p["accent"],
                     font=("Cambria", 22, "bold")).pack(pady=(10, 0))
            tk.Label(card, text=label, bg=p["surface"], fg=p["text_dim"],
                     font=("Segoe UI", 9)).pack(pady=(2, 10))

        m = self.metrics.state
        scans_val = str(m.get("scans_total", 0))
        score_val = (f"{m['last_exposure_score']}/100"
                     if m.get("last_exposure_score") is not None else "—")
        last_at_val = self._format_last_scan_time(m.get("last_scan_at"))

        metric_card(metrics_row, scans_val, "SCANĂRI", 0)
        metric_card(metrics_row, score_val, "ULTIMA EXPUNERE", 1)
        metric_card(metrics_row, last_at_val, "ULTIMA SCANARE", 2)

        # Action buttons
        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x", pady=(0, 12))

        ttk.Button(actions, text="Deschide dashboard",
                   style="Accent.TButton",
                   command=self._open_dashboard).pack(side="left", padx=(0, 8),
                                                      fill="x", expand=True)

        self._pause_btn = ttk.Button(actions, text="⏸ Pauză",
                                     style="Secondary.TButton",
                                     command=self._on_toggle_pause)
        self._pause_btn.pack(side="left")

        # Detalii expandabilă
        details_header = ttk.Frame(wrap, style="TFrame")
        details_header.pack(fill="x", pady=(8, 0))

        self._details_arrow = tk.StringVar(
            value="▾" if self._details_expanded else "▸"
        )
        arrow_lbl = tk.Label(details_header, textvariable=self._details_arrow,
                             bg=p["bg"], fg=p["accent"],
                             font=("Segoe UI", 10), cursor="hand2")
        arrow_lbl.pack(side="left", padx=(0, 4))
        det_lbl = tk.Label(details_header, text="Detalii și log activitate",
                           bg=p["bg"], fg=p["text_dim"],
                           font=("Segoe UI", 10), cursor="hand2")
        det_lbl.pack(side="left")

        arrow_lbl.bind("<Button-1>", lambda e: self._toggle_details_section())
        det_lbl.bind("<Button-1>", lambda e: self._toggle_details_section())

        # Container pentru detalii (afisat doar daca expanded)
        self._details_container = ttk.Frame(wrap, style="TFrame")
        if self._details_expanded:
            self._build_details_section(self._details_container)
        self._details_container.pack(fill="both", expand=self._details_expanded,
                                     pady=(8, 0))

        # Footer
        footer = ttk.Frame(self.root, style="TFrame")
        footer.place(relx=0.5, rely=1.0, y=-12, anchor="s")
        autostart_state = autostart.is_enabled()
        autostart_text = "activ ✓" if autostart_state else "dezactivat"
        ttk.Label(footer,
                  text=f"Pornește automat la logon: {autostart_text}  ·  v{core.AGENT_VERSION}",
                  style="Footer.TLabel").pack()

        # Start dot pulse + status refresh tick
        self._render_status_dot()
        self.root.after(2000, self._tick_status_refresh)

    def _format_last_scan_time(self, iso: str | None) -> str:
        """Formateaza timestamp ISO la 'HH:MM' (azi) sau 'DD lun HH:MM'."""
        if not iso:
            return "—"
        from datetime import datetime
        try:
            dt = datetime.fromisoformat(iso)
            now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
            if dt.date() == now.date():
                return dt.strftime("%H:%M")
            return dt.strftime("%d %b %H:%M")
        except (ValueError, TypeError):
            return "—"

    def _build_details_section(self, parent) -> None:
        """Construieste continutul sectiunii Detalii (log + info tehnice)."""
        p = self.theme.palette

        # Info tehnic compact
        try:
            api_base, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            return

        info_box = tk.Frame(parent, bg=p["surface"], bd=0,
                            highlightthickness=1, highlightbackground=p["border"])
        info_box.pack(fill="x", pady=(0, 8))
        tk.Label(info_box, text=f"UID tehnic: {device_uid}",
                 bg=p["surface"], fg=p["text_dim"],
                 font=("Consolas", 9)).pack(anchor="w", padx=10, pady=(8, 2))
        tk.Label(info_box, text=f"API: {api_base}",
                 bg=p["surface"], fg=p["text_dim"],
                 font=("Consolas", 9)).pack(anchor="w", padx=10, pady=(0, 8))

        # Log live
        ttk.Label(parent, text="ACTIVITATE", style="Dim.TLabel").pack(anchor="w",
                                                                       pady=(4, 4))

        log_frame = tk.Frame(parent, bg=p["surface"], bd=0,
                             highlightthickness=1, highlightbackground=p["border"])
        log_frame.pack(fill="both", expand=True)

        self._log_text = tk.Text(log_frame, bg=p["surface"], fg=p["text"],
                                 insertbackground=p["text"],
                                 font=("Consolas", 9), bd=0, padx=10, pady=8,
                                 wrap="word", state="disabled", height=8)
        self._log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_frame, orient="vertical",
                               command=self._log_text.yview)
        scroll.pack(side="right", fill="y")
        self._log_text.configure(yscrollcommand=scroll.set)
        for sev in SEVERITY_COLOR_KEYS:
            self._log_text.tag_configure(sev, foreground=severity_color(self.theme, sev))

    def _toggle_details_section(self) -> None:
        self._details_expanded = not self._details_expanded
        self._details_arrow.set("▾" if self._details_expanded else "▸")
        self._save_details_expanded_pref(self._details_expanded)
        # Re-render pagina pentru a reflecta colapsarea / expanderea
        self._render_status_page()

    def _render_status_dot(self) -> None:
        """Deseneaza dot-ul cu culoare + glow in functie de status_state."""
        p = self.theme.palette
        color_map = {
            "online":    p["green"],
            "degraded":  p["amber"],
            "offline":   p["red"],
            "paused":    p["text_muted"],
            "starting":  p["amber"],
        }
        color = color_map.get(self._status_state, p["text_muted"])

        if not hasattr(self, "_status_dot"):
            return
        self._status_dot.delete("all")
        # Glow exterior (doar online)
        if self._status_state == "online":
            self._status_dot.create_oval(0, 0, 18, 18, fill=color, outline="",
                                         stipple="gray50")
        self._status_dot.create_oval(4, 4, 14, 14, fill=color, outline="")

    def _tick_status_refresh(self) -> None:
        """Apelat la 2s: actualizeaza dot status + subline pe baza ultimului heartbeat."""
        import time as _t
        if not hasattr(self, "_status_dot"):
            return

        if self.daemon.is_paused():
            new_state = "paused"
            txt = "În pauză"
        elif not self.daemon.is_running():
            new_state = "starting"
            txt = "Pornesc daemon-ul..."
        elif self._last_heartbeat_ts == 0.0:
            new_state = "starting"
            txt = "Pornesc daemon-ul..."
        else:
            age = _t.time() - self._last_heartbeat_ts
            if age <= 15:
                new_state = "online"
                txt = "Activ și conectat"
            elif age <= 60:
                new_state = "degraded"
                txt = "Conexiune intermitentă"
            else:
                new_state = "offline"
                txt = "Fără conexiune cu serverul"

        self._status_state = new_state
        self._status_var.set(txt)

        # Subline update
        try:
            _, device_uid, _ = core.get_enrollment()
        except RuntimeError:
            device_uid = "—"
        meta = core.get_enrollment_meta()
        device_name = meta.get("device_name") or device_uid
        user_email = meta.get("user_email") or "(unknown)"

        if self._last_heartbeat_ts == 0:
            hb_txt = "—"
        else:
            age = int(_t.time() - self._last_heartbeat_ts)
            if age < 60:
                hb_txt = f"acum {age}s"
            else:
                hb_txt = f"acum {age // 60} min"

        self._status_subline.set(
            f"{device_name}  ·  {user_email}  ·  ultim heartbeat {hb_txt}"
        )

        self._render_status_dot()
        self.root.after(2000, self._tick_status_refresh)
```

- [ ] **Step 4: Modifică `DaemonRunner` să raporteze heartbeat success înapoi**

În clasa `DaemonRunner.__init__`, adaugă:

```python
        self.last_heartbeat_ts: float = 0.0  # actualizat de daemon thread
```

În `daemon_loop` (în `core.py`), trebuie să updatăm o referință externă. Cea mai simpla soluție: trecem o callable `on_heartbeat_ok` ca parameter.

Modifică `agent/core.py`, în signatura `daemon_loop` (~linia 587), adaugă parameter nou:

```python
def daemon_loop(
    api_base: str, device_uid: str, device_token: str,
    *,
    poll_interval: int = 3,
    heartbeat_interval: int = 10,
    auto_interval: int = 0,
    log: LogFn = _noop_log,
    should_stop: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
    on_token_invalid: Callable[[], None] | None = None,
    on_heartbeat_ok: Callable[[], None] | None = None,
    on_scan_done: Callable[[int, str, int], None] | None = None,
) -> None:
```

În blockul de heartbeat success (după `api_heartbeat(api_base, device_token, ...)` linia ~621), adaugă:

```python
            try:
                api_heartbeat(api_base, device_token, AGENT_VERSION, capabilities, os_version)
                if on_heartbeat_ok:
                    on_heartbeat_ok()  # NOU
            except DeviceTokenInvalidError as e:
                _handle_token_invalid(e)
                return
            except ApiError as e:
                log(f"[{_ts()}] Heartbeat esuat (continui): {e}", "warn")
            last_heartbeat = now
```

Modifică `run_one_job` (~linia 555). Caută blockul după `result = api_submit_job_result(...)` (~linia 569):

```python
        result = api_submit_job_result(api_base, device_token, job_id, data)
        score = result.get("exposure_score")
        scan_id = result.get("scan_id")
        log(f"[{_ts()}] Job #{job_id} done ({scan_type}). Scan #{scan_id}, score {score}/100.", "ok")
```

Adaugă DUPĂ aceste linii, dar înainte de `except`:

```python
        # NOU: notifica metrics tracker
        if on_scan_done and score is not None:
            try:
                on_scan_done(int(score), scan_type, int(job_id))
            except Exception:
                pass
```

PROBLEMĂ: `run_one_job` nu primește `on_scan_done` ca parameter în prezent. Modifică signatura `run_one_job`:

```python
def run_one_job(api_base: str, device_uid: str, device_token: str,
                job: dict, log: LogFn = _noop_log,
                on_scan_done: Callable[[int, str, int], None] | None = None) -> None:
```

În `daemon_loop` (~linia 633), apelul `run_one_job(...)`:

```python
        if job is not None:
            try:
                run_one_job(api_base, device_uid, device_token, job, log=log,
                            on_scan_done=on_scan_done)
            except DeviceTokenInvalidError as e:
                _handle_token_invalid(e)
                return
            continue
```

- [ ] **Step 5: Conectează `DaemonRunner` la noile callbacks**

În `gui.py`, clasa `DaemonRunner`, modifică `_run`:

```python
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
                on_heartbeat_ok=self._on_heartbeat_ok,
                on_scan_done=self._on_scan_done,
            )
        finally:
            self._emit("Daemon oprit.", "info")

    def _on_heartbeat_ok(self) -> None:
        import time as _t
        self.last_heartbeat_ts = _t.time()

    def _on_scan_done(self, score: int, scan_type: str, job_id: int) -> None:
        try:
            self.log_queue.put_nowait(("__SCAN_DONE__", f"{score}|{scan_type}|{job_id}"))
        except queue.Full:
            pass
```

- [ ] **Step 6: În `AgentApp._poll_log_queue`, interceptează `__SCAN_DONE__`**

Localizează `_poll_log_queue` (~linia 823). Înlocuiește cu:

```python
    def _poll_log_queue(self) -> None:
        try:
            while True:
                msg, sev = self.log_queue.get_nowait()
                if msg == "__TOKEN_INVALID__":
                    self._handle_token_invalid()
                    return
                if msg == "__SCAN_DONE__":
                    # sev contine "score|scan_type|job_id"
                    try:
                        score_s, scan_type, job_id_s = sev.split("|")
                        self.metrics.record_scan(int(score_s), scan_type, int(job_id_s))
                        # Re-render Status doar daca suntem acolo
                        if core.is_enrolled():
                            self._render_status_page()
                    except (ValueError, AttributeError):
                        pass
                    continue
                self._append_log(msg, sev)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_log_queue)
```

- [ ] **Step 7: În `AgentApp._auto_start_daemon`, citește `last_heartbeat_ts` din daemon**

Conectează heartbeat-ul DaemonRunner cu state-ul AgentApp. Cea mai simplă: AgentApp citește `self.daemon.last_heartbeat_ts` în `_tick_status_refresh`. Modifică `_tick_status_refresh` să folosească asta:

În `_tick_status_refresh`, înlocuiește prima linie după `import time as _t`:

```python
        if not hasattr(self, "_status_dot"):
            return

        # Sincronizeaza cu daemon thread
        self._last_heartbeat_ts = self.daemon.last_heartbeat_ts

        if self.daemon.is_paused():
            ...
```

- [ ] **Step 8: Smoke test**

```bash
cd agent
PYTHONUTF8=1 ../server/.venv/Scripts/python scan.py gui
```

Logare → enroll → ar trebui să vezi Status page cu:
- Dot care își schimbă culoarea (galben → verde după ~10s primul heartbeat)
- 3 carduri metrici cu 0 scanări inițial
- Buton „Deschide dashboard" + „⏸ Pauză"
- „▸ Detalii și log activitate" colapsat default (click expand)

Forțează o scanare din UI web (`/devices` → „Scanează acum") → după finalizare, contorul SCANĂRI ar trebui să devină 1.

Închide cu Alt+F4.

- [ ] **Step 9: Run all tests**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/ -v 2>&1 | tail -3
```
Expected: PASS — 47 teste.

- [ ] **Step 10: Commit**

```bash
git add agent/gui.py agent/core.py
git commit -m "feat(agent/gui): Status regandit cu dot 5 stari + 3 metrici + Detalii expandabila"
```

---

## Task 6: Modale (API URL editor, Despre) + Meniu ⚙

**Files:**
- Modify: `agent/gui.py` — adaugă metode `_open_settings_menu`, `_open_about_dialog`, înlocuiește `_open_api_url_modal` stub-ul cu versiune completă, adaugă `_on_change_account`, `_on_disconnect_pc`

- [ ] **Step 1: Înlocuiește `_open_api_url_modal` (stub din Task 3) cu versiune completă**

Localizează metoda stub `_open_api_url_modal` din Task 3 și înlocuieste-o cu:

```python
    def _open_api_url_modal(self) -> None:
        """Modal pentru editare API URL — fereastra Toplevel cu input + butoane."""
        p = self.theme.palette
        modal = tk.Toplevel(self.root)
        modal.title("Setări avansate")
        modal.configure(bg=p["bg"])
        modal.geometry("440x220")
        modal.resizable(False, False)
        modal.transient(self.root)
        modal.grab_set()

        # Centreaza pe parent
        modal.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - 440) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - 220) // 2
        modal.geometry(f"+{x}+{y}")

        wrap = ttk.Frame(modal, style="TFrame", padding=20)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="API URL backend VulnWatch",
                  style="Title.TLabel", font=("Cambria", 14, "bold")).pack(anchor="w")
        ttk.Label(wrap, text="Modifică doar dacă știi ce faci.",
                  style="Subtitle.TLabel", font=("Segoe UI", 10),
                  wraplength=400).pack(anchor="w", pady=(2, 12))

        ttk.Label(wrap, text="URL", style="Dim.TLabel").pack(anchor="w")
        var = tk.StringVar(value=self._var_api.get() if hasattr(self, "_var_api")
                           else core.DEFAULT_API_BASE)
        entry = ttk.Entry(wrap, textvariable=var, font=("Segoe UI", 11))
        entry.pack(fill="x", pady=(2, 14))
        entry.focus_set()
        entry.select_range(0, "end")

        actions = ttk.Frame(wrap, style="TFrame")
        actions.pack(fill="x")

        def on_save():
            new_url = var.get().strip().rstrip("/")
            if new_url:
                if hasattr(self, "_var_api"):
                    self._var_api.set(new_url)
                    self._refresh_api_short()
            modal.destroy()

        def on_reset():
            var.set(core.DEFAULT_API_BASE)

        ttk.Button(actions, text="Salvează", style="Accent.TButton",
                   command=on_save).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Anulează", style="Secondary.TButton",
                   command=modal.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Revino la default", style="Link.TButton",
                   command=on_reset).pack(side="right")

        modal.bind("<Return>", lambda e: on_save())
        modal.bind("<Escape>", lambda e: modal.destroy())
```

- [ ] **Step 2: Adaugă `_open_about_dialog`**

În `AgentApp`:

```python
    def _open_about_dialog(self) -> None:
        """Modal Despre — versiune + link dashboard + scurta descriere."""
        p = self.theme.palette
        modal = tk.Toplevel(self.root)
        modal.title("Despre VulnWatch Agent")
        modal.configure(bg=p["bg"])
        modal.geometry("420x280")
        modal.resizable(False, False)
        modal.transient(self.root)
        modal.grab_set()

        modal.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - 420) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - 280) // 2
        modal.geometry(f"+{x}+{y}")

        wrap = ttk.Frame(modal, style="TFrame", padding=24)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="VULNWATCH AGENT",
                  style="Brand.TLabel").pack(anchor="w")
        ttk.Label(wrap, text=f"versiunea {core.AGENT_VERSION}",
                  style="Title.TLabel", font=("Cambria", 18, "bold")).pack(anchor="w",
                                                                            pady=(4, 12))
        ttk.Label(wrap, text=(
            "VulnWatch monitorizează expunerea de securitate a acestui PC "
            "și raportează rezultatele într-un dashboard web.\n\n"
            "Scanările se inițiază din platforma web — acest agent rulează "
            "în fundal și execută jobs."
        ), style="Subtitle.TLabel", wraplength=370, justify="left",
           font=("Segoe UI", 10)).pack(anchor="w")

        ttk.Button(wrap, text="Închide", style="Secondary.TButton",
                   command=modal.destroy).pack(side="right", pady=(16, 0))
        modal.bind("<Escape>", lambda e: modal.destroy())
```

- [ ] **Step 3: Adaugă `_open_settings_menu`**

```python
    def _open_settings_menu(self, anchor_widget) -> None:
        """Menu drop-down de la iconita ⚙ — afiseaza actiuni rar folosite."""
        p = self.theme.palette
        m = tk.Menu(self.root, tearoff=0,
                    bg=p["surface"], fg=p["text"],
                    activebackground=p["elevated"], activeforeground=p["accent"],
                    bd=1, font=("Segoe UI", 10))

        # Toggle autostart
        autostart_on = autostart.is_enabled()
        m.add_command(
            label=("✓ Pornește la logon" if autostart_on else "  Pornește la logon"),
            command=self._on_toggle_autostart,
        )
        m.add_separator()

        m.add_command(label="Schimbă cont", command=self._on_change_account)
        m.add_command(label="Deconectează acest PC", command=self._on_disconnect_pc)
        m.add_separator()

        m.add_command(label="Setări avansate API URL...",
                      command=self._open_api_url_modal)
        m.add_command(label="Despre VulnWatch Agent",
                      command=self._open_about_dialog)

        # Pozitionare sub iconita ⚙
        x = anchor_widget.winfo_rootx()
        y = anchor_widget.winfo_rooty() + anchor_widget.winfo_height()
        try:
            m.tk_popup(x, y)
        finally:
            m.grab_release()
```

- [ ] **Step 4: Modifică `_on_toggle_autostart` să nu mai depindă de `_autostart_var`**

Localizează `_on_toggle_autostart` (~linia 788). Înlocuiește cu:

```python
    def _on_toggle_autostart(self) -> None:
        """Toggle autostart — invocat din meniul ⚙."""
        if autostart.is_enabled():
            ok, msg = autostart.disable()
        else:
            ok, msg = autostart.enable()
        self._append_log(msg, "ok" if ok else "error")
        # Re-render Status ca sa apara starea actualizata in footer
        if core.is_enrolled():
            self._render_status_page()
```

- [ ] **Step 5: Adaugă `_on_change_account` și `_on_disconnect_pc`**

Caută `_on_logout` (~linia 795). Înlocuieste cu:

```python
    def _on_change_account(self) -> None:
        """'Schimba cont' — sterge configul local, pastreaza device pe contul vechi."""
        prev_email = core.get_enrollment_meta().get("user_email", "?")
        if not messagebox.askyesno(
            "Schimbă cont",
            f"Vei fi delogat de pe acest PC.\n\n"
            f"Device-ul rămâne pe contul tău ({prev_email}) și-l poți reactiva "
            f"oricând cu același cont.\n\n"
            f"Continui?",
        ):
            return
        self._terminate_session_and_return_to_login(reset_metrics=False)

    def _on_disconnect_pc(self) -> None:
        """'Deconecteaza acest PC' — sterge configul + reseteaza metricile.
        Backend-ul nu sterge inca device-ul automat (backlog: endpoint dedicat).
        Afisam user-ului instructiune sa-l elimine manual din UI web."""
        if not messagebox.askyesno(
            "Deconectează acest PC",
            "Acest PC nu va mai trimite scanări către contul tău.\n\n"
            "Notă: device-ul va rămâne listat în dashboard web până când îl "
            "ștergi manual de acolo. Pentru a-l elimina complet, mergi la "
            "Dashboard → Devices → Șterge.\n\n"
            "Continui?",
        ):
            return
        self._terminate_session_and_return_to_login(reset_metrics=True)

    def _terminate_session_and_return_to_login(self, reset_metrics: bool) -> None:
        """Helper comun: opreste daemon + tray, sterge config, revine la Login."""
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

        if reset_metrics and hasattr(self, "metrics"):
            self.metrics.reset()

        core.clear_config()
        self._render_login_page()
```

- [ ] **Step 6: Asigură-te că `_handle_token_invalid` rămâne functional**

`_handle_token_invalid` rămâne neschimbată — ea apelează `core.clear_config()` și `_render_login_page()`. Nu trebuie modificată.

Verifică:
```bash
grep -n "def _handle_token_invalid" agent/gui.py
```
Expected: o singură ocurență, intactă.

- [ ] **Step 7: Smoke test integral**

```bash
cd agent
PYTHONUTF8=1 ../server/.venv/Scripts/python scan.py gui
```

Login → enroll → Status. Click ⚙ → vezi meniu cu „Pornește la logon" (cu ✓ sau fără), „Schimbă cont", „Deconectează acest PC", „Setări avansate API URL...", „Despre".
- Toggle autostart → footer status actualizat
- Despre → modal cu versiune + descriere
- Setări API → modal cu URL editor
- Schimbă cont → confirm → revine la Login (metrici păstrate)
- Deconectează PC → confirm cu warning → revine la Login + metrici resetate

- [ ] **Step 8: Commit**

```bash
git add agent/gui.py
git commit -m "feat(agent/gui): meniu setari + modale (API URL editor, Despre)"
```

---

## Task 7: Memory.md updates + smoke testing checklist

**Files:**
- Modify: `agent/memory.md`
- Modify: `agent/tests/memory.md`

- [ ] **Step 1: Update `agent/memory.md`**

Localizează tabelul `## Fisiere`. Înlocuieste rândul pentru `gui.py`:

```markdown
| `gui.py`                   | **Interfata Tkinter regandita cu paleta Honey & Plum (dark + light, toggle persistat).** 3 pagini: **Login** (Google button outlined + email/parola + toggle Register + footer API URL ✎ + theme toggle ☾/☀), **Enroll consolidat** (sub-stari `new device` vs `relink` in aceeasi pagina, banner contextual cand exista UID), **Status** (status dot 5 stari `online/degraded/offline/paused/starting` cu glow live + 3 metric cards `SCANĂRI/ULTIMA EXPUNERE/ULTIMA SCANARE` + sectiune Detalii expandabila + meniu ⚙ cu Schimbă cont / Deconectează acest PC / Setări avansate API / Despre). Helpers: `ThemeManager` (toggle + persist), `_make_theme_toggle_button`, `_tick_status_refresh` (refresh la 2s). Google login flow async pe thread separat ca inainte. Daemon ruleaza pe thread separat (`DaemonRunner`) cu callbacks `on_heartbeat_ok` + `on_scan_done` pentru live metrics. |
```

Localizează secțiunea `## Configul local` și înlocuieste-o cu:

```markdown
## Configul local

Stocat la `~/.vulnwatch/config.ini` (creat automat dupa enrollment, permisiuni
0600 pe POSIX). Sectiunile:

- `[agent]` — credentials + identitate device:
  - `api_base` — URL backend
  - `device_uid` — identificator tehnic stabil
  - `device_token` — tokenul plain (generat local; vezi spec client-side tokens)
  - `device_name` (optional) — nume afisabil
  - `user_email` (optional) — email user
- `[ui]` — preferinte UI:
  - `theme` — `dark` (default) sau `light`
  - `log_expanded` — `true` sau `false` (state colapsare sectiunea Detalii)

## Cache metrici (`~/.vulnwatch/metrics.json`)

Fisier separat cu istoricul ultimelor 20 scanari + counters lifetime. Managed
prin clasa `MetricsTracker` din `core.py`. Scriere atomica (write-to-temp →
rename) pentru a evita corupere. Citire defensiva: JSON corupt → state gol +
log warn, fara crash. Reset doar la „Deconecteaza acest PC" (nu la „Schimba
cont", pentru ca istoria apartine device-ului, nu user-ului).
```

- [ ] **Step 2: Update `agent/tests/memory.md`**

Localizează tabelul de fișiere. Adaugă rând nou:

```markdown
| `test_metrics_tracker.py` | 5 teste pentru `MetricsTracker`: state gol cand fisier lipseste, `record_scan` persista atomic, history capped la 20, JSON corupt fallback la state gol, `reset()` sterge fisier. Logica pura — fara network sau UI. |
```

În descrierea finală despre numărul total de teste, actualizează numărul (era 32 sau 39, acum trebuie să fie 47).

- [ ] **Step 3: Smoke testing checklist (manual)**

Rulează manual și marchează rezultatul:

```
[ ] 1. Pornire fresh: stergere ~/.vulnwatch/* + lansare scan.py gui →
       fereastra deschide, pagina Login afisata, fundal plum.

[ ] 2. Login email/parola: introdu test@test.com / testtest123 →
       Autentificare → trece la Enroll page.

[ ] 3. Login Google: click „Continua cu Google" → consimtamant → revine
       direct la Status page (skip enroll pentru ca enrollment-ul Google
       e atomic).

[ ] 4. Toggle Register pe Login: click „Inregistreaza-te" → titlu si
       buton se schimba; revert „Autentifica-te" funcționează.

[ ] 5. Theme toggle ☾/☀: click pe iconita dreapta-sus → toate culorile
       comuta; restart aplicatie → tema persista.

[ ] 6. API URL footer ✎: click ✎ → modal cu URL editor + Salveaza /
       Anuleaza / Revino la default; Save persista valoarea pana la
       proxima editare.

[ ] 7. Enroll new device: pe un PC neenrollat, vezi card sistem + UID
       tehnic + link [Schimbă]; submit „Conectează" → trece la Status.

[ ] 8. Enroll re-link: dupa stergere ~/.vulnwatch/config.ini cu device
       existent pe cont, login → vezi banner ⚠ portocaliu cu numele
       device-ului existent + buton „Refoloseste înregistrarea"; link
       discret „Vrei să-l înregistrezi ca PC nou? →" jos.

[ ] 9. Status dot online: dupa enroll, asteapta ~10s → dot devine verde
       cu glow + text „Activ și conectat" + subline cu „ultim heartbeat
       acum Xs".

[ ] 10. Status dot offline: opreste backend (docker compose stop db) →
        dupa 60s dot devine roz „Fara conexiune cu serverul".

[ ] 11. Status dot pauza: click „⏸ Pauză" → dot devine gri, text „În
        pauză", buton schimba in „▶ Reia".

[ ] 12. Metrici cresc dupa scan: porneste backend, fortteaza scan din
        UI web → dupa terminare, contorul SCANĂRI creste cu 1, ULTIMA
        EXPUNERE arata scorul, ULTIMA SCANARE arata ora.

[ ] 13. Detalii expandabila: click „▸ Detalii" → expandeaza cu UID +
        API + log live; click din nou → colapseaza; restart aplicatie →
        state persistat.

[ ] 14. Meniu ⚙ → toggle autostart: click „Pornește la logon" →
        registry HKCU schimba; footer reflecta starea.

[ ] 15. Meniu ⚙ → Schimba cont: confirm dialog cu mesaj despre
        device pastrat pe cont; OK → revine la Login + metricile
        păstrate pe disk.

[ ] 16. Meniu ⚙ → Deconecteaza acest PC: confirm cu warning despre
        stergere manuala din UI web; OK → revine la Login + metricile
        resetate (metrics.json lipseste).

[ ] 17. Meniu ⚙ → Despre: modal cu titlu, versiune, descriere; Esc /
        Inchide functioneaza.

[ ] 18. 401 recovery: cu daemon pornit, sterge device din UI web →
        in max 15s UI sare la Login cu mesajul „Conexiunea cu platforma
        a expirat..." + tema păstrată.

[ ] 19. Light mode parity: dupa toggle la light, verifica:
        - input borders vizibile (nu se „pierd" pe bg)
        - brand label honey vizibil pe cream
        - footer text muted lizibil
        - submit honey button cu text plum lizibil

[ ] 20. Restart cu metrici existente: dupa cateva scanari, restart
        executabil → metricile reapar corect (scans_total, last_*).
```

- [ ] **Step 4: Run all tests final**

```bash
PYTHONUTF8=1 server/.venv/Scripts/python -m pytest agent/tests/ server/tests/ --ignore=server/tests/test_google_auth.py 2>&1 | tail -3
```
Expected: PASS — 47 (agent) + 102 (server) = 149 teste.

- [ ] **Step 5: Commit**

```bash
git add agent/memory.md agent/tests/memory.md
git commit -m "docs(agent): memory.md reflecta GUI redesign + cache metrici"
```

---

## Self-Review checklist

După parcurgerea task-urilor 1-7, verifică:

- [ ] **Toate testele trec**: `pytest agent/tests/ server/tests/ --ignore=server/tests/test_google_auth.py` → 0 failures
- [ ] **Niciun fișier backend nu a fost atins**: `git diff main --stat -- server/app/` → empty
- [ ] **Frontend web nu a fost atins**: `git diff main --stat -- web/` → empty
- [ ] **GUI smoke test pe live system**: cele 20 puncte din Task 7 Step 3 toate ✓
- [ ] **`metrics.json` apare în config dir**: după prima scanare, `cat ~/.vulnwatch/metrics.json` valid JSON cu cheile așteptate
- [ ] **Theme persist**: după restart, tema (dark / light) se păstrează
- [ ] **Detalii state persist**: după restart, secțiunea Detalii colapsată / expandată se păstrează
- [ ] **Niciun `Co-Authored-By: Claude`** în commits

---

**Plan complete. 7 task-uri cu pași codificați, fără placeholder-uri. Cache metrici scrise primul (Task 1 cu unit tests), apoi theme system foundation (Task 2), apoi 3 pagini secvențial (Task 3-5), apoi modale/meniu (Task 6), apoi docs + smoke (Task 7).**
