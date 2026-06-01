"""
System tray icon pentru daemon. Foloseste `pystray` + `Pillow`.

API public:
    TrayController(state).start()   → porneste icon-ul intr-un thread
                                      separat. Idempotent.
    controller.update_status(text)  → schimba tooltip-ul
    controller.stop()               → opreste icon-ul

`state` este un obiect cu atributele:
    paused: bool
    on_open_dashboard(): None    deschide UI in browser
    on_quit(): None              opreste daemon-ul + iesire
"""

from __future__ import annotations

import threading
import webbrowser
from dataclasses import dataclass, field
from typing import Callable

try:
    import pystray
    from PIL import Image, ImageDraw
    _AVAILABLE = True
except ImportError:
    pystray = None  # type: ignore[assignment]
    Image = None    # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    _AVAILABLE = False


def is_available() -> bool:
    """True daca pystray + Pillow sunt disponibile."""
    return _AVAILABLE


@dataclass
class TrayState:
    """Starea expusa tray-ului. Scrieri din thread-ul GUI/daemon."""
    paused: bool = False
    tooltip: str = "VulnWatch Agent"
    on_open_dashboard: Callable[[], None] = lambda: webbrowser.open("http://localhost:5173")
    on_toggle_pause: Callable[[], None] = lambda: None
    on_quit: Callable[[], None] = lambda: None
    _lock: threading.Lock = field(default_factory=threading.Lock)


def _safe_title(text: str) -> str:
    """Coerce titlul tray la latin-1 (backend-ul pystray X11/Xlib codeaza titlul
    ferestrei ca latin-1 si crapa pe caractere non-latin1 ex. em-dash U+2014).

    Inlocuim cateva caractere uzuale cu echivalent ASCII, apoi pierdem orice
    ramane in afara latin-1 (replace), ca sa nu crape niciodata callback-ul GUI.
    """
    if not text:
        return ""
    repl = {"—": "-", "–": "-", "‘": "'", "’": "'",
            "“": '"', "”": '"', "…": "...", " ": " "}
    for k, v in repl.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


def _make_icon_image(paused: bool) -> "Image.Image":
    """Genereaza un icon 64x64 (scut). Verde = activ, gri = pauza."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = (107, 114, 128, 255) if paused else (74, 222, 128, 255)
    # Forma de scut stilizata
    draw.polygon([(32, 4), (60, 16), (60, 36), (32, 60), (4, 36), (4, 16)],
                 fill=color)
    # Litera V in interior
    draw.line([(20, 20), (32, 48), (44, 20)], fill=(2, 16, 24, 255), width=4)
    return img


class TrayController:
    """Wrapper peste pystray.Icon, ruleaza pe thread separat."""

    def __init__(self, state: TrayState):
        if not _AVAILABLE:
            raise RuntimeError("pystray sau Pillow lipsesc")
        self.state = state
        self._icon: "pystray.Icon | None" = None
        self._thread: threading.Thread | None = None

    def _build_menu(self) -> "pystray.Menu":
        def open_dashboard(_icon, _item):
            self.state.on_open_dashboard()

        def toggle_pause(_icon, _item):
            self.state.on_toggle_pause()
            self._refresh_icon()

        def quit_agent(_icon, _item):
            self.state.on_quit()
            self.stop()

        return pystray.Menu(
            pystray.MenuItem("Deschide dashboard", open_dashboard, default=True),
            pystray.MenuItem(
                lambda _: "Pornește scanări" if self.state.paused else "Pauză",
                toggle_pause,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Iesire", quit_agent),
        )

    def _refresh_icon(self) -> None:
        if not self._icon:
            return
        self._icon.icon = _make_icon_image(self.state.paused)
        self._icon.title = _safe_title(self.state.tooltip)

    def update_tooltip(self, text: str) -> None:
        self.state.tooltip = text
        if self._icon:
            self._icon.title = _safe_title(text)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._icon = pystray.Icon(
            "vulnwatch",
            icon=_make_icon_image(self.state.paused),
            title=self.state.tooltip,
            menu=self._build_menu(),
        )
        self._thread = threading.Thread(target=self._icon.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
            self._icon = None
