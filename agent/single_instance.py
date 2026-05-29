"""Single-instance guard pentru agentul VulnWatch.

Scop: impiedica rularea simultana a mai multor instante GUI (ex: dublu-click
repetat pe VulnWatchAgent.exe). A doua instanta detecteaza ca prima ruleaza
si iese fara sa porneasca o a doua fereastra / un al doilea daemon.

Doua strategii, alese automat:
  1. Named mutex Windows (pywin32) — kernel-managed, eliberat automat cand
     procesul moare (inclusiv la crash). Calea preferata in .exe.
  2. Fallback lock-file cu lock exclusiv la nivel de OS (msvcrt pe Windows fara
     pywin32, fcntl pe POSIX) — eliberat cand handle-ul se inchide la moartea
     procesului. Folosit in dev / pe Linux (teste CI).

API:
    guard = SingleInstance("VulnWatchAgent")
    if not guard.acquire():
        # alta instanta ruleaza deja
        ...
    # tine `guard` viu pe toata durata procesului; release() la iesire
    guard.release()

Sau ca context manager:
    with SingleInstance("VulnWatchAgent") as guard:
        if guard.acquired:
            ...
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

# pywin32 — doar pe Windows. Degradeaza gracefully cand lipseste.
try:
    import win32event
    import win32api
    import winerror
    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False

# Lock primitives pentru fallback
try:
    import msvcrt  # Windows
    _HAS_MSVCRT = True
except ImportError:
    _HAS_MSVCRT = False

try:
    import fcntl  # POSIX
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False


DEFAULT_LOCK_NAME = "VulnWatchAgent"


def _lock_file_path(name: str) -> Path:
    """Calea fisierului de lock pentru strategia fallback (per-user)."""
    base = Path(tempfile.gettempdir())
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_"))
    return base / f"{safe}.lock"


class SingleInstance:
    """Garda de instanta unica. `acquire()` intoarce True daca am obtinut
    lock-ul (suntem prima instanta), False daca alta instanta il detine deja."""

    def __init__(self, name: str = DEFAULT_LOCK_NAME):
        self.name = name
        self.acquired = False
        # Handle-uri interne, in functie de strategie
        self._mutex = None
        self._lock_fh = None

    # ── API public ──────────────────────────────────────────────────────────

    def acquire(self) -> bool:
        """Incearca sa obtina lock-ul. Idempotent: a doua chemare pe acelasi
        obiect intoarce starea curenta."""
        if self.acquired:
            return True
        if _PYWIN32_AVAILABLE:
            return self._acquire_mutex()
        return self._acquire_file()

    def release(self) -> None:
        """Elibereaza lock-ul (no-op daca nu il detinem)."""
        if self._mutex is not None:
            # Detectia se bazeaza pe existenta obiectului named mutex (cat timp
            # un handle ramane deschis). Nu detinem ownership (bInitialOwner=
            # False), deci e suficient CloseHandle — la inchidere kernel-ul
            # elibereaza named object-ul daca eram ultimul handle.
            try:
                win32api.CloseHandle(self._mutex)
            except Exception:
                pass
            self._mutex = None
        if self._lock_fh is not None:
            try:
                self._unlock_file(self._lock_fh)
            except Exception:
                pass
            try:
                self._lock_fh.close()
            except Exception:
                pass
            self._lock_fh = None
        self.acquired = False

    def __enter__(self) -> "SingleInstance":
        self.acquire()
        return self

    def __exit__(self, *_exc) -> None:
        self.release()

    # ── Strategia 1: Named mutex (Windows + pywin32) ─────────────────────────

    def _acquire_mutex(self) -> bool:
        # Namespace per-sesiune (nu "Global\\") — un user nu blocheaza alt user.
        mutex_name = f"VulnWatch_{self.name}_singleton"
        self._mutex = win32event.CreateMutex(None, False, mutex_name)
        last_error = win32api.GetLastError()
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            # Mutex-ul exista deja → alta instanta ruleaza. Inchidem handle-ul
            # nostru (nu detinem ownership-ul) si raportam esec.
            try:
                win32api.CloseHandle(self._mutex)
            except Exception:
                pass
            self._mutex = None
            self.acquired = False
            return False
        self.acquired = True
        return True

    # ── Strategia 2: Lock-file (fallback cross-platform) ─────────────────────

    def _acquire_file(self) -> bool:
        path = _lock_file_path(self.name)
        try:
            # Deschidem (sau cream) fisierul si incercam lock exclusiv non-blocant.
            fh = open(path, "a+")
        except OSError:
            # Daca nu putem nici macar deschide fisierul, presupunem ca putem rula
            # (mai bine fals-pozitiv decat sa blocam complet agentul).
            self.acquired = True
            return True
        try:
            self._lock_exclusive(fh)
        except OSError:
            # Lock detinut de alta instanta
            try:
                fh.close()
            except Exception:
                pass
            self.acquired = False
            return False
        # Avem lock-ul — scriem PID-ul pentru diagnostic
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(str(os.getpid()))
            fh.flush()
        except OSError:
            pass
        self._lock_fh = fh
        self.acquired = True
        return True

    @staticmethod
    def _lock_exclusive(fh) -> None:
        """Lock exclusiv non-blocant. Ridica OSError daca e deja detinut."""
        if _HAS_FCNTL:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif _HAS_MSVCRT:
            # msvcrt blocheaza pe byte range; lock-uim 1 byte de la pozitia 0.
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            # Fara primitiva de lock — nu putem garanta, presupunem succes.
            return

    @staticmethod
    def _unlock_file(fh) -> None:
        if _HAS_FCNTL:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        elif _HAS_MSVCRT:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
