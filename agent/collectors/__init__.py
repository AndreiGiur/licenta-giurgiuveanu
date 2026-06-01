"""Modul de colectori composabili. Fiecare colector primeste un ScanProfile
si returneaza datele relevante pentru nivelul curent."""
from .forensics import collect_forensics
from .linux_audit import collect_linux_audit
from .network import collect_network
from .persistence import collect_persistence
from .processes import collect_processes
from .software import collect_software
from .system_info import collect_system

__all__ = [
    "collect_network",
    "collect_processes",
    "collect_software",
    "collect_system",
    "collect_persistence",
    "collect_forensics",
    "collect_linux_audit",
]
