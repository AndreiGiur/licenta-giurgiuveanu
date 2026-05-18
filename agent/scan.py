#!/usr/bin/env python3
"""
VulnWatch Agent — entry point.

Comportament la rulare:
- Cu argumente (subcomenzi)  → modul CLI clasic.
- Fara argumente             → deschide GUI (Tkinter).
                              Util pentru dublu-click pe `scan.py` / `.exe`.

Subcomenzi:
    enroll     Inrolare interactiva sau prin flag-uri.
    scan       Push direct: o scanare unica (fara daemon).
    daemon     Foreground; proceseaza joburile cerute din UI.
    gui        Forteaza modul grafic.
    autostart  Inregistreaza/dezinregistreaza pornirea automata la logon.
    status     Afiseaza configul (fara token).
    logout     Sterge configul local.
"""

from __future__ import annotations

import argparse
import getpass
import platform
import socket
import sys
from datetime import datetime

# Importurile relative functioneaza si din PyInstaller bundle ("agent" e package).
try:
    from . import core
except ImportError:  # rulat ca script: `python scan.py`
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
    from agent import core  # type: ignore[no-redef]


def _print_log(msg: str, severity: str = "info") -> None:
    print(msg)


# ── Subcomenzi CLI ────────────────────────────────────────────────────────────

def cmd_enroll(args: argparse.Namespace) -> int:
    api_base = (args.api or core.DEFAULT_API_BASE).rstrip("/")

    print("=" * 60)
    print(" VulnWatch — inrolare dispozitiv")
    print("=" * 60)
    print(f" API: {api_base}")
    print()

    email = (args.email or input("Email: ")).strip().lower()
    password = args.password or getpass.getpass("Parola: ")
    if not email or not password:
        print("Email si parola sunt obligatorii.")
        return 2

    default_uid = args.device_uid or socket.gethostname().lower()
    device_uid = input(f"Device UID [{default_uid}]: ").strip() or default_uid
    default_name = args.name or f"{platform.system()} {socket.gethostname()}"
    device_name = input(f"Nume afisat [{default_name}]: ").strip() or default_name

    try:
        core.perform_enrollment(api_base, email, password, device_uid, device_name,
                                allow_create_account=True, log=_print_log)
    except core.ApiError as e:
        print(f"EROARE: {e}")
        return 3

    print(f"\nConfig salvat la {core.CONFIG_FILE}")
    print("Acum poti rula: python scan.py daemon")
    return 0


def cmd_scan(_args: argparse.Namespace) -> int:
    try:
        api_base, device_uid, device_token = core.get_enrollment()
    except RuntimeError:
        print("Agent neinrolat. Ruleaza: python scan.py enroll")
        return 1

    print("=" * 60)
    print(" VulnWatch — scanare")
    print("=" * 60)
    print(f" API        : {api_base}")
    print(f" Device UID : {device_uid}")
    print(f" Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Admin      : {core.is_admin()}")
    print()

    print("Colectez date sistem...")
    data = core.collect_system_data(device_uid)
    print(f"  OS       : {data['os']['system']} {data['os']['release']}")
    print(f"  Hostname : {data['os']['hostname']}")
    print(f"  Porturi  : {data['network']['open_ports'] or 'niciunul detectat'}")
    print(f"  Procese  : {len(data['processes'])}")
    print(f"  Software : {len(data['software'])} programe")
    print()

    print("Trimit scanarea...")
    try:
        result = core.api_send_scan(api_base, device_token, data)
    except core.ApiError as e:
        print(f"  EROARE: {e}")
        if "invalid device token" in str(e).lower():
            print("  Tokenul nu mai e valid. Re-inroleaza:")
            print("    python scan.py enroll")
        return 5

    print()
    print("Scanare trimisa cu succes!")
    print(f"  Scan ID       : {result.get('scan_id')}")
    print(f"  Exposure Score: {result.get('exposure_score')}/100")
    findings = result.get("findings", [])
    print(f"  Findings      : {len(findings)}")

    if findings:
        sev_label = {"critical": "[CRIT] ", "high": "[HIGH] ", "medium": "[MED]  ", "low": "[LOW]  "}
        print()
        print("Vulnerabilitati detectate:")
        for f in findings:
            label = sev_label.get(f.get("severity", ""), "[INFO] ")
            print(f"  {label} {f.get('title', '')}")
            print(f"           {f.get('recommendation', '')}")

    frontend = api_base.replace("/api/v1", "").replace("8000", "5173")
    print(f"\nVezi rezultatele: {frontend}/dashboard?device={device_uid}")
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    try:
        api_base, device_uid, device_token = core.get_enrollment()
    except RuntimeError:
        print("Agent neinrolat. Ruleaza: python scan.py enroll")
        return 1

    poll_interval = max(1, int(args.poll))
    auto_interval = int(args.auto_interval) if args.auto_interval else 0
    once = bool(args.once)

    print("=" * 60)
    print(" VulnWatch Agent — daemon")
    print("=" * 60)
    print(f" API           : {api_base}")
    print(f" Device UID    : {device_uid}")
    print(f" Poll interval : {poll_interval}s")
    print(f" Auto-scan     : {('la fiecare ' + str(auto_interval) + 's') if auto_interval else 'dezactivat'}")
    print(f" Mode          : {'one-shot (--once)' if once else 'loop'}")
    print()
    print("Astept joburi de la backend... (Ctrl+C pentru oprire)")
    print()

    if once:
        try:
            job = core.api_get_next_job(api_base, device_token)
        except core.ApiError as e:
            print(f"Eroare polling: {e}")
            return 6
        if job is None:
            print("Niciun job pending. Ies (--once).")
            return 0
        core.run_one_job(api_base, device_uid, device_token, job, log=_print_log)
        return 0

    try:
        core.daemon_loop(
            api_base, device_uid, device_token,
            poll_interval=poll_interval,
            auto_interval=auto_interval,
            log=_print_log,
        )
    except KeyboardInterrupt:
        print("\nDaemon oprit.")
    return 0


def cmd_gui(_args: argparse.Namespace) -> int:
    """Deschide modul grafic. Fail soft daca Tkinter lipseste."""
    try:
        from . import gui
    except ImportError:
        from agent import gui  # type: ignore[no-redef]
    return gui.run_gui()


def cmd_logout(_args: argparse.Namespace) -> int:
    if core.clear_config():
        print(f"Config sters: {core.CONFIG_FILE}")
        return 0
    print("Niciun config gasit.")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    cfg = core.read_config()
    if not cfg.has_section("agent"):
        print("Agent neinrolat.")
        return 1
    api_base = cfg.get("agent", "api_base", fallback="?")
    device_uid = cfg.get("agent", "device_uid", fallback="?")
    has_token = bool(cfg.get("agent", "device_token", fallback="").strip())
    print(f"API        : {api_base}")
    print(f"Device UID : {device_uid}")
    print(f"Token      : {'configurat' if has_token else 'lipseste'}")
    print(f"Config file: {core.CONFIG_FILE}")
    return 0


def cmd_autostart(args: argparse.Namespace) -> int:
    try:
        from . import autostart
    except ImportError:
        from agent import autostart  # type: ignore[no-redef]

    if args.action == "enable":
        ok, msg = autostart.enable()
    elif args.action == "disable":
        ok, msg = autostart.disable()
    else:
        ok, msg = autostart.status()
    print(msg)
    return 0 if ok else 1


# ── CLI parser ───────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="VulnWatch Agent — colectare locala si trimitere catre backend.",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_enroll = sub.add_parser("enroll", help="Inrolare interactiva.")
    p_enroll.add_argument("--api", help=f"URL API (default: {core.DEFAULT_API_BASE})")
    p_enroll.add_argument("--email")
    p_enroll.add_argument("--password")
    p_enroll.add_argument("--device-uid", dest="device_uid")
    p_enroll.add_argument("--name")
    p_enroll.set_defaults(func=cmd_enroll)

    sub.add_parser("scan", help="Push direct: o scanare unica.").set_defaults(func=cmd_scan)

    p_daemon = sub.add_parser("daemon", help="Foreground; proceseaza joburi cerute din UI.")
    p_daemon.add_argument("--poll", type=int, default=3)
    p_daemon.add_argument("--auto-interval", dest="auto_interval", type=int, default=0)
    p_daemon.add_argument("--once", action="store_true")
    p_daemon.set_defaults(func=cmd_daemon)

    sub.add_parser("gui", help="Deschide modul grafic.").set_defaults(func=cmd_gui)
    sub.add_parser("status", help="Afiseaza configul curent.").set_defaults(func=cmd_status)
    sub.add_parser("logout", help="Sterge configul local.").set_defaults(func=cmd_logout)

    p_auto = sub.add_parser("autostart", help="Pornire automata la logon.")
    p_auto.add_argument("action", choices=["enable", "disable", "status"])
    p_auto.set_defaults(func=cmd_autostart)

    return parser


def main(argv: list[str] | None = None) -> int:
    if "--service" in sys.argv:
        try:
            from . import service
        except ImportError:
            from agent import service  # type: ignore[no-redef]
        return service.run_as_service()
    if "--install-service" in sys.argv:
        try:
            from . import service
        except ImportError:
            from agent import service  # type: ignore[no-redef]
        return service.install_service()
    if "--uninstall-service" in sys.argv:
        try:
            from . import service
        except ImportError:
            from agent import service  # type: ignore[no-redef]
        return service.uninstall_service()

    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    # Fara argumente → deschidem GUI (utile la dublu-click pe .exe).
    if not argv:
        return cmd_gui(argparse.Namespace())

    args = parser.parse_args(argv)
    if not args.cmd:
        return cmd_gui(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
