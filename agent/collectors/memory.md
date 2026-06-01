# memory.md — agent/collectors/

Modul de colectori composabili. Fiecare functie primeste un `ScanProfile`
(definit in `agent/core.py`) si returneaza datele relevante pentru flag-urile
active. Toti colectorii sunt no-op (returneaza `{}` / `[]`) pe non-Windows
pentru sub-colectorii Windows-only.

## Fisiere

| Fisier              | Functie + scop |
| ------------------- | -------------- |
| `__init__.py`       | Re-export pentru `collect_network`, `collect_processes`, `collect_software`, `collect_system`, `collect_persistence`, `collect_forensics`, `collect_linux_audit`. |
| `network.py`        | `collect_network(cfg)` → `{open_ports, **port_bindings**, **identity**, port_processes?, connections?, shares?, adapters?}`. **(2026-06-02) `collect_network_identity()`** → `{iface, local_ip, mac}` ale interfetei active principale (up, non-loopback, IPv4 privata; MAC din AF_LINK) sau `{}`. Date cu caracter personal — colectam DOAR o interfata (minimizare GDPR); folosite in identitatea dispozitivului din PDF. Foloseste psutil pentru porturi+conexiuni; **port_bindings** e lista `[{port, ip}]` pentru analiza adresei locale (folosit de regula NET-OPEN-PORTS-1 sa downgrade severity cand portul e doar pe adaptor virtual Hyper-V/WSL/Docker). Share-uri Windows prin **`Get-SmbShare`** (PowerShell JSON) — `net share` parsing era confundat de output localizat (RO) sau text de header; psutil pentru adaptoare. Fallback `net share` cu validare path (drive letter / UNC). |
| `processes.py`      | `collect_processes(cfg)` → `list[{pid, name, memory_percent, username, cmdline?, ppid?}]`. Sortat dupa memory_percent desc. Limita din `cfg.process_limit` (None = toate). |
| `software.py`       | `collect_software(cfg)` → `list[{name, version}]`. Citeste 3 chei Uninstall (HKLM x64, HKLM WOW6432, HKCU). Dedupe pe (name, version). |
| `system_info.py`    | `collect_system(cfg)` → `{system, release, version, machine, hostname, username, uptime_seconds, is_admin, firewall?, local_users?, bitlocker?, defender?}`. Firewall din registry; useri si Defender prin PowerShell. **defender** include + **`third_party_av`** lista din WMI `root\SecurityCenter2 AntiVirusProduct` cu real-time bit 0x1000 setat — regula AV-DISABLED skip cand exista AV tert activ. |
| `persistence.py`    | `collect_persistence(cfg)` → `{startup?, tasks?, services?, ps_policy?, reg_persistence?, wmi_subscriptions?}`. Startup din registry direct; tasks/services/WMI prin PowerShell + `ConvertTo-Json`. `reg_persistence` cauta AppInit_DLLs / IFEO Debugger / Winlogon Userinit & Shell modificate. |
| `forensics.py`      | `collect_forensics(cfg)` → `{event_log?, hosts?, dns_cache?, arp_table?, certificates?, recent_files?}`. Event log: ultimele 500 events 4625/4672/4720 din Security. Hosts: parsare directa cu **`utf-8-sig` encoding** (strip BOM ﻿) + skip linii goale/comentariu. Certs: `Cert:\\LocalMachine\\Root`. Recent files: System32 + Program Files modificate in 7 zile. |
| `linux_audit.py`    | **(2026-06-01) Colector dedicat Linux** — gated `platform.system()=="Linux"` (returneaza `{}` altfel), degradeaza grationos fara root. `collect_linux_audit(cfg)` → `scan["linux"]`: `ssh` (parse `/etc/ssh/sshd_config`: permit_root_login/empty_passwords/password_auth/x11_forwarding), `firewall` (ufw/iptables/nft), `users` (UID0, parole goale din `/etc/shadow`, sudo NOPASSWD), `kernel`, `sysctl` (ip_forward/aslr/suid_dumpable), `login_defs` (pass_max_days/umask), `tmp_missing_noexec` (din `/proc/mounts`), `packages` (dpkg/rpm), `auto_updates`; advanced+ adauga `cron`+`services` (systemctl); deep adauga `suid`/`sgid`/`world_writable`. Functii de parsare **pure** (`_parse_sshd_config`, `_uid0_accounts`, `_empty_password_accounts`, `_parse_sysctl`, `_parse_login_defs`, `_tmp_missing_noexec`, `_filter_suid` cu set `KNOWN_SUID`, `_sudo_nopasswd`) testabile fara subprocess; impure: `_firewall`, `_suid`, `_sgid`, `_world_writable`, `_cron`, `_services`, `_packages`. Consumat de regulile din `server/app/rules_linux.py`. |

## Pattern PowerShell

Functiile helper `_ps(script, timeout)` din fiecare modul ruleaza PowerShell
silent (`-NoProfile -NonInteractive -Command ...`) cu timeout default
60s (event log 120s, system info 30s). Returneaza stdout sau `None` la
esec. Output-ul este intotdeauna `| ConvertTo-Json -Compress` si parsam
cu `json.loads`. Pentru un singur rezultat, PowerShell returneaza dict
in loc de list — codul trateaza ambele cazuri prin `if isinstance(data, dict): data = [data]`.
