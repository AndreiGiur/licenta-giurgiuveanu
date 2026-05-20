# memory.md — agent/collectors/

Modul de colectori composabili. Fiecare functie primeste un `ScanProfile`
(definit in `agent/core.py`) si returneaza datele relevante pentru flag-urile
active. Toti colectorii sunt no-op (returneaza `{}` / `[]`) pe non-Windows
pentru sub-colectorii Windows-only.

## Fisiere

| Fisier              | Functie + scop |
| ------------------- | -------------- |
| `__init__.py`       | Re-export pentru `collect_network`, `collect_processes`, `collect_software`, `collect_system`, `collect_persistence`, `collect_forensics`. |
| `network.py`        | `collect_network(cfg)` → `{open_ports, **port_bindings**, port_processes?, connections?, shares?, adapters?}`. Foloseste psutil pentru porturi+conexiuni; **port_bindings** e lista `[{port, ip}]` pentru analiza adresei locale (folosit de regula NET-OPEN-PORTS-1 sa downgrade severity cand portul e doar pe adaptor virtual Hyper-V/WSL/Docker). Share-uri Windows prin **`Get-SmbShare`** (PowerShell JSON) — `net share` parsing era confundat de output localizat (RO) sau text de header; psutil pentru adaptoare. Fallback `net share` cu validare path (drive letter / UNC). |
| `processes.py`      | `collect_processes(cfg)` → `list[{pid, name, memory_percent, username, cmdline?, ppid?}]`. Sortat dupa memory_percent desc. Limita din `cfg.process_limit` (None = toate). |
| `software.py`       | `collect_software(cfg)` → `list[{name, version}]`. Citeste 3 chei Uninstall (HKLM x64, HKLM WOW6432, HKCU). Dedupe pe (name, version). |
| `system_info.py`    | `collect_system(cfg)` → `{system, release, version, machine, hostname, username, uptime_seconds, is_admin, firewall?, local_users?, bitlocker?, defender?}`. Firewall din registry; useri si Defender prin PowerShell. **defender** include + **`third_party_av`** lista din WMI `root\SecurityCenter2 AntiVirusProduct` cu real-time bit 0x1000 setat — regula AV-DISABLED skip cand exista AV tert activ. |
| `persistence.py`    | `collect_persistence(cfg)` → `{startup?, tasks?, services?, ps_policy?, reg_persistence?, wmi_subscriptions?}`. Startup din registry direct; tasks/services/WMI prin PowerShell + `ConvertTo-Json`. `reg_persistence` cauta AppInit_DLLs / IFEO Debugger / Winlogon Userinit & Shell modificate. |
| `forensics.py`      | `collect_forensics(cfg)` → `{event_log?, hosts?, dns_cache?, arp_table?, certificates?, recent_files?}`. Event log: ultimele 500 events 4625/4672/4720 din Security. Hosts: parsare directa cu **`utf-8-sig` encoding** (strip BOM ﻿) + skip linii goale/comentariu. Certs: `Cert:\\LocalMachine\\Root`. Recent files: System32 + Program Files modificate in 7 zile. |

## Pattern PowerShell

Functiile helper `_ps(script, timeout)` din fiecare modul ruleaza PowerShell
silent (`-NoProfile -NonInteractive -Command ...`) cu timeout default
60s (event log 120s, system info 30s). Returneaza stdout sau `None` la
esec. Output-ul este intotdeauna `| ConvertTo-Json -Compress` si parsam
cu `json.loads`. Pentru un singur rezultat, PowerShell returneaza dict
in loc de list — codul trateaza ambele cazuri prin `if isinstance(data, dict): data = [data]`.
