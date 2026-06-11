# Design: 15 reguli noi de scanare + colectori bogati (abordarea C)

**Data:** 2026-06-11
**Status:** aprobat verbal, in asteptarea review-ului pe spec

## Context si obiectiv

Motorul de reguli are azi 46 de reguli (23 Windows/cross + NMAP-LUA-1 + 22 Linux). Adaugam **15 reguli noi** (5 per nivel de scanare),
orientate Windows + cross-platform (Linux ramane neatins — are deja 22 de reguli
dedicate). Abordarea aleasa: **colectori bogati** — pe langa regulile care consuma
date deja colectate dar nefolosite, agentul primeste subsisteme noi de colectare
(WiFi, politica de parole, audit policy, UAC/autologon/SMBv1, exclusions Defender).

Costul de colectare respecta nivelul: registry one-liners la standard, comenzi
medii (secedit, netsh export) la advanced, comenzi scumpe (auditpol, Get-MpPreference)
la deep.

## Principii de privacy (obligatorii)

- **Niciodata parole sau chei**: la autologon colectam doar *prezenta* valorii
  `DefaultPassword` (bool) + `DefaultUserName`; la WiFi exportam profilele FARA
  `key=clear`, deci XML-ul nu contine cheia.
- Output localizat (Windows RO) NU se parseaza dupa text: folosim chei
  locale-independente — INF-ul secedit (chei fixe), CSV auditpol cu **GUID-uri
  de subcategorie**, XML-ul netsh (schema fixa).

## Cele 15 reguli

### Standard (5)

| Rule ID | os | category | weight | conf | sev | Conditie | Compliance |
|---|---|---|---|---|---|---|---|
| `OS-UPTIME-1` | any | hygiene | 0.5 | 1.0 | low | `os.uptime_seconds` > 30 zile (prag `UPTIME_DAYS_THRESHOLD` in config.py) | CIS-7.3, NIST-PR.PS-02 |
| `UAC-DISABLED-1` | windows | hygiene | 1.2 | 1.0 | high | `system_info.uac.enable_lua == false` SAU `consent_prompt_admin == 0` (silent elevate) | CIS-4.1, CIS-5.4, NIST-PR.AA-05 |
| `AUTOLOGON-PASSWORD-1` | windows | critical_risk | 1.5 | 1.0 | critical | `system_info.autologon.password_present == true` (parola in clar in registry) | CIS-5.2, CIS-4.1, NIST-PR.AA-01 |
| `SMB1-ENABLED-1` | windows | network_exposure | 1.5 | 1.0 | high | `system_info.smb1_enabled == true` (DOAR la valoare explicita 1 in registry — lipsa cheii nu declanseaza) | CIS-4.2, CIS-4.8, NIST-PR.PS-01, NIST-ID.RA-01 |
| `USER-GUEST-ENABLED-1` | windows | hygiene | 1.0 | 1.0 | medium | cont `Guest` cu `enabled == true`, SAU orice cont activ cu `password_required == false` | CIS-5.2, CIS-5.3, NIST-PR.AA-01 |

### Advanced (5)

| Rule ID | os | category | weight | conf | sev | Conditie | Compliance |
|---|---|---|---|---|---|---|---|
| `PROC-ENCODED-CMDLINE-1` | windows | activity | 1.2 | 0.8 | high | proces `powershell`/`pwsh` cu cmdline continand `-enc`/`-encodedcommand`/`downloadstring`/`frombase64string`/`invoke-expression`/`iex(` | CIS-8.5, CIS-10.7, NIST-DE.AE-02 |
| `WIFI-INSECURE-1` | windows | network_exposure | 1.0 | 1.0 | high (Open/WEP) / medium (WPA1) | profil WiFi salvat cu autentificare `open`/`WEP`/`WPAPSK` (WPA1); un singur finding, severitate = max | CIS-12.6, NIST-PR.IR-01 |
| `PASS-POLICY-WEAK-1` | windows | hygiene | 1.0 | 1.0 | medium | `min_password_length < 8` SAU `lockout_threshold` absent (0 = never) | CIS-5.2, NIST-PR.AA-01 |
| `SVC-UNQUOTED-PATH-1` | windows | hygiene | 0.8 | 0.9 | medium | serviciu cu `binary_path` necitat care contine spatii inainte de `.exe` (unquoted service path privesc) | CIS-4.1, NIST-PR.PS-01 |
| `PORT-PROCESS-SUSPECT-1` | windows | network_exposure | 1.2 | 1.0 | high | proces care asculta (LISTEN) cu `exe` in director user-writable (`\temp\`, `\appdata\local\temp`, `\users\public\`, `\programdata\temp`) | CIS-4.5, CIS-13.5, NIST-DE.CM-01 |

### Deep (5)

| Rule ID | os | category | weight | conf | sev | Conditie | Compliance |
|---|---|---|---|---|---|---|---|
| `DEFENDER-EXCLUSIONS-1` | windows | critical_risk | 1.5 | 1.0 | high | exclusions Defender pe path-uri largi/suspecte: radacina de drive (`C:\`), `C:\Users`, `C:\Windows`, directoare temp; sau ExclusionProcess pe `powershell.exe`/`cmd.exe` | CIS-10.1, CIS-10.6, NIST-PR.PS-05 |
| `ARP-SPOOF-1` | windows | network_exposure | 1.2 | 0.7 | high | acelasi MAC mapat la >= 2 IP-uri distincte in `forensics.arp_table`; exclude broadcast (`ff:ff:...`), multicast (`01:00:5e`, `33:33`), IP-uri >= 224.0.0.0 si 255.255.255.255 | CIS-13.3, NIST-DE.CM-01 |
| `DNS-SUSPICIOUS-1` | windows | activity | 0.8 | 0.6 | medium | intrari `forensics.dns_cache` cu punycode (`xn--`), TLD frecvent abuzat (`.tk .ml .ga .cf .gq .top`), sau label >= 25 caractere fara vocale (heuristic DGA) | CIS-9.2, NIST-DE.AE-02 |
| `RECENT-SYSTEM-FILES-1` | windows | activity | 0.7 | 0.6 | medium | fisiere `.exe/.dll/.sys` din `forensics.recent_files` (System32/Program Files modificate in 7 zile); evidence cap la 20 | CIS-10.7, NIST-PR.DS-06 |
| `AUDIT-POLICY-OFF-1` | windows | hygiene | 1.0 | 0.8 | medium | `AuditLogonEvents == 0` SAU `AuditAccountManage == 0` din INF-ul secedit `[Event Audit]` (valori numerice, locale-independente; conf 0.8 fiindca advanced audit policy poate suprascrie categoriile legacy) | CIS-8.2, CIS-8.5, NIST-DE.CM-09 |

Balanta pe categorii: hygiene 6, network_exposure 4, activity 3, critical_risk 2.

## Modificari in agent

### `agent/collectors/system_info.py`

- `uac` (standard, winreg direct): `{enable_lua: bool, consent_prompt_admin: int}` din
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
- `autologon` (standard, winreg direct): `{enabled: bool, default_username: str, password_present: bool}`
  din `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
  (`AutoAdminLogon`, `DefaultUserName`, existenta `DefaultPassword` — valoarea NU se citeste).
- `smb1_enabled` (standard, winreg direct): `bool | None` din
  `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`
  (None daca cheia lipseste — regula nu se declanseaza pe None).
- `local_users` extins: `Get-LocalUser` aduce in plus `enabled` si `password_required`
  per cont (campuri noi in dict-urile existente).
- `password_policy` (advanced, flag nou): export `secedit /export /cfg <tmp> /quiet`,
  parsare INF `[System Access]`: `MinimumPasswordLength`, `MaximumPasswordAge`,
  `LockoutBadCount`. Chei locale-independente. Fara admin → camp absent (degradare).
- `defender.exclusions` (deep, fara flag nou — extinde query-ul Defender existent):
  `Get-MpPreference` → `{paths: [...], processes: [...], extensions: [...]}`.
- `audit_policy` (deep, flag nou): din ACELASI export secedit ca password_policy —
  sectiunea `[Event Audit]`, cheile `AuditLogonEvents` si `AuditAccountManage`
  (0=none, 1=success, 2=failure, 3=both; numerice, locale-independente).
  Motivare schimbare fata de auditpol: CSV-ul auditpol are valorile setarilor
  localizate (RO), GUID-ul identifica doar randul, nu si valoarea.
  Necesita admin; fara admin → camp absent.

### `agent/collectors/network.py`

- `wifi_profiles` (advanced, flag nou, Windows-only): `netsh wlan export profile folder=<tmp>`
  (FARA `key=clear`), parsare XML per profil → `[{ssid, authentication}]`.
  XML schema fixa — imun la localizare. Masini fara WiFi → lista goala.
- `port_processes` extins: camp `exe` per intrare (`psutil.Process.exe()`,
  `AccessDenied` → `""`).

### `agent/core.py`

- `ScanProfile` primeste 3 flag-uri noi: `include_wifi_profiles` (advanced+),
  `include_password_policy` (advanced+), `include_audit_policy` (deep).
- Functiile de parsare noi sunt **pure** (primesc text, intorc dict) pentru
  testare fara subprocess: `_parse_secedit_inf`, `_parse_auditpol_csv`,
  `_parse_wifi_profile_xml`.

## Modificari in server

- `server/app/rules_extended.py` (modul NOU): cele 15 functii cu `@rule`
  (14 `os="windows"`, `OS-UPTIME-1` `os="any"`), importat la finalul `rules.py`
  — acelasi pattern ca `rules_linux.py`; `rules.py` nu se umfla.
- `server/app/config.py`: praguri noi `UPTIME_DAYS_THRESHOLD = 30`,
  `MIN_PASSWORD_LENGTH_THRESHOLD = 8`.
- `test_rules_count_matches_expectation`: 46 → 61.
- Zero modificari in modele DB, API, frontend (findings generice, UI le afiseaza deja).

## Testare

- **Server** (~35 teste noi): pozitiv + negativ per regula; parametrizarile din
  `test_rule_contract.py` si noile rule ID-uri intra automat in suite-urile existente.
- **Agent** (~15 teste noi): parserele pure (INF secedit, CSV auditpol cu GUID-uri,
  XML wifi) pe fixture-uri text; structura output colectori (campuri noi prezente
  la nivelul corect de profil); no-op pe non-Windows.
- **Degradare gratioasa**: fiecare camp nou absent → regula corespunzatoare
  intoarce None (niciun crash, pattern existent `(scan.get(...) or {})`).

## Explicit in afara scopului

- Reguli Linux noi (setul Linux ramane 22).
- Feed CVE live (ramane hook-ul `_refresh_from_feed`).
- Colectare WiFi keys, parole, hash-uri — interzis prin design.
- Modificari UI dincolo de afisarea generica a findings.

## Actualizari memory.md (conventie proiect)

`agent/memory.md`, `agent/collectors/memory.md`, `agent/tests/memory.md`,
`server/app/memory.md`, `server/tests/memory.md` — dupa fiecare task care
modifica fisiere din folderul respectiv.
