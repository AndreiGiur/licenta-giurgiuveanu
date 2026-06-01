# Design — Set de reguli Linux (Lynis-style) + colector + filtrare pe OS

Data: 2026-06-01
Status: aprobat (design), urmeaza plan de implementare

## Context

Motorul de reguli (`server/app/rules.py`) are 23 de reguli, in mare orientate pe
Windows (registry, WMI, Defender, BitLocker, event log, servicii, scheduled tasks).
Pe Linux/Kali, colectorii aduc doar porturi/procese/OS (psutil, cross-platform);
restul sunt gated `platform.system()=="Windows"`. Rezultat: scanarile pe Linux
produc aproape zero findings — inselator.

Utilizatorul vrea un **set de reguli Linux cuprinzator (stil Lynis)**. Asta inseamna
trei piese: (A) filtrare pe OS in motor, (B) un colector Linux nou care aduce date
specifice, (C) ~19 reguli Linux care le evalueaza.

## Principii

- Reguli = functii pure pe dict → testabile complet pe orice OS (payload mock-uit).
- Colectorul Linux ruleaza DOAR pe Linux, degradeaza gratios fara root (campuri
  goale, nu crash). Testat cu `subprocess` mock-uit.
- Reutilizam scoring-ul multidimensional + compliance + UI/PDF existente (findings
  generice → apar automat).
- Zero dependinte noi.

---

## A. Filtrare pe OS in motorul de reguli

`@rule(..., os: str = "any")` — valori `"any" | "windows" | "linux"`. Validare in
decorator (ridica ValueError la valoare invalida). `fn._os = os`.

In `evaluate(scan)`: pe langa filtrul `min_level`, sare peste regula daca
`fn._os != "any"` si `fn._os != _scan_os(scan)`, unde
`_scan_os(scan) = "linux" if scan["os"]["system"].lower().startswith("linux") else
"windows" if ...startswith("windows") else "other"`.

Tag-uirea regulilor existente:
- **Windows-only** (`os="windows"`): REG-HIJACK, WMI-PERSIST, AV-DISABLED,
  BITLOCKER-OFF, EVENTLOG-BRUTEFORCE, EVENTLOG-PRIVESC, STARTUP-SUSPICIOUS,
  TASK-SUSPICIOUS, SVC-SUSPICIOUS, PS-POLICY, NET-SHARE, FW-DISABLED, USER-ADMIN,
  CERT-UNTRUSTED, HOSTS-TAMPERED. (cele care depind de date Windows-only)
- **Cross-platform** (raman `os="any"`): NET-OPEN-PORTS, NET-MANY-PORTS,
  NET-ESTABLISHED, OS-ADMIN, PROC-SUSPICIOUS, PROC-POWERSHELL, SW-VULNERABLE,
  OS-EOL, NMAP-LUA.
- **Linux** (`os="linux"`): regulile noi (sectiunea C).

`evaluate` returneaza si numarul de reguli aplicabile (sau il expunem separat) ca
UI-ul sa poata afisa "X reguli aplicabile pe acest OS". (Detaliu: adaugam in
output un camp meta optional, fara sa rupem semnatura `(score, breakdown, findings)`
— il punem ca atribut pe findings sau un endpoint separat. Decizie de implementare:
**nu schimbam semnatura**; UI-ul deduce OS din `scan.os.system` si stie ce reguli
se aplica. Nu adaugam meta acum — YAGNI.)

## B. Colector Linux — `agent/collectors/linux_audit.py`

`collect_linux_audit(cfg: ScanProfile) -> dict` — ruleaza doar daca
`platform.system()=="Linux"` (altfel `{}`). Fiecare sub-colector e izolat in
try/except → camp gol la eroare/lipsa permisiuni. Output (cheia `linux` in payload):

```
{
  "ssh": {"permit_root_login": "yes|no|prohibit-password|None",
          "password_auth": "yes|no|None", "port": int|None},
  "firewall": {"tool": "ufw|iptables|nftables|none", "active": bool},
  "users": {"uid0_accounts": [str], "empty_password_accounts": [str],
            "sudo_nopasswd": [str]},
  "suid": [str],                       # binare SUID NEcunoscute (filtrate de known-good)
  "world_writable": [str],             # fisiere world-writable in dirs sensibile
  "cron": [{"source": str, "line": str}],
  "services": [{"name": str, "exec": str}],   # systemd units din cai neobisnuite
  "packages": [{"name": str, "version": str}],
  "kernel": str,                       # uname -r
  "sysctl": {"ip_forward": "0|1|None", "aslr": "0|1|2|None"},
  "auto_updates": bool|None,           # unattended-upgrades activ (Debian)
}
```

Surse (comenzi/fisiere): `/etc/ssh/sshd_config`; `ufw status`/`iptables -S`/`nft list ruleset`;
`/etc/passwd` (UID 0), `/etc/shadow` (empty pass — doar daca readable/root),
`sudo -l`/`/etc/sudoers*` (NOPASSWD); `find {/usr/bin,/usr/sbin,/bin,/sbin} -perm -4000`
(comparat cu KNOWN_SUID); `find {dirs sensibile} -perm -0002 -type f`; `/etc/crontab`,
`/etc/cron.d/*`, `crontab -l`; `systemctl list-units --type=service` + path unit;
`dpkg -l`/`rpm -qa`; `uname -r`; `sysctl net.ipv4.ip_forward kernel.randomize_va_space`;
`systemctl is-enabled unattended-upgrades`.

Nivele (in `ScanProfile`, prin flag-uri noi sau reutilizand existente):
- **standard**: ssh, firewall, users, kernel, sysctl, auto_updates, packages.
- **advanced+**: + cron, services.
- **deep**: + suid, world_writable (cele lente — `find`).

Limite anti-blocare: `find` cu `-maxdepth` rezonabil + timeout pe subprocess; liste
capate (ex: max 200 SUID/world-writable).

## C. Set reguli Linux (~19) — `server/app/rules.py`

Toate `os="linux"`, cu `category` + `weight` + `confidence` + `compliance` (CIS Linux
benchmark + NIST CSF). Consuma `scan["linux"]`.

**critical_risk:**
- `LNX-SSH-ROOT-LOGIN-1` — `ssh.permit_root_login == "yes"` (high, w=1.5).
- `LNX-EMPTY-PASSWD-1` — `users.empty_password_accounts` nevid (critical, w=2).
- `LNX-UID0-1` — alt cont decat `root` cu UID 0 (critical, w=2).
- `LNX-PKG-VULNERABLE-1` — pachet din `packages` match pe semnaturile vulnerabile
  (reutilizeaza `VULNERABLE_SOFTWARE`) (severity din semnatura, w=1.5).
- `LNX-SUID-UNCOMMON-1` — binare SUID in afara listei known-good (high, w=1.2, conf=0.7).

**network_exposure:**
- `LNX-FW-DISABLED-1` — `firewall.active == False` (high, w=1.2).
- `LNX-SSH-PASSWORD-AUTH-1` — `ssh.password_auth == "yes"` (medium).
- `LNX-OPEN-PORTS-1` — porturi riscante in ascultare (reutilizeaza RISKY_PORTS;
  doar pe Linux ca sa nu dubleze NET-OPEN-PORTS care e `any` — vezi nota*).

*Nota: NET-OPEN-PORTS-1 ramane `any` si acopera porturile riscante pe ambele OS.
Deci NU adaugam LNX-OPEN-PORTS (ar dubla). **Eliminat din set** (YAGNI).

**hygiene:**
- `LNX-SUDO-NOPASSWD-1` — `users.sudo_nopasswd` nevid (medium).
- `LNX-WORLD-WRITABLE-1` — `world_writable` nevid (medium, conf=0.8).
- `LNX-KERNEL-EOL-1` — kernel/distro EOL (reutilizeaza `EOL_OPERATING_SYSTEMS` +
  kernel pattern) (high).
- `LNX-SYSCTL-IPFWD-1` — `sysctl.ip_forward == "1"` (low/medium, conf=0.7 — poate fi legitim).
- `LNX-ASLR-WEAK-1` — `sysctl.aslr` < "2" (medium).
- `LNX-AUTOUPDATE-OFF-1` — `auto_updates == False` (low).

**activity:**
- `LNX-CRON-SUSPICIOUS-1` — linie cron cu pattern ofensiv (`curl|bash`, `/tmp/`,
  `base64 -d`, `wget`) (high, conf=0.8).
- `LNX-SVC-SUSPICIOUS-1` — serviciu systemd cu exec din `/tmp`, `/home`, `/dev/shm`
  sau unit world-writable (high, w=0.8).

(~14 reguli efective dupa eliminarea dublurilor; "cuprinzator" = acoperire larga pe
SSH/users/firewall/SUID/cron/sysctl/pachete/kernel. Putem adauga ulterior fara efort.)

## D. Integrare scoring / compliance / UI / PDF

- Findings Linux trec prin acelasi `evaluate` → scoring multidimensional + breakdown.
- Compliance: fiecare regula primeste refs CIS (ex: `CIS-5.2.x` SSH, `CIS-1.x` filesystem)
  + NIST. Apar in UI + PDF ca la Windows.
- UI/PDF: zero schimbari structurale — findings generice.

## E. Testare

- **Reguli (pure):** un fisier `server/tests/test_linux_rules.py` — pentru fiecare
  regula: caz pozitiv + negativ, pe un payload `linux` mock-uit. + test ca regulile
  Windows NU se aprind pe payload Linux si invers (filtrarea OS).
- **`@rule(os=)`:** test in `test_scan_types.py` / nou — os invalid ridica ValueError;
  `evaluate` filtreaza pe OS.
- **Colector:** `agent/tests/test_linux_audit.py` — `subprocess.run` + citirile de
  fisiere mock-uite; verifica parsarea (sshd_config, ufw, passwd UID0, sysctl, etc.)
  + ca pe non-Linux intoarce `{}`.
- TSC/pytest verzi; nu pot rula colectorul live pe Linux aici → user verifica pe Kali.

## F. Faze

1. **Filtrare OS** — `@rule(os=)` + `evaluate` + `_scan_os` + tag reguli existente + teste.
2. **Colector** — `linux_audit.py` (gated Linux, try/except per sub-colector, limite)
   + flag-uri ScanProfile + integrare in `collect_system_data` + teste mock.
3. **Reguli Linux** — ~14 reguli `os="linux"` cu compliance + teste.
4. **Finalizare** — memory.md + suita completa + rebuild .exe (agent schimbat) +
   verificare live pe Kali.

## Non-obiective (YAGNI)

- Fara feed CVE live pentru pachete (reutilizam semnaturile statice existente).
- Fara LNX-OPEN-PORTS separat (NET-OPEN-PORTS `any` acopera).
- Fara scanare integritate fisiere (AIDE/tripwire-style) — prea greu.
- Fara modificari de UI/PDF (findings generice apar automat).
- Colectorul nu escaladeaza privilegii — ce nu e citibil ca user → camp gol.
