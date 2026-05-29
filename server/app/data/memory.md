# memory.md — server/app/data/

Date statice editabile fara modificari de cod, incarcate de aplicatie la runtime.

## Fisiere

| Fisier                  | Rol                                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| `vuln_signatures.json`  | **Semnaturi de software vulnerabil + sisteme de operare EOL.** Incarcat de `rules.py` (`_load_vuln_signatures()`). Doua chei: `vulnerable_software` (lista de `{name_contains, severity, cve, note}`, match prin substring case-insensitive pe numele software-ului) + `eol_operating_systems` (lista de `{system, rel, severity, note}`, match pe `system in os.system AND rel in os.release`). Sursa de adevar pentru regulile `SW-VULNERABLE-1` si `OS-EOL-1`. Daca fisierul lipseste/e corupt, `rules.py` cade pe un set minimal embedded (`_FALLBACK_*`). Hook `_refresh_from_feed()` permite hot-reload dintr-un feed live (NVD/OSV) in productie. |
