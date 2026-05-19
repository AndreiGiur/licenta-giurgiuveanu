# memory.md — agent/tests/

Smoke tests pentru `core.py`. Testeaza partea **fara network/UI**:
config roundtrip, structura datelor colectate, helperi de enrollment cu
mock-uri pentru apelurile HTTP.

Rulare: `python -m pytest agent/tests` (din radacina repo-ului).

## Fisiere

| Fisier                  | Rol                                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| `__init__.py`           | Marcheaza directorul ca pachet pytest.                               |
| `test_core.py`          | 11 teste: `is_enrolled`, `save_enrollment`/`get_enrollment` roundtrip, `clear_config` idempotent, `get_enrollment` ridica `RuntimeError` cand lipseste configul, `collect_system_data` smoke test (structura), `executable_path` returneaza `Path`, `is_frozen` returneaza `bool`, `perform_enrollment` propaga `ApiError`, **+3 teste `_run_nmap_if_deep`** (standard returneaza None, advanced returneaza None, deep fara nmap returneaza `{error: nmap_missing}`). Foloseste `monkeypatch` pentru a redirectiona `CONFIG_DIR`/`CONFIG_FILE` in `tmp_path`. |
| `test_core_relink.py`   | 9 teste pentru smart re-link: `save_enrollment` cu metadata (`device_name`, `user_email`), `get_enrollment_meta` cu sau fara config, `login_or_register` cu fallback la register pe 401, `login_or_register` propaga erori non-401, `api_get_device_by_uid` returneaza `None` pe 404 si propaga alte erori, `enroll_device_with_session` ramuri pentru relink vs create. Foloseste `unittest.mock.patch.object` pentru a stuba apelurile HTTP. |
| `test_collectors.py`    | 13 teste: `SCAN_PROFILES` are 3 nivele cu flag-uri corecte (standard minimal, advanced + persistence, deep + forensics); colectorii din `agent/collectors/` returneaza structurile asteptate (`open_ports`, `connections` pe advanced, `cmdline` pe advanced+, etc.); `collect_system_data(scan_type)` orchestreaza corect; `progress_cb` este apelat intre colectori cu progres in [0, 100]. |
| `test_google_oauth.py`  | 2 teste mock pentru `api_google_enroll`: `test_api_google_enroll_sends_token_hash` (POST cu body care contine `id_token` + `token_hash`, raspuns FARA `device_token`) + propagare `ApiError`. |
| `test_daemon_recovery.py` | 3 teste pentru `daemon_loop` auto-recovery la 401: `test_daemon_invalid_token_exits_after_first_401` (heartbeat 401 → `on_token_invalid` apelat, loop iese imediat), `test_daemon_network_error_keeps_running` (ApiError → continua retry, callback NU apelat), `test_daemon_get_job_401_also_triggers_recovery` (heartbeat OK dar `api_get_next_job` da 401 → recovery). |
| `test_metrics_tracker.py` | 5 teste pentru `MetricsTracker`: state gol cand fisier lipseste, `record_scan` persista atomic + actualizeaza `scans_total`/`last_*`/history, history capped la 20, JSON corupt fallback la state gol (fara crash), `reset()` sterge fisierul. Logica pura — fara network sau UI. |
| `test_ipc.py`           | 3 teste pentru protocol IPC localhost (TCP socket port 47815): request/response cu handler default, push events catre subscribers, eroare pe cmd necunoscut. Foloseste fixture `server_port` (closed before yield ca SO_REUSEADDR sa permita reconectare pe Windows). |
| `test_nmap_runner.py`   | 7 teste pentru `agent/nmap_runner.py`: `validate_cidr` accepta forme valide, `validate_lan_target` refuza public IP + subnet > 4096 hosts, `build_nmap_args` include `-oX`, `--script vulnwatch-audit`, top-1000, all-ports (`-p-`). |
| `test_nmap_parser.py`   | 3 teste pentru `agent/nmap_parser.py`: parse fixture `nmap_localhost.xml`, extract JSON din `<script id="vulnwatch-audit">`, `NmapParseError` pe XML invalid. |

## Pattern

Toate testele sunt **fara network**:
- Apelurile HTTP sunt mock-uite cu `mock.patch.object(core, "api_login", ...)`.
- Configul scrie/citeste in `tmp_path` (fixture `tmp_config_dir`/`tmp_config`).
- `collect_system_data` ruleaza efectiv pe sistemul curent (citeste procese reale)
  dar verifica doar **structura** raspunsului, nu valori specifice.

Testele de end-to-end (cu HTTP real catre backend) sunt in `server/tests/`.

**Total: 63 teste** (11 + 9 + 13 + 2 + 3 + 5 + 3 IPC + 7 nmap_runner + 3 nmap_parser + alti smoke per agent collectors aliniati la SCAN_PROFILES).
