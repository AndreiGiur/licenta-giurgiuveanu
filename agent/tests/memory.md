# memory.md — agent/tests/

Smoke tests pentru `core.py`. Testeaza partea **fara network/UI**:
config roundtrip, structura datelor colectate, helperi de enrollment cu
mock-uri pentru apelurile HTTP.

Rulare: `python -m pytest agent/tests` (din radacina repo-ului).

## Fisiere

| Fisier                  | Rol                                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| `__init__.py`           | Marcheaza directorul ca pachet pytest.                               |
| `test_core.py`          | 8 teste: `is_enrolled`, `save_enrollment`/`get_enrollment` roundtrip, `clear_config` idempotent, `get_enrollment` ridica `RuntimeError` cand lipseste configul, `collect_system_data` smoke test (structura), `executable_path` returneaza `Path`, `is_frozen` returneaza `bool`, `perform_enrollment` propaga `ApiError`. Foloseste `monkeypatch` pentru a redirectiona `CONFIG_DIR`/`CONFIG_FILE` in `tmp_path`. |
| `test_core_relink.py`   | 9 teste pentru smart re-link: `save_enrollment` cu metadata (`device_name`, `user_email`), `get_enrollment_meta` cu sau fara config, `login_or_register` cu fallback la register pe 401, `login_or_register` propaga erori non-401, `api_get_device_by_uid` returneaza `None` pe 404 si propaga alte erori, `enroll_device_with_session` ramuri pentru relink vs create. Foloseste `unittest.mock.patch.object` pentru a stuba apelurile HTTP. |
| `test_collectors.py`    | 13 teste: `SCAN_PROFILES` are 3 nivele cu flag-uri corecte (standard minimal, advanced + persistence, deep + forensics); colectorii din `agent/collectors/` returneaza structurile asteptate (`open_ports`, `connections` pe advanced, `cmdline` pe advanced+, etc.); `collect_system_data(scan_type)` orchestreaza corect; `progress_cb` este apelat intre colectori cu progres in [0, 100]. **Total agent: 30 teste (17 existente + 13 noi).** |

## Pattern

Toate testele sunt **fara network**:
- Apelurile HTTP sunt mock-uite cu `mock.patch.object(core, "api_login", ...)`.
- Configul scrie/citeste in `tmp_path` (fixture `tmp_config_dir`/`tmp_config`).
- `collect_system_data` ruleaza efectiv pe sistemul curent (citeste procese reale)
  dar verifica doar **structura** raspunsului, nu valori specifice.

Testele de end-to-end (cu HTTP real catre backend) sunt in `server/tests/`.
