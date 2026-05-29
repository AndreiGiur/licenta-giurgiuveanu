# memory.md — server/alembic/

Migrari de schema DB (Alembic). Additiv — folosit in productie pe Postgres.
Dev + teste raman pe `Base.metadata.create_all` (SQLite), deci suita de teste
nu depinde de Alembic.

## Fisiere

| Fisier            | Rol                                                                       |
| ----------------- | ------------------------------------------------------------------------- |
| `env.py`          | Config Alembic. Adauga radacina `server/` in `sys.path`, citeste `DATABASE_URL` din env (prioritate peste `alembic.ini`), `target_metadata = app.models.Base.metadata` pentru autogenerate. |
| `script.py.mako`  | Template pentru migrari noi (boilerplate Alembic).                        |
| `versions/3966a149d091_initial_schema.py` | Migrarea initiala — creeaza cele 7 tabele (users, sessions, devices, scans, findings, scan_jobs, scan_schedules) + indexuri. Generata cu `--autogenerate` din modele. |

## Comenzi

```bash
cd server
alembic upgrade head                          # aplica migrarile (productie)
alembic revision --autogenerate -m "mesaj"    # genereaza o migrare noua din modele
alembic downgrade -1                          # revine o migrare
```

`DATABASE_URL` din env are prioritate peste valoarea din `alembic.ini`.
