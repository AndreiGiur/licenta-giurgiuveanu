import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Use environment variable for configuration; fall back to a reasonable dev default.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://exposure:exposure@127.0.0.1:5432/exposure",
)

# Forteaza sesiunile Postgres pe UTC. Codul scrie uneori datetime-uri naive
# (ex: scheduler.py, pentru compat SQLite); fara timezone=utc pe sesiune,
# Postgres le-ar interpreta in timezone-ul serverului si orele programate
# s-ar decala daca serverul nu e pe UTC.
_connect_args = {}
if DATABASE_URL.startswith("postgresql"):
    _connect_args["options"] = "-c timezone=utc"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass
