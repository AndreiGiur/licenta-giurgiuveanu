import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Use environment variable for configuration; fall back to a reasonable dev default.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://exposure:exposure@127.0.0.1:5432/exposure",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass
