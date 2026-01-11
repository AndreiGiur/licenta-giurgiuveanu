import os
import tempfile
from fastapi.testclient import TestClient

# create a temporary sqlite file for tests
_db_file = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file.name}"

# import app after DATABASE_URL is set
from server.app.main import app, Base, engine

# create tables
Base.metadata.create_all(bind=engine)


import pytest

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
