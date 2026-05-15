import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import Base, engine
from .routes import router  # importa config -> incarca .env automat

# In dev este ok sa cream tabelele la pornire. In productie ar trebui Alembic.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnWatch API", version="1.0")

# Origins permise pentru CORS. In productie se poate seta CORS_ORIGINS,
# o lista separata prin virgule (ex: "https://app.example.com,https://admin.example.com").
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
_allowed_origins = [
    o.strip() for o in os.getenv("CORS_ORIGINS", _default_origins).split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    # Credentials = True este necesar pentru cookie-ul HttpOnly de sesiune.
    # FastAPI/Starlette nu permite "*" cand credentials sunt activate.
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Content-Type",
        "X-Session-Token",
        "X-Device-Token",
    ],
)

app.include_router(router, prefix="/api/v1")
