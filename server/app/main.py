import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .db import Base, SessionLocal, engine
from .ratelimit import limiter
from .routes import router  # importa config -> incarca .env automat
from .scheduler import scheduler_loop

logger = logging.getLogger(__name__)

# In dev + teste cream tabelele la pornire (rapid, fara pasi manuali).
# In productie se foloseste Alembic: `alembic upgrade head` (vezi server/alembic/)
# si se seteaza AUTO_CREATE_TABLES=false ca cele doua mecanisme sa nu se
# suprapuna. Migrarile sunt sursa de adevar pentru schema; create_all ramane
# convenabil pentru SQLite-ul din teste si pentru pornirea locala rapida.
if os.getenv("AUTO_CREATE_TABLES", "true").lower() == "true":
    Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Pornire scheduler background (skip in teste prin DISABLE_SCHEDULER=true).
    scheduler_task: asyncio.Task | None = None
    if os.getenv("DISABLE_SCHEDULER", "").lower() != "true":
        scheduler_task = asyncio.create_task(scheduler_loop(SessionLocal))
        logger.info("Scheduler task started")
    yield
    if scheduler_task is not None:
        scheduler_task.cancel()
        try:
            await scheduler_task
        except (asyncio.CancelledError, Exception):
            pass


# Metadata pentru documentația OpenAPI auto-generată la /docs și /redoc.
# Tag-urile grupează endpoint-urile pe domenii funcționale.
_OPENAPI_TAGS = [
    {"name": "auth", "description": "Înregistrare, login, logout, Google OAuth (web). Returnează cookie HttpOnly pentru browser și `session_token` pentru clienți non-browser."},
    {"name": "devices", "description": "Înrolare, listare, relink, ștergere dispozitive. Toate operațiile sunt filtrate pe `owner_id`."},
    {"name": "scans", "description": "Detalii scanări, export PDF, diff între scanări, trend de scor. Acces doar pentru proprietar (sau admin)."},
    {"name": "scan-jobs", "description": "Coada de joburi pentru flow-ul scan-on-demand. UI cere → backend creează → agent execută."},
    {"name": "agent", "description": "Endpoint-uri folosite exclusiv de agent (heartbeat, polling joburi, raportare rezultat, descărcare executabil, înrolare Google desktop)."},
    {"name": "profile", "description": "Gestionare profil utilizator: nume, preferințe, sesiuni active, schimbare parolă, statistici."},
    {"name": "scheduler", "description": "Planificări recurente de scanare (daily/weekly/monthly). Maximum 5 per utilizator."},
    {"name": "admin", "description": "Operații rezervate utilizatorilor cu `role=admin`. Listare cross-user a conturilor, dispozitivelor și scanărilor; resetare parolă; promovare/retrogradare."},
]

app = FastAPI(
    title="VulnWatch API",
    version="1.0",
    description=(
        "API REST pentru platforma VulnWatch — evaluare a expunerii cibernetice "
        "pentru dispozitive personale. Documentația interactivă este disponibilă "
        "la `/docs` (Swagger UI) și `/redoc` (ReDoc)."
    ),
    openapi_tags=_OPENAPI_TAGS,
    lifespan=lifespan,
)

# Inregistreaza rate limiter-ul si handler-ul pentru HTTP 429.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
