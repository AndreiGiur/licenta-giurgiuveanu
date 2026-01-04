from fastapi import FastAPI

from .db import Base, engine
from .routes import router

app = FastAPI(title="Exposure Platform API", version="0.2.0")

Base.metadata.create_all(bind=engine)
app.include_router(router, prefix="/api/v1")
