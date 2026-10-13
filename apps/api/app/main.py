from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.database import engine, session_factory
from app.services.bootstrap import ensure_development_bootstrap


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with session_factory() as session:
        await ensure_development_bootstrap(session)
    yield
    await engine.dispose()


app = FastAPI(
    title="WVM API",
    description="API para gestão e análise de vulnerabilidades.",
    version="0.1.0",
    docs_url="/docs" if settings.is_development else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

app.include_router(api_router, prefix="/api/v1")
