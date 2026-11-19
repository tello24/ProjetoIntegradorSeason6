from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic's default error includes input values; never echo a credential form.
    if request.url.path.startswith("/api/v1/auth"):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Confira os campos. A nova senha precisa ter entre 12 e 200 caracteres."
            },
        )
    if request.url.path.startswith("/api/v1/admin/jira"):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Confira os campos do Jira: endereço, e-mail, projeto, "
                "tipo de item e Cloud ID (UUID, se informado)."
            },
        )
    return await request_validation_exception_handler(request, exc)
