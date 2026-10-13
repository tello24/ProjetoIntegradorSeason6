from fastapi import APIRouter

from app.api.routes import (
    access,
    assets,
    auth,
    dashboard,
    health,
    reports,
    scans,
    tickets,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(access.router, prefix="/access", tags=["access"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(tickets.router, tags=["tickets"])
api_router.include_router(
    vulnerabilities.router,
    prefix="/vulnerabilities",
    tags=["vulnerabilities"],
)
