"""FastAPI application factory for AegisFlow backend."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routes import findings, runs, export, preview


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(title="AegisFlow API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(runs.router)
    app.include_router(findings.router)
    app.include_router(export.router)
    app.include_router(preview.router)

    return app


app = create_app()
