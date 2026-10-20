"""
DNSentinel Cybersecurity Dashboard - FastAPI Backend Server.
Provides RESTful APIs for metrics, live queries, security alerts, and client analytics.
Serves the React frontend single-page application directly on Windows.
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db
from app.sample_data import seed_sample_data
from app.routers import metrics, queries, clients, alerts, settings

# Lifespan event to initialize SQLite and seed demo data on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup SQLite database and seed initial demo dataset
    init_db()
    seed_sample_data(force=False)
    yield

app = FastAPI(
    title="DNSentinel Cybersecurity Gateway - Dashboard API",
    description="API backend for monitoring DNS traffic, threats, and policy enforcement [DEMO / SAMPLE DATA]",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(metrics.router)
app.include_router(queries.router)
app.include_router(clients.router)
app.include_router(alerts.router)
app.include_router(settings.router)

# Frontend Path
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

# Healthcheck endpoint
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "DNSentinel Dashboard Backend",
        "mode": "DEMO / SAMPLE DATA",
        "database": "SQLite Connected"
    }

# SPA Fallback: Serve React Frontend on all non-API web routes
@app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_frontend(full_path: str):
    # Don't intercept API routes
    if full_path.startswith("api/"):
        return HTMLResponse(content="API route not found", status_code=404)

    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        content="""
        <html>
            <head><title>DNSentinel Dashboard</title></head>
            <body style='font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center;'>
                <h1>DNSentinel Cybersecurity Dashboard</h1>
                <p>Backend API is active. Frontend index.html is being prepared.</p>
                <p><a href='/docs' style='color: #38bdf8;'>View Interactive Swagger API Docs</a></p>
            </body>
        </html>
        """,
        status_code=200
    )
