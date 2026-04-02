"""
ScriptOps Internal Automation API
FastAPI application entry point
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import time

from app.routes import reports, cron, database, executions, auth, scripts
from app.middleware.auth import AuthMiddleware
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_STATIC = os.path.join(_APP_DIR, "..", "static")


def _static_root() -> str:
    return os.path.abspath(os.environ.get("SCRIPTOPS_STATIC_DIR", _DEFAULT_STATIC))


def _cors_origins() -> list[str]:
    # List the **dashboard (UI) origin(s)** — not the API hostname (unless UI is served from it).
    # Browsers send Origin: null for pages opened as file:// — that must be allowed if you use file://.
    raw = os.environ.get(
        "SCRIPTOPS_CORS_ORIGINS",
        "https://scriptops.netcorecloud.com,"
        "http://localhost:3000,http://localhost:8080,"
        "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:8080,null",
    )
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    # If you override SCRIPTOPS_CORS_ORIGINS in production, file:// breaks unless "null" is included.
    # Append automatically unless explicitly disabled (public APIs may set SCRIPTOPS_CORS_NO_NULL=1).
    if os.environ.get("SCRIPTOPS_CORS_NO_NULL", "").lower() not in ("1", "true", "yes"):
        if "null" not in origins:
            origins.append("null")
    return origins


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services.schedule_store import init_db
    from app.services.scheduler_worker import shutdown_scheduler, start_scheduler

    init_db()
    await start_scheduler()
    yield
    await shutdown_scheduler()


app = FastAPI(
    title="ScriptOps Internal API",
    description="""
## ScriptOps — Internal Automation Platform API

Provides authenticated endpoints to:
- **Execute report generation scripts** (Python, role: Manager+)
- **Trigger cron jobs manually** (role: Admin/Manager)
- **Run database operations** (INSERT/UPDATE: Admin only, SELECT: Manager+)
- **Stream real-time execution output** via SSE
- **View execution history and logs**
- **List scripts and run by script_id** (`/api/v1/scripts`)

### Authentication
All endpoints require an `X-ScriptOps-Key` header with a valid API key.
Keys are scoped to a role; actions are enforced against that role.

### Role Hierarchy
- `viewer`   — read-only access (logs, status)
- `operator` — shell/server scripts only
- `manager`  — reports + DB read + scheduling
- `admin`    — full access including DB INSERT/UPDATE
""",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    # False: auth uses X-ScriptOps-Key / Bearer headers, not cookies — avoids browser issues
    # with Origin "null" (file://) when combined with Allow-Credentials.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
app.add_middleware(AuthMiddleware)

# ── REQUEST TIMING ────────────────────────────────────────────────────────────
@app.middleware("http")
async def add_timing(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Response-Time"] = f"{duration}ms"
    return response

# ── ROUTES ────────────────────────────────────────────────────────────────────
app.include_router(auth.router,       prefix="/api/v1/auth",       tags=["Auth"])
app.include_router(scripts.router,   prefix="/api/v1/scripts",    tags=["Scripts"])
app.include_router(reports.router,    prefix="/api/v1/reports",    tags=["Reports"])
app.include_router(cron.router,       prefix="/api/v1/cron",       tags=["Cron Jobs"])
app.include_router(database.router,   prefix="/api/v1/database",   tags=["Database"])
app.include_router(executions.router, prefix="/api/v1/executions", tags=["Executions"])

# ── HEALTH ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0", "service": "scriptops-api"}

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "ScriptOps API",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
        "dashboard": "/static/scriptops-dashboard.html",
    }

_static = _static_root()
if os.path.isdir(_static):
    app.mount("/static", StaticFiles(directory=_static), name="static")
    logger.info("Serving static files from %s at /static/", _static)
else:
    logger.warning("Static directory missing (%s); create it or set SCRIPTOPS_STATIC_DIR", _static)


@app.get("/dashboard", tags=["System"])
async def dashboard_redirect():
    """Shortcut to the dashboard HTML when it lives under /static/."""
    target = "/static/scriptops-dashboard.html"
    return RedirectResponse(url=target, status_code=307)

# ── GLOBAL ERROR HANDLER ──────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_error(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "message": "An unexpected error occurred."},
    )
