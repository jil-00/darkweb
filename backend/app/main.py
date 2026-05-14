from collections import defaultdict, deque
from datetime import datetime, timezone
from time import monotonic

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from app.core.config import get_settings
from app.core.database import close_mongo_connection, connect_to_mongo, get_db
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.routers import alerts, auth, dashboard, health, intelligence, monitoring, scan, stream, threat_intel
from app.services.ingestion.external_sources import validate_external_api_configuration
from app.services.rescoring import rescore_persisted_risk
from app.workers.scheduler import start_scheduler, stop_scheduler

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    description="Advanced Threat Intelligence & Infrastructure Analysis Platform",
    version="1.0.0",
    debug=settings.app_debug
)

request_log: dict[str, deque[float]] = defaultdict(deque)
allowed_origins = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5174",
    "http://localhost:5174",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)

    # Keep rate limiting out of the way during local auth/CORS debugging.
    if settings.app_env == "development":
        return await call_next(request)

    start = monotonic()
    client_ip = request.client.host if request.client else "unknown"
    now = monotonic()
    window = settings.rate_limit_window_seconds
    limit = settings.rate_limit_requests

    queue = request_log[client_ip]
    while queue and now - queue[0] > window:
        queue.popleft()

    if len(queue) >= limit:
        origin = request.headers.get("origin")
        headers: dict[str, str] = {}
        if origin in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers=headers,
        )

    queue.append(now)
    response = await call_next(request)
    elapsed = (monotonic() - start) * 1000
    logger.info(
        "{method} {path} status={status} ip={ip} duration_ms={duration:.2f}",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        ip=client_ip,
        duration=elapsed,
    )
    return response


@app.on_event("startup")
async def startup() -> None:
    configure_logging()
    validate_external_api_configuration(settings)
    await connect_to_mongo()
    db = get_db()
    await db.users.create_index("email", unique=True)
    
    # Create default analyst user if it doesn't exist
    default_user = await db.users.find_one({"email": "analyst@example.com"})
    if not default_user:
        await db.users.insert_one({
            "email": "analyst@example.com",
            "password_hash": hash_password("ChangeMe123!"),
            "role": "analyst",
            "created_at": datetime.now(timezone.utc),
        })
        logger.info("Default analyst user created: analyst@example.com / ChangeMe123!")
    
    await db.alerts.create_index([("user_id", 1), ("status", 1)])
    await db.findings.create_index([("user_id", 1), ("created_at", -1)])
    await db.findings.create_index([("user_id", 1), ("query", 1)])
    # Unified intelligence indexes
    await db.unified_enrichments.create_index([("user_id", 1), ("created_at", -1)])
    await db.unified_enrichments.create_index([("ioc_value", 1)])
    # Export history indexes
    await db.exports.create_index([("user_id", 1), ("created_at", -1)])
    await db.exports.create_index([("ioc_value", 1)])
    findings_updated, alerts_updated = await rescore_persisted_risk(db)
    logger.info(
        "Rescoring complete findings_updated={findings_updated} alerts_updated={alerts_updated}",
        findings_updated=findings_updated,
        alerts_updated=alerts_updated,
    )
    start_scheduler(db)
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown() -> None:
    stop_scheduler()
    await close_mongo_connection()
    logger.info("Application shutdown complete")


app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(intelligence.router, prefix="/api/v1")
app.include_router(threat_intel.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(monitoring.router, prefix="/api/v1")
app.include_router(stream.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc),
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    response = JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
    )

    origin = request.headers.get("origin")
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"

    return response