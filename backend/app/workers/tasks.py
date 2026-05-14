import asyncio

from loguru import logger

from app.core.database import close_mongo_connection, connect_to_mongo, get_db
from app.services.monitoring import run_watch_scan
from app.workers.celery_app import celery_app


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def trigger_watch_scan_task(self) -> str:
    async def _run() -> None:
        await connect_to_mongo()
        try:
            await run_watch_scan(get_db())
        finally:
            await close_mongo_connection()

    logger.info("Starting background watch scan task")
    asyncio.run(_run())
    logger.info("Background watch scan task complete")
    return "ok"
