from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.services.monitoring import run_watch_scan

scheduler: AsyncIOScheduler | None = None


def start_scheduler(db) -> None:
    global scheduler
    if scheduler is not None and scheduler.running:
        return

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(run_watch_scan, "interval", minutes=10, kwargs={"db": db})
    scheduler.start()


def stop_scheduler() -> None:
    global scheduler
    if scheduler is not None and scheduler.running:
        scheduler.shutdown(wait=False)
    scheduler = None