from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.schemas import WatchCreate
from app.workers.tasks import trigger_watch_scan_task

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.post("/watch")
async def create_watch(
    payload: WatchCreate,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    created = {
        "user_id": str(user["_id"]),
        "target": payload.target.strip().lower(),
        "query_type": payload.query_type,
        "interval_minutes": payload.interval_minutes,
        "last_scanned_at": None,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.watches.insert_one(created)
    return {"id": str(result.inserted_id), **created}


@router.get("/watch")
async def list_watches(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    cursor = db.watches.find({"user_id": str(user["_id"])}).sort("created_at", -1)
    items = []
    async for watch in cursor:
        items.append(
            {
                "id": str(watch["_id"]),
                "target": watch["target"],
                "query_type": watch["query_type"],
                "interval_minutes": watch["interval_minutes"],
                "last_scanned_at": watch["last_scanned_at"],
                "created_at": watch["created_at"],
            }
        )
    return items


@router.delete("/watch/{watch_id}")
async def delete_watch(
    watch_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    result = await db.watches.delete_one(
        {"_id": ObjectId(watch_id), "user_id": str(user["_id"])}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Watch target not found")
    return {"message": "Watch target removed"}


@router.post("/trigger")
async def trigger_watch_scan(user: dict = Depends(get_current_user)):
    _ = user
    task = trigger_watch_scan_task.delay()
    return {"message": "Watch scan scheduled", "task_id": task.id}