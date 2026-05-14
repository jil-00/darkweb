from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.database import get_db
from app.core.deps import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    status: str | None = None,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    query = {"user_id": str(user["_id"])}
    if status in {"open", "acknowledged"}:
        query["status"] = status

    cursor = db.alerts.find(query).sort("created_at", -1).limit(50)
    items = []
    async for alert in cursor:
        items.append(
            {
                "id": str(alert["_id"]),
                "query": alert["query"],
                "risk_score": alert["risk_score"],
                "reason": alert["reason"],
                "status": alert["status"],
                "created_at": alert["created_at"],
            }
        )
    return items


@router.patch("/{alert_id}/ack")
async def acknowledge_alert(
    alert_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    result = await db.alerts.update_one(
        {"_id": ObjectId(alert_id), "user_id": str(user["_id"])},
        {"$set": {"status": "acknowledged"}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert acknowledged"}