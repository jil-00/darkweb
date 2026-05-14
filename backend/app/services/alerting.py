from datetime import datetime, timezone

from app.services.events import event_bus


async def maybe_create_alert(
    db,
    user_id: str,
    query: str,
    risk_score: float,
    threshold: float,
) -> None:
    if risk_score < threshold:
        return

    await db.alerts.insert_one(
        {
            "user_id": user_id,
            "query": query,
            "risk_score": risk_score,
            "reason": f"Risk score exceeded threshold ({threshold})",
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await event_bus.publish(
        {
            "event": "alert_created",
            "user_id": user_id,
            "query": query,
            "risk_score": risk_score,
            "threshold": threshold,
        }
    )