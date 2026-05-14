import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.services.events import event_bus

router = APIRouter(prefix="/stream", tags=["stream"])


@router.get("/alerts")
async def stream_alerts():
    queue = event_bus.subscribe()

    async def generator():
        try:
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=20)
                    yield message
                except asyncio.TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            event_bus.unsubscribe(queue)

    return StreamingResponse(generator(), media_type="text/event-stream")
