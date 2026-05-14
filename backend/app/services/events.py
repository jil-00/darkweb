import asyncio
import json


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()

    def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)

    async def publish(self, payload: dict) -> None:
        message = f"data: {json.dumps(payload, default=str)}\n\n"
        for queue in list(self._subscribers):
            await queue.put(message)


event_bus = EventBus()
