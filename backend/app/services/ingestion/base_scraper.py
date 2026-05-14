from abc import ABC, abstractmethod


class BaseScraper(ABC):
    source_name: str = "unknown"
    source_type: str = "osint"

    @abstractmethod
    async def collect(self, query: str, query_type: str) -> list[dict]:
        raise NotImplementedError
