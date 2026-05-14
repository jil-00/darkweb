import asyncio

from loguru import logger

from app.services.ingestion.base_scraper import BaseScraper
from app.services.ingestion.breach_api import BreachAPIConnector
from app.services.ingestion.external_sources import (
    IPinfoConnector,
    ShodanConnector,
    VirusTotalConnector,
)
from app.services.ingestion.paste_monitor import PasteMonitor


async def collect_from_sources(query: str, query_type: str) -> list[dict]:
    collectors: list[BaseScraper] = [
        VirusTotalConnector(),
        ShodanConnector(),
        IPinfoConnector(),
        BreachAPIConnector(),
        PasteMonitor(),
    ]
    results: list[dict] = []

    collected = await asyncio.gather(
        *(collector.collect(query=query, query_type=query_type) for collector in collectors),
        return_exceptions=True,
    )

    for collector, rows in zip(collectors, collected, strict=True):
        if isinstance(rows, Exception):
            logger.warning(
                "collector {} failed for query_type={} error={}",
                collector.source_name,
                query_type,
                rows,
            )
            continue
        results.extend(rows)
    return results
