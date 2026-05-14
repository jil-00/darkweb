from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import requests
from loguru import logger
from requests import Response
from requests.exceptions import RequestException, Timeout

from app.core.config import Settings, get_settings
from app.services.ingestion.base_scraper import BaseScraper


@dataclass(slots=True)
class ExternalAPIError(Exception):
    provider: str
    message: str
    status_code: int | None = None

    def __str__(self) -> str:
        if self.status_code is None:
            return f"{self.provider}: {self.message}"
        return f"{self.provider} ({self.status_code}): {self.message}"


class MissingAPIKeyError(ExternalAPIError):
    pass


class APIAuthError(ExternalAPIError):
    pass


class APIRateLimitError(ExternalAPIError):
    pass


class APIResponseFormatError(ExternalAPIError):
    pass


class APITimeoutError(ExternalAPIError):
    pass


class BaseExternalCollector(BaseScraper):
    provider_name = "external"
    source_type = "api"
    env_var_name = ""
    key_attribute_name = ""
    timeout_header = "User-Agent"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.session = requests.Session()

    @property
    def api_key(self) -> str:
        value = getattr(self.settings, self.key_attribute_name, None)
        return (value or "").strip()

    def _mask_secret(self, value: str) -> str:
        if len(value) <= 8:
            return "*" * max(4, len(value))
        return f"{value[:4]}...{value[-4:]}"

    def _log_configuration(self) -> None:
        if self.api_key:
            logger.debug(
                "{} API key loaded: {}",
                self.provider_name,
                self._mask_secret(self.api_key),
            )
        else:
            logger.warning(
                "{} disabled because {} is missing or empty",
                self.provider_name,
                self.env_var_name,
            )

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        timeout = self.settings.external_api_timeout_seconds
        attempts = max(1, self.settings.external_api_max_retries)
        base_delay = max(0.1, self.settings.external_api_backoff_seconds)

        for attempt in range(1, attempts + 1):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    timeout=timeout,
                )
            except Timeout as exc:
                if attempt >= attempts:
                    raise APITimeoutError(self.provider_name, "request timed out") from exc
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "{} timeout on attempt {}/{}; retrying in {:.2f}s",
                    self.provider_name,
                    attempt,
                    attempts,
                    delay,
                )
                time.sleep(delay)
                continue
            except RequestException as exc:
                if attempt >= attempts:
                    raise ExternalAPIError(self.provider_name, "network request failed") from exc
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "{} network error on attempt {}/{}; retrying in {:.2f}s",
                    self.provider_name,
                    attempt,
                    attempts,
                    delay,
                )
                time.sleep(delay)
                continue

            if response.status_code in (401, 403):
                raise APIAuthError(
                    self.provider_name,
                    "authentication failed",
                    status_code=response.status_code,
                )

            if response.status_code == 429:
                if attempt >= attempts:
                    raise APIRateLimitError(
                        self.provider_name,
                        "rate limit exceeded",
                        status_code=response.status_code,
                    )
                retry_after = self._retry_after_seconds(response)
                delay = max(retry_after, base_delay * (2 ** (attempt - 1)))
                logger.warning(
                    "{} rate limited on attempt {}/{}; retrying in {:.2f}s",
                    self.provider_name,
                    attempt,
                    attempts,
                    delay,
                )
                time.sleep(delay)
                continue

            if 500 <= response.status_code < 600:
                if attempt >= attempts:
                    raise ExternalAPIError(
                        self.provider_name,
                        f"upstream error {response.status_code}",
                        status_code=response.status_code,
                    )
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "{} upstream error {}; retrying in {:.2f}s",
                    self.provider_name,
                    response.status_code,
                    delay,
                )
                time.sleep(delay)
                continue

            return self._decode_response(response)

        raise ExternalAPIError(self.provider_name, "request failed after retries")

    def _retry_after_seconds(self, response: Response) -> float:
        retry_after = response.headers.get("Retry-After", "0")
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            return 0.0

    def _decode_response(self, response: Response) -> dict[str, Any] | list[Any]:
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower():
            raise APIResponseFormatError(
                self.provider_name,
                f"unexpected content type: {content_type or 'unknown'}",
                status_code=response.status_code,
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise APIResponseFormatError(
                self.provider_name,
                "response was not valid JSON",
                status_code=response.status_code,
            ) from exc

        if payload in ({}, [], None):
            raise APIResponseFormatError(
                self.provider_name,
                "response payload was empty",
                status_code=response.status_code,
            )

        if not isinstance(payload, (dict, list)):
            raise APIResponseFormatError(
                self.provider_name,
                "response payload had an unsupported structure",
                status_code=response.status_code,
            )

        return payload

    def _normalize_domain_target(self, query: str, query_type: str) -> str | None:
        if query_type == "email" and "@" in query:
            return query.split("@", 1)[1].strip().lower()
        if query_type == "domain":
            return query.strip().lower()
        if query_type == "username":
            return None
        return query.strip().lower() or None

    def _resolve_target_kind(self, value: str | None) -> str | None:
        if not value:
            return None
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            return "domain"

    def _build_finding(
        self,
        *,
        query: str,
        payload: dict[str, Any],
        occurrences: int,
        confidence: float,
        contains_password: bool = False,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "source": self.provider_name,
            "source_type": self.source_type,
            "query": query,
            "data_type": "api",
            "payload": {
                "match": query,
                "occurrences": max(1, int(occurrences)),
                "contains_password": contains_password,
                "confidence": round(max(0.0, min(confidence, 1.0)), 2),
                "provider_payload": payload,
            },
            "first_seen": first_seen or now - timedelta(days=1),
            "last_seen": last_seen or now,
        }

    async def collect(self, query: str, query_type: str) -> list[dict]:
        return await asyncio.to_thread(self.collect_sync, query, query_type)

    def collect_sync(self, query: str, query_type: str) -> list[dict]:
        raise NotImplementedError


class VirusTotalConnector(BaseExternalCollector):
    source_name = "virustotal"
    provider_name = "virustotal"
    env_var_name = "VIRUSTOTAL_API_KEY"
    key_attribute_name = "virustotal_api_key"

    def collect_sync(self, query: str, query_type: str) -> list[dict]:
        self._log_configuration()
        if not self.api_key:
            return []

        target = self._normalize_domain_target(query, query_type)
        target_kind = self._resolve_target_kind(target)
        if not target or not target_kind or query_type == "username":
            return []

        endpoint = f"https://www.virustotal.com/api/v3/{'ip_addresses' if target_kind == 'ip' else 'domains'}/{quote(target, safe='')}"
        payload = self._request_json(
            "GET",
            endpoint,
            headers={"x-apikey": self.api_key},
        )
        if not isinstance(payload, dict):
            return []

        data = payload.get("data")
        if not isinstance(data, dict):
            raise APIResponseFormatError(self.provider_name, "missing data object in response")

        attributes = data.get("attributes", {})
        if not isinstance(attributes, dict):
            raise APIResponseFormatError(self.provider_name, "missing attributes in response")

        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            raise APIResponseFormatError(self.provider_name, "missing analysis stats in response")

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        occurrences = malicious + suspicious
        if occurrences <= 0:
            return []

        total_scans = sum(int(value or 0) for value in stats.values()) or 1
        confidence = (malicious + (suspicious * 0.5)) / total_scans
        first_seen = attributes.get("first_submission_date")
        last_seen = attributes.get("last_modification_date")
        return [
            self._build_finding(
                query=target,
                payload={"attributes": attributes, "analysis_stats": stats},
                occurrences=occurrences,
                confidence=confidence,
                first_seen=datetime.fromtimestamp(first_seen, tz=timezone.utc)
                if isinstance(first_seen, (int, float))
                else None,
                last_seen=datetime.fromtimestamp(last_seen, tz=timezone.utc)
                if isinstance(last_seen, (int, float))
                else None,
            )
        ]


class ShodanConnector(BaseExternalCollector):
    source_name = "shodan"
    provider_name = "shodan"
    env_var_name = "SHODAN_API_KEY"
    key_attribute_name = "shodan_api_key"

    def collect_sync(self, query: str, query_type: str) -> list[dict]:
        self._log_configuration()
        if not self.api_key:
            return []

        target = self._normalize_domain_target(query, query_type)
        if not target or query_type == "username":
            return []

        query_text = f'hostname:"{target}"'
        target_kind = self._resolve_target_kind(target)
        if target_kind == "ip":
            query_text = f'ip:"{target}"'

        payload = self._request_json(
            "GET",
            "https://api.shodan.io/shodan/host/search",
            params={"key": self.api_key, "query": query_text},
        )
        if not isinstance(payload, dict):
            return []

        matches = payload.get("matches", [])
        if not isinstance(matches, list):
            raise APIResponseFormatError(self.provider_name, "matches field must be a list")

        total = int(payload.get("total") or len(matches) or 0)
        if total <= 0:
            return []

        top_match = matches[0] if matches else {}
        if not isinstance(top_match, dict):
            top_match = {}

        open_ports = sorted(
            {
                int(match.get("port"))
                for match in matches
                if isinstance(match, dict) and str(match.get("port", "")).isdigit()
            }
        )
        confidence = min(1.0, total / 10.0)
        return [
            self._build_finding(
                query=target,
                payload={
                    "total": total,
                    "open_ports": open_ports[:10],
                    "top_match": top_match,
                },
                occurrences=max(1, min(total, 10)),
                confidence=confidence,
            )
        ]


class IPinfoConnector(BaseExternalCollector):
    source_name = "ipinfo"
    provider_name = "ipinfo"
    env_var_name = "IPINFO_TOKEN"
    key_attribute_name = "ipinfo_token"

    def collect_sync(self, query: str, query_type: str) -> list[dict]:
        self._log_configuration()
        if not self.api_key:
            return []

        target = self._normalize_domain_target(query, query_type)
        if not target or query_type == "username":
            return []

        payload = self._request_json(
            "GET",
            f"https://ipinfo.io/{quote(target, safe='')}/json",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        if not isinstance(payload, dict):
            return []

        privacy = payload.get("privacy", {})
        abuse = payload.get("abuse", {})
        if not isinstance(privacy, dict):
            privacy = {}
        if not isinstance(abuse, dict):
            abuse = {}

        risk_flags = [
            bool(privacy.get("vpn")),
            bool(privacy.get("proxy")),
            bool(privacy.get("tor")),
            bool(privacy.get("relay")),
            bool(privacy.get("hosting")),
            bool(abuse.get("is_abuse")),
        ]
        occurrences = sum(1 for flag in risk_flags if flag)
        if occurrences <= 0:
            return []

        confidence = min(1.0, occurrences / len(risk_flags))
        return [
            self._build_finding(
                query=target,
                payload={
                    "ipinfo": payload,
                    "privacy": privacy,
                    "abuse": abuse,
                },
                occurrences=occurrences,
                confidence=confidence,
                contains_password=False,
            )
        ]


def validate_external_api_configuration(settings: Settings | None = None) -> dict[str, bool]:
    current_settings = settings or get_settings()
    provider_status = current_settings.external_api_status()
    key_mapping = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "shodan": "SHODAN_API_KEY",
        "ipinfo": "IPINFO_TOKEN",
    }

    for provider, configured in provider_status.items():
        env_var = key_mapping[provider]
        if configured:
            logger.info(
                "{} configured via {} ({})",
                provider,
                env_var,
                _masked_value(getattr(current_settings, f"{provider}_api_key", None) if provider != "ipinfo" else current_settings.ipinfo_token),
            )
        else:
            logger.warning("{} is missing. Set {} in your .env file.", provider, env_var)
    return provider_status


def _masked_value(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return "missing"
    if len(text) <= 8:
        return "*" * max(4, len(text))
    return f"{text[:4]}...{text[-4:]}"
