import hashlib
import ipaddress
import re
from urllib.parse import urlparse

from loguru import logger

from app.models.threat_intel import IOCType


class IOCNormalizer:
    """Normalize and validate IOCs."""

    # Regex patterns for IOC detection
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
    )
    URL_PATTERN = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
    USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")

    TRUSTED_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "github.com", "stackoverflow.com", "wikipedia.org",
        "cloudflare.com", "amazonaws.com",
    }

    TRUSTED_IPS = {
        "8.8.8.8", "8.8.4.4",  # Google DNS
        "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
        "208.67.222.222", "208.67.220.220",  # OpenDNS
    }

    @staticmethod
    def normalize(value: str) -> str:
        """Normalize IOC value for consistent comparison."""
        if not value:
            return ""
        return value.strip().lower()

    @classmethod
    def detect_ioc_type(cls, value: str) -> IOCType | None:
        """Auto-detect IOC type from value."""
        normalized = cls.normalize(value)
        if not normalized:
            return None

        if cls.MD5_PATTERN.match(normalized):
            return IOCType.HASH_MD5
        if cls.SHA1_PATTERN.match(normalized):
            return IOCType.HASH_SHA1
        if cls.SHA256_PATTERN.match(normalized):
            return IOCType.HASH_SHA256

        try:
            ipaddress.ip_address(normalized)
            return IOCType.IP
        except ValueError:
            pass

        if cls.EMAIL_PATTERN.match(normalized):
            return IOCType.EMAIL

        if cls.URL_PATTERN.match(normalized):
            return IOCType.URL

        if cls.DOMAIN_PATTERN.match(normalized):
            return IOCType.DOMAIN

        if cls.USERNAME_PATTERN.match(normalized):
            return IOCType.USERNAME

        return None

    @classmethod
    def validate_ioc(cls, value: str, ioc_type: IOCType) -> tuple[bool, str]:
        """Validate IOC value against its type."""
        normalized = cls.normalize(value)

        if len(normalized) > 512:
            return False, "IOC value exceeds maximum length (512 characters)"

        if ioc_type == IOCType.IP:
            try:
                ipaddress.ip_address(normalized)
                return True, ""
            except ValueError:
                return False, f"Invalid IP address: {value}"

        if ioc_type == IOCType.DOMAIN:
            if not cls.DOMAIN_PATTERN.match(normalized):
                return False, f"Invalid domain format: {value}"
            return True, ""

        if ioc_type == IOCType.EMAIL:
            if not cls.EMAIL_PATTERN.match(normalized):
                return False, f"Invalid email format: {value}"
            return True, ""

        if ioc_type == IOCType.URL:
            try:
                urlparse(normalized)
                if not cls.URL_PATTERN.match(normalized):
                    return False, f"Invalid URL format: {value}"
                return True, ""
            except Exception as exc:
                return False, f"Invalid URL: {str(exc)}"

        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            if ioc_type == IOCType.HASH_MD5 and not cls.MD5_PATTERN.match(normalized):
                return False, f"Invalid MD5 hash: {value}"
            if ioc_type == IOCType.HASH_SHA1 and not cls.SHA1_PATTERN.match(normalized):
                return False, f"Invalid SHA1 hash: {value}"
            if ioc_type == IOCType.HASH_SHA256 and not cls.SHA256_PATTERN.match(normalized):
                return False, f"Invalid SHA256 hash: {value}"
            return True, ""

        if ioc_type == IOCType.USERNAME:
            if not cls.USERNAME_PATTERN.match(normalized):
                return False, f"Invalid username format: {value}"
            return True, ""

        return False, f"Unsupported IOC type: {ioc_type}"

    @classmethod
    def is_trusted(cls, value: str, ioc_type: IOCType) -> bool:
        """Check if IOC is from a trusted source (to reduce false positives)."""
        normalized = cls.normalize(value)

        if ioc_type == IOCType.DOMAIN:
            for trusted_domain in cls.TRUSTED_DOMAINS:
                if normalized == trusted_domain or normalized.endswith(f".{trusted_domain}"):
                    return True

        if ioc_type == IOCType.IP:
            if normalized in cls.TRUSTED_IPS:
                return True
            try:
                ip = ipaddress.ip_address(normalized)
                if ip.is_private or ip.is_loopback or ip.is_reserved:
                    return True
            except ValueError:
                pass

        return False

    @classmethod
    def extract_domain_from_url(cls, url: str) -> str | None:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            domain = domain.split(":")[0].split("/")[0].strip()
            if domain:
                return cls.normalize(domain)
        except Exception as exc:
            logger.warning("Failed to extract domain from URL: {}", exc)
        return None

    @classmethod
    def extract_domain_from_email(cls, email: str) -> str | None:
        """Extract domain from email."""
        normalized = cls.normalize(email)
        if "@" not in normalized:
            return None
        domain = normalized.split("@", 1)[1]
        return domain if domain else None
