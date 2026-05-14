# Security & Hardening Guide

## API Key Security

### Storage
```python
# ✅ CORRECT: Use python-dotenv
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("VIRUSTOTAL_API_KEY")

# ❌ WRONG: Hardcoded keys
api_key = "5127b504d1a60190798d08f3d379fa896e2c76a906fc83215de1e354b81f9d74"
```

### Validation
```python
if not api_key or not api_key.strip():
    logger.error("Missing VIRUSTOTAL_API_KEY in .env file")
    raise MissingAPIKeyError("VIRUSTOTAL_API_KEY not configured")
```

### Logging
```python
# ✅ CORRECT: Masked logging
def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * max(4, len(value))
    return f"{value[:4]}...{value[-4:]}"

logger.info("API key loaded: {}", _mask_secret(api_key))

# ❌ WRONG: Full key in logs
logger.info("API key: {}", api_key)
```

## Request Handling

### Timeout Protection
```python
# ✅ CORRECT: All requests have timeout
response = session.request(
    method="GET",
    url="https://api.virustotal.com/...",
    timeout=15.0
)

# ❌ WRONG: No timeout
response = requests.get(url)  # Can hang indefinitely
```

### Error Handling
```python
# ✅ CORRECT: Handle all scenarios
try:
    response = session.request(...)
    if response.status_code == 401:
        raise APIAuthError("Invalid API key")
    elif response.status_code == 429:
        raise APIRateLimitError("Rate limited")
    elif response.status_code >= 500:
        raise ExternalAPIError("Server error")
except Timeout:
    raise APITimeoutError("Request timeout")
except RequestException as exc:
    raise ExternalAPIError("Network error") from exc

# ❌ WRONG: Silent failures
try:
    response = requests.get(url)
except:
    pass
```

## Data Validation

### Input Validation
```python
# ✅ CORRECT: Validate IOC before use
ioc_type = IOCNormalizer.detect_ioc_type(ioc_value)
is_valid, error = IOCNormalizer.validate_ioc(ioc_value, ioc_type)

if not is_valid:
    raise ValueError(f"Invalid IOC: {error}")

# ❌ WRONG: Direct use without validation
result = virustotal.check(ioc_value)
```

### Response Validation
```python
# ✅ CORRECT: Validate response structure
def _decode_response(response):
    if "json" not in response.headers.get("content-type", ""):
        raise APIResponseFormatError("Unexpected content type")
    
    try:
        payload = response.json()
    except ValueError:
        raise APIResponseFormatError("Invalid JSON")
    
    if not payload or payload in ({}, [], None):
        raise APIResponseFormatError("Empty response")
    
    if not isinstance(payload, (dict, list)):
        raise APIResponseFormatError("Invalid structure")
    
    return payload

# ❌ WRONG: Direct access without validation
data = response.json()
analysis_stats = data["data"]["attributes"]["last_analysis_stats"]  # KeyError
```

## Retry Logic

### Exponential Backoff
```python
# ✅ CORRECT: Smart retry with backoff
for attempt in range(1, max_retries + 1):
    try:
        response = session.request(...)
        return response
    except Timeout:
        if attempt >= max_retries:
            raise
        delay = backoff_seconds * (2 ** (attempt - 1))
        time.sleep(delay)

# ❌ WRONG: No backoff or infinite loop
while True:
    try:
        response = requests.get(url)
    except:
        pass  # Infinite retry
```

### Retry-After Header
```python
# ✅ CORRECT: Respect rate limit headers
def _retry_after_seconds(response):
    retry_after = response.headers.get("Retry-After", "0")
    try:
        return max(0.0, float(retry_after))
    except ValueError:
        return 0.0

retry_delay = _retry_after_seconds(response)
time.sleep(retry_delay)

# ❌ WRONG: Ignore rate limits
time.sleep(1)  # Fixed delay
```

## Authentication

### Bearer Token
```python
# ✅ CORRECT: Pass token in Authorization header
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(url, headers=headers)

# ❌ WRONG: Pass in query string (logged in URLs)
response = requests.get(f"{url}?token={token}")
```

### API Key Headers
```python
# ✅ CORRECT: Provider-specific headers
if provider == "virustotal":
    headers = {"x-apikey": api_key}  # VirusTotal requirement
elif provider == "shodan":
    params = {"key": api_key}  # Shodan query parameter
elif provider == "ipinfo":
    headers = {"Authorization": f"Bearer {api_key}"}
```

## Malicious Data Handling

### Empty Response Detection
```python
# ✅ CORRECT: Handle empty gracefully
if not findings or findings == []:
    logger.info("No threat intelligence available")
    return IOCIndicator(threat_level=ThreatLevel.INFO)

# ❌ WRONG: IndexError crash
return findings[0]  # Crashes if findings empty
```

### Type Checking
```python
# ✅ CORRECT: Verify types before use
attributes = payload.get("data", {})
if not isinstance(attributes, dict):
    raise APIResponseFormatError("Invalid attributes structure")

stats = attributes.get("last_analysis_stats", {})
if not isinstance(stats, dict):
    raise APIResponseFormatError("Missing analysis stats")

# ❌ WRONG: Assume structure
stats = payload["data"]["attributes"]["last_analysis_stats"]
```

## Deployment Security

### Environment Variables
```bash
# ✅ CORRECT: .env file (not committed)
.env
.env.example

# ❌ WRONG: Committed credentials
config.py with API_KEY = "..."
```

### Production Settings
```python
# ✅ CORRECT: Production-safe settings
if APP_ENV == "production":
    APP_DEBUG = False
    APP_LOG_LEVEL = "WARNING"  # Don't expose stack traces
    
# ❌ WRONG: Debug enabled in production
APP_DEBUG = True
APP_LOG_LEVEL = "DEBUG"
```

### CORS Configuration
```python
# ✅ CORRECT: Specific allowed origins
allowed_origins = [
    "https://threat-intel.company.com",
    "https://soc.company.com",
]

# ❌ WRONG: Allow all origins
allowed_origins = ["*"]
```

## Monitoring

### Audit Logging
```python
# ✅ CORRECT: Log all enrichment requests
logger.info(
    "IOC enriched: user={}, ioc={}, status={}, sources={}",
    user_email,
    ioc_value,
    status,
    sources
)

# ✅ CORRECT: Log API failures
logger.warning(
    "API failure: provider={}, status_code={}, attempt={}",
    provider_name,
    status_code,
    attempt_number
)
```

### Alerting
```python
# ✅ CORRECT: Alert on critical issues
if response_code == 401:
    alert_security_team("API authentication failed")
    
if malicious_count >= 50:
    alert_security_team(f"High-risk IOC detected: {ioc}")
```

## Threat Modeling

### Attack Vectors Mitigated

| Vector | Mitigation |
|--------|-----------|
| API Key Exposure | Masked logging, env vars, .env.example |
| MITM Attack | HTTPS enforcement, timeout protection |
| DoS Attack | Rate limiting, timeout per request |
| Malformed Input | Input validation, type checking |
| Malicious Response | Response validation, schema checking |
| API Quota Abuse | Retry-After parsing, exponential backoff |
| Crash on Bad Data | Type guards, try-except handlers |
| Information Disclosure | Debug mode disabled in production |
| Credential Spraying | Rate limiting, request queuing |

## Compliance

### Data Protection
- ✅ GDPR: No personal data stored in cache
- ✅ SOC 2: Audit logging enabled
- ✅ ISO 27001: Encrypted credentials

### Incident Response
- ✅ API key rotation: Update .env and redeploy
- ✅ API compromise: Revoke key immediately
- ✅ Service outage: Automatic failover to cached data

## Security Checklist

Before production deployment:

- [ ] All API keys in .env (not in code)
- [ ] .env file in .gitignore
- [ ] .env.example created without secrets
- [ ] Logging masks all sensitive data
- [ ] All external requests have timeout
- [ ] All responses validated before use
- [ ] Error messages don't leak secrets
- [ ] CORS restricted to known origins
- [ ] Debug mode disabled
- [ ] Audit logging enabled
- [ ] Rate limiting configured
- [ ] HTTPS enforced in production
- [ ] Database backups configured
- [ ] Monitoring and alerting active
- [ ] Security headers configured
- [ ] Input validation comprehensive
- [ ] Retry logic has max attempts
- [ ] Tests cover error scenarios
- [ ] Documentation updated
- [ ] Security review completed

---

**Last Updated:** May 13, 2026
