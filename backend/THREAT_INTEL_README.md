# Dark Web Threat Intelligence Platform

## Overview

A production-grade threat intelligence platform for SOC analysts, threat hunters, and incident responders. Integrates multiple threat intelligence sources to provide comprehensive IOC enrichment, threat scoring, correlation analysis, and investigation automation.

## Architecture

```
backend/
├── app/
│   ├── core/
│   │   ├── config.py              # Configuration, env var loading
│   │   ├── database.py            # MongoDB connection
│   │   ├── security.py            # Auth and security
│   │   └── deps.py                # Dependencies
│   │
│   ├── models/
│   │   ├── schemas.py             # User and general schemas
│   │   └── threat_intel.py        # IOC and threat models
│   │
│   ├── services/
│   │   ├── ingestion/             # External API clients
│   │   │   ├── external_sources.py # VirusTotal, Shodan, IPinfo
│   │   │   └── base_scraper.py
│   │   │
│   │   ├── processor/             # Data processing
│   │   │   ├── ioc_normalizer.py  # IOC validation & normalization
│   │   │   └── normalizer.py
│   │   │
│   │   ├── ioc_enrichment.py      # IOC enrichment orchestration
│   │   ├── threat_scoring.py      # Threat scoring engine
│   │   ├── correlation_engine.py  # IOC correlation & analysis
│   │   └── risk.py
│   │
│   ├── routers/
│   │   ├── threat_intel.py        # Threat intelligence endpoints
│   │   ├── auth.py                # Authentication
│   │   └── intelligence.py
│   │
│   ├── main.py                    # FastAPI application
│   └── tests/
│       ├── test_threat_intel.py   # Threat intel tests
│       ├── test_external_intel.py # API client tests
│       └── test_risk.py
│
├── .env                           # API credentials
├── .env.example                   # Example configuration
└── requirements.txt               # Python dependencies
```

## Key Features

### 1. **IOC Enrichment**
- Automatic IOC type detection (IP, Domain, Email, URL, Hash, etc.)
- Validation and normalization
- Multi-source enrichment with VirusTotal, Shodan, and IPinfo
- Trusted domain/IP detection for false-positive reduction

### 2. **Threat Scoring**
- Comprehensive scoring based on multiple factors
- Malware family severity assessment
- Source reliability weighting
- Confidence level calculation
- Automatic threat level classification

### 3. **IOC Correlation**
- Find relationships between multiple IOCs
- Identify common infrastructure
- Build threat graphs
- Campaign identification
- Investigation recommendations

### 4. **Secure API Integration**
- Masked credential logging
- Automatic retry with exponential backoff
- Timeout protection
- Error resilience
- Rate limit handling

### 5. **Intelligence Features**
- Cross-source correlation
- False-positive reduction
- Threat intelligence aggregation
- Risk categorization
- Automated investigation workflows

## API Endpoints

### IOC Enrichment

```
POST /api/v1/threat-intel/enrich
{
  "ioc_value": "192.168.1.1",
  "ioc_type": "ip",
  "force_refresh": false,
  "include_raw_data": false
}
```

**Response:**
```json
{
  "status": "success",
  "ioc": {
    "ioc_type": "ip",
    "value": "192.168.1.1",
    "threat_level": "high",
    "confidence": "high",
    "risk_score": 75.5,
    "is_malicious": true,
    "malware_families": ["trojan"],
    "sources": ["virustotal", "shodan"],
    "tags": ["high", "ip", "trojan"]
  },
  "sources_queried": ["virustotal", "shodan", "ipinfo"],
  "sources_failed": []
}
```

### Batch Enrichment

```
POST /api/v1/threat-intel/batch-enrich
[
  {"ioc_value": "192.168.1.1"},
  {"ioc_value": "malicious.com"},
  {"ioc_value": "d41d8cd98f00b204e9800998ecf8427e"}
]
```

### IOC Correlation

```
POST /api/v1/threat-intel/correlate
{
  "ioc_values": ["192.168.1.1", "malicious.com", "attacker@example.com"]
}
```

**Response:**
```json
{
  "indicators_analyzed": 3,
  "correlations": {...},
  "infrastructure": {...},
  "threat_graph": {
    "nodes": [...],
    "edges": [...]
  },
  "recommendations": [
    "Multiple high-risk indicators detected. Escalate to incident response team.",
    "Ransomware detected. Isolate affected systems immediately."
  ]
}
```

### Threat Graph

```
GET /api/v1/threat-intel/threat-graph/{ioc_value}
```

### Enrichment History

```
GET /api/v1/threat-intel/enrichments?limit=20
```

## Configuration

### Environment Variables

```bash
# API Credentials
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
IPINFO_TOKEN=your_ipinfo_token

# Retry Configuration
EXTERNAL_API_TIMEOUT_SECONDS=15
EXTERNAL_API_MAX_RETRIES=3
EXTERNAL_API_BACKOFF_SECONDS=0.75

# Application
APP_ENV=production
APP_DEBUG=false
APP_LOG_LEVEL=INFO
```

## Threat Scoring

### Scoring Factors

1. **Detection Ratio** (VirusTotal)
   - Malicious detections × 100
   - Suspicious detections × 50

2. **Source Reliability**
   - VirusTotal: 95%
   - Shodan: 80%
   - IPinfo: 70%
   - Internal DB: 85%

3. **Malware Severity**
   - Ransomware: +95%
   - Trojan: +90%
   - Botnet: +85%
   - Rootkit: +90%

4. **Age Factor**
   - Older than 90 days: 50% reduction

### Threat Levels

- **CRITICAL**: Score ≥ 90
- **HIGH**: Score ≥ 70
- **MEDIUM**: Score ≥ 40
- **LOW**: Score ≥ 20
- **INFO**: Score < 20

### Confidence Levels

- **CERTAIN**: ≥5 malicious detections
- **HIGH**: ≥3 malicious detections
- **MEDIUM**: ≥1 detection + 2 sources
- **LOW**: ≥3 suspicious OR 1 detection + 1 source
- **UNKNOWN**: No detections

## Error Handling

### Implemented Scenarios

- ✅ 401 Unauthorized (invalid API key)
- ✅ 403 Forbidden (quota exceeded)
- ✅ 404 Not Found (missing indicator)
- ✅ 429 Rate Limit (throttled)
- ✅ Timeout (network delay)
- ✅ DNS Failure
- ✅ Invalid JSON
- ✅ Empty responses
- ✅ Malformed data
- ✅ API schema changes

### Retry Strategy

- Exponential backoff starting at 0.75 seconds
- Maximum 3 retry attempts
- 15-second timeout per request
- Automatic retry header parsing

### Logging

All sensitive data is masked:
```
2026-05-13 09:31:30.766 | INFO | virustotal configured via VIRUSTOTAL_API_KEY (5127...9d74)
```

## IOC Validation

### Supported Types

| Type | Pattern | Example |
|------|---------|---------|
| IP | IPv4/IPv6 | 192.168.1.1 |
| DOMAIN | RFC 1035 | example.com |
| EMAIL | RFC 5322 | user@example.com |
| URL | RFC 3986 | https://example.com/path |
| HASH_MD5 | 32 hex chars | d41d8cd98f00b204e9800998ecf8427e |
| HASH_SHA1 | 40 hex chars | aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d |
| HASH_SHA256 | 64 hex chars | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| USERNAME | 3-32 alphanumeric | admin123 |

### Trusted Sources

**Domains:**
- google.com, microsoft.com, apple.com
- github.com, stackoverflow.com
- cloudflare.com, amazonaws.com

**IPs:**
- 8.8.8.8 (Google DNS)
- 1.1.1.1 (Cloudflare DNS)
- Private/loopback ranges

## Testing

Run all tests:
```bash
pytest app/tests/ -v
```

Run specific test suite:
```bash
pytest app/tests/test_threat_intel.py -v
```

Test coverage:
```
21 tests passing
├── IOC Normalization (5 tests)
├── Threat Scoring (4 tests)
├── Correlation Engine (2 tests)
├── External API Clients (5 tests)
└── Risk Scoring (5 tests)
```

## Security Considerations

1. **Secret Management**
   - Never log full API keys
   - Use environment variables
   - Validate before use
   - Mask in debug output

2. **API Security**
   - All requests use HTTPS
   - Bearer token authentication
   - Custom API key headers per provider
   - Timeout protection

3. **Data Validation**
   - Input validation for all IOCs
   - JSON schema validation
   - Response format checking
   - Maximum length limits

4. **Rate Limiting**
   - Per-endpoint rate limiting
   - Automatic backoff
   - Retry-After header support

## Performance Optimization

1. **Batch Processing**
   - Support for up to 100 IOCs per batch
   - Async/await for parallel enrichment
   - Connection pooling

2. **Caching**
   - Enrichment history in MongoDB
   - Configurable refresh intervals

3. **Efficient Scoring**
   - Single-pass calculation
   - Early exit optimization
   - Confidence pre-computation

## Usage Examples

### Python Client Example

```python
import requests

API_URL = "http://127.0.0.1:8000/api/v1"
TOKEN = "your_auth_token"

# Login
response = requests.post(
    f"{API_URL}/auth/login",
    json={"email": "user@example.com", "password": "password"}
)
token = response.json()["access_token"]

# Enrich IOC
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    f"{API_URL}/threat-intel/enrich",
    json={"ioc_value": "192.168.1.1", "ioc_type": "ip"},
    headers=headers
)

print(response.json())
```

### CURL Example

```bash
# Login
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Enrich IOC
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/enrich \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ioc_value":"192.168.1.1"}'
```

## Monitoring & Logs

Structured logging with loguru:
```
2026-05-13 09:31:30.766 | INFO | app.services.ingestion.external_sources:validate_external_api_configuration:471
IOC enriched: user=user@example.com, ioc=192.168.1.1, status=success
```

## Production Deployment

1. **Setup**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with real API credentials
   ```

3. **Start Server**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

4. **Database**
   - MongoDB connection required
   - Indexes automatically created
   - Collections: users, findings, enrichments, queries

## Troubleshooting

### API Key Issues
```
Missing VIRUSTOTAL_API_KEY: Set VIRUSTOTAL_API_KEY in your .env file.
```

### Rate Limiting
- VirusTotal: 4 requests per minute (free tier)
- Shodan: API plan dependent
- IPinfo: 50,000 requests/month (free tier)

### Timeout Issues
- Increase `EXTERNAL_API_TIMEOUT_SECONDS` in .env
- Check network connectivity
- Verify API provider status

## Future Enhancements

- [ ] Machine learning-based threat scoring
- [ ] Dark web source integration
- [ ] Automated incident response workflows
- [ ] GraphQL API support
- [ ] Real-time alerting
- [ ] MISP integration
- [ ] Custom IOC rules engine
- [ ] Threat actor attribution

## Support & Contributing

For issues, security reports, or feature requests, contact the security team.

## License

Proprietary - Internal Use Only

---

**Last Updated:** May 13, 2026
**Status:** Production-Ready
**Version:** 1.0.0
