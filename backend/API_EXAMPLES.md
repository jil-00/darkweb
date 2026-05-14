# API Testing & Examples

## Quick Start

### 1. Register User
```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@company.com",
    "password": "SecurePassword123!",
    "role": "user"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 2. Login
```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@company.com",
    "password": "SecurePassword123!"
  }'
```

Save the `access_token` for subsequent requests.

### 3. Enrich Single IOC
```bash
TOKEN="your_access_token_here"

# IP Address Enrichment
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/enrich \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "192.168.1.1",
    "ioc_type": "ip",
    "include_raw_data": false
  }'

# Domain Enrichment
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/enrich \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "example-malware.com",
    "ioc_type": "domain"
  }'

# File Hash Enrichment
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/enrich \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
    "ioc_type": "hash_md5"
  }'

# Auto-detect IOC Type
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/enrich \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "attacker@malicious-domain.com"
  }'
```

### 4. Batch Enrich Multiple IOCs
```bash
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/batch-enrich \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {"ioc_value": "192.168.1.1"},
    {"ioc_value": "malicious.com"},
    {"ioc_value": "attacker@example.com"},
    {"ioc_value": "d41d8cd98f00b204e9800998ecf8427e"},
    {"ioc_value": "https://malicious-site.com/payload.exe"}
  ]'
```

Response:
```json
{
  "total": 5,
  "enriched": 5,
  "results": [
    {
      "status": "success",
      "ioc": {
        "ioc_type": "ip",
        "value": "192.168.1.1",
        "threat_level": "high",
        "risk_score": 75.5,
        "is_malicious": true
      }
    },
    ...
  ]
}
```

### 5. Correlate Multiple IOCs
```bash
curl -X POST http://127.0.0.1:8000/api/v1/threat-intel/correlate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_values": [
      "192.168.1.100",
      "attacker.com",
      "attacker@attacker.com",
      "c2-server.net"
    ]
  }'
```

Response includes:
- Correlations between IOCs
- Shared infrastructure
- Threat graph visualization data
- Investigation recommendations

### 6. Get Threat Graph
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/threat-intel/threat-graph/malicious.com" \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "ioc": "malicious.com",
  "threat_level": "high",
  "risk_score": 82.5,
  "graph": {
    "nodes": [
      {
        "id": "domain:malicious.com",
        "label": "malicious.com",
        "type": "domain",
        "threat_level": "high",
        "risk_score": 82.5
      },
      {
        "id": "ip:192.168.1.100",
        "label": "192.168.1.100",
        "type": "ip",
        "threat_level": "medium"
      }
    ],
    "edges": [
      {
        "source": "domain:malicious.com",
        "target": "ip:192.168.1.100",
        "weight": 0.85
      }
    ]
  }
}
```

### 7. Get Enrichment History
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/threat-intel/enrichments?limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

## Python Client Example

```python
import requests
import json

class ThreatIntelClient:
    def __init__(self, base_url="http://127.0.0.1:8000", email=None, password=None):
        self.base_url = base_url
        self.session = requests.Session()
        
        if email and password:
            self.authenticate(email, password)
    
    def authenticate(self, email, password):
        """Login and store token."""
        response = self.session.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {token}"})
    
    def enrich_ioc(self, ioc_value, ioc_type=None, include_raw_data=False):
        """Enrich a single IOC."""
        response = self.session.post(
            f"{self.base_url}/api/v1/threat-intel/enrich",
            json={
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "include_raw_data": include_raw_data
            }
        )
        response.raise_for_status()
        return response.json()
    
    def batch_enrich(self, ioc_values):
        """Enrich multiple IOCs."""
        requests_list = [{"ioc_value": ioc} for ioc in ioc_values]
        response = self.session.post(
            f"{self.base_url}/api/v1/threat-intel/batch-enrich",
            json=requests_list
        )
        response.raise_for_status()
        return response.json()
    
    def correlate_iocs(self, ioc_values):
        """Find correlations between IOCs."""
        response = self.session.post(
            f"{self.base_url}/api/v1/threat-intel/correlate",
            json={"ioc_values": ioc_values}
        )
        response.raise_for_status()
        return response.json()
    
    def get_threat_graph(self, ioc_value):
        """Get threat graph for IOC."""
        response = self.session.get(
            f"{self.base_url}/api/v1/threat-intel/threat-graph/{ioc_value}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_history(self, limit=20):
        """Get enrichment history."""
        response = self.session.get(
            f"{self.base_url}/api/v1/threat-intel/enrichments",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()

# Usage Example
if __name__ == "__main__":
    client = ThreatIntelClient(
        email="analyst@company.com",
        password="SecurePassword123!"
    )
    
    # Enrich single IOC
    result = client.enrich_ioc("malicious.com")
    print(f"Threat Level: {result['ioc']['threat_level']}")
    print(f"Risk Score: {result['ioc']['risk_score']}")
    
    # Batch enrich
    results = client.batch_enrich([
        "192.168.1.100",
        "attacker.com",
        "attacker@example.com"
    ])
    print(f"Enriched {results['enriched']} out of {results['total']} IOCs")
    
    # Correlate
    correlations = client.correlate_iocs([
        "192.168.1.100",
        "attacker.com"
    ])
    print(f"Found {len(correlations['infrastructure'])} infrastructure items")
```

## Expected Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (invalid IOC) |
| 401 | Unauthorized (invalid token) |
| 403 | Forbidden (not admin) |
| 404 | Not found |
| 429 | Rate limited |
| 500 | Server error |

## Performance Metrics

### Response Times (typical)
- Single IOC enrichment: 2-5 seconds
- Batch (10 IOCs): 10-15 seconds
- Correlation analysis: 5-10 seconds
- Threat graph generation: 2-4 seconds

### Throughput
- ~20 enrichments per minute per user
- ~100 enrichments per minute per server
- Batch limit: 100 IOCs per request

## Troubleshooting

### 401 Unauthorized
```
Token expired or invalid. Re-authenticate.
```

### 429 Too Many Requests
```
API rate limit exceeded. Wait and retry.
```

### 500 Server Error
```
Check logs: docker logs threat-intel-api
```

### Empty Response
```
IOC may be benign or trusted source. Check logs for details.
```

---

**Last Updated:** May 13, 2026
