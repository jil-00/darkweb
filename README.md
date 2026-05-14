# Threat Intelligence and Dark Web Monitoring Platform

Production-oriented mini SIEM platform for legal OSINT and simulated dark web intelligence.

## Product Scope

- Ingest OSINT and simulated leak data continuously
- Process and correlate raw intelligence into actionable findings
- Score risk dynamically with configurable source/sensitivity weights
- Visualize intelligence in a live dashboard with alert streaming

## Stack

- Frontend: React + TypeScript + Tailwind + Vite
- Backend: FastAPI (async)
- Database: MongoDB
- Queue: Celery + Redis
- Reverse Proxy: Nginx
- Logging: loguru
- Deployment: Docker Compose

## Architecture

- backend/app/services/ingestion/
  - base_scraper.py
  - breach_api.py
  - paste_monitor.py
- backend/app/services/processor/
  - parser.py
  - entity_extractor.py
  - normalizer.py
- backend/app/services/risk.py (configurable weights)
- backend/app/workers/
  - scheduler.py
  - celery_app.py
  - tasks.py
- backend/app/routers/
  - auth.py
  - scan.py
  - alerts.py
  - dashboard.py
  - monitoring.py
  - stream.py

## Core API

Base path: /api/v1

- Auth
  - POST /auth/register
  - POST /auth/login
- Scan and Results
  - POST /scan
  - GET /results/{query}
- Intelligence compatibility
  - POST /intel/search
  - GET /intel/history
- Alerts
  - GET /alerts
  - PATCH /alerts/{alert_id}/ack
- Monitoring
  - POST /monitoring/watch
  - GET /monitoring/watch
  - DELETE /monitoring/watch/{watch_id}
  - POST /monitoring/trigger
- Live stream
  - GET /stream/alerts (SSE)
- Health
  - GET /health

## Data Flow

1. User submits query
2. API validates input and authenticates user
3. Scan runs ingestion connectors
4. Processing engine normalizes + extracts entities + deduplicates
5. Risk score calculated from source_weight x frequency x sensitivity
6. Findings persisted in MongoDB
7. Alerts generated if threshold exceeded
8. SSE pushes live alert event to frontend

## Security and Reliability

- JWT authentication
- Request rate limiting middleware
- Input validation via Pydantic schemas
- Retry-enabled Celery tasks
- Request and lifecycle logs via loguru

## Running Locally (without Docker)

### Backend

1. Create and activate virtual env
2. Install dependencies
   - pip install -r backend/requirements.txt
3. Create environment file
   - copy backend/.env.example backend/.env
4. Run API
   - uvicorn app.main:app --reload --app-dir backend

### Frontend

1. Install dependencies
   - cd frontend
   - npm install
2. Start dev server
   - npm run dev
3. Open
   - http://localhost:5173

Important: opening http://127.0.0.1:5500 means Live Server is showing folder listing, not the React app.

## Running with Docker Compose

1. Create backend/.env from backend/.env.example
2. Start stack
   - docker compose up --build
3. Open Nginx endpoint
   - http://localhost

Services:
- nginx (public)
- frontend
- backend
- celery-worker
- redis
- mongodb

## Ethics and Compliance

- Only legal OSINT and simulated sources are used
- No unauthorized access or illegal scraping
- Educational and defensive cybersecurity purpose only
