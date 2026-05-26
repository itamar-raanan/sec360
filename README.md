# SEC360 - Security Visibility Platform

A full-stack security visibility platform that aggregates data from SentinelOne, Symantec, Prisma Access, Google Workspace, and HiBob HR to provide unified security visibility.

## Architecture

- **Backend**: FastAPI + SQLAlchemy (async) + PostgreSQL
- **Frontend**: React + TypeScript + Vite + TailwindCSS
- **Data Collection**: APScheduler-based collectors with retry logic
- **Engines**: Correlation, Compliance, Risk Scoring, Behavioral Analysis

## Quick Start

### 1. Start services with Docker Compose

```bash
cp .env.example .env
# Edit .env with your API keys (optional - platform works without them)
docker-compose up --build
```

### 2. Seed the database

```bash
docker-compose exec backend python -m app.seed
```

### 3. Access the platform

- **Frontend**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs

### 4. Login

| Email | Password | Role |
|-------|----------|------|
| admin@sec360.local | Admin123! | Admin |
| analyst@sec360.local | Analyst123! | Analyst |

## Features

### Dashboard
- Real-time security metrics (users, endpoints, compliance, risk)
- Compliance distribution pie chart
- Risk level bar chart
- High-risk users list
- Suspicious activity feed

### Endpoints
- Full endpoint inventory with OS, agents, compliance, risk
- Filters: compliance status, OS type, search
- Click-through to endpoint detail

### Users
- User inventory with risk scores, MFA status, departments
- Filters: department, risk level, employment status
- Click-through to user detail

### Compliance
- Compliance status across all endpoints
- Checks: EDR installed, agent current, OS current, disk encrypted, recently seen
- Trigger re-evaluation on-demand
- Summary stats

### Activity
- Security event feed (logins, app usage, VPN, network)
- Filter by event type and suspicious flag
- Real-time suspicious activity highlighting

### Investigation
- Search users and endpoints
- User deep-dive: risk factors, MFA status, device list, activity timeline
- Device deep-dive: compliance checks, agent status, owner info

## Data Sources

| Source | Data Type | Endpoint |
|--------|-----------|----------|
| SentinelOne | Endpoints + EDR agents | GET /web/api/v2.1/agents |
| HiBob | Users (HR) | GET /v1/people |
| Google Workspace | Login activity | Reports API |
| Symantec | DLP agent status | GET /sepm/api/v1/computers |
| Prisma Access | Network events | GET /api/sase/v1.0/resource/query/traffic |

## Risk Scoring

**User Risk (0-100)**
- +30 Impossible travel detected
- +20 Multiple countries in short window
- +25 Non-compliant device
- +15 No MFA
- +10 Inactive 30+ days

**Endpoint Risk (0-100)**
- +30 No EDR installed
- +25 Agent outdated
- +20 OS outdated
- +15 Not seen in 24h
- +10 No disk encryption

Risk levels: Low (0-25), Medium (26-50), High (51-75), Critical (76-100)

## Development

### Backend only

```bash
cd backend
pip install -r requirements.txt
DB_URL=postgresql+asyncpg://sec360:sec360pass@localhost:5432/sec360 \
  JWT_SECRET=dev-secret \
  uvicorn app.main:app --reload
```

### Frontend only

```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000/api npm run dev
```
