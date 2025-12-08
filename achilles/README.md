# ACHILLES - Test Results Visualizer

A standalone web application for visualizing F0RT1KA security test results from Elasticsearch.

## Features

- **Defense Score Dashboard** - Overall protection rate visualization
- **Trend Analysis** - Defense score over time
- **Test Breakdown** - Protection rates by individual test
- **Technique Analysis** - Defense coverage by MITRE ATT&CK technique
- **Organization Comparison** - Cross-org protection metrics
- **Recent Executions** - Live feed of test results
- **Dark/Light Theme** - Consistent with F0RT1KA design system

## Quick Start

```bash
# Start development servers
./start.sh
```

This will:
1. Install dependencies (if needed)
2. Start backend on http://localhost:3002
3. Start frontend on http://localhost:5174

## First Time Setup

1. Open http://localhost:5174
2. You'll be redirected to the setup page
3. Enter your Elasticsearch connection details:
   - **Elastic Cloud**: Cloud ID + API Key
   - **Direct URL**: Elasticsearch URL + API Key
4. Click "Connect" to test and save

## Architecture

```
achilles/
├── backend/           # Express + TypeScript API
│   └── src/
│       ├── routes/    # API endpoints
│       ├── services/  # ES client, settings
│       └── types/     # TypeScript definitions
│
└── frontend/          # React + Vite + Tailwind
    └── src/
        ├── components/  # UI components
        ├── pages/       # Page components
        ├── services/    # API client
        └── hooks/       # React hooks
```

## API Endpoints

### Settings
- `GET /api/settings` - Get current settings (masked)
- `POST /api/settings` - Save settings
- `POST /api/settings/test` - Test ES connection

### Analytics
- `GET /api/analytics/defense-score` - Overall score
- `GET /api/analytics/defense-score/trend` - Time series
- `GET /api/analytics/defense-score/by-test` - By test breakdown
- `GET /api/analytics/defense-score/by-technique` - By ATT&CK technique
- `GET /api/analytics/defense-score/by-org` - By organization
- `GET /api/analytics/executions` - Recent test executions
- `GET /api/analytics/organizations` - List organizations

### Query Parameters
- `org` - Filter by organization UUID
- `from` - Start date (ES format, e.g., "now-7d")
- `to` - End date
- `interval` - Time bucket (hour, day, week)
- `limit` - Max results

## Elasticsearch Index

Expects data in `f0rtika-results-*` indices with fields:
- `routing.oid` - Organization UUID
- `routing.event_time` - Event timestamp
- `routing.hostname` - Endpoint hostname
- `f0rtika.test_uuid` - Test identifier
- `f0rtika.test_name` - Test display name
- `f0rtika.techniques` - MITRE ATT&CK technique IDs
- `f0rtika.is_protected` - Boolean protection status

## Configuration

Settings are stored in `~/.achilles/settings.json` with encrypted credentials.

## Development

```bash
# Backend only
cd backend && npm run dev

# Frontend only
cd frontend && npm run dev

# Build for production
cd backend && npm run build
cd frontend && npm run build
```

## Ports

| Service | Port |
|---------|------|
| Backend | 3002 |
| Frontend | 5174 |

Ports are different from Security Test Browser (3001/5173) to allow running both simultaneously.

## Tech Stack

- **Backend**: Express, TypeScript, @elastic/elasticsearch
- **Frontend**: React 18, Vite, Tailwind CSS, Recharts
- **Icons**: Lucide React
- **Date handling**: date-fns
