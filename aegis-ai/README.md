# Aegis AI — Autonomous Cyber Defense Operating System

> An AI-first cybersecurity platform for autonomous threat detection, investigation, and response.

---

## Architecture

Aegis AI is a microservices platform built on:

- **14 FastAPI services** communicating over Kafka
- **LangGraph multi-agent AI** for autonomous investigation
- **Neo4j Knowledge Graph** linking assets, threats, and incidents
- **Elasticsearch** for log storage and full-text search
- **PostgreSQL** for relational core data
- **Next.js 14** frontend with real-time streaming

See `docs/architecture/system-overview.md` for the full design.

---

## Quick Start

### Prerequisites
- Docker Desktop (4.x+)
- Python 3.11+
- Node.js 20+
- Ollama with `llama3.2` pulled (`ollama pull llama3.2`)
- 16GB RAM minimum

### 1. Clone and setup

```bash
git clone https://github.com/your-org/aegis-ai.git
cd aegis-ai
bash scripts/dev-setup.sh
```

This will:
- Check all prerequisites
- Generate a secure `.env` from the template
- Start all infrastructure (Postgres, Neo4j, Elasticsearch, Redis, Kafka)
- Create all Kafka topics
- Run unit tests

### 2. Start the gateway service

```bash
cd services/gateway
PYTHONPATH=../../shared/python uvicorn app.main:app --reload --port 8000
```

### 3. Explore the API

- **API Docs**: http://localhost:8000/docs
- **Default admin**: `admin@aegis.local` / `AegisAdmin@2024!`
- **Neo4j Browser**: http://localhost:7474
- **Elasticsearch**: http://localhost:9200

### 4. Observability (optional)

```bash
cd infrastructure/docker
docker compose --profile observability up -d
```

- **Kafka UI**: http://localhost:8080
- **Grafana**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Kibana**: http://localhost:5601

---

## Development Workflow

```bash
# Run unit tests
cd aegis-ai
PYTHONPATH="shared/python:services/gateway" \
  pytest services/gateway/tests/unit/ -v

# Lint
ruff check services/gateway/ shared/python/

# Format
ruff format services/gateway/ shared/python/

# Stop all infrastructure
cd infrastructure/docker && docker compose down

# Full reset (destroys all data)
cd infrastructure/docker && docker compose down -v
```

---

## Project Structure

```
aegis-ai/
├── .github/workflows/    # CI/CD pipelines
├── docs/                 # Architecture docs, API specs
├── infrastructure/       # Docker Compose, Kubernetes, monitoring
├── services/             # 14 microservices (FastAPI)
│   ├── gateway/          # ← Milestone 1: Auth & routing
│   ├── asset-discovery/  # ← Milestone 2
│   ├── telemetry-collector/
│   ├── detection-engine/ # ← Milestone 3
│   └── ...
├── shared/python/        # aegis_common: shared library
│   └── aegis_common/
│       ├── auth/         # JWT, RBAC, password hashing
│       ├── kafka/        # Producer/consumer wrappers
│       ├── models/       # Shared Pydantic schemas
│       └── logging/      # Structured logging
└── frontend/             # Next.js 14 (Milestone 2)
```

---

## Milestone Progress

| Milestone | Description | Status |
|---|---|---|
| 1 | Foundation — infrastructure, auth, gateway | ✅ Complete |
| 2 | Data Plane — asset discovery, telemetry | 🔄 Next |
| 3 | Detection Engine — rules, ML, MITRE | ⏳ Upcoming |
| 4 | Threat Intelligence | ⏳ |
| 5 | Knowledge Graph | ⏳ |
| 6 | Multi-Agent AI | ⏳ |
| 7 | Response & Approval Workflow | ⏳ |
| 8 | Digital Twin | ⏳ |
| 9 | Learning System + Polish | ⏳ |
| 10 | Security Hardening + Docs | ⏳ |

---

## Security Notes

- Never commit `.env` to version control
- Change the default admin password immediately
- The `initial_admin_password` in `.env` is only used on first boot
- All defensive actions require human approval by default (Approval Mode)
- Production deployment requires enabling Elasticsearch TLS and PostgreSQL SSL

---

## License

Private — Final Year Project / MVP. Not for redistribution.
