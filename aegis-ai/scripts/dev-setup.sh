#!/usr/bin/env bash
# =============================================================================
# AEGIS AI — Development Environment Setup
# Run once after cloning: bash scripts/dev-setup.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         AEGIS AI — Dev Setup             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ---------------------------------------------------------------------------
# 1. Prerequisites check
# ---------------------------------------------------------------------------
log_info "Checking prerequisites..."

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 is not installed. $2"
        exit 1
    fi
    log_success "$1 found: $(command -v $1)"
}

check_command docker "Install from https://docs.docker.com/get-docker/"
check_command python3 "Install Python 3.11+ from https://python.org"
check_command git "Install git from https://git-scm.com"

# Check Docker is running
if ! docker info &>/dev/null; then
    log_error "Docker daemon is not running. Start Docker Desktop."
    exit 1
fi
log_success "Docker daemon is running"

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_MAJOR=3
REQUIRED_MINOR=11
if python3 -c "import sys; exit(0 if sys.version_info >= ($REQUIRED_MAJOR, $REQUIRED_MINOR) else 1)"; then
    log_success "Python $PYTHON_VERSION"
else
    log_error "Python 3.11+ required. Found: $PYTHON_VERSION"
    exit 1
fi

# Check Ollama (optional but recommended)
if command -v ollama &>/dev/null; then
    log_success "Ollama found"
    if ollama list 2>/dev/null | grep -q "llama3.2"; then
        log_success "llama3.2 model already pulled"
    else
        log_warn "llama3.2 not pulled yet. Run: ollama pull llama3.2"
    fi
else
    log_warn "Ollama not found. Install from https://ollama.ai for AI features (needed in Milestone 6)"
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Environment file
# ---------------------------------------------------------------------------
log_info "Setting up environment..."

if [ ! -f ".env" ]; then
    cp .env.example .env

    # Generate a real JWT secret
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|JWT_SECRET_KEY=changeme_generate_with_openssl|JWT_SECRET_KEY=$JWT_SECRET|" .env
    else
        sed -i "s|JWT_SECRET_KEY=changeme_generate_with_openssl|JWT_SECRET_KEY=$JWT_SECRET|" .env
    fi

    log_success ".env created with generated JWT secret"
    log_warn "Review .env and update passwords before production use"
else
    log_success ".env already exists — skipping"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. Install shared Python library
# ---------------------------------------------------------------------------
log_info "Installing shared Python library (aegis-common)..."

python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -e shared/python/

log_success "aegis-common installed"

# ---------------------------------------------------------------------------
# 4. Install gateway dependencies (for local dev/testing)
# ---------------------------------------------------------------------------
log_info "Installing gateway dependencies..."

python3 -m pip install --quiet \
    fastapi "uvicorn[standard]" "sqlalchemy[asyncio]" asyncpg alembic \
    "python-jose[cryptography]" "passlib[bcrypt]" bcrypt \
    pydantic pydantic-settings "redis[hiredis]" \
    structlog httpx python-multipart aiokafka \
    prometheus-client prometheus-fastapi-instrumentator \
    pytest pytest-asyncio pytest-cov ruff

log_success "Gateway dependencies installed"

echo ""

# ---------------------------------------------------------------------------
# 5. Start infrastructure
# ---------------------------------------------------------------------------
log_info "Starting infrastructure services..."

cd infrastructure/docker

# Pull images first (shows progress)
log_info "Pulling Docker images (this takes a few minutes on first run)..."
docker compose pull --quiet 2>/dev/null || true

# Start core infrastructure only (not the Aegis services yet)
docker compose up -d postgres neo4j elasticsearch redis zookeeper kafka kafka-init

log_info "Waiting for services to be healthy..."

wait_healthy() {
    local service=$1
    local max_wait=${2:-60}
    local waited=0
    echo -n "  Waiting for $service"
    while ! docker compose ps "$service" 2>/dev/null | grep -q "healthy"; do
        sleep 3
        waited=$((waited + 3))
        echo -n "."
        if [ $waited -ge $max_wait ]; then
            echo ""
            log_warn "$service health check timed out — it may still be starting"
            return 0
        fi
    done
    echo ""
    log_success "$service is healthy"
}

wait_healthy postgres 60
wait_healthy redis 30
wait_healthy elasticsearch 90
wait_healthy kafka 60

cd "$REPO_ROOT"

echo ""

# ---------------------------------------------------------------------------
# 6. Verify Kafka topics
# ---------------------------------------------------------------------------
log_info "Verifying Kafka topics..."

sleep 5  # Give kafka-init a moment to complete

TOPIC_COUNT=$(docker exec aegis-kafka \
    kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | \
    grep "^aegis\." | wc -l | tr -d ' ')

if [ "$TOPIC_COUNT" -ge 15 ]; then
    log_success "All $TOPIC_COUNT Aegis topics created"
else
    log_warn "Only $TOPIC_COUNT topics found — kafka-init may still be running"
    log_warn "Check with: docker exec aegis-kafka kafka-topics --bootstrap-server localhost:9092 --list"
fi

echo ""

# ---------------------------------------------------------------------------
# 7. Run unit tests
# ---------------------------------------------------------------------------
log_info "Running unit tests..."

PYTHONPATH="shared/python:services/gateway" \
POSTGRES_PASSWORD=aegis_dev_password \
JWT_SECRET_KEY="test_secret_at_least_64_chars_long_for_testing_purposes_xxxxxxxxx" \
NEO4J_PASSWORD=aegis_dev_password \
python3 -m pytest services/gateway/tests/unit/ -v --tb=short 2>&1 | tail -20

echo ""

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Infrastructure:                                             ║"
echo "║    PostgreSQL   → localhost:5432                             ║"
echo "║    Neo4j        → localhost:7474 (browser)                   ║"
echo "║    Elasticsearch→ localhost:9200                             ║"
echo "║    Redis        → localhost:6379                             ║"
echo "║    Kafka        → localhost:9092                             ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║    Start gateway:  cd services/gateway && uvicorn app.main:app --reload"
echo "║    API docs:       http://localhost:8000/docs                ║"
echo "║    Kafka UI:       docker compose --profile observability up ║"
echo "║    Neo4j browser:  http://localhost:7474                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
log_warn "Default admin credentials: admin@aegis.local / AegisAdmin@2024!"
log_warn "Change the password immediately after first login."
