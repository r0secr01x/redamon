#!/bin/bash

# RedAmon System Startup Script
# Starts all Docker services in the correct order and then runs the webapp

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print colored status messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a container is running
container_running() {
    docker ps --format '{{.Names}}' | grep -q "^$1$"
}

# Function to wait for a container to be healthy
wait_for_healthy() {
    local container=$1
    local max_attempts=${2:-30}
    local attempt=1

    log_info "Waiting for $container to be healthy..."

    while [ $attempt -le $max_attempts ]; do
        health=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")

        if [ "$health" = "healthy" ]; then
            log_success "$container is healthy"
            return 0
        elif [ "$health" = "none" ]; then
            # No healthcheck defined, check if running
            if container_running "$container"; then
                log_success "$container is running (no healthcheck)"
                return 0
            fi
        fi

        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    echo ""
    log_warn "$container health check timed out, continuing anyway..."
    return 0
}

# Function to start a service with docker-compose
start_service() {
    local service_dir=$1
    local service_name=$2
    local container_name=$3
    local build_first=${4:-false}

    log_info "Starting $service_name..."

    cd "$PROJECT_ROOT/$service_dir"

    if [ "$build_first" = true ]; then
        log_info "Building $service_name..."
        docker-compose build --quiet 2>/dev/null || docker-compose build
    fi

    # Check if already running
    if [ -n "$container_name" ] && container_running "$container_name"; then
        log_warn "$service_name is already running"
    else
        docker-compose up -d
        log_success "$service_name started"
    fi

    cd "$PROJECT_ROOT"
}

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   RedAmon System Startup                      ║${NC}"
echo -e "${GREEN}║         Unmask the hidden before the world does.              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Create Docker network if it doesn't exist
log_info "Checking Docker network..."
if ! docker network inspect redamon-network >/dev/null 2>&1; then
    log_info "Creating redamon-network..."
    docker network create redamon-network
    log_success "Docker network created"
else
    log_success "Docker network already exists"
fi

# Step 2: Start PostgreSQL
start_service "postgres_db" "PostgreSQL" "redamon-postgres"
wait_for_healthy "redamon-postgres" 30

# Step 3: Start Neo4j Graph Database
start_service "graph_db" "Neo4j Graph Database" "redamon-neo4j"
wait_for_healthy "redamon-neo4j" 60

# Step 4: Build recon image if needed (for recon_orchestrator)
log_info "Checking recon image..."
if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "redamon-recon:latest"; then
    log_info "Building recon image..."
    cd "$PROJECT_ROOT/recon"
    docker-compose build
    cd "$PROJECT_ROOT"
    log_success "Recon image built"
else
    log_success "Recon image already exists"
fi

# Step 5: Start Recon Orchestrator
# Export HOST_RECON_PATH so the orchestrator knows the actual host path for volume mounts
export HOST_RECON_PATH="$PROJECT_ROOT/recon"
start_service "recon_orchestrator" "Recon Orchestrator" "redamon-recon-orchestrator" true

# Step 6: Start MCP Servers (Kali Sandbox)
start_service "mcp" "MCP Servers (Kali Sandbox)" "redamon-kali" true
# MCP takes longer to start, wait for healthcheck
wait_for_healthy "redamon-kali" 90

# Step 7: Start Agentic
start_service "agentic" "Agentic AI Agent" "redamon-agent" true
wait_for_healthy "redamon-agent" 60

# Step 8: Setup webapp dependencies and Prisma
log_info "Setting up webapp..."
cd "$PROJECT_ROOT/webapp"

# Check if node_modules exists, if not run npm install
if [ ! -d "node_modules" ]; then
    log_info "Installing npm dependencies..."
    npm install
    log_success "npm dependencies installed"
else
    log_success "npm dependencies already installed"
fi

# Run Prisma setup if schema exists
if [ -f "prisma/schema.prisma" ]; then
    # Clear cached Prisma client to ensure fresh generation with new defaults
    log_info "Clearing Prisma cache..."
    rm -rf node_modules/.prisma 2>/dev/null || true

    log_info "Regenerating Prisma client..."
    npx prisma generate
    log_success "Prisma client regenerated"

    # Sync database schema
    log_info "Syncing database schema..."
    npx prisma db push
    log_success "Database schema synced"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              All services started successfully!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
log_info "Services running:"
echo "  - PostgreSQL:         localhost:5432"
echo "  - Neo4j Browser:      http://localhost:7474"
echo "  - Neo4j Bolt:         bolt://localhost:7687"
echo "  - Recon Orchestrator: http://localhost:8010"
echo "  - MCP Naabu:          http://localhost:8000"
echo "  - MCP Curl:           http://localhost:8001"
echo "  - MCP Nuclei:         http://localhost:8002"
echo "  - MCP Metasploit:     http://localhost:8003"
echo "  - Agentic API:        http://localhost:8090"
echo ""

# Step 9: Start webapp
log_info "Starting webapp (npm run dev)..."
echo ""
cd "$PROJECT_ROOT/webapp"
npm run dev
