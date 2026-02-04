#!/bin/bash

# RedAmon System Stop Script
# Stops all Docker services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo ""
echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║                   RedAmon System Shutdown                     ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Stop services in reverse order
services=(
    "agentic:Agentic AI Agent"
    "mcp:MCP Servers"
    "recon_orchestrator:Recon Orchestrator"
    "graph_db:Neo4j Graph Database"
    "postgres_db:PostgreSQL"
)

for service in "${services[@]}"; do
    dir="${service%%:*}"
    name="${service##*:}"

    log_info "Stopping $name..."
    cd "$PROJECT_ROOT/$dir"
    docker-compose down 2>/dev/null || true
    log_success "$name stopped"
done

cd "$PROJECT_ROOT"

echo ""
log_success "All services stopped"
echo ""
