# ─────────────────────────────────────────────────────────────────
# Auto Recon Framework - Makefile
# ─────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help setup install lint format test test-cov security docker docker-push clean scan

PYTHON     := python3
PIP        := pip3
TARGET     ?= example.com
CONFIG     ?= config/default.yaml
OUTPUT_DIR ?= output
IMAGE      ?= auto-recon:latest
REGISTRY   ?= ghcr.io/your-org

# ── Colors ────────────────────────────────────────────────────────
CYAN  := \033[0;36m
GREEN := \033[0;32m
RESET := \033[0m

help: ## Show this help message
	@echo ""
	@echo "  $(CYAN)Auto Recon Framework$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ── Environment ───────────────────────────────────────────────────
setup: ## Run full setup (install all tools + Python deps)
	@chmod +x setup.sh && ./setup.sh

install: ## Install Python dependencies only
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

install-tools: ## Install Go-based recon tools
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	go install github.com/sensepost/gowitness@latest
	nuclei -update-templates -silent

# ── Code Quality ──────────────────────────────────────────────────
lint: ## Run ruff linter
	ruff check . --output-format=concise

format: ## Run ruff formatter
	ruff format .
	ruff check . --fix

typecheck: ## Run mypy type checker
	mypy . --ignore-missing-imports

# ── Tests ─────────────────────────────────────────────────────────
test: ## Run unit tests
	pytest tests/ -v

test-cov: ## Run tests with coverage report
	pytest tests/ -v \
	  --cov=. \
	  --cov-report=term-missing \
	  --cov-report=html:htmlcov

test-fast: ## Run tests, stop on first failure
	pytest tests/ -x -q

# ── Security ──────────────────────────────────────────────────────
security: ## Run Bandit SAST + pip-audit
	bandit -r . -c pyproject.toml -q
	pip-audit -r requirements.txt

# ── Docker ────────────────────────────────────────────────────────
docker: ## Build Docker image
	docker build -f docker/Dockerfile -t $(IMAGE) .

docker-run: docker ## Build and run a scan in Docker
	docker run --rm \
	  --cap-add NET_RAW --cap-add NET_ADMIN \
	  --network host \
	  -v $(PWD)/output:/app/output \
	  $(IMAGE) -t $(TARGET)

docker-push: ## Push image to registry
	docker tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	docker push $(REGISTRY)/$(IMAGE)

compose-scan: ## Run scan via docker-compose
	docker-compose -f docker/docker-compose.yml run --rm recon -t $(TARGET)

compose-reports: ## Serve reports on localhost:8080
	docker-compose -f docker/docker-compose.yml --profile reports up -d report-server
	@echo "Reports available at http://localhost:8080"

# ── Scanning ──────────────────────────────────────────────────────
scan: ## Run a full scan (TARGET=example.com make scan)
	$(PYTHON) main.py -t $(TARGET) -c $(CONFIG) --output $(OUTPUT_DIR)

scan-quick: ## Quick web scan — no nmap, no subfinder
	$(PYTHON) main.py -t $(TARGET) --no-nmap --no-subfinder \
	  --output $(OUTPUT_DIR)/quick

scan-ports: ## Port scan only
	$(PYTHON) main.py -t $(TARGET) \
	  --no-subfinder --no-httpx --no-nuclei --no-screenshots \
	  --output $(OUTPUT_DIR)/ports

scan-vulns: ## Vuln scan only (assumes subdomains known)
	$(PYTHON) main.py -t $(TARGET) \
	  --no-nmap --no-subfinder --no-screenshots \
	  --output $(OUTPUT_DIR)/vulns

init-config: ## Generate default config.yaml
	$(PYTHON) main.py --init-config

# ── Maintenance ───────────────────────────────────────────────────
update-templates: ## Update nuclei templates
	nuclei -update-templates

clean: ## Remove generated output
	rm -rf output/reports/* output/screenshots/* output/json/*
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean ## Remove output + coverage + build artifacts
	rm -rf htmlcov/ .coverage coverage.xml dist/ build/ *.egg-info/

# ── CI helpers ────────────────────────────────────────────────────
ci: lint typecheck test security ## Run full CI pipeline locally
	@echo "$(GREEN)✓ All CI checks passed$(RESET)"
