# CSCP -- developer convenience targets.  Requires Python 3.11+.
PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

.PHONY: help venv install test lint type check certs server client cli demo bench capture up down logs client-stack clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv and install dev + client extras
	python3 -m venv .venv
	$(PIP) install -U pip
	$(PIP) install -e ".[dev,client]"

install: ## Install the package (dev extras only)
	$(PIP) install -e ".[dev]"

test: ## Run the full test suite
	$(PY) -m pytest tests --timeout=120 --timeout-method=thread

lint: ## Lint with ruff
	.venv/bin/ruff check protocol server security messaging client tests scripts

type: ## Type-check with mypy (strict)
	.venv/bin/mypy protocol server security messaging client --ignore-missing-imports

check: lint type test ## Lint + type-check + test

certs: ## Generate the local CA + server + client certificates
	$(PY) -m security.certs --outdir security/certs

server: ## Run the server (stub auth, PLAIN mode if no certs)
	$(PY) -m server.main --auth stub

client: ## Launch the PyQt6 desktop client
	$(PY) -m client.main --gui --config config/client.yaml

cli: ## Console client (one-shot send).  Usage: make cli USER=alice PEER=bob SEND=hi
	$(PY) -m client.main --config config/client.yaml --username $(USER) --peer $(PEER) --send "$(SEND)"

demo: ## Generate capturable demo traffic (plain / e2ee / tls)
	$(PY) scripts/traffic_demo.py --mode $(MODE)

bench: ## Run the load benchmark.  Usage: make bench CLIENTS=200 MSGS=10
	$(PY) scripts/bench.py --clients $(or $(CLIENTS),100) --messages $(or $(MSGS),10)

capture: ## Capture loopback CSCP traffic to captures/ (needs sudo).  MODE=plain|e2ee|tls
	sudo tcpdump -i lo0 -s 0 -w captures/$(or $(MODE),plain).pcap 'tcp port 9443'

up: ## Build + start the local Docker stack (turnkey; creates .env if missing)
	@cd deploy && { [ -f .env ] || { cp .env.example .env; echo "deploy/.env created from example -- edit the secrets before real use"; }; }
	@cd deploy && docker compose up -d --build
	@echo "CSCP on :9443 (TLS 1.3 + mTLS); admin on http://127.0.0.1:9444"
	@echo "Run the desktop client with:  make client-stack"

down: ## Stop the local Docker stack
	@cd deploy && docker compose down

logs: ## Follow the local Docker stack logs
	@cd deploy && docker compose logs -f cscp

client-stack: ## Launch the GUI against the local Docker stack (TLS + mTLS)
	$(PY) -m client.main --gui --config deploy/client.local.yaml

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
