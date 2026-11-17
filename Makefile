# Shortcuts for the benchmark and the transport stack. Run `make` for the list of targets.
# Uses `python` from the active environment (e.g. `conda activate crypto`), or
# $(TRANSPORT_ENV)/bin/python when TRANSPORT_ENV is set, as in TRANSPORT.md.

TRANSPORT_ENV ?=
PYTHON ?= $(if $(TRANSPORT_ENV),$(TRANSPORT_ENV)/bin/python,python)
PROXY_PORT ?= 8080
APP_PORT ?= 8081
# serve writes its nginx config and logs here; it is emptied at the start of every serve.
RUN_DIR ?= $(CURDIR)/.transport-run
LOGS := $(RUN_DIR)/logs
STACK := PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/transport_stack.py

.DEFAULT_GOAL := help
.PHONY: help serve logs check tokens sweep load versions test benchmark setup

help:
	@echo "make serve      start nginx (http://localhost:$(PROXY_PORT)) and the app (port $(APP_PORT)); Ctrl+C stops both"
	@echo "make logs       follow the nginx and app logs of the running serve"
	@echo "make check      send one browser request through the stack, then stop it"
	@echo "make tokens     send every configuration's token as a cookie and a Bearer header"
	@echo "make sweep      cookie and Bearer sweeps of all six, at default and raised nginx buffers (SWEEP_DIR=$(SWEEP_DIR))"
	@echo "make load       end-to-end latency and throughput of all six through the stack (LOAD_DIR=$(LOAD_DIR))"
	@echo "make versions   compare installed versions with transport/stack.json"
	@echo "make test       run the full test suite"
	@echo "make benchmark  run the Sprint 1 benchmark (ITERATIONS=$(ITERATIONS), WARMUP=$(WARMUP))"
	@echo "make setup PREFIX=/path/to/env   create or update the pinned transport environment"
	@echo "Override PYTHON, TRANSPORT_ENV, PROXY_PORT, APP_PORT, or RUN_DIR, e.g. make serve PROXY_PORT=9090"

serve:
	rm -rf "$(RUN_DIR)"
	@echo "Open http://localhost:$(PROXY_PORT)/  (logs: $(LOGS); run 'make logs' in another terminal)"
	$(STACK) serve --proxy-port $(PROXY_PORT) --app-port $(APP_PORT) --run-dir "$(RUN_DIR)"

logs:
	@test -d "$(LOGS)" || { echo "No logs in $(LOGS); start 'make serve' first." >&2; exit 1; }
	tail -n 20 -F "$(LOGS)/proxy-access.log" "$(LOGS)/proxy-error.log" "$(LOGS)/app.log"

check:
	$(STACK) check

tokens:
	$(STACK) tokens

SWEEP_DIR ?= results/transport/$(shell date -u +%Y%m%dT%H%M%SZ)
sweep:
	$(STACK) sweep --output-dir "$(SWEEP_DIR)/cookie-default"
	$(STACK) sweep --proxy-buffers 16k --output-dir "$(SWEEP_DIR)/cookie-16k"
	$(STACK) sweep --transport bearer --output-dir "$(SWEEP_DIR)/bearer-default"
	$(STACK) sweep --transport bearer --header-buffers 512k --step 16384 --max-bytes 327680 --output-dir "$(SWEEP_DIR)/bearer-512k"

# The run directory names the machine, as results/transport/ does: macos, wsl2, or linux.
LOAD_PLATFORM ?= $(shell if [ "$$(uname -s)" = Darwin ]; then echo macos; \
	elif grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then echo wsl2; \
	else echo linux; fi)
LOAD_DIR ?= results/load/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)
# Not defaults, and recorded in load.json's settings (see END_TO_END_RESULTS.md):
# --upstream-keepalive keeps macOS from running out of ephemeral ports, because nginx otherwise
# opens a new connection to waitress per request, and 2 s cells keep every committed file under
# 10 MiB.
load:
	$(STACK) load --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir "$(LOAD_DIR)"

versions:
	$(STACK) versions

test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests

ITERATIONS ?= 1000
WARMUP ?= 100
benchmark:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/benchmark.py --iterations $(ITERATIONS) --warmup $(WARMUP)

setup:
	@test -n "$(PREFIX)" || { echo "usage: make setup PREFIX=/path/to/env" >&2; exit 2; }
	bash transport/setup.sh "$(PREFIX)"
