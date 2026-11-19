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
.PHONY: help serve logs check tokens sweep load claims cookies refs protocols versions test benchmark setup

help:
	@echo "make serve      start nginx (http://localhost:$(PROXY_PORT)) and the app (port $(APP_PORT)); Ctrl+C stops both"
	@echo "make logs       follow the nginx and app logs of the running serve"
	@echo "make check      send one browser request through the stack, then stop it"
	@echo "make tokens     send every configuration's token as a cookie and a Bearer header"
	@echo "make sweep      cookie and Bearer sweeps of all six, at default and raised nginx buffers (SWEEP_DIR=$(SWEEP_DIR))"
	@echo "make load       end-to-end latency and throughput of all six through the stack (LOAD_DIR=$(LOAD_DIR))"
	@echo "make claims     smaller claim sets: token sizes, size limits, and latency, oidc vs essential (CLAIMS_DIR=$(CLAIMS_DIR))"
	@echo "make cookies    cookie splitting: chunk plan, size limits, chunk handling, and latency, jwt cookie vs split (COOKIES_DIR=$(COOKIES_DIR))"
	@echo "make refs       reference tokens: size limits, reference handling, and lookup latency, Bearer JWT vs reference (REFS_DIR=$(REFS_DIR))"
	@echo "make protocols  cookie and Bearer sweeps over HTTPS and HTTP/2, compared with Sprint 2's plain HTTP (PROTOCOLS_DIR=$(PROTOCOLS_DIR))"
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

CLAIMS_DIR ?= results/claims/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)
# S3-02's smaller claim sets (see MITIGATION_RESULTS.md). The size-limits stack keeps nginx's
# defaults; the latency stacks repeat make load's recorded flags, without size controls.
claims:
	$(STACK) claims --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir "$(CLAIMS_DIR)"

COOKIES_DIR ?= results/cookies/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)
# S3-02's cookie splitting (see MITIGATION_RESULTS.md). One size-limits stack keeps nginx's
# defaults; the raised-limits and latency stacks get these buffers, and the latency stacks
# repeat make load's keepalive and 2 s cells.
cookies:
	$(STACK) cookies --header-buffers 32k --proxy-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir "$(COOKIES_DIR)"

REFS_DIR ?= results/refs/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)
# S3-02's reference tokens (see MITIGATION_RESULTS.md). The size-limits and behavior stacks keep
# nginx's defaults; the three latency stacks repeat make load's header buffers, keepalive, and
# 2 s cells.
refs:
	$(STACK) refs --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir "$(REFS_DIR)"

PROTOCOLS_DIR ?= results/transport/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)
# S3-04's HTTPS and HTTP/2 sweeps (see TRANSPORT_RESULTS.md): the four make sweep runs, each over
# HTTPS (HTTP/1.1 over TLS) and HTTP/2 with a per-run self-signed certificate and experiment key,
# compared with Sprint 2's plain-HTTP WSL2 runs.
protocols:
	$(STACK) protocols --output-dir "$(PROTOCOLS_DIR)"

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
