"""Check the S3-01 end-to-end load: the application's opt-in server timings, run_load against a
stand-in server and against real stacks, the saved results, the `load` command, the network
model, and the docs and committed run; no timing thresholds."""

import base64
from collections import Counter, defaultdict
from contextlib import contextmanager
import csv
from datetime import datetime, timedelta
import getpass
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import inspect
import io
from itertools import groupby
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qsl, urlsplit
from wsgiref.util import setup_testing_defaults

from scripts import transport_app
from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.benchmark import environment as benchmark_environment
from scripts.rsa_jwt import summarize
from scripts.token_sizing import (CLAIM_SETS, claim_set, pad_for_target, padded_claims,
                                  padded_token, token_bytes)
from scripts.transport_stack import (PROXY_MARKER, http_get, load_manifest, manifest_layers,
                                     start_stack)

try:
    from scripts import transport_load
    LOAD_IMPORT_ERROR = None
except ImportError as error:  # Before S3-01 is built: the tests that need it fail, not vanish.
    transport_load, LOAD_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
TRANSPORT_DOC = REPO / "TRANSPORT.md"
RESULTS_DOC = REPO / "END_TO_END_RESULTS.md"
PROGRESS = REPO / "PROGRESS.md"
README = REPO / "README.md"
MAKEFILE = REPO / "Makefile"
LOAD_RESULTS = REPO / "results" / "load"
# The commit S3-01 builds on; R16's unchanged files and the Sprint 2 application come from it.
BASE_COMMIT = "a61cbb288d7a91707d79750c0a9fa206e7f05c24"

HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
CLIENTS = ["direct", "browser"]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
NONCE = re.compile(r"[0-9a-f]{32}")
LOGGED_NONCE = re.compile(r"[?&]nonce=([0-9a-f]{32})")
REQUEST_LINE = re.compile(r'"GET (?P<target>\S+) HTTP/[\d.]+" (?P<status>\d{3})(?P<fields>.*)$')
RUN_NAME = re.compile(r"\d{8}T\d{6}Z-macos")
ERROR_LINE = re.compile(r"(?m)^Error:")
# An active directive only: the template names large_client_header_buffers in a comment.
HEADER_BUFFERS_DIRECTIVE = re.compile(r"(?m)^\s*large_client_header_buffers\b")
LOG_NAMES = ("proxy-access.log", "proxy-error.log", "app.log")
GRACE = 15.0
CLI_TIMEOUT = 600
MIB = 1024 * 1024
# nginx opens a new upstream connection per request, and macOS keeps each closed one in TIME_WAIT
# for 30 s, so back-to-back load runs can use up its 16,384 ephemeral ports (EADDRNOTAVAIL).
# Each run first waits until earlier runs' connections have drained below this count.
TIME_WAIT_LIMIT = 6_000
TIME_WAIT_GRACE = 90.0
# Scheduler delay between a worker's deadline check and its own timestamp; not a speed limit.
WINDOW_SLACK_NS = 1_000_000_000
# Rounding between the clock behind measured_seconds and the requests' own timestamps.
CLOCK_SLACK_SECONDS = 0.01
MS_SCALES = (1, 1000)  # Docs may show milliseconds as ms or as µs.

RESULT_KEYS = {"schema_version", "started_utc", "finished_utc", "settings", "workload",
               "environment", "layers", "browser", "proxy_url", "app_url", "run_dir",
               "experiment_keys", "results", "comparisons", "network_model", "raw"}
SAVED_KEYS = (RESULT_KEYS - {"raw"}) | {"recorded_utc", "evidence"}
SETTINGS_KEYS = {"algorithms", "transport", "clients", "claims", "concurrency", "duration",
                 "warmup", "reference", "size_controls", "timeout", "proxy_buffers",
                 "header_buffers", "upstream_keepalive"}
CELL_KEYS = {"client", "concurrency", "algorithm", "variant", "signed_with", "claims", "pad",
             "token_bytes", "issue", "requests", "verified", "failed", "statuses",
             "measured_seconds", "throughput_rps", "latency", "bytes"}
ISSUE_KEYS = {"status", "delivered", "error"}
BYTES_KEYS = {"header_line", "app_received_headers", "response_body"}
COMPONENTS = ("total", "transfer", "other_handling", "verification")
SUMMARY_KEYS = {"median_ms", "p95_ms", "mean_ms"}
DIFFERENCE_KEYS = {*COMPONENTS, "token_size"}
COMPARISON_KEYS = {"client", "concurrency", "algorithm", "reference", "token_bytes",
                   "reference_token_bytes", "throughput_rps", "reference_throughput_rps",
                   "difference_ms", "size_control"}
SIZE_CONTROL_KEYS = {"token_bytes", "pad", "difference_ms"}
RAW_COLUMNS = ["client", "concurrency", "algorithm", "variant", "signed_with", "pad",
               "token_bytes", "worker", "sequence", "nonce", "start_ns", "total_ns",
               "handler_ns", "verify_ns", "status", "verified", "error"]
INT_COLUMNS = ("concurrency", "pad", "token_bytes", "worker", "sequence", "start_ns", "total_ns")
OPTIONAL_INT_COLUMNS = ("handler_ns", "verify_ns", "status")
MODEL_KEYS = {"basis", "mss_bytes", "initial_window_segments", "profiles", "rows"}
MODEL_ROW_KEYS = {"algorithm", "request_bytes", "extra_request_bytes", "modeled"}
MODELED_KEYS = {"uplink_mbps", "rtt_ms", "transfer_ms", "difference_ms"}
PROFILES = [{"uplink_mbps": 100, "rtt_ms": 10}, {"uplink_mbps": 10, "rtt_ms": 50},
            {"uplink_mbps": 1, "rtt_ms": 100}]
HEADER_LINE = {"bearer": len("Authorization: Bearer \r\n"), "cookie": len("Cookie: jwt=\r\n")}
RUN_LOAD_DEFAULTS = {"algorithms": None, "transport": "bearer", "clients": None,
                     "concurrency": [1, 4], "duration": 5.0, "warmup": 1.0, "claims": "minimal",
                     "reference": "ES256", "size_controls": True, "timeout": 60.0,
                     "proxy_buffers": None, "header_buffers": None, "upstream_keepalive": None}
SHARED_OPTIONS = ("--proxy-port", "--app-port", "--run-dir", "--timeout", "--proxy-buffers",
                  "--header-buffers")
LOAD_OPTIONS = (*SHARED_OPTIONS, "--transport", "--client", "--alg", "--claims", "--concurrency",
                "--duration", "--warmup", "--reference", "--no-size-controls", "--settings",
                "--output-dir")

# Sprint 2's verify response bodies (scripts/transport_app.py at BASE_COMMIT).
VERIFIED_KEYS = {"layer", "verified", "algorithm", "source", "token_bytes", "claims",
                 "experiment_key", "received"}
FAILED_KEYS = {"layer", "verified", "source", "error", "experiment_key", "received"}
APP_LOG_MESSAGE = re.compile(r'^(?P<remote>\S+) "(?P<method>\S+) (?P<target>\S+) '
                             r'(?P<protocol>\S+)" (?P<status>\d{3}) ?(?P<fields>.*)$')

TRANSPORT_HEADINGS = ("Stack", "Versions and documented limits", "Setup", "Run the check",
                      "Support for Sprint 2 tasks", "Limitations")
RESULTS_HEADINGS = ("Workload", "Latency and throughput", "Token size versus verification",
                    "Modeled network cost", "Reproduce", "Limitations")
S3_01_ITEMS = (
    "Define the workload (request mix, concurrency, duration, and where the client runs) and "
    "record it with every run.",
    "Measure request latency (median and p95) and throughput for every configuration through the "
    "Sprint 2 path, separating token transfer, verification, and other server handling.",
)

IMPORT_CHECK = """\
import json
import os
import subprocess
import sys
import threading
sys.path.insert(0, sys.argv[1])
import scripts.transport_load
listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True)
output, _ = listing.communicate()
children = [fields[0] for fields in (line.split() for line in output.splitlines())
            if len(fields) == 2 and fields[1] == str(os.getpid())
            and fields[0] != str(listing.pid)]
print(json.dumps({"children": len(children), "threads": threading.active_count()}))
"""
STACK_IMPORT_CHECK = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
import scripts.transport_stack
print(json.dumps(sorted(name for name in ("scripts.transport_load", "scripts.algorithms",
                                          "cryptography", "playwright")
                        if name in sys.modules)))
"""


# ---- the module under test ---------------------------------------------------------------

def module():
    """Return scripts.transport_load, failing the calling test when it cannot be imported."""
    if transport_load is None:
        raise AssertionError(f"scripts/transport_load.py cannot be imported: {LOAD_IMPORT_ERROR}")
    return transport_load


def run_load(stack, **settings) -> dict:
    return module().run_load(stack, **settings)


def write_load_results(result: dict, output_dir: Path):
    return module().write_load_results(result, output_dir)


def summary_lines(result: dict) -> list[str]:
    return module().summary_lines(result)


def modeled_transfer_ms(request_bytes, uplink_mbps, rtt_ms) -> float:
    return module().modeled_transfer_ms(request_bytes, uplink_mbps, rtt_ms)


# ---- general helpers ---------------------------------------------------------------------

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def free_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for probe in sockets:
            probe.bind((HOST, 0))
        return [probe.getsockname()[1] for probe in sockets]
    finally:
        for probe in sockets:
            probe.close()


def accepts(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=2):
            return True
    except OSError:
        return False


def eventually(condition, grace: float = GRACE) -> bool:
    """Poll a condition for a grace period, e.g. while nginx writes its access log."""
    deadline = time.monotonic() + grace
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.1)
    return True


def refused(port: int) -> bool:
    return eventually(lambda: not accepts(port))


def time_wait_count() -> int:
    """The number of TCP connections in TIME_WAIT on this machine, or 0 when it cannot be read."""
    if sys.platform.startswith("linux"):
        count = 0
        for name in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(name, encoding="ascii") as table:
                    count += sum(line.split()[3] == "06" for line in list(table)[1:])
            except (OSError, IndexError):
                pass
        return count
    try:
        listing = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True,
                                 timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return 0
    return listing.stdout.count("TIME_WAIT")


def wait_for_ephemeral_ports() -> None:
    """Before a load run, let earlier runs' TIME_WAIT connections drain; never a failure."""
    deadline = time.monotonic() + TIME_WAIT_GRACE
    while time_wait_count() >= TIME_WAIT_LIMIT and time.monotonic() < deadline:
        time.sleep(1.0)


def port_options(ports: list[int]) -> list[str]:
    return ["--proxy-port", str(ports[0]), "--app-port", str(ports[1])]


def cli_environment(**extra: str) -> dict:
    return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **extra}


def run_cli(*arguments, cwd, environment: dict | None = None,
            timeout: float = CLI_TIMEOUT) -> subprocess.CompletedProcess:
    """Run the CLI like subprocess.run, but stop it with SIGTERM so it can clean up on timeout."""
    process = subprocess.Popen([sys.executable, str(SCRIPT), *map(str, arguments)], cwd=cwd,
                               env=environment or cli_environment(), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop(process)
        raise AssertionError(f"{list(arguments)} did not finish within {timeout} s") from None
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def run_python(code: str, *arguments: str) -> subprocess.CompletedProcess:
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    return subprocess.run([sys.executable, "-c", code, *arguments], cwd=REPO, env=environment,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def git_show(path: str) -> str | None:
    """Return a file as committed at BASE_COMMIT, or None when git or the commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), "show", f"{BASE_COMMIT}:{path}"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def tracked_files() -> list[str] | None:
    try:
        result = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True,
                                text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return [path for path in result.stdout.split("\0") if path]


@contextmanager
def hidden_modules(*names: str):
    """Make `import <name>` raise ImportError while the context is active."""
    saved = {name: sys.modules[name] for name in names if name in sys.modules}
    for name in names:
        sys.modules[name] = None
    try:
        yield
    finally:
        for name in names:
            if name in saved:
                sys.modules[name] = saved[name]
            else:
                sys.modules.pop(name, None)


_ENVIRONMENT: dict = {}


def reference_environment() -> dict:
    """scripts.benchmark.environment() of this process, computed once."""
    if not _ENVIRONMENT:
        _ENVIRONMENT.update(benchmark_environment())
    return _ENVIRONMENT


def private_names() -> list[str]:
    """This machine's host name and user name, which no result may contain."""
    names = {socket.gethostname(), socket.gethostname().split(".")[0]}
    try:
        names.add(getpass.getuser())
    except (OSError, KeyError):
        pass
    return [name for name in names if len(name) >= 4 and name != "localhost"]


def is_int(value) -> bool:
    return type(value) is int


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


# ---- what the spec says a run records ----------------------------------------------------

def expected_settings(**given) -> dict:
    """The settings run_load records for these keyword arguments (R3, R12)."""
    reference = given.get("reference", "ES256")
    selected = given.get("algorithms")
    algorithms = (list(NAMES) if selected is None
                  else [name for name in NAMES if name in selected or name == reference])
    clients = given.get("clients")
    return {"algorithms": algorithms, "transport": given.get("transport", "bearer"),
            "clients": list(CLIENTS) if clients is None else list(clients),
            "claims": given.get("claims", "minimal"),
            "concurrency": list(given.get("concurrency", (1, 4))),
            "duration": given.get("duration", 5.0), "warmup": given.get("warmup", 1.0),
            "reference": reference, "size_controls": given.get("size_controls", True),
            "timeout": given.get("timeout", 60.0), "proxy_buffers": given.get("proxy_buffers"),
            "header_buffers": given.get("header_buffers"),
            "upstream_keepalive": given.get("upstream_keepalive")}


def signed_bytes(signed_with: str, claims: str, pad: int) -> int:
    return token_bytes(signed_with, padded_claims(claim_set(claims), pad))


def expected_cells(settings: dict) -> list[tuple]:
    """(client, concurrency, algorithm, variant, signed_with, pad) of every cell, in order (R4)."""
    claims = claim_set(settings["claims"])
    reference = settings["reference"]
    cells = []
    for client in settings["clients"]:
        for concurrency in settings["concurrency"]:
            for name in settings["algorithms"]:
                cells.append((client, concurrency, name, "token", name, 0))
                if settings["size_controls"] and name != reference:
                    pad = pad_for_target(reference, claims, token_bytes(name, claims))
                    if pad is not None:
                        cells.append((client, concurrency, name, "size_control", reference, pad))
    return cells


def cell_key(entry: dict) -> tuple:
    return tuple(entry[key] for key in ("client", "concurrency", "algorithm", "variant",
                                        "signed_with", "pad"))


def direct_request_bytes(proxy_url: str, transport: str, size: int) -> int:
    """The request header block http.client sends for a token of `size` bytes (R22)."""
    block = (f"GET {VERIFY_PATH}?timing=1&nonce={'0' * 32} HTTP/1.1\r\n"
             f"Host: {urlsplit(proxy_url).netloc}\r\nAccept-Encoding: identity\r\n\r\n")
    return len(block.encode("latin-1")) + HEADER_LINE[transport] + size


def slow_start_ms(size: int, uplink_mbps: float, rtt_ms: float) -> float:
    """R22's model written out independently: upload time plus one RTT per extra round."""
    flights, sent, window = 0, 0, 10 * 1460
    while sent < size:
        sent, window, flights = sent + window, window * 2, flights + 1
    return size * 8 / (uplink_mbps * 1_000_000) * 1000 + (flights - 1) * rtt_ms


def component_values(rows: list[dict]) -> dict[str, list[int]]:
    """Per-request nanoseconds of each latency component over the verified rows (R9)."""
    verified = [row for row in rows if row["verified"]]
    return {"total": [row["total_ns"] for row in verified],
            "transfer": [row["total_ns"] - row["handler_ns"] for row in verified],
            "other_handling": [row["handler_ns"] - row["verify_ns"] for row in verified],
            "verification": [row["verify_ns"] for row in verified]}


def mean_ms(cell: dict, component: str) -> float:
    return cell["latency"][component]["mean_ms"]


def csv_field(value) -> str:
    """A raw value as R13 writes it: null as an empty field, booleans as true/false."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def raw_rows_from_csv(path: Path) -> tuple[list[str], list[dict]]:
    """Read raw.csv.gz back into the types of result["raw"]."""
    with gzip.open(path, "rt", encoding="utf-8", newline="") as file:
        reader = csv.reader(file)
        header = next(reader, [])
        rows = []
        for values in reader:
            row = dict(zip(header, values))
            for key in INT_COLUMNS:
                row[key] = int(row[key])
            for key in OPTIONAL_INT_COLUMNS:
                row[key] = int(row[key]) if row[key] else None
            row["verified"] = {"true": True, "false": False}[row["verified"]]
            row["error"] = row["error"] or None
            rows.append(row)
    return header, rows


def log_nonces(text: str) -> set[str]:
    return set(LOGGED_NONCE.findall(text))


def logged_requests(text: str) -> list[tuple[str, int, dict]]:
    """(target, status, key=value fields) of each request line in app.log or nginx's log."""
    found = []
    for line in text.splitlines():
        match = REQUEST_LINE.search(line)
        if match:
            fields = dict(item.split("=", 1) for item in match["fields"].split() if "=" in item)
            found.append((match["target"], int(match["status"]), fields))
    return found


def query_of(target: str) -> dict:
    return dict(parse_qsl(urlsplit(target).query, keep_blank_values=True))


def token_algorithm(token: str) -> str | None:
    """The unverified `alg` of a compact JWT, or None."""
    try:
        segment = token.split(".", 1)[0]
        header = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        return header.get("alg")
    except (ValueError, AttributeError):
        return None


# ---- Markdown helpers --------------------------------------------------------------------

def headings(lines: list[str]) -> list[tuple[int, str, int]]:
    """Return (level, text, line index) for Markdown headings outside fenced code blocks."""
    found, fenced = [], False
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced:
            match = re.match(r"(#{1,6}) (.*?)\s*$", line)
            if match:
                found.append((len(match[1]), match[2], index))
    return found


def section(text: str, title: str, level: int = 2) -> str | None:
    """Return the body below the first heading named title (or starting with it) at a level."""
    lines = text.splitlines()
    marks = headings(lines)
    for position, (depth, name, index) in enumerate(marks):
        if depth == level and (name == title or name.startswith(f"{title} ")):
            end = next((line for depth_after, _, line in marks[position + 1:]
                        if depth_after <= level), len(lines))
            return "\n".join(lines[index + 1:end])
    return None


def code_blocks(text: str) -> list[str]:
    blocks, current = [], None
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            if current is None:
                current = []
            else:
                blocks.append("\n".join(current))
                current = None
        elif current is not None:
            current.append(line)
    return blocks


def table_rows(text: str) -> list[str]:
    """The Markdown table rows of text, without separator rows."""
    return [line.strip() for line in text.splitlines() if line.strip().startswith("|")
            and not re.fullmatch(r"[|:\-\s]+", line.strip())]


def relative_links(text: str) -> list[str]:
    targets = re.findall(r"\]\(([^)\s]+)\)", text)
    return [target for target in targets
            if not target.startswith(("http://", "https://", "#", "mailto:"))]


def contains_number(text: str, number: int) -> bool:
    return re.search(rf"(?<![\d,.])(?:{number}|{number:,})(?!,?\d)", text) is not None


DISPLAYED_NUMBER = re.compile(r"(?<![\w.])[-−+]?\d[\d,]*(?:\.\d+)?")


def shows(text: str, value: float, scales=(1,)) -> bool:
    """True when text shows value (or value times a scale) at the precision it is shown with."""
    for name in NAMES:  # "ML-DSA-44" and "SHA2-128f" are names, not numbers.
        text = text.replace(name, " ")
    for match in DISPLAYED_NUMBER.finditer(text):
        shown = match.group().replace("−", "-").replace("+", "").replace(",", "")
        decimals = len(shown.partition(".")[2])
        for scale in scales:
            if abs(float(shown) - value * scale) <= 0.5 * 10 ** -decimals + 1e-9:
                return True
    return False


# ---- a stand-in for nginx and the application --------------------------------------------

class StandIn:
    """Answer the issue and verify endpoints in place of nginx, as each test chooses.

    It records every request with its connection's client port and header block, and appends a
    request line to <run_dir>/logs/proxy-access.log and app.log. app_url names a port where
    nothing listens, so run_load must never need the application directly.
    """

    VERIFY_NS = 1_000
    HANDLER_NS = 3_000

    def __init__(self, root: Path):
        self.run_dir = root / "stand-in-run"
        for directory in (self.run_dir / "logs", self.run_dir / "nginx"):
            directory.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "nginx" / "nginx.conf").write_text("# stand-in\n", encoding="utf-8")
        for name in LOG_NAMES:
            (self.run_dir / "logs" / name).touch()
        self.lock = threading.Lock()
        self.records: list[SimpleNamespace] = []
        self.keys: dict[str, object] = {}
        self.issue_mode = self.verify_mode = "ok"
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                stand_in.answer(self)

            def log_message(self, *arguments):
                pass  # answer() writes the log lines.

        self.server = ThreadingHTTPServer((HOST, 0), Handler)
        self.server.daemon_threads = True
        self.proxy_url = f"http://{HOST}:{self.server.server_address[1]}"
        self.app_url = f"http://{HOST}:{free_ports(1)[0]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exception):
        self.server.shutdown()
        self.server.server_close()

    def mark(self) -> int:
        with self.lock:
            return len(self.records)

    def since(self, mark: int) -> list[SimpleNamespace]:
        with self.lock:
            return list(self.records[mark:])

    def token(self, algorithm: str, claims: str, pad: int) -> str:
        with self.lock:
            if algorithm not in self.keys:
                self.keys[algorithm] = ADAPTERS[algorithm].generate_keypair()[0]
            private_key = self.keys[algorithm]
        return padded_token(algorithm, claim_set(claims), pad, private_key)

    def answer(self, handler: BaseHTTPRequestHandler) -> None:
        parts = urlsplit(handler.path)
        headers = list(handler.headers.items())
        record = SimpleNamespace(path=parts.path, query=query_of(handler.path),
                                 headers={name.lower(): value for name, value in headers},
                                 port=handler.client_address[1], token=None, status=None,
                                 header_bytes=sum(len(name) + len(value) + 4
                                                  for name, value in headers),
                                 body_bytes=None)
        if parts.path == ISSUE_PATH:
            status, body, marked = self.issue(record)
        elif parts.path == VERIFY_PATH:
            status, body, marked = self.verify(record)
        else:
            status, body, marked = 404, {"layer": "application", "error": "not found"}, True
        data = None if status is None else (json.dumps(body) + "\n").encode("utf-8")
        record.status, record.body_bytes = status, None if data is None else len(data)
        with self.lock:
            self.records.append(record)
            for name in ("proxy-access.log", "app.log"):
                with (self.run_dir / "logs" / name).open("a", encoding="utf-8") as log:
                    log.write(f'{HOST} "GET {handler.path} HTTP/1.1" {status or 0}\n')
        if data is None:  # No response at all: the connection is closed instead.
            time.sleep(0.02)
            handler.close_connection = True
            return
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(data)))
        if marked:
            handler.send_header(PROXY_MARKER, "nginx (stand-in)")
        handler.end_headers()
        handler.wfile.write(data)

    def issue(self, record: SimpleNamespace) -> tuple:
        query = record.query
        if self.issue_mode == "error":
            return 503, {"layer": "application", "error": "stand-in failure"}, True
        algorithm, claims, pad = (query.get("alg"), query.get("claims", "minimal"),
                                  query.get("pad", "0"))
        if algorithm not in ADAPTERS or claims not in CLAIM_SETS or not pad.isdigit():
            return 400, {"layer": "application", "error": "bad issue parameters"}, True
        body = {"layer": "application", "algorithm": algorithm, "delivery": "body",
                "experiment_key": True}
        if self.issue_mode == "no_token":
            return 200, body, True
        record.token = self.token(algorithm, claims, int(pad))
        return 200, {**body, "token": record.token, "token_bytes": len(record.token)}, True

    def verify(self, record: SimpleNamespace) -> tuple:
        authorization = record.headers.get("authorization", "")
        cookie = record.headers.get("cookie", "")
        if authorization.startswith("Bearer "):
            record.token, source = authorization[len("Bearer "):], "bearer"
        elif cookie.startswith("jwt="):
            record.token, source = cookie[len("jwt="):], "cookie"
        else:
            return 401, {"layer": "application", "verified": False, "error": "no token"}, True
        mode = self.verify_mode
        if mode == "drop":
            return None, None, False
        algorithm = token_algorithm(record.token)
        body = {"layer": "application", "verified": mode != "unverified", "algorithm": algorithm,
                "source": source, "token_bytes": len(record.token), "claims": {},
                "experiment_key": True,
                "received": {"headers": len(record.headers), "header_bytes": record.header_bytes,
                             "cookie_bytes": None, "authorization_bytes": None}}
        if mode == "wrong_alg":
            body["algorithm"] = "RS256" if algorithm != "RS256" else "ES256"
        if mode == "wrong_source":
            body["source"] = "cookie" if source == "bearer" else "bearer"
        if record.query.get("timing") == "1":
            body["timing"] = {"verify_ns": self.VERIFY_NS, "handler_ns": self.HANDLER_NS}
        return (401 if mode == "status_401" else 200), body, mode != "no_marker"


# ---- in-process WSGI calls ---------------------------------------------------------------

class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def wsgi_call(application, target: str, headers: dict | None = None) -> SimpleNamespace:
    """Call a WSGI application in process; return its status, headers, body, and log lines."""
    path, _, query = target.partition("?")
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query,
               "REQUEST_URI": target, "REMOTE_ADDR": HOST, "SERVER_PROTOCOL": "HTTP/1.1"}
    for name, value in (headers or {}).items():
        environ[f"HTTP_{name.upper().replace('-', '_')}"] = value
    setup_testing_defaults(environ)
    started = {}

    def start_response(status, response_headers, exc_info=None):
        started.update(status=status, headers=list(response_headers))
        return lambda data: None

    logger = logging.getLogger("transport_app")
    capture, level = LogCapture(), logger.level
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    try:
        chunks = application(environ, start_response)
        body = b"".join(chunks)
    finally:
        logger.removeHandler(capture)
        logger.setLevel(level)
    return SimpleNamespace(status=started["status"], code=int(started["status"].split()[0]),
                           headers=started["headers"], body=body, log=capture.messages)


def base_application():
    """scripts/transport_app.py as of BASE_COMMIT, sharing this process's experiment keys."""
    text = git_show("scripts/transport_app.py")
    if text is None:
        return None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "transport_app_s2.py"
        path.write_text(text, encoding="utf-8")
        # A name inside the scripts package, so the module does not change sys.path.
        spec = importlib.util.spec_from_file_location("scripts._transport_app_s2", path)
        base = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(base)
    base.EXPERIMENT_KEYS = transport_app.EXPERIMENT_KEYS
    base.EXPERIMENT_KEYS_LOCK = transport_app.EXPERIMENT_KEYS_LOCK
    base.TEST_PAGE = transport_app.TEST_PAGE
    return base


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def cookie(token: str) -> dict:
    return {"Cookie": f"jwt={token}"}


def tampered(token: str) -> str:
    """Change one character in the middle of the signature segment."""
    header, payload, signature = token.split(".")
    middle = len(signature) // 2
    changed = "A" if signature[middle] != "A" else "B"
    return f"{header}.{payload}.{signature[:middle]}{changed}{signature[middle + 1:]}"


def foreign_alg_token() -> str:
    """A well-formed token whose header names HS256, which no adapter handles."""
    def segment(value: dict) -> str:
        data = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    return f"{segment({'alg': 'HS256', 'typ': 'JWT'})}.{segment({'sub': 'x'})}.c2ln"


def log_fields(message: str) -> tuple[str, list[str]]:
    """Split an app.log message into its target and its key=value fields, in order."""
    match = APP_LOG_MESSAGE.match(message)
    if match is None:
        raise AssertionError(f"unexpected app.log line: {message!r}")
    return match["target"], match["fields"].split()


# ---- checks that every recorded run must pass --------------------------------------------

class LoadCase(unittest.TestCase):
    """Assertions shared by every run_load result, whatever served it (R3-R12, R22)."""

    def assertUtc(self, text) -> datetime:
        self.assertIsInstance(text, str)
        value = datetime.fromisoformat(text)
        self.assertEqual(value.utcoffset(), timedelta(0), text)
        return value

    def assertClose(self, first, second, msg=None) -> None:
        self.assertTrue(is_number(first), f"{first!r} is not a number: {msg}")
        self.assertTrue(math.isclose(first, second, rel_tol=1e-9, abs_tol=1e-9),
                        f"{first!r} != {second!r}: {msg}")

    def check_private(self, text: str) -> None:
        """R12, R13: no token and no host or user name."""
        self.assertNotIn("eyJ", text)
        for name in private_names():
            self.assertNotIn(name, text)

    def check_result(self, result: dict, settings: dict, stack=None) -> None:
        """Check run_load's result in full."""
        self.assertIsInstance(result, dict)
        self.assertEqual(set(result), RESULT_KEYS)
        self.check_recorded(result, result["raw"], settings)
        for row in result["raw"]:
            self.assertEqual(list(row), RAW_COLUMNS)
        if stack is not None:
            self.assertEqual(result["proxy_url"], stack.proxy_url)
            self.assertEqual(result["app_url"], stack.app_url)
            self.assertEqual(result["run_dir"], str(stack.run_dir))
        self.check_private(json.dumps(result))
        self.check_summary(summary_lines(result), result["comparisons"])

    def check_summary(self, lines, comparisons: list[dict]) -> None:
        """R14: one line per comparison, naming its client, concurrency, and configuration."""
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), len(comparisons))
        for line, entry in zip(lines, comparisons):
            self.assertIsInstance(line, str)
            self.assertIn(entry["client"], line)
            self.assertIn(entry["algorithm"], line)
            rest = line.replace(entry["algorithm"], " ")
            self.assertRegex(rest, rf"(?<![\d.]){entry['concurrency']}(?![\d.])")

    def check_recorded(self, result: dict, raw: list[dict], settings: dict,
                       local: bool = True) -> None:
        """Check a result, or a saved load.json with raw rows read back, against its settings."""
        self.assertIs(type(result["schema_version"]), int)
        self.assertEqual(result["schema_version"], 1)
        self.assertLessEqual(self.assertUtc(result["started_utc"]),
                             self.assertUtc(result["finished_utc"]))
        self.assertEqual(set(result["settings"]), SETTINGS_KEYS)
        self.assertEqual(result["settings"], settings)
        self.check_workload(result["workload"], settings)
        self.check_environment(result["environment"], local)
        self.assertEqual(result["layers"], manifest_layers(load_manifest()))
        if "browser" in settings["clients"]:
            self.assertIsInstance(result["browser"], dict)
            self.assertEqual(set(result["browser"]), {"version", "user_agent"})
            for value in result["browser"].values():
                self.assertTrue(isinstance(value, str) and value.strip())
        else:
            self.assertIsNone(result["browser"])
        for key in ("proxy_url", "app_url", "run_dir"):
            self.assertIsInstance(result[key], str)
        self.assertIs(result["experiment_keys"], True)
        self.check_cells(result, raw, settings)
        self.check_comparisons(result, settings)
        self.check_network_model(result, settings)

    def check_workload(self, workload: dict, settings: dict) -> None:
        self.assertLessEqual({"request_mix", "loop", "client_location", "timers"}, set(workload))
        mix = workload["request_mix"]
        self.assertIsInstance(mix, list)
        self.assertEqual(len(mix), 1)
        self.assertEqual((mix[0]["method"], mix[0]["path"], mix[0]["fraction"]),
                         ("GET", VERIFY_PATH, 1.0))
        self.assertEqual(workload["loop"], "closed")
        self.assertEqual(set(workload["client_location"]), {"network", *settings["clients"]})
        for key in settings["clients"]:
            value = workload["client_location"][key]
            self.assertTrue(isinstance(value, str) and value.strip(), key)
        self.assertEqual(set(workload["timers"]), {"server", *settings["clients"]})

    def check_environment(self, environment: dict, local: bool) -> None:
        expected = reference_environment()
        self.assertLessEqual({*expected, "page_size_bytes", "waitress_threads"}, set(environment))
        self.assertEqual(environment["waitress_threads"], 4)
        if local:
            self.assertEqual(environment["page_size_bytes"], PAGE_SIZE)
            for key in ("python", "platform", "machine", "cryptography", "pyjwt", "pqcrypto",
                        "openssl"):
                self.assertEqual(environment[key], expected[key], key)
        else:
            self.assertTrue(is_int(environment["page_size_bytes"]))
            self.assertGreater(environment["page_size_bytes"], 0)

    def check_cells(self, result: dict, raw: list[dict], settings: dict) -> None:
        """R4, R5, R9, R11: the cells, their order, and their values recomputed from raw rows."""
        results = result["results"]
        self.assertIsInstance(results, list)
        self.assertEqual([cell_key(cell) for cell in results], expected_cells(settings))
        claims = claim_set(settings["claims"])
        position = 0
        for cell in results:
            with self.subTest(cell=cell_key(cell)):
                self.assertEqual(set(cell), CELL_KEYS)
                self.assertEqual(cell["claims"], settings["claims"])
                self.assertEqual(cell["token_bytes"], signed_bytes(cell["signed_with"],
                                                                   settings["claims"],
                                                                   cell["pad"]))
                if cell["variant"] == "size_control":
                    own = token_bytes(cell["algorithm"], claims)
                    self.assertIn(cell["token_bytes"], (own, own - 1))
                issue = cell["issue"]
                self.assertEqual(set(issue), ISSUE_KEYS)
                self.assertIsInstance(issue["delivered"], bool)
                if issue["delivered"]:
                    self.assertEqual(issue["status"], 200)
                else:
                    self.assertTrue(isinstance(issue["error"], str) and issue["error"].strip())
                    self.assertEqual(cell["requests"], 0)
                for key in ("requests", "verified", "failed"):
                    self.assertTrue(is_int(cell[key]) and cell[key] >= 0, key)
                self.assertLessEqual(cell["verified"], cell["requests"])
                self.assertEqual(cell["failed"], cell["requests"] - cell["verified"])
                self.assertIsInstance(cell["statuses"], dict)
                self.assertEqual(sum(cell["statuses"].values()), cell["requests"])
                for status in cell["statuses"]:
                    self.assertTrue(status == "error" or re.fullmatch(r"\d{3}", status), status)
                rows = raw[position:position + cell["requests"]]
                position += cell["requests"]
                self.check_rows(cell, rows, settings)
        self.assertEqual(position, len(raw), "raw rows outside every cell")
        nonces = [row["nonce"] for row in raw]
        self.assertEqual(len(nonces), len(set(nonces)), "a nonce repeats within the run")

    def check_rows(self, cell: dict, rows: list[dict], settings: dict) -> None:
        self.assertEqual(len(rows), cell["requests"])
        window_ns = settings["duration"] * 1_000_000_000 + WINDOW_SLACK_NS
        sequences = defaultdict(list)
        for row in rows:
            for key in ("client", "concurrency", "algorithm", "variant", "signed_with", "pad",
                        "token_bytes"):
                self.assertEqual(row[key], cell[key], key)
            self.assertTrue(is_int(row["worker"]) and 0 <= row["worker"] < cell["concurrency"])
            self.assertTrue(is_int(row["sequence"]) and row["sequence"] >= 1)
            self.assertIsInstance(row["nonce"], str)
            self.assertRegex(row["nonce"], rf"^{NONCE.pattern}$")
            self.assertTrue(is_int(row["start_ns"]) and 0 <= row["start_ns"] <= window_ns, row)
            self.assertTrue(is_int(row["total_ns"]) and row["total_ns"] >= 0, row)
            self.assertIsInstance(row["verified"], bool)
            self.assertTrue(row["status"] is None or is_int(row["status"]), row)
            self.assertTrue(row["error"] is None or isinstance(row["error"], str), row)
            if row["status"] is None:
                self.assertTrue(row["error"] and row["error"].strip(), row)
            for key in ("handler_ns", "verify_ns"):
                self.assertTrue(row[key] is None or is_int(row[key]), row)
            if row["verified"]:
                self.assertEqual(row["status"], 200)
                self.assertTrue(is_int(row["handler_ns"]) and is_int(row["verify_ns"]), row)
                self.assertLessEqual(0, row["verify_ns"])
                self.assertLessEqual(row["verify_ns"], row["handler_ns"])
            sequences[row["worker"]].append(row["sequence"])
        for worker, seen in sequences.items():
            self.assertEqual(sorted(seen), list(range(1, len(seen) + 1)), f"worker {worker}")

        statuses = Counter("error" if row["status"] is None else str(row["status"])
                           for row in rows)
        self.assertEqual({key: count for key, count in cell["statuses"].items() if count},
                         dict(statuses))
        verified = [row for row in rows if row["verified"]]
        self.assertEqual(cell["verified"], len(verified))
        if not verified:
            self.assertIsNone(cell["latency"])
        else:
            values = component_values(verified)
            self.assertEqual(set(cell["latency"]), set(COMPONENTS))
            for component in COMPONENTS:
                summary = cell["latency"][component]
                self.assertEqual(set(summary), SUMMARY_KEYS)
                expected = summarize(values[component])
                self.assertEqual(summary["median_ms"], expected["median_ms"], component)
                self.assertEqual(summary["p95_ms"], expected["p95_ms"], component)
                self.assertClose(summary["mean_ms"],
                                 statistics.fmean(values[component]) / 1_000_000, component)

        if cell["requests"] == 0:
            self.assertEqual(cell["measured_seconds"], 0.0)
            self.assertEqual(cell["throughput_rps"], 0.0)
        else:
            self.assertTrue(is_number(cell["measured_seconds"]))
            self.assertGreater(cell["measured_seconds"], 0)
            last = max(row["start_ns"] + row["total_ns"] for row in rows) / 1_000_000_000
            self.assertGreaterEqual(cell["measured_seconds"], last - CLOCK_SLACK_SECONDS)
            self.assertClose(cell["throughput_rps"], cell["verified"] / cell["measured_seconds"])

        counted = cell["bytes"]
        self.assertEqual(set(counted), BYTES_KEYS)
        self.assertEqual(counted["header_line"],
                         HEADER_LINE[settings["transport"]] + cell["token_bytes"])
        if verified:
            self.assertTrue(is_int(counted["app_received_headers"]))
            self.assertGreater(counted["app_received_headers"], counted["header_line"])
            self.assertTrue(is_int(counted["response_body"]))
            self.assertGreater(counted["response_body"], 0)
        else:
            self.assertIsNone(counted["app_received_headers"])
            self.assertIsNone(counted["response_body"])

    def check_comparisons(self, result: dict, settings: dict) -> None:
        """R10: one comparison per token cell, with the identities between its parts."""
        reference = settings["reference"]
        cells = {(cell["client"], cell["concurrency"], cell["algorithm"], cell["variant"]): cell
                 for cell in result["results"]}
        tokens = [cell for cell in result["results"] if cell["variant"] == "token"]
        comparisons = result["comparisons"]
        self.assertIsInstance(comparisons, list)
        self.assertEqual(len(comparisons), len(tokens))
        for entry, cell in zip(comparisons, tokens):
            where = (cell["client"], cell["concurrency"], cell["algorithm"])
            with self.subTest(comparison=where):
                self.assertEqual(set(entry), COMPARISON_KEYS)
                self.assertEqual((entry["client"], entry["concurrency"], entry["algorithm"]),
                                 where)
                base = cells[(cell["client"], cell["concurrency"], reference, "token")]
                self.assertEqual(entry["reference"], reference)
                self.assertEqual(entry["token_bytes"], cell["token_bytes"])
                self.assertEqual(entry["reference_token_bytes"], base["token_bytes"])
                self.assertEqual(entry["throughput_rps"], cell["throughput_rps"])
                self.assertEqual(entry["reference_throughput_rps"], base["throughput_rps"])
                difference = entry["difference_ms"]
                if cell["latency"] is None or base["latency"] is None:
                    self.assertIsNone(difference)
                else:
                    self.assertEqual(set(difference), DIFFERENCE_KEYS)
                    for component in COMPONENTS:
                        self.assertClose(difference[component],
                                         mean_ms(cell, component) - mean_ms(base, component),
                                         component)
                    self.assertClose(difference["token_size"],
                                     difference["total"] - difference["verification"])
                    self.assertTrue(math.isclose(difference["token_size"],
                                                 difference["transfer"]
                                                 + difference["other_handling"],
                                                 rel_tol=1e-9, abs_tol=1e-6))
                    if cell["algorithm"] == reference:
                        for value in difference.values():
                            self.assertEqual(value, 0.0)

                control = cells.get((cell["client"], cell["concurrency"], cell["algorithm"],
                                     "size_control"))
                if control is None:
                    self.assertIsNone(entry["size_control"])
                    continue
                size_control = entry["size_control"]
                self.assertEqual(set(size_control), SIZE_CONTROL_KEYS)
                self.assertEqual((size_control["token_bytes"], size_control["pad"]),
                                 (control["token_bytes"], control["pad"]))
                if None in (cell["latency"], control["latency"], base["latency"]):
                    self.assertIsNone(size_control["difference_ms"])
                    continue
                split = size_control["difference_ms"]
                self.assertEqual(set(split), {"token_size", "verification"})
                self.assertClose(split["token_size"],
                                 mean_ms(control, "total") - mean_ms(base, "total"))
                self.assertClose(split["verification"],
                                 mean_ms(cell, "total") - mean_ms(control, "total"))
                self.assertTrue(math.isclose(split["token_size"] + split["verification"],
                                             difference["total"], rel_tol=1e-9, abs_tol=1e-6))

    def check_network_model(self, result: dict, settings: dict) -> None:
        """R22: the calculated cost of each configuration's request on the three profiles."""
        model = result["network_model"]
        self.assertEqual(set(model), MODEL_KEYS)
        basis = model["basis"]
        self.assertIsInstance(basis, str)
        for term in ("calculated", "not measured", "loss", "tls"):
            self.assertIn(term, basis.lower())
        self.assertEqual(model["mss_bytes"], 1460)
        self.assertEqual(model["initial_window_segments"], 10)
        self.assertEqual(model["profiles"], PROFILES)
        rows = model["rows"]
        self.assertEqual([row["algorithm"] for row in rows], settings["algorithms"])
        claims = claim_set(settings["claims"])
        by_name = {row["algorithm"]: row for row in rows}
        reference = by_name[settings["reference"]]
        reference_bytes = token_bytes(settings["reference"], claims)
        for row in rows:
            with self.subTest(model=row["algorithm"]):
                self.assertEqual(set(row), MODEL_ROW_KEYS)
                size = token_bytes(row["algorithm"], claims)
                self.assertEqual(row["request_bytes"],
                                 direct_request_bytes(result["proxy_url"], settings["transport"],
                                                      size))
                self.assertEqual(row["extra_request_bytes"],
                                 row["request_bytes"] - reference["request_bytes"])
                self.assertEqual(row["extra_request_bytes"], size - reference_bytes)
                self.assertEqual(len(row["modeled"]), len(PROFILES))
                for modeled, base, profile in zip(row["modeled"], reference["modeled"], PROFILES):
                    self.assertEqual(set(modeled), MODELED_KEYS)
                    self.assertEqual((modeled["uplink_mbps"], modeled["rtt_ms"]),
                                     (profile["uplink_mbps"], profile["rtt_ms"]))
                    self.assertClose(modeled["transfer_ms"],
                                     slow_start_ms(row["request_bytes"], **profile))
                    self.assertClose(modeled["difference_ms"],
                                     modeled["transfer_ms"] - base["transfer_ms"])
                if row is reference:
                    self.assertEqual(row["extra_request_bytes"], 0)
                    for modeled in row["modeled"]:
                        self.assertEqual(modeled["difference_ms"], 0.0)


# ---- R22: the network model ---------------------------------------------------------------

class NetworkModelTests(unittest.TestCase):
    EXAMPLES = (
        (14_600, 10, 50, 11.68),
        (14_601, 10, 50, 61.6808),
        (43_800, 10, 50, 85.04),
        (43_801, 10, 50, 135.0408),
        (102_200, 10, 50, 181.76),
        (102_201, 10, 50, 231.7608),
        (1, 100, 10, 0.00008),
        (14_601, 100, 0, 1.16808),
        (1_000, 2.5, 10, 3.2),
    )

    def test_constants(self):
        load = module()
        self.assertEqual(load.MSS_BYTES, 1460)
        self.assertEqual(load.INITIAL_WINDOW_SEGMENTS, 10)
        self.assertIsInstance(load.NETWORK_PROFILES, tuple)
        self.assertEqual([dict(profile) for profile in load.NETWORK_PROFILES], PROFILES)

    def test_examples(self):
        for size, uplink, rtt, expected in self.EXAMPLES:
            with self.subTest(size=size, uplink=uplink, rtt=rtt):
                value = modeled_transfer_ms(size, uplink, rtt)
                self.assertIsInstance(value, float)
                self.assertAlmostEqual(value, expected, places=9)

    def test_rounds_double_from_the_initial_window(self):
        for size in (1, 14_599, 14_600, 14_601, 43_799, 43_800, 43_801, 102_200, 102_201,
                     218_999, 219_000, 219_001, 1_000_000):
            for profile in PROFILES:
                with self.subTest(size=size, **profile):
                    self.assertAlmostEqual(modeled_transfer_ms(size, **profile),
                                           slow_start_ms(size, **profile), places=9)

    def test_invalid_arguments(self):
        cases = [(0, 10, 50), (-1, 10, 50), (1.5, 10, 50), (True, 10, 50), ("100", 10, 50),
                 (None, 10, 50), (100, 0, 50), (100, -10, 50), (100, math.nan, 50),
                 (100, math.inf, 50), (100, True, 50), (100, "10", 50), (100, None, 50),
                 (100, 10, -1), (100, 10, math.nan), (100, 10, math.inf), (100, 10, True),
                 (100, 10, "50"), (100, 10, None)]
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                modeled_transfer_ms(*arguments)


# ---- R1: the module and its interface -----------------------------------------------------

class InterfaceTests(unittest.TestCase):
    def test_public_functions_and_defaults(self):
        load = module()
        parameters = inspect.signature(load.run_load).parameters
        self.assertEqual(list(parameters), ["stack", *RUN_LOAD_DEFAULTS])
        self.assertIs(parameters["stack"].default, inspect.Parameter.empty)
        for name, default in RUN_LOAD_DEFAULTS.items():
            with self.subTest(parameter=name):
                value = parameters[name].default
                if name == "concurrency":
                    self.assertEqual(list(value), default)
                elif isinstance(default, bool) or default is None:
                    self.assertIs(value, default)
                else:
                    self.assertEqual(value, default)
        for function, names in ((load.write_load_results, ["result", "output_dir"]),
                                (load.summary_lines, ["result"]),
                                (load.modeled_transfer_ms,
                                 ["request_bytes", "uplink_mbps", "rtt_ms"])):
            with self.subTest(function=function.__name__):
                self.assertEqual(list(inspect.signature(function).parameters), names)

    def test_module_docstring_describes_the_workload(self):
        text = module().__doc__ or ""
        self.assertGreater(len(text.strip()), 200)
        lowered = text.lower()
        for term in ("verify", "nginx"):
            self.assertIn(term, lowered)

    def test_import_starts_no_process_or_thread(self):
        result = run_python(IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"children": 0, "threads": 1})

    def test_stack_module_imports_the_load_module_lazily(self):
        result = run_python(STACK_IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])


# ---- R8: the application's opt-in server timings ------------------------------------------

class ApplicationTimingTests(unittest.TestCase):
    """In-process WSGI calls; the Sprint 2 application at BASE_COMMIT is the reference."""

    @classmethod
    def setUpClass(cls):
        cls.base = base_application()
        cls.tokens = {}
        for algorithm in ("ES256", "EdDSA"):
            reply = wsgi_call(transport_app.application,
                              f"{ISSUE_PATH}?alg={algorithm}&delivery=body")
            cls.tokens[algorithm] = json.loads(reply.body)["token"]

    def failure_cases(self) -> list[tuple[str, dict, int, bool]]:
        """(name, headers, status, whether verify_token is called) of failing verify requests."""
        es256 = self.tokens["ES256"]
        return [("no token", {}, 401, False),
                ("cookie and bearer", {**cookie(es256), **bearer(es256)}, 400, False),
                ("two jwt cookies", {"Cookie": f"jwt={es256}; jwt={es256}"}, 400, False),
                ("unreadable alg", bearer("not-a-token"), 401, False),
                ("foreign alg", bearer(foreign_alg_token()), 401, False),
                ("bad signature", bearer(tampered(es256)), 401, True)]

    def check_timing(self, timing, verify_called: bool) -> None:
        self.assertIsInstance(timing, dict)
        self.assertEqual(set(timing), {"verify_ns", "handler_ns"})
        self.assertIs(type(timing["handler_ns"]), int)
        self.assertGreaterEqual(timing["handler_ns"], 0)
        if verify_called:
            self.assertIs(type(timing["verify_ns"]), int)
            self.assertLessEqual(0, timing["verify_ns"])
            self.assertLessEqual(timing["verify_ns"], timing["handler_ns"])
        else:
            self.assertIsNone(timing["verify_ns"])

    def test_verified_requests_report_both_timings(self):
        for name, headers in (("ES256 bearer", bearer(self.tokens["ES256"])),
                              ("EdDSA cookie", cookie(self.tokens["EdDSA"]))):
            with self.subTest(name):
                plain = wsgi_call(transport_app.application, VERIFY_PATH, headers)
                timed = wsgi_call(transport_app.application, f"{VERIFY_PATH}?timing=1", headers)
                self.assertEqual((plain.code, timed.code), (200, 200))
                body = json.loads(timed.body)
                self.assertEqual(set(body), VERIFIED_KEYS | {"timing"})
                self.check_timing(body["timing"], verify_called=True)
                self.assertEqual({key: value for key, value in body.items() if key != "timing"},
                                 json.loads(plain.body))
                self.assertEqual([name for name, _ in timed.headers],
                                 [name for name, _ in plain.headers])
                self.assertEqual(dict(timed.headers)["Content-Length"], str(len(timed.body)))

    def test_failed_requests_report_timings(self):
        for name, headers, status, verify_called in self.failure_cases():
            with self.subTest(name):
                plain = wsgi_call(transport_app.application, VERIFY_PATH, headers)
                timed = wsgi_call(transport_app.application, f"{VERIFY_PATH}?timing=1", headers)
                self.assertEqual((plain.code, timed.code), (status, status))
                body = json.loads(timed.body)
                self.assertEqual(set(body), FAILED_KEYS | {"timing"})
                self.check_timing(body["timing"], verify_called)
                self.assertEqual({key: value for key, value in body.items() if key != "timing"},
                                 json.loads(plain.body))
                self.assertEqual([name for name, _ in timed.headers],
                                 [name for name, _ in plain.headers])

    def test_other_timing_values_change_nothing(self):
        for query in ("timing=0", "timing=true", "timing=", "timing", "timing=01", "timing=1.0",
                      "timing=yes", "timing=%201", "timing=1%20"):
            for name, headers in (("verified", bearer(self.tokens["ES256"])), ("no token", {})):
                with self.subTest(query=query, request=name):
                    plain = wsgi_call(transport_app.application, VERIFY_PATH, headers)
                    other = wsgi_call(transport_app.application, f"{VERIFY_PATH}?{query}",
                                      headers)
                    self.assertEqual((other.status, other.headers, other.body),
                                     (plain.status, plain.headers, plain.body))
                    self.assertNotIn("timing", json.loads(other.body))

    def test_default_responses_keep_sprint_2_keys(self):
        verified = wsgi_call(transport_app.application, VERIFY_PATH, bearer(self.tokens["ES256"]))
        self.assertEqual(set(json.loads(verified.body)), VERIFIED_KEYS)
        self.assertEqual([name for name, _ in verified.headers],
                         ["Content-Type", "Content-Length"])
        for name, headers, status, _ in self.failure_cases():
            with self.subTest(name):
                reply = wsgi_call(transport_app.application, VERIFY_PATH, headers)
                self.assertEqual(reply.code, status)
                self.assertEqual(set(json.loads(reply.body)), FAILED_KEYS)
                self.assertEqual([name for name, _ in reply.headers],
                                 ["Content-Type", "Content-Length"])

    def test_responses_and_log_lines_match_sprint_2(self):
        if self.base is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        requests = [(VERIFY_PATH, headers) for _, headers, _, _ in self.failure_cases()]
        requests += [
            (VERIFY_PATH, bearer(self.tokens["ES256"])),
            (VERIFY_PATH, cookie(self.tokens["EdDSA"])),
            (f"{VERIFY_PATH}?timing=0&nonce={'a' * 32}", bearer(self.tokens["ES256"])),
            (f"{ISSUE_PATH}?alg=EdDSA&delivery=body", {}),
            (f"{ISSUE_PATH}?alg=EdDSA&delivery=body&timing=1", {}),
            (f"{ISSUE_PATH}?alg=EdDSA&timing=1", {}),
            (f"{ISSUE_PATH}?alg=EdDSA&delivery=body&claims=oidc&pad=5&timing=1", {}),
            (f"{ISSUE_PATH}?alg=HS256&timing=1", {}),
            ("/api/echo?timing=1&x=y", {"X-Test": "1"}),
            ("/?timing=1", {}),
            ("/missing?timing=1", {}),
        ]
        for target, headers in requests:
            with self.subTest(target=target, headers=sorted(headers)):
                new = wsgi_call(transport_app.application, target, headers)
                old = wsgi_call(self.base.application, target, headers)
                self.assertEqual((new.status, new.headers, new.body),
                                 (old.status, old.headers, old.body))
                self.assertEqual(new.log, old.log)

    def test_timed_log_lines_keep_their_fields(self):
        cases = [("verified", bearer(self.tokens["ES256"]))]
        cases += [(name, headers) for name, headers, _, _ in self.failure_cases()]
        for name, headers in cases:
            with self.subTest(name):
                plain = wsgi_call(transport_app.application, VERIFY_PATH, headers)
                timed = wsgi_call(transport_app.application, f"{VERIFY_PATH}?timing=1", headers)
                self.assertEqual((len(plain.log), len(timed.log)), (1, 1))
                plain_target, plain_fields = log_fields(plain.log[0])
                timed_target, timed_fields = log_fields(timed.log[0])
                self.assertEqual(timed_target, f"{VERIFY_PATH}?timing=1")
                self.assertEqual(timed_fields[:len(plain_fields)], plain_fields)
                for message in (plain.log[0], timed.log[0]):
                    self.assertNotIn("eyJ", message)
                    for value in headers.values():
                        self.assertNotIn(value, message)


# ---- run_load against a stand-in ----------------------------------------------------------

class StandInLoadTests(LoadCase):
    """run_load against a stand-in server whose answers each test chooses (R2-R7, R9-R12)."""

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.stand_in = cls.enterClassContext(StandIn(cls.directory))

    def setUp(self):
        self.stand_in.issue_mode = self.stand_in.verify_mode = "ok"

    def short_run(self, **given) -> tuple[dict, list[SimpleNamespace], dict]:
        """Run a short load; return the result, the requests the stand-in saw, and settings."""
        settings = {"algorithms": ["ES256"], "clients": ["direct"], "concurrency": [1],
                    "duration": 0.15, "warmup": 0.0, **given}
        mark = self.stand_in.mark()
        result = run_load(self.stand_in, **settings)
        return result, self.stand_in.since(mark), expected_settings(**settings)

    def test_all_configurations_by_default(self):
        result, _, expected = self.short_run(algorithms=None, concurrency=(1,), duration=0.05)
        self.check_result(result, expected, self.stand_in)
        self.assertEqual(result["settings"]["algorithms"], NAMES)
        controls = [cell["algorithm"] for cell in result["results"]
                    if cell["variant"] == "size_control"]
        self.assertEqual(controls, [name for name in NAMES if name != "ES256"])
        for cell in result["results"]:
            with self.subTest(cell=cell_key(cell)):
                self.assertGreater(cell["verified"], 0)

    def test_reference_claims_tuples_and_recorded_buffers(self):
        # The buffer settings are only recorded: the stand-in has no nginx to configure.
        result, records, expected = self.short_run(algorithms=("ES256",), reference="EdDSA",
                                                   claims="oidc", concurrency=(1,), timeout=30,
                                                   proxy_buffers="16k", header_buffers="32k")
        self.check_result(result, expected, self.stand_in)
        self.assertEqual((result["settings"]["proxy_buffers"],
                          result["settings"]["header_buffers"]), ("16k", "32k"))
        self.assertEqual(result["settings"]["algorithms"], ["ES256", "EdDSA"])
        self.assertEqual(result["settings"]["concurrency"], [1])
        self.assertEqual([cell["variant"] for cell in result["results"]],
                         ["token", "size_control", "token"])
        issues = [record.query for record in records if record.path == ISSUE_PATH]
        self.assertEqual({query.get("claims") for query in issues}, {"oidc"})
        self.assertEqual([entry["reference"] for entry in result["comparisons"]],
                         ["EdDSA", "EdDSA"])

    def test_tokens_are_issued_through_the_proxy_once_per_cell(self):
        result, records, expected = self.short_run(algorithms=["EdDSA"], warmup=0.05)
        self.check_result(result, expected, self.stand_in)
        cells = result["results"]
        issues = [record for record in records if record.path == ISSUE_PATH]
        self.assertEqual(len(issues), len(cells))
        for record, cell in zip(issues, cells):
            query = record.query
            self.assertEqual((query.get("alg"), query.get("delivery"), query.get("claims"),
                              query.get("pad")),
                             (cell["signed_with"], "body", "minimal", str(cell["pad"])))
            self.assertRegex(query.get("nonce", ""), rf"^{NONCE.pattern}$")
        # Each cell's token is issued before its first timed request, and its measured requests
        # carry only that token. R5 does not say whether a cell's token is issued just before it.
        verifies = [(index, record) for index, record in enumerate(records)
                    if record.path == VERIFY_PATH]
        self.assertLessEqual({record.token for _, record in verifies},
                             {issue.token for issue in issues})
        runs = [token for token, _ in groupby(record.token for _, record in verifies)]
        self.assertEqual(len(runs), len(set(runs)), "two cells' requests interleave")
        for issue, cell in zip(issues, cells):
            carrying = [(index, record) for index, record in verifies
                        if record.token == issue.token]
            self.assertTrue(carrying, cell_key(cell))
            self.assertLess(records.index(issue), carrying[0][0])
            sent = {record.query.get("nonce") for _, record in carrying}
            recorded = {row["nonce"] for row in result["raw"] if cell_key(row) == cell_key(cell)}
            self.assertTrue(recorded)
            self.assertLessEqual(recorded, sent)

    def test_timed_requests_differ_only_in_their_token(self):
        result, records, _ = self.short_run(algorithms=["EdDSA"])
        verifies = [record for record in records if record.path == VERIFY_PATH]
        self.assertTrue(verifies)
        self.assertEqual(len({frozenset(record.headers) for record in verifies}), 1)
        others = {tuple(sorted((name, value) for name, value in record.headers.items()
                               if name != "authorization")) for record in verifies}
        self.assertEqual(len(others), 1)
        nonces = []
        for record in verifies:
            self.assertEqual(sorted(record.query), ["nonce", "timing"])
            self.assertEqual(record.query["timing"], "1")
            self.assertRegex(record.query["nonce"], rf"^{NONCE.pattern}$")
            self.assertEqual(record.headers["authorization"], f"Bearer {record.token}")
            self.assertNotIn("cookie", record.headers)
            nonces.append(record.query["nonce"])
        self.assertEqual(len(nonces), len(set(nonces)))
        self.assertGreater(len(result["raw"]), 0)

    def test_cookie_transport_from_the_direct_client(self):
        result, records, expected = self.short_run(transport="cookie")
        self.check_result(result, expected, self.stand_in)
        self.assertGreater(result["results"][0]["verified"], 0)
        issues = [record for record in records if record.path == ISSUE_PATH]
        self.assertEqual([record.query.get("delivery") for record in issues], ["body"])
        for record in records:
            if record.path == VERIFY_PATH:
                self.assertEqual(record.headers.get("cookie"), f"jwt={issues[0].token}")
                self.assertNotIn("authorization", record.headers)

    def test_warm_up_is_sent_but_not_recorded(self):
        result, records, _ = self.short_run(warmup=0.1)
        sent = {record.query["nonce"] for record in records if record.path == VERIFY_PATH}
        recorded = {row["nonce"] for row in result["raw"]}
        self.assertTrue(recorded)
        self.assertLess(recorded, sent)
        result, records, _ = self.short_run(warmup=0.0)
        sent = {record.query["nonce"] for record in records if record.path == VERIFY_PATH}
        self.assertEqual({row["nonce"] for row in result["raw"]}, sent)

    def test_each_worker_keeps_one_connection(self):
        result, records, _ = self.short_run(concurrency=[2], duration=0.2, warmup=0.05)
        ports = {record.query["nonce"]: record.port for record in records
                 if record.path == VERIFY_PATH}
        by_worker = defaultdict(set)
        for row in result["raw"]:
            by_worker[row["worker"]].add(ports[row["nonce"]])
        self.assertEqual(sorted(by_worker), [0, 1])
        for worker, seen in by_worker.items():
            self.assertEqual(len(seen), 1, f"worker {worker} used {len(seen)} connections")
        self.assertEqual(len(set.union(*by_worker.values())), 2)

    def test_server_timings_split_each_request(self):
        result, records, expected = self.short_run(concurrency=[2])
        self.check_result(result, expected, self.stand_in)
        cell = result["results"][0]
        self.assertGreater(cell["verified"], 0)
        for row in result["raw"]:
            self.assertEqual((row["handler_ns"], row["verify_ns"]),
                             (StandIn.HANDLER_NS, StandIn.VERIFY_NS))
        for component, value in (("verification", StandIn.VERIFY_NS),
                                 ("other_handling", StandIn.HANDLER_NS - StandIn.VERIFY_NS)):
            for statistic in SUMMARY_KEYS:
                self.assertAlmostEqual(cell["latency"][component][statistic], value / 1e6,
                                       places=12)
        verifies = [record for record in records if record.path == VERIFY_PATH]
        self.assertEqual(cell["bytes"]["app_received_headers"], verifies[0].header_bytes)
        self.assertEqual(cell["bytes"]["response_body"], verifies[0].body_bytes)

    def test_only_complete_answers_count_as_verified(self):
        for mode, status in (("no_marker", "200"), ("wrong_alg", "200"), ("wrong_source", "200"),
                             ("unverified", "200"), ("status_401", "401")):
            with self.subTest(mode=mode):
                self.stand_in.verify_mode = mode
                result, _, expected = self.short_run()
                self.check_result(result, expected, self.stand_in)
                cell = result["results"][0]
                self.assertGreater(cell["requests"], 0)
                self.assertEqual((cell["verified"], cell["failed"]), (0, cell["requests"]))
                self.assertEqual(cell["statuses"], {status: cell["requests"]})
                self.assertIsNone(cell["latency"])
                self.assertEqual(cell["throughput_rps"], 0.0)
                self.assertIsNone(result["comparisons"][0]["difference_ms"])
                self.assertFalse(any(row["verified"] for row in result["raw"]))

    def test_requests_without_a_response_are_recorded(self):
        self.stand_in.verify_mode = "drop"
        result, _, expected = self.short_run()
        self.check_result(result, expected, self.stand_in)
        cell = result["results"][0]
        self.assertGreater(cell["requests"], 0)
        self.assertEqual(cell["statuses"], {"error": cell["requests"]})
        self.assertEqual(len(result["raw"]), cell["requests"])
        for row in result["raw"]:
            self.assertIsNone(row["status"])
            self.assertFalse(row["verified"])
            self.assertTrue(isinstance(row["error"], str) and row["error"])

    def test_undelivered_tokens_send_no_timed_request(self):
        for mode, status in (("error", 503), ("no_token", 200)):
            with self.subTest(mode=mode):
                self.stand_in.issue_mode = mode
                result, records, expected = self.short_run(algorithms=["EdDSA"])
                self.check_result(result, expected, self.stand_in)
                for cell in result["results"]:
                    self.assertEqual(cell["issue"]["status"], status)
                    self.assertIs(cell["issue"]["delivered"], False)
                    self.assertEqual((cell["requests"], cell["verified"], cell["failed"]),
                                     (0, 0, 0))
                    self.assertEqual((cell["measured_seconds"], cell["throughput_rps"]),
                                     (0.0, 0.0))
                    self.assertIsNone(cell["latency"])
                self.assertEqual([record for record in records if record.path == VERIFY_PATH],
                                 [])
                self.assertEqual(result["raw"], [])
                for entry in result["comparisons"]:
                    self.assertIsNone(entry["difference_ms"])

    def test_upstream_keepalive_is_recorded(self):
        # Team decision after the build: nginx's keepalive count to waitress is a recorded
        # setting, so --settings starts the same stack again. Like the buffers, it is only
        # recorded here; run_load takes the stack's own when it is not given.
        base = {"algorithms": ["ES256"], "clients": ["direct"], "concurrency": [1],
                "duration": 0.05, "warmup": 0.0}
        result, _, expected = self.short_run(upstream_keepalive=8)
        self.check_result(result, expected, self.stand_in)
        self.assertEqual(result["settings"]["upstream_keepalive"], 8)
        stack = SimpleNamespace(proxy_url=self.stand_in.proxy_url,
                                app_url=self.stand_in.app_url,
                                run_dir=self.stand_in.run_dir, upstream_keepalive=8)
        self.assertEqual(run_load(stack, **base)["settings"]["upstream_keepalive"], 8)
        cases = [(self.stand_in, value) for value in (0, 1025, True, "8", 2.0)]
        cases.append((stack, 4))  # A count that does not match the stack's.
        for target, value in cases:
            with self.subTest(stack=type(target).__name__, upstream_keepalive=repr(value)):
                mark = self.stand_in.mark()
                with self.assertRaises(ValueError):
                    run_load(target, **base, upstream_keepalive=value)
                self.assertEqual(self.stand_in.since(mark), [])

    def test_invalid_arguments_raise_before_any_request(self):
        base = {"algorithms": ["ES256"], "clients": ["direct"], "concurrency": [1],
                "duration": 0.05, "warmup": 0.0}
        invalid = [
            {"algorithms": "ES256"}, {"algorithms": []}, {"algorithms": ["ES256", "ES256"]},
            {"algorithms": ["HS256"]}, {"algorithms": [None]}, {"algorithms": 5},
            {"transport": "query"}, {"transport": "Bearer"}, {"transport": None},
            {"clients": []}, {"clients": ["curl"]}, {"clients": ["direct", "direct"]},
            {"clients": "direct"}, {"clients": [None]},
            {"concurrency": []}, {"concurrency": [0]}, {"concurrency": [65]},
            {"concurrency": [-1]}, {"concurrency": [1, 1]}, {"concurrency": [True]},
            {"concurrency": [1.0]}, {"concurrency": [2.5]}, {"concurrency": 1},
            {"concurrency": "1"}, {"concurrency": None},
            {"duration": 0}, {"duration": -1.0}, {"duration": math.nan}, {"duration": math.inf},
            {"duration": True}, {"duration": "5"}, {"duration": None},
            {"warmup": -0.1}, {"warmup": math.nan}, {"warmup": math.inf}, {"warmup": True},
            {"warmup": "1"}, {"warmup": None},
            {"claims": "large"}, {"claims": None},
            {"reference": "HS256"}, {"reference": None},
            {"size_controls": 1}, {"size_controls": "yes"}, {"size_controls": None},
            {"timeout": 0}, {"timeout": -1}, {"timeout": math.nan}, {"timeout": True},
            {"timeout": "60"},
        ]
        for override in invalid:
            with self.subTest(**{key: repr(value) for key, value in override.items()}):
                mark = self.stand_in.mark()
                with self.assertRaises(ValueError):
                    run_load(self.stand_in, **{**base, **override})
                self.assertEqual(self.stand_in.since(mark), [])

    def test_direct_client_needs_no_playwright(self):
        with hidden_modules("playwright", "playwright.sync_api"):
            result, _, expected = self.short_run()
            self.assertIsNone(result["browser"])
            self.assertGreater(result["results"][0]["verified"], 0)
            with self.assertRaises(RuntimeError) as raised:
                run_load(self.stand_in, algorithms=["ES256"], clients=["browser"],
                         concurrency=[1], duration=0.1, warmup=0.0)
        self.assertTrue(str(raised.exception).startswith("automation:"), str(raised.exception))

    def test_playwright_errors_become_browser_errors(self):
        with tempfile.TemporaryDirectory() as empty, \
                mock.patch.dict(os.environ, {"PLAYWRIGHT_BROWSERS_PATH": empty}):
            with self.assertRaises(RuntimeError) as raised:
                run_load(self.stand_in, algorithms=["ES256"], clients=["browser"],
                         concurrency=[1], duration=0.1, warmup=0.0, timeout=30)
        self.assertTrue(str(raised.exception).startswith("browser:"), str(raised.exception))


# ---- run_load against real stacks ---------------------------------------------------------

class StackRun(LoadCase):
    """Starts one stack per class and runs run_load once with the class's settings."""

    stack_options: dict = {}
    settings: dict = {}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        wait_for_ephemeral_ports()
        cls.stack = cls.enterClassContext(start_stack(run_dir=cls.directory / "run",
                                                      **cls.stack_options))
        cls.logs = Path(cls.stack.run_dir) / "logs"
        cls.offsets = {name: file_size(cls.logs / name) for name in LOG_NAMES}
        cls.expected = expected_settings(**cls.settings)
        cls.result = run_load(cls.stack, **cls.settings)

    def run_log(self, name: str) -> str:
        """The part of a log written since this class's run started."""
        try:
            with (self.logs / name).open("rb") as log:
                log.seek(self.offsets[name])
                return log.read().decode("utf-8", errors="replace")
        except OSError:
            return ""

    def cells(self, variant: str | None = None) -> list[dict]:
        return [cell for cell in self.result["results"]
                if variant is None or cell["variant"] == variant]


class RunChecks:
    """Tests shared by every real-stack run; mixed into StackRun subclasses."""

    def test_recorded_run(self):
        self.check_result(self.result, self.expected, self.stack)

    def test_stack_keeps_running(self):
        status, headers, _ = http_get(f"{self.stack.proxy_url}/api/echo", timeout=30)
        self.assertEqual(status, 200)
        self.assertIn(PROXY_MARKER.lower(), headers)

    def test_logs_trace_every_verified_request(self):
        verified = {row["nonce"] for row in self.result["raw"] if row["verified"]}
        self.assertTrue(verified, "no request verified")
        for name in ("proxy-access.log", "app.log"):
            def logged(name=name) -> bool:
                return verified <= log_nonces(self.run_log(name))
            self.assertTrue(eventually(logged), f"a verified request is missing from {name}")
        for name in ("app.log", "proxy-access.log"):
            self.assertNotIn("eyJ", read_text(self.logs / name), name)
        if all(row["verified"] for row in self.result["raw"]):
            self.assertNotIn("eyJ", read_text(self.logs / "proxy-error.log"))

    def test_timed_requests_carry_timing_and_a_nonce(self):
        targets = [target for target, _, _ in logged_requests(self.run_log("app.log"))
                   if urlsplit(target).path == VERIFY_PATH]
        self.assertGreaterEqual(len(targets), sum(row["verified"] for row in self.result["raw"]))
        for target in targets:
            query = parse_qsl(urlsplit(target).query, keep_blank_values=True)
            self.assertEqual(sorted(name for name, _ in query), ["nonce", "timing"], target)
            values = dict(query)
            self.assertEqual(values["timing"], "1")
            self.assertRegex(values["nonce"], rf"^{NONCE.pattern}$")
        logged = {query_of(target)["nonce"] for target in targets}
        recorded = {row["nonce"] for row in self.result["raw"]}
        if self.expected["warmup"] > 0:
            self.assertTrue(logged - recorded, "no warm-up request reached the application")
        else:
            self.assertLessEqual(logged, recorded, "a timed request was not recorded")

    def test_tokens_travel_in_the_transport(self):
        fields = {query_of(target).get("nonce"): values
                  for target, _, values in logged_requests(self.run_log("app.log"))
                  if urlsplit(target).path == VERIFY_PATH}
        transport = self.expected["transport"]
        for row in self.result["raw"]:
            if not row["verified"]:
                continue
            logged = fields.get(row["nonce"])
            self.assertIsNotNone(logged, row["nonce"])
            self.assertEqual((logged.get("alg"), logged.get("token_bytes"), logged.get("verified")),
                             (row["signed_with"], str(row["token_bytes"]), "true"))
            if transport == "bearer":
                carried = (logged.get("authorization_bytes"), logged.get("cookie_bytes"))
                self.assertEqual(carried, (str(len("Bearer ") + row["token_bytes"]), "-"))
            else:
                carried = (logged.get("cookie_bytes"), logged.get("authorization_bytes"))
                self.assertEqual(carried, (str(len("jwt=") + row["token_bytes"]), "-"))

    def test_tokens_were_issued_through_the_proxy(self):
        transport = self.expected["transport"]
        expected = Counter()
        for cell in self.result["results"]:
            delivery = "cookie" if transport == "cookie" and cell["client"] == "browser" else "body"
            expected[(cell["signed_with"], delivery, str(cell["pad"]),
                      self.expected["claims"])] += 1
        access = self.run_log("proxy-access.log")
        issued = Counter()
        pages = 0
        for target, _, _ in logged_requests(access):
            path = urlsplit(target).path
            if path == ISSUE_PATH:
                query = query_of(target)
                issued[(query.get("alg"), query.get("delivery"), query.get("pad"),
                        query.get("claims"))] += 1
            elif path == "/":
                pages += 1
        for key, count in expected.items():
            self.assertGreaterEqual(issued[key], count, key)
        browser_cells = sum(cell["client"] == "browser" for cell in self.result["results"])
        self.assertGreaterEqual(pages, browser_cells)


class DirectLoadTests(RunChecks, StackRun):
    settings = {"algorithms": ["ML-DSA-44"], "clients": ["direct"], "concurrency": [2],
                "duration": 0.2, "warmup": 0.1}

    def test_reference_is_added_in_adapter_order(self):
        self.assertEqual(self.result["settings"]["algorithms"], ["ES256", "ML-DSA-44"])
        self.assertEqual([(cell["algorithm"], cell["variant"]) for cell in self.cells()],
                         [("ES256", "token"), ("ML-DSA-44", "token"),
                          ("ML-DSA-44", "size_control")])

    def test_every_request_verified(self):
        for cell in self.cells():
            with self.subTest(cell=cell_key(cell)):
                self.assertTrue(cell["issue"]["delivered"])
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)
                self.assertEqual(cell["statuses"], {"200": cell["requests"]})

    def test_size_control_is_the_reference_token_padded_to_size(self):
        (control,) = self.cells("size_control")
        self.assertEqual(control["signed_with"], "ES256")
        self.assertGreater(control["pad"], 0)
        own = token_bytes("ML-DSA-44", claim_set("minimal"))
        self.assertIn(control["token_bytes"], (own, own - 1))
        entry = self.result["comparisons"][1]
        self.assertEqual(entry["size_control"]["token_bytes"], control["token_bytes"])
        self.assertIsNotNone(entry["size_control"]["difference_ms"])

    def test_saved_result(self):
        output = self.directory / "saved" / "nested"
        run_logs = sorted(path.name for path in self.logs.iterdir() if path.is_file())
        before = {name: (self.logs / name).read_bytes() for name in run_logs}
        returned = write_load_results(self.result, output)
        self.assertEqual(Path(returned), output)
        self.assertEqual({path.name for path in output.iterdir()},
                         {"load.json", "raw.csv.gz", "logs", "nginx.conf"})
        text = (output / "load.json").read_text(encoding="utf-8")
        saved = json.loads(text)
        self.assertEqual(set(saved), SAVED_KEYS)
        self.assertUtc(saved["recorded_utc"])
        expected = json.loads(json.dumps({key: value for key, value in self.result.items()
                                          if key != "raw"}))
        self.assertEqual({key: value for key, value in saved.items()
                          if key not in ("recorded_utc", "evidence")}, expected)
        self.assertEqual(saved["evidence"], {
            "raw": "raw.csv.gz",
            "logs": {name: f"logs/{name}.gz" for name in run_logs},
            "nginx_conf": "nginx.conf",
        })
        self.check_private(text)

        self.assertEqual(sorted(path.name for path in (output / "logs").iterdir()),
                         sorted(f"{name}.gz" for name in run_logs))
        for name in run_logs:
            with self.subTest(log=name):
                data = (output / "logs" / f"{name}.gz").read_bytes()
                copied = gzip.decompress(data)
                # nginx may append info lines (e.g. closed keep-alive connections) at any time.
                self.assertTrue(copied.startswith(before[name]))
                self.assertTrue((self.logs / name).read_bytes().startswith(copied))
                self.assertEqual(data[4:8], b"\0\0\0\0")  # mtime 0
                self.assertEqual(data[3] & 0x08, 0)  # No file name in the header.
        self.assertEqual((output / "nginx.conf").read_bytes(),
                         (Path(self.stack.run_dir) / "nginx" / "nginx.conf").read_bytes())

        with gzip.open(output / "raw.csv.gz", "rt", encoding="utf-8", newline="") as file:
            rows = list(csv.reader(file))
        self.assertEqual(rows[0], RAW_COLUMNS)
        self.assertEqual(rows[1:], [[csv_field(row[column]) for column in RAW_COLUMNS]
                                    for row in self.result["raw"]])
        self.check_private(gzip.decompress((output / "raw.csv.gz").read_bytes()).decode())
        header, parsed = raw_rows_from_csv(output / "raw.csv.gz")
        self.assertEqual(parsed, self.result["raw"])


class DefaultLimitRejectionTests(RunChecks, StackRun):
    settings = {"algorithms": ["SLH-DSA-SHA2-128f", "ES256"], "clients": ["direct"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.1}

    def test_settings_list_configurations_in_adapter_order(self):
        self.assertEqual(self.result["settings"]["algorithms"], ["ES256", "SLH-DSA-SHA2-128f"])

    def test_nginx_rejects_the_slh_dsa_requests(self):
        reference, token, control = self.cells()
        self.assertGreater(reference["verified"], 0)
        for cell in (token, control):
            with self.subTest(variant=cell["variant"]):
                self.assertTrue(cell["issue"]["delivered"])
                self.assertGreater(cell["requests"], 0)
                self.assertEqual(cell["verified"], 0)
                self.assertLessEqual(set(cell["statuses"]), {"400", "error"})
                self.assertGreater(cell["statuses"].get("400", 0), 0)
                self.assertIsNone(cell["latency"])
                self.assertEqual(cell["throughput_rps"], 0.0)
                self.assertIsNone(cell["bytes"]["app_received_headers"])
                self.assertIsNone(cell["bytes"]["response_body"])
                rows = [row for row in self.result["raw"] if cell_key(row) == cell_key(cell)]
                self.assertEqual(len(rows), cell["requests"])
                for row in rows:
                    self.assertFalse(row["verified"])
                    self.assertIsNone(row["handler_ns"])
                    self.assertIsNone(row["verify_ns"])

    def test_comparisons_have_no_difference(self):
        reference, rejected = self.result["comparisons"]
        self.assertEqual(reference["algorithm"], "ES256")
        self.assertIsNotNone(reference["difference_ms"])
        self.assertEqual(rejected["algorithm"], "SLH-DSA-SHA2-128f")
        self.assertIsNone(rejected["difference_ms"])
        self.assertIsNotNone(rejected["size_control"])
        self.assertIsNone(rejected["size_control"]["difference_ms"])
        rows = [row["algorithm"] for row in self.result["network_model"]["rows"]]
        self.assertEqual(rows, ["ES256", "SLH-DSA-SHA2-128f"])


class RaisedHeaderBufferTests(RunChecks, StackRun):
    stack_options = {"header_buffers": "32k"}
    settings = {"algorithms": ["SLH-DSA-SHA2-128f"], "clients": ["direct"], "concurrency": [1],
                "duration": 0.2, "warmup": 0.1, "header_buffers": "32k"}

    def test_every_request_verified(self):
        self.assertEqual(self.result["settings"]["header_buffers"], "32k")
        for cell in self.cells():
            with self.subTest(cell=cell_key(cell)):
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)

    def test_slh_dsa_has_both_differences(self):
        entry = self.result["comparisons"][1]
        self.assertEqual(entry["algorithm"], "SLH-DSA-SHA2-128f")
        self.assertIsNotNone(entry["difference_ms"])
        self.assertIsNotNone(entry["size_control"]["difference_ms"])


class BrowserBearerLoadTests(RunChecks, StackRun):
    settings = {"algorithms": ["EdDSA"], "clients": ["browser"], "concurrency": [2],
                "duration": 0.2, "warmup": 0.1}

    def test_browser_identity_and_workload(self):
        self.assertEqual(set(self.result["browser"]), {"version", "user_agent"})
        self.assertEqual(set(self.result["workload"]["client_location"]), {"network", "browser"})
        self.assertEqual(set(self.result["workload"]["timers"]), {"server", "browser"})

    def test_every_request_verified(self):
        self.assertEqual([cell_key(cell) for cell in self.cells()],
                         [("browser", 2, "ES256", "token", "ES256", 0),
                          ("browser", 2, "EdDSA", "token", "EdDSA", 0),
                          ("browser", 2, "EdDSA", "size_control", "ES256",
                           pad_for_target("ES256", claim_set("minimal"),
                                          token_bytes("EdDSA", claim_set("minimal"))))])
        for cell in self.cells():
            with self.subTest(cell=cell_key(cell)):
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)
                workers = {row["worker"] for row in self.result["raw"]
                           if cell_key(row) == cell_key(cell)}
                self.assertLessEqual(workers, {0, 1})


class CookieLoadTests(RunChecks, StackRun):
    settings = {"algorithms": ["ES256"], "transport": "cookie", "clients": ["browser", "direct"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.0}

    def test_clients_run_in_settings_order(self):
        self.assertEqual([cell["client"] for cell in self.cells()], ["browser", "direct"])
        for cell in self.cells():
            with self.subTest(client=cell["client"]):
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)
                self.assertEqual(cell["bytes"]["header_line"],
                                 len("Cookie: jwt=\r\n") + cell["token_bytes"])

    def test_browser_stores_the_cookie_from_set_cookie(self):
        deliveries = Counter(query_of(target).get("delivery")
                             for target, _, _ in logged_requests(self.run_log("proxy-access.log"))
                             if urlsplit(target).path == ISSUE_PATH)
        self.assertGreaterEqual(deliveries["cookie"], 1)  # The browser cell.
        self.assertGreaterEqual(deliveries["body"], 1)  # The direct cell.


# ---- R14, R15: the load command -----------------------------------------------------------

class LoadCommandTests(LoadCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        wait_for_ephemeral_ports()
        cls.first_ports = free_ports(2)
        cls.first_output = cls.directory / "first"
        cls.first_output.mkdir()  # An existing empty directory is accepted.
        cls.first_run_dir = cls.directory / "first-run"
        cls.first = run_cli("load", "--alg", "SLH-DSA-SHA2-128f", "--client", "direct",
                            "--concurrency", "2", "1", "--duration", "0.2", "--warmup", "0.1",
                            "--timeout", "30", "--proxy-buffers", "16k",
                            "--upstream-keepalive", "8",
                            *port_options(cls.first_ports), "--run-dir", cls.first_run_dir,
                            "--output-dir", cls.first_output, cwd=cls.directory)
        cls.first_settings = {
            "algorithms": ["ES256", "SLH-DSA-SHA2-128f"], "transport": "bearer",
            "clients": ["direct"], "claims": "minimal", "concurrency": [2, 1], "duration": 0.2,
            "warmup": 0.1, "reference": "ES256", "size_controls": True, "timeout": 30.0,
            "proxy_buffers": "16k", "header_buffers": None, "upstream_keepalive": 8,
        }

    def require_first_run(self) -> None:
        self.assertEqual(self.first.returncode, 0, self.first.stderr)

    def saved(self, output: Path) -> tuple[dict, list[dict]]:
        """Check a saved run's files and return load.json and the raw rows read back."""
        self.assertEqual({path.name for path in output.iterdir()},
                         {"load.json", "raw.csv.gz", "logs", "nginx.conf"})
        text = (output / "load.json").read_text(encoding="utf-8")
        self.check_private(text)
        saved = json.loads(text)
        self.assertEqual(set(saved), SAVED_KEYS)
        header, rows = raw_rows_from_csv(output / "raw.csv.gz")
        self.assertEqual(header, RAW_COLUMNS)
        self.assertNotIn("eyJ", gzip.decompress((output / "raw.csv.gz").read_bytes()).decode())
        return saved, rows

    def check_saved_run(self, output: Path, run_dir: Path, ports: list[int],
                        settings: dict) -> dict:
        saved, rows = self.saved(output)
        self.check_recorded(saved, rows, settings)
        self.assertEqual(urlsplit(saved["proxy_url"]).port, ports[0])
        self.assertEqual(urlsplit(saved["app_url"]).port, ports[1])
        run_logs = sorted(path.name for path in (run_dir / "logs").iterdir())
        self.assertEqual(saved["evidence"], {
            "raw": "raw.csv.gz", "logs": {name: f"logs/{name}.gz" for name in run_logs},
            "nginx_conf": "nginx.conf"})
        self.assertEqual(sorted(path.name for path in (output / "logs").iterdir()),
                         sorted(f"{name}.gz" for name in run_logs))
        self.assertEqual((output / "nginx.conf").read_bytes(),
                         (run_dir / "nginx" / "nginx.conf").read_bytes())
        return saved

    def test_first_run_exits_0_with_rejected_requests(self):
        self.require_first_run()
        saved, _ = self.saved(self.first_output)
        rejected = [cell for cell in saved["results"] if cell["signed_with"] == "SLH-DSA-SHA2-128f"]
        self.assertTrue(rejected)
        for cell in rejected:
            self.assertGreater(cell["requests"], 0)
            self.assertEqual(cell["verified"], 0)
        reference = [cell for cell in saved["results"] if cell["algorithm"] == "ES256"]
        self.assertTrue(all(cell["verified"] > 0 for cell in reference))

    def test_first_run_records_its_settings_and_evidence(self):
        self.require_first_run()
        saved = self.check_saved_run(self.first_output, self.first_run_dir, self.first_ports,
                                     self.first_settings)
        self.assertEqual([cell["concurrency"] for cell in saved["results"]], [2, 2, 2, 1, 1, 1])
        config = (self.first_output / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_buffer_size 16k;", config)
        self.assertIn("keepalive 8;", config)
        self.assertNotRegex(config, HEADER_BUFFERS_DIRECTIVE)

    def test_first_run_prints_the_summary_then_the_output_directory(self):
        self.require_first_run()
        saved, rows = self.saved(self.first_output)
        expected = summary_lines({**saved, "raw": rows})
        self.assertTrue(expected)
        lines = self.first.stdout.splitlines()
        # R14 orders the summary before the output directory; it does not forbid earlier lines.
        starts = [index for index in range(len(lines) - len(expected) + 1)
                  if lines[index:index + len(expected)] == expected]
        self.assertTrue(starts, self.first.stdout)
        rest = lines[starts[0] + len(expected):]
        names = (str(self.first_output), str(self.first_output.resolve()))
        self.assertTrue(any(name in line for line in rest for name in names), self.first.stdout)

    def test_first_run_stops_every_process(self):
        self.require_first_run()
        for port in self.first_ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_settings_reuse_the_saved_workload(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        ports, run_dir = free_ports(2), self.directory / "reuse-run"
        output = self.directory / "reuse" / "nested" / "out"
        result = run_cli("load", "--settings", self.first_output / "load.json",
                         *port_options(ports), "--run-dir", run_dir, "--output-dir", output,
                         cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_saved_run(output, run_dir, ports, self.first_settings)
        config = (output / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_buffer_size 16k;", config)
        self.assertIn("keepalive 8;", config)  # Carried by --settings.
        self.assertNotRegex(config, HEADER_BUFFERS_DIRECTIVE)
        for port in ports:
            self.assertTrue(refused(port))

    def test_command_line_overrides_saved_settings(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        ports, run_dir = free_ports(2), self.directory / "override-run"
        output = self.directory / "override"
        result = run_cli("load", "--settings", self.first_output / "load.json",
                         "--concurrency", "1", "--no-size-controls", "--header-buffers", "32k",
                         "--timeout", "20", *port_options(ports), "--run-dir", run_dir,
                         "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = {**self.first_settings, "concurrency": [1], "size_controls": False,
                    "header_buffers": "32k", "timeout": 20.0}
        saved = self.check_saved_run(output, run_dir, ports, settings)
        config = (output / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_buffer_size 16k;", config)
        self.assertIn("large_client_header_buffers 4 32k;", config)
        self.assertIn("keepalive 8;", config)
        for cell in saved["results"]:
            self.assertGreater(cell["verified"], 0, cell["algorithm"])

    def test_help_lists_every_option(self):
        result = run_cli("load", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in LOAD_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)

    def test_usage_errors_exit_2_before_any_process_starts(self):
        settings_dir = self.directory / "bad-settings"
        settings_dir.mkdir()
        not_json = settings_dir / "not-json.json"
        not_json.write_text("{not json", encoding="utf-8")
        no_settings = settings_dir / "no-settings.json"
        no_settings.write_text(json.dumps({"results": []}), encoding="utf-8")
        unknown_alg = settings_dir / "unknown-alg.json"
        unknown_alg.write_text(json.dumps({"settings": {**self.first_settings,
                                                        "algorithms": ["HS256"]}}),
                               encoding="utf-8")
        occupied = self.directory / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        short = ["--alg", "ES256", "--client", "direct", "--duration", "0.1", "--warmup", "0"]
        cases = {
            "missing output dir": [*short],
            "non-empty output dir": [*short, "--output-dir", occupied],
            "repeated alg": ["--alg", "ES256", "ES256", "--output-dir", "{out}"],
            "repeated client": ["--client", "direct", "direct", "--output-dir", "{out}"],
            "repeated concurrency": ["--concurrency", "1", "1", "--output-dir", "{out}"],
            "concurrency 0": ["--concurrency", "0", "--output-dir", "{out}"],
            "concurrency 65": ["--concurrency", "65", "--output-dir", "{out}"],
            "zero duration": ["--duration", "0", "--output-dir", "{out}"],
            "negative duration": ["--duration=-1", "--output-dir", "{out}"],
            "negative warmup": ["--warmup=-0.5", "--output-dir", "{out}"],
            "unknown alg": ["--alg", "HS256", "--output-dir", "{out}"],
            "unknown reference": ["--reference", "HS256", "--output-dir", "{out}"],
            "unknown claims": ["--claims", "large", "--output-dir", "{out}"],
            "unknown client": ["--client", "curl", "--output-dir", "{out}"],
            "unknown transport": ["--transport", "query", "--output-dir", "{out}"],
            "missing settings file": ["--settings", settings_dir / "missing.json",
                                      "--output-dir", "{out}"],
            "settings not JSON": ["--settings", not_json, "--output-dir", "{out}"],
            "settings without settings": ["--settings", no_settings, "--output-dir", "{out}"],
            "settings with unknown alg": ["--settings", unknown_alg, "--output-dir", "{out}"],
        }
        for index, (name, arguments) in enumerate(cases.items()):
            with self.subTest(name):
                ports, run_dir = free_ports(2), self.directory / f"usage-run-{index}"
                output = self.directory / f"usage-out-{index}"
                arguments = [output if argument == "{out}" else argument
                             for argument in arguments]
                result = run_cli("load", *arguments, *port_options(ports), "--run-dir", run_dir,
                                 cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse((run_dir / "logs" / "app.log").exists(),
                                 "the application was started")
                for port in ports:
                    self.assertFalse(accepts(port))
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
        self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_runtime_failure_exits_1_and_stops_every_process(self):
        with tempfile.TemporaryDirectory() as empty:
            ports = free_ports(2)
            result = run_cli("load", "--alg", "ES256", "--client", "browser", "--concurrency", "1",
                             "--duration", "0.1", "--warmup", "0", "--timeout", "30",
                             *port_options(ports), "--run-dir", self.directory / "failing-run",
                             "--output-dir", self.directory / "failing",
                             cwd=self.directory,
                             environment=cli_environment(PLAYWRIGHT_BROWSERS_PATH=empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        for port in ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_signals_stop_the_run_and_every_process(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum.name):
                wait_for_ephemeral_ports()
                ports, run_dir = free_ports(2), self.directory / f"signal-{signum.name}"
                command = [sys.executable, str(SCRIPT), "load", "--alg", "ES256", "--client",
                           "direct", "--concurrency", "1", "--duration", "20", "--warmup", "0",
                           *port_options(ports), "--run-dir", str(run_dir), "--output-dir",
                           str(self.directory / f"signal-out-{signum.name}")]
                process = subprocess.Popen(command, cwd=self.directory, env=cli_environment(),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    access = run_dir / "logs" / "proxy-access.log"
                    eventually(lambda: process.poll() is not None
                               or VERIFY_PATH in read_text(access), grace=120)
                    self.assertIsNone(process.poll(), "the run ended before the signal")
                    process.send_signal(signum)
                    _, stderr = process.communicate(timeout=120)
                finally:
                    stop(process)
                self.assertEqual(process.returncode, 1, stderr)
                self.assertRegex(stderr, ERROR_LINE)
                for port in ports:
                    self.assertTrue(refused(port), f"port {port} still accepts connections")


# ---- R16: what stays unchanged ------------------------------------------------------------

class UnchangedTests(unittest.TestCase):
    def require(self, text: str | None) -> str:
        if text is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return text

    def test_other_commands_keep_their_options(self):
        try:
            archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar",
                                      BASE_COMMIT, "scripts", "transport", "fixtures"],
                                     capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("BASE_COMMIT is not available in this checkout")
        environment = {key: value for key, value in cli_environment(COLUMNS="100",
                                                                     NO_COLOR="1").items()
                       if key not in ("FORCE_COLOR", "PYTHON_COLORS")}
        with tempfile.TemporaryDirectory() as directory:
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                tar.extractall(directory, filter="data")
            for command in ("check", "tokens", "sweep", "serve", "versions"):
                with self.subTest(command=command):
                    outputs = []
                    for script in (Path(directory) / "scripts" / "transport_stack.py", SCRIPT):
                        result = subprocess.run([sys.executable, str(script), command, "--help"],
                                                cwd=directory, env=environment, text=True,
                                                capture_output=True, timeout=120)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        outputs.append(result.stdout)
                    self.assertIn(f"usage: transport_stack.py {command}", outputs[0])
                    self.assertEqual(outputs[1], outputs[0])

    def test_pinned_files_and_manifest_unchanged(self):
        for path in ("requirements.txt", "transport/requirements.txt",
                     "transport/conda-requirements.txt", "transport/stack.json"):
            with self.subTest(path=path):
                self.assertEqual((REPO / path).read_text(encoding="utf-8"),
                                 self.require(git_show(path)))

    def test_template_keeps_its_limits(self):
        directive = re.compile(r"^\s*(timer_resolution|large_client_header_buffers|"
                               r"client_header_buffer_size|proxy_buffer_size|proxy_buffers|"
                               r"proxy_busy_buffers_size)\b.*$", re.MULTILINE)
        before = self.require(git_show("transport/nginx.conf.template"))
        after = (REPO / "transport" / "nginx.conf.template").read_text(encoding="utf-8")
        self.assertEqual([match.group().strip() for match in directive.finditer(after)],
                         [match.group().strip() for match in directive.finditer(before)])
        self.assertIn("timer_resolution 100ms;", after)

    def test_existing_tests_unchanged(self):
        try:
            listing = subprocess.run(["git", "-C", str(REPO), "ls-tree", "--name-only",
                                      BASE_COMMIT, "tests/"], capture_output=True, text=True,
                                     check=True).stdout.split()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("BASE_COMMIT is not available in this checkout")
        self.assertTrue(listing)
        for path in listing:
            with self.subTest(path=path):
                self.assertEqual((REPO / path).read_text(encoding="utf-8"),
                                 self.require(git_show(path)))

    def test_done_when_lines_unchanged(self):
        def done_when(text: str) -> list[str]:
            return [line for line in text.splitlines() if line.startswith("**Done when:**")]
        before = self.require(git_show("PROGRESS.md"))
        self.assertEqual(done_when(PROGRESS.read_text(encoding="utf-8")), done_when(before))


# ---- R18: Makefile ------------------------------------------------------------------------

class MakefileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MAKEFILE.read_text(encoding="utf-8")

    def make(self, *arguments: str) -> subprocess.CompletedProcess:
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not installed")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MAKEFLAGS", "MFLAGS", "LOAD_DIR")}
        return subprocess.run([make, "--no-print-directory", *arguments], cwd=REPO,
                              env=environment, capture_output=True, text=True, timeout=60)

    def test_target_is_phony_and_in_help(self):
        phony = next((line for line in self.text.splitlines() if line.startswith(".PHONY:")), "")
        self.assertIn("load", phony.split())
        result = self.make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(line.startswith("make load") for line in result.stdout.splitlines()),
                        result.stdout)

    def test_recipe_and_output_directory(self):
        # Team decision after the build: make load passes --upstream-keepalive 64 (without it
        # macOS runs out of ephemeral ports) and 2 s cells (committed files stay under 10 MiB),
        # both recorded in load.json, and its directory names the platform as results/ does.
        self.assertRegex(self.text, r"(?m)^LOAD_DIR \?= results/load/"
                                    r"\$\(shell date -u \+%Y%m%dT%H%M%SZ\)-\$\(LOAD_PLATFORM\)")
        self.assertRegex(self.text, r'(?m)^load:.*\n(?:\t.*\n)*?\t\$\(STACK\) load '
                                    r'--header-buffers 32k --upstream-keepalive 64 --duration 2 '
                                    r'--output-dir "\$\(LOAD_DIR\)"[ \t]*$')
        result = self.make("-n", "load", "LOAD_DIR=results/load/dry-run", "PYTHON=python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/transport_stack.py load --header-buffers 32k '
                      '--upstream-keepalive 64 --duration 2 --output-dir '
                      '"results/load/dry-run"', result.stdout)
        if sys.platform == "darwin":
            result = self.make("-n", "load", "PYTHON=python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'--output-dir "results/load/\d{8}T\d{6}Z-macos"')


# ---- R19: TRANSPORT.md --------------------------------------------------------------------

class TransportDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(TRANSPORT_DOC)

    def section(self, title: str, level: int = 2) -> str:
        body = section(self.text, title, level)
        self.assertIsNotNone(body, f"missing heading: {'#' * level} {title}")
        return body

    def test_required_headings_in_order(self):
        found = [name for depth, name, _ in headings(self.text.splitlines())
                 if depth == 2 and name in TRANSPORT_HEADINGS]
        self.assertEqual(found, list(TRANSPORT_HEADINGS))

    def test_timing_parameter_with_the_token_endpoints(self):
        body = self.section("Token endpoints", level=3)
        for term in ("timing=1", "verify_ns", "handler_ns"):
            self.assertIn(term, body)

    def test_load_command_under_run_the_check(self):
        body = self.section("Run the check")
        self.assertTrue(any(re.search(r"transport_stack\.py[\"']?\s+load\b", block)
                            for block in code_blocks(body)))
        for option in LOAD_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, body)
        for term in ("default", VERIFY_PATH, "total", "transfer", "other_handling",
                     "verification", "load.json", "raw.csv.gz", "logs", "nginx.conf"):
            with self.subTest(term=term):
                self.assertIn(term, body)


# ---- R20: the committed run and END_TO_END_RESULTS.md -------------------------------------

def committed_run() -> tuple[Path, dict] | None:
    """The latest results/load/<YYYYMMDDTHHMMSSZ>-macos/ run recorded on macOS, or None."""
    runs = []
    for path in sorted(LOAD_RESULTS.glob("*/load.json")):
        if not RUN_NAME.fullmatch(path.parent.name):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        platform_name = str((data.get("environment") or {}).get("platform", ""))
        if platform_name.startswith("macOS"):
            runs.append((path.parent, data))
    return runs[-1] if runs else None


class CommittedRunTests(LoadCase):
    @classmethod
    def setUpClass(cls):
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)
        cls.header, cls.rows = [], []
        if found and (cls.run_dir / "raw.csv.gz").is_file():
            cls.header, cls.rows = raw_rows_from_csv(cls.run_dir / "raw.csv.gz")

    def setUp(self):
        self.assertIsNotNone(self.saved, "no macOS run committed under "
                                         "results/load/<YYYYMMDDTHHMMSSZ>-macos/")

    def test_settings(self):
        settings = self.saved["settings"]
        self.assertEqual(settings["transport"], "bearer")
        self.assertEqual(settings["header_buffers"], "32k")
        self.assertEqual(settings["upstream_keepalive"], 64)
        self.assertEqual(settings["clients"], ["direct", "browser"])
        self.assertEqual(settings["algorithms"], NAMES)
        self.assertEqual(settings["reference"], "ES256")
        self.assertIs(settings["size_controls"], True)
        self.assertIn(1, settings["concurrency"])
        self.assertTrue(self.saved["environment"]["platform"].startswith("macOS"))

    def test_every_cell_verified(self):
        for cell in self.saved["results"]:
            with self.subTest(cell=cell_key(cell)):
                self.assertIn(cell["variant"], ("token", "size_control"))
                self.assertGreater(cell["verified"], 0)

    def test_recorded_structure_and_raw_rows(self):
        self.assertEqual(set(self.saved), SAVED_KEYS)
        self.assertUtc(self.saved["recorded_utc"])
        self.assertEqual(self.header, RAW_COLUMNS)
        self.assertEqual(len(self.rows), sum(cell["requests"] for cell in self.saved["results"]))
        self.check_recorded(self.saved, self.rows, self.saved["settings"], local=False)
        self.check_summary(summary_lines({**self.saved, "raw": self.rows}),
                           self.saved["comparisons"])

    def test_files_and_evidence(self):
        logs = sorted(path.name for path in (self.run_dir / "logs").iterdir())
        self.assertTrue(logs)
        self.assertTrue(all(name.endswith(".log.gz") for name in logs), logs)
        self.assertEqual(self.saved["evidence"], {
            "raw": "raw.csv.gz",
            "logs": {name[:-len(".gz")]: f"logs/{name}" for name in logs},
            "nginx_conf": "nginx.conf"})
        for name in logs:
            gzip.decompress((self.run_dir / "logs" / name).read_bytes())
        config = (self.run_dir / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("large_client_header_buffers 4 32k;", config)
        self.assertIn("keepalive 64;", config)

    def test_sizes_and_no_uncompressed_logs(self):
        for path in LOAD_RESULTS.rglob("*"):
            if path.is_file():
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertLessEqual(path.stat().st_size, 10 * MIB)
                    self.assertFalse(path.name.endswith(".log"))
        tracked = tracked_files()
        if tracked is not None:
            for path in tracked:
                if path.startswith("results/load/"):
                    self.assertFalse(path.endswith(".log"), path)

    def test_no_tokens_and_logs_trace_verified_requests(self):
        self.check_private((self.run_dir / "load.json").read_text(encoding="utf-8"))
        self.assertNotIn("eyJ", gzip.decompress((self.run_dir / "raw.csv.gz").read_bytes())
                         .decode("utf-8"))
        verified = {row["nonce"] for row in self.rows if row["verified"]}
        for name in ("proxy-access.log", "app.log"):
            with self.subTest(log=name):
                path = self.run_dir / "logs" / f"{name}.gz"
                self.assertTrue(path.is_file(), name)
                text = gzip.decompress(path.read_bytes()).decode("utf-8", errors="replace")
                self.assertNotIn("eyJ", text)
                missing = verified - log_nonces(text)
                self.assertEqual(len(missing), 0, f"{len(missing)} verified nonces missing")


class ResultsDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(RESULTS_DOC)
        found = committed_run()
        # Not cls.run, which would shadow unittest.TestCase.run.
        cls.run_dir, cls.saved = found if found else (None, None)
        cls.rows = []
        if found and (cls.run_dir / "raw.csv.gz").is_file():
            cls.rows = raw_rows_from_csv(cls.run_dir / "raw.csv.gz")[1]

    def section(self, title: str) -> str:
        body = section(self.text, title)
        self.assertIsNotNone(body, f"missing heading: ## {title}")
        return body

    def require_run(self) -> dict:
        self.assertIsNotNone(self.saved, "no committed macOS run under results/load/")
        return self.saved

    def rows_naming(self, body: str, name: str) -> list[str]:
        return [row for row in table_rows(body) if name in row]

    def test_headings_in_order(self):
        self.assertTrue(RESULTS_DOC.is_file(), "END_TO_END_RESULTS.md is missing")
        found = [name for depth, name, _ in headings(self.text.splitlines())
                 if depth == 2 and name in RESULTS_HEADINGS]
        self.assertEqual(found, list(RESULTS_HEADINGS))

    def test_names_every_configuration_in_right_aligned_tables(self):
        for name in NAMES:
            with self.subTest(name=name):
                self.assertIn(name, self.text)
        self.assertRegex(self.text, r"(?m)^\s*\|.*-+:\s*\|")

    def test_links_to_the_committed_run(self):
        self.require_run()
        run_dir = self.run_dir
        links = relative_links(self.text)
        resolved = {(REPO / link.split("#", 1)[0]).resolve() for link in links}
        self.assertIn((run_dir / "load.json").resolve(), resolved)
        self.assertIn((run_dir / "raw.csv.gz").resolve(), resolved)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((REPO / link.split("#", 1)[0]).exists(), link)

    def test_workload(self):
        body = self.section("Workload")
        lowered = body.lower()
        for term in ("/api/token/verify", "http.client", "chromium", "loopback", "127.0.0.1",
                     "concurrency", "duration", "warm"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        settings = self.require_run()["settings"]
        for level in settings["concurrency"]:
            self.assertTrue(contains_number(body, level), level)
        self.assertTrue(shows(body, settings["duration"]))
        self.assertTrue(shows(body, settings["warmup"]))

    def test_command_and_summary_output(self):
        blocks = code_blocks(self.text)
        self.assertTrue(any(re.search(r"transport_stack\.py[\"']?\s+load\b", block)
                            for block in blocks))
        run = self.require_run()
        shown = {line.strip() for block in blocks for line in block.splitlines()}
        for line in summary_lines({**run, "raw": self.rows}):
            with self.subTest(line=line):
                self.assertIn(line.strip(), shown)

    def test_latency_and_throughput(self):
        body = self.section("Latency and throughput")
        for cell in self.require_run()["results"]:
            if cell["variant"] != "token":
                continue
            with self.subTest(cell=cell_key(cell)):
                rows = self.rows_naming(body, cell["algorithm"])
                self.assertTrue(any(contains_number(row, cell["token_bytes"]) for row in rows))
                if cell["token_bytes"] >= 1000:
                    self.assertIn(f"{cell['token_bytes']:,}", body)
                total = cell["latency"]["total"]
                self.assertTrue(any(shows(row, total["median_ms"], MS_SCALES)
                                    and shows(row, total["p95_ms"], MS_SCALES)
                                    and shows(row, cell["throughput_rps"]) for row in rows))

    def test_token_size_versus_verification(self):
        body = self.section("Token size versus verification")
        lowered = body.lower()
        self.assertIn("size", lowered)
        self.assertIn("control", lowered)
        run = self.require_run()
        for name in NAMES:
            if name == run["settings"]["reference"]:
                continue
            with self.subTest(name=name):
                rows = self.rows_naming(body, name)
                entries = [entry for entry in run["comparisons"]
                           if entry["algorithm"] == name and entry["difference_ms"]]
                self.assertTrue(entries)
                self.assertTrue(any(
                    shows(row, entry["difference_ms"]["token_size"], MS_SCALES)
                    and shows(row, entry["difference_ms"]["verification"], MS_SCALES)
                    for row in rows for entry in entries))
                controls = [entry["size_control"]["difference_ms"] for entry in entries
                            if entry["size_control"] and entry["size_control"]["difference_ms"]]
                if controls:
                    self.assertTrue(any(shows(row, split["token_size"], MS_SCALES)
                                        and shows(row, split["verification"], MS_SCALES)
                                        for row in rows for split in controls))

    def test_modeled_network_cost(self):
        body = self.section("Modeled network cost")
        lowered = body.lower()
        for term in ("calculated", "not measured", "illustrative", "loss", "tls", "http/2"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue(any(term in lowered for term in ("initial window", "slow start",
                                                         "slow-start")))
        run = self.require_run()
        measured = {entry["algorithm"]: entry["difference_ms"] for entry in run["comparisons"]
                    if entry["client"] == "direct" and entry["concurrency"] == 1}
        for row in run["network_model"]["rows"]:
            with self.subTest(name=row["algorithm"]):
                verification = (measured.get(row["algorithm"]) or {}).get("verification")
                self.assertTrue(any(
                    contains_number(line, row["request_bytes"])
                    and contains_number(line, row["extra_request_bytes"])
                    and all(shows(line, modeled["difference_ms"], MS_SCALES)
                            for modeled in row["modeled"])
                    and (verification is None or shows(line, verification, MS_SCALES))
                    for line in self.rows_naming(body, row["algorithm"])))

    def test_limitations_and_wsl2(self):
        body = self.section("Limitations").lower()
        self.assertIn("loopback", body)
        self.assertIn("bandwidth", body)
        self.assertRegex(body, r"round[- ]trip|\brtt\b")
        wsl2 = [line for line in self.text.splitlines() if "WSL2" in line]
        self.assertTrue(any("not" in line for line in wsl2), "no line says WSL2 is not done yet")


# ---- R21: PROGRESS.md and README.md -------------------------------------------------------

class ProgressAndReadmeTests(unittest.TestCase):
    def test_progress_s3_01(self):
        body = section(PROGRESS.read_text(encoding="utf-8"), "S3-01", level=3)
        self.assertIsNotNone(body, "missing heading: ### S3-01")
        items = re.findall(r"(?m)^- \[( |x)\] (.*)$", body)
        self.assertEqual(items, [("x", item) for item in S3_01_ITEMS])
        self.assertNotIn("- [ ]", body)
        status = [line for line in body.splitlines() if line.startswith("**Status:**")]
        self.assertEqual(len(status), 1)
        for term in ("load", "macOS", "END_TO_END_RESULTS.md"):
            self.assertIn(term, status[0])

    def test_readme(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("](END_TO_END_RESULTS.md", text)
        shortcuts = section(text, "Make shortcuts")
        self.assertIsNotNone(shortcuts, "missing heading: ## Make shortcuts")
        lines = [line.strip() for block in code_blocks(shortcuts) for line in block.splitlines()]
        self.assertTrue(any(line.startswith("make load") for line in lines))


if __name__ == "__main__":
    unittest.main()
