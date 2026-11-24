"""Check S3-02's reference tokens end to end: the store process, start_stack's remote store,
run_refs and the refs command on real stacks with Chromium, the Makefile, the committed macOS
run, MITIGATION_RESULTS.md, TRANSPORT.md, and the other docs, and what stays unchanged; no
timing thresholds."""

import csv
import dataclasses
from datetime import datetime, timedelta
import getpass
import gzip
import http.client
import importlib.util
import inspect
import io
import json
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
import unittest
from urllib.parse import parse_qsl, urlsplit

from scripts import transport_app, transport_load
from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import claim_set, pad_for_target, padded_claims, token_bytes
from scripts.transport_stack import Stack, load_manifest, manifest_layers, start_stack

try:
    from scripts import transport_refs
    REFS_IMPORT_ERROR = None
except Exception as error:  # Before S3-02's reference tokens are built: tests fail, not vanish.
    transport_refs, REFS_IMPORT_ERROR = None, error

try:
    from scripts.transport_claims import without_tokens
except Exception:  # Reported by the tests that need it.
    without_tokens = None


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
APP_SCRIPT = REPO / "scripts" / "transport_app.py"
MAKEFILE = REPO / "Makefile"
TRANSPORT_DOC = REPO / "TRANSPORT.md"
MITIGATION_DOC = REPO / "MITIGATION_RESULTS.md"
PROGRESS = REPO / "PROGRESS.md"
README = REPO / "README.md"
TRANSPORT_RESULTS = REPO / "TRANSPORT_RESULTS.md"
REFS_RESULTS = REPO / "results" / "refs"
# The commit reference tokens build on: files that stay unchanged are compared with it.
BASE_COMMIT = "2129d9958ab810185a3556bc4fb4c62378182231"
S3_01_RUN = REPO / "results" / "load" / "20261117T035444Z-macos"
COOKIES_RUN = REPO / "results" / "cookies" / "20261118T174416Z-macos"
# The committed claims run whose size-limit verdicts the committed refs run derives (R21).
CLAIMS_SOURCE = "results/claims/20261118T053507Z-macos/claims.json"

HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
REFERENCE_PATH = "/api/token/reference"
REVOKE_PATH = "/api/token/revoke"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
RUN_NAME = re.compile(r"\d{8}T\d{6}Z-macos")
ERROR_LINE = re.compile(r"(?m)^Error:")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
# The tail of a Linux platform.platform() string, e.g. on WSL2 (see token_runs).
PLATFORM_TAG = re.compile(r"[A-Za-z0-9_-]*-(?:x86_64|aarch64)-with-glibc[0-9]*")
NONCE = re.compile(r"[0-9a-f]{32}")
REF_FORMAT = re.compile(r"ref_[A-Za-z0-9_-]{43}")
APP_STATUS = re.compile(r'" (\d{3}) headers=')
SERVING_ON = re.compile(r"http://127\.0\.0\.1:(\d+)")
REQUEST_LINE = re.compile(r"([A-Z]+) (\S+) (HTTP/\d\.\d)")
GRACE = 15.0
CLI_TIMEOUT = 1200
SIGNAL_GRACE = 600
MIB = 1024 * 1024
TIME_WAIT_LIMIT = 6_000
TIME_WAIT_GRACE = 90.0

REF_BYTES = 47
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
CLAIM_SET_NAMES = ("minimal", "oidc", "essential")
TRANSPORTS = ("cookie", "bearer")
HEADER_LINE = {"cookie": 65, "bearer": 71}
PROBE_ALGORITHM = "SLH-DSA-SHA2-128f"
PROBE_TARGETS = (65536, 300000)
COMPONENTS = ("total", "transfer", "other_handling", "verification")
REF_COMPONENTS = ("total", "transfer", "other_handling", "lookup", "verification")
RAW_FIELDS = ("client", "concurrency", "algorithm", "variant", "signed_with", "pad",
              "token_bytes", "worker", "sequence", "nonce", "start_ns", "total_ns", "handler_ns",
              "verify_ns", "status", "verified", "error")
NETWORK_PROFILES = ({"uplink_mbps": 100, "rtt_ms": 10}, {"uplink_mbps": 10, "rtt_ms": 50},
                    {"uplink_mbps": 1, "rtt_ms": 100})
LAYERS = ("browser", "proxy", "app_server", "application")
RUNS = ("jwt", "ref_memory", "ref_remote")
STACK_DIRS = ("limits", "behavior", "latency-jwt", "latency-ref-memory", "latency-ref-remote")
LATENCY_DIRS = {"jwt": "latency-jwt", "ref_memory": "latency-ref-memory",
                "ref_remote": "latency-ref-remote"}
LATENCY_RUNS = {run: f"{directory}/load.json" for run, directory in LATENCY_DIRS.items()}
REF_STORES = {"ref_memory": "memory", "ref_remote": "remote"}
LIMIT_LOGS = ("app.log", "browser.log", "proxy-access.log", "proxy-error.log")
BEHAVIOR_LOGS = ("app.log", "proxy-access.log", "proxy-error.log", "store.log")
SAVED_LOAD_FILES = {"load.json", "raw.csv.gz", "logs", "nginx.conf"}

REFS_KEYS = {"schema_version", "started_utc", "finished_utc", "recorded_utc", "settings",
             "environment", "layers", "browser", "experiment_keys", "format", "plan", "limits",
             "probes", "handling", "latency", "evidence"}
SETTINGS_KEYS = {"algorithms", "claims", "clients", "concurrency", "duration", "warmup",
                 "timeout", "header_buffers", "upstream_keepalive"}
FORMAT = {"reference_prefix": "ref_", "random_bytes": 32, "reference_bytes": REF_BYTES,
          "cookie_name": "jwt_ref", "cookie_attributes": FULL_ATTRIBUTES,
          "default_ttl_seconds": 3600, "max_ttl_seconds": 86400, "stores": ["memory", "remote"]}
PLAN_KEYS = {"algorithm", "token_bytes", "reference_bytes", "name_value_bytes",
             "set_cookie_bytes", "cookie_line_bytes", "authorization_line_bytes", "fits"}
LIMITS_KEYS = {"stack", "header_buffers", "proxy_buffers", "ref_store", "cookie_attributes",
               "results", "jwt", "moved"}
RESULT_KEYS = {"algorithm", "transport", "token_bytes", "reference_bytes", "outcome",
               "rejected_by", "verified_directly", "cookie_stored", "issue_status",
               "verify_status", "bytes", "issue_nonce", "verify_nonce", "evidence"}
PROBE_KEYS = {"algorithm", "target_bytes", "pad", "token_bytes", "transport", "reference_bytes",
              "outcome", "rejected_by", "cookie_stored", "issue_status", "verify_status",
              "bytes", "issue_nonce", "verify_nonce", "evidence"}
BYTES_KEYS = {"header_line", "app_received_headers"}
JWT_KEYS = {"source", "claims", "results"}
JWT_RESULT_KEYS = ("algorithm", "transport", "token_bytes", "outcome", "rejected_by")
MOVED_KEYS = {"algorithm", "transport", "jwt", "ref", "moved"}
HANDLING_KEYS = {"algorithm", "claims", "token_bytes", "stack", "ref_store",
                 "expired_ttl_seconds", "cases"}
CASE_KEYS = {"name", "method", "path", "sent", "store", "status", "verified", "source",
             "ref_status", "lookup_called", "verify_called", "revoke_status", "set_cookie",
             "error", "nonce"}
LATENCY_KEYS = {"transport", "reference", "size_controls", "runs", "rows", "network_model"}
LATENCY_ROW_KEYS = {"client", "concurrency", "algorithm", "token_bytes", "reference_bytes",
                    "delivered", "verified", "failed", "throughput_rps", "median_ms", "p95_ms",
                    "mean_ms", "difference_ms"}
NETWORK_KEYS = {"algorithm", "request_bytes", "saved_bytes", "modeled"}
REFS_OPTIONS = ("--output-dir", "--settings", "--alg", "--claims", "--client", "--concurrency",
                "--duration", "--warmup", "--timeout", "--header-buffers",
                "--upstream-keepalive", "--run-dir")
MAKE_SETTINGS = {"algorithms": NAMES, "claims": "oidc", "clients": ["direct", "browser"],
                 "concurrency": [1, 4], "duration": 2.0, "warmup": 1.0, "timeout": 60.0,
                 "header_buffers": "32k", "upstream_keepalive": 64}

# R15's cases: name, status, source, ref status, lookup called, verify_token called, and the
# cookie names (plus "bearer") sent, in order.
HANDLING_CASES = (
    ("cookie", 200, "ref_cookie", "found", True, True, ["jwt_ref"]),
    ("bearer", 200, "ref_bearer", "found", True, True, ["bearer"]),
    ("among_other_cookies", 200, "ref_cookie", "found", True, True, ["a", "jwt_ref", "theme"]),
    ("unknown", 401, "ref_bearer", "unknown", True, False, ["bearer"]),
    ("malformed_cookie", 401, "ref_cookie", "malformed", False, False, ["jwt_ref"]),
    ("expired", 401, "ref_bearer", "expired", True, False, ["bearer"]),
    ("revoked", 401, "ref_bearer", "revoked", True, False, ["bearer"]),
    ("two_references", 400, None, None, False, False, ["jwt_ref", "jwt_ref"]),
    ("reference_and_jwt", 400, None, None, False, False, ["jwt_ref", "bearer"]),
    ("reference_as_jwt", 401, "cookie", None, False, False, ["jwt"]),
    ("store_unavailable", 503, "ref_bearer", "unavailable", True, False, ["bearer"]),
    ("jwt_without_store", 200, "bearer", None, False, True, ["bearer"]),
    ("issue_without_store", 503, None, None, False, False, []),
)
CASE_NAMES = tuple(case[0] for case in HANDLING_CASES)
STOPPED_CASES = {"store_unavailable", "jwt_without_store", "issue_without_store"}

MITIGATION_PARTS = ("Format", "Size limits", "Reference handling", "What the design gives up",
                    "Latency", "Reproduce", "Limitations")
TRANSPORT_HEADINGS = ("Stack", "Versions and documented limits", "Setup", "Run the check",
                      "Support for Sprint 2 tasks", "Limitations")
S3_02_ITEMS = (
    "Smaller claim sets: measure how much each configuration's token shrinks with only "
    "essential claims, and whether that moves any Sprint 2 boundary.",
    "Cookie splitting: split oversized tokens across several cookies and reassemble them in the "
    "application. Record the per-cookie, cookie-count, and total header limits it runs into, "
    "and how it handles missing or reordered chunks.",
    "Reference tokens: replace the JWT in transit with a short opaque reference and look up the "
    "signed token on the server. Measure the lookup latency, and note what the design gives up, "
    "such as stateless and offline verification.",
)


# ---- the module under test ---------------------------------------------------------------

def module():
    """Return scripts.transport_refs, failing the calling test when it cannot be imported."""
    if transport_refs is None:
        raise AssertionError(f"scripts/transport_refs.py cannot be imported: "
                             f"{REFS_IMPORT_ERROR!r}")
    return transport_refs


def app_api(name: str):
    """An attribute R2-R4 add to scripts/transport_app.py, failing the test when it is missing."""
    if not hasattr(transport_app, name):
        raise AssertionError(f"scripts/transport_app.py has no {name}")
    return getattr(transport_app, name)


def summary_lines(result: dict) -> list[str]:
    """transport_refs.summary_lines(result); fails the test without the module."""
    return module().summary_lines(result)


# ---- general helpers ---------------------------------------------------------------------

def read_text(path: Path) -> str:
    """A text file's contents, or "" when it cannot be read."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_gzip(path: Path) -> str:
    """A gzip file's decompressed text."""
    return gzip.decompress(path.read_bytes()).decode("utf-8", errors="replace")


def read_any(path: Path) -> str:
    """A gzip file's or a plain file's text."""
    return read_gzip(path) if path.suffix == ".gz" else read_text(path)


def visible_names(directory: Path) -> set[str]:
    """A directory's entry names, without hidden ones such as Finder's .DS_Store (gitignored)."""
    return {path.name for path in Path(directory).iterdir() if not path.name.startswith(".")}


def token_runs(text: str) -> list[str]:
    """Base64url runs of 40 or more characters (tokens and references), except git commits."""
    # Also skips the tail of a Linux platform.platform() string: on WSL2,
    # "...-microsoft-standard-WSL2-x86_64-with-glibc2.39" holds a 44-character run.
    return [run for run in TOKEN_LIKE.findall(text)
            if not HEX_COMMIT.fullmatch(run) and not PLATFORM_TAG.fullmatch(run)]


NGINX_TIME = re.compile(r"(?m)^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[")


def nginx_times(path: Path) -> list[str]:
    """The timestamps of an nginx error log's lines; their fixed-width format sorts as text."""
    return NGINX_TIME.findall(read_text(path))


def free_ports(count: int) -> list[int]:
    """Ports on 127.0.0.1 that were free a moment ago."""
    sockets = [socket.socket() for _ in range(count)]
    try:
        for probe in sockets:
            probe.bind((HOST, 0))
        return [probe.getsockname()[1] for probe in sockets]
    finally:
        for probe in sockets:
            probe.close()


def accepts(port: int) -> bool:
    """True when something accepts connections on the port."""
    try:
        with socket.create_connection((HOST, port), timeout=2):
            return True
    except OSError:
        return False


def eventually(condition, grace: float = GRACE) -> bool:
    """Poll a condition for a grace period, e.g. while a process shuts down."""
    deadline = time.monotonic() + grace
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.1)
    return True


def refused(port: int) -> bool:
    """True once nothing accepts connections on the port any more."""
    return eventually(lambda: not accepts(port))


def children() -> set[int]:
    """The live child processes of this test process, zombies excluded."""
    listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid=,stat="], stdout=subprocess.PIPE,
                               text=True)
    output, _ = listing.communicate()
    found = set()
    for line in output.splitlines():
        fields = line.split()
        if (len(fields) >= 3 and fields[1] == str(os.getpid())
                and fields[0] != str(listing.pid) and not fields[2].startswith("Z")):
            found.add(int(fields[0]))
    return found


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


def cli_environment(**extra: str) -> dict:
    """This process's environment for a CLI run, plus extra."""
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
    """Terminate a process that is still running, then kill it if it does not exit."""
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def git(*arguments: str) -> str | None:
    """Run git in the repository and return its stdout, or None when git or a commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), *arguments], capture_output=True,
                              text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def git_show(path: str, commit: str = BASE_COMMIT) -> str | None:
    """Return a file as committed at commit, or None when git or the commit is missing."""
    return git("show", f"{commit}:{path}")


def base_checkout(directory: str) -> Path | None:
    """Extract scripts/, transport/, and fixtures/ as of BASE_COMMIT; None when unavailable."""
    try:
        archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar",
                                  BASE_COMMIT, "scripts", "transport", "fixtures"],
                                 capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(directory, filter="data")
    return Path(directory)


def private_names() -> list[str]:
    """This machine's host name and user name, which no result may contain."""
    names = {socket.gethostname(), socket.gethostname().split(".")[0]}
    try:
        names.add(getpass.getuser())
    except (OSError, KeyError):
        pass
    return [name for name in names if len(name) >= 4 and name != "localhost"]


def conf_ports(path: Path) -> set[int]:
    """The 127.0.0.1 ports a rendered nginx.conf listens on or proxies to."""
    return {int(port) for port in re.findall(r"127\.0\.0\.1:(\d+)", read_text(path))}


def run_ports(run_dir: Path) -> set[int]:
    """Every port a run's stacks used: from each nginx.conf, and from waitress's 'Serving on'
    lines in app.log and store.log."""
    ports = set()
    for path in Path(run_dir).glob("**/nginx.conf"):
        ports |= conf_ports(path)
    for name in ("app.log", "store.log"):
        for path in Path(run_dir).glob(f"**/logs/{name}"):
            for line in read_text(path).splitlines():
                if "Serving on" in line:
                    ports |= {int(port) for port in SERVING_ON.findall(line)}
    return ports


def store_ports(run_dir: Path) -> set[int]:
    """The ports waitress said the run's store processes served on, when store.log says so."""
    ports = set()
    for path in Path(run_dir).glob("**/logs/store.log"):
        for line in read_text(path).splitlines():
            if "Serving on" in line:
                ports |= {int(port) for port in SERVING_ON.findall(line)}
    return ports


def directive(name: str) -> re.Pattern:
    """A pattern for an nginx directive set on a line of its own, not one named in a comment."""
    return re.compile(rf"(?m)^\s*{re.escape(name)}\s")


def normalized_conf(text: str, run_dir: Path) -> str:
    """A rendered nginx.conf with its run directory and ports replaced, for comparison."""
    text = text.replace(str(Path(run_dir).absolute()), "<run_dir>")
    return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<port>", text)


def query_of(url: str) -> dict:
    """A URL's query parameters, each with its last value."""
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def parse_utc(text) -> datetime:
    """An ISO 8601 time; raises ValueError unless it is UTC."""
    value = datetime.fromisoformat(text)
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{text!r} is not UTC")
    return value


def browser_records(text: str) -> list[dict]:
    """browser.log's JSON Lines records."""
    records = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def request_record(records: list[dict], nonce: str, path: str) -> dict | None:
    """The browser.log request event of the request to path with this nonce."""
    for record in records:
        url = record.get("url")
        if (record.get("event") == "request" and isinstance(url, str) and nonce in url
                and urlsplit(url).path == path):
            return record
    return None


def app_line(app_log: str, nonce: str) -> str | None:
    """The line the application itself wrote for the request with this nonce."""
    return next((line for line in app_log.splitlines()
                 if nonce in line and APP_STATUS.search(line)), None)


def app_header_bytes(app_log: str, nonce: str) -> int | None:
    """header_bytes of the line the application itself wrote for the request with this nonce."""
    line = app_line(app_log, nonce)
    match = re.search(r"\bheader_bytes=(\d+)", line or "")
    return int(match[1]) if match else None


def failed_layer(logs: dict[str, str], nonce: str) -> str:
    """The layer to blame for a request the browser got no 200 for, from every layer's log."""
    if nonce not in logs["proxy-access.log"]:
        return "browser"
    mentioning = [line for line in logs["app.log"].splitlines() if nonce in line]
    line = app_line(logs["app.log"], nonce)
    if not mentioning or (line is not None and APP_STATUS.search(line)[1] == "200"):
        return "proxy"
    if any("rejected by waitress" in line for line in mentioning):
        return "app_server"
    return "application"


def http_call(method: str, url: str, headers: dict | None = None,
              timeout: float = 30.0) -> tuple[int, dict, bytes]:
    """Send one request with http.client; return its status, lowercased headers, and body."""
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        connection.request(method, target or "/", headers=headers or {})
        response = connection.getresponse()
        return (response.status, {name.lower(): value for name, value in response.getheaders()},
                response.read())
    finally:
        connection.close()


def json_reply(status_headers_body: tuple[int, dict, bytes]) -> tuple[int, dict, dict]:
    """A reply's status, headers, and JSON object body; raises AssertionError for anything else."""
    status, headers, body = status_headers_body
    value = json.loads(body)
    if not isinstance(value, dict):
        raise AssertionError(f"not a JSON object: {body[:200]!r}")
    return status, headers, value


def start_process(command: list, log_path: Path) -> subprocess.Popen:
    """Start a server process in its own session, with stdout and stderr in log_path."""
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    with log_path.open("ab") as log:
        return subprocess.Popen([str(part) for part in command], cwd=log_path.parent,
                                env=environment, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)


def stop_process(process: subprocess.Popen) -> None:
    """Stop a server process and its session, and reap it."""
    if process.poll() is None:
        # macOS answers EPERM for a group whose leader exited but is not yet reaped.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait()


def start_store(port: int, log_path: Path) -> subprocess.Popen:
    """Start `transport_app.py --serve-store --port port`; fail the test unless it serves."""
    process = start_process([sys.executable, APP_SCRIPT, "--serve-store", "--port", port],
                            log_path)
    if not eventually(lambda: process.poll() is not None or accepts(port), grace=30):
        stop_process(process)
        raise AssertionError(f"the store did not start on port {port}")
    if process.poll() is not None:
        raise AssertionError(f"the store exited with {process.returncode}: "
                             f"{read_text(log_path)[-2000:]}")
    return process


def start_application(port: int, log_path: Path, store_port: int | None = None):
    """Start the application (with --store-port when given); fail unless /api/echo answers."""
    command = [sys.executable, APP_SCRIPT, "--port", port]
    if store_port is not None:
        command += ["--store-port", store_port]
    process = start_process(command, log_path)

    def ready() -> bool:
        if process.poll() is not None:
            return True
        try:
            return http_call("GET", f"http://{HOST}:{port}/api/echo", timeout=2)[0] == 200
        except (OSError, http.client.HTTPException):
            return False

    if not eventually(ready, grace=30) or process.poll() is not None:
        stop_process(process)
        raise AssertionError(f"the application did not start: {read_text(log_path)[-2000:]}")
    return process


def http_requests(stream: bytes) -> list[tuple[str, str, str]]:
    """(method, target, version) of each HTTP/1.x request in one connection's client bytes,
    skipping each body by its Content-Length or chunked encoding."""
    requests, position = [], 0
    while (end := stream.find(b"\r\n\r\n", position)) >= 0:
        lines = stream[position:end].decode("latin-1").split("\r\n")
        match = REQUEST_LINE.fullmatch(lines[0])
        if match is None:
            break
        requests.append(match.groups())
        fields = {name.strip().lower(): value.strip()
                  for name, _, value in (line.partition(":") for line in lines[1:])}
        position = end + len(b"\r\n\r\n")
        if "chunked" in fields.get("transfer-encoding", "").lower():
            while (line_end := stream.find(b"\r\n", position)) >= 0:
                size = int(stream[position:line_end].split(b";")[0] or b"0", 16)
                position = line_end + 2 + size + 2
                if size == 0:
                    break
        else:
            position += int(fields.get("content-length", "0") or 0)
    return requests


class RecordingProxy:
    """A loopback TCP relay in front of the store that records every connection and what the
    client sent on it, and can drop every open connection."""

    def __init__(self, upstream_port: int):
        self.upstream_port = upstream_port
        self.listener = socket.create_server((HOST, 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.url = f"http://{HOST}:{self.port}"
        self.lock = threading.Lock()
        self.streams: list[bytearray] = []
        self.sockets: list[socket.socket] = []
        self.closing = threading.Event()
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self) -> None:
        """Accept clients and relay each to the store until closed."""
        while not self.closing.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            client.settimeout(None)
            try:
                upstream = socket.create_connection((HOST, self.upstream_port), timeout=10)
                upstream.settimeout(None)
            except OSError:
                client.close()
                continue
            stream = bytearray()
            with self.lock:
                self.streams.append(stream)
                self.sockets += [client, upstream]
            threading.Thread(target=self.pump, args=(client, upstream, stream),
                             daemon=True).start()
            threading.Thread(target=self.pump, args=(upstream, client, None),
                             daemon=True).start()

    def pump(self, source: socket.socket, target: socket.socket,
             stream: bytearray | None) -> None:
        """Copy bytes from source to target, recording them in stream when given."""
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                if stream is not None:
                    with self.lock:
                        stream.extend(data)
                target.sendall(data)
        except OSError:
            pass
        finally:
            for end in (source, target):
                try:
                    end.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                end.close()

    @property
    def connections(self) -> int:
        """The number of connections clients opened."""
        with self.lock:
            return len(self.streams)

    def sent(self) -> bytes:
        """Every byte clients sent, connection after connection."""
        with self.lock:
            return b"\n".join(bytes(stream) for stream in self.streams)

    def requests(self) -> list[tuple[str, str, str]]:
        """(method, target, version) of every request clients sent, connection by connection."""
        with self.lock:
            streams = [bytes(stream) for stream in self.streams]
        return [request for stream in streams for request in http_requests(stream)]

    def drop(self) -> None:
        """Close every open connection, as a store that closed them would."""
        with self.lock:
            sockets = list(self.sockets)
        for end in sockets:
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            end.close()

    def close(self) -> None:
        """Stop accepting and drop every connection."""
        self.closing.set()
        self.listener.close()
        self.drop()


class BrokenStore:
    """A loopback server that is not a working store, whatever the store's protocol: "error"
    answers every request with 500, and "hang_up" closes every connection without an answer."""

    def __init__(self, mode: str):
        self.mode = mode
        self.listener = socket.create_server((HOST, 0))
        self.listener.settimeout(0.2)
        self.url = f"http://{HOST}:{self.listener.getsockname()[1]}"
        self.closing = threading.Event()
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self) -> None:
        """Accept clients until closed, each on its own thread."""
        while not self.closing.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self.answer, args=(client,), daemon=True).start()

    def answer(self, client: socket.socket) -> None:
        """Hang up, or answer every request on the connection with 500."""
        with client:
            if self.mode == "hang_up":
                return
            client.settimeout(10)
            data = b""
            try:
                while True:
                    while b"\r\n\r\n" not in data:
                        chunk = client.recv(65536)
                        if not chunk:
                            return
                        data += chunk
                    head, _, data = data.partition(b"\r\n\r\n")
                    length = re.search(rb"(?im)^content-length:\s*(\d+)", head)
                    needed = int(length[1]) if length else 0
                    while len(data) < needed:
                        chunk = client.recv(65536)
                        if not chunk:
                            return
                        data += chunk
                    data = data[needed:]
                    body = b'{"error": "broken"}'
                    client.sendall(b"HTTP/1.1 500 Internal Server Error\r\n"
                                   b"Content-Type: application/json\r\n"
                                   b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                                   + body)
            except OSError:
                return

    def close(self) -> None:
        """Stop accepting connections."""
        self.closing.set()
        self.listener.close()


# ---- what the spec says, computed independently ---------------------------------------------

def manifest_limits() -> tuple[int, int]:
    """transport/stack.json's browser cookie limit and proxy single_header limit."""
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return (layers["browser"]["limits"]["cookie"]["bytes"],
            layers["proxy"]["limits"]["single_header"]["bytes"])


def expected_plan_row(algorithm: str, claims: str) -> dict:
    """R13's row for one configuration, computed from the spec's formulas."""
    cookie_limit, line_limit = manifest_limits()
    total = token_bytes(algorithm, claim_set(claims))
    name_value = {"jwt": 3 + total, "ref": 7 + REF_BYTES}
    cookie_line = {"jwt": len("Cookie: jwt=\r\n") + total,
                   "ref": len("Cookie: jwt_ref=\r\n") + REF_BYTES}
    authorization = {"jwt": len("Authorization: Bearer \r\n") + total,
                     "ref": len("Authorization: Bearer \r\n") + REF_BYTES}
    return {
        "algorithm": algorithm, "token_bytes": total, "reference_bytes": REF_BYTES,
        "name_value_bytes": name_value,
        "set_cookie_bytes": {"jwt": len(f"Set-Cookie: jwt=; {FULL_ATTRIBUTES}\r\n") + total,
                             "ref": len(f"Set-Cookie: jwt_ref=; {FULL_ATTRIBUTES}\r\n")
                             + REF_BYTES},
        "cookie_line_bytes": cookie_line, "authorization_line_bytes": authorization,
        "fits": {side: {"per_cookie": name_value[side] <= cookie_limit,
                        "cookie_line": cookie_line[side] <= line_limit,
                        "authorization_line": authorization[side] <= line_limit}
                 for side in ("jwt", "ref")},
    }


def matching_claims_source() -> str | None:
    """R14: the newest committed claims.json recorded on a machine like this one, or None."""
    environment = transport_load.run_environment()
    for path in sorted(REPO.glob("results/claims/*/claims.json"), reverse=True):
        try:
            recorded = json.loads(path.read_text(encoding="utf-8")).get("environment") or {}
        except (OSError, ValueError, AttributeError):
            continue
        if (recorded.get("page_size_bytes") == environment["page_size_bytes"]
                and str(recorded.get("platform", "")).split("-")[0]
                == str(environment["platform"]).split("-")[0]):
            return path.relative_to(REPO).as_posix()
    return None


def expected_jwt(algorithms: list[str], claims: str, source: str | None) -> dict | None:
    """R14's limits.jwt: the claims run's verdicts for the run's claims, or None."""
    if source is None:
        return None
    saved = json.loads((REPO / source).read_text(encoding="utf-8"))
    verdicts = {(entry["algorithm"], entry["transport"]): entry
                for entry in saved["limits"]["results"] if entry["claims"] == claims}
    if not verdicts:
        return None
    return {"source": source, "claims": claims,
            "results": [{key: verdicts[(algorithm, transport)][key] for key in JWT_RESULT_KEYS}
                        for algorithm in algorithms for transport in TRANSPORTS
                        if (algorithm, transport) in verdicts]}


def expected_moved(results: list[dict], jwt: dict | None) -> list[dict]:
    """R14's moved entries, one per result, from the derived verdicts."""
    derived = ({(entry["algorithm"], entry["transport"]): entry["outcome"]
                for entry in jwt["results"]} if jwt is not None else {})
    entries = []
    for entry in results:
        outcome = derived.get((entry["algorithm"], entry["transport"]))
        entries.append({"algorithm": entry["algorithm"], "transport": entry["transport"],
                        "jwt": outcome, "ref": entry["outcome"],
                        "moved": None if outcome is None else (outcome == "rejected"
                                                               and entry["outcome"]
                                                               == "verified")})
    return entries


def evidence_paths(value) -> list[str]:
    """Every string in an evidence object."""
    if isinstance(value, dict):
        return [path for item in value.values() for path in evidence_paths(item)]
    if isinstance(value, list):
        return [path for item in value for path in evidence_paths(item)]
    return [value]


def token_cells(load: dict) -> list[dict]:
    """A load result's token cells, in order."""
    return [cell for cell in load["results"] if cell["variant"] == "token"]


def total_statistic(cell: dict, key: str):
    """One statistic of a cell's total latency, or None if nothing verified."""
    return None if cell["latency"] is None else cell["latency"]["total"][key]


def run_means(run: str, cell: dict) -> dict | None:
    """R16's mean_ms of one run's cell: five components, lookup 0.0 for the jwt run."""
    if cell["latency"] is None:
        return None
    if run == "jwt":
        return {**{component: cell["latency"][component]["mean_ms"] for component in COMPONENTS},
                "lookup": 0.0}
    return {component: cell["latency"][component]["mean_ms"] for component in REF_COMPONENTS}


def expected_latency_rows(loads: dict[str, dict]) -> list[dict]:
    """R16's rows, derived from the three saved load.json files."""
    matches = {run: {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
                     for cell in token_cells(loads[run])} for run in ("ref_memory", "ref_remote")}
    rows = []
    for cell in token_cells(loads["jwt"]):
        key = (cell["client"], cell["concurrency"], cell["algorithm"])
        cells = {"jwt": cell, "ref_memory": matches["ref_memory"][key],
                 "ref_remote": matches["ref_remote"][key]}
        means = {run: run_means(run, entry) for run, entry in cells.items()}
        difference = {run: None if means[run] is None or means["jwt"] is None else
                      {component: means[run][component] - means["jwt"][component]
                       for component in REF_COMPONENTS}
                      for run in ("ref_memory", "ref_remote")}
        rows.append({
            "client": cell["client"], "concurrency": cell["concurrency"],
            "algorithm": cell["algorithm"], "token_bytes": cell["token_bytes"],
            "reference_bytes": REF_BYTES,
            "delivered": {run: entry["issue"]["delivered"] for run, entry in cells.items()},
            **{key: {run: entry[key] for run, entry in cells.items()}
               for key in ("verified", "failed", "throughput_rps")},
            "median_ms": {run: total_statistic(entry, "median_ms")
                          for run, entry in cells.items()},
            "p95_ms": {run: total_statistic(entry, "p95_ms") for run, entry in cells.items()},
            "mean_ms": means, "difference_ms": difference})
    return rows


def expected_network_model(algorithms, loads: dict[str, dict]) -> list[dict]:
    """R16's network_model, from latency-jwt's and latency-ref-memory's network models."""
    rows = {run: {row["algorithm"]: row for row in loads[run]["network_model"]["rows"]}
            for run in ("jwt", "ref_memory")}
    entries = []
    for algorithm in algorithms:
        jwt, ref = rows["jwt"][algorithm], rows["ref_memory"][algorithm]
        modeled = [{"uplink_mbps": profile["uplink_mbps"], "rtt_ms": profile["rtt_ms"],
                    "saved_ms": jwt["modeled"][index]["transfer_ms"]
                    - ref["modeled"][index]["transfer_ms"]}
                   for index, profile in enumerate(NETWORK_PROFILES)]
        entries.append({"algorithm": algorithm,
                        "request_bytes": {"jwt": jwt["request_bytes"],
                                          "ref": ref["request_bytes"]},
                        "saved_bytes": jwt["request_bytes"] - ref["request_bytes"],
                        "modeled": modeled})
    return entries


def expected_load_settings(settings: dict) -> dict:
    """R16: the settings latency-jwt/load.json records."""
    return {"algorithms": settings["algorithms"], "transport": "bearer",
            "clients": settings["clients"], "claims": settings["claims"],
            "concurrency": settings["concurrency"], "duration": settings["duration"],
            "warmup": settings["warmup"], "reference": "ES256", "size_controls": False,
            "timeout": settings["timeout"], "proxy_buffers": None,
            "header_buffers": settings["header_buffers"],
            "upstream_keepalive": settings["upstream_keepalive"]}


def raw_table(path: Path) -> tuple[list[str], list[dict]]:
    """raw.csv.gz's header and its rows as dicts."""
    reader = csv.reader(io.StringIO(read_gzip(path)))
    header = next(reader)
    return header, [dict(zip(header, row)) for row in reader]


def summary_words(result: dict) -> list[str]:
    """R18: the phase word each summary line starts with, in order."""
    return (["plan"] * len(result["plan"]) + ["limits"] * len(result["limits"]["results"])
            + ["probe"] * len(result["probes"]) + ["handling"] * len(result["handling"]["cases"])
            + ["latency"] * len(result["latency"]["rows"]))


def committed_run() -> tuple[Path, dict] | None:
    """The newest results/refs/<YYYYMMDDTHHMMSSZ>-macos/ run recorded on macOS, or None."""
    runs = []
    for path in sorted(REFS_RESULTS.glob("*/refs.json")):
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
    """The text of each fenced code block, in order."""
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
    """Markdown link targets that point into the repository."""
    targets = re.findall(r"\]\(([^)\s]+)\)", text)
    return [target for target in targets
            if not target.startswith(("http://", "https://", "#", "mailto:"))]


def contains_number(text: str, number: int) -> bool:
    """True when text shows number, with or without thousands separators."""
    return re.search(rf"(?<![\d,.])(?:{number}|{number:,})(?!,?\d)", text) is not None


def shows_count(text: str, number: int) -> bool:
    """True when text shows a byte count, with thousands separators from 1,000 on."""
    number = abs(number)
    return contains_number(text, number) and (number < 1000 or f"{number:,}" in text)


DISPLAYED_NUMBER = re.compile(r"(?<![\w.])[-−+]?\d[\d,]*(?:\.\d+)?")
# R18's 'moved' marker; "not moved" or "unmoved" on a line whose pair did not move is fine.
MOVED_WORD = re.compile(r"(?<!not )(?<![\w-])moved\b")


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


def shows_ms(text: str, value: float) -> bool:
    """True when text shows value in ms with exactly 3 decimals."""
    for name in NAMES:
        text = text.replace(name, " ")
    for match in DISPLAYED_NUMBER.finditer(text):
        shown = match.group().replace("−", "-").replace("+", "").replace(",", "")
        if len(shown.partition(".")[2]) == 3 and abs(float(shown) - value) <= 0.0005 + 1e-9:
            return True
    return False


def make_blocks(text: str) -> dict[str, list[str]]:
    """Each target's rule line and recipe lines, by target name."""
    blocks, current = {}, None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_][\w-]*):(?!=)", line)
        if match:
            current = blocks.setdefault(match[1], [])
            current.append(line)
        elif current is not None and line.startswith("\t"):
            current.append(line)
        else:
            current = None
    return blocks


# ---- R3, R4: the store process --------------------------------------------------------------

class StoreProcessTests(unittest.TestCase):
    """`transport_app.py --serve-store`, RemoteRefStore over loopback HTTP, and --store-port."""

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.processes = []
        cls.port = free_ports(1)[0]
        cls.log = cls.directory / "store.log"
        cls.store_process, cls.error = None, None
        try:
            cls.store_process = start_store(cls.port, cls.log)
        except AssertionError as error:  # Reported by every test instead of failing setUpClass.
            cls.error = error

    @classmethod
    def tearDownClass(cls):
        if cls.store_process is not None:
            stop_process(cls.store_process)
        for process in cls.processes:
            stop_process(process)

    def setUp(self):
        app_api("RemoteRefStore")
        self.assertIsNone(self.error)
        self.url = f"http://{HOST}:{self.port}"

    def remote(self, url: str | None = None, **options):
        """A RemoteRefStore for the class's store, or for url."""
        return app_api("RemoteRefStore")(url or self.url, **options)

    def started(self, process: subprocess.Popen) -> subprocess.Popen:
        """Record a process for tearDownClass and return it."""
        type(self).processes.append(process)
        return process

    def proxy(self) -> RecordingProxy:
        """A RecordingProxy in front of the class's store, closed after the test."""
        proxy = RecordingProxy(self.port)
        self.addCleanup(proxy.close)
        return proxy

    def test_store_semantics_over_http(self):
        store = self.remote()
        self.assertEqual(store.kind, "remote")
        new_reference = app_api("new_reference")
        found, short, revoked, unknown = (new_reference() for _ in range(4))
        self.assertIsNone(store.put(found, "a.b.c", 3600))
        self.assertIsNone(store.put(short, "d.e.f", 1))
        store.put(revoked, "g.h.i", 3600)
        self.assertEqual(tuple(store.get(found)), ("found", "a.b.c"))
        self.assertEqual(tuple(store.get(unknown)), ("unknown", None))
        self.assertEqual(store.revoke(revoked), "found")
        self.assertEqual(tuple(store.get(revoked)), ("revoked", None))
        self.assertEqual(store.revoke(revoked), "revoked")
        self.assertEqual(store.revoke(unknown), "unknown")
        self.assertEqual(tuple(store.get(unknown)), ("unknown", None))
        store.put(found, "j.k.l", 3600)  # Putting again replaces the token.
        self.assertEqual(tuple(store.get(found)), ("found", "j.k.l"))
        time.sleep(1.2)  # Lets the 1-second reference expire; a precondition, not a measurement.
        self.assertEqual(tuple(store.get(short)), ("expired", None))
        self.assertEqual(store.revoke(short), "expired")
        self.assertEqual(tuple(store.get(short)), ("revoked", None))
        # Another client of the same process sees the same entries.
        self.assertEqual(tuple(self.remote().get(found)), ("found", "j.k.l"))

    def test_put_validates_its_arguments(self):
        store = self.remote()
        good = app_api("new_reference")()
        for arguments in (("not-a-reference", "token", 60), (good, "", 60), (good, None, 60),
                          (good, "t", 0), (good, "t", 86401), (good, "t", True),
                          (good, "t", 1.0)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                store.put(*arguments)
        self.assertEqual(tuple(store.get(good)), ("unknown", None))

    def test_one_connection_per_thread(self):
        proxy = self.proxy()
        store = self.remote(proxy.url)
        references = [app_api("new_reference")() for _ in range(5)]
        for index, reference in enumerate(references):
            store.put(reference, f"t.{index}.x", 3600)
        for _ in range(30):
            self.assertEqual(store.get(references[0])[0], "found")
        self.assertEqual(proxy.connections, 1, "one persistent connection for this thread")
        errors = []

        def worker() -> None:
            try:
                for reference in references * 4:
                    if store.get(reference)[0] != "found":
                        errors.append(reference)
            except Exception as error:  # Reported below.
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(proxy.connections, 4, "at most one more connection per thread")
        self.assertGreaterEqual(len(proxy.requests()), 5 + 30 + 60)

    def test_reopens_a_closed_connection_once(self):
        proxy = self.proxy()
        store = self.remote(proxy.url)
        reference = app_api("new_reference")()
        store.put(reference, "a.b.c", 3600)
        self.assertEqual(proxy.connections, 1)
        proxy.drop()  # The store side closes the persistent connection.
        self.assertEqual(tuple(store.get(reference)), ("found", "a.b.c"))
        self.assertEqual(proxy.connections, 2)
        proxy.drop()
        self.assertEqual(store.revoke(reference), "found")

    def test_requests_carry_no_reference_or_token_in_their_targets(self):
        proxy = self.proxy()
        store = self.remote(proxy.url)
        reference = app_api("new_reference")()
        token = f"{'eyJ' + 'A' * 60}.{'B' * 80}.{'C' * 90}"
        store.put(reference, token, 3600)
        store.get(reference)
        store.revoke(reference)
        store.get(reference)
        requests = proxy.requests()
        self.assertGreaterEqual(len(requests), 4)
        for method, target, version in requests:
            with self.subTest(request=f"{method} {target[:80]}"):
                self.assertEqual(version, "HTTP/1.1")
                self.assertNotIn(reference, target)
                self.assertNotIn(token, target)
                self.assertNotIn("eyJ", target)
                self.assertEqual(token_runs(target), [])
        # The reference and the token did travel, in the bodies.
        self.assertIn(reference.encode(), proxy.sent())
        self.assertIn(token.encode(), proxy.sent())

    def test_store_log_has_one_line_per_request_and_no_secret(self):
        port = free_ports(1)[0]
        log = self.directory / f"store-{port}.log"
        process = self.started(start_store(port, log))
        store = self.remote(f"http://{HOST}:{port}")
        reference = app_api("new_reference")()
        token = f"{'eyJ' + 'D' * 50}.{'E' * 70}.{'F' * 40}"
        store.put(reference, token, 3600)
        store.get(reference)
        store.revoke(reference)
        store.get(app_api("new_reference")())
        request_lines = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD)\b.*\b[1-5]\d\d\b")
        self.assertTrue(eventually(lambda: len([
            line for line in read_text(log).splitlines() if request_lines.search(line)]) >= 4),
            read_text(log))
        stop_process(process)
        text = read_text(log)
        self.assertNotIn(reference, text)
        self.assertNotIn(token, text)
        self.assertNotIn("eyJ", text)
        self.assertEqual(token_runs(text), [])

    def test_stopped_store_raises_ref_store_unavailable(self):
        port = free_ports(1)[0]
        process = self.started(start_store(port, self.directory / f"store-{port}.log"))
        store = self.remote(f"http://{HOST}:{port}", timeout=5.0)
        reference = app_api("new_reference")()
        store.put(reference, "a.b.c", 3600)
        self.assertEqual(tuple(store.get(reference)), ("found", "a.b.c"))
        stop_process(process)
        self.assertTrue(refused(port))
        unavailable = app_api("RefStoreUnavailable")
        for name, call in (("get", lambda: store.get(reference)),
                           ("revoke", lambda: store.revoke(reference)),
                           ("put", lambda: store.put(reference, "a.b.c", 60))):
            with self.subTest(method=name), self.assertRaises(unavailable):
                call()

    def test_unexpected_answers_raise_ref_store_unavailable(self):
        unavailable = app_api("RefStoreUnavailable")
        for mode in ("error", "hang_up"):
            server = BrokenStore(mode)
            self.addCleanup(server.close)
            store = self.remote(server.url, timeout=5.0)
            reference = app_api("new_reference")()
            for name, call in (("get", lambda: store.get(reference)),
                               ("revoke", lambda: store.revoke(reference)),
                               ("put", lambda: store.put(reference, "a.b.c", 60))):
                with self.subTest(mode=mode, method=name), self.assertRaises(unavailable):
                    call()

    def test_serve_store_with_store_port_exits_2(self):
        port, store_port = free_ports(2)
        process = subprocess.Popen([sys.executable, str(APP_SCRIPT), "--serve-store", "--port",
                                    str(port), "--store-port", str(store_port)],
                                   cwd=self.directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env=cli_environment())
        try:
            _, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            stop(process)
            raise AssertionError("--serve-store with --store-port did not exit") from None
        self.assertEqual(process.returncode, 2, stderr)
        self.assertFalse(accepts(port))

    def test_application_with_a_store_port_uses_the_store_process(self):
        store_port, app_port = free_ports(2)
        store_log, app_log = (self.directory / f"{name}-{app_port}.log" for name in ("store",
                                                                                     "app"))
        store_process = self.started(start_store(store_port, store_log))
        self.started(start_application(app_port, app_log, store_port))
        app_url, direct = f"http://{HOST}:{app_port}", self.remote(f"http://{HOST}:{store_port}")
        status, _, body = json_reply(http_call(
            "GET", f"{app_url}{REFERENCE_PATH}?alg=ES256&delivery=body&claims=oidc"))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["store"], "remote")
        reference = body["reference"]
        found, token = direct.get(reference)
        self.assertEqual(found, "found")
        self.assertEqual(len(token), body["token_bytes"])
        status, _, verified = json_reply(http_call(
            "GET", f"{app_url}{VERIFY_PATH}?timing=1",
            {"Authorization": f"Bearer {reference}"}))
        self.assertEqual(status, 200, verified)
        self.assertEqual(verified["ref"], {"status": "found", "store": "remote",
                                           "reference_bytes": REF_BYTES})
        status, _, revoked = json_reply(http_call(
            "POST", f"{app_url}{REVOKE_PATH}", {"Cookie": f"jwt_ref={reference}"}))
        self.assertEqual(status, 200, revoked)
        self.assertEqual(tuple(direct.get(reference)), ("revoked", None))
        other = json_reply(http_call(
            "GET", f"{app_url}{REFERENCE_PATH}?alg=ES256&delivery=body"))[2]["reference"]
        stop_process(store_process)
        self.assertTrue(refused(store_port))
        status, _, body = json_reply(http_call(
            "GET", f"{app_url}{VERIFY_PATH}?timing=1", {"Authorization": f"Bearer {other}"}))
        self.assertEqual(status, 503, body)
        self.assertEqual(body["ref"]["status"], "unavailable")
        status, headers, body = json_reply(http_call(
            "GET", f"{app_url}{REFERENCE_PATH}?alg=ES256&delivery=cookie"))
        self.assertEqual(status, 503, body)
        self.assertNotIn("set-cookie", headers)
        for path in (store_log, app_log):
            with self.subTest(log=path.name):
                text = read_text(path)
                for secret in (reference, other, token):
                    self.assertNotIn(secret, text)
                self.assertEqual(token_runs(text), [])
        self.assertIn("store=remote", read_text(app_log))

    def test_application_alone_uses_the_memory_store(self):
        app_port = free_ports(1)[0]
        app_log = self.directory / f"app-{app_port}.log"
        self.started(start_application(app_port, app_log))
        app_url = f"http://{HOST}:{app_port}"
        status, _, body = json_reply(http_call(
            "GET", f"{app_url}{REFERENCE_PATH}?alg=EdDSA&delivery=body"))
        self.assertEqual((status, body["store"]), (200, "memory"), body)
        status, _, verified = json_reply(http_call(
            "GET", f"{app_url}{VERIFY_PATH}", {"Cookie": f"jwt_ref={body['reference']}"}))
        self.assertEqual(status, 200, verified)
        self.assertEqual(verified["ref"]["store"], "memory")


# ---- R4: start_stack's reference store ---------------------------------------------------

class StartStackTests(unittest.TestCase):
    def require_ref_store(self) -> None:
        """Fail, rather than error, while start_stack has no ref_store keyword."""
        self.assertIn("ref_store", inspect.signature(start_stack).parameters,
                      "start_stack has no ref_store keyword")

    def test_signature_and_stack_fields(self):
        parameters = inspect.signature(start_stack).parameters
        self.assertEqual(list(parameters), ["proxy_port", "app_port", "run_dir", "timeout",
                                            "proxy_buffers", "header_buffers",
                                            "upstream_keepalive", "ref_store"])
        self.assertEqual(parameters["ref_store"].default, "memory")
        fields = dataclasses.fields(Stack)
        names = [field.name for field in fields]
        self.assertEqual(names[:4], ["proxy_url", "app_url", "run_dir", "upstream_keepalive"])
        self.assertEqual(sorted(names[4:]), ["ref_store", "store_url"])
        defaults = {field.name: field.default for field in fields}
        self.assertIsNone(defaults["upstream_keepalive"])
        self.assertEqual(defaults["ref_store"], "memory")
        self.assertIsNone(defaults["store_url"])

    def test_invalid_ref_store_raises_before_anything_starts(self):
        self.require_ref_store()
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate(("bogus", "Memory", "REMOTE", "", None, 1, "redis")):
                run_dir = Path(directory) / f"run-{index}"
                before = children()
                with self.subTest(ref_store=value):
                    with self.assertRaises(ValueError):
                        with start_stack(run_dir=run_dir, ref_store=value):
                            pass
                    self.assertEqual(children() - before, set(), "a process was started")
                    for name in ("app.log", "store.log", "proxy-error.log"):
                        self.assertFalse((run_dir / "logs" / name).exists(), name)

    def issue_and_verify(self, stack) -> tuple[str, dict]:
        """Issue a reference through nginx and verify it as a Bearer header."""
        status, _, body = json_reply(http_call(
            "GET", f"{stack.proxy_url}{REFERENCE_PATH}?alg=ML-DSA-44&delivery=body&claims=oidc"))
        self.assertEqual(status, 200, body)
        status, headers, verified = json_reply(http_call(
            "GET", f"{stack.proxy_url}{VERIFY_PATH}?timing=1",
            {"Authorization": f"Bearer {body['reference']}"}))
        self.assertEqual(status, 200, verified)
        self.assertIn("x-transport-proxy", headers)
        return body["reference"], verified

    def test_remote_and_memory_stacks(self):
        self.require_ref_store()
        with tempfile.TemporaryDirectory() as directory:
            proxy_port, app_port = free_ports(2)
            remote_dir, memory_dir = Path(directory) / "remote", Path(directory) / "memory"
            before = children()
            with start_stack(proxy_port=proxy_port, app_port=app_port, run_dir=remote_dir,
                             ref_store="remote") as stack:
                self.assertEqual(stack.ref_store, "remote")
                match = re.fullmatch(r"http://127\.0\.0\.1:(\d+)", str(stack.store_url))
                self.assertIsNotNone(match, stack.store_url)
                store_port = int(match[1])
                self.assertNotIn(store_port, (proxy_port, app_port))
                self.assertTrue(accepts(store_port))
                self.assertEqual(len(children() - before), 3, "nginx, the app, and the store")
                reference, verified = self.issue_and_verify(stack)
                self.assertEqual(verified["ref"]["store"], "remote")
                status, token = app_api("RemoteRefStore")(stack.store_url).get(reference)
                self.assertEqual(status, "found")
                remote_logs = visible_names(remote_dir / "logs")
                remote_conf = read_text(remote_dir / "nginx" / "nginx.conf")
            for port in (proxy_port, app_port, store_port):
                self.assertTrue(refused(port), f"port {port} still accepts connections")
            self.assertTrue(eventually(lambda: children() - before == set()))
            self.assertIn("store.log", remote_logs)
            self.assertNotIn(store_port, conf_ports(remote_dir / "nginx" / "nginx.conf"))
            for log in ("app.log", "store.log", "proxy-access.log"):
                text = read_text(remote_dir / "logs" / log)
                with self.subTest(log=log):
                    self.assertNotIn(reference, text)
                    self.assertNotIn(token, text)
                    self.assertEqual(token_runs(text), [])

            for name, options in (("memory", {"ref_store": "memory"}), ("default", {})):
                run_dir = memory_dir / name
                with self.subTest(stack=name):
                    with start_stack(proxy_port=proxy_port, app_port=app_port, run_dir=run_dir,
                                     **options) as stack:
                        self.assertEqual((stack.ref_store, stack.store_url), ("memory", None))
                        self.assertEqual(len(children() - before), 2, "nginx and the app only")
                        _, verified = self.issue_and_verify(stack)
                        self.assertEqual(verified["ref"]["store"], "memory")
                        memory_logs = visible_names(run_dir / "logs")
                        memory_conf = read_text(run_dir / "nginx" / "nginx.conf")
                    self.assertEqual(remote_logs, memory_logs | {"store.log"})
                    self.assertNotIn("store.log", memory_logs)
                    # The store is not behind nginx, so both stores render the same config.
                    self.assertEqual(normalized_conf(remote_conf, remote_dir),
                                     normalized_conf(memory_conf, run_dir))
                    self.assertTrue(eventually(lambda: children() - before == set()))

    def test_remote_stack_stops_everything_on_error(self):
        self.require_ref_store()
        with tempfile.TemporaryDirectory() as directory:
            before, ports = children(), []
            with self.assertRaises(RuntimeError):
                with start_stack(run_dir=Path(directory) / "run", ref_store="remote") as stack:
                    ports = [int(urlsplit(url).port) for url in (stack.proxy_url, stack.app_url,
                                                                 stack.store_url)]
                    raise RuntimeError("stop here")
            self.assertEqual(len(ports), 3)
            for port in ports:
                self.assertTrue(refused(port), f"port {port} still accepts connections")
            self.assertTrue(eventually(lambda: children() - before == set()))

    def test_memory_stack_starts_what_it_started_before(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = base_checkout(str(Path(directory) / "base"))
            if checkout is None:
                self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
            name = "scripts._transport_stack_2129d99"
            spec = importlib.util.spec_from_file_location(
                name, checkout / "scripts" / "transport_stack.py")
            base = importlib.util.module_from_spec(spec)
            sys.modules[name] = base  # For its dataclass; removed again below.
            self.addCleanup(sys.modules.pop, name, None)
            spec.loader.exec_module(base)
            proxy_port, app_port = free_ports(2)
            observed = {}
            for name, starter, run_dir in (
                    ("base", base.start_stack, Path(directory) / "base-run"),
                    ("memory", start_stack, Path(directory) / "memory-run")):
                before = children()
                with starter(proxy_port=proxy_port, app_port=app_port, run_dir=run_dir):
                    started = len(children() - before)
                    logs = visible_names(run_dir / "logs")
                    conf = normalized_conf(read_text(run_dir / "nginx" / "nginx.conf"), run_dir)
                observed[name] = (started, logs, conf)
                self.assertTrue(eventually(lambda: children() - before == set()))
            self.assertEqual(observed["memory"], observed["base"])


# ---- checks shared by every refs run -----------------------------------------------------

class RefsCase(unittest.TestCase):
    """Assertions shared by run_refs, the refs command, and the committed run (R12-R18)."""

    def assertUtc(self, text) -> datetime:
        """Parse an ISO 8601 UTC time; fail unless it is one."""
        self.assertIsInstance(text, str)
        value = datetime.fromisoformat(text)
        self.assertEqual(value.utcoffset(), timedelta(0), text)
        return value

    def assertJsonClose(self, actual, expected, where: str = "result") -> None:
        """Compare JSON-like values exactly, except floats, which may differ by rounding."""
        if isinstance(expected, dict):
            self.assertIsInstance(actual, dict, where)
            self.assertEqual(set(actual), set(expected), where)
            for key in expected:
                self.assertJsonClose(actual[key], expected[key], f"{where}.{key}")
        elif isinstance(expected, list):
            self.assertIsInstance(actual, list, where)
            self.assertEqual(len(actual), len(expected), where)
            for index, (got, wanted) in enumerate(zip(actual, expected)):
                self.assertJsonClose(got, wanted, f"{where}[{index}]")
        elif isinstance(expected, bool) or expected is None:
            self.assertIs(actual, expected, where)
        elif isinstance(expected, int):
            self.assertIs(type(actual), int, f"{where}: {actual!r}")
            self.assertEqual(actual, expected, where)
        elif isinstance(expected, float):
            self.assertTrue(isinstance(actual, (int, float)) and not isinstance(actual, bool),
                            f"{where}: {actual!r}")
            self.assertTrue(math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-12),
                            f"{where}: {actual!r} != {expected!r}")
        else:
            self.assertEqual(actual, expected, where)

    def logs(self, output: Path, stack: str, names) -> dict[str, str]:
        """A stack's saved logs, decompressed, by log name."""
        directory = output / stack / "logs"
        return {name: read_gzip(directory / f"{name}.gz") for name in names}

    def loads(self, output: Path) -> dict[str, dict]:
        """The three latency runs' load.json files, by run."""
        return {run: json.loads((output / path).read_text(encoding="utf-8"))
                for run, path in LATENCY_RUNS.items()}

    def check_top(self, result: dict, settings: dict) -> None:
        """R17: the top-level keys, times, settings, recorded context, format, and plan."""
        self.assertEqual(set(result), REFS_KEYS)
        self.assertIs(type(result["schema_version"]), int)
        self.assertEqual(result["schema_version"], 1)
        started, finished, recorded = (self.assertUtc(result[key]) for key in
                                       ("started_utc", "finished_utc", "recorded_utc"))
        self.assertLessEqual(started, finished)
        self.assertLessEqual(finished, recorded)
        self.assertEqual(set(result["settings"]), SETTINGS_KEYS)
        self.assertEqual(result["settings"], settings)
        for key in ("algorithms", "clients", "concurrency"):
            self.assertIsInstance(result["settings"][key], list, key)
        self.assertEqual(set(result["environment"]), set(transport_load.run_environment()))
        for key in ("git_commit", "git_dirty_scripts_or_fixtures", "page_size_bytes"):
            self.assertIn(key, result["environment"])
        self.assertEqual(result["layers"], manifest_layers(load_manifest()))
        self.assertIsInstance(result["browser"], dict)
        self.assertEqual(set(result["browser"]), {"version", "user_agent"})
        for value in result["browser"].values():
            self.assertTrue(isinstance(value, str) and value.strip())
        self.assertIn("HeadlessChrome", result["browser"]["user_agent"])
        self.assertIs(result["experiment_keys"], True)
        self.assertEqual(result["format"], FORMAT)
        for row in result["plan"]:
            self.assertEqual(set(row), PLAN_KEYS)
        self.assertJsonClose(result["plan"],
                             [expected_plan_row(name, settings["claims"])
                              for name in settings["algorithms"]], "plan")

    def check_pair(self, entry: dict, keys: set, logs: dict, claims: str, algorithm: str,
                   transport: str, pad: int = 0) -> None:
        """R14: one measured reference pair or probe, consistent with every layer's log."""
        self.assertEqual(set(entry), keys)
        self.assertEqual((entry["algorithm"], entry["transport"]), (algorithm, transport))
        total = token_bytes(algorithm, padded_claims(claim_set(claims), pad))
        self.assertEqual(entry["token_bytes"], total)
        self.assertEqual(entry["reference_bytes"], REF_BYTES)
        self.assertIn(entry["outcome"], ("verified", "rejected"))
        for key in ("issue_status", "verify_status"):
            self.assertTrue(entry[key] is None or type(entry[key]) is int, key)
        if transport == "bearer":
            self.assertIsNone(entry["cookie_stored"])
        else:
            self.assertIsInstance(entry["cookie_stored"], bool)
        if "verified_directly" in keys:
            self.assertIs(entry["verified_directly"], True)
        if entry["outcome"] == "verified":
            self.assertIsNone(entry["rejected_by"])
            self.assertEqual((entry["issue_status"], entry["verify_status"]), (200, 200))
            if transport == "cookie":
                self.assertIs(entry["cookie_stored"], True)
        else:
            self.assertIn(entry["rejected_by"], LAYERS)
            if type(entry["issue_status"]) is int and entry["issue_status"] != 200:
                self.assertEqual(entry["rejected_by"], failed_layer(logs, entry["issue_nonce"]))
            elif entry["cookie_stored"] is False:
                self.assertEqual(entry["rejected_by"], "browser")
            elif type(entry["verify_status"]) is int and entry["verify_status"] != 200:
                self.assertEqual(entry["rejected_by"], failed_layer(logs, entry["verify_nonce"]))
        recorded = entry["bytes"]
        self.assertEqual(set(recorded), BYTES_KEYS)
        self.assertEqual(recorded["header_line"], HEADER_LINE[transport])
        self.assertEqual(recorded["app_received_headers"],
                         app_header_bytes(logs["app.log"], entry["verify_nonce"]))
        for name in ("issue_nonce", "verify_nonce"):
            self.assertRegex(entry[name], NONCE)
            if name == "issue_nonce" or entry["outcome"] == "verified":
                self.assertIn(entry[name], logs["browser.log"], name)
            if entry["outcome"] == "verified":
                self.assertIn(entry[name], logs["proxy-access.log"], name)
                self.assertIn(entry[name], logs["app.log"], name)
        if entry["outcome"] == "verified":
            # R9, R14: the size-limits stack keeps the memory store.
            for name, suffix in (("issue_nonce", "ref=issued store=memory"),
                                 ("verify_nonce", "ref=found store=memory")):
                line = app_line(logs["app.log"], entry[name]) or ""
                self.assertTrue(line.endswith(suffix), (name, line))
        evidence = entry["evidence"]
        self.assertTrue(isinstance(evidence, str) and evidence.strip())
        self.assertNotIn("eyJ", evidence)
        self.assertEqual(token_runs(evidence), [])
        if without_tokens is not None:
            self.assertEqual(without_tokens(evidence), evidence)
        records = browser_records(logs["browser.log"])
        issue = request_record(records, entry["issue_nonce"], REFERENCE_PATH)
        self.assertIsNotNone(issue, "browser.log has no reference request with this nonce")
        query = query_of(issue["url"])
        self.assertEqual(query.get("alg"), algorithm)
        self.assertEqual(query.get("claims"), claims)
        self.assertEqual(query.get("attrs"), "full")
        self.assertEqual(query.get("delivery"), "cookie" if transport == "cookie" else "body")
        self.assertEqual(query.get("pad", "0"), str(pad))
        if entry["outcome"] == "verified":
            verify = request_record(records, entry["verify_nonce"], VERIFY_PATH)
            self.assertIsNotNone(verify, "browser.log has no verify request with this nonce")
            headers = verify["headers"]
            if transport == "cookie":
                cookie = headers.get("cookie", "")
                self.assertRegex(cookie, rf"(?:^|;\s*)jwt_ref={REF_FORMAT.pattern}(?:;|$)")
                self.assertNotRegex(cookie, r"(?:^|;\s*)jwt=")
            else:
                self.assertRegex(headers.get("authorization", ""),
                                 rf"\ABearer {REF_FORMAT.pattern}\Z")
            # The request no longer carries the token, so it fits nginx's 8,192-byte line.
            self.assertLessEqual(recorded["app_received_headers"], manifest_limits()[1])

    def check_limits(self, result: dict, output: Path, jwt_source: str | None) -> None:
        """R14: the reference pairs and probes at the documented defaults, and the derived JWT
        verdicts they are compared with."""
        limits, settings = result["limits"], result["settings"]
        algorithms, claims = settings["algorithms"], settings["claims"]
        self.assertEqual(set(limits), LIMITS_KEYS)
        self.assertEqual({key: limits[key] for key in ("stack", "header_buffers", "proxy_buffers",
                                                       "ref_store", "cookie_attributes")},
                         {"stack": "limits", "header_buffers": None, "proxy_buffers": None,
                          "ref_store": "memory", "cookie_attributes": FULL_ATTRIBUTES})
        self.assertEqual([(pair["algorithm"], pair["transport"]) for pair in limits["results"]],
                         [(name, transport) for name in algorithms for transport in TRANSPORTS])
        logs = self.logs(output, "limits", LIMIT_LOGS)
        nonces = []
        for pair in limits["results"]:
            with self.subTest(pair=(pair["algorithm"], pair["transport"])):
                self.check_pair(pair, RESULT_KEYS, logs, claims, pair["algorithm"],
                                pair["transport"])
            nonces += [pair["issue_nonce"], pair["verify_nonce"]]
        jwt = expected_jwt(algorithms, claims, jwt_source)
        if jwt is None:
            self.assertIsNone(limits["jwt"])
        else:
            self.assertEqual(set(limits["jwt"]), JWT_KEYS)
            for entry in limits["jwt"]["results"]:
                self.assertEqual(set(entry), set(JWT_RESULT_KEYS))
            self.assertEqual(limits["jwt"], jwt)
        for entry in limits["moved"]:
            self.assertEqual(set(entry), MOVED_KEYS)
        self.assertEqual(limits["moved"], expected_moved(limits["results"], jwt))
        probes = result["probes"]
        self.assertIsInstance(probes, list)
        self.assertEqual([(probe["target_bytes"], probe["transport"]) for probe in probes],
                         [(target, transport) for target in PROBE_TARGETS
                          for transport in TRANSPORTS])
        for probe in probes:
            with self.subTest(probe=(probe["target_bytes"], probe["transport"])):
                pad = pad_for_target(PROBE_ALGORITHM, claim_set(claims), probe["target_bytes"])
                self.assertEqual(probe["pad"], pad)
                self.check_pair(probe, PROBE_KEYS, logs, claims, PROBE_ALGORITHM,
                                probe["transport"], pad)
                self.assertLessEqual(probe["token_bytes"], probe["target_bytes"])
                self.assertGreater(token_bytes(PROBE_ALGORITHM,
                                               padded_claims(claim_set(claims), pad + 1)),
                                   probe["target_bytes"])
                if probe["outcome"] == "verified":
                    # The request size does not depend on the token's.
                    self.assertLess(probe["bytes"]["app_received_headers"], probe["token_bytes"])
            nonces += [probe["issue_nonce"], probe["verify_nonce"]]
        self.assertEqual(len(set(nonces)), len(nonces), "nonces repeat")
        # No JWT went through nginx in this phase, so its error log quotes none.
        for name in ("proxy-error.log", "proxy-access.log", "app.log"):
            with self.subTest(log=name):
                self.assertNotIn("eyJ", logs[name])
                self.assertEqual(token_runs(logs[name]), [])

    def check_handling(self, result: dict, output: Path) -> None:
        """R15: the reference-handling cases on the remote-store stack, with R15's statuses."""
        handling, claims = result["handling"], result["settings"]["claims"]
        self.assertEqual(set(handling), HANDLING_KEYS)
        self.assertEqual({key: handling[key] for key in HANDLING_KEYS - {"cases"}},
                         {"algorithm": "ML-DSA-44", "claims": claims,
                          "token_bytes": token_bytes("ML-DSA-44", claim_set(claims)),
                          "stack": "behavior", "ref_store": "remote", "expired_ttl_seconds": 1})
        cases = handling["cases"]
        self.assertEqual([case["name"] for case in cases], list(CASE_NAMES))
        logs = self.logs(output, "behavior", BEHAVIOR_LOGS)
        for case, (name, status, source, ref_status, lookup, verify, sent) in zip(
                cases, HANDLING_CASES):
            with self.subTest(case=name):
                self.assertEqual(set(case), CASE_KEYS)
                self.assertEqual(case["method"], "GET")
                path = REFERENCE_PATH if name == "issue_without_store" else VERIFY_PATH
                self.assertEqual(urlsplit(case["path"]).path, path)
                self.assertEqual(case["sent"], sent)
                self.assertEqual(case["store"], "stopped" if name in STOPPED_CASES else "running")
                self.assertEqual(case["status"], status)
                self.assertIs(case["verified"], status == 200)
                self.assertEqual(case["source"], source)
                self.assertEqual(case["ref_status"], ref_status)
                self.assertIs(case["lookup_called"], lookup)
                self.assertIs(case["verify_called"], verify)
                self.assertEqual(case["revoke_status"], 200 if name == "revoked" else None)
                self.assertFalse(case["set_cookie"])
                if status == 200:
                    self.assertIsNone(case["error"])
                else:
                    self.assertIsInstance(case["error"], str)
                    self.assertEqual(token_runs(case["error"]), [])
                    if without_tokens is not None:
                        self.assertEqual(without_tokens(case["error"]), case["error"])
                if ref_status in ("unknown", "expired", "revoked"):
                    self.assertIn(ref_status, case["error"])
                if name == "store_unavailable":
                    self.assertTrue(case["error"].startswith("reference store unavailable"))
                if status == 400:
                    self.assertTrue(case["error"].startswith("more than one token"))
                if name == "issue_without_store" and case["nonce"] is None:
                    # R15 names this request's URL without a nonce; find it by path and status.
                    line = next((line for line in logs["app.log"].splitlines()
                                 if f"GET {REFERENCE_PATH}?" in line and "delivery=cookie" in line
                                 and APP_STATUS.search(line)
                                 and APP_STATUS.search(line)[1] == "503"), None)
                    self.assertIn(f"GET {REFERENCE_PATH}?", logs["proxy-access.log"])
                else:
                    self.assertRegex(case["nonce"], NONCE)
                    self.assertIn(case["nonce"], logs["proxy-access.log"])
                    line = app_line(logs["app.log"], case["nonce"])
                self.assertIsNotNone(line, "app.log has no line for this case")
                if name == "issue_without_store":
                    self.assertTrue(line.endswith("ref=unavailable store=remote"), line)
                elif ref_status is not None:
                    self.assertTrue(line.endswith(f"ref={ref_status} store=remote"), line)
                elif source is not None:  # Requests without a reference keep their fields.
                    self.assertNotIn("ref=", line)
                    self.assertTrue(line.split()[-1].startswith("verified="), line)
        nonces = [case["nonce"] for case in cases if case["nonce"] is not None]
        self.assertGreaterEqual(len(nonces), len(cases) - 1)
        self.assertEqual(len(set(nonces)), len(nonces), "nonces repeat")
        revokes = [line for line in logs["app.log"].splitlines()
                   if f'"POST {REVOKE_PATH}' in line and APP_STATUS.search(line)]
        self.assertEqual(len(revokes), 1, revokes)
        self.assertTrue(revokes[0].endswith("ref=found store=remote"), revokes[0])
        self.assertIn(f"POST {REVOKE_PATH}", logs["proxy-access.log"])
        self.assertTrue(any(REFERENCE_PATH in line and "ttl=1" in line
                            for line in logs["app.log"].splitlines()))
        # R15: A, B, and C go into the remote store, and they and J are issued straight from
        # the application, so nginx sees only issue_without_store's reference request.
        issued = [line for line in logs["app.log"].splitlines()
                  if REFERENCE_PATH in line and APP_STATUS.search(line)
                  and line.endswith("ref=issued store=remote")]
        self.assertEqual(len(issued), 3, issued)
        proxied = re.findall(r'"[A-Z]+ (\S+) HTTP', logs["proxy-access.log"])
        self.assertEqual([target for target in proxied if urlsplit(target).path == ISSUE_PATH],
                         [])
        self.assertEqual(len([target for target in proxied
                              if urlsplit(target).path == REFERENCE_PATH]), 1, proxied)
        for name, text in logs.items():
            with self.subTest(log=name):
                self.assertNotIn("eyJ", text)
                self.assertEqual(token_runs(text), [])

    def check_raw(self, load: dict, directory: Path, components) -> None:
        """R11, R16: raw.csv.gz's header, and each cell's component means recomputed from it."""
        header, rows = raw_table(directory / "raw.csv.gz")
        reference = "lookup" in components
        self.assertEqual(header, [*RAW_FIELDS, *(["lookup_ns"] if reference else [])])
        samples = {}
        for row in rows:
            if row["verified"] != "true":
                continue
            total, handler, verify = (int(row[key]) for key in ("total_ns", "handler_ns",
                                                                 "verify_ns"))
            lookup = int(row["lookup_ns"]) if reference else 0
            values = {"total": total, "transfer": total - handler,
                      "other_handling": handler - verify - lookup, "verification": verify}
            if reference:
                values["lookup"] = lookup
            key = (row["client"], int(row["concurrency"]), row["algorithm"], row["variant"])
            samples.setdefault(key, []).append(values)
        for cell in load["results"]:
            key = (cell["client"], cell["concurrency"], cell["algorithm"], cell["variant"])
            measured = samples.get(key, [])
            with self.subTest(cell=key):
                self.assertEqual(len(measured), cell["verified"])
                if cell["latency"] is None:
                    self.assertEqual(measured, [])
                    continue
                self.assertEqual(set(cell["latency"]), set(components))
                for component in components:
                    mean = statistics.fmean(values[component] for values in measured) / 1e6
                    self.assertTrue(math.isclose(cell["latency"][component]["mean_ms"], mean,
                                                 rel_tol=1e-9, abs_tol=1e-9), component)

    def check_latency(self, result: dict, output: Path) -> None:
        """R11, R16: the three saved load runs and the comparison derived from them."""
        latency, settings = result["latency"], result["settings"]
        self.assertEqual(set(latency), LATENCY_KEYS)
        self.assertEqual({key: latency[key] for key in ("transport", "reference",
                                                        "size_controls", "runs")},
                         {"transport": "bearer", "reference": "ES256", "size_controls": False,
                          "runs": LATENCY_RUNS})
        loads = self.loads(output)
        jwt_settings = expected_load_settings(settings)
        self.assertEqual(loads["jwt"]["settings"], jwt_settings)
        for run, store in REF_STORES.items():
            with self.subTest(run=run):
                self.assertEqual(loads[run]["settings"],
                                 {**jwt_settings, "transport": "ref_bearer", "ref_store": store})
                self.assertLessEqual(set(loads["jwt"]), set(loads[run]))
        for run, load in loads.items():
            directory = output / LATENCY_DIRS[run]
            components = COMPONENTS if run == "jwt" else REF_COMPONENTS
            with self.subTest(run=run):
                self.assertTrue(load["results"])
                for cell in load["results"]:
                    total = token_bytes(cell["algorithm"], claim_set(settings["claims"]))
                    self.assertEqual(cell["variant"], "token")
                    self.assertEqual(cell["claims"], settings["claims"])
                    self.assertEqual(cell["token_bytes"], total)
                    if run == "jwt":
                        self.assertNotIn("reference_bytes", cell)
                        self.assertEqual(cell["bytes"]["header_line"],
                                         len("Authorization: Bearer \r\n") + total)
                    else:
                        self.assertEqual(cell["reference_bytes"], REF_BYTES)
                        self.assertEqual(cell["bytes"]["header_line"], 71)
                    if not cell["issue"]["delivered"]:
                        self.assertEqual(cell["requests"], 0)
                        self.assertTrue(cell["issue"]["error"])
                self.check_raw(load, directory, components)
        jwt_keys = {key for cell in token_cells(loads["jwt"]) for key in cell}
        for run in REF_STORES:
            for cell in token_cells(loads[run]):
                self.assertLessEqual(jwt_keys | {"reference_bytes"}, set(cell))
        expected = expected_latency_rows(loads)
        self.assertEqual(len(latency["rows"]), len(expected))
        for row, wanted in zip(latency["rows"], expected):
            with self.subTest(row=(wanted["client"], wanted["concurrency"], wanted["algorithm"])):
                self.assertEqual(set(row), LATENCY_ROW_KEYS)
                self.assertJsonClose(row, wanted, "latency row")
        for entry in latency["network_model"]:
            self.assertEqual(set(entry), NETWORK_KEYS)
        self.assertJsonClose(latency["network_model"],
                             expected_network_model(settings["algorithms"], loads),
                             "network_model")
        hosts = {len(urlsplit(load["proxy_url"]).netloc) for load in loads.values()}
        if len(hosts) == 1:  # A reference header line instead of the token's.
            for entry in latency["network_model"]:
                total = token_bytes(entry["algorithm"], claim_set(settings["claims"]))
                self.assertEqual(entry["saved_bytes"], total - REF_BYTES)
        self.check_latency_logs(loads, output)

    def check_latency_logs(self, loads: dict[str, dict], output: Path) -> None:
        """R11: how each latency run issued and sent its tokens or references."""
        for run, load in loads.items():
            directory = output / LATENCY_DIRS[run]
            access = read_gzip(directory / "logs" / "proxy-access.log.gz")
            app = read_gzip(directory / "logs" / "app.log.gz")
            targets = re.findall(r'"GET (\S+) HTTP', access)
            issues = [target for target in targets if urlsplit(target).path == ISSUE_PATH]
            references = [target for target in targets
                          if urlsplit(target).path == REFERENCE_PATH]
            timed = [target for target in targets if urlsplit(target).path == VERIFY_PATH]
            with self.subTest(run=run):
                self.assertTrue(timed)
                for target in timed:
                    self.assertRegex(target, rf"\A{VERIFY_PATH}\?timing=1&nonce=[0-9a-f]{{32}}\Z")
                issued = issues if run == "jwt" else references
                self.assertEqual([] if run == "jwt" else issues, [])
                if run == "jwt":
                    self.assertEqual(references, [])
                self.assertEqual(len(issued), len(token_cells(load)))
                for target in issued:
                    query = query_of(target)
                    self.assertEqual(query.get("delivery"), "body")
                    self.assertEqual(query.get("claims"), load["settings"]["claims"])
                    self.assertEqual(query.get("pad", "0"), "0")
                verified = [line for line in app.splitlines()
                            if "timing=1" in line and '" 200 ' in line]
                self.assertTrue(verified)
                for line in verified:
                    if run == "jwt":
                        self.assertNotIn("ref=", line)
                    else:
                        self.assertTrue(line.endswith(f"ref=found store={REF_STORES[run]}"),
                                        line)
                logs = visible_names(directory / "logs")
                self.assertIs("store.log.gz" in logs, run == "ref_remote")
                if "browser" in load["settings"]["clients"]:
                    browser = read_gzip(directory / "logs" / "browser.log.gz")
                    records = browser_records(browser)
                    if run == "jwt":  # Exactly run_load's browser.log.
                        self.assertTrue([record for record in records
                                         if record.get("event") == "load_issue"])
                    for record in records:  # Cookie names only, never a reference or token.
                        if "cookie_names" in record:
                            self.assertIsInstance(record["cookie_names"], list)
                    self.assertNotIn("eyJ", browser)
                    self.assertEqual(token_runs(browser), [])
                    self.assertEqual(REF_FORMAT.findall(browser), [])

    def check_phase_order(self, result: dict, output: Path) -> None:
        """R12, R16: the jwt, ref_memory, and ref_remote runs, in order, inside the run."""
        loads = self.loads(output)
        times = [parse_utc(result["started_utc"])]
        for run in RUNS:
            times += [parse_utc(loads[run]["started_utc"]), parse_utc(loads[run]["finished_utc"])]
        times.append(parse_utc(result["finished_utc"]))
        self.assertEqual(times, sorted(times))

    def check_layout(self, result: dict, output: Path) -> None:
        """R17: the files of a saved run and the evidence that names them."""
        self.assertEqual(visible_names(output), {"refs.json", *STACK_DIRS})
        expected = {}
        for stack, names in (("limits", LIMIT_LOGS), ("behavior", BEHAVIOR_LOGS)):
            with self.subTest(directory=stack):
                self.assertEqual(visible_names(output / stack), {"logs", "nginx.conf"})
                self.assertEqual(visible_names(output / stack / "logs"),
                                 {f"{name}.gz" for name in names})
            expected[stack] = {"logs": {name: f"{stack}/logs/{name}.gz" for name in names},
                               "nginx_conf": f"{stack}/nginx.conf"}
        expected["latency"] = {}
        for run, directory in LATENCY_DIRS.items():
            with self.subTest(run=run):
                self.assertEqual(visible_names(output / directory), SAVED_LOAD_FILES)
                load = json.loads((output / directory / "load.json").read_text(encoding="utf-8"))
                logs = sorted(visible_names(output / directory / "logs"))
                self.assertTrue(logs)
                self.assertTrue(all(log.endswith(".log.gz") for log in logs), logs)
                self.assertEqual(load["evidence"], {
                    "raw": "raw.csv.gz",
                    "logs": {log[:-len(".gz")]: f"logs/{log}" for log in logs},
                    "nginx_conf": "nginx.conf"})
            expected["latency"][run] = {
                "load": f"{directory}/load.json", "raw": f"{directory}/raw.csv.gz",
                "logs": {log[:-len(".gz")]: f"{directory}/logs/{log}" for log in logs},
                "nginx_conf": f"{directory}/nginx.conf"}
        self.assertEqual(result["evidence"], expected)
        for path in output.rglob("*.gz"):
            with self.subTest(gzip=str(path.relative_to(output))):
                self.assertEqual(path.read_bytes()[4:8], b"\0\0\0\0", "gzip mtime is not 0")
                gzip.decompress(path.read_bytes())
        named = {"refs.json"}
        for path in evidence_paths(result["evidence"]):
            with self.subTest(evidence=path):
                self.assertIsInstance(path, str)
                self.assertFalse(Path(path).is_absolute(), path)
                self.assertTrue((output / path).is_file(), path)
                if without_tokens is not None:
                    self.assertEqual(without_tokens(path), path)
                named.add(Path(path).as_posix())
        saved = {path.relative_to(output).as_posix() for path in output.rglob("*")
                 if path.is_file() and not path.name.startswith(".")}
        self.assertEqual(saved - named, set(), "files missing from evidence")

    def check_nginx_confs(self, result: dict, output: Path) -> None:
        """R14-R16: default limits for limits and behavior, and the latency stacks' settings."""
        settings = result["settings"]
        defaults = {}
        for stack in ("limits", "behavior"):
            text = read_text(output / stack / "nginx.conf")
            with self.subTest(stack=stack):
                self.assertNotIn("Not a default", text)
                # The template's header comment names these directives; none may be set.
                self.assertNotRegex(text, directive("large_client_header_buffers"))
                self.assertNotRegex(text, directive("proxy_buffer_size"))
                self.assertNotRegex(text, directive("proxy_buffers"))
                self.assertNotRegex(text, directive("keepalive"))
                self.assertEqual(len(conf_ports(output / stack / "nginx.conf")), 2)
            defaults[stack] = re.sub(r"\"[^\"]*\"", '"<path>"',
                                     re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<port>", text))
        self.assertEqual(defaults["limits"], defaults["behavior"])
        rendered = {}
        for run, directory in LATENCY_DIRS.items():
            text = read_text(output / directory / "nginx.conf")
            with self.subTest(run=run):
                self.assertIn(f"large_client_header_buffers 4 {settings['header_buffers']};",
                              text)
                self.assertNotRegex(text, directive("proxy_buffer_size"))
                if settings["upstream_keepalive"] is not None:
                    self.assertIn(f"keepalive {settings['upstream_keepalive']};", text)
                else:
                    self.assertNotRegex(text, directive("keepalive"))
                self.assertEqual(len(conf_ports(output / directory / "nginx.conf")), 2)
            rendered[run] = re.sub(r"\"[^\"]*\"", '"<path>"',
                                   re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<port>", text))
        self.assertEqual(rendered["ref_memory"], rendered["jwt"])
        self.assertEqual(rendered["ref_remote"], rendered["jwt"])
        for path in output.glob("*/nginx.conf"):
            listens = re.findall(r"(?m)^\s*listen\s+(\S+?);", read_text(path))
            self.assertTrue(listens)
            self.assertTrue(all(value.startswith(f"{HOST}:") for value in listens), listens)

    def check_privacy(self, output: Path, every_file: bool) -> None:
        """R17, R21: no token or reference where none may be; no path, host, or user name."""
        refs_text = read_text(output / "refs.json")
        for path in (str(REPO), str(REPO.resolve()), "CIS628Project"):
            self.assertNotIn(path, refs_text)
        token_free = [output / "refs.json"]
        for stack, names in (("limits", ("app.log", "proxy-access.log", "proxy-error.log")),
                             ("behavior", BEHAVIOR_LOGS)):
            token_free += [output / stack / "logs" / f"{name}.gz" for name in names]
        for directory in LATENCY_DIRS.values():
            token_free += [output / directory / "load.json", output / directory / "raw.csv.gz",
                           *sorted((output / directory / "logs").glob("*.log.gz"))]
        for path in token_free:
            with self.subTest(file=str(path.relative_to(output))):
                text = read_any(path)
                self.assertNotIn("eyJ", text)
                self.assertEqual(token_runs(text)[:3], [])
        holder = output / "limits" / "logs" / "browser.log.gz"
        for path in sorted(output.rglob("*")):
            if path.is_file() and path != holder:
                with self.subTest(references=str(path.relative_to(output))):
                    self.assertEqual(REF_FORMAT.findall(read_any(path))[:3], [])
        checked = (sorted(path for path in output.rglob("*") if path.is_file()) if every_file
                   else [output / "refs.json", *(output / run for run in LATENCY_RUNS.values())])
        names = private_names()
        for path in checked:
            text = read_any(path)
            for name in names:
                self.assertNotIn(name, text, str(path.relative_to(output)))

    def check_summary(self, lines, result: dict) -> None:
        """R18: the lines in phase order, each starting with its phase word and naming its row."""
        self.assertIsInstance(lines, list)
        words = summary_words(result)
        self.assertEqual(len(lines), len(words), "\n".join(map(str, lines)))
        for line, word in zip(lines, words):
            self.assertIsInstance(line, str)
            self.assertTrue(line.startswith(word), f"{line!r} should start with {word!r}")
        position = 0
        for row in result["plan"]:
            self.assertIn(row["algorithm"], lines[position])
            position += 1
        for entry, moved in zip(result["limits"]["results"], result["limits"]["moved"]):
            line = lines[position]
            self.assertIn(entry["algorithm"], line)
            self.assertIn(entry["outcome"], line)
            if moved["jwt"] is not None:
                self.assertIn(moved["jwt"], line)
            self.assertIs(MOVED_WORD.search(line) is not None, moved["moved"] is True, line)
            position += 1
        for probe in result["probes"]:
            line = lines[position]
            self.assertIn(probe["algorithm"], line)
            self.assertIn(probe["transport"], line)
            self.assertTrue(contains_number(line, probe["token_bytes"]), line)
            position += 1
        for case in result["handling"]["cases"]:
            self.assertIn(case["name"], lines[position])
            self.assertRegex(lines[position], rf"(?<!\d){case['status']}(?!\d)")
            position += 1
        for row in result["latency"]["rows"]:
            line = lines[position]
            self.assertIn(row["algorithm"], line)
            if all(row["mean_ms"][run] is not None for run in RUNS):
                for run in RUNS:
                    self.assertTrue(shows_ms(line, row["mean_ms"][run]["total"]), (run, line))
                for run in ("ref_memory", "ref_remote"):
                    self.assertTrue(shows_ms(line, row["difference_ms"][run]["total"]),
                                    (run, line))
            position += 1

    def check_saved_run(self, output: Path, settings: dict, current: bool = True,
                        jwt_source: str | None = None) -> dict:
        """Check a run saved by run_refs or the refs command in full; return refs.json.

        current: the run was recorded from this checkout, so its environment and its derived
        JWT verdicts are this machine's.
        """
        result = json.loads((output / "refs.json").read_text(encoding="utf-8"))
        self.check_top(result, settings)
        if current:
            self.assertEqual(result["environment"], transport_load.run_environment())
            jwt_source = matching_claims_source()
        self.check_limits(result, output, jwt_source)
        self.check_handling(result, output)
        self.check_latency(result, output)
        self.check_phase_order(result, output)
        self.check_layout(result, output)
        self.check_nginx_confs(result, output)
        self.check_privacy(output, every_file=not current)
        self.check_summary(summary_lines(result), result)
        # refs.json is written last, after every phase.
        newest = max(path.stat().st_mtime_ns for path in output.rglob("*") if path.is_file())
        self.assertEqual((output / "refs.json").stat().st_mtime_ns, newest)
        return result


# ---- R12-R18: run_refs on real stacks ----------------------------------------------------

class RunRefsTests(RefsCase):
    """One short run_refs: ES256 only (the fixed probes and cases add the others), both
    clients."""

    SETTINGS = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct", "browser"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.0, "timeout": 60.0,
                "header_buffers": "32k", "upstream_keepalive": 8}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.output = cls.directory / "out" / "refs"  # Created by run_refs.
        cls.run_dir = cls.directory / "run"
        cls.result, cls.error = None, None
        cls.before, cls.after = children(), None
        if transport_refs is None:
            return
        wait_for_ephemeral_ports()
        try:
            cls.result = transport_refs.run_refs(
                cls.output, algorithms=["ES256"], clients=["direct", "browser"],
                concurrency=[1], duration=0.2, warmup=0.0, upstream_keepalive=8,
                run_dir=cls.run_dir)
        except Exception as error:  # Reported by every test instead of failing setUpClass.
            cls.error = error
        cls.after = children()

    def setUp(self):
        module()
        self.assertIsNone(self.error, f"run_refs raised {self.error!r}")

    def test_saved_run(self):
        self.check_saved_run(self.output, self.SETTINGS)

    def test_returns_what_it_saved(self):
        saved = json.loads((self.output / "refs.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json.dumps(self.result)), saved)

    def test_settings_repeat_the_run(self):
        bound = inspect.signature(module().run_refs).bind(self.directory / "new",
                                                          **self.result["settings"])
        self.assertEqual(set(bound.arguments), {"output_dir", *SETTINGS_KEYS})
        self.assertEqual(module().checked_settings(**self.result["settings"]),
                         self.result["settings"])

    def test_every_reference_pair_and_probe_verified(self):
        for entry in (*self.result["limits"]["results"], *self.result["probes"]):
            with self.subTest(pair=(entry["algorithm"], entry["transport"],
                                    entry.get("target_bytes"))):
                self.assertEqual(entry["outcome"], "verified", entry["evidence"])
        if self.result["limits"]["jwt"] is not None:  # ES256's JWT fits too: nothing moved.
            self.assertTrue(all(entry["moved"] is False
                                for entry in self.result["limits"]["moved"]))

    def test_handling_statuses(self):
        self.assertEqual([case["status"] for case in self.result["handling"]["cases"]],
                         [case[1] for case in HANDLING_CASES])

    def test_every_latency_cell_is_delivered(self):
        for run, load in self.loads(self.output).items():
            for cell in token_cells(load):
                with self.subTest(run=run, client=cell["client"]):
                    self.assertIs(cell["issue"]["delivered"], True, cell["issue"])
                    self.assertGreater(cell["verified"], 0)
                    self.assertEqual(cell["failed"], 0)

    def test_stack_run_directories(self):
        for name in STACK_DIRS:
            with self.subTest(stack=name):
                self.assertTrue((self.run_dir / name / "nginx" / "nginx.conf").is_file())
                self.assertTrue((self.run_dir / name / "logs" / "app.log").is_file())
                self.assertIs((self.run_dir / name / "logs" / "store.log").is_file(),
                              name in ("behavior", "latency-ref-remote"))
        for stack, names in (("limits", LIMIT_LOGS), ("behavior", BEHAVIOR_LOGS)):
            for name in names:
                with self.subTest(stack=stack, log=name):
                    saved = read_gzip(self.output / stack / "logs" / f"{name}.gz")
                    self.assertTrue(read_text(self.run_dir / stack / "logs" / name)
                                    .startswith(saved))
        for name in STACK_DIRS:
            self.assertEqual((self.output / name / "nginx.conf").read_bytes(),
                             (self.run_dir / name / "nginx" / "nginx.conf").read_bytes())
        for run, path in LATENCY_RUNS.items():
            load = json.loads((self.output / path).read_text(encoding="utf-8"))
            self.assertEqual(Path(load["run_dir"]), (self.run_dir / LATENCY_DIRS[run]).absolute())

    def test_every_process_stopped(self):
        self.assertEqual(self.after - self.before, set(), "a started process is still running")
        ports = run_ports(self.run_dir)
        self.assertGreaterEqual(len(ports), 2)
        for port in ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_each_stack_stopped_before_the_next_started(self):
        # nginx logs its start and, when stopped, its exit, so the error logs of stacks that
        # ran one after another never overlap (to the second nginx logs).
        times = {name: nginx_times(self.run_dir / name / "logs" / "proxy-error.log")
                 for name in STACK_DIRS}
        for index, first in enumerate(STACK_DIRS):
            for second in STACK_DIRS[index + 1:]:
                with self.subTest(stacks=(first, second)):
                    self.assertTrue(times[first] and times[second], times)
                    self.assertLessEqual(max(times[first]), min(times[second]))

    def test_run_logs_hold_no_token_or_reference(self):
        for name in STACK_DIRS:
            for log in ("app.log", "proxy-access.log", "proxy-error.log", "store.log"):
                path = self.run_dir / name / "logs" / log
                if not path.exists():
                    continue
                with self.subTest(stack=name, log=log):
                    text = read_text(path)
                    self.assertNotIn("eyJ", text)
                    self.assertEqual(token_runs(text)[:3], [])

    def test_summary_lines_from_the_saved_json(self):
        saved = json.loads((self.output / "refs.json").read_text(encoding="utf-8"))
        lines = summary_lines(saved)
        self.check_summary(lines, saved)
        self.assertEqual(lines, summary_lines(self.result))


# ---- R19: the refs command -----------------------------------------------------------------

class RefsCommandTests(RefsCase):
    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44"], "claims": "oidc", "clients": ["direct"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.0, "timeout": 60.0,
                "header_buffers": "32k", "upstream_keepalive": 8}
    # Short values for the options a usage-error case does not set, so a wrongly accepted case
    # runs briefly.
    FILLER = {"--alg": ["ES256"], "--client": ["direct"], "--concurrency": ["1"],
              "--duration": ["0.1"], "--warmup": ["0"]}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        wait_for_ephemeral_ports()
        cls.output = cls.directory / "first"
        cls.output.mkdir()  # An existing empty directory is accepted.
        cls.run_dir = cls.directory / "first-run"
        cls.first = run_cli("refs", "--alg", "ML-DSA-44", "--client", "direct",
                            "--concurrency", "1", "--duration", "0.2", "--warmup", "0",
                            "--upstream-keepalive", "8", "--timeout", "60",
                            "--run-dir", cls.run_dir, "--output-dir", cls.output,
                            cwd=cls.directory)

    def require_first_run(self) -> None:
        """Fail unless the class's first refs run exited 0."""
        self.assertEqual(self.first.returncode, 0, self.first.stderr)

    def check_stopped(self, run_dir: Path) -> None:
        """Fail if any port a run used still accepts connections."""
        for port in run_ports(run_dir) | store_ports(run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_first_run_exits_0_and_saves_the_run(self):
        self.require_first_run()
        self.assertNotRegex(self.first.stderr, ERROR_LINE)
        saved = self.check_saved_run(self.output, self.SETTINGS)
        for entry in (*saved["limits"]["results"], *saved["probes"]):
            with self.subTest(pair=(entry["algorithm"], entry["transport"])):
                self.assertEqual(entry["outcome"], "verified", entry["evidence"])
        if saved["limits"]["jwt"] is not None:
            # ML-DSA-44's 4,095-byte OIDC JWT does not fit Chromium's cookie limit; its
            # 47-byte reference does.
            moved = {(entry["algorithm"], entry["transport"]): entry["moved"]
                     for entry in saved["limits"]["moved"]}
            self.assertIs(moved[("ML-DSA-44", "cookie")], True)
            self.assertIs(moved[("ML-DSA-44", "bearer")], False)

    def test_prints_the_summary_then_the_output_directory(self):
        self.require_first_run()
        saved = json.loads((self.output / "refs.json").read_text(encoding="utf-8"))
        expected = summary_lines(saved)
        self.assertTrue(expected)
        lines = self.first.stdout.splitlines()
        starts = [index for index in range(len(lines) - len(expected) + 1)
                  if lines[index:index + len(expected)] == expected]
        self.assertTrue(starts, self.first.stdout)
        rest = lines[starts[0] + len(expected):]
        names = (str(self.output), str(self.output.resolve()))
        self.assertTrue(any(line.startswith("Saved the results to ")
                            and any(name in line for name in names) for line in rest),
                        self.first.stdout)

    def test_first_run_stops_every_process(self):
        self.require_first_run()
        for name in STACK_DIRS:
            self.assertEqual(len(conf_ports(self.run_dir / name / "nginx" / "nginx.conf")), 2)
        self.check_stopped(self.run_dir)

    def test_settings_reuse_the_saved_run_with_overrides(self):
        # Minimal claims have no derived JWT verdicts, so limits.jwt and every moved are null.
        self.require_first_run()
        wait_for_ephemeral_ports()
        output, run_dir = self.directory / "reuse" / "nested", self.directory / "reuse-run"
        result = run_cli("refs", "--settings", self.output / "refs.json", "--alg", "ES256",
                         "--claims", "minimal", "--warmup", "0.1", "--timeout", "30",
                         "--run-dir", run_dir, "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = {**self.SETTINGS, "algorithms": ["ES256"], "claims": "minimal",
                    "warmup": 0.1, "timeout": 30.0}
        saved = self.check_saved_run(output, settings)
        self.assertIsNone(saved["limits"]["jwt"])
        self.assertTrue(all(entry["jwt"] is None and entry["moved"] is None
                            for entry in saved["limits"]["moved"]))
        self.check_stopped(run_dir)

    def test_saved_jwt_latency_settings_repeat_with_load(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        path = self.output / "latency-jwt" / "load.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        output = self.directory / "load-again"
        result = run_cli("load", "--settings", path, "--run-dir", self.directory / "load-run",
                         "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        again = json.loads((output / "load.json").read_text(encoding="utf-8"))
        self.assertEqual(again["settings"], saved["settings"])
        self.assertEqual(again["settings"]["transport"], "bearer")
        for cell in token_cells(again):
            with self.subTest(algorithm=cell["algorithm"]):
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)

    def test_reference_latency_settings_are_not_load_settings(self):
        self.require_first_run()
        for run in REF_STORES:
            with self.subTest(run=run):
                run_dir, output = self.directory / f"{run}-run", self.directory / f"{run}-out"
                result = run_cli("load", "--settings", self.output / LATENCY_RUNS[run],
                                 "--run-dir", run_dir, "--output-dir", output,
                                 cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(run_dir.exists())
                self.assertFalse(output.exists())

    def test_help_lists_every_option(self):
        result = run_cli("refs", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in REFS_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)
        for option in ("--proxy-buffers", "--proxy-port", "--app-port", "--transport"):
            with self.subTest(absent=option):
                self.assertNotIn(option, result.stdout)
        choices = re.search(r"--claims \{([a-z,]+)\}", result.stdout)
        self.assertIsNotNone(choices, result.stdout)
        self.assertEqual(set(choices[1].split(",")), set(CLAIM_SET_NAMES))

    def test_usage_errors_exit_2_before_anything_starts(self):
        # Without the refs command, argparse would reject every case for the wrong reason.
        self.assertEqual(run_cli("refs", "--help", cwd=self.directory).returncode, 0)
        bad = self.directory / "bad-settings"
        bad.mkdir()
        valid = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct"],
                 "concurrency": [1], "duration": 0.1, "warmup": 0.0, "timeout": 30.0,
                 "header_buffers": "32k", "upstream_keepalive": 8}
        files = {
            "not-json.json": "{not json",
            "no-settings.json": json.dumps({"results": []}),
            "list-settings.json": json.dumps({"settings": [1]}),
            "proxy-buffers.json": json.dumps({"settings": {**valid, "proxy_buffers": "32k"}}),
            "transport.json": json.dumps({"settings": {**valid, "transport": "bearer"}}),
            "ref-store.json": json.dumps({"settings": {**valid, "ref_store": "memory"}}),
            "bad-concurrency.json": json.dumps({"settings": {**valid, "concurrency": [0]}}),
            "bad-alg.json": json.dumps({"settings": {**valid, "algorithms": ["HS256"]}}),
            "bad-claims.json": json.dumps({"settings": {**valid, "claims": "huge"}}),
            "bad-duration.json": json.dumps({"settings": {**valid, "duration": 0}}),
            "bad-header-buffers.json": json.dumps({"settings": {**valid,
                                                                "header_buffers": "big"}}),
            "null-header-buffers.json": json.dumps({"settings": {**valid,
                                                                 "header_buffers": None}}),
            "bad-keepalive.json": json.dumps({"settings": {**valid, "upstream_keepalive": 0}}),
        }
        for name, text in files.items():
            (bad / name).write_text(text, encoding="utf-8")
        occupied = self.directory / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        cases = {
            "missing output dir": [],
            "non-empty output dir": ["--output-dir", occupied],
            "repeated alg": ["--alg", "ES256", "ES256", "--output-dir", "{out}"],
            "repeated client": ["--client", "direct", "direct", "--output-dir", "{out}"],
            "repeated concurrency": ["--concurrency", "1", "1", "--output-dir", "{out}"],
            "unknown alg": ["--alg", "HS256", "--output-dir", "{out}"],
            "unknown client": ["--client", "curl", "--output-dir", "{out}"],
            "unknown claims": ["--claims", "huge", "--output-dir", "{out}"],
            "concurrency 0": ["--concurrency", "0", "--output-dir", "{out}"],
            "concurrency 65": ["--concurrency", "65", "--output-dir", "{out}"],
            "zero duration": ["--duration", "0", "--output-dir", "{out}"],
            "negative duration": ["--duration=-1", "--output-dir", "{out}"],
            "negative warmup": ["--warmup=-0.5", "--output-dir", "{out}"],
            "zero timeout": ["--timeout", "0", "--output-dir", "{out}"],
            "invalid header buffers": ["--header-buffers", "big", "--output-dir", "{out}"],
            "keepalive 0": ["--upstream-keepalive", "0", "--output-dir", "{out}"],
            "keepalive 1025": ["--upstream-keepalive", "1025", "--output-dir", "{out}"],
            "proxy buffers option": ["--proxy-buffers", "32k", "--output-dir", "{out}"],
            "missing settings": ["--settings", bad / "missing.json", "--output-dir", "{out}"],
            **{f"settings {name}": ["--settings", bad / name, "--output-dir", "{out}"]
               for name in files},
        }
        if (S3_01_RUN / "load.json").is_file():  # A load.json has settings refs does not take.
            cases["settings from load.json"] = ["--settings", S3_01_RUN / "load.json",
                                                "--output-dir", "{out}"]
        if (COOKIES_RUN / "cookies.json").is_file():  # So has a cookies.json (proxy_buffers).
            cases["settings from cookies.json"] = ["--settings", COOKIES_RUN / "cookies.json",
                                                   "--output-dir", "{out}"]
        for index, (name, arguments) in enumerate(cases.items()):
            with self.subTest(name):
                run_dir = self.directory / f"usage-run-{index}"
                output = self.directory / f"usage-out-{index}"
                arguments = [output if argument == "{out}" else argument
                             for argument in arguments]
                given = {str(argument).split("=", 1)[0] for argument in arguments}
                if "--settings" not in given:  # Command-line options would override the file.
                    for option, values in self.FILLER.items():
                        if option not in given:
                            arguments += [option, *values]
                result = run_cli("refs", *arguments, "--run-dir", run_dir, cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(run_dir.exists(), "a stack was started")
                self.assertFalse(output.exists(), "the output directory was created")
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
        self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_runtime_failure_exits_1_and_stops_every_process(self):
        run_dir, output = self.directory / "failing-run", self.directory / "failing"
        with tempfile.TemporaryDirectory() as empty:
            result = run_cli("refs", "--alg", "ES256", "--client", "direct", "--concurrency",
                             "1", "--duration", "0.1", "--warmup", "0", "--timeout", "30",
                             "--run-dir", run_dir, "--output-dir", output, cwd=self.directory,
                             environment=cli_environment(PLAYWRIGHT_BROWSERS_PATH=empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        self.assertFalse((output / "refs.json").exists())
        self.check_stopped(run_dir)

    def test_signals_stop_the_run_and_every_process(self):
        # SIGINT while the size-limits phase sends its pairs, SIGTERM once the latency runs
        # have started; three short latency runs still follow the first timed request.
        for signum, stack, marker in ((signal.SIGINT, "limits", REFERENCE_PATH),
                                      (signal.SIGTERM, "latency-jwt", "timing=1")):
            with self.subTest(signal=signum.name):
                wait_for_ephemeral_ports()
                run_dir = self.directory / f"signal-{signum.name}"
                output = self.directory / f"signal-out-{signum.name}"
                command = [sys.executable, str(SCRIPT), "refs", "--alg", "ES256", "--client",
                           "direct", "--concurrency", "1", "--duration", "0.5", "--warmup",
                           "0", "--run-dir", str(run_dir), "--output-dir", str(output)]
                process = subprocess.Popen(command, cwd=self.directory, env=cli_environment(),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    log = run_dir / stack / "logs" / "proxy-access.log"
                    eventually(lambda: process.poll() is not None or marker in read_text(log),
                               grace=SIGNAL_GRACE)
                    self.assertIsNone(process.poll(), "the run ended before the signal")
                    process.send_signal(signum)
                    _, stderr = process.communicate(timeout=120)
                finally:
                    stop(process)
                self.assertEqual(process.returncode, 1, stderr)
                self.assertRegex(stderr, ERROR_LINE)
                self.assertFalse((output / "refs.json").exists())
                self.assertTrue(run_ports(run_dir))
                self.check_stopped(run_dir)


class OtherCommandsTests(unittest.TestCase):
    """R19, R25: the other commands keep their help, options, defaults, and outputs."""

    def help_output(self, script: Path, command: str, cwd: Path) -> str:
        """A command's --help output from script, uncolored and 100 columns wide."""
        environment = {key: value for key, value in cli_environment(COLUMNS="100",
                                                                     NO_COLOR="1").items()
                       if key not in ("FORCE_COLOR", "PYTHON_COLORS")}
        result = subprocess.run([sys.executable, str(script), command, "--help"], cwd=cwd,
                                env=environment, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_other_commands_keep_their_help(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = base_checkout(directory)
            if checkout is None:
                self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
            base = checkout / "scripts" / "transport_stack.py"
            for command in ("check", "tokens", "sweep", "serve", "versions", "load", "claims",
                            "cookies"):
                with self.subTest(command=command):
                    self.assertEqual(self.help_output(SCRIPT, command, Path(directory)),
                                     self.help_output(base, command, Path(directory)))
            new = self.help_output(SCRIPT, "load", Path(directory))
        choices = re.search(r"--transport \{([a-z,]+)\}", new)
        self.assertIsNotNone(choices, new)
        self.assertEqual(choices[1].split(","), ["bearer", "cookie", "split"])

    def test_main_help_names_refs(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--help"], cwd=REPO,
                                env=cli_environment(), text=True, capture_output=True,
                                timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("refs", result.stdout)
        self.assertIn("scripts/transport_refs.py", result.stdout)

    def test_serve_prints_only_its_urls_and_run_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            proxy_port, app_port = free_ports(2)
            run_dir = Path(directory) / "serve"
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), "serve", "--proxy-port", str(proxy_port),
                 "--app-port", str(app_port), "--run-dir", str(run_dir)], cwd=directory,
                env=cli_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            try:
                first = process.stdout.readline()
                process.send_signal(signal.SIGINT)
                rest, stderr = process.communicate(timeout=120)
            finally:
                stop(process)
            self.assertEqual(json.loads(first),
                             {"proxy_url": f"http://{HOST}:{proxy_port}",
                              "app_url": f"http://{HOST}:{app_port}",
                              "run_dir": str(run_dir.absolute())})
            self.assertEqual(rest.strip(), "", stderr)
            self.assertNotIn("store.log", visible_names(run_dir / "logs"))
            for port in (proxy_port, app_port):
                self.assertTrue(refused(port))


# ---- R20: Makefile -------------------------------------------------------------------------

class MakefileTests(unittest.TestCase):
    RECIPE = ('\t$(STACK) refs --header-buffers 32k --upstream-keepalive 64 --duration 2 '
              '--output-dir "$(REFS_DIR)"')
    ASSIGNMENT = "REFS_DIR ?= results/refs/$(shell date -u +%Y%m%dT%H%M%SZ)-$(LOAD_PLATFORM)"

    @classmethod
    def setUpClass(cls):
        cls.text = MAKEFILE.read_text(encoding="utf-8")

    def make(self, *arguments: str) -> subprocess.CompletedProcess:
        """Run make in the repository without inherited directory overrides; skips without make."""
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not installed")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MAKEFLAGS", "MFLAGS", "LOAD_DIR", "CLAIMS_DIR",
                                      "COOKIES_DIR", "REFS_DIR")}
        return subprocess.run([make, "--no-print-directory", *arguments], cwd=REPO,
                              env=environment, capture_output=True, text=True, timeout=60)

    def test_target_is_phony_and_in_help_after_cookies(self):
        phony = next((line for line in self.text.splitlines() if line.startswith(".PHONY:")), "")
        self.assertIn("refs", phony.split())
        result = self.make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        refs = [index for index, line in enumerate(lines) if line.startswith("make refs")]
        cookies = [index for index, line in enumerate(lines) if line.startswith("make cookies")]
        self.assertEqual(len(refs), 1, result.stdout)
        self.assertEqual(len(cookies), 1, result.stdout)
        self.assertGreater(refs[0], cookies[0])

    def test_recipe_and_output_directory(self):
        self.assertIn(self.ASSIGNMENT, self.text.splitlines())
        blocks = make_blocks(self.text)
        self.assertIn("refs", blocks)
        self.assertEqual(blocks["refs"][1:], [self.RECIPE])
        result = self.make("-n", "refs", "REFS_DIR=results/refs/dry-run", "PYTHON=python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/transport_stack.py refs --header-buffers 32k --upstream-keepalive '
                      '64 --duration 2 --output-dir "results/refs/dry-run"', result.stdout)
        if sys.platform == "darwin":
            result = self.make("-n", "refs", "PYTHON=python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'--output-dir "results/refs/\d{8}T\d{6}Z-macos"')

    def test_comment_above_the_target(self):
        lines = self.text.splitlines()
        index = next((position for position, line in enumerate(lines)
                      if line.startswith("refs:")), None)
        self.assertIsNotNone(index, "the Makefile has no refs target")
        above = []
        for line in reversed(lines[:index]):
            if not line.strip():
                break
            above.append(line)
        self.assertTrue(any(line.startswith("#") for line in above), above)

    def test_everything_else_unchanged(self):
        before = git_show("Makefile")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        old, new = make_blocks(before), make_blocks(self.text)
        # Later Sprint 3 items (S3-04) may add their own targets and help lines.
        self.assertLessEqual(set(old) | {"refs"}, set(new))
        for target, lines in old.items():
            with self.subTest(target=target):
                if target == "help":  # help gains the refs line, after the cookies line.
                    added = [line for line in new[target] if line not in lines]
                    refs = [line for line in added if line.startswith('\t@echo "make refs')]
                    self.assertEqual(len(refs), 1, added)
                    self.assertEqual([line for line in new[target] if line in lines], lines)
                    cookies = next(index for index, line in enumerate(new[target])
                                   if 'make cookies' in line)
                    self.assertGreater(new[target].index(refs[0]), cookies)
                else:
                    self.assertEqual(new[target], lines)
        assignments = [line for line in before.splitlines()
                       if re.match(r"^[A-Z_]+ *(\?|:)?=", line)]
        self.assertTrue(any(line.startswith("COOKIES_DIR ") for line in assignments))
        for line in assignments:
            with self.subTest(line=line):
                self.assertIn(line, self.text.splitlines())
        phony_before = next(line for line in before.splitlines() if line.startswith(".PHONY:"))
        phony_after = next(line for line in self.text.splitlines() if line.startswith(".PHONY:"))
        self.assertLessEqual(set(phony_before.split()) | {"refs"}, set(phony_after.split()))


# ---- R21: the committed run --------------------------------------------------------------

class CommittedRunTests(RefsCase):
    @classmethod
    def setUpClass(cls):
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def setUp(self):
        self.assertIsNotNone(self.saved, "no macOS run committed under "
                                         "results/refs/<YYYYMMDDTHHMMSSZ>-macos/")

    def test_exactly_one_run(self):
        runs = sorted(visible_names(REFS_RESULTS))
        self.assertEqual(len(runs), 1, runs)
        self.assertRegex(runs[0], RUN_NAME)
        tracked = git("ls-files", "--", "results/refs")
        self.assertIn(f"results/refs/{runs[0]}/refs.json", (tracked or "").split())

    def test_environment(self):
        environment = self.saved["environment"]
        self.assertTrue(environment["platform"].startswith("macOS"))
        self.assertEqual(environment["page_size_bytes"], 16384)
        self.assertRegex(str(environment["git_commit"]), HEX_COMMIT)
        self.assertEqual(len(environment["git_commit"]), 40)
        self.assertIs(environment["git_dirty_scripts_or_fixtures"], False)

    def test_settings_and_structure(self):
        self.check_top(self.saved, MAKE_SETTINGS)

    def test_limits_and_probes(self):
        self.assertEqual(self.saved["limits"]["jwt"]["source"], CLAIMS_SOURCE)
        self.check_limits(self.saved, self.run_dir, CLAIMS_SOURCE)
        for entry in (*self.saved["limits"]["results"], *self.saved["probes"]):
            with self.subTest(pair=(entry["algorithm"], entry["transport"],
                                    entry.get("target_bytes"))):
                self.assertEqual(entry["outcome"], "verified", entry["evidence"])

    def test_handling(self):
        self.check_handling(self.saved, self.run_dir)
        self.assertEqual([case["status"] for case in self.saved["handling"]["cases"]],
                         [case[1] for case in HANDLING_CASES])

    def test_latency(self):
        self.check_latency(self.saved, self.run_dir)
        self.check_phase_order(self.saved, self.run_dir)
        for run, load in self.loads(self.run_dir).items():
            with self.subTest(run=run):  # make refs with TMPDIR unset: stacks in /tmp.
                self.assertTrue(str(load["run_dir"]).startswith("/tmp/"), load["run_dir"])

    def test_files_and_nginx_confs(self):
        self.check_layout(self.saved, self.run_dir)
        self.check_nginx_confs(self.saved, self.run_dir)
        for path in self.run_dir.rglob("*"):
            if path.is_file():
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertLessEqual(path.stat().st_size, 10 * MIB)
                    self.assertFalse(path.name.endswith(".log"))
        tracked = git("ls-files", "-z", "--", "results/refs")
        for path in (tracked or "").split("\0"):
            self.assertFalse(path.endswith(".log"), path)

    def test_privacy(self):
        self.check_privacy(self.run_dir, every_file=True)

    def test_summary_lines(self):
        self.check_summary(summary_lines(self.saved), self.saved)


# ---- R22: MITIGATION_RESULTS.md ----------------------------------------------------------

class MitigationDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(MITIGATION_DOC)
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def require_run(self) -> dict:
        """The committed run's refs.json; fails without one."""
        self.assertIsNotNone(self.saved, "no committed macOS run under results/refs/")
        return self.saved

    def body(self) -> str:
        """The '## Reference tokens' section; fails without it."""
        body = section(self.text, "Reference tokens")
        self.assertIsNotNone(body, "missing heading: ## Reference tokens")
        return body

    def part(self, title: str) -> str:
        """One level-3 subsection of the section; fails without it."""
        body = section(self.body(), title, level=3)
        self.assertIsNotNone(body, f"missing heading: ### {title}")
        return body

    def section_intro(self) -> str:
        """The section's text before its first subsection."""
        body = self.body()
        first = next((index for depth, _, index in headings(body.splitlines()) if depth == 3),
                     None)
        return "\n".join(body.splitlines()[:first])

    def rows_naming(self, body: str, name: str) -> list[str]:
        """The table rows of body that contain name."""
        return [row for row in table_rows(body) if name in row]

    def test_headings_in_order(self):
        level_two = [name for depth, name, _ in headings(self.text.splitlines()) if depth == 2]
        self.assertIn("Cookie splitting", level_two)
        self.assertIn("Reference tokens", level_two)
        self.assertEqual(level_two.index("Reference tokens"),
                         level_two.index("Cookie splitting") + 1)
        self.assertEqual(level_two[-1], "Reference tokens")
        found = []
        for depth, name, _ in headings(self.body().splitlines()):
            match = next((title for title in MITIGATION_PARTS
                          if name == title or name.startswith(f"{title} ")), None)
            if depth == 3 and match:
                found.append(match)
        self.assertEqual(found, list(MITIGATION_PARTS))

    def test_document_introduction(self):
        intro = self.text.split("## Smaller claim sets", 1)[0]
        self.assertIn("S3-02", intro)
        paragraphs = [block for block in re.split(r"\n\s*\n", intro)
                      if block.strip() and not block.lstrip().startswith("#")]
        self.assertTrue(paragraphs)
        first = paragraphs[0]
        lowered = first.lower()
        self.assertIn("cookies", first)
        self.assertIn("first two", lowered)
        self.assertIn("](TRANSPORT.md#the-refs-command)", first)
        for term in ("smaller claim sets", "cookie splitting", "reference token"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        lines = intro.splitlines()
        self.assertNotIn("- **Reference tokens:** not covered yet.", lines)
        bullets = [line for line in lines if line.startswith("- **Reference tokens:**")]
        self.assertEqual(len(bullets), 1, bullets)
        self.assertNotIn("not covered yet", bullets[0].lower())
        self.assertNotIn("cookie splitting", bullets[0].lower())
        cookie_bullets = [line for line in lines if line.startswith("- ")
                          and "cookie splitting" in line.lower()]
        self.assertEqual(len(cookie_bullets), 1, cookie_bullets)
        lowered_lines = self.text.lower().splitlines()
        self.assertTrue(any("reference token" in line and "not" in line
                            for line in lowered_lines))
        self.assertTrue(any("cookie splitting" in line and "not" in line
                            for line in lowered_lines))

    def test_earlier_sections_unchanged(self):
        before = git_show("MITIGATION_RESULTS.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        for title in ("Smaller claim sets", "Cookie splitting"):
            with self.subTest(section=title):
                new = section(self.text, title)
                self.assertIsNotNone(new)
                self.assertEqual(new.rstrip(), section(before, title).rstrip())

    def test_section_introduction(self):
        intro = self.section_intro()
        lowered = intro.lower()
        self.assertIn("question", lowered)
        self.assertTrue(any(line.startswith("- ") for line in intro.splitlines()))
        for term in ("ephemeral", "experiment key", "production", "random", "memory",
                     "machine state", "time_wait", "load average"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue(any(term in lowered for term in ("candidate", "process", "running")))
        run = self.require_run()
        self.assertIn("macOS", intro)
        self.assertIn(run["environment"]["git_commit"][:7], intro)
        self.assertIn(self.run_dir.name, intro)
        started = parse_utc(run["started_utc"])
        days = {(started + timedelta(hours=offset)).date() for offset in (-14, 0, 14)}
        dates = [form for day in days for form in
                 (day.isoformat(), f"{day:%B} {day.day}, {day.year}",
                  f"{day.day} {day:%B} {day.year}", f"{day:%b} {day.day}, {day.year}")]
        self.assertTrue(any(date in intro for date in dates), dates)
        self.assertIn("UTC", intro)

    def test_links_resolve_and_reach_the_run(self):
        for link in relative_links(self.text):
            with self.subTest(link=link):
                self.assertTrue((REPO / link.split("#", 1)[0]).exists(), link)
        run = self.require_run()
        resolved = {(REPO / link.split("#", 1)[0]).resolve()
                    for link in relative_links(self.body())}
        wanted = [self.run_dir / "refs.json"]
        for stack in ("limits", "behavior"):
            wanted += [self.run_dir / path for path in evidence_paths(run["evidence"][stack])]
        for entry in run["evidence"]["latency"].values():
            wanted += [self.run_dir / entry[key] for key in ("load", "raw", "nginx_conf")]
        for path in wanted:
            with self.subTest(target=str(path.relative_to(REPO))):
                self.assertIn(path.resolve(), resolved)
        for run_name, entry in run["evidence"]["latency"].items():
            logs = [self.run_dir / path for path in entry["logs"].values()]
            with self.subTest(logs=run_name):
                self.assertTrue(all(path.resolve() in resolved for path in logs)
                                or logs[0].parent.resolve() in resolved)

    def test_format(self):
        body = self.part("Format")
        for term in ("ref_", "jwt_ref"):
            self.assertIn(term, body)
        for number in (47, 32):
            self.assertTrue(contains_number(body, number), number)
        for number in (3600, 86400):
            self.assertTrue(shows_count(body, number), number)

    def test_size_limits(self):
        body = self.part("Size limits")
        lowered = body.lower()
        for term in ("4,096", "8,192"):
            self.assertIn(term, body)
        for term in ("calculated", "derived", "moved", "probe"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertIn(Path(CLAIMS_SOURCE).parent.name, body)
        run = self.require_run()
        for row in run["plan"]:
            with self.subTest(plan=row["algorithm"]):
                self.assertTrue(any(shows_count(line, row["token_bytes"])
                                    for line in self.rows_naming(body, row["algorithm"])))
        for entry in run["limits"]["results"]:
            with self.subTest(pair=(entry["algorithm"], entry["transport"])):
                self.assertTrue(any(entry["outcome"] in line.lower()
                                    for line in self.rows_naming(body, entry["algorithm"])))
        for probe in run["probes"]:
            with self.subTest(probe=(probe["target_bytes"], probe["transport"])):
                self.assertTrue(shows_count(body, probe["token_bytes"]))
                self.assertTrue(shows_count(body, probe["bytes"]["app_received_headers"]))

    def test_reference_handling(self):
        body = self.part("Reference handling")
        rows = table_rows(body)
        for case in self.require_run()["handling"]["cases"]:
            with self.subTest(case=case["name"]):
                names = (case["name"], case["name"].replace("_", " "))
                self.assertTrue(any(any(name in row.lower() for name in names)
                                    and contains_number(row, case["status"]) for row in rows))

    def test_what_the_design_gives_up(self):
        body = self.part("What the design gives up")
        lowered = body.lower()
        for term in ("stateless", "offline", "unknown", "expired", "revoked", "immediate", "exp",
                     "lookup", "state", "not measured"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue("third-party" in lowered or "third party" in lowered)
        for name in ("store_unavailable", "jwt_without_store", "reference_as_jwt"):
            with self.subTest(case=name):
                self.assertTrue(name in lowered or name.replace("_", " ") in lowered)

    def test_latency(self):
        body = self.part("Latency")
        lowered = body.lower()
        for term in ("noise", "eddsa", "order", "transfer", "lookup", "verification",
                     "calculated", "not measured"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue("other handling" in lowered or "other_handling" in lowered)
        run = self.require_run()
        for row in run["latency"]["rows"]:
            key = (row["client"], row["concurrency"], row["algorithm"])
            lines = self.rows_naming(body, row["algorithm"])
            means = row["mean_ms"]
            measured = [name for name in RUNS if means[name] is not None]
            with self.subTest(row=key):
                differences = [row["difference_ms"][name]["total"]
                               for name in ("ref_memory", "ref_remote")
                               if row["difference_ms"][name] is not None]
                self.assertTrue(any(all(shows_ms(line, means[name]["total"])
                                        for name in measured)
                                    and all(shows_ms(line, value) for value in differences)
                                    for line in lines))
                for name in measured:
                    for value in (row["median_ms"][name], row["p95_ms"][name],
                                  row["throughput_rps"][name]):
                        self.assertTrue(any(shows(line, value) for line in lines), value)
            if (row["client"], row["concurrency"]) == ("direct", 1):
                for name in ("ref_memory", "ref_remote"):
                    difference = row["difference_ms"][name]
                    if difference is None:
                        continue
                    with self.subTest(components=(row["algorithm"], name)):
                        self.assertTrue(any(all(shows_ms(line, difference[component])
                                                for component in ("transfer", "other_handling",
                                                                  "lookup", "verification"))
                                            for line in lines))
        shared = [row for row in table_rows(body) if not any(name in row for name in NAMES)]
        for entry in run["latency"]["network_model"]:
            with self.subTest(model=entry["algorithm"]):
                lines = self.rows_naming(body, entry["algorithm"])
                for modeled in entry["modeled"]:
                    profile_rows = [row for row in shared if shows(row, modeled["uplink_mbps"])
                                    and shows(row, modeled["rtt_ms"])]
                    self.assertTrue(any(shows(line, modeled["saved_ms"])
                                        for line in lines + profile_rows), modeled)

    def test_reproduce(self):
        body = self.part("Reproduce")
        lines = [line.strip() for block in code_blocks(body) for line in block.splitlines()]
        self.assertTrue(any(line.startswith("make refs") for line in lines))
        command = re.compile(r"transport_stack\.py[\"']?\s+refs\s+--header-buffers\s+32k\s+"
                             r"--upstream-keepalive\s+64\s+--duration\s+2\s+--output-dir\s+"
                             r"[\"']?results/refs/.*-macos")
        self.assertTrue(any(command.search(line) for line in lines))
        run = self.require_run()
        committed = self.run_dir.relative_to(REPO).as_posix()
        self.assertTrue(any(re.search(r"\brefs\s+--settings\b", line)
                            and f"{committed}/refs.json" in line for line in lines))
        self.assertTrue(any(re.search(rf"\bload\s+--settings\s+[\"']?{re.escape(committed)}/"
                                      r"latency-jwt/load\.json", line) for line in lines))
        self.assertRegex(body.lower(), r"\b(\d+|one|two|three|four|five|six|seven|eight|nine|"
                                       r"ten)\s+(seconds?|minutes?)\b")
        shown = set(lines)
        for line in summary_lines(run):
            with self.subTest(line=line):
                self.assertIn(line.strip(), shown)

    def test_limitations(self):
        body = self.part("Limitations")
        lowered = body.lower()
        self.assertTrue(any("WSL2" in line and "not" in line for line in body.splitlines()))
        for term in ("loopback", "one run", "derived", "waitress", "memory", "chromium",
                     "http/1.1", "tls", "s3-04", "browser.log", "keepalive", "buffer"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue(any(term in lowered for term in ("re-verif", "again", "every request")))
        self.assertTrue(any(term in lowered for term in ("machine state", "state of the machine",
                                                         "other candidate", "idle")))


# ---- R23: TRANSPORT.md --------------------------------------------------------------------

class TransportDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(TRANSPORT_DOC)

    def section(self, text: str, title: str, level: int) -> str:
        """A section of text; fails when the heading is missing."""
        body = section(text, title, level)
        self.assertIsNotNone(body, f"missing heading: {'#' * level} {title}")
        return body

    def test_required_headings_in_order(self):
        found = [name for depth, name, _ in headings(self.text.splitlines())
                 if depth == 2 and name in TRANSPORT_HEADINGS]
        self.assertEqual(found, list(TRANSPORT_HEADINGS))

    def test_refs_command_subsection(self):
        run_check = self.section(self.text, "Run the check", 2)
        order = [name for depth, name, _ in headings(run_check.splitlines()) if depth == 3]
        self.assertIn("The cookies command", order)
        self.assertIn("The refs command", order)
        self.assertEqual(order.index("The refs command"), order.index("The cookies command") + 1)
        body = self.section(run_check, "The refs command", 3)
        commands = [line for block in code_blocks(body) for line in block.splitlines()
                    if re.search(r"transport_stack\.py[\"']?\s+refs\b", line)]
        self.assertGreaterEqual(len(commands), 3, commands)
        self.assertTrue(any(re.search(r"refs\s+--header-buffers\s+32k\s+--upstream-keepalive\s+64"
                                      r"\s+--duration\s+2\s+--output-dir", line)
                            for line in commands), commands)
        self.assertTrue(any("--settings" in line for line in commands), commands)
        lines = body.splitlines()
        for option in REFS_OPTIONS:
            with self.subTest(option=option):
                self.assertTrue(any(line.startswith("|") and option in line for line in lines))
        for option, defaults in (("--duration", (5,)), ("--warmup", (1,)), ("--timeout", (60,)),
                                 ("--concurrency", (1, 4))):
            with self.subTest(default=option):
                self.assertTrue(any(option in line and all(contains_number(line, value)
                                                           for value in defaults)
                                    for line in lines))
        for option, default in (("--output-dir", "required"), ("--settings", "none"),
                                ("--alg", "all six"), ("--claims", "oidc"),
                                ("--client", "direct"), ("--client", "browser"),
                                ("--header-buffers", "32k"), ("--upstream-keepalive", "none"),
                                ("--run-dir", "temporary")):
            with self.subTest(default=(option, default)):
                self.assertTrue(any(option in line and default in line.lower()
                                    for line in lines))
        lowered = body.lower()
        for term in ("exit 2", "exit 1", "usage", "phase", "refs.json", "limits/", "behavior/",
                     "latency-jwt/", "latency-ref-memory/", "latency-ref-remote/", "store",
                     "browser.log", "token", "reference", "run_refs(output_dir", "ref_plan",
                     "checked_settings", "default_settings", "read_saved_settings",
                     "summary_lines", "scripts/transport_refs.py",
                     "](mitigation_results.md#reference-tokens)"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_token_endpoints_document_references(self):
        body = self.section(self.text, "Token endpoints", 3)
        for term in ("/api/token/reference", "jwt_ref", "ref_cookie", "ref_bearer", "400",
                     "401", "503", "/api/token/revoke", "POST", "405", "lookup_ns"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        plain = body.replace("`", "")
        self.assertIn("other than cookie, body, or split", plain)
        self.assertNotIn("other than cookie or body", plain)

    def test_what_the_stack_provides(self):
        body = self.section(self.text, "What the stack provides", 3)
        for term in ("/api/token/reference", "/api/token/revoke", "store.log", "store"):
            with self.subTest(term=term):
                self.assertIn(term, body)

    def test_application_log_fields(self):
        body = self.section(self.text, "Application log fields", 3)
        for term in ("ref=", "store=", "store.log"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        found = committed_run()
        self.assertIsNotNone(found, "no committed macOS run under results/refs/")
        logged = set()
        for path in found[0].glob("*/logs/*.log.gz"):
            logged |= {line.strip() for line in read_gzip(path).splitlines()}
        shown = [line.strip() for block in code_blocks(body) for line in block.splitlines()
                 if "ref=" in line]
        self.assertTrue(shown, "no example line with a ref= field")
        self.assertTrue(any(line in logged for line in shown), shown)

    def test_upstream_keepalive_bullet(self):
        body = self.section(self.text, "Configuration that is not a default", 3)
        bullets = [line for line in body.splitlines()
                   if line.startswith("- ") and "--upstream-keepalive" in line]
        self.assertTrue(bullets)
        for term in ("refs", "cookies", "claims", "--proxy-buffers", "--header-buffers"):
            with self.subTest(term=term):
                self.assertTrue(any(term in line for line in bullets), bullets)

    def test_stack_table_unchanged(self):
        before = git_show("TRANSPORT.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")

        def stack_table(text: str) -> list[str]:
            body = section(text, "Stack") or ""
            first = next((index for depth, _, index in headings(body.splitlines())
                          if depth == 3), None)
            return table_rows("\n".join(body.splitlines()[:first]))

        self.assertEqual(stack_table(self.text), stack_table(before))
        self.assertTrue(stack_table(before))


# ---- R24: PROGRESS.md, README.md, TRANSPORT_RESULTS.md ------------------------------------

class ProgressTests(unittest.TestCase):
    def test_s3_02_items_and_status(self):
        body = section(PROGRESS.read_text(encoding="utf-8"), "S3-02", level=3)
        self.assertIsNotNone(body, "missing heading: ### S3-02")
        items = re.findall(r"(?m)^- \[( |x)\] (.*)$", body)
        self.assertEqual([text for _, text in items], list(S3_02_ITEMS))
        self.assertEqual([mark for mark, _ in items], ["x", "x", "x"])
        status = [line for line in body.splitlines() if line.startswith("**Status:**")]
        self.assertEqual(len(status), 1, status)
        for term in ("claims", "cookies", "macOS", "MITIGATION_RESULTS.md", "ML-DSA-44", "WSL2",
                     "641", "refs", "make refs", "MITIGATION_RESULTS.md#reference-tokens",
                     "UTC"):
            with self.subTest(term=term):
                self.assertIn(term, status[0])
        lowered = status[0].lower()
        for term in ("cookie splitting", "reference token", "not"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_other_sections_and_done_when_lines_unchanged(self):
        before = git_show("PROGRESS.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        after = PROGRESS.read_text(encoding="utf-8")

        def done_when(text: str) -> list[str]:
            return [line for line in text.splitlines() if line.startswith("**Done when:**")]
        self.assertEqual(done_when(after), done_when(before))
        # Later Sprint 3 items (S3-03, S3-04) update their own sections, so only the text
        # before S3-02 stays frozen.
        self.assertEqual(after.split("\n### S3-02", 1)[0], before.split("\n### S3-02", 1)[0])
        old, new = section(before, "S3-02", 3), section(after, "S3-02", 3)
        changed = [line for line in new.splitlines() if line not in old.splitlines()]
        self.assertTrue(all(line.startswith(("**Status:**", "- [x] Reference tokens:"))
                            for line in changed), changed)


class ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = README.read_text(encoding="utf-8")

    def test_project_status(self):
        status = section(self.text, "Project status")
        self.assertIsNotNone(status, "missing heading: ## Project status")
        self.assertNotIn("Reference tokens follow there in a later run.", status)
        self.assertNotIn("Cookie splitting and reference tokens follow", status)
        lowered = status.lower()
        self.assertIn("smaller claim sets", lowered)
        self.assertIn("reference token", lowered)
        self.assertIn("MITIGATION_RESULTS.md#reference-tokens", relative_links(status))
        before = git_show("README.md")
        if before is not None:
            for link in relative_links(section(before, "Project status") or ""):
                self.assertIn(link, relative_links(status))

    def test_make_shortcuts(self):
        shortcuts = section(self.text, "Make shortcuts")
        self.assertIsNotNone(shortcuts, "missing heading: ## Make shortcuts")
        lines = [line.strip() for block in code_blocks(shortcuts) for line in block.splitlines()]
        refs = [line for line in lines if line.startswith("make refs")]
        self.assertEqual(len(refs), 1, lines)
        self.assertIn("#", refs[0])
        self.assertTrue(refs[0].endswith("results/refs/<time>/"), refs[0])
        before = git_show("README.md")
        if before is not None:
            old = section(before, "Make shortcuts") or ""
            for line in (line.strip() for block in code_blocks(old)
                         for line in block.splitlines()):
                self.assertIn(line, lines)

    def test_existing_links_kept(self):
        before = git_show("README.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        links = set(relative_links(self.text))
        for link in relative_links(before):
            self.assertIn(link, links)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((REPO / link.split("#", 1)[0]).exists(), link)


# ---- R25: what stays unchanged ------------------------------------------------------------

class UnchangedTests(unittest.TestCase):
    def require(self, value):
        """value, or skip the test when BASE_COMMIT is not available."""
        if value is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return value

    def test_pinned_files_results_and_tests_unchanged(self):
        tests = self.require(git("ls-tree", "--name-only", BASE_COMMIT, "tests/")).split()
        # The claims and cookie tests were loosened later for S3-03, so they are not frozen here.
        later = {"tests/test_transport_claims.py", "tests/test_transport_cookies.py"}
        tests = [path for path in tests if path not in later]
        self.assertTrue(tests)
        # S3-04 adds HTTPS and HTTP/2 rendering and new sweep runs, so the nginx template and
        # results/transport are not frozen here; test_template_keeps_its_limits still checks
        # the template's limits.
        paths = ["transport/stack.json", "requirements.txt", "transport/requirements.txt",
                 "transport/conda-requirements.txt",
                 "transport/static/index.html", "transport/setup.sh", "fixtures",
                 "END_TO_END_RESULTS.md", "RESULTS.md", "results/load",
                 "results/claims", "results/cookies", ":(glob)results/2026110*/**", *tests]
        changed = self.require(git("diff", "--name-only", BASE_COMMIT, "--", *paths)).split()
        untracked = self.require(git("ls-files", "--others", "--exclude-standard", "--",
                                     *paths)).split()
        self.assertEqual(changed + untracked, [])

    def test_no_new_run_outside_results_refs(self):
        for directory in ("results/load", "results/claims", "results/cookies",
                          "results/transport"):
            with self.subTest(directory=directory):
                listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:{directory}"))
                on_disk = {path.name for path in (REPO / directory).iterdir() if path.is_dir()}
                if directory == "results/transport":  # S3-04 adds its HTTPS and HTTP/2 runs here.
                    self.assertLessEqual(set(listing.split()), on_disk)
                else:
                    self.assertEqual(on_disk, set(listing.split()))

    def test_template_keeps_its_limits(self):
        template = (REPO / "transport" / "nginx.conf.template").read_text(encoding="utf-8")
        self.assertIn("timer_resolution 100ms;", template)
        self.assertNotIn("Not a default", template)

    def test_transport_results_gains_links(self):
        # S3-04 adds its HTTPS and HTTP/2 results to TRANSPORT_RESULTS.md, so only the links
        # to MITIGATION_RESULTS.md are checked here.
        before = self.require(git_show("TRANSPORT_RESULTS.md")).splitlines()
        after = TRANSPORT_RESULTS.read_text(encoding="utf-8").splitlines()
        added = [line for line in after if line not in before]
        self.assertTrue(any("](MITIGATION_RESULTS.md" in line for line in added), added)

    def test_stack_module_docstring_describes_refs(self):
        text = (REPO / "scripts" / "transport_stack.py").read_text(encoding="utf-8")
        docstring = (re.match(r'\s*"""(.*?)"""', text, re.S) or [None, ""])[1]
        self.assertIn("refs", docstring)
        self.assertIn("scripts/transport_refs.py", docstring)


if __name__ == "__main__":
    unittest.main()
