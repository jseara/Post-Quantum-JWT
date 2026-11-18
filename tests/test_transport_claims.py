"""Check S3-02's smaller claim sets end to end: the issue endpoint with the essential claims, the
load command's --claims essential, run_claims and the claims command on real stacks, the
Makefile, the committed macOS run, MITIGATION_RESULTS.md, and the other docs; no timing
thresholds."""

import base64
from datetime import datetime, timedelta
import getpass
import gzip
import importlib.util
import inspect
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qsl, urlencode, urlsplit
from wsgiref.util import setup_testing_defaults

from scripts import transport_app, transport_load
from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import padded_claims, token_bytes
from scripts.transport_stack import (PROXY_MARKER, http_get, load_manifest, manifest_layers,
                                     start_stack)

try:
    from scripts import transport_claims
    CLAIMS_IMPORT_ERROR = None
except Exception as error:  # Before S3-02 is built: the tests that need it fail, not vanish.
    transport_claims, CLAIMS_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
MAKEFILE = REPO / "Makefile"
TRANSPORT_DOC = REPO / "TRANSPORT.md"
MITIGATION_DOC = REPO / "MITIGATION_RESULTS.md"
PROGRESS = REPO / "PROGRESS.md"
README = REPO / "README.md"
CLAIMS_RESULTS = REPO / "results" / "claims"
# The commit S3-02 builds on (S3-01): files that stay unchanged are compared with it.
BASE_COMMIT = "455828d0f63f8a138590a0fac32f1a83ea51c07f"
# The commit whose check, tokens, sweep, serve, and versions --help output stays byte-identical.
HELP_COMMIT = "a61cbb288d7a91707d79750c0a9fa206e7f05c24"
S3_01_RUN = REPO / "results" / "load" / "20261117T035444Z-macos"
SPRINT2_RUN = "results/transport/20261113T074114Z-wsl2"

HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
RUN_NAME = re.compile(r"\d{8}T\d{6}Z-macos")
ERROR_LINE = re.compile(r"(?m)^Error:")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
GRACE = 15.0
CLI_TIMEOUT = 600
MIB = 1024 * 1024
TIME_WAIT_LIMIT = 6_000
TIME_WAIT_GRACE = 90.0

CLAIM_SET_NAMES = ("minimal", "oidc", "essential")
COMPARED = ("oidc", "essential")
TRANSPORTS = ("cookie", "bearer")
FIXTURE_FILES = {"minimal": "fixtures/claims.json", "oidc": "fixtures/claims_oidc.json",
                 "essential": "fixtures/claims_essential.json"}
ESSENTIAL_CLAIMS = ["iss", "sub", "aud", "exp", "iat"]
PAYLOAD_BYTES = {"minimal": 63, "oidc": 618, "essential": 137}
TOKEN_BYTES = {
    "RS256": {"minimal": 464, "oidc": 1204, "essential": 563},
    "ES256": {"minimal": 208, "oidc": 948, "essential": 307},
    "EdDSA": {"minimal": 208, "oidc": 948, "essential": 307},
    "ML-DSA-44": {"minimal": 3355, "oidc": 4095, "essential": 3454},
    "SLH-DSA-SHA2-128s": {"minimal": 10613, "oidc": 11353, "essential": 10712},
    "SLH-DSA-SHA2-128f": {"minimal": 22922, "oidc": 23662, "essential": 23021},
}
FIXED_BYTES = {"RS256": 380, "ES256": 124, "EdDSA": 124, "ML-DSA-44": 3271,
               "SLH-DSA-SHA2-128s": 10529, "SLH-DSA-SHA2-128f": 22838}
SIGNATURE_BYTES = {"RS256": 256, "ES256": 64, "EdDSA": 64, "ML-DSA-44": 2420,
                   "SLH-DSA-SHA2-128s": 7856, "SLH-DSA-SHA2-128f": 17088}
BOUNDARY_NAMES = ("cookie-default", "cookie-16k", "bearer-default")
BOUNDARY_TRANSPORTS = {"cookie-default": "cookie", "cookie-16k": "cookie",
                       "bearer-default": "bearer"}
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
DEFAULT_ATTRIBUTES = "Path=/; HttpOnly; SameSite=Strict"
COMPONENTS = ("total", "transfer", "other_handling", "verification")
LIMIT_LOGS = ("app.log", "browser.log", "proxy-access.log", "proxy-error.log")
# The words a document may use for each layer judge() names.
LAYER_WORDS = {"browser": ("browser", "chromium"), "proxy": ("proxy", "nginx"),
               "app_server": ("app_server", "waitress"), "application": ("application",)}

CLAIMS_KEYS = {"schema_version", "started_utc", "finished_utc", "recorded_utc", "settings",
               "environment", "layers", "browser", "experiment_keys", "claim_sets", "sizes",
               "boundaries", "limits", "latency", "evidence"}
SETTINGS_KEYS = {"algorithms", "clients", "concurrency", "duration", "warmup", "timeout",
                 "header_buffers", "upstream_keepalive"}
LIMIT_KEYS = {"algorithm", "transport", "claims", "token_bytes", "outcome", "rejected_by",
              "verified_directly", "cookie_stored", "issue_nonce", "verify_nonce", "evidence"}
MOVED_KEYS = {"algorithm", "transport", "oidc", "essential", "moved"}
LATENCY_KEYS = {"transport", "reference", "size_controls", "runs", "rows", "network_model"}
LATENCY_ROW_KEYS = {"client", "concurrency", "algorithm", "token_bytes", "verified", "failed",
                    "throughput_rps", "median_ms", "p95_ms", "mean_ms", "difference_ms"}
LATENCY_RUNS = {"oidc": "latency-oidc/load.json", "essential": "latency-essential/load.json"}
SAVED_LOAD_FILES = {"load.json", "raw.csv.gz", "logs", "nginx.conf"}
CLAIMS_OPTIONS = ("--output-dir", "--settings", "--alg", "--client", "--concurrency",
                  "--duration", "--warmup", "--timeout", "--header-buffers",
                  "--upstream-keepalive", "--run-dir")
MITIGATION_PARTS = ("Claim sets", "Token sizes", "Size limits", "Latency", "Reproduce",
                    "Limitations")
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
    """Return scripts.transport_claims, failing the calling test when it cannot be imported."""
    if transport_claims is None:
        raise AssertionError(f"scripts/transport_claims.py cannot be imported: "
                             f"{CLAIMS_IMPORT_ERROR!r}")
    return transport_claims


def essential_fixture() -> dict:
    """fixtures/claims_essential.json, failing the calling test when it is missing."""
    path = REPO / FIXTURE_FILES["essential"]
    if not path.is_file():
        raise AssertionError(f"{FIXTURE_FILES['essential']} is missing")
    return json.loads(path.read_text(encoding="utf-8"))


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


def visible_names(directory: Path) -> set[str]:
    """A directory's entry names, without hidden ones such as Finder's .DS_Store (gitignored)."""
    return {path.name for path in Path(directory).iterdir() if not path.name.startswith(".")}


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
    """Every port of every stack a claims run started under run_dir."""
    ports = set()
    for path in Path(run_dir).glob("**/nginx.conf"):
        ports |= conf_ports(path)
    return ports


def stack_ports(run_dir: Path) -> dict[str, set[int]]:
    """The proxy and application ports of each stack of a claims run, by stack directory."""
    return {name: conf_ports(Path(run_dir) / name / "nginx" / "nginx.conf")
            for name in ("limits", "latency-oidc", "latency-essential")}


def json_body(data: bytes | None) -> dict | None:
    """A response body parsed as a JSON object, or None."""
    try:
        value = json.loads(data)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def payload_of(token: str) -> dict:
    """The unverified payload of a compact JWT."""
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def query_of(url: str) -> dict:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def issue_query(browser_log: str, nonce: str) -> dict | None:
    """The query of the issue request with this nonce, as browser.log recorded its URL."""
    for line in browser_log.splitlines():
        if nonce not in line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        url = record.get("url") if isinstance(record, dict) else None
        if isinstance(url, str) and nonce in url and ISSUE_PATH in url:
            return query_of(url)
    return None


def parse_utc(text) -> datetime:
    value = datetime.fromisoformat(text)
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{text!r} is not UTC")
    return value


# ---- what the spec says a run records ----------------------------------------------------

def expected_algorithms(selected) -> list[str]:
    """R5: the selected configurations plus ES256, in ADAPTER_LIST order; None means all six."""
    if selected is None:
        return list(NAMES)
    return [name for name in NAMES if name in selected or name == "ES256"]


def expected_size_rows(names) -> list[dict]:
    """R6's rows for these configurations, from the spec's numbers."""
    rows = []
    for name in names:
        sizes = TOKEN_BYTES[name]
        shrink = sizes["oidc"] - sizes["essential"]
        rows.append({"algorithm": name, "signature_bytes": SIGNATURE_BYTES[name],
                     "fixed_bytes": FIXED_BYTES[name], "token_bytes": dict(sizes),
                     "shrink_bytes": shrink, "shrink_percent": 100 * shrink / sizes["oidc"]})
    return rows


def sweep_largest(name: str) -> int:
    """The largest verified token of a committed Sprint 2 sweep, read from its sweep.json."""
    data = json.loads((REPO / SPRINT2_RUN / name / "sweep.json").read_text(encoding="utf-8"))
    return max(entry["largest_verified_token_bytes"] for entry in data["results"]
               if entry["largest_verified_token_bytes"] is not None)


def expected_boundaries(sizes: list[dict]) -> list[dict]:
    """R7's entries for these size rows, derived independently from the committed sweeps."""
    entries = []
    for name in BOUNDARY_NAMES:
        largest = sweep_largest(name)
        rows = []
        for row in sizes:
            fits = {claims: row["token_bytes"][claims] <= largest for claims in COMPARED}
            rows.append({"algorithm": row["algorithm"], "fits": fits,
                         "headroom_bytes": {claims: largest - row["token_bytes"][claims]
                                            for claims in COMPARED},
                         "moved": fits["oidc"] != fits["essential"]})
        entries.append({"name": name, "transport": BOUNDARY_TRANSPORTS[name],
                        "source": f"{SPRINT2_RUN}/{name}/sweep.json",
                        "largest_verified_token_bytes": largest, "rows": rows})
    return entries


def expected_limit(algorithm: str, transport: str, claims: str) -> tuple[str, str | None]:
    """R8's expected outcome and rejecting layer on a 16 KiB-page Mac at the default limits."""
    if algorithm in ("RS256", "ES256", "EdDSA"):
        return "verified", None
    if algorithm == "ML-DSA-44":
        rejected = transport == "cookie" and claims == "oidc"
        return ("rejected", "browser") if rejected else ("verified", None)
    if transport == "bearer":
        return "rejected", "proxy"
    return "rejected", "browser" if algorithm == "SLH-DSA-SHA2-128s" else "proxy"


def expected_claim_sets() -> list[dict]:
    """R11's claim_sets: each fixture's name, file, claim names in order, and payload bytes."""
    sets = []
    for name in CLAIM_SET_NAMES:
        path = REPO / FIXTURE_FILES[name]
        claims = (list(json.loads(path.read_text(encoding="utf-8"))) if path.is_file()
                  else ESSENTIAL_CLAIMS)
        sets.append({"name": name, "file": FIXTURE_FILES[name], "claims": claims,
                     "payload_bytes": PAYLOAD_BYTES[name]})
    return sets


def expected_evidence() -> dict:
    return {"limits": {"logs": {name: f"limits/logs/{name}.gz" for name in LIMIT_LOGS},
                       "nginx_conf": "limits/nginx.conf"},
            "latency": dict(LATENCY_RUNS)}


def evidence_paths(value) -> list[str]:
    """Every path string in an evidence object."""
    if isinstance(value, dict):
        return [path for item in value.values() for path in evidence_paths(item)]
    return [value]


def token_cells(load: dict) -> list[dict]:
    return [cell for cell in load["results"] if cell["variant"] == "token"]


def cell_means(cell: dict) -> dict | None:
    if cell["latency"] is None:
        return None
    return {component: cell["latency"][component]["mean_ms"] for component in COMPONENTS}


def total_statistic(cell: dict, key: str):
    return None if cell["latency"] is None else cell["latency"]["total"][key]


def expected_latency_rows(oidc: dict, essential: dict) -> list[dict]:
    """R10's rows, derived from the two saved load.json files."""
    matches = {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
               for cell in token_cells(essential)}
    rows = []
    for cell in token_cells(oidc):
        pair = {"oidc": cell,
                "essential": matches[(cell["client"], cell["concurrency"], cell["algorithm"])]}
        means = {name: cell_means(entry) for name, entry in pair.items()}
        difference = (None if any(value is None for value in means.values()) else
                      {component: means["essential"][component] - means["oidc"][component]
                       for component in COMPONENTS})
        rows.append({
            "client": cell["client"], "concurrency": cell["concurrency"],
            "algorithm": cell["algorithm"],
            **{key: {name: entry[key] for name, entry in pair.items()}
               for key in ("token_bytes", "verified", "failed", "throughput_rps")},
            "median_ms": {name: total_statistic(entry, "median_ms")
                          for name, entry in pair.items()},
            "p95_ms": {name: total_statistic(entry, "p95_ms") for name, entry in pair.items()},
            "mean_ms": means, "difference_ms": difference})
    return rows


def expected_network_model(algorithms, oidc: dict, essential: dict) -> list[dict]:
    """R10's network_model, derived from the two saved load.json files."""
    rows = {name: {row["algorithm"]: row for row in load["network_model"]["rows"]}
            for name, load in (("oidc", oidc), ("essential", essential))}
    entries = []
    for algorithm in algorithms:
        request = {name: rows[name][algorithm]["request_bytes"] for name in COMPARED}
        modeled = []
        for index, profile in enumerate(transport_load.NETWORK_PROFILES):
            transfer = {name: rows[name][algorithm]["modeled"][index]["transfer_ms"]
                        for name in COMPARED}
            modeled.append({"uplink_mbps": profile["uplink_mbps"], "rtt_ms": profile["rtt_ms"],
                            "saved_ms": transfer["oidc"] - transfer["essential"]})
        entries.append({"algorithm": algorithm, "request_bytes": request,
                        "saved_bytes": request["oidc"] - request["essential"],
                        "modeled": modeled})
    return entries


def expected_load_settings(settings: dict, claims: str) -> dict:
    """R9: the settings each latency run's load.json records."""
    return {"algorithms": settings["algorithms"], "transport": "bearer",
            "clients": settings["clients"], "claims": claims,
            "concurrency": settings["concurrency"], "duration": settings["duration"],
            "warmup": settings["warmup"], "reference": "ES256", "size_controls": False,
            "timeout": settings["timeout"], "proxy_buffers": None,
            "header_buffers": settings["header_buffers"],
            "upstream_keepalive": settings["upstream_keepalive"]}


def summary_lines(result: dict) -> list[str]:
    return module().summary_lines(result)


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


def without_section(text: str, title: str, level: int = 3) -> str:
    """The text with one section, its heading included, removed."""
    lines = text.splitlines()
    marks = headings(lines)
    for position, (depth, name, index) in enumerate(marks):
        if depth == level and (name == title or name.startswith(f"{title} ")):
            end = next((line for depth_after, _, line in marks[position + 1:]
                        if depth_after <= level), len(lines))
            return "\n".join(lines[:index] + lines[end:])
    return text


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


def shows_count(text: str, number: int) -> bool:
    """True when text shows a byte count, with thousands separators from 1,000 on."""
    number = abs(number)
    return contains_number(text, number) and (number < 1000 or f"{number:,}" in text)


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


def shows_ms(text: str, value: float) -> bool:
    """True when text shows value in ms with exactly 3 decimals."""
    for name in NAMES:
        text = text.replace(name, " ")
    for match in DISPLAYED_NUMBER.finditer(text):
        shown = match.group().replace("−", "-").replace("+", "").replace(",", "")
        if len(shown.partition(".")[2]) == 3 and abs(float(shown) - value) <= 0.0005 + 1e-9:
            return True
    return False


def committed_run() -> tuple[Path, dict] | None:
    """The newest results/claims/<YYYYMMDDTHHMMSSZ>-macos/ run recorded on macOS, or None."""
    runs = []
    for path in sorted(CLAIMS_RESULTS.glob("*/claims.json")):
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
        path = Path(directory) / "transport_app_s3_01.py"
        path.write_text(text, encoding="utf-8")
        # A name inside the scripts package, so the module does not change sys.path.
        spec = importlib.util.spec_from_file_location("scripts._transport_app_s3_01", path)
        base = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(base)
    # Sharing keys only saves key generation (tokens are masked), so module internals the
    # current application no longer has are left alone.
    for name in ("EXPERIMENT_KEYS", "EXPERIMENT_KEYS_LOCK", "TEST_PAGE"):
        if hasattr(base, name) and hasattr(transport_app, name):
            setattr(base, name, getattr(transport_app, name))
    return base


def response_token(response: SimpleNamespace) -> str | None:
    """The token an issue response delivered, in its body or its Set-Cookie header."""
    body = json_body(response.body) or {}
    if isinstance(body.get("token"), str):
        return body["token"]
    for name, value in response.headers:
        if name.lower() == "set-cookie" and value.startswith("jwt="):
            return value[len("jwt="):].split(";", 1)[0]
    return None


def normalized(response: SimpleNamespace) -> tuple:
    """A response with its token replaced by its length, so two signings compare equal."""
    token = response_token(response)

    def masked(text: str) -> str:
        return text.replace(token, f"<token of {len(token)} bytes>") if token else text
    return (response.status, [(name, masked(value)) for name, value in response.headers],
            masked(response.body.decode("utf-8")), response.log)


# ---- checks shared by every claims run ---------------------------------------------------

class ClaimsCase(unittest.TestCase):
    """Assertions shared by run_claims, the claims command, and the committed run (R5-R14)."""

    def assertUtc(self, text) -> datetime:
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

    def loads(self, output: Path) -> dict[str, dict]:
        """The two latency runs' load.json files, by claim set."""
        return {name: json.loads((output / path).read_text(encoding="utf-8"))
                for name, path in LATENCY_RUNS.items()}

    def check_top(self, result: dict, settings: dict) -> None:
        """R11: the top-level keys, times, settings, and recorded context."""
        self.assertEqual(set(result), CLAIMS_KEYS)
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
        self.assertEqual(result["layers"], manifest_layers(load_manifest()))
        self.assertIsInstance(result["browser"], dict)
        self.assertEqual(set(result["browser"]), {"version", "user_agent"})
        for value in result["browser"].values():
            self.assertTrue(isinstance(value, str) and value.strip())
        self.assertIn("HeadlessChrome", result["browser"]["user_agent"])  # R8: headless.
        self.assertIs(result["experiment_keys"], True)
        self.assertEqual(set(result["environment"]), set(transport_load.run_environment()))
        self.assertEqual(result["claim_sets"], expected_claim_sets())

    def check_sizes(self, result: dict) -> None:
        """R6, R7: sizes for the run's configurations and the derived Sprint 2 boundaries."""
        sizes = expected_size_rows(result["settings"]["algorithms"])
        self.assertJsonClose(result["sizes"], sizes, "sizes")
        self.assertJsonClose(result["boundaries"], expected_boundaries(sizes), "boundaries")

    def check_limits(self, result: dict, output: Path, layers: bool) -> None:
        """R8: one pair per configuration, transport, and claim set, judged with layers."""
        limits = result["limits"]
        self.assertEqual(set(limits), {"cookie_attributes", "results", "moved"})
        self.assertEqual(limits["cookie_attributes"], FULL_ATTRIBUTES)
        algorithms = result["settings"]["algorithms"]
        self.assertEqual([(entry["algorithm"], entry["transport"], entry["claims"])
                          for entry in limits["results"]],
                         [(name, transport, claims) for name in algorithms
                          for transport in TRANSPORTS for claims in COMPARED])
        logs = output / "limits" / "logs"
        browser_log = read_gzip(logs / "browser.log.gz")
        access_log = read_gzip(logs / "proxy-access.log.gz")
        app_log = read_gzip(logs / "app.log.gz")
        nonces, outcomes = [], {}
        for entry in limits["results"]:
            key = (entry["algorithm"], entry["transport"], entry["claims"])
            with self.subTest(pair=key):
                self.assertEqual(set(entry), LIMIT_KEYS)
                self.assertEqual(entry["token_bytes"], TOKEN_BYTES[key[0]][key[2]])
                outcome, layer = expected_limit(*key)
                self.assertEqual(entry["outcome"], outcome)
                outcomes[key] = entry["outcome"]
                evidence = entry["evidence"]
                self.assertTrue(isinstance(evidence, str) and evidence.strip())
                self.assertNotIn("eyJ", evidence)
                self.assertIsNone(TOKEN_LIKE.search(evidence), evidence)
                if outcome == "verified":
                    self.assertIsNone(entry["rejected_by"])
                else:
                    self.assertIn(entry["rejected_by"], LAYER_WORDS)
                    self.assertIn(entry["rejected_by"], evidence)
                    if layers:
                        self.assertEqual(entry["rejected_by"], layer)
                self.assertIs(entry["verified_directly"], True)
                if key[1] == "cookie":
                    self.assertIs(entry["cookie_stored"], outcome == "verified")
                else:
                    self.assertIsNone(entry["cookie_stored"])
                for name in ("issue_nonce", "verify_nonce"):
                    self.assertTrue(isinstance(entry[name], str) and entry[name])
                    self.assertIn(entry[name], browser_log, name)
                    if outcome == "verified":
                        self.assertIn(entry[name], access_log, name)
                        self.assertIn(entry[name], app_log, name)
                    nonces.append(entry[name])
                query = issue_query(browser_log, entry["issue_nonce"])
                self.assertIsNotNone(query, "browser.log has no issue request with this nonce")
                self.assertEqual(query.get("alg"), key[0])
                self.assertEqual(query.get("claims"), key[2])
                self.assertEqual(query.get("delivery"), "cookie" if key[1] == "cookie" else "body")
                if key[1] == "cookie":
                    self.assertEqual(query.get("attrs"), "full")
        self.assertEqual(len(set(nonces)), len(nonces), "nonces repeat")
        self.assertEqual([(entry["algorithm"], entry["transport"]) for entry in limits["moved"]],
                         [(name, transport) for name in algorithms for transport in TRANSPORTS])
        for entry in limits["moved"]:
            with self.subTest(moved=(entry["algorithm"], entry["transport"])):
                self.assertEqual(set(entry), MOVED_KEYS)
                for claims in COMPARED:
                    self.assertEqual(entry[claims],
                                     outcomes[(entry["algorithm"], entry["transport"], claims)])
                self.assertIs(entry["moved"], entry["oidc"] != entry["essential"])
        self.assertEqual([(entry["algorithm"], entry["transport"])
                          for entry in limits["moved"] if entry["moved"]],
                         [("ML-DSA-44", "cookie")] if "ML-DSA-44" in algorithms else [])

    def check_latency(self, result: dict, output: Path) -> None:
        """R9, R10: the two saved load runs and the comparison derived from them."""
        latency, settings = result["latency"], result["settings"]
        self.assertEqual(set(latency), LATENCY_KEYS)
        self.assertEqual((latency["transport"], latency["reference"]), ("bearer", "ES256"))
        self.assertIs(latency["size_controls"], False)
        self.assertEqual(latency["runs"], LATENCY_RUNS)
        loads = self.loads(output)
        for name, load in loads.items():
            with self.subTest(run=name):
                self.assertEqual(load["settings"], expected_load_settings(settings, name))
                self.assertTrue(load["results"])
                for cell in load["results"]:
                    self.assertEqual(cell["variant"], "token")
                    self.assertEqual(cell["claims"], name)
                    self.assertEqual(cell["token_bytes"], TOKEN_BYTES[cell["algorithm"]][name])
        expected = expected_latency_rows(loads["oidc"], loads["essential"])
        self.assertEqual(len(latency["rows"]), len(expected))
        for row, wanted in zip(latency["rows"], expected):
            with self.subTest(row=(wanted["client"], wanted["concurrency"], wanted["algorithm"])):
                self.assertEqual(set(row), LATENCY_ROW_KEYS)
                if wanted["difference_ms"] is None:  # Either form of "null" is accepted.
                    difference = row["difference_ms"]
                    self.assertTrue(difference is None or (
                        isinstance(difference, dict) and set(difference) == set(COMPONENTS)
                        and all(value is None for value in difference.values())), difference)
                    row = {**row, "difference_ms": None}
                self.assertJsonClose(row, wanted, "latency row")
        self.assertJsonClose(latency["network_model"],
                             expected_network_model(settings["algorithms"], loads["oidc"],
                                                    loads["essential"]), "network_model")

    def check_phase_order(self, result: dict, output: Path) -> None:
        """R9, R11: the oidc run, then the essential run, both inside the claims run."""
        loads = self.loads(output)
        times = [parse_utc(result["started_utc"]),
                 parse_utc(loads["oidc"]["started_utc"]),
                 parse_utc(loads["oidc"]["finished_utc"]),
                 parse_utc(loads["essential"]["started_utc"]),
                 parse_utc(loads["essential"]["finished_utc"]),
                 parse_utc(result["finished_utc"])]
        self.assertEqual(times, sorted(times))

    def check_layout(self, result: dict, output: Path) -> None:
        """R8, R9, R11: the files of a saved run and the evidence that names them."""
        self.assertEqual(result["evidence"], expected_evidence())
        for path in evidence_paths(result["evidence"]):
            self.assertFalse(Path(path).is_absolute(), path)
            self.assertTrue((output / path).is_file(), path)
        self.assertEqual(visible_names(output),
                         {"claims.json", "limits", "latency-oidc", "latency-essential"})
        self.assertEqual(visible_names(output / "limits"), {"logs", "nginx.conf"})
        self.assertEqual(visible_names(output / "limits" / "logs"),
                         {f"{name}.gz" for name in LIMIT_LOGS})
        for name, path in LATENCY_RUNS.items():
            directory = output / Path(path).parent
            with self.subTest(run=name):
                self.assertEqual(visible_names(directory), SAVED_LOAD_FILES)
                load = json.loads((directory / "load.json").read_text(encoding="utf-8"))
                logs = sorted(visible_names(directory / "logs"))
                self.assertTrue(logs)
                self.assertTrue(all(log.endswith(".log.gz") for log in logs), logs)
                self.assertEqual(load["evidence"], {
                    "raw": "raw.csv.gz",
                    "logs": {log[:-len(".gz")]: f"logs/{log}" for log in logs},
                    "nginx_conf": "nginx.conf"})
        for path in output.rglob("*.gz"):
            with self.subTest(gzip=str(path.relative_to(output))):
                self.assertEqual(path.read_bytes()[4:8], b"\0\0\0\0", "gzip mtime is not 0")
                gzip.decompress(path.read_bytes())

    def check_nginx_confs(self, result: dict, output: Path) -> None:
        """R8, R9: default limits for the limits stack; the latency stacks' own settings."""
        config = (output / "limits" / "nginx.conf").read_text(encoding="utf-8")
        self.assertNotIn("Not a default", config)
        settings = result["settings"]
        for path in LATENCY_RUNS.values():
            text = (output / Path(path).parent / "nginx.conf").read_text(encoding="utf-8")
            with self.subTest(config=path):
                if settings["header_buffers"] is not None:
                    self.assertIn(f"large_client_header_buffers 4 {settings['header_buffers']};",
                                  text)
                if settings["upstream_keepalive"] is not None:
                    self.assertIn(f"keepalive {settings['upstream_keepalive']};", text)
                self.assertNotRegex(text, r"(?m)^\s*proxy_buffers?\b")
                self.assertNotRegex(text, r"(?m)^\s*proxy_buffer_size\b")
        for path in [output / "limits" / "nginx.conf",
                     *(output / Path(run).parent / "nginx.conf" for run in LATENCY_RUNS.values())]:
            listens = re.findall(r"(?m)^\s*listen\s+(\S+?);", path.read_text(encoding="utf-8"))
            self.assertTrue(listens)
            self.assertTrue(all(value.startswith(f"{HOST}:") for value in listens), listens)

    def check_privacy(self, output: Path, every_file: bool) -> None:
        """R11 (R14): no token where none may be, no repository path, user, or host name."""
        claims_text = (output / "claims.json").read_text(encoding="utf-8")
        self.assertNotIn("eyJ", claims_text)
        for path in (str(REPO), str(REPO.resolve()), "CIS628Project"):
            self.assertNotIn(path, claims_text)
        token_free = [output / "claims.json", output / "limits" / "logs" / "app.log.gz",
                      output / "limits" / "logs" / "proxy-access.log.gz"]
        for run in LATENCY_RUNS.values():
            directory = output / Path(run).parent
            token_free += [directory / "load.json", directory / "raw.csv.gz",
                           directory / "logs" / "app.log.gz",
                           directory / "logs" / "proxy-access.log.gz"]
        for path in token_free:
            with self.subTest(file=str(path.relative_to(output))):
                text = read_gzip(path) if path.suffix == ".gz" else read_text(path)
                self.assertNotIn("eyJ", text)
        for path in output.rglob("proxy-error.log.gz"):
            for line in read_gzip(path).splitlines():
                if "eyJ" in line:
                    self.assertIn("client sent too long header line", line, str(path))
        checked = (sorted(path for path in output.rglob("*") if path.is_file()) if every_file
                   else [output / "claims.json",
                         *(output / run for run in LATENCY_RUNS.values())])
        names = private_names()
        for path in checked:
            text = read_gzip(path) if path.suffix == ".gz" else read_text(path)
            for name in names:
                self.assertNotIn(name, text, str(path.relative_to(output)))

    def check_summary(self, lines, result: dict) -> None:
        """R12: lines for every size row, moved entry, and latency row, each naming its row."""
        self.assertIsInstance(lines, list)
        names = [row["algorithm"] for row in result["sizes"]]
        for line in lines:
            self.assertIsInstance(line, str)
            self.assertTrue(any(name in line for name in names), line)
        for name in names:
            needed = (1 + sum(entry["algorithm"] == name for entry in result["limits"]["moved"])
                      + sum(row["algorithm"] == name for row in result["latency"]["rows"]))
            self.assertGreaterEqual(len([line for line in lines if name in line]), needed,
                                    lines)

    def check_saved_run(self, output: Path, settings: dict, layers: bool) -> dict:
        """Check a run saved by run_claims or the claims command in full; return claims.json."""
        result = json.loads((output / "claims.json").read_text(encoding="utf-8"))
        self.check_top(result, settings)
        self.assertEqual(result["environment"], transport_load.run_environment())
        self.check_sizes(result)
        self.check_limits(result, output, layers)
        self.check_latency(result, output)
        self.check_phase_order(result, output)
        self.check_layout(result, output)
        self.check_nginx_confs(result, output)
        self.check_privacy(output, every_file=False)
        self.check_summary(summary_lines(result), result)
        # claims.json is written last, after every phase.
        newest = max(path.stat().st_mtime_ns for path in output.rglob("*") if path.is_file())
        self.assertEqual((output / "claims.json").stat().st_mtime_ns, newest)
        return result


# ---- R3: the issue endpoint with the essential claims ------------------------------------

class IssueParityTests(unittest.TestCase):
    """In process: claims=essential is accepted wherever claims=oidc is, and every other
    response is the one S3-01's application (scripts/transport_app.py at BASE_COMMIT) gives."""

    @classmethod
    def setUpClass(cls):
        cls.base = base_application()

    def require_base(self):
        if self.base is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return self.base

    def verified_claims(self, token: str, source: str) -> dict:
        """Verify a token at the current application and return the claims it verified."""
        headers = ({"Cookie": f"jwt={token}"} if source == "cookie"
                   else {"Authorization": f"Bearer {token}"})
        response = wsgi_call(transport_app.application, f"{VERIFY_PATH}?nonce=1", headers)
        body = json_body(response.body) or {}
        self.assertEqual(response.code, 200, body)
        self.assertIs(body.get("verified"), True)
        self.assertEqual(body.get("source"), source)
        return body["claims"]

    def test_other_claim_sets_and_defaults_unchanged(self):
        base = self.require_base()
        queries = ["", "&delivery=body", "&delivery=cookie", "&claims=minimal",
                   "&claims=oidc&delivery=body", "&claims=oidc&attrs=full",
                   "&claims=minimal&pad=5", "&claims=oidc&pad=0&attrs=default&delivery=body",
                   "&pad=3&delivery=body", "&claims=oidc&pad=1234567"]
        for name in NAMES:
            for query in queries:
                target = f"{ISSUE_PATH}?alg={name}{query}&nonce=abc"
                with self.subTest(target=target):
                    current = wsgi_call(transport_app.application, target)
                    previous = wsgi_call(base.application, target)
                    self.assertEqual(normalized(current), normalized(previous))

    def test_essential_accepted_wherever_oidc_is(self):
        base = self.require_base()
        essential = essential_fixture()
        for name in NAMES:
            for delivery in ("cookie", "body"):
                for attrs in ("default", "full", "bogus"):
                    for pad in ("0", "12", "-1"):
                        query = f"alg={name}&delivery={delivery}&attrs={attrs}&pad={pad}"
                        with self.subTest(query=query):
                            current = wsgi_call(transport_app.application,
                                                f"{ISSUE_PATH}?{query}&claims=essential")
                            previous = wsgi_call(base.application,
                                                 f"{ISSUE_PATH}?{query}&claims=oidc")
                            self.assertEqual(current.code, previous.code)
                            body, before = json_body(current.body), json_body(previous.body)
                            self.assertEqual(set(body), set(before))
                            if current.code != 200:
                                continue
                            self.assertEqual(body["claims"], "essential")
                            self.assertEqual(body["pad"], int(pad))
                            if delivery == "cookie":
                                self.assertEqual(body["attrs"], attrs)
                            expected = padded_claims(essential, int(pad))
                            token = response_token(current)
                            self.assertEqual(len(token), token_bytes(name, expected))
                            self.assertEqual(body["token_bytes"], len(token))
                            self.assertEqual(payload_of(token), expected)
                            for source in TRANSPORTS:
                                self.assertEqual(self.verified_claims(token, source), expected)

    def test_unknown_claim_sets_get_400(self):
        base = self.require_base()
        for value in ("large", "huge", "Essential", "", "essentials"):
            for delivery in ("cookie", "body"):
                target = f"{ISSUE_PATH}?alg=ES256&delivery={delivery}&claims={value}&nonce=abc"
                with self.subTest(target=target):
                    current = wsgi_call(transport_app.application, target)
                    previous = wsgi_call(base.application, target)
                    self.assertEqual(current.code, 400)
                    body, before = json_body(current.body), json_body(previous.body)
                    self.assertEqual(set(body), set(before))
                    self.assertEqual(body["layer"], "application")
                    self.assertIs(body["experiment_key"], True)
                    for name in CLAIM_SET_NAMES:
                        self.assertIn(name, body["error"])
                    self.assertFalse(any(name.lower() == "set-cookie"
                                         for name, _ in current.headers))
                    self.assertEqual(current.log, previous.log)


class IssueEndpointTests(unittest.TestCase):
    """Through a real stack: essential tokens issued through nginx verify from both carriers."""

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.stack = cls.enterClassContext(start_stack(run_dir=cls.directory / "run"))
        cls.logs = Path(cls.stack.run_dir) / "logs"

    def get(self, base: str, path: str, headers: dict | None = None,
            **query: str) -> tuple[int, dict, dict | None]:
        url = f"{base}{path}?{urlencode({**query, 'nonce': secrets.token_hex(16)})}"
        status, response_headers, body = http_get(url, headers=headers, timeout=60)
        return status, response_headers, json_body(body)

    def verify(self, base: str, token: str, source: str, expected: dict, algorithm: str) -> None:
        headers = ({"Cookie": f"jwt={token}"} if source == "cookie"
                   else {"Authorization": f"Bearer {token}"})
        status, response_headers, body = self.get(base, VERIFY_PATH, headers)
        self.assertEqual(status, 200, body)
        if base == self.stack.proxy_url:
            self.assertIn(PROXY_MARKER.lower(), response_headers)
        self.assertIs(body["verified"], True)
        self.assertEqual((body["algorithm"], body["source"]), (algorithm, source))
        self.assertEqual(body["claims"], expected)

    def issue(self, base: str, algorithm: str, delivery: str, **query: str) -> tuple[str, dict]:
        status, headers, body = self.get(base, ISSUE_PATH, alg=algorithm, delivery=delivery,
                                         claims="essential", **query)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["claims"], "essential")
        self.assertEqual(body["pad"], int(query.get("pad", "0")))
        if delivery == "body":
            self.assertNotIn("set-cookie", headers)
            token = body["token"]
        else:
            attributes = FULL_ATTRIBUTES if query.get("attrs") == "full" else DEFAULT_ATTRIBUTES
            self.assertEqual(body["attrs"], query.get("attrs", "default"))
            self.assertNotIn("token", body)
            cookie = headers["set-cookie"]
            self.assertTrue(cookie.startswith("jwt="), cookie)
            self.assertTrue(cookie.endswith(f"; {attributes}"), cookie)
            token = cookie[len("jwt="):-len(f"; {attributes}")]
        self.assertEqual(body["token_bytes"], len(token))
        return token, body

    def test_essential_tokens_through_the_proxy(self):
        essential = essential_fixture()
        for name in ("RS256", "ES256", "EdDSA", "ML-DSA-44"):
            for delivery, query in (("body", {}), ("cookie", {"attrs": "full"}),
                                    ("cookie", {"attrs": "default"})):
                with self.subTest(algorithm=name, delivery=delivery, **query):
                    token, _ = self.issue(self.stack.proxy_url, name, delivery, **query)
                    self.assertEqual(len(token), TOKEN_BYTES[name]["essential"])
                    self.assertEqual(payload_of(token), essential)
                    for source in TRANSPORTS:
                        self.verify(self.stack.proxy_url, token, source, essential, name)

    def test_slh_dsa_essential_tokens_at_the_application(self):
        essential = essential_fixture()
        for name in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"):
            for delivery, query in (("body", {}), ("cookie", {"attrs": "full"})):
                with self.subTest(algorithm=name, delivery=delivery):
                    token, _ = self.issue(self.stack.app_url, name, delivery, **query)
                    self.assertEqual(len(token), TOKEN_BYTES[name]["essential"])
                    for source in TRANSPORTS:
                        self.verify(self.stack.app_url, token, source, essential, name)

    def test_padded_essential_tokens(self):
        essential = essential_fixture()
        for name in ("ES256", "ML-DSA-44"):
            with self.subTest(algorithm=name):
                token, _ = self.issue(self.stack.proxy_url, name, "body", pad="25")
                expected = padded_claims(essential, 25)
                self.assertEqual(len(token), token_bytes(name, expected))
                self.verify(self.stack.proxy_url, token, "bearer", expected, name)

    def test_unknown_claim_sets_get_400_through_the_proxy(self):
        for value in ("large", "huge", "Essential"):
            with self.subTest(claims=value):
                status, headers, body = self.get(self.stack.proxy_url, ISSUE_PATH, alg="ES256",
                                                 claims=value)
                self.assertEqual(status, 400)
                self.assertIn(PROXY_MARKER.lower(), headers)
                self.assertNotIn("set-cookie", headers)
                self.assertEqual(body["layer"], "application")
                for name in CLAIM_SET_NAMES:
                    self.assertIn(name, body["error"])

    def test_logs_hold_no_token(self):
        token, _ = self.issue(self.stack.proxy_url, "ML-DSA-44", "body")
        self.verify(self.stack.proxy_url, token, "bearer", essential_fixture(), "ML-DSA-44")
        for name in ("app.log", "proxy-access.log"):
            log = self.logs / name
            self.assertTrue(eventually(lambda log=log: VERIFY_PATH in read_text(log)), name)
            self.assertNotIn("eyJ", read_text(log), name)


# ---- R4: the load command accepts the essential claims; other commands are frozen ---------

class LoadCommandTests(unittest.TestCase):
    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44"], "transport": "bearer",
                "clients": ["direct"], "claims": "essential", "concurrency": [1],
                "duration": 0.2, "warmup": 0.0, "reference": "ES256", "size_controls": False,
                "timeout": 30.0, "proxy_buffers": None, "header_buffers": "32k",
                "upstream_keepalive": 8}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        wait_for_ephemeral_ports()
        cls.ports, cls.output = free_ports(2), cls.directory / "essential"
        cls.first = run_cli("load", "--claims", "essential", "--alg", "ML-DSA-44", "--client",
                            "direct", "--concurrency", "1", "--duration", "0.2", "--warmup", "0",
                            "--no-size-controls", "--header-buffers", "32k",
                            "--upstream-keepalive", "8", "--timeout", "30",
                            *port_options(cls.ports), "--run-dir", cls.directory / "run",
                            "--output-dir", cls.output, cwd=cls.directory)

    def check_saved(self, output: Path) -> dict:
        saved = json.loads((output / "load.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["settings"], self.SETTINGS)
        self.assertTrue(saved["results"])
        for cell in saved["results"]:
            with self.subTest(algorithm=cell["algorithm"]):
                self.assertEqual(cell["claims"], "essential")
                self.assertEqual(cell["token_bytes"], TOKEN_BYTES[cell["algorithm"]]["essential"])
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)
        return saved

    def test_claims_essential_runs(self):
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        self.check_saved(self.output)
        self.assertIn(f"Saved the results to {self.output}", self.first.stdout)
        for port in self.ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_settings_with_essential_claims_are_accepted(self):
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        wait_for_ephemeral_ports()
        output, ports = self.directory / "again", free_ports(2)
        result = run_cli("load", "--settings", self.output / "load.json", *port_options(ports),
                         "--run-dir", self.directory / "again-run", "--output-dir", output,
                         cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_saved(output)

    def test_help_lists_essential(self):
        result = run_cli("load", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        choices = re.search(r"--claims \{([a-z,]+)\}", result.stdout)
        self.assertIsNotNone(choices, result.stdout)
        self.assertEqual(set(choices[1].split(",")), set(CLAIM_SET_NAMES))

    def test_unknown_claims_exit_2_before_any_process_starts(self):
        for command in ("load", "sweep"):
            for value in (("large", "essential") if command == "sweep" else ("large", "huge")):
                with self.subTest(command=command, claims=value):
                    ports, run_dir = free_ports(2), self.directory / f"usage-{command}-{value}"
                    output = self.directory / f"usage-out-{command}-{value}"
                    extra = ["--output-dir", output] if command == "load" else []
                    result = run_cli(command, "--claims", value, *extra, *port_options(ports),
                                     "--run-dir", run_dir, cwd=self.directory)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("usage:", result.stderr)
                    self.assertFalse(run_dir.exists(), "a stack was started")
                    self.assertFalse(output.exists())
                    for port in ports:
                        self.assertFalse(accepts(port))

    def test_other_commands_keep_their_help(self):
        archive = None
        try:
            archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar",
                                      HELP_COMMIT, "scripts", "transport", "fixtures"],
                                     capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest(f"{HELP_COMMIT} is not available in this checkout")
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
                    self.assertEqual(outputs[1], outputs[0])


# ---- R5, R8-R11: run_claims on real stacks ------------------------------------------------

class RunClaimsTests(ClaimsCase):
    """One short run of run_claims: ML-DSA-44 (ES256 is added), the direct client only."""

    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44"], "clients": ["direct"], "concurrency": [1],
                "duration": 0.2, "warmup": 0.0, "timeout": 60.0, "header_buffers": "32k",
                "upstream_keepalive": 8}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.output = cls.directory / "out" / "claims"  # Created by run_claims.
        cls.run_dir = cls.directory / "run"
        cls.result, cls.error = None, None
        if transport_claims is None:
            return
        wait_for_ephemeral_ports()
        try:
            cls.result = transport_claims.run_claims(
                cls.output, algorithms=["ML-DSA-44"], clients=["direct"], concurrency=[1],
                duration=0.2, warmup=0.0, header_buffers="32k", upstream_keepalive=8,
                run_dir=cls.run_dir)
        except Exception as error:  # Reported by every test instead of failing setUpClass.
            cls.error = error

    def setUp(self):
        module()
        self.assertIsNone(self.error, f"run_claims raised {self.error!r}")

    def test_saved_run(self):
        self.check_saved_run(self.output, self.SETTINGS, layers=PAGE_SIZE == 16384)

    def test_returns_what_it_saved(self):
        saved = json.loads((self.output / "claims.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json.dumps(self.result)), saved)

    def test_settings_repeat_the_run(self):
        bound = inspect.signature(module().run_claims).bind(self.directory / "new",
                                                            **self.result["settings"])
        self.assertEqual(set(bound.arguments), {"output_dir", *SETTINGS_KEYS})

    def test_stack_run_directories(self):
        for name in ("limits", "latency-oidc", "latency-essential"):
            with self.subTest(stack=name):
                self.assertTrue((self.run_dir / name / "nginx" / "nginx.conf").is_file())
                self.assertTrue((self.run_dir / name / "logs" / "app.log").is_file())
        logs = self.run_dir / "limits" / "logs"
        for name in LIMIT_LOGS:
            with self.subTest(log=name):
                saved = read_gzip(self.output / "limits" / "logs" / f"{name}.gz")
                self.assertTrue(read_text(logs / name).startswith(saved))
        self.assertEqual((self.output / "limits" / "nginx.conf").read_bytes(),
                         (self.run_dir / "limits" / "nginx" / "nginx.conf").read_bytes())
        for name in LATENCY_RUNS:
            self.assertEqual((self.output / f"latency-{name}" / "nginx.conf").read_bytes(),
                             (self.run_dir / f"latency-{name}" / "nginx" / "nginx.conf")
                             .read_bytes())

    def test_every_process_stopped(self):
        for name, ports in stack_ports(self.run_dir).items():
            with self.subTest(stack=name):
                self.assertEqual(len(ports), 2, ports)  # The proxy and the application.
                for port in ports:
                    self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_each_stack_stopped_before_the_next_started(self):
        # R9: nginx logs its start and, when stopped, its exit, so the error logs of stacks that
        # ran one after another never overlap (to the second nginx logs).
        stacks = ("limits", "latency-oidc", "latency-essential")
        times = {name: nginx_times(self.run_dir / name / "logs" / "proxy-error.log")
                 for name in stacks}
        for index, first in enumerate(stacks):
            for second in stacks[index + 1:]:
                with self.subTest(stacks=(first, second)):
                    self.assertTrue(times[first] and times[second], times)
                    self.assertTrue(max(times[first]) <= min(times[second])
                                    or max(times[second]) <= min(times[first]),
                                    {name: (min(times[name]), max(times[name]))
                                     for name in (first, second)})

    def test_run_logs_hold_no_token(self):
        for name in ("limits", "latency-oidc", "latency-essential"):
            for log in ("app.log", "proxy-access.log"):
                with self.subTest(stack=name, log=log):
                    self.assertNotIn("eyJ", read_text(self.run_dir / name / "logs" / log))

    def test_summary_lines_from_the_saved_json(self):
        saved = json.loads((self.output / "claims.json").read_text(encoding="utf-8"))
        lines = summary_lines(saved)
        self.check_summary(lines, saved)
        self.assertEqual(lines, summary_lines(self.result))


# ---- R12: the claims command ---------------------------------------------------------------

class ClaimsCommandTests(ClaimsCase):
    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44"], "clients": ["direct"], "concurrency": [1],
                "duration": 0.2, "warmup": 0.0, "timeout": 60.0, "header_buffers": "32k",
                "upstream_keepalive": 8}
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
        cls.first = run_cli("claims", "--alg", "ML-DSA-44", "--client", "direct",
                            "--concurrency", "1", "--duration", "0.2", "--warmup", "0",
                            "--header-buffers", "32k", "--upstream-keepalive", "8",
                            "--run-dir", cls.run_dir, "--output-dir", cls.output,
                            cwd=cls.directory)

    def require_first_run(self) -> None:
        self.assertEqual(self.first.returncode, 0, self.first.stderr)

    def check_stopped(self, run_dir: Path) -> None:
        for port in run_ports(run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_first_run_exits_0_with_rejected_pairs(self):
        self.require_first_run()
        saved = self.check_saved_run(self.output, self.SETTINGS, layers=PAGE_SIZE == 16384)
        self.assertIn("rejected", [entry["outcome"] for entry in saved["limits"]["results"]])

    def test_prints_the_summary_then_the_output_directory(self):
        self.require_first_run()
        saved = json.loads((self.output / "claims.json").read_text(encoding="utf-8"))
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
        for name, ports in stack_ports(self.run_dir).items():
            self.assertEqual(len(ports), 2, f"{name}: {ports}")
        self.check_stopped(self.run_dir)

    def test_settings_reuse_the_saved_run_with_overrides(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        output, run_dir = self.directory / "reuse" / "nested", self.directory / "reuse-run"
        result = run_cli("claims", "--settings", self.output / "claims.json", "--alg", "ES256",
                         "--warmup", "0.1", "--timeout", "30", "--run-dir", run_dir,
                         "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = {**self.SETTINGS, "algorithms": ["ES256"], "warmup": 0.1, "timeout": 30.0}
        self.check_saved_run(output, settings, layers=PAGE_SIZE == 16384)
        self.check_stopped(run_dir)

    def test_saved_latency_settings_repeat_with_load(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        saved = json.loads((self.output / "latency-essential" / "load.json")
                           .read_text(encoding="utf-8"))
        output = self.directory / "load-again"
        result = run_cli("load", "--settings", self.output / "latency-essential" / "load.json",
                         "--run-dir", self.directory / "load-again-run", "--output-dir", output,
                         cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        again = json.loads((output / "load.json").read_text(encoding="utf-8"))
        self.assertEqual(again["settings"], saved["settings"])
        self.assertEqual(again["settings"]["claims"], "essential")

    def test_help_lists_every_option(self):
        result = run_cli("claims", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in CLAIMS_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)

    def test_usage_errors_exit_2_before_anything_starts(self):
        # Without the claims command, argparse would reject every case for the wrong reason.
        self.assertEqual(run_cli("claims", "--help", cwd=self.directory).returncode, 0)
        bad = self.directory / "bad-settings"
        bad.mkdir()
        valid = {"algorithms": ["ES256"], "clients": ["direct"], "concurrency": [1],
                 "duration": 0.1, "warmup": 0.0, "timeout": 30.0, "header_buffers": "32k",
                 "upstream_keepalive": 8}
        files = {
            "not-json.json": "{not json",
            "no-settings.json": json.dumps({"results": []}),
            "list-settings.json": json.dumps({"settings": [1]}),
            "unknown-key.json": json.dumps({"settings": {**valid, "transport": "bearer"}}),
            "bad-concurrency.json": json.dumps({"settings": {**valid, "concurrency": [0]}}),
            "bad-alg.json": json.dumps({"settings": {**valid, "algorithms": ["HS256"]}}),
            "bad-duration.json": json.dumps({"settings": {**valid, "duration": 0}}),
            "bad-buffers.json": json.dumps({"settings": {**valid, "header_buffers": "big"}}),
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
            "concurrency 0": ["--concurrency", "0", "--output-dir", "{out}"],
            "concurrency 65": ["--concurrency", "65", "--output-dir", "{out}"],
            "zero duration": ["--duration", "0", "--output-dir", "{out}"],
            "negative duration": ["--duration=-1", "--output-dir", "{out}"],
            "negative warmup": ["--warmup=-0.5", "--output-dir", "{out}"],
            "invalid header buffers": ["--header-buffers", "big", "--output-dir", "{out}"],
            "keepalive 0": ["--upstream-keepalive", "0", "--output-dir", "{out}"],
            "keepalive 1025": ["--upstream-keepalive", "1025", "--output-dir", "{out}"],
            "missing settings": ["--settings", bad / "missing.json", "--output-dir", "{out}"],
            **{f"settings {name}": ["--settings", bad / name, "--output-dir", "{out}"]
               for name in files},
        }
        if (S3_01_RUN / "load.json").is_file():  # A load.json has settings claims does not take.
            cases["settings from load.json"] = ["--settings", S3_01_RUN / "load.json",
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
                result = run_cli("claims", *arguments, "--run-dir", run_dir, cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(run_dir.exists(), "a stack was started")
                self.assertFalse(output.exists(), "the output directory was created")
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
        self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_runtime_failure_exits_1_and_stops_every_process(self):
        run_dir, output = self.directory / "failing-run", self.directory / "failing"
        with tempfile.TemporaryDirectory() as empty:
            result = run_cli("claims", "--alg", "ES256", "--client", "direct", "--concurrency",
                             "1", "--duration", "0.1", "--warmup", "0", "--timeout", "30",
                             "--run-dir", run_dir, "--output-dir", output, cwd=self.directory,
                             environment=cli_environment(PLAYWRIGHT_BROWSERS_PATH=empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        self.assertFalse((output / "claims.json").exists())
        self.check_stopped(run_dir)

    def test_signals_stop_the_run_and_every_process(self):
        # SIGINT while the limits phase sends its pairs, SIGTERM during a latency run.
        for signum, stack, marker in ((signal.SIGINT, "limits", ISSUE_PATH),
                                      (signal.SIGTERM, "latency-oidc", "timing=1")):
            with self.subTest(signal=signum.name):
                wait_for_ephemeral_ports()
                run_dir = self.directory / f"signal-{signum.name}"
                output = self.directory / f"signal-out-{signum.name}"
                command = [sys.executable, str(SCRIPT), "claims", "--alg", "ES256", "--client",
                           "direct", "--concurrency", "1", "--duration", "20", "--warmup", "0",
                           "--run-dir", str(run_dir), "--output-dir", str(output)]
                process = subprocess.Popen(command, cwd=self.directory, env=cli_environment(),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    log = run_dir / stack / "logs" / "proxy-access.log"
                    eventually(lambda: process.poll() is not None or marker in read_text(log),
                               grace=180)
                    self.assertIsNone(process.poll(), "the run ended before the signal")
                    process.send_signal(signum)
                    _, stderr = process.communicate(timeout=120)
                finally:
                    stop(process)
                self.assertEqual(process.returncode, 1, stderr)
                self.assertRegex(stderr, ERROR_LINE)
                self.assertFalse((output / "claims.json").exists())
                self.assertTrue(run_ports(run_dir))
                self.check_stopped(run_dir)
                if stack.startswith("latency"):
                    # R12: --header-buffers and --upstream-keepalive default to None, as
                    # run_claims's do, so the latency stack keeps nginx's defaults.
                    config = read_text(run_dir / stack / "nginx" / "nginx.conf")
                    self.assertIn("listen", config)
                    self.assertNotIn("Not a default", config)


# ---- R13: Makefile ------------------------------------------------------------------------

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


class MakefileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MAKEFILE.read_text(encoding="utf-8")

    def make(self, *arguments: str) -> subprocess.CompletedProcess:
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not installed")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MAKEFLAGS", "MFLAGS", "LOAD_DIR", "CLAIMS_DIR")}
        return subprocess.run([make, "--no-print-directory", *arguments], cwd=REPO,
                              env=environment, capture_output=True, text=True, timeout=60)

    def test_target_is_phony_and_in_help(self):
        phony = next((line for line in self.text.splitlines() if line.startswith(".PHONY:")), "")
        self.assertIn("claims", phony.split())
        result = self.make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(line.startswith("make claims") for line in result.stdout.splitlines()),
                        result.stdout)

    def test_recipe_and_output_directory(self):
        self.assertRegex(self.text, r"(?m)^CLAIMS_DIR \?= results/claims/"
                                    r"\$\(shell date -u \+%Y%m%dT%H%M%SZ\)-\$\(LOAD_PLATFORM\)"
                                    r"[ \t]*$")
        self.assertRegex(self.text, r'(?m)^claims:.*\n(?:\t.*\n)*?\t\$\(STACK\) claims '
                                    r'--header-buffers 32k --upstream-keepalive 64 --duration 2 '
                                    r'--output-dir "\$\(CLAIMS_DIR\)"[ \t]*$')
        result = self.make("-n", "claims", "CLAIMS_DIR=results/claims/dry-run", "PYTHON=python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/transport_stack.py claims --header-buffers 32k '
                      '--upstream-keepalive 64 --duration 2 --output-dir '
                      '"results/claims/dry-run"', result.stdout)
        if sys.platform == "darwin":
            result = self.make("-n", "claims", "PYTHON=python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'--output-dir "results/claims/\d{8}T\d{6}Z-macos"')

    def test_existing_targets_unchanged(self):
        before = git_show("Makefile")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        old, new = make_blocks(before), make_blocks(self.text)
        for target, lines in old.items():
            with self.subTest(target=target):
                self.assertIn(target, new)
                if target == "help":  # help gains the claims line.
                    for line in lines[1:]:
                        self.assertIn(line, new[target])
                else:
                    self.assertEqual(new[target], lines)
        assignments = [line for line in before.splitlines()
                       if re.match(r"^[A-Z_]+ *(\?|:)?=", line)]
        self.assertTrue(any(line.startswith("LOAD_DIR ") for line in assignments))
        for line in assignments:
            with self.subTest(line=line):
                self.assertIn(line, self.text.splitlines())


# ---- R14: the committed run --------------------------------------------------------------

class CommittedRunTests(ClaimsCase):
    SETTINGS = {"algorithms": NAMES, "clients": ["direct", "browser"], "concurrency": [1, 4],
                "duration": 2.0, "warmup": 1.0, "timeout": 60.0, "header_buffers": "32k",
                "upstream_keepalive": 64}

    @classmethod
    def setUpClass(cls):
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def setUp(self):
        self.assertIsNotNone(self.saved, "no macOS run committed under "
                                         "results/claims/<YYYYMMDDTHHMMSSZ>-macos/")

    def test_environment(self):
        environment = self.saved["environment"]
        self.assertTrue(environment["platform"].startswith("macOS"))
        self.assertEqual(environment["page_size_bytes"], 16384)
        self.assertRegex(str(environment["git_commit"]), HEX_COMMIT)
        self.assertEqual(len(environment["git_commit"]), 40)
        self.assertIs(environment["git_dirty_scripts_or_fixtures"], False)

    def test_settings_and_structure(self):
        self.check_top(self.saved, self.SETTINGS)
        self.check_sizes(self.saved)

    def test_limits_match_this_mac(self):
        self.check_limits(self.saved, self.run_dir, layers=True)

    def test_latency_every_token_cell_verified(self):
        self.check_latency(self.saved, self.run_dir)
        self.check_phase_order(self.saved, self.run_dir)
        for row in self.saved["latency"]["rows"]:
            with self.subTest(row=(row["client"], row["concurrency"], row["algorithm"])):
                for claims in COMPARED:
                    self.assertGreater(row["verified"][claims], 0)
                    self.assertEqual(row["failed"][claims], 0)
        for name, load in self.loads(self.run_dir).items():
            for cell in token_cells(load):
                with self.subTest(run=name, cell=(cell["client"], cell["concurrency"],
                                                  cell["algorithm"])):
                    self.assertGreater(cell["verified"], 0)
                    self.assertEqual(cell["failed"], 0)

    def test_files_and_nginx_confs(self):
        self.check_layout(self.saved, self.run_dir)
        self.check_nginx_confs(self.saved, self.run_dir)
        for path in self.run_dir.rglob("*"):
            if path.is_file():
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertLessEqual(path.stat().st_size, 10 * MIB)
                    self.assertFalse(path.name.endswith(".log"))
        tracked = git("ls-files", "-z", "--", "results/claims")
        for path in (tracked or "").split("\0"):
            self.assertFalse(path.endswith(".log"), path)

    def test_privacy(self):
        self.check_privacy(self.run_dir, every_file=True)

    def test_summary_lines(self):
        self.check_summary(summary_lines(self.saved), self.saved)


# ---- R15: MITIGATION_RESULTS.md ----------------------------------------------------------

class MitigationDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(MITIGATION_DOC)
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def require_run(self) -> dict:
        self.assertIsNotNone(self.saved, "no committed macOS run under results/claims/")
        return self.saved

    def body(self) -> str:
        self.assertTrue(MITIGATION_DOC.is_file(), "MITIGATION_RESULTS.md is missing")
        body = section(self.text, "Smaller claim sets")
        self.assertIsNotNone(body, "missing heading: ## Smaller claim sets")
        return body

    def part(self, title: str) -> str:
        body = section(self.body(), title, level=3)
        self.assertIsNotNone(body, f"missing heading: ### {title}")
        return body

    def rows_naming(self, body: str, name: str) -> list[str]:
        return [row for row in table_rows(body) if name in row]

    def test_headings_in_order(self):
        found = []
        for depth, name, _ in headings(self.body().splitlines()):
            match = next((title for title in MITIGATION_PARTS
                          if name == title or name.startswith(f"{title} ")), None)
            if depth == 3 and match:
                found.append(match)
        self.assertEqual(found, list(MITIGATION_PARTS))

    def test_introduction(self):
        body = self.body()
        first = next((index for depth, _, index in headings(body.splitlines()) if depth == 3),
                     None)
        intro = (self.text.split("## Smaller claim sets", 1)[0] + "\n"
                 + "\n".join(body.splitlines()[:first]))
        self.assertIn("S3-02", intro)
        self.assertIn("first", intro.lower())
        lowered = [line.lower() for line in self.text.splitlines()]
        for name in ("cookie splitting", "reference token"):
            with self.subTest(mitigation=name):
                self.assertTrue(any(name in line for line in intro.lower().splitlines()))
                self.assertTrue(any(name in line and "not" in line for line in lowered))
        text = self.text.lower()
        for term in ("ephemeral", "experiment key", "production"):
            self.assertIn(term, text)

    def test_names_the_machine_date_and_commit(self):
        run = self.require_run()
        self.assertIn("macOS", self.text)
        self.assertIn(run["environment"]["git_commit"][:7], self.text)
        started = parse_utc(run["started_utc"])
        # The local date may differ from the UTC one by a day.
        days = {(started + timedelta(hours=offset)).date() for offset in (-14, 0, 14)}
        dates = [form for day in days for form in
                 (day.isoformat(), f"{day:%B} {day.day}, {day.year}",
                  f"{day.day} {day:%B} {day.year}", f"{day:%b} {day.day}, {day.year}")]
        self.assertTrue(any(date in self.text for date in dates), dates)

    def test_links_resolve_and_reach_the_run(self):
        links = relative_links(self.text)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((REPO / link.split("#", 1)[0]).exists(), link)
        self.require_run()
        resolved = {(REPO / link.split("#", 1)[0]).resolve() for link in links}
        wanted = [self.run_dir / "claims.json", self.run_dir / "limits" / "nginx.conf",
                  *(self.run_dir / "limits" / "logs" / f"{name}.gz" for name in LIMIT_LOGS),
                  *(REPO / SPRINT2_RUN / name / "sweep.json" for name in BOUNDARY_NAMES)]
        for name in COMPARED:
            wanted += [self.run_dir / f"latency-{name}" / "load.json",
                       self.run_dir / f"latency-{name}" / "raw.csv.gz"]
        for path in wanted:
            with self.subTest(target=str(path.relative_to(REPO))):
                self.assertIn(path.resolve(), resolved)

    def test_claim_sets(self):
        body = self.part("Claim sets")
        for name in ESSENTIAL_CLAIMS:
            self.assertRegex(body, rf"\b{name}\b")
        for number in (17, 22, 618, 137):
            self.assertTrue(contains_number(body, number), number)
        lowered = body.lower()
        self.assertTrue("openid connect core" in lowered or "oidc core" in lowered)
        self.assertIn("required", lowered)
        for term in ("userinfo", "session", "not measured"):
            self.assertIn(term, lowered)

    def test_token_sizes(self):
        body = self.part("Token sizes")
        for row in self.require_run()["sizes"]:
            with self.subTest(algorithm=row["algorithm"]):
                values = [*row["token_bytes"].values(), row["fixed_bytes"], row["shrink_bytes"]]
                self.assertTrue(any(all(shows_count(line, value) for value in values)
                                    and f"{row['shrink_percent']:.1f}" in line
                                    for line in self.rows_naming(body, row["algorithm"])))
        lowered = body.lower()
        self.assertTrue(contains_number(body, 641))
        self.assertIn("header", lowered)
        self.assertIn("signature", lowered)

    def test_size_limits(self):
        body = self.part("Size limits")
        lowered = body.lower()
        for term in ("derived", "wsl2", "moved", "bearer", "fixed"):
            self.assertIn(term, lowered)
        for name in ("ML-DSA-44", "SLH-DSA"):
            self.assertIn(name, body)
        run = self.require_run()
        for entry in run["boundaries"]:
            self.assertTrue(contains_number(body, entry["largest_verified_token_bytes"]))
            for row in entry["rows"]:
                lines = self.rows_naming(body, row["algorithm"])
                for claims in COMPARED:
                    with self.subTest(boundary=entry["name"], algorithm=row["algorithm"],
                                      claims=claims):
                        headroom = row["headroom_bytes"][claims]
                        self.assertTrue(any(shows_count(line, headroom) for line in lines),
                                        headroom)
        for entry in run["limits"]["results"]:
            if entry["outcome"] != "rejected":
                continue
            with self.subTest(pair=(entry["algorithm"], entry["transport"], entry["claims"])):
                words = LAYER_WORDS[entry["rejected_by"]]
                self.assertTrue(any(word in line.lower() for word in words
                                    for line in self.rows_naming(body, entry["algorithm"])))

    def test_latency(self):
        body = self.part("Latency")
        lowered = body.lower()
        for term in ("noise", "calculated", "not measured"):
            self.assertIn(term, lowered)
        run = self.require_run()
        for row in run["latency"]["rows"]:
            with self.subTest(row=(row["client"], row["concurrency"], row["algorithm"])):
                lines = self.rows_naming(body, row["algorithm"])
                means = row["mean_ms"]
                self.assertTrue(any(shows_ms(line, means["oidc"]["total"])
                                    and shows_ms(line, means["essential"]["total"])
                                    and shows_ms(line, row["difference_ms"]["total"])
                                    for line in lines))
                for claims in COMPARED:
                    for value in (row["median_ms"][claims], row["p95_ms"][claims],
                                  row["throughput_rps"][claims]):
                        self.assertTrue(any(shows(line, value) for line in lines), value)
        # R15 asks for the saving per profile: a row per configuration, or, since every
        # configuration may save the same, a row per profile that names no configuration.
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
        self.assertTrue(any(line.startswith("make claims") for line in lines))
        command = re.compile(r"transport_stack\.py[\"']?\s+claims\s+--header-buffers\s+32k\s+"
                             r"--upstream-keepalive\s+64\s+--duration\s+2\s+--output-dir\s+"
                             r"[\"']?results/claims/.*-macos")
        self.assertTrue(any(command.search(line) for line in lines))
        run = self.require_run()
        committed = f"{self.run_dir.relative_to(REPO).as_posix()}/claims.json"
        self.assertTrue(any("--settings" in line and committed in line for line in lines),
                        committed)
        shown = set(lines)
        for line in summary_lines(run):
            with self.subTest(line=line):
                self.assertIn(line.strip(), shown)

    def test_limitations(self):
        body = self.part("Limitations")
        lowered = body.lower()
        self.assertTrue(any("WSL2" in line and "not" in line for line in body.splitlines()))
        for term in ("loopback", "illustrative", "assumption", "not measured", "truncated",
                     "32k", "keepalive", "64"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue("run-to-run" in lowered or "one run" in lowered)
        self.assertTrue(any(term in lowered for term in ("idle", "other candidate", "concurrent",
                                                         "machine state", "state of the machine",
                                                         "other runs")))


# ---- R16: TRANSPORT.md --------------------------------------------------------------------

class TransportDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(TRANSPORT_DOC)

    def section(self, text: str, title: str, level: int) -> str:
        body = section(text, title, level)
        self.assertIsNotNone(body, f"missing heading: {'#' * level} {title}")
        return body

    def test_required_headings_in_order(self):
        found = [name for depth, name, _ in headings(self.text.splitlines())
                 if depth == 2 and name in TRANSPORT_HEADINGS]
        self.assertEqual(found, list(TRANSPORT_HEADINGS))

    def test_sized_tokens_name_essential(self):
        body = self.section(self.text, "Token endpoints", 3)
        line = next((line for line in body.splitlines() if "Sized tokens" in line), "")
        self.assertIn("essential", line)
        self.assertIn("fixtures/claims_essential.json", line)

    def test_load_claims_option_lists_essential(self):
        body = self.section(self.text, "The load command", 3)
        rows = [row for row in table_rows(body) if row.startswith("| `--claims")]
        self.assertEqual(len(rows), 1, rows)
        self.assertIn("essential", rows[0])

    def test_claims_command_subsection(self):
        run_check = self.section(self.text, "Run the check", 2)
        order = [name for depth, name, _ in headings(run_check.splitlines()) if depth == 3]
        self.assertIn("The load command", order)
        self.assertIn("The claims command", order)
        self.assertLess(order.index("The load command"), order.index("The claims command"))
        body = self.section(run_check, "The claims command", 3)
        self.assertTrue(any(re.search(r"transport_stack\.py[\"']?\s+claims\b", block)
                            for block in code_blocks(body)))
        for option in CLAIMS_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, body)
        lines = body.splitlines()
        for option, defaults in (("--duration", (5,)), ("--warmup", (1,)), ("--timeout", (60,)),
                                 ("--concurrency", (1, 4))):
            with self.subTest(default=option):
                self.assertTrue(any(option in line and all(contains_number(line, value)
                                                           for value in defaults)
                                    for line in lines))
        self.assertTrue(any("--output-dir" in line and "required" in line.lower()
                            for line in lines))
        lowered = body.lower()
        for term in ("default", "limits", "latency", "boundar", "claims.json", "latency-oidc",
                     "latency-essential", "](mitigation_results.md"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_upstream_keepalive_bullet_covers_claims(self):
        body = self.section(self.text, "Configuration that is not a default", 3)
        bullets = [line for line in body.splitlines()
                   if line.startswith("- ") and "--upstream-keepalive" in line]
        self.assertTrue(bullets)
        self.assertTrue(any("claims" in line for line in bullets), bullets)


# ---- R17, R18: PROGRESS.md and README.md -------------------------------------------------

class ProgressTests(unittest.TestCase):
    def test_s3_02_items_and_status(self):
        body = section(PROGRESS.read_text(encoding="utf-8"), "S3-02", level=3)
        self.assertIsNotNone(body, "missing heading: ### S3-02")
        items = re.findall(r"(?m)^- \[( |x)\] (.*)$", body)
        # The smaller-claim-sets item is ticked; the later mitigations tick their own items.
        self.assertEqual([text for _, text in items], list(S3_02_ITEMS))
        self.assertEqual(items[0][0], "x")
        status = [line for line in body.splitlines() if line.startswith("**Status:**")]
        self.assertEqual(len(status), 1, status)
        for term in ("claims", "macOS", "MITIGATION_RESULTS.md", "ML-DSA-44", "WSL2"):
            with self.subTest(term=term):
                self.assertIn(term, status[0])
        lowered = status[0].lower()
        for term in ("cookie splitting", "reference token", "not"):
            self.assertIn(term, lowered)

    def test_other_sections_and_done_when_lines_unchanged(self):
        before = git_show("PROGRESS.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        after = PROGRESS.read_text(encoding="utf-8")

        def done_when(text: str) -> list[str]:
            return [line for line in text.splitlines() if line.startswith("**Done when:**")]
        self.assertEqual(done_when(after), done_when(before))
        self.assertEqual(without_section(after, "S3-02").rstrip("\n"),
                         without_section(before, "S3-02").rstrip("\n"))


class ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = README.read_text(encoding="utf-8")

    def test_project_status_links_the_results(self):
        status = section(self.text, "Project status")
        self.assertIsNotNone(status, "missing heading: ## Project status")
        self.assertIn("](MITIGATION_RESULTS.md", status)
        self.assertIn("S3-02", status)
        self.assertIn("claim", status.lower())

    def test_make_shortcuts(self):
        shortcuts = section(self.text, "Make shortcuts")
        self.assertIsNotNone(shortcuts, "missing heading: ## Make shortcuts")
        lines = [line.strip() for block in code_blocks(shortcuts) for line in block.splitlines()]
        self.assertTrue(any(line.startswith("make claims") for line in lines))
        self.assertTrue(any(line.startswith("make load") for line in lines))
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


# ---- R19: what stays unchanged -------------------------------------------------------------

class UnchangedTests(unittest.TestCase):
    def require(self, value):
        if value is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return value

    def test_pinned_files_results_and_tests_unchanged(self):
        tests = self.require(git("ls-tree", "--name-only", BASE_COMMIT, "tests/")).split()
        self.assertTrue(tests)
        paths = ["transport/stack.json", "requirements.txt", "transport/requirements.txt",
                 "transport/conda-requirements.txt", "transport/nginx.conf.template",
                 "fixtures/claims.json", "fixtures/claims_oidc.json",
                 "END_TO_END_RESULTS.md", "results/transport", "results/load",
                 ":(glob)results/2026110*/**", *tests]
        changed = self.require(git("diff", "--name-only", BASE_COMMIT, "--", *paths)).split()
        untracked = self.require(git("ls-files", "--others", "--exclude-standard", "--",
                                     *paths)).split()
        self.assertEqual(changed + untracked, [])

    def test_no_new_load_run(self):
        listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:results/load"))
        on_disk = {path.name for path in (REPO / "results" / "load").iterdir() if path.is_dir()}
        self.assertEqual(on_disk, set(listing.split()))

    def test_template_keeps_its_limits(self):
        template = (REPO / "transport" / "nginx.conf.template").read_text(encoding="utf-8")
        self.assertIn("timer_resolution 100ms;", template)
        self.assertNotIn("Not a default", template)

    def test_claims_module_and_fixture_added_and_nothing_removed(self):
        # Later S3-02 mitigations (cookie splitting, reference tokens) add their own modules, so
        # this checks only that the claims run's files are present and no earlier file is gone.
        for directory, added in (("scripts", "transport_claims.py"),
                                 ("fixtures", "claims_essential.json")):
            with self.subTest(directory=directory):
                listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:{directory}"))
                on_disk = {path.name for path in (REPO / directory).iterdir()
                           if path.is_file() and not path.name.startswith(".")}
                self.assertLessEqual({*listing.split(), added}, on_disk)

    def test_transport_results_only_gains_a_link(self):
        before = self.require(git_show("TRANSPORT_RESULTS.md")).splitlines()
        after = (REPO / "TRANSPORT_RESULTS.md").read_text(encoding="utf-8").splitlines()
        added = [line for line in after if line not in before]
        removed = [line for line in before if line not in after]
        for line in added:
            self.assertIn("MITIGATION_RESULTS.md", line)
        self.assertLessEqual(len(removed), len(added))


if __name__ == "__main__":
    unittest.main()
