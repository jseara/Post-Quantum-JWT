"""Check S3-02's cookie splitting end to end: run_cookies and the cookies command on real stacks
with Chromium, the load command's split transport, the Makefile, the committed macOS run,
MITIGATION_RESULTS.md, TRANSPORT.md, and the other docs, and what stays unchanged; no timing
thresholds."""

from datetime import datetime, timedelta
import getpass
import gzip
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
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from urllib.parse import parse_qsl, urlsplit

from scripts import transport_load
from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import claim_set, pad_for_target, padded_claims, token_bytes
from scripts.transport_stack import load_manifest, manifest_layers

try:
    from scripts import transport_cookies
    COOKIES_IMPORT_ERROR = None
except Exception as error:  # Before S3-02's cookie splitting is built: tests fail, not vanish.
    transport_cookies, COOKIES_IMPORT_ERROR = None, error

try:
    from scripts.transport_claims import without_tokens
except Exception:  # Reported by the tests that need it.
    without_tokens = None


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
MAKEFILE = REPO / "Makefile"
TRANSPORT_DOC = REPO / "TRANSPORT.md"
MITIGATION_DOC = REPO / "MITIGATION_RESULTS.md"
PROGRESS = REPO / "PROGRESS.md"
README = REPO / "README.md"
TRANSPORT_RESULTS = REPO / "TRANSPORT_RESULTS.md"
COOKIES_RESULTS = REPO / "results" / "cookies"
# The commit cookie splitting builds on: files that stay unchanged are compared with it.
BASE_COMMIT = "6f50c937af37d9dfb19db421a4693aabee95cfe8"
S3_01_RUN = REPO / "results" / "load" / "20261117T035444Z-macos"

HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
# nginx's default proxy_buffer_size is one memory page. ML-DSA-44's split issue response (two
# Set-Cookie headers with the full attributes, about 4.4 KB) fits this Mac's 16 KiB but not
# WSL2's 4 KiB, so live runs expect it to verify at the defaults only on 16 KiB pages.
DEFAULT_FITS_ML_DSA_44_SPLIT = PAGE_SIZE == 16384
RUN_NAME = re.compile(r"\d{8}T\d{6}Z-macos")
ERROR_LINE = re.compile(r"(?m)^Error:")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
NONCE = re.compile(r"[0-9a-f]{32}")
APP_STATUS = re.compile(r'" (\d{3}) headers=')
GRACE = 15.0
CLI_TIMEOUT = 1200
SIGNAL_GRACE = 600
MIB = 1024 * 1024
TIME_WAIT_LIMIT = 6_000
TIME_WAIT_GRACE = 90.0

SPLIT_CHUNK_BYTES = 4000
SPLIT_MAX_CHUNKS = 1000
DOMAIN_MAX_COOKIES = 180
BOUNDARY_MAX_TOKEN = 16_384
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
CLAIM_SET_NAMES = ("minimal", "oidc", "essential")
TRANSPORTS = ("cookie", "split")
COMPONENTS = ("total", "transfer", "other_handling", "verification")
LAYERS = ("browser", "proxy", "app_server", "application")
# The words a document may use for each layer the judge names.
LAYER_WORDS = {"browser": ("browser", "chromium"), "proxy": ("proxy", "nginx"),
               "app_server": ("app_server", "waitress"), "application": ("application",)}
LIMIT_LOGS = ("app.log", "browser.log", "proxy-access.log", "proxy-error.log")
LIMITS_DIRS = {"default": "limits-default", "raised": "limits-raised"}
LATENCY_RUNS = {"cookie": "latency-cookie/load.json", "split": "latency-split/load.json"}
STACK_DIRS = ("limits-default", "limits-raised", "latency-cookie", "latency-split")
SAVED_LOAD_FILES = {"load.json", "raw.csv.gz", "logs", "nginx.conf"}

COOKIES_KEYS = {"schema_version", "started_utc", "finished_utc", "recorded_utc", "settings",
                "environment", "layers", "browser", "experiment_keys", "format", "plan",
                "limits", "boundary", "probes", "handling", "latency", "evidence"}
SETTINGS_KEYS = {"algorithms", "claims", "clients", "concurrency", "duration", "warmup",
                 "timeout", "header_buffers", "proxy_buffers", "upstream_keepalive"}
FORMAT = {"cookie_name": "jwt.<index>.<count>", "chunk_bytes": SPLIT_CHUNK_BYTES,
          "max_chunks": SPLIT_MAX_CHUNKS, "domain_max_cookies": DOMAIN_MAX_COOKIES,
          "cookie_attributes": FULL_ATTRIBUTES}
PLAN_KEYS = {"algorithm", "token_bytes", "chunks", "chunk_bytes", "cookie_names",
             "name_value_bytes", "set_cookie_bytes", "cookie_line_bytes", "fits"}
LIMITS_STACK_KEYS = {"stack", "header_buffers", "proxy_buffers", "results", "moved"}
RESULT_KEYS = {"algorithm", "transport", "token_bytes", "chunks", "outcome", "rejected_by",
               "verified_directly", "cookies_expected", "cookies_stored", "chunk_order",
               "issue_status", "verify_status", "bytes", "issue_nonce", "verify_nonce",
               "evidence"}
BYTES_KEYS = {"largest_name_value", "cookie_line", "upstream_response_headers",
              "browser_request_headers", "app_received_headers"}
MOVED_KEYS = {"algorithm", "cookie", "split", "moved"}
BOUNDARY_KEYS = {"algorithm", "claims", "stack", "low_pad", "high_pad", "largest_verified",
                 "first_rejected", "probes"}
BOUNDARY_PROBE_KEYS = {"pad", "token_bytes", "chunks", "outcome", "rejected_by",
                       "cookies_stored", "verify_status", "bytes", "issue_nonce",
                       "verify_nonce", "evidence"}
PROBE_KEYS = RESULT_KEYS | {"name", "pad"}
HANDLING_KEYS = {"algorithm", "claims", "token_bytes", "chunks", "stack", "cases"}
CASE_KEYS = {"name", "cookies", "bearer", "status", "verified", "source", "error",
             "verify_called", "chunks", "nonce"}
LATENCY_KEYS = {"transports", "reference", "size_controls", "runs", "rows", "network_model"}
LATENCY_ROW_KEYS = {"client", "concurrency", "algorithm", "token_bytes", "chunks", "delivered",
                    "verified", "failed", "throughput_rps", "median_ms", "p95_ms", "mean_ms",
                    "difference_ms"}
NETWORK_KEYS = {"algorithm", "request_bytes", "extra_bytes", "modeled"}
COOKIES_OPTIONS = ("--output-dir", "--settings", "--alg", "--claims", "--client",
                   "--concurrency", "--duration", "--warmup", "--timeout", "--header-buffers",
                   "--proxy-buffers", "--upstream-keepalive", "--run-dir")
MAKE_SETTINGS = {"algorithms": NAMES, "claims": "oidc", "clients": ["direct", "browser"],
                 "concurrency": [1, 4], "duration": 2.0, "warmup": 1.0, "timeout": 60.0,
                 "header_buffers": "32k", "proxy_buffers": "32k", "upstream_keepalive": 64}

# R12's cases: cookie names in the order sent, statuses, and the app's chunks objects.
CASE_NAMES = ("in_order", "reversed", "rotated", "among_other_cookies", "missing_0",
              "missing_1", "missing_2", "duplicate", "conflicting_count", "out_of_range_index",
              "mixed_tokens", "with_jwt_cookie", "with_bearer")
A = ("jwt.0.3", "jwt.1.3", "jwt.2.3")
CASE_COOKIES = {
    "in_order": [A[0], A[1], A[2]], "reversed": [A[2], A[1], A[0]],
    "rotated": [A[1], A[2], A[0]],
    "among_other_cookies": ["a", A[2], "jwt_old", A[0], "theme", A[1]],
    "missing_0": [A[1], A[2]], "missing_1": [A[0], A[2]], "missing_2": [A[0], A[1]],
    "duplicate": [A[0], A[1], A[1], A[2]], "conflicting_count": [*A, "jwt.0.2"],
    "out_of_range_index": [*A, "jwt.3.3"], "mixed_tokens": list(A),
    "with_jwt_cookie": [*A, "jwt"], "with_bearer": list(A),
}
CASE_STATUSES = {"in_order": 200, "reversed": 200, "rotated": 200, "among_other_cookies": 200,
                 "missing_0": 401, "missing_1": 401, "missing_2": 401, "duplicate": 400,
                 "conflicting_count": 400, "out_of_range_index": 400, "mixed_tokens": 401,
                 "with_jwt_cookie": 400, "with_bearer": 400}
CASE_CHUNKS = {
    "in_order": {"count": 3, "received": [0, 1, 2], "missing": []},
    "reversed": {"count": 3, "received": [2, 1, 0], "missing": []},
    "rotated": {"count": 3, "received": [1, 2, 0], "missing": []},
    "among_other_cookies": {"count": 3, "received": [2, 0, 1], "missing": []},
    "missing_0": {"count": 3, "received": [1, 2], "missing": [0]},
    "missing_1": {"count": 3, "received": [0, 2], "missing": [1]},
    "missing_2": {"count": 3, "received": [0, 1], "missing": [2]},
    "duplicate": {"count": 3, "received": [0, 1, 1, 2], "missing": []},
    "conflicting_count": {"count": None, "received": [0, 1, 2, 0], "missing": []},
    "out_of_range_index": {"count": 3, "received": [0, 1, 2, 3], "missing": []},
    "mixed_tokens": {"count": 3, "received": [0, 1, 2], "missing": []},
    "with_jwt_cookie": None,
    "with_bearer": None,
}
VERIFY_CALLED = {"in_order", "reversed", "rotated", "among_other_cookies", "mixed_tokens"}

MITIGATION_PARTS = ("Format", "Chunk plan", "Size limits", "Missing and reordered chunks",
                    "Latency", "Reproduce", "Limitations")
TRANSPORT_HEADINGS = ("Stack", "Versions and documented limits", "Setup", "Run the check",
                      "Support for Sprint 2 tasks", "Limitations")
CHROMIUM_SOURCE = "https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.4/"
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
    """Return scripts.transport_cookies, failing the calling test when it cannot be imported."""
    if transport_cookies is None:
        raise AssertionError(f"scripts/transport_cookies.py cannot be imported: "
                             f"{COOKIES_IMPORT_ERROR!r}")
    return transport_cookies


def summary_lines(result: dict) -> list[str]:
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
    return read_gzip(path) if path.suffix == ".gz" else read_text(path)


def visible_names(directory: Path) -> set[str]:
    """A directory's entry names, without hidden ones such as Finder's .DS_Store (gitignored)."""
    return {path.name for path in Path(directory).iterdir() if not path.name.startswith(".")}


def token_runs(text: str) -> list[str]:
    """Base64url runs of 40 or more characters, except 40-hex-digit git commits."""
    return [run for run in TOKEN_LIKE.findall(text) if not HEX_COMMIT.fullmatch(run)]


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
    """Every port of every stack a run started under run_dir."""
    ports = set()
    for path in Path(run_dir).glob("**/nginx.conf"):
        ports |= conf_ports(path)
    return ports


def stack_ports(run_dir: Path) -> dict[str, set[int]]:
    """The proxy and application ports of each stack of a cookies run, by stack directory."""
    return {name: conf_ports(Path(run_dir) / name / "nginx" / "nginx.conf")
            for name in STACK_DIRS}


def query_of(url: str) -> dict:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def parse_utc(text) -> datetime:
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


def app_header_bytes(app_log: str, nonce: str) -> int | None:
    """header_bytes of the line the application itself wrote for the request with this nonce."""
    for line in app_log.splitlines():
        if nonce in line and APP_STATUS.search(line):
            match = re.search(r"\bheader_bytes=(\d+)", line)
            return int(match[1]) if match else None
    return None


def app_line(app_log: str, nonce: str) -> str | None:
    return next((line for line in app_log.splitlines()
                 if nonce in line and APP_STATUS.search(line)), None)


def failed_layer(logs: dict[str, str], nonce: str) -> str:
    """R10: the layer to blame for a request the browser got no 200 for, from every layer's log.

    The browser when nginx never logged it; the proxy when the application did not answer or
    answered 200; waitress when it rejected the request; otherwise the application's own 4xx.
    """
    if nonce not in logs["proxy-access.log"]:
        return "browser"
    mentioning = [line for line in logs["app.log"].splitlines() if nonce in line]
    line = app_line(logs["app.log"], nonce)
    if not mentioning or (line is not None and APP_STATUS.search(line)[1] == "200"):
        return "proxy"
    if any("rejected by waitress" in line for line in mentioning):
        return "app_server"
    return "application"


# ---- what the spec says, computed independently ---------------------------------------------

def default_count(total: int) -> int:
    return max(1, math.ceil(total / SPLIT_CHUNK_BYTES))


def chunk_sizes(total: int, count: int | None = None) -> list[int]:
    count = default_count(total) if count is None else count
    return [total // count + (1 if index < total % count else 0) for index in range(count)]


def chunk_names(count: int) -> list[str]:
    return [f"jwt.{index}.{count}" for index in range(count)]


def split_line_bytes(total: int, count: int | None = None) -> int:
    names = chunk_names(len(chunk_sizes(total, count)))
    return (len("Cookie: \r\n") + total + sum(len(name) + 1 for name in names)
            + 2 * (len(names) - 1))


def split_set_cookie_bytes(total: int, count: int | None = None,
                           attributes: str = FULL_ATTRIBUTES) -> int:
    sizes = chunk_sizes(total, count)
    return sum(len(f"Set-Cookie: {name}=; {attributes}\r\n") + size
               for name, size in zip(chunk_names(len(sizes)), sizes))


def largest_name_value(total: int, count: int | None = None) -> int:
    sizes = chunk_sizes(total, count)
    return max(len(name) + size for name, size in zip(chunk_names(len(sizes)), sizes))


def manifest_limits() -> tuple[int, int]:
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return (layers["browser"]["limits"]["cookie"]["bytes"],
            layers["proxy"]["limits"]["single_header"]["bytes"])


def expected_plan_row(algorithm: str, claims: str) -> dict:
    """R9's row for one configuration, computed from the spec's formulas."""
    cookie_limit, line_limit = manifest_limits()
    total = token_bytes(algorithm, claim_set(claims))
    count = default_count(total)
    name_value = {"cookie": len("jwt") + total, "split": largest_name_value(total)}
    cookie_line = {"cookie": len("Cookie: jwt=\r\n") + total, "split": split_line_bytes(total)}
    return {
        "algorithm": algorithm, "token_bytes": total, "chunks": count,
        "chunk_bytes": chunk_sizes(total), "cookie_names": chunk_names(count),
        "name_value_bytes": name_value,
        "set_cookie_bytes": {"cookie": len(f"Set-Cookie: jwt=; {FULL_ATTRIBUTES}\r\n") + total,
                             "split": split_set_cookie_bytes(total)},
        "cookie_line_bytes": cookie_line,
        "fits": {"cookie": {"per_cookie": name_value["cookie"] <= cookie_limit,
                            "cookie_line": cookie_line["cookie"] <= line_limit},
                 "split": {"per_cookie": name_value["split"] <= cookie_limit,
                           "cookie_count": count <= DOMAIN_MAX_COOKIES,
                           "cookie_line": cookie_line["split"] <= line_limit}},
    }


def expected_algorithms(selected) -> list[str]:
    """R8: the selected configurations plus ES256, in ADAPTER_LIST order; None means all six."""
    if selected is None:
        return list(NAMES)
    return [name for name in NAMES if name in selected or name == "ES256"]


def per_cookie_pad(claims: str) -> int:
    """R11: the largest pad whose larger chunk of two has name + value <= 4,096 bytes."""
    cookie_limit, _ = manifest_limits()
    return pad_for_target("ML-DSA-44", claim_set(claims), 2 * (cookie_limit - len("jwt.0.2")))


def evidence_paths(value) -> list[str]:
    """Every string in an evidence object."""
    if isinstance(value, dict):
        return [path for item in value.values() for path in evidence_paths(item)]
    if isinstance(value, list):
        return [path for item in value for path in evidence_paths(item)]
    return [value]


def token_cells(load: dict) -> list[dict]:
    return [cell for cell in load["results"] if cell["variant"] == "token"]


def cell_means(cell: dict) -> dict | None:
    if cell["latency"] is None:
        return None
    return {component: cell["latency"][component]["mean_ms"] for component in COMPONENTS}


def total_statistic(cell: dict, key: str):
    return None if cell["latency"] is None else cell["latency"]["total"][key]


def expected_latency_rows(cookie: dict, split: dict) -> list[dict]:
    """R13's rows, derived from the two saved load.json files."""
    matches = {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
               for cell in token_cells(split)}
    rows = []
    for cell in token_cells(cookie):
        pair = {"cookie": cell,
                "split": matches[(cell["client"], cell["concurrency"], cell["algorithm"])]}
        means = {name: cell_means(entry) for name, entry in pair.items()}
        difference = (None if any(value is None for value in means.values()) else
                      {component: means["split"][component] - means["cookie"][component]
                       for component in COMPONENTS})
        rows.append({
            "client": cell["client"], "concurrency": cell["concurrency"],
            "algorithm": cell["algorithm"], "token_bytes": cell["token_bytes"],
            "chunks": default_count(cell["token_bytes"]),
            "delivered": {name: entry["issue"]["delivered"] for name, entry in pair.items()},
            **{key: {name: entry[key] for name, entry in pair.items()}
               for key in ("verified", "failed", "throughput_rps")},
            "median_ms": {name: total_statistic(entry, "median_ms")
                          for name, entry in pair.items()},
            "p95_ms": {name: total_statistic(entry, "p95_ms") for name, entry in pair.items()},
            "mean_ms": means, "difference_ms": difference})
    return rows


def expected_network_model(algorithms, cookie: dict, split: dict) -> list[dict]:
    """R13's network_model, derived from the two saved load.json files."""
    rows = {name: {row["algorithm"]: row for row in load["network_model"]["rows"]}
            for name, load in (("cookie", cookie), ("split", split))}
    entries = []
    for algorithm in algorithms:
        request = {name: rows[name][algorithm]["request_bytes"] for name in TRANSPORTS}
        modeled = []
        for index, profile in enumerate(transport_load.NETWORK_PROFILES):
            transfer = {name: rows[name][algorithm]["modeled"][index]["transfer_ms"]
                        for name in TRANSPORTS}
            modeled.append({"uplink_mbps": profile["uplink_mbps"], "rtt_ms": profile["rtt_ms"],
                            "extra_ms": transfer["split"] - transfer["cookie"]})
        entries.append({"algorithm": algorithm, "request_bytes": request,
                        "extra_bytes": request["split"] - request["cookie"],
                        "modeled": modeled})
    return entries


def expected_load_settings(settings: dict, transport: str) -> dict:
    """R13: the settings each latency run's load.json records."""
    return {"algorithms": settings["algorithms"], "transport": transport,
            "clients": settings["clients"], "claims": settings["claims"],
            "concurrency": settings["concurrency"], "duration": settings["duration"],
            "warmup": settings["warmup"], "reference": "ES256", "size_controls": False,
            "timeout": settings["timeout"], "proxy_buffers": settings["proxy_buffers"],
            "header_buffers": settings["header_buffers"],
            "upstream_keepalive": settings["upstream_keepalive"]}


def summary_words(result: dict) -> list[str]:
    """R15: the phase word each summary line starts with, in order."""
    return (["plan"] * len(result["plan"])
            + ["limits"] * (2 * len(result["settings"]["algorithms"])) + ["boundary"]
            + ["probe"] * 4 + ["handling"] * len(CASE_NAMES)
            + ["latency"] * len(result["latency"]["rows"]))


def committed_run() -> tuple[Path, dict] | None:
    """The newest results/cookies/<YYYYMMDDTHHMMSSZ>-macos/ run recorded on macOS, or None."""
    runs = []
    for path in sorted(COOKIES_RESULTS.glob("*/cookies.json")):
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


# ---- checks shared by every cookies run --------------------------------------------------

class CookiesCase(unittest.TestCase):
    """Assertions shared by run_cookies, the cookies command, and the committed run (R8-R15)."""

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

    def logs(self, output: Path, stack: str) -> dict[str, str]:
        """A limits stack's four saved logs, decompressed, by log name."""
        directory = output / LIMITS_DIRS[stack] / "logs"
        return {name: read_gzip(directory / f"{name}.gz") for name in LIMIT_LOGS}

    def loads(self, output: Path) -> dict[str, dict]:
        """The two latency runs' load.json files, by transport."""
        return {name: json.loads((output / path).read_text(encoding="utf-8"))
                for name, path in LATENCY_RUNS.items()}

    def check_top(self, result: dict, settings: dict) -> None:
        """R14: the top-level keys, times, settings, recorded context, format, and plan."""
        self.assertEqual(set(result), COOKIES_KEYS)
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
        for key in ("git_commit", "git_dirty_scripts_or_fixtures"):
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
                   transport: str, pad: int = 0, count: int | None = None) -> None:
        """R10, R11, R14: one judged pair or probe, consistent with every layer's log."""
        self.assertEqual(set(entry), keys)
        self.assertEqual((entry["algorithm"], entry["transport"]), (algorithm, transport))
        total = token_bytes(algorithm, padded_claims(claim_set(claims), pad))
        self.assertEqual(entry["token_bytes"], total)
        if transport == "cookie":
            self.assertIsNone(entry["chunks"])
            self.assertEqual(entry["cookies_expected"], 1)
            self.assertIsNone(entry["chunk_order"])
            name_value, line = len("jwt") + total, len("Cookie: jwt=\r\n") + total
            set_cookie = len(f"Set-Cookie: jwt=; {FULL_ATTRIBUTES}\r\n") + total
        else:
            count = default_count(total) if count is None else count
            self.assertEqual(entry["chunks"], count)
            self.assertEqual(entry["cookies_expected"], count)
            name_value, line = largest_name_value(total, count), split_line_bytes(total, count)
            set_cookie = split_set_cookie_bytes(total, count)
        self.assertIs(type(entry["cookies_stored"]), int)
        self.assertTrue(0 <= entry["cookies_stored"] <= entry["cookies_expected"],
                        entry["cookies_stored"])
        self.assertIn(entry["outcome"], ("verified", "rejected"))
        # R10: walk issue, cookie jar, then verify, and blame the first layer that failed.
        if type(entry["issue_status"]) is int and entry["issue_status"] != 200:
            self.assertEqual((entry["outcome"], entry["rejected_by"]),
                             ("rejected", failed_layer(logs, entry["issue_nonce"])))
        elif (entry["issue_status"] == 200
              and entry["cookies_stored"] < entry["cookies_expected"]):
            self.assertEqual((entry["outcome"], entry["rejected_by"]), ("rejected", "browser"))
        elif (entry["issue_status"] == 200 and type(entry["verify_status"]) is int
              and entry["verify_status"] != 200):
            self.assertEqual((entry["outcome"], entry["rejected_by"]),
                             ("rejected", failed_layer(logs, entry["verify_nonce"])))
        if entry["outcome"] == "verified":
            self.assertIsNone(entry["rejected_by"])
            self.assertEqual((entry["issue_status"], entry["verify_status"]), (200, 200))
            self.assertEqual(entry["cookies_stored"], entry["cookies_expected"])
            if transport == "split":
                self.assertEqual(sorted(entry["chunk_order"]), list(range(count)))
        else:
            self.assertIn(entry["rejected_by"], LAYERS)
        if entry["chunk_order"] is not None:
            self.assertEqual(transport, "split")
            self.assertTrue(all(type(index) is int for index in entry["chunk_order"]))
        for key in ("issue_status", "verify_status"):
            self.assertTrue(entry[key] is None or type(entry[key]) is int, key)
        self.assertIs(entry["verified_directly"], True)
        recorded = entry["bytes"]
        self.assertEqual(set(recorded), BYTES_KEYS)
        self.assertEqual(recorded["largest_name_value"], name_value)
        self.assertEqual(recorded["cookie_line"], line)
        self.assertIs(type(recorded["upstream_response_headers"]), int)
        self.assertGreater(recorded["upstream_response_headers"], set_cookie)
        records = browser_records(logs["browser.log"])
        verify = request_record(records, entry["verify_nonce"], VERIFY_PATH)
        if verify is None:
            self.assertIsNone(recorded["browser_request_headers"])
        else:
            # The header lines browser.log recorded, as `name: value\r\n` each; Sprint 2's sweep
            # also counts the request line and the final CRLF, which is accepted too.
            lines = sum(len(f"{name}: {value}\r\n") for name, value in verify["headers"].items())
            parts = urlsplit(verify["url"])
            block = len(f"GET {parts.path}?{parts.query} HTTP/1.1\r\n") + lines + len("\r\n")
            self.assertIs(type(recorded["browser_request_headers"]), int)
            self.assertIn(recorded["browser_request_headers"], (lines, block))
            if entry["outcome"] == "verified":  # Every chunk went out in the Cookie line.
                self.assertGreaterEqual(recorded["browser_request_headers"], line)
        self.assertEqual(recorded["app_received_headers"],
                         app_header_bytes(logs["app.log"], entry["verify_nonce"]))
        if entry["outcome"] == "verified":
            self.assertGreaterEqual(recorded["app_received_headers"], line)
            self.assertIsNotNone(verify, "browser.log has no verify request with this nonce")
        for name in ("issue_nonce", "verify_nonce"):
            self.assertRegex(entry[name], NONCE)
            if name == "issue_nonce" or entry["outcome"] == "verified":
                self.assertIn(entry[name], logs["browser.log"], name)
            if entry["outcome"] == "verified":
                self.assertIn(entry[name], logs["proxy-access.log"], name)
                self.assertIn(entry[name], logs["app.log"], name)
        evidence = entry["evidence"]
        self.assertTrue(isinstance(evidence, str) and evidence.strip())
        self.assertNotIn("eyJ", evidence)
        self.assertEqual(token_runs(evidence), [])
        if without_tokens is not None:
            self.assertEqual(without_tokens(evidence), evidence)
        issue = request_record(records, entry["issue_nonce"], ISSUE_PATH)
        self.assertIsNotNone(issue, "browser.log has no issue request with this nonce")
        query = query_of(issue["url"])
        self.assertEqual(query.get("alg"), algorithm)
        self.assertEqual(query.get("claims"), claims)
        self.assertEqual(query.get("delivery"), transport)
        self.assertEqual(query.get("attrs"), "full")
        self.assertEqual(query.get("pad", "0"), str(pad))
        if transport == "split":
            self.assertEqual(query.get("chunks", str(default_count(total))), str(count))
        for event in ("request", "response", "cookies"):
            self.assertTrue(any(record.get("event") == event
                                and record.get("transport") == transport
                                and record.get("algorithm") == algorithm
                                for record in records), (event, transport))

    def check_limits(self, result: dict, output: Path, default_fits: bool) -> None:
        """R10, R11: the cookie and split pairs on both stacks, and which of them moved.

        default_fits: whether ML-DSA-44's split pair is expected to verify at the defaults too.
        """
        limits, settings = result["limits"], result["settings"]
        self.assertEqual(set(limits), set(LIMITS_DIRS))
        algorithms, claims = settings["algorithms"], settings["claims"]
        nonces = []
        for stack, directory in LIMITS_DIRS.items():
            entry = limits[stack]
            with self.subTest(stack=stack):
                self.assertEqual(set(entry), LIMITS_STACK_KEYS)
                self.assertEqual(entry["stack"], directory)
                raised = (settings["header_buffers"], settings["proxy_buffers"])
                self.assertEqual((entry["header_buffers"], entry["proxy_buffers"]),
                                 (None, None) if stack == "default" else raised)
                self.assertEqual([(pair["algorithm"], pair["transport"])
                                  for pair in entry["results"]],
                                 [(name, transport) for name in algorithms
                                  for transport in TRANSPORTS])
                logs = self.logs(output, stack)
                outcomes = {}
                for pair in entry["results"]:
                    with self.subTest(pair=(pair["algorithm"], pair["transport"])):
                        self.check_pair(pair, RESULT_KEYS, logs, claims, pair["algorithm"],
                                        pair["transport"])
                    outcomes[(pair["algorithm"], pair["transport"])] = pair["outcome"]
                    nonces += [pair["issue_nonce"], pair["verify_nonce"]]
                self.assertEqual([moved["algorithm"] for moved in entry["moved"]], algorithms)
                for moved in entry["moved"]:
                    self.assertEqual(set(moved), MOVED_KEYS)
                    for transport in TRANSPORTS:
                        self.assertEqual(moved[transport],
                                         outcomes[(moved["algorithm"], transport)])
                    self.assertIs(moved["moved"], moved["cookie"] != moved["split"])
                if "ML-DSA-44" in algorithms and (stack == "raised" or default_fits):
                    self.assertEqual(outcomes[("ML-DSA-44", "split")], "verified")
        self.assertEqual(len(set(nonces)), len(nonces), "nonces repeat")

    def check_boundary(self, result: dict, output: Path, default_fits: bool) -> None:
        """R10: the bisection for the largest split ML-DSA-44 token that gets through.

        default_fits: whether ML-DSA-44's split pair at pad 0 is expected to verify at the
        defaults, as on this 16 KiB-page Mac (see DEFAULT_FITS_ML_DSA_44_SPLIT).
        """
        boundary, claims = result["boundary"], result["settings"]["claims"]
        self.assertEqual(set(boundary), BOUNDARY_KEYS)
        self.assertEqual((boundary["algorithm"], boundary["claims"], boundary["stack"]),
                         ("ML-DSA-44", claims, "limits-default"))
        high = pad_for_target("ML-DSA-44", claim_set(claims), BOUNDARY_MAX_TOKEN)
        self.assertEqual((boundary["low_pad"], boundary["high_pad"]), (0, high))
        probes = boundary["probes"]
        self.assertIsInstance(probes, list)
        self.assertGreaterEqual(len(probes), 2)
        pads = [probe["pad"] for probe in probes]
        # R10 and R14 record every probe but fix no order (sent, or sorted by pad).
        self.assertIn(0, pads)
        self.assertIn(high, pads)
        self.assertEqual(len(set(pads)), len(pads), "a pad was probed twice")
        self.assertTrue(all(0 <= pad <= high for pad in pads), pads)
        self.assertLessEqual(len(probes), 3 + high.bit_length())
        logs = self.logs(output, "default")
        for probe in probes:
            with self.subTest(pad=probe["pad"]):
                self.assertLessEqual(BOUNDARY_PROBE_KEYS, set(probe))
                total = token_bytes("ML-DSA-44", padded_claims(claim_set(claims), probe["pad"]))
                self.assertEqual(probe["token_bytes"], total)
                self.assertLessEqual(total, BOUNDARY_MAX_TOKEN)
                self.assertEqual(probe["chunks"], default_count(total))
                self.assertIn(probe["outcome"], ("verified", "rejected"))
                if probe["outcome"] == "verified":
                    self.assertIsNone(probe["rejected_by"])
                    self.assertEqual(probe["verify_status"], 200)
                else:
                    self.assertIn(probe["rejected_by"], LAYERS)
                self.assertIs(type(probe["cookies_stored"]), int)
                self.assertLessEqual(probe["cookies_stored"], probe["chunks"])
                self.assertEqual(set(probe["bytes"]), BYTES_KEYS)
                self.assertEqual(probe["bytes"]["cookie_line"], split_line_bytes(total))
                for name in ("issue_nonce", "verify_nonce"):
                    self.assertRegex(probe[name], NONCE)
                    # As for pairs, the verify may not be sent after a failed issue (R14's
                    # browser_request_headers is null then).
                    if name == "issue_nonce" or probe["outcome"] == "verified":
                        self.assertIn(probe[name], logs["browser.log"])
                self.assertEqual(token_runs(probe["evidence"]), [])
        self.assertGreater(token_bytes("ML-DSA-44", padded_claims(claim_set(claims), high + 1)),
                           BOUNDARY_MAX_TOKEN)
        by_pad = {probe["pad"]: probe for probe in probes}

        def recorded_probe(entry: dict) -> dict:
            """The probe that a largest_verified or first_rejected entry records."""
            self.assertIsInstance(entry, dict)
            self.assertIn(entry.get("pad"), by_pad)
            probe = by_pad[entry["pad"]]
            for key in set(entry) & set(probe):
                self.assertEqual(entry[key], probe[key], key)
            return probe

        largest, first = boundary["largest_verified"], boundary["first_rejected"]
        verified = [probe["pad"] for probe in probes if probe["outcome"] == "verified"]
        rejected = [probe["pad"] for probe in probes if probe["outcome"] == "rejected"]
        if default_fits:  # The split pair at pad 0 verifies on this stack.
            self.assertEqual(by_pad[0]["outcome"], "verified")
        # A bisection's ends are the largest verified pad and the smallest rejected one.
        if verified:
            self.assertIsNotNone(largest)
            largest = recorded_probe(largest)
            self.assertEqual(largest["outcome"], "verified")
            self.assertEqual(largest["pad"], max(verified))
        else:
            self.assertIsNone(largest)
        if rejected:
            self.assertIsNotNone(first)
            first = recorded_probe(first)
            self.assertEqual(first["outcome"], "rejected")
            self.assertEqual(first["pad"], min(rejected))
        else:
            self.assertIsNone(first)
        if by_pad[0]["outcome"] == "verified" and by_pad[high]["outcome"] == "rejected":
            # Bisected to one character of padding.
            self.assertEqual(first["pad"], largest["pad"] + 1)
            self.assertGreater(first["token_bytes"], largest["token_bytes"])

    def check_probes(self, result: dict, output: Path) -> None:
        """R11: the per-cookie and cookie-count probes on the raised stack."""
        probes, claims = result["probes"], result["settings"]["claims"]
        self.assertEqual(set(probes), {"stack", "per_cookie", "cookie_count"})
        self.assertEqual(probes["stack"], "limits-raised")
        cookie_limit, _ = manifest_limits()
        at_pad = per_cookie_pad(claims)
        logs = self.logs(output, "raised")
        expected = {"per_cookie": [("at_limit", "ML-DSA-44", at_pad, 2),
                                   ("over_limit", "ML-DSA-44", at_pad + 1, 2)],
                    "cookie_count": [("at_limit", "ES256", 0, DOMAIN_MAX_COOKIES),
                                     ("over_limit", "ES256", 0, DOMAIN_MAX_COOKIES + 1)]}
        for kind, entries in expected.items():
            self.assertEqual([probe["name"] for probe in probes[kind]],
                             [name for name, *_ in entries])
            for probe, (name, algorithm, pad, count) in zip(probes[kind], entries):
                with self.subTest(probe=(kind, name)):
                    self.assertEqual(probe["pad"], pad)
                    self.check_pair(probe, PROBE_KEYS, logs, claims, algorithm, "split", pad,
                                    count)
                    if kind == "per_cookie":
                        if name == "at_limit":
                            self.assertLessEqual(probe["bytes"]["largest_name_value"],
                                                 cookie_limit)
                        else:
                            self.assertGreater(probe["bytes"]["largest_name_value"],
                                               cookie_limit)

    def check_handling(self, result: dict, output: Path) -> None:
        """R12: the 13 chunk-handling cases on the raised stack, with R12's statuses."""
        handling, claims = result["handling"], result["settings"]["claims"]
        self.assertEqual(set(handling), HANDLING_KEYS)
        self.assertEqual((handling["algorithm"], handling["claims"], handling["chunks"],
                          handling["stack"]), ("ML-DSA-44", claims, 3, "limits-raised"))
        self.assertEqual(handling["token_bytes"], token_bytes("ML-DSA-44", claim_set(claims)))
        cases = handling["cases"]
        self.assertEqual([case["name"] for case in cases], list(CASE_NAMES))
        logs = self.logs(output, "raised")
        for case in cases:
            name = case["name"]
            with self.subTest(case=name):
                self.assertEqual(set(case), CASE_KEYS)
                self.assertEqual(case["cookies"], CASE_COOKIES[name])
                self.assertIs(case["bearer"], name == "with_bearer")
                self.assertEqual(case["status"], CASE_STATUSES[name])
                self.assertIs(case["verified"], CASE_STATUSES[name] == 200)
                self.assertEqual(case["source"], None if CASE_CHUNKS[name] is None else "split")
                self.assertIs(case["verify_called"], name in VERIFY_CALLED)
                self.assertEqual(case["chunks"], CASE_CHUNKS[name])
                if case["status"] == 200:
                    self.assertIsNone(case["error"])
                else:
                    self.assertIsInstance(case["error"], str)
                if name.startswith("missing_"):
                    self.assertIn("missing", case["error"])
                    self.assertIn(name[-1], case["error"])
                if CASE_CHUNKS[name] is None:
                    self.assertTrue(case["error"].startswith("more than one token"))
                self.assertRegex(case["nonce"], NONCE)
                self.assertIn(case["nonce"], logs["proxy-access.log"])
                line = app_line(logs["app.log"], case["nonce"])
                self.assertIsNotNone(line, "app.log has no line for this case")
                chunks = CASE_CHUNKS[name]
                if chunks is not None:
                    count = "-" if chunks["count"] is None else chunks["count"]
                    self.assertTrue(line.endswith(f"chunks={len(chunks['received'])}/{count}"),
                                    line)
                else:  # Lines without the split source keep their format.
                    self.assertNotIn("chunks=", line)
                    self.assertTrue(line.split()[-1].startswith("verified="), line)
                self.assertNotIn("eyJ", line)
                self.assertEqual(token_runs(line), [])
        self.assertEqual(len({case["nonce"] for case in cases}), len(cases))

    def check_latency(self, result: dict, output: Path) -> None:
        """R13: the two saved load runs and the comparison derived from them."""
        latency, settings = result["latency"], result["settings"]
        self.assertEqual(set(latency), LATENCY_KEYS)
        self.assertEqual(latency["transports"], ["cookie", "split"])
        self.assertEqual(latency["reference"], "ES256")
        self.assertIs(latency["size_controls"], False)
        self.assertEqual(latency["runs"], LATENCY_RUNS)
        loads = self.loads(output)
        for name, load in loads.items():
            with self.subTest(run=name):
                self.assertEqual(load["settings"], expected_load_settings(settings, name))
                self.assertTrue(load["results"])
                for cell in load["results"]:
                    self.assertEqual(cell["variant"], "token")
                    self.assertEqual(cell["claims"], settings["claims"])
                    self.assertEqual(cell["token_bytes"],
                                     token_bytes(cell["algorithm"], claim_set(settings["claims"])))
                    if not cell["issue"]["delivered"]:
                        self.assertEqual(cell["requests"], 0)
                        self.assertTrue(cell["issue"]["error"])
        expected = expected_latency_rows(loads["cookie"], loads["split"])
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
        for entry in latency["network_model"]:
            self.assertEqual(set(entry), NETWORK_KEYS)
        self.assertJsonClose(latency["network_model"],
                             expected_network_model(settings["algorithms"], loads["cookie"],
                                                    loads["split"]), "network_model")

    def check_phase_order(self, result: dict, output: Path) -> None:
        """R13, R14: the cookie run, then the split run, both inside the cookies run."""
        loads = self.loads(output)
        times = [parse_utc(result["started_utc"]),
                 parse_utc(loads["cookie"]["started_utc"]),
                 parse_utc(loads["cookie"]["finished_utc"]),
                 parse_utc(loads["split"]["started_utc"]),
                 parse_utc(loads["split"]["finished_utc"]),
                 parse_utc(result["finished_utc"])]
        self.assertEqual(times, sorted(times))

    def check_layout(self, result: dict, output: Path) -> None:
        """R14: the files of a saved run and the evidence that names them."""
        self.assertEqual(visible_names(output), {"cookies.json", *STACK_DIRS})
        for directory in LIMITS_DIRS.values():
            with self.subTest(directory=directory):
                self.assertEqual(visible_names(output / directory), {"logs", "nginx.conf"})
                self.assertEqual(visible_names(output / directory / "logs"),
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
        named = set()
        for path in evidence_paths(result["evidence"]):
            with self.subTest(evidence=path):
                self.assertIsInstance(path, str)
                self.assertFalse(Path(path).is_absolute(), path)
                self.assertTrue((output / path).is_file(), path)
                named.add(Path(path).as_posix())
                if Path(path).name == "load.json":  # It names its own run's files.
                    load = json.loads((output / path).read_text(encoding="utf-8"))
                    parent = Path(path).parent
                    named |= {(parent / item).as_posix()
                              for item in evidence_paths(load.get("evidence") or {})}
        saved = {path.relative_to(output).as_posix() for path in output.rglob("*")
                 if path.is_file() and not path.name.startswith(".")}
        self.assertEqual(saved - named - {"cookies.json"}, set(), "files missing from evidence")
        for path in ("limits-default/nginx.conf", "limits-raised/nginx.conf",
                     *LATENCY_RUNS.values()):
            self.assertIn(path, named)

    def check_nginx_confs(self, result: dict, output: Path) -> None:
        """R10, R11, R13: default limits, raised buffers, and the latency stacks' settings."""
        settings = result["settings"]
        default = read_text(output / "limits-default" / "nginx.conf")
        self.assertNotIn("Not a default", default)
        raised = read_text(output / "limits-raised" / "nginx.conf")
        self.assertIn(f"large_client_header_buffers 4 {settings['header_buffers']};", raised)
        self.assertIn(f"proxy_buffer_size {settings['proxy_buffers']};", raised)
        self.assertIn(f"proxy_buffers 8 {settings['proxy_buffers']};", raised)
        self.assertIn("Not a default", raised)
        self.assertNotRegex(raised, r"(?m)^\s*keepalive\s+\d+;")
        for path in LATENCY_RUNS.values():
            text = read_text(output / Path(path).parent / "nginx.conf")
            with self.subTest(config=path):
                self.assertIn(f"large_client_header_buffers 4 {settings['header_buffers']};",
                              text)
                self.assertIn(f"proxy_buffer_size {settings['proxy_buffers']};", text)
                if settings["upstream_keepalive"] is not None:
                    self.assertIn(f"keepalive {settings['upstream_keepalive']};", text)
        for path in [output / "limits-default" / "nginx.conf",
                     output / "limits-raised" / "nginx.conf",
                     *(output / Path(run).parent / "nginx.conf" for run in LATENCY_RUNS.values())]:
            listens = re.findall(r"(?m)^\s*listen\s+(\S+?);", read_text(path))
            self.assertTrue(listens)
            self.assertTrue(all(value.startswith(f"{HOST}:") for value in listens), listens)

    def check_privacy(self, output: Path, every_file: bool) -> None:
        """R14: no token, chunk value, or Cookie value where none may be; no host or user."""
        cookies_text = read_text(output / "cookies.json")
        for path in (str(REPO), str(REPO.resolve()), "CIS628Project"):
            self.assertNotIn(path, cookies_text)
        token_free = [output / "cookies.json"]
        for directory in LIMITS_DIRS.values():
            token_free += [output / directory / "logs" / "app.log.gz",
                           output / directory / "logs" / "proxy-access.log.gz"]
        for run in LATENCY_RUNS.values():
            directory = output / Path(run).parent
            token_free += [directory / "load.json", directory / "raw.csv.gz",
                           directory / "logs" / "app.log.gz",
                           directory / "logs" / "proxy-access.log.gz"]
        for path in token_free:
            with self.subTest(file=str(path.relative_to(output))):
                text = read_any(path)
                self.assertNotIn("eyJ", text)
                self.assertEqual(token_runs(text)[:3], [])
        for path in output.rglob("proxy-error.log.gz"):
            for line in read_gzip(path).splitlines():
                if "eyJ" in line or token_runs(line):
                    self.assertIn("client sent too long header line", line, str(path))
        checked = (sorted(path for path in output.rglob("*") if path.is_file()) if every_file
                   else [output / "cookies.json",
                         *(output / run for run in LATENCY_RUNS.values())])
        names = private_names()
        for path in checked:
            text = read_any(path)
            for name in names:
                self.assertNotIn(name, text, str(path.relative_to(output)))

    def check_summary(self, lines, result: dict) -> None:
        """R15: the lines in phase order, each starting with its phase word and naming its row."""
        self.assertIsInstance(lines, list)
        words = summary_words(result)
        self.assertEqual(len(lines), len(words), "\n".join(map(str, lines)))
        for line, word in zip(lines, words):
            self.assertIsInstance(line, str)
            self.assertTrue(line.startswith(word), f"{line!r} should start with {word!r}")
        algorithms = result["settings"]["algorithms"]
        position = 0
        for row in result["plan"]:
            self.assertIn(row["algorithm"], lines[position])
            position += 1
        for stack in LIMITS_DIRS:
            for moved in result["limits"][stack]["moved"]:
                line = lines[position]
                self.assertIn(stack, line)
                self.assertIn(moved["algorithm"], line)
                if moved["moved"]:
                    self.assertRegex(line, r"\bmoved\b")
                position += 1
        self.assertEqual(position, len(algorithms) * 3)
        self.assertIn("ML-DSA-44", lines[position])
        position += 5
        for case in result["handling"]["cases"]:
            self.assertIn(case["name"], lines[position])
            self.assertRegex(lines[position], rf"(?<!\d){case['status']}(?!\d)")
            position += 1
        for row in result["latency"]["rows"]:
            self.assertIn(row["algorithm"], lines[position])
            position += 1

    def check_saved_run(self, output: Path, settings: dict) -> dict:
        """Check a run saved by run_cookies or the cookies command in full; return cookies.json."""
        result = json.loads((output / "cookies.json").read_text(encoding="utf-8"))
        self.check_top(result, settings)
        self.assertEqual(result["environment"], transport_load.run_environment())
        self.check_limits(result, output, DEFAULT_FITS_ML_DSA_44_SPLIT)
        self.check_boundary(result, output, DEFAULT_FITS_ML_DSA_44_SPLIT)
        self.check_probes(result, output)
        self.check_handling(result, output)
        self.check_latency(result, output)
        self.check_phase_order(result, output)
        self.check_layout(result, output)
        self.check_nginx_confs(result, output)
        self.check_privacy(output, every_file=False)
        self.check_summary(summary_lines(result), result)
        # cookies.json is written last, after every phase.
        newest = max(path.stat().st_mtime_ns for path in output.rglob("*") if path.is_file())
        self.assertEqual((output / "cookies.json").stat().st_mtime_ns, newest)
        return result


# ---- R8-R15: run_cookies on real stacks -------------------------------------------------

class RunCookiesTests(CookiesCase):
    """One short run_cookies: ES256 only (the fixed probes add ML-DSA-44), both clients."""

    SETTINGS = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct", "browser"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.0, "timeout": 60.0,
                "header_buffers": "32k", "proxy_buffers": "32k", "upstream_keepalive": 8}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.output = cls.directory / "out" / "cookies"  # Created by run_cookies.
        cls.run_dir = cls.directory / "run"
        cls.result, cls.error = None, None
        if transport_cookies is None:
            return
        wait_for_ephemeral_ports()
        try:
            cls.result = transport_cookies.run_cookies(
                cls.output, algorithms=["ES256"], clients=["direct", "browser"],
                concurrency=[1], duration=0.2, warmup=0.0, upstream_keepalive=8,
                run_dir=cls.run_dir)
        except Exception as error:  # Reported by every test instead of failing setUpClass.
            cls.error = error

    def setUp(self):
        module()
        self.assertIsNone(self.error, f"run_cookies raised {self.error!r}")

    def test_saved_run(self):
        self.check_saved_run(self.output, self.SETTINGS)

    def test_returns_what_it_saved(self):
        saved = json.loads((self.output / "cookies.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json.dumps(self.result)), saved)

    def test_settings_repeat_the_run(self):
        bound = inspect.signature(module().run_cookies).bind(self.directory / "new",
                                                             **self.result["settings"])
        self.assertEqual(set(bound.arguments), {"output_dir", *SETTINGS_KEYS})
        self.assertEqual(module().checked_settings(**self.result["settings"]),
                         self.result["settings"])

    def test_es256_pairs_verify_on_both_stacks(self):
        for stack in LIMITS_DIRS:
            for pair in self.result["limits"][stack]["results"]:
                with self.subTest(stack=stack, transport=pair["transport"]):
                    self.assertEqual(pair["outcome"], "verified", pair["evidence"])
                    self.assertIs(self.result["limits"][stack]["moved"][0]["moved"], False)

    def test_browser_latency_cells_are_delivered(self):
        for transport, load in self.loads(self.output).items():
            for cell in token_cells(load):
                with self.subTest(transport=transport, client=cell["client"]):
                    self.assertIs(cell["issue"]["delivered"], True, cell["issue"])
                    self.assertGreater(cell["verified"], 0)
                    self.assertEqual(cell["failed"], 0)
        browser = read_gzip(self.output / "latency-split" / "logs" / "browser.log.gz")
        issues = [record for record in browser_records(browser)
                  if record.get("event") == "load_issue"]
        self.assertTrue(issues)
        for record in issues:
            self.assertEqual(record.get("transport"), "split")
            self.assertIn("jwt.0.1", record["cookie_names"])
            self.assertEqual(token_runs(json.dumps(record)), [])

    def test_stack_run_directories(self):
        for name in STACK_DIRS:
            with self.subTest(stack=name):
                self.assertTrue((self.run_dir / name / "nginx" / "nginx.conf").is_file())
                self.assertTrue((self.run_dir / name / "logs" / "app.log").is_file())
        for stack, directory in LIMITS_DIRS.items():
            logs = self.run_dir / directory / "logs"
            for name in LIMIT_LOGS:
                with self.subTest(stack=stack, log=name):
                    saved = read_gzip(self.output / directory / "logs" / f"{name}.gz")
                    self.assertTrue(read_text(logs / name).startswith(saved))
            self.assertEqual((self.output / directory / "nginx.conf").read_bytes(),
                             (self.run_dir / directory / "nginx" / "nginx.conf").read_bytes())
        for path in LATENCY_RUNS.values():
            name = Path(path).parent.name
            self.assertEqual((self.output / name / "nginx.conf").read_bytes(),
                             (self.run_dir / name / "nginx" / "nginx.conf").read_bytes())

    def test_every_process_stopped(self):
        for name, ports in stack_ports(self.run_dir).items():
            with self.subTest(stack=name):
                self.assertEqual(len(ports), 2, ports)  # The proxy and the application.
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
                    self.assertLessEqual(max(times[first]), min(times[second]),
                                         {name: (min(times[name]), max(times[name]))
                                          for name in (first, second)})

    def test_run_logs_hold_no_token(self):
        for name in STACK_DIRS:
            for log in ("app.log", "proxy-access.log"):
                with self.subTest(stack=name, log=log):
                    text = read_text(self.run_dir / name / "logs" / log)
                    self.assertNotIn("eyJ", text)
                    self.assertEqual(token_runs(text)[:3], [])

    def test_summary_lines_from_the_saved_json(self):
        saved = json.loads((self.output / "cookies.json").read_text(encoding="utf-8"))
        lines = summary_lines(saved)
        self.check_summary(lines, saved)
        self.assertEqual(lines, summary_lines(self.result))


# ---- R16: the cookies command --------------------------------------------------------------

class CookiesCommandTests(CookiesCase):
    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44"], "claims": "oidc", "clients": ["direct"],
                "concurrency": [1], "duration": 0.2, "warmup": 0.0, "timeout": 60.0,
                "header_buffers": "32k", "proxy_buffers": "32k", "upstream_keepalive": 8}
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
        cls.first = run_cli("cookies", "--alg", "ML-DSA-44", "--client", "direct",
                            "--concurrency", "1", "--duration", "0.2", "--warmup", "0",
                            "--upstream-keepalive", "8", "--timeout", "60",
                            "--run-dir", cls.run_dir, "--output-dir", cls.output,
                            cwd=cls.directory)

    def require_first_run(self) -> None:
        self.assertEqual(self.first.returncode, 0, self.first.stderr)

    def check_stopped(self, run_dir: Path) -> None:
        for port in run_ports(run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_first_run_exits_0_and_saves_the_run(self):
        # Exit 0 also when pairs were rejected: rejections are results, and the run records
        # them (each with its rejecting layer) instead of failing.
        self.require_first_run()
        self.assertNotRegex(self.first.stderr, ERROR_LINE)
        saved = self.check_saved_run(self.output, self.SETTINGS)
        outcomes = {(stack, pair["algorithm"], pair["transport"]): pair["outcome"]
                    for stack in LIMITS_DIRS for pair in saved["limits"][stack]["results"]}
        for stack in LIMITS_DIRS:
            if stack == "raised" or DEFAULT_FITS_ML_DSA_44_SPLIT:
                self.assertEqual(outcomes[(stack, "ML-DSA-44", "split")], "verified")

    def test_prints_the_summary_then_the_output_directory(self):
        self.require_first_run()
        saved = json.loads((self.output / "cookies.json").read_text(encoding="utf-8"))
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
        result = run_cli("cookies", "--settings", self.output / "cookies.json", "--alg", "ES256",
                         "--claims", "essential", "--warmup", "0.1", "--timeout", "30",
                         "--run-dir", run_dir, "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = {**self.SETTINGS, "algorithms": ["ES256"], "claims": "essential",
                    "warmup": 0.1, "timeout": 30.0}
        self.check_saved_run(output, settings)
        self.check_stopped(run_dir)

    def test_saved_latency_settings_repeat_with_load(self):
        self.require_first_run()
        wait_for_ephemeral_ports()
        path = self.output / "latency-split" / "load.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        output = self.directory / "load-again"
        result = run_cli("load", "--settings", path, "--run-dir", self.directory / "load-run",
                         "--output-dir", output, cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        again = json.loads((output / "load.json").read_text(encoding="utf-8"))
        self.assertEqual(again["settings"], saved["settings"])
        self.assertEqual(again["settings"]["transport"], "split")
        for cell in token_cells(again):
            with self.subTest(algorithm=cell["algorithm"]):
                self.assertGreater(cell["verified"], 0)
                self.assertEqual(cell["failed"], 0)

    def test_help_lists_every_option(self):
        result = run_cli("cookies", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in COOKIES_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)
        choices = re.search(r"--claims \{([a-z,]+)\}", result.stdout)
        self.assertIsNotNone(choices, result.stdout)
        self.assertEqual(set(choices[1].split(",")), set(CLAIM_SET_NAMES))

    def test_usage_errors_exit_2_before_anything_starts(self):
        # Without the cookies command, argparse would reject every case for the wrong reason.
        self.assertEqual(run_cli("cookies", "--help", cwd=self.directory).returncode, 0)
        bad = self.directory / "bad-settings"
        bad.mkdir()
        valid = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct"],
                 "concurrency": [1], "duration": 0.1, "warmup": 0.0, "timeout": 30.0,
                 "header_buffers": "32k", "proxy_buffers": "32k", "upstream_keepalive": 8}
        files = {
            "not-json.json": "{not json",
            "no-settings.json": json.dumps({"results": []}),
            "list-settings.json": json.dumps({"settings": [1]}),
            "unknown-key.json": json.dumps({"settings": {**valid, "transport": "split"}}),
            "bad-concurrency.json": json.dumps({"settings": {**valid, "concurrency": [0]}}),
            "bad-alg.json": json.dumps({"settings": {**valid, "algorithms": ["HS256"]}}),
            "bad-claims.json": json.dumps({"settings": {**valid, "claims": "huge"}}),
            "bad-duration.json": json.dumps({"settings": {**valid, "duration": 0}}),
            "bad-header-buffers.json": json.dumps({"settings": {**valid,
                                                                "header_buffers": "big"}}),
            "null-header-buffers.json": json.dumps({"settings": {**valid,
                                                                 "header_buffers": None}}),
            "bad-proxy-buffers.json": json.dumps({"settings": {**valid, "proxy_buffers": "big"}}),
            "null-proxy-buffers.json": json.dumps({"settings": {**valid,
                                                                "proxy_buffers": None}}),
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
            "invalid proxy buffers": ["--proxy-buffers", "16kb", "--output-dir", "{out}"],
            "keepalive 0": ["--upstream-keepalive", "0", "--output-dir", "{out}"],
            "keepalive 1025": ["--upstream-keepalive", "1025", "--output-dir", "{out}"],
            "missing settings": ["--settings", bad / "missing.json", "--output-dir", "{out}"],
            **{f"settings {name}": ["--settings", bad / name, "--output-dir", "{out}"]
               for name in files},
        }
        if (S3_01_RUN / "load.json").is_file():  # A load.json has settings cookies does not take.
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
                result = run_cli("cookies", *arguments, "--run-dir", run_dir, cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(run_dir.exists(), "a stack was started")
                self.assertFalse(output.exists(), "the output directory was created")
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
        self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_runtime_failure_exits_1_and_stops_every_process(self):
        run_dir, output = self.directory / "failing-run", self.directory / "failing"
        with tempfile.TemporaryDirectory() as empty:
            result = run_cli("cookies", "--alg", "ES256", "--client", "direct", "--concurrency",
                             "1", "--duration", "0.1", "--warmup", "0", "--timeout", "30",
                             "--run-dir", run_dir, "--output-dir", output, cwd=self.directory,
                             environment=cli_environment(PLAYWRIGHT_BROWSERS_PATH=empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        self.assertFalse((output / "cookies.json").exists())
        self.check_stopped(run_dir)

    def test_signals_stop_the_run_and_every_process(self):
        # SIGINT while the size-limits phase sends its pairs, SIGTERM during a latency run.
        for signum, stack, marker in ((signal.SIGINT, "limits-default", ISSUE_PATH),
                                      (signal.SIGTERM, "latency-cookie", "timing=1")):
            with self.subTest(signal=signum.name):
                wait_for_ephemeral_ports()
                run_dir = self.directory / f"signal-{signum.name}"
                output = self.directory / f"signal-out-{signum.name}"
                command = [sys.executable, str(SCRIPT), "cookies", "--alg", "ES256", "--client",
                           "direct", "--concurrency", "1", "--duration", "20", "--warmup", "0",
                           "--run-dir", str(run_dir), "--output-dir", str(output)]
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
                self.assertFalse((output / "cookies.json").exists())
                self.assertTrue(run_ports(run_dir))
                self.check_stopped(run_dir)


class OtherCommandsTests(unittest.TestCase):
    """R16, R22: the other commands keep their help, options, and defaults."""

    def help_output(self, script: Path, command: str, cwd: Path) -> str:
        environment = {key: value for key, value in cli_environment(COLUMNS="100",
                                                                     NO_COLOR="1").items()
                       if key not in ("FORCE_COLOR", "PYTHON_COLORS")}
        result = subprocess.run([sys.executable, str(script), command, "--help"], cwd=cwd,
                                env=environment, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def base_scripts(self, directory: str) -> Path:
        try:
            archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar",
                                      BASE_COMMIT, "scripts", "transport", "fixtures"],
                                     capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(directory, filter="data")
        return Path(directory) / "scripts" / "transport_stack.py"

    def test_other_commands_keep_their_help(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self.base_scripts(directory)
            for command in ("check", "tokens", "sweep", "serve", "versions"):
                with self.subTest(command=command):
                    self.assertEqual(self.help_output(SCRIPT, command, Path(directory)),
                                     self.help_output(base, command, Path(directory)))

    def test_load_and_claims_keep_every_option(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self.base_scripts(directory)
            for command in ("load", "claims"):
                with self.subTest(command=command):
                    old = self.help_output(base, command, Path(directory))
                    new = self.help_output(SCRIPT, command, Path(directory))
                    self.assertLessEqual(set(re.findall(r"--[a-z][a-z-]+", old)),
                                         set(re.findall(r"--[a-z][a-z-]+", new)))
            new = self.help_output(SCRIPT, "load", Path(directory))
        choices = re.search(r"--transport \{([a-z,]+)\}", new)
        self.assertIsNotNone(choices, new)
        self.assertEqual(choices[1].split(","), ["bearer", "cookie", "split"])


# ---- R7: the load command's split transport -------------------------------------------------

class LoadSplitCommandTests(unittest.TestCase):
    SETTINGS = {"algorithms": ["ES256", "ML-DSA-44", "SLH-DSA-SHA2-128f"], "transport": "split",
                "clients": ["direct", "browser"], "claims": "oidc", "concurrency": [1],
                "duration": 0.2, "warmup": 0.0, "reference": "ES256", "size_controls": False,
                "timeout": 30.0, "proxy_buffers": None, "header_buffers": "32k",
                "upstream_keepalive": 8}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        wait_for_ephemeral_ports()
        cls.ports, cls.output = free_ports(2), cls.directory / "split"
        cls.run_dir = cls.directory / "run"
        cls.result = run_cli("load", "--transport", "split", "--alg", "ML-DSA-44",
                             "SLH-DSA-SHA2-128f", "--client", "direct", "browser", "--claims",
                             "oidc", "--concurrency", "1", "--duration", "0.2", "--warmup", "0",
                             "--no-size-controls", "--header-buffers", "32k",
                             "--upstream-keepalive", "8", "--timeout", "30",
                             *port_options(cls.ports), "--run-dir", cls.run_dir,
                             "--output-dir", cls.output, cwd=cls.directory)

    def setUp(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        self.saved = json.loads((self.output / "load.json").read_text(encoding="utf-8"))

    def test_settings_and_output(self):
        self.assertEqual(self.saved["settings"], self.SETTINGS)
        self.assertIn(f"Saved the results to {self.output}", self.result.stdout)
        for port in self.ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")

    def test_cells(self):
        cells = token_cells(self.saved)
        self.assertEqual([(cell["client"], cell["algorithm"]) for cell in cells],
                         [(client, name) for client in ("direct", "browser")
                          for name in self.SETTINGS["algorithms"]])
        for cell in cells:
            with self.subTest(client=cell["client"], algorithm=cell["algorithm"]):
                total = token_bytes(cell["algorithm"], claim_set("oidc"))
                self.assertEqual(cell["token_bytes"], total)
                self.assertEqual(cell["bytes"]["header_line"], split_line_bytes(total))
                issue = cell["issue"]
                # The browser's split issue goes through nginx's default proxy_buffer_size here:
                # SLH-DSA-SHA2-128f's six Set-Cookie headers never fit, and ML-DSA-44's two fit
                # this Mac's 16 KiB but not WSL2's 4 KiB.
                if (cell["client"] == "direct" or cell["algorithm"] == "ES256"
                        or (cell["algorithm"] == "ML-DSA-44" and DEFAULT_FITS_ML_DSA_44_SPLIT)):
                    self.assertIs(issue["delivered"], True, issue)
                if issue["delivered"]:
                    self.assertEqual(issue["status"], 200)
                    self.assertGreater(cell["verified"], 0)
                    self.assertEqual(cell["failed"], 0)
                    self.assertGreaterEqual(cell["bytes"]["app_received_headers"],
                                            split_line_bytes(total))
                else:
                    self.assertEqual(cell["requests"], 0)
                    self.assertTrue(issue["error"])
                if issue["status"] != 200:
                    self.assertIs(issue["delivered"], False)

    def test_issues_and_logs(self):
        logs = self.run_dir / "logs"
        access = read_text(logs / "proxy-access.log")
        deliveries = [query_of(target).get("delivery")
                      for target in re.findall(r'"GET (\S+) HTTP', access)
                      if urlsplit(target).path == ISSUE_PATH]
        self.assertIn("split", deliveries)  # The browser cells.
        self.assertIn("body", deliveries)  # The direct cells.
        app = read_text(logs / "app.log")
        timed = [line for line in app.splitlines() if "timing=1" in line and " 200 " in line]
        self.assertTrue(timed)
        for line in timed:
            self.assertRegex(line, r"chunks=(\d+)/\1$")
        for name in ("app.log", "proxy-access.log"):
            text = read_text(logs / name)
            self.assertNotIn("eyJ", text)
            self.assertEqual(token_runs(text)[:3], [])
        issues = [record for record in browser_records(read_text(logs / "browser.log"))
                  if record.get("event") == "load_issue"]
        self.assertEqual(len(issues), len(self.SETTINGS["algorithms"]))
        for record in issues:
            with self.subTest(algorithm=record.get("algorithm")):
                self.assertEqual(record.get("transport"), "split")
                self.assertIsInstance(record["cookie_names"], list)
                self.assertEqual(token_runs(json.dumps(record)), [])
                self.assertNotIn("eyJ", json.dumps(record))

    def test_raw_rows_hold_no_token(self):
        text = read_gzip(self.output / "raw.csv.gz")
        self.assertNotIn("eyJ", text)
        self.assertEqual(token_runs(text)[:3], [])


# ---- R17: Makefile -------------------------------------------------------------------------

class MakefileTests(unittest.TestCase):
    RECIPE = ('\t$(STACK) cookies --header-buffers 32k --proxy-buffers 32k --upstream-keepalive '
              '64 --duration 2 --output-dir "$(COOKIES_DIR)"')

    @classmethod
    def setUpClass(cls):
        cls.text = MAKEFILE.read_text(encoding="utf-8")

    def make(self, *arguments: str) -> subprocess.CompletedProcess:
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not installed")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MAKEFLAGS", "MFLAGS", "LOAD_DIR", "CLAIMS_DIR",
                                      "COOKIES_DIR")}
        return subprocess.run([make, "--no-print-directory", *arguments], cwd=REPO,
                              env=environment, capture_output=True, text=True, timeout=60)

    def test_target_is_phony_and_in_help(self):
        phony = next((line for line in self.text.splitlines() if line.startswith(".PHONY:")), "")
        self.assertIn("cookies", phony.split())
        result = self.make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(line.startswith("make cookies")
                            for line in result.stdout.splitlines()), result.stdout)

    def test_recipe_and_output_directory(self):
        self.assertIn("COOKIES_DIR ?= results/cookies/$(shell date -u +%Y%m%dT%H%M%SZ)"
                      "-$(LOAD_PLATFORM)", self.text.splitlines())
        blocks = make_blocks(self.text)
        self.assertIn("cookies", blocks)
        self.assertEqual(blocks["cookies"][1:], [self.RECIPE])
        result = self.make("-n", "cookies", "COOKIES_DIR=results/cookies/dry-run",
                           "PYTHON=python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/transport_stack.py cookies --header-buffers 32k --proxy-buffers '
                      '32k --upstream-keepalive 64 --duration 2 --output-dir '
                      '"results/cookies/dry-run"', result.stdout)
        if sys.platform == "darwin":
            result = self.make("-n", "cookies", "PYTHON=python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'--output-dir "results/cookies/\d{8}T\d{6}Z-macos"')

    def test_comment_above_the_target(self):
        lines = self.text.splitlines()
        index = next((position for position, line in enumerate(lines)
                      if line.startswith("cookies:")), None)
        self.assertIsNotNone(index, "the Makefile has no cookies target")
        above = []
        for line in reversed(lines[:index]):
            if not line.strip():
                break
            above.append(line)
        self.assertTrue(any(line.startswith("#") for line in above), above)

    def test_existing_targets_unchanged(self):
        before = git_show("Makefile")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        old, new = make_blocks(before), make_blocks(self.text)
        for target, lines in old.items():
            with self.subTest(target=target):
                self.assertIn(target, new)
                if target == "help":  # help gains the cookies line.
                    for line in lines[1:]:
                        self.assertIn(line, new[target])
                else:
                    self.assertEqual(new[target], lines)
        assignments = [line for line in before.splitlines()
                       if re.match(r"^[A-Z_]+ *(\?|:)?=", line)]
        self.assertTrue(any(line.startswith("CLAIMS_DIR ") for line in assignments))
        for line in assignments:
            with self.subTest(line=line):
                self.assertIn(line, self.text.splitlines())
        phony_before = next(line for line in before.splitlines() if line.startswith(".PHONY:"))
        phony_after = next(line for line in self.text.splitlines() if line.startswith(".PHONY:"))
        self.assertLessEqual(set(phony_before.split()), set(phony_after.split()))


# ---- R18: the committed run --------------------------------------------------------------

class CommittedRunTests(CookiesCase):
    @classmethod
    def setUpClass(cls):
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def setUp(self):
        self.assertIsNotNone(self.saved, "no macOS run committed under "
                                         "results/cookies/<YYYYMMDDTHHMMSSZ>-macos/")

    def test_exactly_one_run(self):
        runs = sorted(visible_names(COOKIES_RESULTS))
        self.assertEqual(len(runs), 1, runs)
        self.assertRegex(runs[0], RUN_NAME)
        tracked = git("ls-files", "--", "results/cookies")
        self.assertIn(f"results/cookies/{runs[0]}/cookies.json", (tracked or "").split())

    def test_environment(self):
        environment = self.saved["environment"]
        self.assertTrue(environment["platform"].startswith("macOS"))
        self.assertEqual(environment["page_size_bytes"], 16384)
        self.assertRegex(str(environment["git_commit"]), HEX_COMMIT)
        self.assertEqual(len(environment["git_commit"]), 40)
        self.assertIs(environment["git_dirty_scripts_or_fixtures"], False)

    def test_settings_and_structure(self):
        self.check_top(self.saved, MAKE_SETTINGS)

    def test_limits(self):
        self.check_limits(self.saved, self.run_dir, default_fits=True)  # Recorded on this Mac.
        for stack in LIMITS_DIRS:
            pair = next(entry for entry in self.saved["limits"][stack]["results"]
                        if (entry["algorithm"], entry["transport"]) == ("ML-DSA-44", "split"))
            with self.subTest(stack=stack):
                self.assertEqual(pair["outcome"], "verified", pair["evidence"])

    def test_boundary_probes_and_handling(self):
        self.check_boundary(self.saved, self.run_dir, default_fits=True)
        self.check_probes(self.saved, self.run_dir)
        self.check_handling(self.saved, self.run_dir)
        self.assertEqual([case["status"] for case in self.saved["handling"]["cases"]],
                         [CASE_STATUSES[name] for name in CASE_NAMES])

    def test_latency(self):
        self.check_latency(self.saved, self.run_dir)
        self.check_phase_order(self.saved, self.run_dir)
        for name, load in self.loads(self.run_dir).items():
            with self.subTest(run=name):  # make cookies with TMPDIR unset: stacks in /tmp.
                self.assertTrue(str(load["run_dir"]).startswith("/tmp/"), load["run_dir"])

    def test_files_and_nginx_confs(self):
        self.check_layout(self.saved, self.run_dir)
        self.check_nginx_confs(self.saved, self.run_dir)
        for path in self.run_dir.rglob("*"):
            if path.is_file():
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertLessEqual(path.stat().st_size, 10 * MIB)
                    self.assertFalse(path.name.endswith(".log"))
        tracked = git("ls-files", "-z", "--", "results/cookies")
        for path in (tracked or "").split("\0"):
            self.assertFalse(path.endswith(".log"), path)

    def test_privacy(self):
        self.check_privacy(self.run_dir, every_file=True)

    def test_summary_lines(self):
        self.check_summary(summary_lines(self.saved), self.saved)


# ---- R19: MITIGATION_RESULTS.md ----------------------------------------------------------

class MitigationDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(MITIGATION_DOC)
        found = committed_run()
        cls.run_dir, cls.saved = found if found else (None, None)

    def require_run(self) -> dict:
        self.assertIsNotNone(self.saved, "no committed macOS run under results/cookies/")
        return self.saved

    def body(self) -> str:
        body = section(self.text, "Cookie splitting")
        self.assertIsNotNone(body, "missing heading: ## Cookie splitting")
        return body

    def part(self, title: str) -> str:
        body = section(self.body(), title, level=3)
        self.assertIsNotNone(body, f"missing heading: ### {title}")
        return body

    def section_intro(self) -> str:
        body = self.body()
        first = next((index for depth, _, index in headings(body.splitlines()) if depth == 3),
                     None)
        return "\n".join(body.splitlines()[:first])

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
        level_two = [name for depth, name, _ in headings(self.text.splitlines()) if depth == 2]
        self.assertIn("Smaller claim sets", level_two)
        self.assertIn("Cookie splitting", level_two)
        self.assertEqual(level_two.index("Cookie splitting"),
                         level_two.index("Smaller claim sets") + 1)

    def test_document_introduction(self):
        intro = self.text.split("## Smaller claim sets", 1)[0]
        self.assertIn("S3-02", intro)
        self.assertIn("first", intro.lower())
        paragraphs = [block for block in re.split(r"\n\s*\n", intro)
                      if block.strip() and not block.lstrip().startswith("#")]
        self.assertTrue(paragraphs)
        first = paragraphs[0]
        self.assertIn("cookies", first)
        self.assertIn("first two", first.lower())
        lines = intro.splitlines()
        cookie_bullets = [line for line in lines if line.startswith("- ")
                          and "cookie splitting" in line.lower()]
        self.assertEqual(len(cookie_bullets), 1, cookie_bullets)
        self.assertNotIn("not covered yet", cookie_bullets[0].lower())
        self.assertTrue(any(word in cookie_bullets[0].lower()
                            for word in ("nginx", "header", "proxy_buffer_size")),
                        cookie_bullets[0])
        # The reference-token bullet is covered by its own run, so only its presence is checked.
        self.assertTrue(any(line.startswith("- ") and "reference token" in line.lower()
                            for line in lines))
        self.assertTrue(any("cookie splitting" in line and "not" in line
                            for line in self.text.lower().splitlines()))

    def test_smaller_claim_sets_unchanged(self):
        before = git_show("MITIGATION_RESULTS.md")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        old = section(before, "Smaller claim sets")
        new = section(self.text, "Smaller claim sets")
        self.assertIsNotNone(new)
        self.assertEqual(new.rstrip(), old.rstrip())

    def test_section_introduction(self):
        intro = self.section_intro()
        lowered = intro.lower()
        self.assertIn("question", lowered)
        self.assertTrue(any(line.startswith("- ") for line in intro.splitlines()))
        for term in ("ephemeral", "experiment key", "production", "machine state", "candidate"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
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
        links = relative_links(self.text)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((REPO / link.split("#", 1)[0]).exists(), link)
        self.require_run()
        resolved = {(REPO / link.split("#", 1)[0]).resolve() for link in relative_links(
            self.body())}
        wanted = [self.run_dir / "cookies.json"]
        for directory in LIMITS_DIRS.values():
            wanted += [self.run_dir / directory / "nginx.conf",
                       *(self.run_dir / directory / "logs" / f"{name}.gz"
                         for name in LIMIT_LOGS)]
        for path in LATENCY_RUNS.values():
            directory = self.run_dir / Path(path).parent
            wanted += [directory / "load.json", directory / "raw.csv.gz"]
        for path in wanted:
            with self.subTest(target=str(path.relative_to(REPO))):
                self.assertIn(path.resolve(), resolved)

    def test_format(self):
        body = self.part("Format")
        # The name format as cookies.json's format.cookie_name writes it, or as R1 does
        # ('jwt.' + index + '.' + count) with an example chunk name.
        lowered = body.lower()
        self.assertTrue("jwt.<index>.<count>" in body
                        or (re.search(r"\bjwt\.\d+\.\d+\b", body) is not None
                            and "index" in lowered and "count" in lowered), body)
        self.assertTrue(contains_number(body, 4000))

    def test_chunk_plan(self):
        body = self.part("Chunk plan")
        self.assertIn("calculated", body.lower())
        for row in self.require_run()["plan"]:
            with self.subTest(algorithm=row["algorithm"]):
                self.assertTrue(any(shows_count(line, row["token_bytes"])
                                    for line in self.rows_naming(body, row["algorithm"])))

    def test_size_limits(self):
        body = self.part("Size limits")
        lowered = body.lower()
        for term in ("8,192", "32,768", "proxy_buffer_size", "16 KiB", "4 KiB"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        for term in ("derived", "wsl2", "moved", "boundary", "probe"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        run = self.require_run()
        for stack in LIMITS_DIRS:
            for entry in run["limits"][stack]["results"]:
                if entry["outcome"] != "rejected":
                    continue
                with self.subTest(pair=(stack, entry["algorithm"], entry["transport"])):
                    words = LAYER_WORDS[entry["rejected_by"]]
                    self.assertTrue(any(word in line.lower() for word in words
                                        for line in self.rows_naming(body, entry["algorithm"])))
        boundary = run["boundary"]
        for key in ("largest_verified", "first_rejected"):
            if boundary[key] is not None:
                with self.subTest(boundary=key):
                    self.assertTrue(shows_count(body, boundary[key]["token_bytes"]))
        if boundary["first_rejected"] is not None:
            words = LAYER_WORDS[boundary["first_rejected"]["rejected_by"]]
            self.assertTrue(any(word in lowered for word in words))
        for probe in run["probes"]["per_cookie"]:
            with self.subTest(probe=("per_cookie", probe["name"])):
                self.assertTrue(shows_count(body, probe["bytes"]["largest_name_value"])
                                or shows_count(body, probe["token_bytes"]))
        for probe in run["probes"]["cookie_count"]:
            with self.subTest(probe=("cookie_count", probe["name"])):
                self.assertTrue(contains_number(body, probe["chunks"]))
                self.assertTrue(contains_number(body, probe["cookies_stored"]))

    def test_missing_and_reordered_chunks(self):
        body = self.part("Missing and reordered chunks")
        rows = table_rows(body)
        for case in self.require_run()["handling"]["cases"]:
            with self.subTest(case=case["name"]):
                names = (case["name"], case["name"].replace("_", " "))
                self.assertTrue(any(any(name in row.lower() for name in names)
                                    and contains_number(row, case["status"]) for row in rows))
        lowered = body.lower()
        self.assertIn("chromium", lowered)
        self.assertIn("order", lowered)

    def test_latency(self):
        body = self.part("Latency")
        lowered = body.lower()
        for term in ("noise", "eddsa", "transfer", "verification", "calculated",
                     "not measured"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        run = self.require_run()
        for row in run["latency"]["rows"]:
            with self.subTest(row=(row["client"], row["concurrency"], row["algorithm"])):
                lines = self.rows_naming(body, row["algorithm"])
                means = row["mean_ms"]
                sides = [side for side in TRANSPORTS if means[side] is not None]
                self.assertTrue(any(all(shows_ms(line, means[side]["total"]) for side in sides)
                                    and (row["difference_ms"] is None
                                         or shows_ms(line, row["difference_ms"]["total"]))
                                    for line in lines))
                for side in sides:
                    for value in (row["median_ms"][side], row["p95_ms"][side],
                                  row["throughput_rps"][side]):
                        self.assertTrue(any(shows(line, value) for line in lines), value)
        shared = [row for row in table_rows(body) if not any(name in row for name in NAMES)]
        for entry in run["latency"]["network_model"]:
            with self.subTest(model=entry["algorithm"]):
                lines = self.rows_naming(body, entry["algorithm"])
                for modeled in entry["modeled"]:
                    profile_rows = [row for row in shared if shows(row, modeled["uplink_mbps"])
                                    and shows(row, modeled["rtt_ms"])]
                    self.assertTrue(any(shows(line, modeled["extra_ms"])
                                        for line in lines + profile_rows), modeled)

    def test_reproduce(self):
        body = self.part("Reproduce")
        lines = [line.strip() for block in code_blocks(body) for line in block.splitlines()]
        self.assertTrue(any(line.startswith("make cookies") for line in lines))
        command = re.compile(r"transport_stack\.py[\"']?\s+cookies\s+--header-buffers\s+32k\s+"
                             r"--proxy-buffers\s+32k\s+--upstream-keepalive\s+64\s+--duration\s+2"
                             r"\s+--output-dir\s+[\"']?results/cookies/.*-macos")
        self.assertTrue(any(command.search(line) for line in lines))
        run = self.require_run()
        committed = self.run_dir.relative_to(REPO).as_posix()
        self.assertTrue(any("cookies" in line and "--settings" in line
                            and f"{committed}/cookies.json" in line for line in lines))
        self.assertTrue(any(re.search(rf"\bload\s+--settings\s+[\"']?{re.escape(committed)}/"
                                      r"latency-(cookie|split)/load\.json", line)
                            for line in lines))
        shown = set(lines)
        for line in summary_lines(run):
            with self.subTest(line=line):
                self.assertIn(line.strip(), shown)

    def test_limitations(self):
        body = self.part("Limitations")
        lowered = body.lower()
        self.assertTrue(any("WSL2" in line and "not" in line for line in body.splitlines()))
        for term in ("loopback", "one run", "chromium", "http/1.1", "tls", "http/2", "s3-04",
                     "stale", "conflicting", "buffer", "keepalive", "browser.log", "truncated"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertTrue(any(term in lowered for term in ("machine state", "state of the machine",
                                                         "other candidate", "idle")))


# ---- R20: TRANSPORT.md --------------------------------------------------------------------

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

    def test_token_endpoints_document_split(self):
        body = self.section(self.text, "Token endpoints", 3)
        for term in ("delivery=split", "chunks", "jwt.<index>.<count>", "split", "missing",
                     "received", "401", "400"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        plain = body.replace("`", "")
        self.assertIn("other than cookie, body, or split", plain)
        self.assertNotIn("other than cookie or body", plain)

    def test_application_log_fields(self):
        body = self.section(self.text, "Application log fields", 3)
        self.assertIn("chunks", body)

    def test_browser_log(self):
        body = self.section(self.text, "Browser log", 3)
        self.assertIn("split", body)

    def test_upstream_keepalive_bullet(self):
        body = self.section(self.text, "Configuration that is not a default", 3)
        bullets = [line for line in body.splitlines()
                   if line.startswith("- ") and "--upstream-keepalive" in line]
        self.assertTrue(bullets)
        for term in ("cookies", "claims", "--proxy-buffers", "--header-buffers"):
            with self.subTest(term=term):
                self.assertTrue(any(term in line for line in bullets), bullets)

    def test_load_transport_row_lists_split(self):
        body = self.section(self.text, "The load command", 3)
        rows = [row for row in table_rows(body) if row.startswith("| `--transport")]
        self.assertEqual(len(rows), 1, rows)
        self.assertIn("split", rows[0])

    def test_cookies_command_subsection(self):
        run_check = self.section(self.text, "Run the check", 2)
        order = [name for depth, name, _ in headings(run_check.splitlines()) if depth == 3]
        self.assertIn("The claims command", order)
        self.assertIn("The cookies command", order)
        self.assertEqual(order.index("The cookies command"),
                         order.index("The claims command") + 1)
        body = self.section(run_check, "The cookies command", 3)
        self.assertTrue(any(re.search(r"transport_stack\.py[\"']?\s+cookies\b", block)
                            for block in code_blocks(body)))
        for option in COOKIES_OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, body)
        lines = body.splitlines()
        for option, defaults in (("--duration", (5,)), ("--warmup", (1,)), ("--timeout", (60,)),
                                 ("--concurrency", (1, 4))):
            with self.subTest(default=option):
                self.assertTrue(any(option in line and all(contains_number(line, value)
                                                           for value in defaults)
                                    for line in lines))
        for option, default in (("--claims", "oidc"), ("--header-buffers", "32k"),
                                ("--proxy-buffers", "32k")):
            with self.subTest(default=option):
                self.assertTrue(any(option in line and default in line for line in lines))
        self.assertTrue(any("--output-dir" in line and "required" in line.lower()
                            for line in lines))
        lowered = body.lower()
        for term in ("exit", "usage", "boundary", "probe", "latency", "ml-dsa-44", "es256",
                     "180", "181", "cookies.json", "limits-default", "limits-raised",
                     "latency-cookie", "latency-split", "token", "scripts/transport_cookies.py",
                     "](mitigation_results.md"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_cites_kdomainmaxcookies(self):
        lines = [line for line in self.text.splitlines() if "kDomainMaxCookies" in line]
        self.assertTrue(lines)
        self.assertTrue(any(contains_number(line, DOMAIN_MAX_COOKIES)
                            and re.search(rf"\]\({re.escape(CHROMIUM_SOURCE)}\S+\)", line)
                            for line in lines), lines)


# ---- R21: PROGRESS.md, README.md, TRANSPORT_RESULTS.md ------------------------------------

class ProgressTests(unittest.TestCase):
    def test_s3_02_items_and_status(self):
        body = section(PROGRESS.read_text(encoding="utf-8"), "S3-02", level=3)
        self.assertIsNotNone(body, "missing heading: ### S3-02")
        items = re.findall(r"(?m)^- \[( |x)\] (.*)$", body)
        self.assertEqual([text for _, text in items], list(S3_02_ITEMS))
        # Smaller claim sets and cookie splitting are ticked; reference tokens ticks its own item.
        self.assertEqual([mark for mark, _ in items[:2]], ["x", "x"])
        status = [line for line in body.splitlines() if line.startswith("**Status:**")]
        self.assertEqual(len(status), 1, status)
        for term in ("claims", "cookies", "macOS", "MITIGATION_RESULTS.md", "ML-DSA-44", "WSL2",
                     "641"):
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


class ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = README.read_text(encoding="utf-8")

    def test_project_status(self):
        status = section(self.text, "Project status")
        self.assertIsNotNone(status, "missing heading: ## Project status")
        self.assertIn("S3-02", status)
        lowered = status.lower()
        self.assertIn("smaller claim sets", lowered)
        self.assertIn("reference token", lowered)
        self.assertTrue(any("cookie splitting" in line.lower() and "MITIGATION_RESULTS.md" in line
                            for line in status.splitlines()), status)
        # 6f50c93 said both mitigations follow later; cookie splitting no longer does.
        self.assertNotIn("Cookie splitting and reference tokens follow", status)
        before = git_show("README.md")
        if before is not None:
            for link in relative_links(section(before, "Project status") or ""):
                self.assertIn(link, relative_links(status))

    def test_make_shortcuts(self):
        shortcuts = section(self.text, "Make shortcuts")
        self.assertIsNotNone(shortcuts, "missing heading: ## Make shortcuts")
        lines = [line.strip() for block in code_blocks(shortcuts) for line in block.splitlines()]
        cookies = [line for line in lines if line.startswith("make cookies")]
        self.assertEqual(len(cookies), 1, lines)
        self.assertIn("#", cookies[0])
        self.assertIn("results/cookies/<time>/", cookies[0])
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


# ---- R22, R23: what stays unchanged, and where the code goes -------------------------------

class UnchangedTests(unittest.TestCase):
    def require(self, value):
        if value is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return value

    def test_pinned_files_results_and_tests_unchanged(self):
        tests = self.require(git("ls-tree", "--name-only", BASE_COMMIT, "tests/")).split()
        # The claims tests were loosened later for S3-03, so that file is not frozen here.
        tests = [path for path in tests if path != "tests/test_transport_claims.py"]
        self.assertTrue(tests)
        # S3-04 adds HTTPS and HTTP/2 rendering and new sweep runs, so the nginx template and
        # results/transport are not frozen here; test_template_keeps_its_limits still checks
        # the template's limits. The test page gained a read-only mode later
        # (tests/test_transport_pages.py checks it), so it is not frozen here either.
        paths = ["transport/stack.json", "requirements.txt", "transport/requirements.txt",
                 "transport/conda-requirements.txt",
                 "transport/setup.sh", "fixtures/claims.json",
                 "fixtures/claims_oidc.json", "fixtures/claims_essential.json",
                 "END_TO_END_RESULTS.md", "RESULTS.md", "results/load",
                 "results/claims", ":(glob)results/2026110*/**", *tests]
        changed = self.require(git("diff", "--name-only", BASE_COMMIT, "--", *paths)).split()
        untracked = self.require(git("ls-files", "--others", "--exclude-standard", "--",
                                     *paths)).split()
        self.assertEqual(changed + untracked, [])

    def test_no_new_run_outside_results_cookies(self):
        for directory in ("results/load", "results/claims", "results/transport"):
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

    def test_cookies_module_added_and_nothing_removed(self):
        # Later mitigations (reference tokens) add their own modules, so this checks only that
        # the cookies module is present and no earlier file is gone.
        for directory, added in (("scripts", {"transport_cookies.py"}), ("fixtures", set())):
            with self.subTest(directory=directory):
                listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:{directory}"))
                on_disk = {path.name for path in (REPO / directory).iterdir()
                           if path.is_file() and not path.name.startswith(".")}
                self.assertLessEqual({*listing.split(), *added}, on_disk)

    def test_transport_results_gains_links(self):
        # S3-04 adds its HTTPS and HTTP/2 results to TRANSPORT_RESULTS.md, so only the links
        # to MITIGATION_RESULTS.md are checked here.
        before = self.require(git_show("TRANSPORT_RESULTS.md")).splitlines()
        after = TRANSPORT_RESULTS.read_text(encoding="utf-8").splitlines()
        added = [line for line in after if line not in before]
        self.assertTrue(any("](MITIGATION_RESULTS.md" in line for line in added), added)


if __name__ == "__main__":
    unittest.main()
