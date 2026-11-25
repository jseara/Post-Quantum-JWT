"""Check S3-04's HTTPS and HTTP/2 transport end to end: start_tls_stack with its certificate and
experiment key, the rendered nginx.conf, http_get and client_context against nginx, run_check
and run_sweep over HTTPS and HTTP/2 with Chromium, run_protocols and the protocols command, the
Makefile, the committed macOS run, TRANSPORT_RESULTS.md, TRANSPORT.md, PROGRESS.md, README.md,
RECOMMENDATIONS.md, and what stays unchanged; no timing thresholds."""

import ast
from collections import Counter
import dataclasses
from datetime import datetime, timedelta
import getpass
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qsl, urlsplit

from scripts import transport_load, transport_stack
from scripts.algorithms import ADAPTER_LIST
from scripts.transport_stack import (Stack, http_get, load_manifest, manifest_layers,
                                     nginx_string, run_check, start_stack)
from scripts.transport_sweep import run_sweep, write_results

try:
    from scripts import transport_tls
    TLS_IMPORT_ERROR = None
except Exception as error:  # Before S3-04's TLS helpers are built: tests fail, not vanish.
    transport_tls, TLS_IMPORT_ERROR = None, error

try:
    from scripts import transport_protocols
    PROTOCOLS_IMPORT_ERROR = None
except Exception as error:  # Before S3-04's protocols command is built.
    transport_protocols, PROTOCOLS_IMPORT_ERROR = None, error


from tests.moved_docs import (HISTORY, MOVE_EDITED_TESTS, DocPath, changed_moved, moved, repo_file,
                               split_moved)
REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
MAKEFILE = REPO / "Makefile"
TRANSPORT_DOC = moved("TRANSPORT.md")
TRANSPORT_RESULTS = moved("TRANSPORT_RESULTS.md")
PROGRESS = moved("PROGRESS.md")
README = DocPath(HISTORY)
RECOMMENDATIONS = moved("RECOMMENDATIONS.md")
TRANSPORT_RUNS = REPO / "results" / "transport"
# The commit S3-04 builds on: files that stay unchanged are compared with it.
BASE_COMMIT = "96c554305fd63c72b0d16d7fcd2695a4ae1d896a"
SPRINT_2_NAME = "20261113T074114Z-wsl2"
SPRINT_2 = TRANSPORT_RUNS / SPRINT_2_NAME
BASELINE_SETTING = f"results/transport/{SPRINT_2_NAME}"
SECTION = "HTTPS and HTTP/2 (S3-04)"
ANCHOR = "https-and-http2-s3-04"

HOST = "127.0.0.1"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
PROTOCOL_ORDER = ("http", "https", "h2")
SWEEP_NAMES = ("cookie-default", "cookie-16k", "bearer-default", "bearer-512k")
VERSIONS = {"https": "HTTP/1.1", "h2": "HTTP/2.0"}
CLIENTS = {"cookie": ["browser"], "bearer": ["browser", "direct"]}
CLIENT_NAMES = {"browser": "Chromium", "direct": "http.client"}
# R11: what each sweep runs with, as `make sweep` does.
SWEEP_DEFINITIONS = {
    "cookie-default": {"transport": "cookie", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24576},
    "cookie-16k": {"transport": "cookie", "proxy_buffers": "16k", "header_buffers": None,
                   "step": 512, "max_bytes": 24576},
    "bearer-default": {"transport": "bearer", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24576},
    "bearer-512k": {"transport": "bearer", "proxy_buffers": None, "header_buffers": "512k",
                    "step": 16384, "max_bytes": 327680},
}
LOG_NAMES = ("app.log", "browser.log", "proxy-access.log", "proxy-error.log")
SAVED_FILES = {"sweep.json", "nginx.conf", *(f"logs/{name}.gz" for name in LOG_NAMES)}
PLAIN_CHECK_KEYS = {"ok", "proxy_url", "app_url", "run_dir", "layers", "browser", "page",
                    "request", "response"}
PLAIN_SWEEP_KEYS = {"transport", "settings", "proxy_url", "app_url", "run_dir", "layers",
                    "browser_version", "results"}
PLAIN_SAVED_KEYS = PLAIN_SWEEP_KEYS | {"recorded_utc", "evidence"}
PLAIN_SETTINGS_KEYS = {"algorithms", "clients", "claims", "attrs", "cookie_attributes", "step",
                       "max_bytes", "proxy_buffers", "header_buffers", "padding"}
ENTRY_KEYS = {"client", "algorithm", "smallest_token_bytes", "largest_verified_token_bytes",
              "first_rejection", "boundaries", "probes"}
COOKIE_PROBE_KEYS = {"client", "pad", "token_bytes", "outcome", "rejected_by",
                     "verified_directly", "issue_status", "issue_error", "cookie_stored",
                     "cookie_sent", "verify_status", "bytes", "upstream_status", "evidence",
                     "issue_nonce", "verify_nonce"}
BEARER_PROBE_KEYS = {"client", "pad", "token_bytes", "outcome", "rejected_by",
                     "verified_directly", "issue_status", "verify_status", "verify_error",
                     "bytes", "evidence", "issue_nonce", "verify_nonce"}
DIRECT_PROBE_KEYS = {"client", "pad", "token_bytes", "outcome", "rejected_by",
                     "verified_directly", "verify_status", "verify_error", "bytes", "evidence",
                     "verify_nonce"}
PROTOCOLS_KEYS = {"schema_version", "started_utc", "finished_utc", "recorded_utc", "settings",
                  "sweep_definitions", "environment", "layers", "browser", "experiment_keys",
                  "runs", "comparison", "evidence"}
SETTINGS_KEYS = {"protocols", "sweeps", "algorithms", "baseline", "step", "max_bytes", "timeout"}
DEFINITION_KEYS = {"transport", "clients", "claims", "attrs", "proxy_buffers", "header_buffers",
                   "step", "max_bytes"}
RUN_KEYS = {"protocol", "sweep", "directory", "check", "negotiated", "certificate"}
ROW_KEYS = {"sweep", "algorithm", "client", "baseline", "measured", "moved", "difference_bytes",
            "moved_by_http2"}
DETAILS_KEYS = {"subject", "issuer", "subject_alt_names", "not_before", "not_after",
                "public_key", "sha256_fingerprint"}
OPTIONS = ("--output-dir", "--protocol", "--sweep", "--alg", "--baseline", "--step",
           "--max-bytes", "--timeout", "--run-dir")
OTHER_COMMANDS = ("check", "tokens", "sweep", "serve", "versions", "load", "claims", "cookies",
                  "refs")
TABLE_HEADER = ("| Sweep | Configuration | Client | Sprint 2, plain HTTP/1.1 (WSL2) | "
                "HTTPS, HTTP/1.1 (macOS) | HTTP/2 (macOS) | What moved, and why |")
PLAIN_HEADER = ("| Sweep | Configuration | Client | Sprint 2, plain HTTP/1.1 (WSL2) | "
                "Plain HTTP/1.1 (macOS) | HTTPS, HTTP/1.1 (macOS) | HTTP/2 (macOS) | "
                "What moved, and why |")

RUN_NAME = re.compile(r"\d{8}T\d{6}Z-macos")
ERROR_LINE = re.compile(r"(?m)^Error:")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
ACCESS_REQUEST = re.compile(r'"[A-Z]+ (\S+) (HTTP/\d(?:\.\d)?)"')
TLS_PATH_LINE = re.compile(r'(ssl_certificate|ssl_certificate_key) "((?:[^"\\]|\\.)*)";')
NGINX_TIME = re.compile(r"(?m)^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[")
GRACE = 15.0
CLI_TIMEOUT = 1800
SIGNAL_GRACE = 600
OVERSIZED = 20480  # A Bearer token far over every default header limit, also over HTTP/2.


# ---- the modules under test ----------------------------------------------------------------

def tls():
    """Return scripts.transport_tls, failing the calling test when it cannot be imported."""
    if transport_tls is None:
        raise AssertionError(f"scripts/transport_tls.py cannot be imported: {TLS_IMPORT_ERROR!r}")
    return transport_tls


def protocols():
    """Return scripts.transport_protocols, failing the calling test when it cannot be imported."""
    if transport_protocols is None:
        raise AssertionError(f"scripts/transport_protocols.py cannot be imported: "
                             f"{PROTOCOLS_IMPORT_ERROR!r}")
    return transport_protocols


def api(module, name: str):
    """An attribute S3-04 adds to a module, failing the test when it is missing."""
    if not hasattr(module, name):
        raise AssertionError(f"{module.__name__} has no {name}")
    return getattr(module, name)


def start_tls_stack(*arguments, **keywords):
    return api(transport_stack, "start_tls_stack")(*arguments, **keywords)


def compare_sweeps(sweep: str, baseline, measured) -> list[dict]:
    return api(protocols(), "compare_sweeps")(sweep, baseline, measured)


def summary_lines(result: dict) -> list[str]:
    return api(protocols(), "summary_lines")(result)


def attempt(function, *arguments, **keywords) -> tuple:
    """(function's result, None), or (None, what it raised), for work done in setUpClass."""
    try:
        return function(*arguments, **keywords), None
    except Exception as error:  # Reported by the tests that need the result.
        return None, error


def outcome(test: unittest.TestCase, pair: tuple, what: str):
    """The result attempt() recorded, failing the test when it raised."""
    result, error = pair
    if error is not None:
        test.fail(f"{what} raised {error!r}")
    return result


# ---- general helpers ---------------------------------------------------------------------

def read_text(path: Path) -> str:
    """A text file's contents, or "" when it cannot be read."""
    try:
        return (path if isinstance(path, DocPath) else Path(path)).read_text(
            encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_gzip(path: Path) -> str:
    return gzip.decompress(Path(path).read_bytes()).decode("utf-8", errors="replace")


def read_any(path: Path) -> str:
    """A gzip file's or a plain file's text."""
    return read_gzip(path) if Path(path).suffix == ".gz" else read_text(path)


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def visible_names(directory: Path) -> set[str]:
    """A directory's entry names, without hidden ones such as Finder's .DS_Store."""
    return {path.name for path in Path(directory).iterdir() if not path.name.startswith(".")}


def files_of(directory: Path) -> set[str]:
    """Every visible file under a directory, as POSIX paths relative to it."""
    return {path.relative_to(directory).as_posix() for path in Path(directory).rglob("*")
            if path.is_file() and not any(part.startswith(".")
                                          for part in path.relative_to(directory).parts)}


def token_runs(text: str) -> list[str]:
    """Base64url runs of 40 or more characters (tokens and key material), except git commits."""
    return [run for run in TOKEN_LIKE.findall(text) if not HEX_COMMIT.fullmatch(run)]


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


def processes_mentioning(text: str) -> list[str]:
    """Command lines of running processes that contain text, such as an nginx run directory."""
    listing = subprocess.run(["ps", "-A", "-ww", "-o", "command="], capture_output=True,
                             text=True, timeout=60)
    return [line for line in listing.stdout.splitlines() if text in line and "ps -A" not in line]


def cli_environment(**extra: str) -> dict:
    return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **extra}


def stop(process: subprocess.Popen) -> None:
    """Terminate a process that is still running, then kill it if it does not exit."""
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


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


def git(*arguments: str) -> str | None:
    """Run git in the repository and return its stdout, or None when git or a commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), *arguments], capture_output=True,
                              text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def git_show(path: str, commit: str = BASE_COMMIT) -> str | None:
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
    """Every port the stacks under a run directory used, from each rendered nginx.conf."""
    ports = set()
    for path in Path(run_dir).glob("**/nginx.conf"):
        ports |= conf_ports(path)
    return ports


def key_files(root: Path) -> list[Path]:
    """Every experiment-key.pem left under a directory."""
    return sorted(Path(root).rglob("experiment-key.pem"))


def normalized_conf(text: str, run_dir: Path) -> str:
    """A rendered nginx.conf with its run directory and ports replaced, for comparison."""
    text = text.replace(str(Path(run_dir).absolute()), "<run_dir>")
    return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:<port>", text)


def directive(name: str) -> re.Pattern:
    """A pattern for an nginx directive set on a line of its own, not one named in a comment."""
    return re.compile(rf"(?m)^\s*{re.escape(name)}\s")


def query_of(url: str) -> dict:
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def parse_utc(text) -> datetime:
    """An ISO 8601 time; raises ValueError unless it is UTC."""
    value = datetime.fromisoformat(text)
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{text!r} is not UTC")
    return value


def nginx_times(path: Path) -> list[str]:
    """The timestamps of an nginx error log's lines; their fixed-width format sorts as text."""
    return NGINX_TIME.findall(read_text(path))


def logged_versions(text: str) -> dict[str, str]:
    """The HTTP version of each request nginx logged in proxy-access.log, by its nonce."""
    versions = {}
    for line in text.splitlines():
        match = ACCESS_REQUEST.search(line)
        if match:
            nonce = query_of(match[1]).get("nonce")
            if nonce:
                versions[nonce] = match[2]
    return versions


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


def header_block_bytes(record: dict) -> int:
    """R9's formula from browser.log: the request line, every header line except HTTP/2
    pseudo-header fields, and the final CRLF."""
    parts = urlsplit(record["url"])
    lines = "".join(f"{name}: {value}\r\n" for name, value in record["headers"].items()
                    if not name.startswith(":"))
    return len((f"GET {parts.path}?{parts.query} HTTP/1.1\r\n" + lines + "\r\n")
               .encode("latin-1"))


def direct_request_bytes(proxy_url: str, nonce: str, token_bytes: int) -> int:
    """The request http.client sends for a direct Bearer probe, as Sprint 2 counted it."""
    sent = (f"GET /api/token/verify?nonce={nonce} HTTP/1.1\r\nHost: {urlsplit(proxy_url).netloc}"
            "\r\nAccept-Encoding: identity\r\nAuthorization: Bearer \r\n\r\n")
    return len(sent.encode("latin-1")) + token_bytes


def entries_of(result: dict, client: str | None = None) -> list[dict]:
    return [entry for entry in result["results"]
            if client is None or entry.get("client", "browser") == client]


def probes_of(result: dict, client: str | None = None) -> list[dict]:
    return [probe for entry in entries_of(result, client) for probe in entry["probes"]]


def key_body_lines(pem: str) -> list[str]:
    """The base64 lines of a PEM key, which no log or result may contain."""
    return [line.strip() for line in pem.splitlines()
            if line.strip() and not line.startswith("-----")]


def nginx_unquote(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def check_tls_render(test: unittest.TestCase, conf: str, stack, protocol: str) -> None:
    """R6: `listen ... ssl;`, then the comment and the TLS directives at its indentation."""
    lines = conf.splitlines()
    port = urlsplit(stack.proxy_url).port
    listen = [index for index, line in enumerate(lines)
              if line.strip() == f"listen 127.0.0.1:{port} ssl;"]
    test.assertEqual(len(listen), 1, conf)
    index = listen[0]
    indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    following = lines[index + 1:index + (5 if protocol == "h2" else 4)]
    for line in following:
        test.assertTrue(line.startswith(indent) and not line[len(indent):][:1].isspace(),
                        repr(line))
    test.assertEqual(following[0].strip(), f"# Not a default: --protocol {protocol}.")
    rest = [line.strip() for line in following[1:]]
    paths = {match[1]: match[2] for match in map(TLS_PATH_LINE.fullmatch, rest) if match}
    test.assertEqual(set(paths), {"ssl_certificate", "ssl_certificate_key"}, following)
    if protocol == "h2":
        test.assertIn("http2 on;", rest)
    else:
        test.assertNotIn("http2", conf)
    for name, file_name in (("ssl_certificate", "certificate.pem"),
                            ("ssl_certificate_key", "experiment-key.pem")):
        path = Path(nginx_unquote(paths[name]))
        test.assertTrue(path.is_absolute(), path)
        test.assertEqual(paths[name], nginx_string(path))
        test.assertEqual(path.resolve(), (Path(stack.run_dir) / "tls" / file_name).resolve())
    test.assertIsNone(re.search(r"\b(http3|quic|ssl_protocols|ssl_ciphers)\b", conf))
    for line in lines:
        if line.strip().startswith("listen "):
            test.assertTrue(line.strip().startswith("listen 127.0.0.1:"), line)


def without_tls(conf: str, protocol: str) -> str:
    """A TLS render without its added lines and without ' ssl' on the listen line (R6)."""
    removed = {f"# Not a default: --protocol {protocol}."}
    if protocol == "h2":
        removed.add("http2 on;")
    kept = []
    for line in conf.splitlines(keepends=True):
        stripped = line.strip()
        if stripped in removed or TLS_PATH_LINE.fullmatch(stripped):
            continue
        kept.append(re.sub(r"(listen 127\.0\.0\.1:\d+) ssl;", r"\1;", line))
    return "".join(kept)


def alpn_with(context: ssl.SSLContext, port: int) -> str | None:
    """The ALPN protocol nginx selects for a client using this context."""
    with socket.create_connection((HOST, port), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as secured:
            return secured.selected_alpn_protocol()


def offering_h2(certificate: Path) -> ssl.SSLContext:
    """A verifying client context that offers h2 before http/1.1, as a browser does."""
    context = ssl.create_default_context(cafile=str(certificate))
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


def check_logs_hold_no_secret(test: unittest.TestCase, log_dir: Path, key_pem: str) -> None:
    """R23: no key material in any log, and no token in app.log or proxy-access.log."""
    lines = key_body_lines(key_pem)
    test.assertTrue(lines, "the experiment key could not be read while the stack ran")
    for path in sorted(Path(log_dir).iterdir()):
        text = read_any(path)
        with test.subTest(log=path.name):
            test.assertNotIn("-----BEGIN", text)
            for line in lines:
                test.assertNotIn(line, text)
            if path.name in ("app.log", "proxy-access.log"):
                test.assertEqual(token_runs(text), [])


def committed_runs() -> list[Path]:
    """Every results/transport/<YYYYMMDDTHHMMSSZ>-macos/ directory with a protocols.json."""
    return [path.parent for path in sorted(TRANSPORT_RUNS.glob("*/protocols.json"))
            if RUN_NAME.fullmatch(path.parent.name)]


def is_subsequence(items: list[str], within: list[str]) -> bool:
    iterator = iter(within)
    return all(any(item == candidate for candidate in iterator) for item in items)


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
    return [line.strip() for line in text.splitlines() if line.strip().startswith("|")
            and not re.fullmatch(r"[|:\-\s]+", line.strip())]


def cells(line: str) -> list[str]:
    """The cells of a Markdown table row, split on unescaped pipes."""
    inner = line.strip()
    inner = inner[1:] if inner.startswith("|") else inner
    inner = inner[:-1] if inner.endswith("|") and not inner.endswith("\\|") else inner
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", inner)]


def plain(cell: str) -> str:
    """A cell's text without Markdown emphasis or code marks."""
    return cell.replace("`", "").replace("*", "").strip()


def relative_links(text: str) -> list[str]:
    targets = re.findall(r"\]\(([^)\s]+)\)", text)
    return [target for target in targets
            if not target.startswith(("http://", "https://", "#", "mailto:"))]


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    return {slug(name) for _, name, _ in headings(read_text(path).splitlines())}


def contains_number(text: str, number: int) -> bool:
    return re.search(rf"(?<![\d,.])(?:{number}|{number:,})(?!,?\d)", text) is not None


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


def dates_shown(started: datetime, finished: datetime) -> list[str]:
    """The ways a run's UTC date may be written: 2026-11-19 or November 19, 2026."""
    shown = []
    for value in {started.date(), finished.date()}:
        shown += [value.isoformat(), f"{value:%B} {value.day}, {value.year}"]
    return shown


def check_links_resolve(test: unittest.TestCase, path: Path) -> None:
    """Every relative link in a document points at a file, and links to S3-04's section reach
    its heading."""
    for link in relative_links(read_text(path)):
        target, _, anchor = link.partition("#")
        with test.subTest(document=path.name, link=link):
            test.assertTrue(repo_file(target).exists(), link)
            if target == "TRANSPORT_RESULTS.md" and anchor:
                test.assertIn(anchor, anchors(TRANSPORT_RESULTS))


# ---- R1: plain HTTP stays as it was --------------------------------------------------------

class PlainStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.stack = cls.enterClassContext(start_stack(run_dir=cls.directory / "run"))
        cls.check = attempt(run_check, cls.stack, 60)

    def test_start_stack_yields_a_plain_stack(self):
        self.assertIs(type(self.stack), Stack)
        self.assertRegex(self.stack.proxy_url, r"^http://127\.0\.0\.1:\d+$")
        conf = read_text(self.directory / "run" / "nginx" / "nginx.conf")
        self.assertNotRegex(conf, r"\bssl\b")
        self.assertNotIn("http2", conf)
        self.assertNotIn("Not a default", conf)

    def test_run_check_keeps_its_keys(self):
        check = outcome(self, self.check, "run_check")
        self.assertEqual(set(check), PLAIN_CHECK_KEYS)
        self.assertTrue(check["ok"])
        for url in (check["proxy_url"], check["page"]["url"], check["request"]["url"]):
            self.assertTrue(url.startswith("http://127.0.0.1:"), url)


class PlainRenderTests(unittest.TestCase):
    def test_plain_render_matches_the_base_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = base_checkout(str(Path(directory) / "base"))
            if checkout is None:
                self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
            name = "scripts._transport_stack_96c5543"
            spec = importlib.util.spec_from_file_location(
                name, checkout / "scripts" / "transport_stack.py")
            base = importlib.util.module_from_spec(spec)
            sys.modules[name] = base  # For its dataclass; removed again below.
            self.addCleanup(sys.modules.pop, name, None)
            spec.loader.exec_module(base)
            proxy_port, app_port = free_ports(2)
            for proxy_buffers, header_buffers in ((None, None), ("16k", "512k")):
                rendered = {}
                for label, starter in (("base", base.start_stack), ("now", start_stack)):
                    run_dir = Path(directory) / f"{label}-{proxy_buffers}"
                    with starter(proxy_port=proxy_port, app_port=app_port, run_dir=run_dir,
                                 proxy_buffers=proxy_buffers, header_buffers=header_buffers):
                        rendered[label] = normalized_conf(
                            read_text(run_dir / "nginx" / "nginx.conf"), run_dir)
                with self.subTest(proxy_buffers=proxy_buffers, header_buffers=header_buffers):
                    self.assertEqual(rendered["now"], rendered["base"])


# ---- R2, R3, R6, R23: start_tls_stack ------------------------------------------------------

class TlsLifecycleTests(unittest.TestCase):
    def setUp(self):
        api(transport_stack, "start_tls_stack")
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def assertStopped(self, before: set[int], ports) -> None:
        for port in ports:
            self.assertTrue(refused(port), f"port {port} still accepts connections")
        self.assertTrue(eventually(lambda: children() - before == set()),
                        "a started process is still running")

    def test_invalid_protocol_raises_before_anything_starts(self):
        for index, value in enumerate(("http", "H2", "h3", "", None, 1, "HTTPS", "http2")):
            run_dir = self.directory / f"run-{index}"
            before = children()
            with self.subTest(protocol=value):
                with self.assertRaises(ValueError):
                    with start_tls_stack(protocol=value, run_dir=run_dir):
                        pass
                self.assertEqual(children() - before, set(), "a process was started")
                self.assertFalse(run_dir.exists(), "a file was written")

    def test_arguments_start_stack_rejects_raise_before_anything_starts(self):
        port = free_ports(1)[0]
        cases = ({"proxy_port": 0}, {"proxy_port": 65536}, {"proxy_port": "8080"},
                 {"app_port": True}, {"app_port": -1}, {"proxy_port": port, "app_port": port},
                 {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")}, {"timeout": "60"},
                 {"proxy_buffers": "16K"}, {"proxy_buffers": ""}, {"header_buffers": "big"},
                 {"header_buffers": 512})
        for index, keywords in enumerate(cases):
            run_dir = self.directory / f"bad-{index}"
            before = children()
            with self.subTest(**{key: repr(value) for key, value in keywords.items()}):
                with self.assertRaises(ValueError):
                    with start_tls_stack(protocol="https", run_dir=run_dir, **keywords):
                        pass
                self.assertEqual(children() - before, set(), "a process was started")
                self.assertFalse(run_dir.exists(), "a file was written")

    def test_running_stack_and_its_experiment_key(self):
        proxy_port, app_port = free_ports(2)
        run_dir = self.directory / "run"
        key = run_dir / "tls" / "experiment-key.pem"
        before = children()
        with start_tls_stack(protocol="https", proxy_port=proxy_port, app_port=app_port,
                             run_dir=run_dir) as stack:
            # Ready when yielded: the first request already gets the echo through nginx.
            status, headers, body = http_get(f"{stack.proxy_url}/api/echo",
                                             certificate=stack.certificate)
            started = len(children() - before)
            key_mode = stat.S_IMODE(key.stat().st_mode) if key.exists() else None
            key_pem = read_text(key)
            certificate_exists = Path(stack.certificate).is_file()
        self.assertEqual(status, 200)
        self.assertIn("x-transport-proxy", headers)
        self.assertEqual(json.loads(body).get("layer"), "application")
        self.assertIsInstance(stack, api(transport_stack, "TlsStack"))
        self.assertIsInstance(stack, Stack)
        self.assertEqual(stack.proxy_url, f"https://{HOST}:{proxy_port}")
        self.assertEqual(stack.app_url, f"http://{HOST}:{app_port}")
        self.assertEqual(stack.run_dir, run_dir.absolute())
        self.assertEqual(stack.protocol, "https")
        self.assertEqual(stack.certificate, run_dir.absolute() / "tls" / "certificate.pem")
        self.assertTrue(certificate_exists)
        self.assertEqual(started, 2, "nginx and the application only")
        self.assertEqual(key_mode, 0o600)
        self.assertIn("PRIVATE KEY", key_pem)
        self.assertFalse(key.exists(), "experiment-key.pem outlived the stack")
        self.assertStopped(before, (proxy_port, app_port))
        check_logs_hold_no_secret(self, run_dir / "logs", key_pem)

    def test_exception_in_the_body_removes_the_key_and_stops_everything(self):
        run_dir = self.directory / "failing"
        before, ports = children(), []
        with self.assertRaises(RuntimeError):
            with start_tls_stack(protocol="h2", run_dir=run_dir) as stack:
                ports = [urlsplit(stack.proxy_url).port, urlsplit(stack.app_url).port]
                self.assertTrue((run_dir / "tls" / "experiment-key.pem").exists())
                raise RuntimeError("stop here")
        self.assertEqual(len(ports), 2)
        self.assertEqual(key_files(run_dir), [])
        self.assertStopped(before, ports)

    def test_startup_failure_after_the_key_was_written_removes_it(self):
        # nginx refuses header buffers smaller than its connection pool and exits at startup,
        # after the key was written for it.
        run_dir = self.directory / "nginx-fails"
        proxy_port, app_port = free_ports(2)
        before = children()
        with self.assertRaises(RuntimeError):
            with start_tls_stack(protocol="https", proxy_port=proxy_port, app_port=app_port,
                                 run_dir=run_dir, header_buffers="1"):
                pass
        self.assertEqual(key_files(run_dir), [])
        self.assertStopped(before, (proxy_port, app_port))

    def test_busy_port_names_the_layer(self):
        for layer, option in (("proxy", "proxy_port"), ("app_server", "app_port")):
            with self.subTest(layer=layer), socket.socket() as busy:
                busy.bind((HOST, 0))
                busy.listen(1)
                run_dir = self.directory / f"busy-{layer}"
                before = children()
                with self.assertRaises(RuntimeError) as caught:
                    with start_tls_stack(protocol="https", run_dir=run_dir,
                                         **{option: busy.getsockname()[1]}):
                        pass
                self.assertIn(layer, str(caught.exception))
                self.assertEqual(key_files(run_dir), [])
                self.assertTrue(eventually(lambda: children() - before == set()))

    def test_tls_render_without_its_lines_is_the_plain_render(self):
        proxy_port, app_port = free_ports(2)
        for protocol, proxy_buffers, header_buffers in (("h2", "16k", "512k"),
                                                        ("https", None, "32k")):
            with self.subTest(protocol=protocol, proxy_buffers=proxy_buffers):
                tls_dir = self.directory / f"tls-{protocol}"
                plain_dir = self.directory / f"plain-{protocol}"
                with start_tls_stack(protocol=protocol, proxy_port=proxy_port,
                                     app_port=app_port, run_dir=tls_dir,
                                     proxy_buffers=proxy_buffers,
                                     header_buffers=header_buffers) as stack:
                    tls_conf = read_text(tls_dir / "nginx" / "nginx.conf")
                with start_stack(proxy_port=proxy_port, app_port=app_port, run_dir=plain_dir,
                                 proxy_buffers=proxy_buffers, header_buffers=header_buffers):
                    plain_conf = read_text(plain_dir / "nginx" / "nginx.conf")
                self.assertRegex(tls_conf, rf"(?m)^\s*listen 127\.0\.0\.1:{proxy_port} ssl;$")
                self.assertEqual(len(TLS_PATH_LINE.findall(tls_conf)), 2)
                self.assertEqual(normalized_conf(without_tls(tls_conf, protocol), tls_dir),
                                 normalized_conf(plain_conf, plain_dir))
                if header_buffers:
                    self.assertIn(f"large_client_header_buffers 4 {header_buffers};", tls_conf)
                self.assertEqual(stack.protocol, protocol)


# ---- R2-R9, R23: an HTTPS stack ------------------------------------------------------------

class TlsStackCase(unittest.TestCase):
    """A TLS stack started in setUpClass; failures there are reported by every test."""

    protocol = "https"
    run_name = "run"

    @classmethod
    def start(cls) -> None:
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.run_dir = cls.directory / cls.run_name
        cls.stack, cls.stack_error, cls.key_pem, cls.key_mode = None, None, "", None
        try:
            cls.stack = cls.enterClassContext(start_tls_stack(protocol=cls.protocol,
                                                              run_dir=cls.run_dir))
        except Exception as error:  # Reported by every test.
            cls.stack_error = error
            return
        key = cls.run_dir / "tls" / "experiment-key.pem"
        cls.key_pem = read_text(key)
        cls.key_mode = stat.S_IMODE(key.stat().st_mode) if key.exists() else None

    def setUp(self):
        self.assertIsNone(self.stack_error, f"start_tls_stack raised {self.stack_error!r}")
        self.assertIsNotNone(self.stack)

    def access_versions(self) -> dict[str, str]:
        return logged_versions(read_text(self.run_dir / "logs" / "proxy-access.log"))

    def check_protocol_fields(self, result: dict, browser_version: str) -> None:
        """Each probe's 'protocol' is what nginx logged for its nonces; negotiated counts them."""
        versions = self.access_versions()
        for entry in result["results"]:
            client = entry.get("client", "browser")
            expected_version = browser_version if client == "browser" else "HTTP/1.1"
            for probe in entry["probes"]:
                steps = ({"issue": probe["issue_nonce"], "verify": probe["verify_nonce"]}
                         if client == "browser" else {"verify": probe["verify_nonce"]})
                with self.subTest(client=client, token_bytes=probe["token_bytes"]):
                    self.assertEqual(probe["protocol"],
                                     {step: versions.get(nonce) for step, nonce in steps.items()})
                    for nonce in steps.values():
                        if nonce in versions:
                            self.assertEqual(versions[nonce], expected_version)
        negotiated = result["negotiated"]
        self.assertEqual(set(negotiated), {entry.get("client", "browser")
                                           for entry in result["results"]})
        for client, counts in negotiated.items():
            expected_version = browser_version if client == "browser" else "HTTP/1.1"
            observed = Counter(version for probe in probes_of(result, client)
                               for version in probe["protocol"].values() if version is not None)
            unlogged = sum(version is None for probe in probes_of(result, client)
                           for version in probe["protocol"].values())
            with self.subTest(client=client):
                self.assertLessEqual(set(counts), {expected_version, "unlogged"})
                self.assertGreater(counts.get(expected_version, 0), 0)
                self.assertTrue(all(isinstance(count, int) and count >= 0
                                    for count in counts.values()), counts)
                self.assertEqual({version: count for version, count in counts.items()
                                  if version != "unlogged" and count},
                                 dict(observed))
                # R9: requests nginx did not log are counted under 'unlogged'.
                self.assertEqual(counts.get("unlogged", 0), unlogged, counts)

    def check_tls_record(self, result: dict) -> None:
        self.assertLessEqual(PLAIN_SWEEP_KEYS | {"tls", "negotiated"}, set(result))
        self.assertEqual(result["settings"]["protocol"], self.protocol)
        self.assertLessEqual(PLAIN_SETTINGS_KEYS | {"protocol"}, set(result["settings"]))
        self.assertEqual(result["tls"], {
            "protocol": self.protocol,
            "certificate": api(tls(), "certificate_details")(self.stack.certificate),
            "experiment_key": True, "private_key_saved": False})
        self.assertTrue(result["proxy_url"].startswith("https://127.0.0.1:"))

    def check_header_bytes(self, result: dict) -> None:
        """Verified browser probes count request headers by R9's formula from browser.log."""
        records = browser_records(read_text(self.run_dir / "logs" / "browser.log"))
        key = ("browser_request_headers" if result["transport"] == "cookie"
               else "client_request_headers")
        checked = 0
        for probe in probes_of(result, "browser"):
            if probe["outcome"] != "verified":
                continue
            record = request_record(records, probe["verify_nonce"], "/api/token/verify")
            self.assertIsNotNone(record, probe["verify_nonce"])
            self.assertEqual(probe["bytes"][key], header_block_bytes(record))
            checked += 1
        self.assertGreater(checked, 0)


class HttpsStackTests(TlsStackCase):
    protocol = "https"
    run_name = "run dir"  # A space, as in the repository's own path.

    @classmethod
    def setUpClass(cls):
        cls.start()
        if cls.stack is None:
            return
        cls.check = attempt(run_check, cls.stack, 60)
        cls.sweep = attempt(run_sweep, cls.stack, "bearer", ["ES256"], step=4096,
                            max_bytes=4096)
        cls.saved = (attempt(write_results, cls.sweep[0], cls.directory / "saved")
                     if cls.sweep[0] is not None else (None, cls.sweep[1]))

    def test_stack_fields(self):
        stack = self.stack
        self.assertIsInstance(stack, api(transport_stack, "TlsStack"))
        self.assertRegex(stack.proxy_url, r"^https://127\.0\.0\.1:\d+$")
        self.assertRegex(stack.app_url, r"^http://127\.0\.0\.1:\d+$")
        self.assertEqual(stack.run_dir, self.run_dir.absolute())
        self.assertEqual(stack.certificate, self.run_dir.absolute() / "tls" / "certificate.pem")
        self.assertTrue(stack.certificate.is_file())
        self.assertEqual(self.key_mode, 0o600)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            stack.protocol = "h2"

    def test_rendered_listen_and_tls_directives(self):
        conf = read_text(self.run_dir / "nginx" / "nginx.conf")
        check_tls_render(self, conf, self.stack, "https")
        plain_dir = self.directory / "plain"
        with start_stack(run_dir=plain_dir):
            plain_conf = read_text(plain_dir / "nginx" / "nginx.conf")
        self.assertEqual(normalized_conf(without_tls(conf, "https"), self.run_dir),
                         normalized_conf(plain_conf, plain_dir))

    def test_template_is_unchanged(self):
        before = git_show("transport/nginx.conf.template")
        if before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        self.assertEqual(read_text(REPO / "transport" / "nginx.conf.template"), before)

    def test_http_get_verifies_the_certificate(self):
        url = f"{self.stack.proxy_url}/api/echo"
        status, headers, body = http_get(url, headers={"X-Probe": "1"},
                                         certificate=self.stack.certificate)
        self.assertEqual(status, 200)
        self.assertIn("x-transport-proxy", headers)
        self.assertEqual(json.loads(body)["headers"].get("x-probe"), "1")
        with self.assertRaises(OSError):  # ssl.SSLError is an OSError.
            http_get(url)
        other, _ = api(tls(), "generate_certificate")(self.directory / "other-tls")
        with self.assertRaises(OSError):
            http_get(url, certificate=other)
        status, _, _ = http_get(f"{self.stack.app_url}/api/echo",
                                certificate=self.directory / "missing.pem")
        self.assertEqual(status, 200)

    def test_client_context_negotiates_http11(self):
        port = urlsplit(self.stack.proxy_url).port
        context = api(tls(), "client_context")(self.stack.certificate)
        self.assertEqual(alpn_with(context, port), "http/1.1")
        # Without `http2 on;`, nginx answers a client that offers h2 with HTTP/1.1 too.
        self.assertEqual(alpn_with(offering_h2(self.stack.certificate), port), "http/1.1")

    def test_run_check_over_https(self):
        check = outcome(self, self.check, "run_check")
        self.assertEqual(set(check), PLAIN_CHECK_KEYS | {"protocol", "negotiated_protocol"})
        self.assertTrue(check["ok"])
        self.assertEqual((check["protocol"], check["negotiated_protocol"]),
                         ("https", "HTTP/1.1"))
        for url in (check["proxy_url"], check["page"]["url"], check["request"]["url"]):
            self.assertTrue(url.startswith("https://127.0.0.1:"), url)
        self.assertEqual(check["page"]["status"], 200)
        self.assertEqual(self.access_versions().get(check["request"]["nonce"]), "HTTP/1.1")

    def test_run_check_raises_when_nginx_logged_another_version(self):
        # R8: this nginx has no `http2 on;`, so it logs HTTP/1.1, which an h2 stack must reject.
        with self.assertRaises(RuntimeError):
            run_check(dataclasses.replace(self.stack, protocol="h2"), 60)

    def test_sweep_records_tls_and_negotiated_protocols(self):
        result = outcome(self, self.sweep, "run_sweep")
        self.check_tls_record(result)
        self.assertEqual([entry["client"] for entry in result["results"]], ["browser", "direct"])
        for entry in result["results"]:
            self.assertEqual(set(entry), ENTRY_KEYS)
            keys = BEARER_PROBE_KEYS if entry["client"] == "browser" else DIRECT_PROBE_KEYS
            for probe in entry["probes"]:
                with self.subTest(client=entry["client"], token_bytes=probe["token_bytes"]):
                    self.assertEqual(probe["outcome"], "verified", probe["evidence"])
                    self.assertLessEqual(keys | {"protocol"}, set(probe))
        self.check_protocol_fields(result, "HTTP/1.1")
        # Every probe verified, so nginx logged each issue and verify request.
        browser = len(probes_of(result, "browser"))
        direct = len(probes_of(result, "direct"))
        counted = {client: {version: count for version, count in counts.items() if count}
                   for client, counts in result["negotiated"].items()}
        self.assertEqual(counted, {"browser": {"HTTP/1.1": 2 * browser},
                                   "direct": {"HTTP/1.1": direct}})

    def test_sweep_byte_counts(self):
        result = outcome(self, self.sweep, "run_sweep")
        self.check_header_bytes(result)
        for probe in probes_of(result, "direct"):
            self.assertEqual(probe["bytes"]["client_request_headers"],
                             direct_request_bytes(self.stack.proxy_url, probe["verify_nonce"],
                                                  probe["token_bytes"]))

    def test_saved_results_hold_no_key(self):
        saved = Path(outcome(self, self.saved, "write_results"))
        self.assertEqual(files_of(saved), SAVED_FILES)
        for path in saved.rglob("*"):
            if path.is_file():
                with self.subTest(file=path.name):
                    self.assertNotIn("-----BEGIN", read_any(path))
        data = load_json(saved / "sweep.json")
        self.assertIs(data["tls"]["private_key_saved"], False)
        self.assertEqual(data["tls"]["certificate"]["sha256_fingerprint"],
                         api(tls(), "certificate_details")(self.stack.certificate)
                         ["sha256_fingerprint"])
        self.assertEqual(set(data["evidence"]["logs"]), set(LOG_NAMES))

    def test_logs_hold_no_key_material(self):
        outcome(self, self.sweep, "run_sweep")
        check_logs_hold_no_secret(self, self.run_dir / "logs", self.key_pem)


# ---- R2-R10, R23: an HTTP/2 stack ----------------------------------------------------------

class H2StackTests(TlsStackCase):
    protocol = "h2"

    @classmethod
    def setUpClass(cls):
        cls.start()
        if cls.stack is None:
            return
        cls.check = attempt(run_check, cls.stack, 60)
        cls.bearer = attempt(run_sweep, cls.stack, "bearer", ["ES256"], step=OVERSIZED,
                             max_bytes=OVERSIZED)
        cls.cookie = attempt(run_sweep, cls.stack, "cookie", ["ES256"], step=2048,
                             max_bytes=2048)

    def test_rendered_http2(self):
        conf = read_text(self.run_dir / "nginx" / "nginx.conf")
        check_tls_render(self, conf, self.stack, "h2")
        self.assertEqual(self.stack.protocol, "h2")
        self.assertEqual(self.key_mode, 0o600)

    def test_alpn(self):
        port = urlsplit(self.stack.proxy_url).port
        context = api(tls(), "client_context")(self.stack.certificate)
        self.assertEqual(alpn_with(context, port), "http/1.1")
        self.assertEqual(alpn_with(offering_h2(self.stack.certificate), port), "h2")

    def test_http_get_uses_http11(self):
        nonce = secrets.token_hex(16)
        status, headers, _ = http_get(f"{self.stack.proxy_url}/api/echo?nonce={nonce}",
                                      certificate=self.stack.certificate)
        self.assertEqual(status, 200)
        self.assertIn("x-transport-proxy", headers)
        self.assertTrue(eventually(lambda: nonce in self.access_versions(), grace=5))
        self.assertEqual(self.access_versions()[nonce], "HTTP/1.1")

    def test_run_check_negotiates_http2(self):
        check = outcome(self, self.check, "run_check")
        self.assertEqual(set(check), PLAIN_CHECK_KEYS | {"protocol", "negotiated_protocol"})
        self.assertEqual((check["protocol"], check["negotiated_protocol"]), ("h2", "HTTP/2.0"))
        self.assertEqual(self.access_versions().get(check["request"]["nonce"]), "HTTP/2.0")

    def test_run_check_raises_when_nginx_logged_another_version(self):
        # R8: Chromium negotiates h2 with this nginx, which an https stack must reject.
        with self.assertRaises(RuntimeError):
            run_check(dataclasses.replace(self.stack, protocol="https"), 60)

    def test_sweeps_record_tls(self):
        for name, pair in (("bearer", self.bearer), ("cookie", self.cookie)):
            with self.subTest(transport=name):
                result = outcome(self, pair, f"run_sweep({name})")
                self.check_tls_record(result)

    def test_browser_requests_are_http2_and_direct_ones_http11(self):
        for name, pair in (("bearer", self.bearer), ("cookie", self.cookie)):
            with self.subTest(transport=name):
                self.check_protocol_fields(outcome(self, pair, f"run_sweep({name})"),
                                           "HTTP/2.0")

    def test_small_token_verifies(self):
        for name, pair in (("bearer", self.bearer), ("cookie", self.cookie)):
            result = outcome(self, pair, f"run_sweep({name})")
            for entry in result["results"]:
                with self.subTest(transport=name, client=entry.get("client", "browser")):
                    smallest = entry["probes"][0]
                    self.assertEqual(smallest["token_bytes"], entry["smallest_token_bytes"])
                    self.assertEqual(smallest["outcome"], "verified", smallest["evidence"])

    def test_oversized_bearer_is_rejected_by_the_proxy(self):
        result = outcome(self, self.bearer, "run_sweep(bearer)")
        for entry in result["results"]:
            oversized = [probe for probe in entry["probes"] if probe["token_bytes"] > 20000]
            with self.subTest(client=entry["client"]):
                self.assertTrue(oversized)
                for probe in oversized:
                    self.assertEqual((probe["outcome"], probe["rejected_by"]),
                                     ("rejected", "proxy"), probe["evidence"])
                    self.assertTrue(probe["verified_directly"])
                    self.assertTrue(probe["evidence"])

    def test_request_header_bytes_leave_out_pseudo_headers(self):
        for name, pair in (("bearer", self.bearer), ("cookie", self.cookie)):
            with self.subTest(transport=name):
                self.check_header_bytes(outcome(self, pair, f"run_sweep({name})"))

    def test_evidence_quotes_no_token(self):
        for name, pair in (("bearer", self.bearer), ("cookie", self.cookie)):
            result = outcome(self, pair, f"run_sweep({name})")
            for entry in result["results"]:
                texts = [probe["evidence"] for probe in entry["probes"]]
                if entry["first_rejection"]:
                    texts.append(entry["first_rejection"]["evidence"])
                for text in texts:
                    with self.subTest(transport=name, client=entry.get("client", "browser")):
                        self.assertEqual(token_runs(text), [])

    def test_logs_hold_no_key_material(self):
        outcome(self, self.bearer, "run_sweep(bearer)")
        check_logs_hold_no_secret(self, self.run_dir / "logs", self.key_pem)


# ---- R11-R14: checks shared by every protocols run -----------------------------------------

class ProtocolsCase(unittest.TestCase):
    """Assertions shared by run_protocols, the protocols command, and the committed run."""

    def assertUtc(self, text) -> datetime:
        try:
            return parse_utc(text)
        except (TypeError, ValueError) as error:
            self.fail(f"{text!r} is not an ISO 8601 UTC time: {error}")

    def sweep_of(self, output: Path, run: dict) -> dict:
        return load_json(output / run["directory"] / "sweep.json")

    def check_layout(self, output: Path, saved: dict) -> None:
        directories = {f"{run['protocol']}-{run['sweep']}" for run in saved["runs"]}
        self.assertEqual(visible_names(output), {"protocols.json", *directories})
        for name in directories:
            with self.subTest(directory=name):
                self.assertEqual(files_of(output / name), SAVED_FILES)

    def check_top(self, saved: dict, protocol_names: set, settings: dict) -> None:
        self.assertEqual(set(saved), PROTOCOLS_KEYS)
        self.assertEqual(saved["schema_version"], 1)
        started = self.assertUtc(saved["started_utc"])
        self.assertLessEqual(started, self.assertUtc(saved["finished_utc"]))
        self.assertLessEqual(started, self.assertUtc(saved["recorded_utc"]))
        self.assertEqual(set(saved["settings"]), SETTINGS_KEYS)
        self.assertEqual(set(saved["settings"]["protocols"]), protocol_names)
        self.assertEqual(len(saved["settings"]["protocols"]), len(protocol_names))
        for key, value in settings.items():
            with self.subTest(setting=key):
                self.assertEqual(saved["settings"][key], value)
        self.assertEqual(set(saved["environment"]), set(transport_load.run_environment()))
        self.assertEqual(saved["layers"], manifest_layers(load_manifest()))
        self.assertEqual(set(saved["browser"]), {"version", "user_agent"})
        documented = next(layer["version"] for layer in load_manifest()["layers"]
                          if layer["role"] == "browser")
        self.assertEqual(saved["browser"]["version"], documented)
        self.assertIn("Chrome", saved["browser"]["user_agent"])
        self.assertIs(saved["experiment_keys"], True)

    def check_definitions(self, saved: dict, steps: dict) -> None:
        """sweep_definitions as used; steps maps each sweep to its (step, max_bytes)."""
        definitions = saved["sweep_definitions"]
        self.assertEqual(set(definitions), set(saved["settings"]["sweeps"]))
        for name, definition in definitions.items():
            with self.subTest(sweep=name):
                expected = SWEEP_DEFINITIONS[name]
                self.assertEqual(set(definition), DEFINITION_KEYS)
                for key in ("transport", "proxy_buffers", "header_buffers"):
                    self.assertEqual(definition[key], expected[key])
                self.assertEqual((definition["step"], definition["max_bytes"]), steps[name])
                self.assertEqual(definition["clients"], CLIENTS[expected["transport"]])
                self.assertEqual(definition["claims"], "minimal")
                if expected["transport"] == "cookie":
                    self.assertEqual(definition["attrs"], "default")
                else:  # Bearer sweeps record no cookie attributes in sweep.json.
                    self.assertIn(definition["attrs"], ("default", None))

    def check_runs(self, saved: dict, output: Path) -> None:
        settings = saved["settings"]
        order = [(protocol, sweep) for protocol in PROTOCOL_ORDER
                 if protocol in settings["protocols"]
                 for sweep in SWEEP_NAMES if sweep in settings["sweeps"]]
        self.assertEqual([(run["protocol"], run["sweep"]) for run in saved["runs"]], order)
        fingerprints = []
        for run in saved["runs"]:
            with self.subTest(run=(run["protocol"], run["sweep"])):
                self.assertEqual(set(run), RUN_KEYS)
                self.assertEqual(run["directory"], f"{run['protocol']}-{run['sweep']}")
                self.assertEqual(set(run["check"]), {"page_status", "negotiated_protocol"})
                self.assertEqual(run["check"]["page_status"], 200)
                sweep = self.sweep_of(output, run)
                if run["protocol"] == "http":
                    self.assertIsNone(run["check"]["negotiated_protocol"])
                    self.assertIsNone(run["negotiated"])
                    self.assertIsNone(run["certificate"])
                    continue
                self.assertEqual(run["check"]["negotiated_protocol"], VERSIONS[run["protocol"]])
                self.assertEqual(run["negotiated"], sweep["negotiated"])
                self.assertEqual(run["certificate"], sweep["tls"]["certificate"])
                self.assertEqual(set(run["certificate"]), DETAILS_KEYS)
                self.assertEqual(run["certificate"]["subject_alt_names"],
                                 ["DNS:localhost", "IP:127.0.0.1"])
                fingerprints.append(run["certificate"]["sha256_fingerprint"])
        self.assertEqual(len(set(fingerprints)), len(fingerprints), "a key was reused")

    def check_negotiated(self, saved: dict) -> None:
        """R16's counts: HTTP/2.0 only from Chromium over h2; HTTP/1.1 everywhere else."""
        for run in saved["runs"]:
            if run["protocol"] == "http":
                continue
            clients = saved["sweep_definitions"][run["sweep"]]["clients"]
            with self.subTest(run=run["directory"]):
                self.assertEqual(set(run["negotiated"]), set(clients))
                for client, counts in run["negotiated"].items():
                    version = ("HTTP/2.0" if run["protocol"] == "h2" and client == "browser"
                               else "HTTP/1.1")
                    self.assertLessEqual(set(counts), {version, "unlogged"}, (client, counts))
                    self.assertGreater(counts.get(version, 0), 0, (client, counts))
                    self.assertTrue(all(isinstance(count, int) and count >= 0
                                        for count in counts.values()), counts)

    def check_sweeps(self, saved: dict, output: Path) -> None:
        for run in saved["runs"]:
            definition = saved["sweep_definitions"][run["sweep"]]
            sweep = self.sweep_of(output, run)
            with self.subTest(run=run["directory"]):
                self.assertEqual(sweep["transport"], definition["transport"])
                for key in ("step", "max_bytes", "proxy_buffers", "header_buffers", "claims",
                            "clients"):
                    self.assertEqual(sweep["settings"][key], definition[key], key)
                self.assertEqual(sweep["settings"]["algorithms"], saved["settings"]["algorithms"])
                self.assertEqual([(entry["algorithm"], entry.get("client", "browser"))
                                  for entry in sweep["results"]],
                                 [(name, client) for name in saved["settings"]["algorithms"]
                                  for client in definition["clients"]])
                if run["protocol"] == "http":  # R1: exactly the keys of a plain sweep.
                    self.assertEqual(set(sweep), PLAIN_SAVED_KEYS)
                    self.assertEqual(set(sweep["settings"]), PLAIN_SETTINGS_KEYS)
                    for entry in sweep["results"]:
                        self.assertEqual(set(entry), ENTRY_KEYS)
                        keys = (DIRECT_PROBE_KEYS if entry["client"] == "direct" else
                                COOKIE_PROBE_KEYS if sweep["transport"] == "cookie" else
                                BEARER_PROBE_KEYS)
                        for probe in entry["probes"]:
                            self.assertEqual(set(probe), keys)
                    continue
                self.assertEqual(sweep["settings"]["protocol"], run["protocol"])
                self.assertEqual(sweep["tls"], {"protocol": run["protocol"],
                                                "certificate": run["certificate"],
                                                "experiment_key": True,
                                                "private_key_saved": False})
                self.assertTrue(sweep["proxy_url"].startswith("https://127.0.0.1:"))
                for client in definition["clients"]:
                    steps = {"issue", "verify"} if client == "browser" else {"verify"}
                    version = ("HTTP/2.0" if run["protocol"] == "h2" and client == "browser"
                               else "HTTP/1.1")
                    tally = Counter()
                    for probe in probes_of(sweep, client):
                        self.assertEqual(set(probe["protocol"]), steps, probe["protocol"])
                        for logged in probe["protocol"].values():
                            self.assertIn(logged, (version, None))
                            tally[logged or "unlogged"] += 1
                    self.assertTrue(tally, f"no {client} probes")
                    # R9: negotiated counts each probe's requests by the version nginx logged.
                    self.assertEqual({name: count for name, count
                                      in sweep["negotiated"][client].items() if count},
                                     dict(tally), client)

    def check_comparison(self, saved: dict, output: Path) -> None:
        baseline_dir = REPO / saved["settings"]["baseline"]  # Relative to the repository.
        expected = []
        for sweep in (name for name in SWEEP_NAMES if name in saved["settings"]["sweeps"]):
            baseline = load_json(baseline_dir / sweep / "sweep.json")
            measured = {run["protocol"]: self.sweep_of(output, run)
                        for run in saved["runs"] if run["sweep"] == sweep}
            expected += compare_sweeps(sweep, baseline, measured)
        self.assertEqual(saved["comparison"], expected)
        for row in saved["comparison"]:
            self.assertEqual(set(row), ROW_KEYS)
            self.assertEqual(list(row["measured"]),
                             [protocol for protocol in PROTOCOL_ORDER
                              if protocol in saved["settings"]["protocols"]])

    def check_evidence(self, saved: dict, output: Path) -> None:
        expected = {run["directory"]: {
            "sweep": f"{run['directory']}/sweep.json",
            "logs": {name: f"{run['directory']}/logs/{name}.gz" for name in LOG_NAMES},
            "nginx_conf": f"{run['directory']}/nginx.conf"} for run in saved["runs"]}
        self.assertEqual(saved["evidence"], expected)
        for paths in expected.values():
            for path in (paths["sweep"], paths["nginx_conf"], *paths["logs"].values()):
                self.assertTrue((output / path).is_file(), path)

    def check_confs(self, saved: dict, output: Path) -> None:
        for run in saved["runs"]:
            conf = read_text(output / run["directory"] / "nginx.conf")
            definition = saved["sweep_definitions"][run["sweep"]]
            with self.subTest(run=run["directory"]):
                listen = re.findall(r"(?m)^\s*listen (\S+)( ssl)?;", conf)
                self.assertEqual(len(listen), 1, conf)
                self.assertTrue(listen[0][0].startswith("127.0.0.1:"))
                if run["protocol"] == "http":
                    self.assertEqual(listen[0][1], "")
                    self.assertNotIn("ssl_certificate", conf)
                    self.assertNotIn("--protocol", conf)
                else:
                    self.assertEqual(listen[0][1], " ssl")
                    self.assertIn(f"# Not a default: --protocol {run['protocol']}.", conf)
                    self.assertEqual(len(TLS_PATH_LINE.findall(conf)), 2)
                self.assertEqual(directive("http2").search(conf) is not None,
                                 run["protocol"] == "h2")
                if definition["proxy_buffers"]:
                    self.assertIn(f"proxy_buffer_size {definition['proxy_buffers']};", conf)
                else:
                    self.assertIsNone(directive("proxy_buffer_size").search(conf))
                if definition["header_buffers"]:
                    self.assertIn(f"large_client_header_buffers 4 "
                                  f"{definition['header_buffers']};", conf)
                else:
                    self.assertIsNone(directive("large_client_header_buffers").search(conf))

    def check_privacy(self, output: Path) -> None:
        text = read_text(output / "protocols.json")
        self.assertEqual(token_runs(text), [])
        names = private_names()
        for path in sorted(output.rglob("*")):
            if not path.is_file():
                continue
            content = read_any(path)
            with self.subTest(file=path.relative_to(output).as_posix()):
                self.assertNotIn("-----BEGIN", content)
                self.assertNotIn("PRIVATE KEY", content)
                for name in names:
                    self.assertNotIn(name, content)

    def check_summary(self, saved: dict) -> None:
        lines = summary_lines(saved)
        self.assertEqual(len(lines), len(saved["runs"]) + len(saved["comparison"]))

    def check_saved_run(self, output: Path, protocol_names: set, settings: dict,
                        steps: dict) -> dict:
        saved = load_json(output / "protocols.json")
        self.check_top(saved, protocol_names, settings)
        self.check_layout(output, saved)
        self.check_definitions(saved, steps)
        self.check_runs(saved, output)
        self.check_negotiated(saved)
        self.check_sweeps(saved, output)
        self.check_comparison(saved, output)
        self.check_evidence(saved, output)
        self.check_confs(saved, output)
        self.check_privacy(output)
        self.check_summary(saved)
        return saved


# ---- R12-R14: run_protocols ----------------------------------------------------------------

class RunProtocolsTests(ProtocolsCase):
    """http and https, given out of order, for cookie-16k and bearer-default with ES256."""

    STEPS = {"cookie-16k": (4096, 12288), "bearer-default": (4096, 12288)}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.output = cls.directory / "out"
        cls.run_dir = cls.directory / "runs"
        # A baseline outside the repository with only the selected sweeps.
        cls.baseline = cls.directory / "baseline"
        for sweep in ("cookie-16k", "bearer-default"):
            (cls.baseline / sweep).mkdir(parents=True)
            shutil.copy(SPRINT_2 / sweep / "sweep.json", cls.baseline / sweep / "sweep.json")
        cls.before = children()
        cls.result = (None, AssertionError("scripts/transport_protocols.py is missing"))
        if transport_protocols is not None and hasattr(transport_protocols, "run_protocols"):
            cls.result = attempt(transport_protocols.run_protocols, cls.output,
                                 protocols=("https", "http"),
                                 sweeps=["bearer-default", "cookie-16k"], algorithms=["ES256"],
                                 baseline=cls.baseline, step=4096, max_bytes=12288,
                                 timeout=60.0, run_dir=cls.run_dir)

    def setUp(self):
        self.returned = outcome(self, self.result, "run_protocols")

    def saved(self) -> dict:
        return load_json(self.output / "protocols.json")

    def test_saved_run(self):
        saved = self.check_saved_run(self.output, {"http", "https"},
                                     {"algorithms": ["ES256"], "step": 4096,
                                      "max_bytes": 12288, "timeout": 60.0},
                                     self.STEPS)
        sweeps = saved["settings"]["sweeps"]
        self.assertEqual(sorted(sweeps), ["bearer-default", "cookie-16k"])
        # The baseline lies outside the repository, so it is recorded as its own path.
        self.assertEqual((REPO / saved["settings"]["baseline"]).resolve(),
                         self.baseline.resolve())

    def test_returns_what_it_saved(self):
        self.assertEqual(json.loads(json.dumps(self.returned)), self.saved())

    def test_runs_in_protocol_then_sweep_order(self):
        self.assertEqual([(run["protocol"], run["sweep"]) for run in self.saved()["runs"]],
                         [("http", "cookie-16k"), ("http", "bearer-default"),
                          ("https", "cookie-16k"), ("https", "bearer-default")])

    def test_each_stack_ran_alone_and_checked_first(self):
        names = [run["directory"] for run in self.saved()["runs"]]
        for name in names:
            with self.subTest(stack=name):
                self.assertTrue((self.run_dir / name / "nginx" / "nginx.conf").is_file())
                access = read_text(self.run_dir / name / "logs" / "proxy-access.log")
                check = access.find("/api/echo?nonce=")
                sweep = access.find("/api/token/")
                self.assertGreaterEqual(check, 0, "run_check did not run on the stack")
                self.assertGreater(sweep, check, "run_sweep ran before run_check")
        for earlier, later in zip(names, names[1:]):
            first = nginx_times(self.run_dir / earlier / "logs" / "proxy-error.log")
            second = nginx_times(self.run_dir / later / "logs" / "proxy-error.log")
            if first and second:
                with self.subTest(earlier=earlier, later=later):
                    self.assertLessEqual(first[-1], second[0])

    def test_comparison_rows(self):
        rows = self.saved()["comparison"]
        self.assertEqual([(row["sweep"], row["algorithm"], row["client"]) for row in rows],
                         [("cookie-16k", "ES256", "browser"),
                          ("bearer-default", "ES256", "browser"),
                          ("bearer-default", "ES256", "direct")])
        # Whether these live boundaries equal each other or Sprint 2's is the finding, checked
        # on the committed run (test_https_bearer_default_matches_sprint_2), not here.
        for row in rows:
            with self.subTest(row=(row["sweep"], row["client"])):
                self.assertEqual(list(row["measured"]), ["http", "https"])
                self.assertEqual(list(row["moved"]), ["http", "https"])
                self.assertEqual(list(row["difference_bytes"]), ["http", "https"])
                self.assertIsNone(row["moved_by_http2"])
                if row["sweep"] == "bearer-default":  # Sprint 2's 8,168-byte boundary.
                    self.assertEqual(row["baseline"]["largest_verified_token_bytes"], 8168)

    def test_every_process_stopped_and_no_key_left(self):
        self.assertEqual(key_files(self.run_dir), [])
        for port in run_ports(self.run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")
        self.assertTrue(eventually(lambda: children() - self.before == set()))
        self.assertEqual(processes_mentioning(str(self.run_dir)), [])


class RunProtocolsArgumentTests(unittest.TestCase):
    def setUp(self):
        self.run_protocols = api(protocols(), "run_protocols")
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def baseline(self, name: str, files: dict[str, object]) -> Path:
        """A baseline directory with <sweep>/sweep.json files holding the given values."""
        root = self.directory / name
        root.mkdir()
        for sweep, value in files.items():
            (root / sweep).mkdir()
            text = value if isinstance(value, str) else json.dumps(value)
            (root / sweep / "sweep.json").write_text(text, encoding="utf-8")
        return root

    def test_invalid_arguments_raise_value_error_before_anything_starts(self):
        bearer = load_json(SPRINT_2 / "bearer-default" / "sweep.json")
        cookie = load_json(SPRINT_2 / "cookie-default" / "sweep.json")
        occupied = self.directory / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        cases = {
            "unknown protocol": {"protocols": ("h3",)},
            "protocol case": {"protocols": ("HTTPS",)},
            "repeated protocol": {"protocols": ("https", "https")},
            "unknown sweep": {"sweeps": ["cookie-32k"]},
            "repeated sweep": {"sweeps": ["bearer-default", "bearer-default"]},
            "unknown algorithm": {"algorithms": ["HS256"]},
            "repeated algorithm": {"algorithms": ["ES256", "ES256"]},
            "zero step": {"step": 0},
            "negative step": {"step": -1},
            "boolean step": {"step": True},
            "fractional step": {"step": 1.5},
            "zero max bytes": {"max_bytes": 0},
            "zero timeout": {"timeout": 0},
            "negative timeout": {"timeout": -1},
            "missing baseline": {"baseline": self.directory / "missing"},
            "baseline without the sweep": {"baseline": self.baseline(
                "only-cookie", {"cookie-default": cookie})},
            "baseline not JSON": {"baseline": self.baseline(
                "not-json", {"bearer-default": "{not json"})},
            "baseline list": {"baseline": self.baseline("list", {"bearer-default": [1]})},
            "baseline transport": {"baseline": self.baseline(
                "transport", {"bearer-default": {**bearer, "transport": "cookie"}})},
            "baseline results": {"baseline": self.baseline(
                "results", {"bearer-default": {**bearer, "results": {}}})},
            "non-empty output dir": {"output_dir": occupied},
        }
        for index, (name, keywords) in enumerate(cases.items()):
            with self.subTest(name):
                output = keywords.pop("output_dir", self.directory / f"out-{index}")
                run_dir = self.directory / f"run-{index}"
                arguments = {"protocols": ("https",), "sweeps": ["bearer-default"],
                             "algorithms": ["ES256"], "step": 4096, "max_bytes": 4096,
                             "run_dir": run_dir, **keywords}
                before = children()
                with self.assertRaises(ValueError):
                    self.run_protocols(output, **arguments)
                self.assertEqual(children() - before, set(), "a process was started")
                self.assertFalse(run_dir.exists(), "a stack was started")
                if output != occupied:
                    self.assertFalse(output.exists(), "the output directory was created")
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])

    def test_run_check_failure_stops_the_run(self):
        output, run_dir = self.directory / "out", self.directory / "runs"
        before = children()
        with tempfile.TemporaryDirectory() as empty:
            with mock.patch.dict(os.environ, {"PLAYWRIGHT_BROWSERS_PATH": empty}):
                with self.assertRaises(RuntimeError):
                    self.run_protocols(output, protocols=("https",), sweeps=["bearer-default"],
                                       algorithms=["ES256"], step=4096, max_bytes=4096,
                                       timeout=30.0, run_dir=run_dir)
        self.assertFalse((output / "protocols.json").exists())
        self.assertEqual(key_files(run_dir), [])
        for port in run_ports(run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")
        self.assertTrue(eventually(lambda: children() - before == set()))


# ---- R11, R14, R23: the protocols command --------------------------------------------------

class ProtocolsCommandTests(ProtocolsCase):
    STEPS = {"bearer-default": (4096, 12288)}
    # Short values for the options a usage-error case does not set, so a wrongly accepted case
    # runs briefly.
    FILLER = {"--protocol": ["https"], "--sweep": ["bearer-default"], "--alg": ["ES256"],
              "--step": ["4096"], "--max-bytes": ["4096"]}

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.output = cls.directory / "first"
        cls.output.mkdir()  # An existing empty directory is accepted.
        cls.run_dir = cls.directory / "first-run"
        # h2 before https: the runs still go in PROTOCOLS order.
        cls.first = run_cli("protocols", "--protocol", "h2", "https", "--sweep",
                            "bearer-default", "--alg", "ES256", "--step", "4096",
                            "--max-bytes", "12288", "--run-dir", cls.run_dir,
                            "--output-dir", cls.output, cwd=cls.directory)

    def require_first_run(self) -> dict:
        self.assertEqual(self.first.returncode, 0, self.first.stderr)
        return load_json(self.output / "protocols.json")

    def check_stopped(self, run_dir: Path) -> None:
        self.assertEqual(key_files(run_dir), [])
        for port in run_ports(run_dir):
            self.assertTrue(refused(port), f"port {port} still accepts connections")
        self.assertTrue(eventually(lambda: processes_mentioning(str(run_dir)) == []))

    def test_first_run_exits_0_and_saves_the_run(self):
        self.require_first_run()
        self.assertNotRegex(self.first.stderr, ERROR_LINE)
        saved = self.check_saved_run(self.output, {"https", "h2"},
                                     {"sweeps": ["bearer-default"], "algorithms": ["ES256"],
                                      "baseline": BASELINE_SETTING, "step": 4096,
                                      "max_bytes": 12288, "timeout": 60.0},
                                     self.STEPS)
        self.assertEqual([run["protocol"] for run in saved["runs"]], ["https", "h2"])

    def test_prints_the_summary_then_the_output_directory(self):
        saved = self.require_first_run()
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

    def test_https_and_h2_rows_against_sprint_2(self):
        # Whether HTTPS matches Sprint 2 is checked on the committed run
        # (test_https_bearer_default_matches_sprint_2); this live run checks the rows' shape.
        saved = self.require_first_run()
        rows = saved["comparison"]
        self.assertEqual([(row["algorithm"], row["client"]) for row in rows],
                         [("ES256", "browser"), ("ES256", "direct")])
        for row in rows:
            with self.subTest(client=row["client"]):
                self.assertEqual(list(row["measured"]), ["https", "h2"])
                self.assertEqual(row["baseline"]["largest_verified_token_bytes"], 8168)
                for protocol in ("https", "h2"):
                    self.assertIn(row["moved"][protocol], (True, False))
                    self.assertIsInstance(row["difference_bytes"][protocol], int)
                self.assertIn(row["moved_by_http2"], (True, False))

    def test_h2_run_sends_http2_from_chromium_only(self):
        saved = self.require_first_run()
        h2 = next(run for run in saved["runs"] if run["protocol"] == "h2")
        self.assertEqual(h2["check"]["negotiated_protocol"], "HTTP/2.0")
        self.assertGreater(h2["negotiated"]["browser"].get("HTTP/2.0", 0), 0)
        self.assertGreater(h2["negotiated"]["direct"].get("HTTP/1.1", 0), 0)
        sweep = self.sweep_of(self.output, h2)
        versions = logged_versions(read_gzip(self.output / "h2-bearer-default" / "logs"
                                             / "proxy-access.log.gz"))
        for probe in probes_of(sweep, "direct"):
            if probe["verify_nonce"] in versions:
                self.assertEqual(versions[probe["verify_nonce"]], "HTTP/1.1")
        for probe in probes_of(sweep, "browser"):
            for nonce in (probe["issue_nonce"], probe["verify_nonce"]):
                if nonce in versions:
                    self.assertEqual(versions[nonce], "HTTP/2.0")

    def test_output_holds_no_key_or_pem(self):
        self.require_first_run()
        for stream in (self.first.stdout, self.first.stderr):
            self.assertNotIn("-----BEGIN", stream)
            self.assertNotIn("PRIVATE KEY", stream)
        self.check_privacy(self.output)

    def test_first_run_stops_every_process(self):
        self.require_first_run()
        for name in ("https-bearer-default", "h2-bearer-default"):
            with self.subTest(stack=name):
                self.assertTrue((self.run_dir / name / "nginx" / "nginx.conf").is_file())
        self.check_stopped(self.run_dir)

    def test_help_lists_every_option(self):
        result = run_cli("protocols", "--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in OPTIONS:
            with self.subTest(option=option):
                self.assertIn(option, result.stdout)
        for option in ("--settings", "--proxy-port", "--app-port", "--proxy-buffers",
                       "--header-buffers", "--transport", "--client"):
            with self.subTest(absent=option):
                self.assertNotIn(option, result.stdout)
        for name in ("http", "https", "h2", *SWEEP_NAMES):
            self.assertIn(name, result.stdout)

    def test_main_help_names_protocols(self):
        result = run_cli("--help", cwd=self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protocols", result.stdout)

    def test_usage_errors_exit_2_before_anything_starts(self):
        # Without the protocols command, argparse would reject every case for the wrong reason.
        self.assertEqual(run_cli("protocols", "--help", cwd=self.directory).returncode, 0)
        bad = self.directory / "baselines"
        bearer = load_json(SPRINT_2 / "bearer-default" / "sweep.json")

        def baseline(name: str, value) -> Path:
            root = bad / name
            (root / "bearer-default").mkdir(parents=True)
            text = value if isinstance(value, str) else json.dumps(value)
            (root / "bearer-default" / "sweep.json").write_text(text, encoding="utf-8")
            return root

        only_cookie = bad / "only-cookie"
        (only_cookie / "cookie-default").mkdir(parents=True)
        shutil.copy(SPRINT_2 / "cookie-default" / "sweep.json",
                    only_cookie / "cookie-default" / "sweep.json")
        occupied = self.directory / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("keep", encoding="utf-8")
        a_file = self.directory / "a-file.txt"
        a_file.write_text("not a directory", encoding="utf-8")
        cases = {
            "missing output dir": [],
            "non-empty output dir": ["--output-dir", occupied],
            "output dir is a file": ["--output-dir", a_file],
            "unknown protocol": ["--protocol", "h3", "--output-dir", "{out}"],
            "protocol case": ["--protocol", "HTTPS", "--output-dir", "{out}"],
            "repeated protocol": ["--protocol", "https", "https", "--output-dir", "{out}"],
            "unknown sweep": ["--sweep", "cookie-32k", "--output-dir", "{out}"],
            "oidc sweep": ["--sweep", "mldsa-oidc-default", "--output-dir", "{out}"],
            "repeated sweep": ["--sweep", "bearer-default", "bearer-default", "--output-dir",
                               "{out}"],
            "unknown alg": ["--alg", "HS256", "--output-dir", "{out}"],
            "repeated alg": ["--alg", "ES256", "ES256", "--output-dir", "{out}"],
            "missing baseline": ["--baseline", bad / "missing", "--output-dir", "{out}"],
            "baseline is a file": ["--baseline", a_file, "--output-dir", "{out}"],
            "baseline without the sweep": ["--baseline", only_cookie, "--output-dir", "{out}"],
            "baseline not JSON": ["--baseline", baseline("not-json", "{not json"),
                                  "--output-dir", "{out}"],
            "baseline list": ["--baseline", baseline("list", [1]), "--output-dir", "{out}"],
            "baseline transport": ["--baseline", baseline("transport",
                                                          {**bearer, "transport": "cookie"}),
                                   "--output-dir", "{out}"],
            "baseline results": ["--baseline", baseline("results", {**bearer, "results": {}}),
                                 "--output-dir", "{out}"],
            "zero step": ["--step", "0", "--output-dir", "{out}"],
            "negative step": ["--step=-512", "--output-dir", "{out}"],
            "fractional step": ["--step", "1.5", "--output-dir", "{out}"],
            "word step": ["--step", "big", "--output-dir", "{out}"],
            "zero max bytes": ["--max-bytes", "0", "--output-dir", "{out}"],
            "word max bytes": ["--max-bytes", "lots", "--output-dir", "{out}"],
            "zero timeout": ["--timeout", "0", "--output-dir", "{out}"],
            "negative timeout": ["--timeout=-5", "--output-dir", "{out}"],
            "proxy buffers option": ["--proxy-buffers", "16k", "--output-dir", "{out}"],
            "settings option": ["--settings", a_file, "--output-dir", "{out}"],
        }
        for index, (name, arguments) in enumerate(cases.items()):
            with self.subTest(name):
                run_dir = self.directory / f"usage-run-{index}"
                output = self.directory / f"usage-out-{index}"
                arguments = [output if argument == "{out}" else argument
                             for argument in arguments]
                given = {str(argument).split("=", 1)[0] for argument in arguments}
                for option, values in self.FILLER.items():
                    if option not in given:
                        arguments += [option, *values]
                result = run_cli("protocols", *arguments, "--run-dir", run_dir,
                                 cwd=self.directory)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertFalse(run_dir.exists(), "a stack was started")
                self.assertFalse(output.exists(), "the output directory was created")
        self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])

    def test_runtime_failure_exits_1_and_stops_every_process(self):
        run_dir, output = self.directory / "failing-run", self.directory / "failing"
        with tempfile.TemporaryDirectory() as empty:
            result = run_cli("protocols", "--protocol", "https", "--sweep", "bearer-default",
                             "--alg", "ES256", "--step", "4096", "--max-bytes", "4096",
                             "--timeout", "30", "--run-dir", run_dir, "--output-dir", output,
                             cwd=self.directory,
                             environment=cli_environment(PLAYWRIGHT_BROWSERS_PATH=empty))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        self.assertNotIn("-----BEGIN", result.stderr + result.stdout)
        self.assertFalse((output / "protocols.json").exists())
        self.assertTrue(run_ports(run_dir), "no stack was started")
        self.check_stopped(run_dir)

    def test_signals_stop_the_run_and_every_process(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum.name):
                run_dir = self.directory / f"signal-{signum.name}"
                output = self.directory / f"signal-out-{signum.name}"
                # Small steps keep the sweep running well past the first token request.
                command = [sys.executable, str(SCRIPT), "protocols", "--protocol", "https",
                           "--sweep", "bearer-default", "--alg", "ES256", "--step", "1024",
                           "--max-bytes", "12288", "--run-dir", str(run_dir),
                           "--output-dir", str(output)]
                process = subprocess.Popen(command, cwd=self.directory, env=cli_environment(),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    log = run_dir / "https-bearer-default" / "logs" / "proxy-access.log"
                    eventually(lambda: process.poll() is not None
                               or "/api/token/" in read_text(log), grace=SIGNAL_GRACE)
                    self.assertIsNone(process.poll(), "the run ended before the signal")
                    process.send_signal(signum)
                    _, stderr = process.communicate(timeout=120)
                finally:
                    stop(process)
                self.assertEqual(process.returncode, 1, stderr)
                self.assertRegex(stderr, ERROR_LINE)
                self.assertFalse((output / "protocols.json").exists())
                self.assertTrue(run_ports(run_dir))
                self.check_stopped(run_dir)


class OtherCommandsTests(unittest.TestCase):
    """R1: every other subcommand's --help output is byte-identical to the base commit's."""

    def help_output(self, script: Path, command: str, cwd: Path) -> str:
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
            for command in OTHER_COMMANDS:
                with self.subTest(command=command):
                    self.assertEqual(self.help_output(SCRIPT, command, Path(directory)),
                                     self.help_output(base, command, Path(directory)))


# ---- R7, R5: what the TLS code never does --------------------------------------------------

def code_without_docstrings(path: Path) -> str:
    """A module's code without comments or docstrings, so prose may name what it avoids."""
    tree = ast.parse(read_text(path))
    for node in ast.walk(tree):
        if (isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class SourceTests(unittest.TestCase):
    FILES = ("transport_stack.py", "transport_tls.py", "transport_protocols.py",
             "transport_sweep.py", "transport_tokens.py")
    FORBIDDEN = (r"CERT_NONE", r"_create_unverified_context",
                 r"check_hostname\s*=\s*False", r"ignore-certificate-errors",
                 r"allow-insecure-localhost", r"add-trusted-cert", r"\bcertutil\b",
                 r"PYTHONHTTPSVERIFY")

    def test_verification_is_never_disabled_and_no_trust_store_is_touched(self):
        for name in self.FILES:
            path = REPO / "scripts" / name
            self.assertTrue(path.is_file(), f"scripts/{name} is missing")
            code = code_without_docstrings(path)
            for pattern in self.FORBIDDEN:
                with self.subTest(file=name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, code))

    def test_chromium_accepts_the_certificate_per_context(self):
        code = "\n".join(code_without_docstrings(REPO / "scripts" / name)
                         for name in ("transport_stack.py", "transport_tokens.py",
                                      "transport_sweep.py"))
        self.assertRegex(code, r"\bignore_https_errors\b")


# ---- R15: Makefile -------------------------------------------------------------------------

class MakefileTests(unittest.TestCase):
    RECIPE = '\t$(STACK) protocols --output-dir "$(PROTOCOLS_DIR)"'
    ASSIGNMENT = ("PROTOCOLS_DIR ?= results/transport/$(shell date -u +%Y%m%dT%H%M%SZ)"
                  "-$(LOAD_PLATFORM)")

    @classmethod
    def setUpClass(cls):
        cls.text = read_text(MAKEFILE)

    def make(self, *arguments: str) -> subprocess.CompletedProcess:
        make = shutil.which("make")
        if make is None:
            self.skipTest("make is not installed")
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("MAKEFLAGS", "MFLAGS", "PROTOCOLS_DIR", "SWEEP_DIR",
                                      "LOAD_DIR", "CLAIMS_DIR", "COOKIES_DIR", "REFS_DIR")}
        return subprocess.run([make, "--no-print-directory", *arguments], cwd=REPO,
                              env=environment, capture_output=True, text=True, timeout=60)

    def test_target_is_phony_and_in_help(self):
        phony = next((line for line in self.text.splitlines() if line.startswith(".PHONY:")), "")
        self.assertIn("protocols", phony.split())
        result = self.make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line for line in result.stdout.splitlines() if line.startswith("make protocols")]
        self.assertEqual(len(lines), 1, result.stdout)
        lowered = lines[0].lower()
        for term in ("cookie", "bearer", "https", "http/2", "sprint 2"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_recipe_and_output_directory(self):
        self.assertIn(self.ASSIGNMENT, self.text.splitlines())
        blocks = make_blocks(self.text)
        self.assertIn("protocols", blocks)
        self.assertEqual(blocks["protocols"][1:], [self.RECIPE])
        result = self.make("-n", "protocols", "PROTOCOLS_DIR=results/transport/dry-run",
                           "PYTHON=python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scripts/transport_stack.py protocols --output-dir '
                      '"results/transport/dry-run"', result.stdout)
        if sys.platform == "darwin":
            result = self.make("-n", "protocols", "PYTHON=python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout,
                             r'protocols --output-dir "results/transport/\d{8}T\d{6}Z-macos"')

    def test_everything_else_unchanged(self):
        before = git_show("Makefile")
        if before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        old, new = make_blocks(before), make_blocks(self.text)
        self.assertLessEqual(set(old) | {"protocols"}, set(new))
        for target, lines in old.items():
            with self.subTest(target=target):
                if target == "help":
                    added = [line for line in new[target] if line not in lines]
                    self.assertEqual(len(added), 1, added)
                    self.assertTrue(added[0].startswith('\t@echo "make protocols'), added)
                    self.assertEqual([line for line in new[target] if line in lines], lines)
                else:
                    self.assertEqual(new[target], lines)
        assignments = [line for line in before.splitlines()
                       if re.match(r"^[A-Z_]+ *(\?|:)?=", line)]
        self.assertTrue(any(line.startswith("SWEEP_DIR ") for line in assignments))
        for line in assignments:
            with self.subTest(line=line):
                self.assertIn(line, self.text.splitlines())
        phony_before = next(line for line in before.splitlines() if line.startswith(".PHONY:"))
        phony_after = next(line for line in self.text.splitlines() if line.startswith(".PHONY:"))
        self.assertLessEqual(set(phony_before.split()) | {"protocols"}, set(phony_after.split()))


# ---- R16: the committed run ----------------------------------------------------------------

class CommittedRunTests(ProtocolsCase):
    @classmethod
    def setUpClass(cls):
        cls.found = committed_runs()
        cls.run_dir = cls.found[0] if len(cls.found) == 1 else None
        cls.saved = load_json(cls.run_dir / "protocols.json") if cls.run_dir else None

    def setUp(self):
        self.assertEqual(len(self.found), 1, "expected one results/transport/"
                                             "<YYYYMMDDTHHMMSSZ>-macos/ run with a "
                                             f"protocols.json, found {self.found}")

    def test_one_new_run_directory_tracked_by_git(self):
        names = {path.name for path in TRANSPORT_RUNS.iterdir()
                 if path.is_dir() and not path.name.startswith(".")}
        self.assertEqual(names, {SPRINT_2_NAME, self.run_dir.name})
        tracked = (git("ls-files", "--", f"results/transport/{self.run_dir.name}") or "").split()
        self.assertIn(f"results/transport/{self.run_dir.name}/protocols.json", tracked)
        on_disk = {f"results/transport/{self.run_dir.name}/{path}"
                   for path in files_of(self.run_dir)}
        self.assertEqual(set(tracked), on_disk)

    def test_saved_run(self):
        self.check_saved_run(self.run_dir, {"https", "h2"},
                             {"protocols": ["https", "h2"], "sweeps": list(SWEEP_NAMES),
                              "algorithms": NAMES, "baseline": BASELINE_SETTING,
                              "step": None, "max_bytes": None, "timeout": 60},
                             {name: (definition["step"], definition["max_bytes"])
                              for name, definition in SWEEP_DEFINITIONS.items()})

    def test_eight_runs(self):
        self.assertEqual([run["directory"] for run in self.saved["runs"]],
                         [f"{protocol}-{sweep}" for protocol in ("https", "h2")
                          for sweep in SWEEP_NAMES])

    def test_recorded_on_apple_silicon_macos(self):
        environment = self.saved["environment"]
        self.assertTrue(str(environment.get("platform", "")).startswith("macOS"), environment)
        self.assertEqual(environment.get("machine"), "arm64")
        self.assertEqual(environment.get("page_size_bytes"), 16384)
        self.assertRegex(str(environment.get("git_commit")), r"^[0-9a-f]{40}$")

    def test_recorded_with_temporary_run_directories(self):
        # make protocols with TMPDIR unset puts each stack in a new directory under /tmp.
        for run in self.saved["runs"]:
            run_dir = self.sweep_of(self.run_dir, run)["run_dir"]
            with self.subTest(run=run["directory"]):
                self.assertTrue(run_dir.startswith(("/tmp/", "/private/tmp/")), run_dir)

    def test_https_bearer_default_matches_sprint_2(self):
        rows = [row for row in self.saved["comparison"] if row["sweep"] == "bearer-default"]
        self.assertEqual(len(rows), 2 * len(NAMES))
        for row in rows:
            with self.subTest(algorithm=row["algorithm"], client=row["client"]):
                self.assertIs(row["moved"]["https"], False)

    def test_summary_lines(self):
        lines = summary_lines(self.saved)
        self.assertEqual(len(lines), len(self.saved["runs"]) + len(self.saved["comparison"]))


# ---- R17: TRANSPORT_RESULTS.md -------------------------------------------------------------

class TransportResultsDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(TRANSPORT_RESULTS)
        found = committed_runs()
        cls.run_dir = found[0] if len(found) == 1 else None
        cls.saved = load_json(cls.run_dir / "protocols.json") if cls.run_dir else None

    def body(self) -> str:
        body = section(self.text, SECTION)
        self.assertIsNotNone(body, f"missing heading: ## {SECTION}")
        return body

    def require_run(self) -> dict:
        self.assertIsNotNone(self.saved, "no committed results/transport/<run>-macos/ run")
        return self.saved

    def test_heading_between_byte_accounting_and_reproduce(self):
        names = [name for depth, name, _ in headings(self.text.splitlines()) if depth == 2]
        self.assertEqual(names.count(SECTION), 1, names)
        position = names.index(SECTION)
        self.assertEqual(names[position - 1], "Byte accounting")
        self.assertEqual(names[position + 1], "Reproduce")
        self.assertIn(ANCHOR, anchors(TRANSPORT_RESULTS))
        before = git_show("TRANSPORT_RESULTS.md")
        if before is not None:
            old = [name for depth, name, _ in headings(before.splitlines()) if depth == 2]
            self.assertEqual([name for name in names if name != SECTION], old)

    def test_platform_date_commit_and_link(self):
        saved, body = self.require_run(), self.body()
        for term in ("macOS", "Apple Silicon", "16 KiB"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        shown = dates_shown(parse_utc(saved["started_utc"]), parse_utc(saved["finished_utc"]))
        self.assertTrue(any(date in body for date in shown), shown)
        self.assertIn(saved["environment"]["git_commit"][:7], body)
        self.assertIn(f"results/transport/{self.run_dir.name}/protocols.json",
                      relative_links(body))

    def test_protocols_and_certificate(self):
        body = self.body()
        for term in ("HTTP/1.1", "TLS", "ALPN", "http2 on;", "HTTP/3", "http_v3", "self-signed",
                     "127.0.0.1", "localhost", "experiment key", "not a production credential"):
            with self.subTest(term=term):
                self.assertIn(term, body)

    def test_runs_table_links_each_run(self):
        saved, links = self.require_run(), relative_links(self.body())
        for run in saved["runs"]:
            base = f"results/transport/{self.run_dir.name}/{run['directory']}"
            for target in (f"{base}/sweep.json", f"{base}/logs/", f"{base}/nginx.conf"):
                with self.subTest(target=target):
                    self.assertIn(target, links)

    def test_boundaries_table_follows_the_comparison(self):
        saved = self.require_run()
        sub = section(self.body(), "Boundaries compared with Sprint 2", 3)
        self.assertIsNotNone(sub, "missing heading: ### Boundaries compared with Sprint 2")
        lines = [line.strip() for line in sub.splitlines()]
        header = PLAIN_HEADER if "http" in saved["settings"]["protocols"] else TABLE_HEADER
        starts = [index for index, line in enumerate(lines) if line.startswith("| Sweep |")]
        self.assertEqual(len(starts), 1, "expected one boundaries table")
        self.assertEqual(lines[starts[0]], header)
        rows = []
        for line in lines[starts[0] + 1:]:
            if not line.startswith("|"):
                break
            if not re.fullmatch(r"[|:\-\s]+", line):
                rows.append(cells(line))
        comparison = saved["comparison"]
        self.assertTrue(comparison, "protocols.json has no comparison rows")
        self.assertEqual(len(rows), len(comparison))
        for row_cells, row in zip(rows, comparison):
            label = (row["sweep"], row["algorithm"], row["client"])
            with self.subTest(row=label):
                summaries = [row["baseline"], *row["measured"].values()]
                self.assertEqual(len(row_cells), 4 + len(summaries))
                self.assertEqual(plain(row_cells[0]), row["sweep"])
                self.assertEqual(plain(row_cells[1]), row["algorithm"])
                self.assertEqual(plain(row_cells[2]), CLIENT_NAMES[row["client"]])
                for cell, item in zip(row_cells[3:-1], summaries):
                    largest = None if item is None else item["largest_verified_token_bytes"]
                    expected = "none" if largest is None else f"{largest:,}"
                    self.assertRegex(plain(cell), rf"(?i)^{re.escape(expected)}(?!\d|,\d)")
                why = plain(row_cells[-1])
                if any(moved is True for moved in row["moved"].values()):
                    self.assertNotEqual(why.lower(), "unchanged")
                    self.assertTrue(any(layer in why for layer in ("Chromium", "nginx",
                                                                   "waitress")), why)
                    self.assertTrue("protocol" in why.lower() or "platform" in why.lower(), why)
                else:
                    self.assertEqual(why.lower(), "unchanged")

    def test_prose(self):
        body = self.body()
        lowered = body.lower()
        # (a) cookie-default is also compared with Sprint 2's cookie-16k; (b) layers and
        # limits; (c) negotiated protocols; (d) http.client rows are HTTP/1.1 controls.
        for term in ("cookie-16k", "proxy_buffer_size", "4 KiB", "HTTP/2.0", "http.client",
                     "Chromium", "nginx"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        for term in ("negotiated", "control", "hpack"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        if re.search(r"(?i)hpack[- ]encoded[^.]*\d", body):  # Such sizes are calculated.
            self.assertIn("calculated", lowered)

    def test_reproduce_commands(self):
        body = self.body()
        self.assertIn("make protocols", body)
        self.assertRegex(body, r"transport_stack\.py\s+protocols")

    def test_question_5_links_the_section(self):
        questions = section(self.text, "Questions for Sprint 3")
        self.assertIsNotNone(questions, "missing heading: ## Questions for Sprint 3")
        fifth = [line for line in questions.splitlines() if line.startswith("5. ")]
        self.assertEqual(len(fifth), 1, questions)
        self.assertIn(f"](#{ANCHOR})", fifth[0])

    def test_other_lines_unchanged(self):
        before = git_show("TRANSPORT_RESULTS.md")
        if before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        may_change = ("5. **HTTPS and HTTP/2 (S3-04):**", "- **One machine.**",
                      "- **One browser, HTTP/1.1, no TLS.**")
        kept = [line for line in before.splitlines() if not line.startswith(may_change)]
        self.assertTrue(is_subsequence(kept, self.text.splitlines()),
                        [line for line in kept if line not in self.text.splitlines()][:5])
        self.assertTrue(any("](MITIGATION_RESULTS.md" in line for line in kept))

    def test_links_resolve(self):
        check_links_resolve(self, TRANSPORT_RESULTS)
        for link in re.findall(r"\]\(#([^)\s]+)\)", self.text):
            with self.subTest(anchor=link):
                self.assertIn(link, anchors(TRANSPORT_RESULTS))


# ---- R18: TRANSPORT.md ---------------------------------------------------------------------

class TransportDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(TRANSPORT_DOC)
        cls.before = git_show("TRANSPORT.md")

    def section(self, text: str, title: str, level: int) -> str:
        body = section(text, title, level)
        self.assertIsNotNone(body, f"missing heading: {'#' * level} {title}")
        return body

    def require_before(self) -> str:
        if self.before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        return self.before

    def test_protocols_subsection_follows_refs(self):
        run_check = self.section(self.text, "Run the check", 2)
        order = [name for depth, name, _ in headings(run_check.splitlines()) if depth == 3]
        for name in ("The cookies command", "The refs command", "The protocols command"):
            self.assertEqual(order.count(name), 1, order)
        self.assertEqual(order.index("The refs command"), order.index("The cookies command") + 1)
        self.assertEqual(order.index("The protocols command"),
                         order.index("The refs command") + 1)

    def test_protocols_subsection(self):
        body = self.section(self.section(self.text, "Run the check", 2),
                            "The protocols command", 3)
        commands = [line for block in code_blocks(body) for line in block.splitlines()]
        self.assertTrue(any("make protocols" in line for line in commands)
                        or "make protocols" in body)
        self.assertTrue(any(re.search(r"transport_stack\.py[\"']?\s+protocols\b.*--output-dir",
                                      line) for line in commands), commands)
        lines = body.splitlines()
        for option in OPTIONS:
            with self.subTest(option=option):
                self.assertTrue(any(line.startswith("|") and option in line for line in lines))
        for option, default in (("--output-dir", "required"), ("--protocol", "https"),
                                ("--protocol", "h2"), ("--sweep", "all four"),
                                ("--alg", "all six"), ("--baseline", SPRINT_2_NAME),
                                ("--run-dir", "temporary")):
            with self.subTest(default=(option, default)):
                # Lowercase both sides: SPRINT_2_NAME has the capitals T and Z.
                self.assertTrue(any(line.startswith("|") and option in line
                                    and default.lower() in line.lower() for line in lines))
        with self.subTest(default="--timeout"):
            self.assertTrue(any(line.startswith("|") and "--timeout" in line
                                and contains_number(line, 60) for line in lines))
        for option in ("--step", "--max-bytes"):
            with self.subTest(default=option):
                self.assertTrue(any(line.startswith("|") and option in line
                                    and ("none" in line.lower() or "own" in line.lower())
                                    for line in lines))
        lowered = body.lower()
        for term in ("exit 2", "exit 1", "usage", "error: ", "certificate.pem",
                     "experiment-key.pem", "0600", "ignore_https_errors", "alpn", "http/1.1",
                     "listen", "ssl_certificate", "ssl_certificate_key", "http2 on;",
                     "negotiated", "private_key_saved", "protocols.json", "sweep.json",
                     "comparison", "sweep_definitions", "start_tls_stack", "tlsstack",
                     "run_check",
                     "http_get", "run_protocols(output_dir", "compare_sweeps", "summary_lines",
                     "generate_certificate", "certificate_details", "client_context",
                     "scripts/transport_protocols.py", "scripts/transport_tls.py",
                     f"transport_results.md#{ANCHOR}"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_configuration_bullet_for_the_tls_directives(self):
        body = self.section(self.text, "Configuration that is not a default", 3)
        bullets = [line for line in body.splitlines()
                   if line.startswith("- ") and "ssl_certificate" in line]
        self.assertTrue(bullets, body)
        self.assertTrue(any("Not a default" in line for line in bullets), bullets)
        old = self.section(self.require_before(), "Configuration that is not a default", 3)
        for line in old.splitlines():
            with self.subTest(line=line[:60]):
                self.assertIn(line, body.splitlines())

    def test_plain_http_limitation(self):
        body = self.section(self.text, "Limitations", 2)
        bullets = [line for line in body.splitlines()
                   if line.startswith("- **Plain HTTP/1.1 on 127.0.0.1")]
        self.assertEqual(len(bullets), 1, body)
        for term in ("protocols", "HTTP/3", "out of scope", "HTTP/1.1", "HTTP/2", "127.0.0.1",
                     "Secure"):
            with self.subTest(term=term):
                self.assertIn(term, bullets[0])

    def test_level_2_headings_and_fixed_sections_unchanged(self):
        before = self.require_before()

        def level_2(text: str) -> list[str]:
            return [name for depth, name, _ in headings(text.splitlines()) if depth == 2]

        def stack_table(text: str) -> list[str]:
            body = section(text, "Stack") or ""
            first = next((index for depth, _, index in headings(body.splitlines())
                          if depth == 3), None)
            return table_rows("\n".join(body.splitlines()[:first]))

        def limits_table(text: str) -> list[str]:
            body = section(text, "Versions and documented limits") or ""
            first = next((index for depth, _, index in headings(body.splitlines())
                          if depth == 3), None)
            return table_rows("\n".join(body.splitlines()[:first]))

        self.assertEqual(level_2(self.text), level_2(before))
        self.assertTrue(stack_table(before))
        self.assertEqual(stack_table(self.text), stack_table(before))
        self.assertTrue(limits_table(before))
        self.assertEqual(limits_table(self.text), limits_table(before))
        self.assertEqual(section(self.text, "Support for Sprint 2 tasks"),
                         section(before, "Support for Sprint 2 tasks"))

    def test_links_resolve(self):
        check_links_resolve(self, TRANSPORT_DOC)


# ---- R19: PROGRESS.md ----------------------------------------------------------------------

class ProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(PROGRESS)
        cls.before = git_show("PROGRESS.md")

    def setUp(self):
        if self.before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")

    def test_s3_04_items_checked(self):
        old, new = section(self.before, "S3-04", 3), section(self.text, "S3-04", 3)
        self.assertIsNotNone(new, "missing heading: ### S3-04")
        old_items = re.findall(r"(?m)^- \[ \] (.*)$", old)
        self.assertEqual(len(old_items), 3)
        items = re.findall(r"(?m)^- \[( |x)\] (.*)$", new)
        self.assertEqual([text for _, text in items], old_items)
        self.assertEqual([mark for mark, _ in items], ["x", "x", "x"])

    def test_s3_04_status(self):
        new = section(self.text, "S3-04", 3)
        self.assertIsNotNone(new, "missing heading: ### S3-04")
        lines = new.splitlines()
        status = [index for index, line in enumerate(lines) if line.startswith("**Status:**")]
        done = [index for index, line in enumerate(lines) if line.startswith("**Done when:**")]
        self.assertEqual(len(status), 1, new)
        self.assertEqual(len(done), 1, new)
        self.assertGreater(status[0], done[0])
        line = lines[status[0]]
        self.assertTrue("make protocols" in line or "transport_stack.py protocols" in line, line)
        for term in ("macOS", "HTTPS", "HTTP/2", "HTTP/3", "out of scope", "WSL2",
                     f"TRANSPORT_RESULTS.md#{ANCHOR}"):
            with self.subTest(term=term):
                self.assertIn(term, line)
        self.assertTrue(any(layer in line for layer in ("nginx", "Chromium", "waitress")), line)
        self.assertIn("not", line.lower())
        found = committed_runs()
        if len(found) == 1:
            self.assertIn(found[0].name, line)
            saved = load_json(found[0] / "protocols.json")
            shown = dates_shown(parse_utc(saved["started_utc"]),
                                parse_utc(saved["finished_utc"]))
            self.assertTrue(any(date in line for date in shown), shown)
        else:
            self.fail(f"expected one committed macOS protocols run, found {found}")

    def test_done_when_lines_and_other_sections_unchanged(self):
        def done_when(text: str) -> list[str]:
            return [line for line in text.splitlines() if line.startswith("**Done when:**")]
        self.assertEqual(done_when(self.text), done_when(self.before))
        self.assertEqual(self.text.split("\n### S3-04", 1)[0],
                         self.before.split("\n### S3-04", 1)[0])
        self.assertEqual(self.text.split("\n## Follow-up backlog", 1)[1:],
                         self.before.split("\n## Follow-up backlog", 1)[1:])

    def test_links_resolve(self):
        check_links_resolve(self, PROGRESS)


# ---- R20: README.md ------------------------------------------------------------------------

class ReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_text(README)
        cls.before = git_show("README.md")

    def test_make_shortcuts(self):
        shortcuts = section(self.text, "Make shortcuts")
        self.assertIsNotNone(shortcuts, "missing heading: ## Make shortcuts")
        lines = [line.strip() for block in code_blocks(shortcuts) for line in block.splitlines()]
        protocols_lines = [line for line in lines if line.startswith("make protocols")]
        self.assertEqual(len(protocols_lines), 1, lines)
        self.assertIn("#", protocols_lines[0])
        self.assertTrue(protocols_lines[0].endswith("results/transport/<time>/"),
                        protocols_lines[0])
        if self.before is not None:
            old = [line.strip() for block in code_blocks(section(self.before, "Make shortcuts")
                                                         or "") for line in block.splitlines()]
            self.assertEqual([line for line in lines if line not in old], protocols_lines)
            for line in old:
                self.assertIn(line, lines)

    def test_project_status(self):
        status = section(self.text, "Project status")
        self.assertIsNotNone(status, "missing heading: ## Project status")
        self.assertIn("S3-04", status)
        self.assertIn(f"TRANSPORT_RESULTS.md#{ANCHOR}", relative_links(status))

    def test_every_existing_line_and_link_kept(self):
        if self.before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        self.assertTrue(is_subsequence(self.before.splitlines(), self.text.splitlines()))
        links = set(relative_links(self.text))
        for link in relative_links(self.before):
            self.assertIn(link, links)
        check_links_resolve(self, README)


# ---- R21: RECOMMENDATIONS.md ---------------------------------------------------------------

class RecommendationsTests(unittest.TestCase):
    BULLET = "- **HTTP/1.1 without TLS.**"

    def test_only_the_tls_limitation_may_change(self):
        before = git_show("RECOMMENDATIONS.md")
        if before is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        old_lines, new_lines = before.splitlines(), read_text(RECOMMENDATIONS).splitlines()
        self.assertEqual(len(new_lines), len(old_lines))

        def numbers(text: str) -> set[str]:
            return set(re.findall(r"\d+(?:[.,]\d+)*", re.sub(r"\]\([^)]*\)", "]", text)))

        for old, new in zip(old_lines, new_lines):
            if not old.startswith(self.BULLET):
                self.assertEqual(new, old)
                continue
            self.assertTrue(new.startswith(self.BULLET), new)
            for term in ("HTTPS", "HTTP/2", "S3-04"):
                with self.subTest(term=term):
                    self.assertIn(term, new)
            self.assertIn("not measured", new.lower())
            self.assertLessEqual(numbers(new), numbers(old))
            if new != old:
                self.assertIn(f"TRANSPORT_RESULTS.md#{ANCHOR}", relative_links(new))

    def test_report_check_passes(self):
        result = subprocess.run([sys.executable, str(REPO / "scripts" / "transport_report.py"),
                                 "--check"], cwd=REPO, capture_output=True, text=True,
                                timeout=600, env=cli_environment())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


# ---- R22: what stays unchanged -------------------------------------------------------------

class UnchangedTests(unittest.TestCase):
    def require(self, value):
        if value is None:
            self.skipTest(f"{BASE_COMMIT} is not available in this checkout")
        return value

    def test_pinned_files_existing_tests_and_earlier_results_unchanged(self):
        tests = self.require(git("ls-tree", "--name-only", BASE_COMMIT, "tests/")).split()
        # The test page gained a read-only mode later (tests/test_transport_pages.py checks
        # it), so it is not frozen here, and these two tests stopped freezing it.
        later = {"tests/test_transport_cookies.py", "tests/test_transport_refs.py"}
        tests = [path for path in tests if path not in later]
        # Tests edited when the documents moved to results/ are not frozen here.
        tests = [path for path in tests if path not in MOVE_EDITED_TESTS]
        self.assertTrue(tests)
        paths = ["transport/stack.json", "requirements.txt", "transport/requirements.txt",
                 "transport/conda-requirements.txt", "transport/setup.sh",
                 "transport/nginx.conf.template", "fixtures",
                 "scripts/transport_app.py", "scripts/transport_load.py",
                 "scripts/transport_claims.py", "scripts/transport_cookies.py",
                 # transport_report.py was edited to write results/RECOMMENDATIONS.md.
                 "scripts/transport_refs.py", "RESULTS.md",
                 "END_TO_END_RESULTS.md", "MITIGATION_RESULTS.md", "results/load",
                 "results/claims", "results/cookies", "results/refs",
                 f"results/transport/{SPRINT_2_NAME}", ":(glob)results/2026110*/**", *tests]
        # The documents moved to results/ later: compare their text with BASE_COMMIT's.
        paths, documents = split_moved(paths)
        changed = self.require(git("diff", "--name-only", BASE_COMMIT, "--", *paths)).split()
        changed += changed_moved(BASE_COMMIT, documents)
        untracked = self.require(git("ls-files", "--others", "--exclude-standard", "--",
                                     *paths)).split()
        self.assertEqual(changed + untracked, [])

    def test_no_new_results_outside_one_transport_run(self):
        top = set(self.require(git("ls-tree", "--name-only", BASE_COMMIT, "results/")).split())
        # The documents that moved to results/ later are files beside the run folders.
        on_disk = {f"results/{name}" for name in visible_names(REPO / "results")
                   if not name.endswith(".md")}
        self.assertEqual(on_disk, top)
        for directory in ("results/load", "results/claims", "results/cookies", "results/refs"):
            with self.subTest(directory=directory):
                listing = self.require(git("ls-tree", "--name-only",
                                           f"{BASE_COMMIT}:{directory}")).split()
                self.assertEqual(visible_names(REPO / directory), set(listing))
        listing = set(self.require(git("ls-tree", "--name-only",
                                       f"{BASE_COMMIT}:results/transport")).split())
        added = visible_names(TRANSPORT_RUNS) - listing
        self.assertLessEqual(listing, visible_names(TRANSPORT_RUNS))
        self.assertEqual(len(added), 1, added)
        self.assertRegex(added.pop(), RUN_NAME)


if __name__ == "__main__":
    unittest.main()
