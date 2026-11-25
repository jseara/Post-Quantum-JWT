"""Check the S2-02 token endpoints, layer logs, and token check end to end; no timing thresholds."""

import ast
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
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
import string
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlsplit
from wsgiref.util import setup_testing_defaults

from scripts import transport_app, transport_stack
from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.transport_stack import (MANIFEST_PATH, Stack, http_get, installed_versions,
                                     load_manifest, run_check, start_stack)


from tests.moved_docs import HISTORY, DocPath, moved, repo_file
REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
APP_SCRIPT = REPO / "scripts" / "transport_app.py"
MANIFEST = REPO / "transport" / "stack.json"
NGINX_TEMPLATE = REPO / "transport" / "nginx.conf.template"
DOC = moved("TRANSPORT.md")
PROGRESS = moved("PROGRESS.md")
CLAIMS = json.loads((REPO / "fixtures" / "claims.json").read_text(encoding="utf-8"))
NAMES = [adapter.name for adapter in ADAPTER_LIST]
SLH_DSA = ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f")
# Token sizes over the Sprint 1 fixture (RESULTS.md); the spec fixes them for S2-02.
TOKEN_BYTES = {"RS256": 464, "ES256": 208, "EdDSA": 208, "ML-DSA-44": 3355,
               "SLH-DSA-SHA2-128s": 10613, "SLH-DSA-SHA2-128f": 22922}
TRANSPORTS = ("cookie", "bearer")
COOKIE_ATTRIBUTES = "; Path=/; HttpOnly; SameSite=Strict"
JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
SET_COOKIE = re.compile(rf"jwt=(?P<token>{JWS.pattern}){re.escape(COOKIE_ATTRIBUTES)}")
SIZE_FIELDS = ["headers", "header_bytes", "cookie_bytes", "authorization_bytes"]
VERIFIED_KEYS = {"layer", "verified", "algorithm", "source", "token_bytes", "claims",
                 "experiment_key", "received"}
FAILED_KEYS = {"layer", "verified", "source", "error", "experiment_key", "received"}
ENTRY_KEYS = ("algorithm", "transport", "token_bytes", "expected", "outcome", "rejected_by", "ok",
              "page_status", "cookie_stored", "evidence", "issue", "verify", "direct")
COOKIE_KEYS = {"name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite"}
LOG_LINE = re.compile(r'(?P<remote>\S+) "(?P<method>[A-Z]+) (?P<target>\S+) '
                      r'(?P<protocol>HTTP/[\d.]+)" (?P<status>\d{3})(?P<fields>(?: [a-z_]+=\S*)*)$')
NONCE = re.compile(r"[0-9a-f]{32}")
URL = re.compile(r"http://127\.0\.0\.1:(\d+)")
ERROR_LINE = re.compile(r"^Error:", re.MULTILINE)
LOG_FILES = {"browser": "browser.log", "proxy_access": "proxy-access.log",
             "proxy_error": "proxy-error.log", "app": "app.log"}
LAYERS = ("browser", "proxy", "app_server", "application")
LAYER_WORDS = {"browser": ("browser", "chromium"), "proxy": ("proxy", "nginx"),
               "app_server": ("app_server", "waitress", "application server"),
               "application": ("application", "app")}
EVIDENCE_LIMIT = 1000
CLI_TIMEOUT = 300
GRACE = 15.0
REQUEST_SKIP = {"host", "connection", "keep-alive", "proxy-connection", "te", "trailer",
                "transfer-encoding", "upgrade", "accept-encoding"}
RESPONSE_SKIP = {"connection", "keep-alive", "transfer-encoding", "content-length", "server",
                 "date"}
WAITRESS_SIZE_ARGUMENTS = {"max_request_header_size", "max_request_body_size", "recv_bytes",
                           "send_bytes", "inbuf_overflow", "outbuf_overflow",
                           "outbuf_high_watermark"}
LOG_FORMAT = ('$remote_addr [$time_local] "$request" $status $body_bytes_sent '
              "request_length=$request_length upstream_status=$upstream_status")
PINS = {
    "requirements.txt": ["cryptography==50.0.2", "PyJWT==2.15.1", "pqcrypto==1.0.0"],
    "transport/requirements.txt": ["playwright==1.64.1", "greenlet==3.5.6", "pyee==14.0.0",
                                   "typing_extensions==4.16.0", "waitress==3.0.2", "cffi==2.1.1",
                                   "pycparser==3.12"],
    "transport/conda-requirements.txt": ["python=3.15.2=*_cp315", "pip==26.2.2", "nginx==1.31.8"],
}
# SHA-256 of each file's text with "\n" line endings, as committed before S2-02.
UNCHANGED = {
    "transport/stack.json": "e69a97cbd74c73756221f49238a32326a1123253a14cc9ca61055e46360c537d",
    "requirements.txt": "608306c7fd19ab1df99f7ceec76253f942766120fa1030da9f0e0b861653d15e",
    "transport/requirements.txt":
        "6cd9ababdd9b3e201581fb3513ab59a94e913e2683d0837d8244bb5df75f38c5",
    "transport/conda-requirements.txt":
        "c7343340877fed8de95c638401034c5a45d8f252f5e906b4163d487991a27f12",
}
# SHA-256 of the stripped S2-02 line in TRANSPORT.md's 'Support for Sprint 2 tasks', before S2-02.
S2_02_BULLET_BEFORE = "60eaaf19ecb1079dc2843d548421427c0de2627fc5cc56dbae243d19b0c1e67e"
# role: (version, cookie bytes, single header bytes, total header bytes) in transport/stack.json.
DOCUMENTED = {"automation": ("1.64.1", None, None, None),
              "browser": ("156.0.8078.4", 4096, None, None),
              "proxy": ("1.31.8", None, 8192, 32768),
              "app_server": ("3.0.2", None, None, 262144)}
HEADINGS = ("Stack", "Versions and documented limits", "Setup", "Run the check",
            "Support for Sprint 2 tasks", "Limitations")
S2_02_ITEMS = (
    "Add a minimal application with one endpoint that issues a token as a cookie and one that "
    "accepts a token from either a cookie or a Bearer header and verifies it with the adapters "
    "in [scripts/algorithms.py](scripts/algorithms.py).",
    "Put the reverse proxy in front of the application, and serve the test page the browser "
    "loads through the proxy.",
    "Log enough at each layer to tell which one handled or rejected a request: the browser's "
    "cookie jar and request headers, the proxy's access and error logs, and the application's "
    "log of received header sizes.",
)
DONE_WHEN = (
    "**Done when:** A normal-sized token from each of the six configurations verifies at the "
    "application as both a cookie and a Bearer header. Sent browser → proxy → application, "
    "every token within the default limits verifies, every other token is rejected with the "
    "rejecting layer identified, and each layer's log shows every request that reached it."
)
OTHER_DONE_WHEN = (
    "**Done when:** The stack runs from a clean checkout on both team machines, and a table lists "
    "every layer with its version and documented limits.",
    "**Done when:** Any configuration can produce a verified token at a requested size, and the "
    "byte accounting for a request can be checked by hand.",
    "**Done when:** For each configuration, the largest cookie-carried token that reaches the "
    "application is known, along with the first layer that rejects a larger one and the "
    "evidence.",
    "**Done when:** For each configuration, the largest Bearer-carried token that reaches the "
    "application is known for both clients, and the next limit behind the first one is "
    "recorded.",
    "**Done when:** Another team member can reproduce the sweeps from a clean checkout, and every "
    "reported boundary can be traced to raw evidence.",
    "**Done when:** For each configuration, the results show how much of the end-to-end "
    "difference comes from token size and how much from verification.",
    "**Done when:** Each mitigation has run under the S3-01 workload, with its effect on the size "
    "limits and on latency recorded.",
    "**Done when:** The results are reproducible from a clean checkout, and every recommendation "
    "can be traced to a measurement.",
)

IMPORT_ONLY = """\
import sys
sys.path.insert(0, sys.argv[1])
import scripts.transport_app
print("imported")
"""
IMPORT_CHECK = """\
import importlib
import sys
sys.path.insert(0, sys.argv[1])
for name in sys.argv[2:]:
    importlib.import_module(name)
import scripts.transport_stack as stack
print(callable(stack.run_token_check))
"""
# A fresh process, so these really are the first token requests the application sees.
FIRST_USE = """\
import json
import sys
import threading
from wsgiref.util import setup_testing_defaults

sys.path.insert(0, sys.argv[1])
from scripts import transport_app

COUNT = 8
barrier = threading.Barrier(COUNT)
issued, verified, errors = [None] * COUNT, [None] * COUNT, []


def request(target, headers):
    path, _, query = target.partition("?")
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query, **headers}
    setup_testing_defaults(environ)
    started = []

    def start_response(status, response_headers, exc_info=None):
        started.append(status)
        return lambda data: None

    body = b"".join(transport_app.application(environ, start_response))
    return int(started[0].split()[0]), json.loads(body)


def worker(index):
    try:
        barrier.wait(timeout=60)
        issued[index] = request("/api/token/issue?alg=RS256&delivery=body", {})
        barrier.wait(timeout=60)
        token = issued[(index + 1) % COUNT][1].get("token", "")
        verified[index] = request("/api/token/verify", {"HTTP_AUTHORIZATION": f"Bearer {token}"})
    except Exception as error:
        barrier.abort()
        errors.append(repr(error))


threads = [threading.Thread(target=worker, args=(index,)) for index in range(COUNT)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print(json.dumps({"issued": issued, "verified": verified, "errors": errors}))
"""
# The application's keys come from ADAPTERS[name].generate_keypair() (R3); handing it a key pair
# the test also holds is the only way to sign an expired token the application would accept.
EXPIRED_CHECK = """\
import dataclasses
import json
import sys
import time
from wsgiref.util import setup_testing_defaults

sys.path.insert(0, sys.argv[1])
from scripts import algorithms

adapter = algorithms.ADAPTERS["ES256"]
pair = adapter.generate_keypair()
held = dataclasses.replace(adapter, generate_keypair=lambda: pair)
algorithms.ADAPTERS["ES256"] = held
algorithms.ADAPTER_LIST = tuple(held if item.name == "ES256" else item
                                for item in algorithms.ADAPTER_LIST)
from scripts import transport_app


def verify(claims):
    token = held.create_token(claims, pair[0])
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/token/verify",
               "HTTP_AUTHORIZATION": f"Bearer {token}"}
    setup_testing_defaults(environ)
    started = []

    def start_response(status, response_headers, exc_info=None):
        started.append(status)
        return lambda data: None

    body = b"".join(transport_app.application(environ, start_response))
    return int(started[0].split()[0]), json.loads(body)


claims = json.loads(sys.argv[2])
now = int(time.time())
print(json.dumps({"valid": verify({**claims, "exp": now + 3600}),
                  "expired": verify({**claims, "exp": now - 3600}),
                  "exp not a number": verify({**claims, "exp": "tomorrow"})}))
"""
RAISING_CHECK = """\
import sys
from pathlib import Path

sys.path[:0] = [entry for entry in sys.argv[1:3] if entry]
from scripts.transport_stack import run_token_check, start_stack

with start_stack(proxy_port=int(sys.argv[3]), app_port=int(sys.argv[4]),
                 run_dir=Path(sys.argv[5])) as stack:
    try:
        run_token_check(stack, algorithms=["ES256"], timeout=30)
    except RuntimeError as error:
        print(f"RuntimeError: {error}")
    else:
        print("returned without RuntimeError")
"""


# ---- in-process WSGI helpers -------------------------------------------------------------

def environ_for(target: str, headers=()) -> dict:
    """Build a plain WSGI environ for GET <target>; repeated headers are joined like waitress."""
    path, _, query = target.partition("?")
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query,
               "REQUEST_URI": target, "REMOTE_ADDR": "127.0.0.1", "SERVER_PROTOCOL": "HTTP/1.1"}
    for name, value in headers:
        key = name.upper().replace("-", "_")
        if key not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            key = f"HTTP_{key}"
        environ[key] = f"{environ[key]}, {value}" if key in environ else value
    setup_testing_defaults(environ)
    return environ


def call(target: str, headers=()) -> SimpleNamespace:
    """Call scripts.transport_app.application in process and collect its response."""
    started = {}

    def start_response(status, response_headers, exc_info=None):
        started.update(status=status, headers=list(response_headers))
        return lambda data: None

    chunks = transport_app.application(environ_for(target, headers), start_response)
    try:
        body = b"".join(chunks)
    finally:
        if hasattr(chunks, "close"):
            chunks.close()
    return SimpleNamespace(status=int(started["status"].split()[0]), headers=started["headers"],
                           names=[name.lower() for name, _ in started["headers"]], body=body)


def values_of(response: SimpleNamespace, name: str) -> list[str]:
    return [value for key, value in response.headers if key.lower() == name]


def received_sizes(headers: dict) -> dict:
    """Apply the R7 arithmetic to a header map as /api/echo returns it."""
    def size(text: str) -> int:
        return len(text.encode("latin-1"))

    return {"headers": len(headers),
            "header_bytes": sum(size(name) + size(value) + 4 for name, value in headers.items()),
            "cookie_bytes": size(headers["cookie"]) if "cookie" in headers else None,
            "authorization_bytes": (size(headers["authorization"])
                                    if "authorization" in headers else None)}


def logged(value) -> str:
    return "-" if value is None else str(value)


def log_fields(text: str) -> list[tuple[str, str]]:
    return [tuple(item.split("=", 1)) for item in text.split()]


def app_requests(text: str) -> list[SimpleNamespace]:
    """Parse the per-request lines of an app.log."""
    found = []
    for line in text.splitlines():
        match = LOG_LINE.search(line)
        if match:
            parts = urlsplit(match["target"])
            found.append(SimpleNamespace(
                line=line, path=parts.path, status=int(match["status"]),
                query=parse_qs(parts.query, keep_blank_values=True),
                fields=log_fields(match["fields"])))
    return found


def nonce_of(request: SimpleNamespace) -> str | None:
    values = request.query.get("nonce", [])
    return values[0] if values and NONCE.fullmatch(values[0]) else None


# ---- token helpers -----------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_segment(value) -> str:
    return b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def decode_segment(segment: str):
    return json.loads(urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def jose_header(token: str) -> dict:
    return decode_segment(token.split(".")[0])


def jose_claims(token: str) -> dict:
    return decode_segment(token.split(".")[1])


def flipped(segment: str) -> str:
    """Change one character in the middle of a base64url segment, which changes its bytes."""
    middle = len(segment) // 2
    return segment[:middle] + ("A" if segment[middle] != "A" else "B") + segment[middle + 1:]


def tampered(token: str) -> str:
    header, payload, signature = token.split(".")
    return f"{header}.{payload}.{flipped(signature)}"


def break_tokens(value: str) -> str:
    return JWS.sub(lambda match: tampered(match.group()), value)


def own_key_token(name: str, claims: dict) -> str:
    """Sign claims with a key pair the test creates, not one the application holds."""
    adapter = ADAPTERS[name]
    private_key, _ = adapter.generate_keypair()
    return adapter.create_token(claims, private_key)


def hs256_token(claims: dict) -> str:
    signing_input = f"{json_segment({'alg': 'HS256', 'typ': 'JWT'})}.{json_segment(claims)}"
    signature = hmac.new(b"k" * 32, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(signature)}"


def expected_outcome(manifest: dict, transport: str, token_bytes: int) -> str:
    """Apply the R15 rule to the documented limits of a manifest."""
    limits = {layer["role"]: layer["limits"] for layer in manifest["layers"]}
    cookie = limits["browser"]["cookie"]["bytes"]
    header_line = limits["proxy"]["single_header"]["bytes"]

    def fits(size: int, limit: int | None) -> bool:
        return limit is None or size <= limit

    if transport == "cookie":
        fit = (fits(len("jwt") + token_bytes, cookie)
               and fits(len("Cookie: jwt=") + token_bytes, header_line))
    else:
        fit = fits(len("Authorization: Bearer ") + token_bytes, header_line)
    return "verified" if fit else "rejected"


# ---- process, port, and file helpers (as in test_transport_stack.py) ---------------------

def port_of(url: str) -> int:
    return urlsplit(url).port


def free_ports(count: int) -> list[int]:
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def accepts(host: str, port: int, family: int = socket.AF_INET) -> bool:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((host, port))
    except OSError:
        return False
    return True


def eventually(condition, grace: float = GRACE) -> bool:
    """Poll a condition for a short grace period."""
    deadline = time.monotonic() + grace
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.2)
    return True


def refused(port: int) -> bool:
    return eventually(lambda: not accepts("127.0.0.1", port))


def fetch(url: str, headers=(), timeout: float = 60) -> SimpleNamespace:
    """GET a URL with a non-browser client, sending headers exactly as given (repeats allowed)."""
    parts = urlsplit(url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        connection.putrequest("GET", target)
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        return SimpleNamespace(status=response.status, headers=response.headers,
                               body=response.read())
    finally:
        connection.close()


def fetch_json(url: str, headers=()) -> tuple[SimpleNamespace, dict | None]:
    response = fetch(url, headers)
    try:
        return response, json.loads(response.body)
    except ValueError:
        return response, None


def padding(length: int) -> str:
    return (string.ascii_letters * (length // len(string.ascii_letters) + 1))[:length]


def descendants() -> set[int]:
    """Return the live (non-zombie) descendant processes of this test process."""
    listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid=,stat="], stdout=subprocess.PIPE,
                               text=True)
    output, _ = listing.communicate()
    children = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] != str(listing.pid) and not fields[2].startswith("Z"):
            children.setdefault(int(fields[1]), []).append(int(fields[0]))
    found, pending = set(), [os.getpid()]
    while pending:
        for child in children.get(pending.pop(), ()):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def processes_mentioning(text: str) -> list[str]:
    """Return live processes whose command line contains text, orphans included."""
    listing = subprocess.run(["ps", "-A", "-ww", "-o", "stat=,command="], capture_output=True,
                             text=True).stdout
    return [line for line in listing.splitlines()
            if text in line and not line.lstrip().startswith("Z")]


def unactivated_environment() -> dict:
    """Drop conda activation so the script must find the stack from its interpreter alone."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CONDA_PREFIX", "CONDA_DEFAULT_ENV", "CONDA_SHLVL",
                                          "CONDA_PROMPT_MODIFIER"))}
    environment["PATH"] = os.pathsep.join(["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    return environment


def without_pythonpath() -> dict:
    return {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}


def run_cli(*arguments, script: Path = SCRIPT, cwd=None, environment=None,
            timeout: float = CLI_TIMEOUT) -> subprocess.CompletedProcess:
    """Run the CLI like subprocess.run, but stop it with SIGTERM so it can clean up on timeout."""
    process = subprocess.Popen([sys.executable, str(script), *arguments], cwd=cwd,
                               env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=GRACE)
        except subprocess.TimeoutExpired:
            process.kill()
        raise AssertionError(f"{list(arguments)} did not finish, or a child kept its output open")
    return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)


def run_python(code: str, *arguments: str, cwd, environment=None,
               timeout: float = CLI_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code, *arguments], cwd=cwd,
                          env=environment if environment is not None else without_pythonpath(),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=timeout)


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def git_status() -> str | None:
    """Return `git status --porcelain`, or None outside a git checkout."""
    try:
        return subprocess.run(["git", "-C", str(REPO), "status", "--porcelain"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def environment_files() -> dict[str, tuple[int, int] | None]:
    """Map each path under sys.prefix to (size, mtime) for files or None for directories."""
    found = {}
    for root, directories, files in os.walk(sys.prefix):
        # Python's own bytecode caches are not runtime files of the stack.
        directories[:] = [name for name in directories if name != "__pycache__"]
        for name in directories:
            found[os.path.relpath(os.path.join(root, name), sys.prefix)] = None
        for name in files:
            path = os.path.join(root, name)
            try:
                stat = os.lstat(path)
            except OSError:
                continue
            found[os.path.relpath(path, sys.prefix)] = (stat.st_size, stat.st_mtime_ns)
    return found


def changed_paths(before: dict, after: dict) -> list[str]:
    return sorted(path for path in before.keys() | after.keys()
                  if before.get(path, "missing") != after.get(path, "missing"))


def copy_checkout(destination: Path) -> Path:
    """Copy the directories the stack runs from into a directory without .git."""
    for name in ("scripts", "transport", "fixtures"):
        shutil.copytree(REPO / name, destination / name,
                        ignore=shutil.ignore_patterns("__pycache__"))
    return destination


def tree_listing(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*")
            if "__pycache__" not in path.relative_to(root).parts}


def is_under(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def browser_events(path: Path) -> list:
    """Parse browser.log strictly as UTF-8 JSON Lines."""
    return [json.loads(line) for line in path.read_bytes().decode("utf-8").splitlines()
            if line.strip()]


def concurrent_tokens(app_url: str, name: str, count: int = 8) -> SimpleNamespace:
    """Issue one configuration's tokens from many threads at once, then verify them crosswise."""
    barrier = threading.Barrier(count)

    def issue(index: int) -> SimpleNamespace:
        barrier.wait(timeout=60)
        return fetch(f"{app_url}/api/token/issue?alg={name}&delivery=body&probe=first-{index}")

    with ThreadPoolExecutor(count) as pool:
        issued = list(pool.map(issue, range(count)))
    tokens = [json.loads(response.body).get("token") if response.status == 200 else None
              for response in issued]

    def verify(index: int) -> SimpleNamespace:
        barrier.wait(timeout=60)
        token = tokens[(index + 1) % count] or "missing"
        return fetch(f"{app_url}/api/token/verify?probe=first-{index}",
                     [("Authorization", f"Bearer {token}")])

    with ThreadPoolExecutor(count) as pool:
        verified = list(pool.map(verify, range(count)))
    return SimpleNamespace(issue_statuses=[response.status for response in issued], tokens=tokens,
                           verify_statuses=[response.status for response in verified],
                           verify_bodies=[json.loads(response.body) for response in verified])


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
    """Return the body below the first heading starting with title, up to its next sibling."""
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


def contains_number(text: str, number: int) -> bool:
    return re.search(rf"(?<![\d,])(?:{number}|{number:,})(?!,?\d)", text) is not None


def without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def nginx_statements(text: str) -> list[list[str]]:
    """Split an nginx configuration into the words of each directive, without comments."""
    return [statement.split() for statement in re.split(r"[;{}]", without_comments(text))
            if statement.split()]


def normalized_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").replace("\r\n", "\n")
                          .encode("utf-8")).hexdigest()


class TamperingProxy:
    """Forward browser requests to the real proxy and break the token or its cookie on the way."""

    def __init__(self, target_url: str, mode: str, replacement: str | None = None):
        self.target = urlsplit(target_url)
        self.mode = mode
        self.replacement = replacement  # The token that "swapped" mode sends instead.
        tamper = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                tamper.forward(self)

            def log_message(self, *arguments):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.handle_error = lambda request, address: None
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exception):
        self.server.shutdown()
        self.server.server_close()

    def changed(self, name: str, value: str) -> str:
        """Change a verify request's Cookie or Authorization value as the mode says."""
        if self.mode == "application":
            return break_tokens(value)
        if self.mode == "swapped":
            return JWS.sub(lambda match: self.replacement, value)
        # "resized": the same token still verifies, but its header is larger than it implies.
        return f"{value}; pad=1" if name == "cookie" else value.replace(" ", "  ", 1)

    def forward(self, request: BaseHTTPRequestHandler) -> None:
        path = urlsplit(request.path).path
        if self.mode == "dropped" and path == "/api/token/verify":
            # Answer without forwarding, so the request never reaches nginx.
            request.send_response(502)
            request.send_header("Content-Length", "0")
            request.send_header("Connection", "close")
            request.end_headers()
            return
        headers = [(name, value) for name, value in request.headers.items()
                   if name.lower() not in REQUEST_SKIP]
        if self.mode in ("application", "swapped", "resized") and path == "/api/token/verify":
            headers = [(name, self.changed(name.lower(), value)
                        if name.lower() in ("cookie", "authorization") else value)
                       for name, value in headers]
        connection = http.client.HTTPConnection(self.target.hostname, self.target.port,
                                                timeout=60)
        try:
            connection.putrequest("GET", request.path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", self.target.netloc)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            status, body = response.status, response.read()
            response_headers = [(name, value) for name, value in response.getheaders()
                                if name.lower() not in RESPONSE_SKIP]
        finally:
            connection.close()
        if self.mode == "browser" and path == "/api/token/issue":
            # Chromium refuses a cookie whose Domain does not match 127.0.0.1.
            response_headers = [(name, f"{value}; Domain=example.com"
                                 if name.lower() == "set-cookie" else value)
                                for name, value in response_headers]
        elif self.mode == "unmarked" and path == "/api/token/verify":
            response_headers = [(name, value) for name, value in response_headers
                                if name.lower() != "x-transport-proxy"]
        request.send_response(status)
        for name, value in response_headers:
            request.send_header(name, value)
        request.send_header("Content-Length", str(len(body)))
        request.send_header("Connection", "close")
        request.end_headers()
        request.wfile.write(body)


class TokenCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.layers = {layer["role"]: layer for layer in cls.manifest["layers"]}

    def assertNamesLayer(self, text: str, layer: str) -> None:
        lowered = text.lower()
        self.assertTrue(any(word in lowered for word in LAYER_WORDS[layer]),
                        f"evidence does not name the {layer} layer: {text!r}")

    def assertRequestObject(self, request: dict, base: str, path: str, query: dict,
                            keys: tuple) -> None:
        for key in keys:
            self.assertIn(key, request)
        nonce = request["nonce"]
        self.assertIsInstance(nonce, str)
        self.assertIsNotNone(NONCE.fullmatch(nonce), nonce)
        parts = urlsplit(request["url"])
        self.assertEqual(f"{parts.scheme}://{parts.netloc}", base)
        self.assertEqual(parts.path, path)
        self.assertEqual(parse_qs(parts.query, keep_blank_values=True),
                         {**{key: [value] for key, value in query.items()}, "nonce": [nonce]})
        status = request["status"]
        self.assertTrue(status is None or type(status) is int, status)
        if "logs" in keys:
            self.assertLessEqual(set(LOG_FILES), set(request["logs"]))
            for key in LOG_FILES:
                self.assertIsInstance(request["logs"][key], bool)

    def assertEntry(self, entry: dict, algorithm: str, transport: str, proxy_url: str,
                    app_url: str, manifest: dict) -> None:
        """Check one R16 result entry and its R15/R16 rules."""
        for key in ENTRY_KEYS:
            self.assertIn(key, entry)
        self.assertEqual(entry["algorithm"], algorithm)
        self.assertEqual(entry["transport"], transport)
        self.assertIs(type(entry["token_bytes"]), int)
        self.assertEqual(entry["token_bytes"], TOKEN_BYTES[algorithm])
        self.assertEqual(entry["expected"],
                         expected_outcome(manifest, transport, entry["token_bytes"]))
        self.assertIn(entry["outcome"], ("verified", "rejected"))
        if entry["outcome"] == "verified":
            self.assertIsNone(entry["rejected_by"])
        else:
            self.assertIn(entry["rejected_by"], (*LAYERS, None))
        self.assertIsInstance(entry["ok"], bool)
        self.assertTrue(entry["page_status"] is None or type(entry["page_status"]) is int)
        if transport == "cookie":
            self.assertIsInstance(entry["cookie_stored"], bool)
        else:
            self.assertIsNone(entry["cookie_stored"])
        self.assertIsInstance(entry["evidence"], str)
        self.assertTrue(entry["evidence"].strip())
        self.assertLessEqual(len(entry["evidence"]), EVIDENCE_LIMIT)
        delivery = "cookie" if transport == "cookie" else "body"
        self.assertRequestObject(entry["issue"], proxy_url, "/api/token/issue",
                                 {"alg": algorithm, "delivery": delivery},
                                 ("url", "nonce", "status", "logs"))
        self.assertRequestObject(entry["verify"], proxy_url, "/api/token/verify", {},
                                 ("url", "nonce", "status", "body", "logs"))
        self.assertTrue(entry["verify"]["body"] is None or isinstance(entry["verify"]["body"],
                                                                       dict))
        self.assertRequestObject(entry["direct"], app_url, "/api/token/verify", {},
                                 ("url", "nonce", "status", "verified"))
        self.assertIsInstance(entry["direct"]["verified"], bool)
        self.assertEqual(entry["ok"], entry["outcome"] == entry["expected"]
                         and (entry["outcome"] == "verified" or entry["rejected_by"] is not None)
                         and entry["direct"]["verified"] is True)

    def assertResult(self, result: dict, algorithms, proxy_url=None, app_url=None, run_dir=None,
                     manifest=None) -> None:
        """Check the R16 shape of a run_token_check result."""
        manifest = manifest or self.manifest
        json.dumps(result)
        for key in ("ok", "proxy_url", "app_url", "run_dir", "layers", "browser", "algorithms",
                    "logs", "results"):
            self.assertIn(key, result)
        self.assertIsInstance(result["ok"], bool)
        for key, expected in (("proxy_url", proxy_url), ("app_url", app_url)):
            self.assertIsNotNone(URL.fullmatch(result[key]), result[key])
            if expected is not None:
                self.assertEqual(result[key], expected)
        self.assertIsInstance(result["run_dir"], str)
        run_path = Path(result["run_dir"])
        self.assertTrue(run_path.is_absolute())
        if run_dir is not None:
            self.assertEqual(run_path.resolve(), Path(run_dir).resolve())
        self.assertEqual(result["layers"], [{key: layer[key] for key in
                                             ("role", "component", "version")}
                                            for layer in self.manifest["layers"]])
        browser = result["browser"]
        self.assertEqual(browser["version"], self.layers["browser"]["version"])
        self.assertIsInstance(browser["user_agent"], str)
        self.assertTrue(browser["user_agent"])
        self.assertEqual(list(result["algorithms"]), list(algorithms))
        for key, name in LOG_FILES.items():
            with self.subTest(log=key):
                self.assertIsInstance(result["logs"][key], str)
                self.assertTrue(Path(result["logs"][key]).is_absolute())
                self.assertEqual(Path(result["logs"][key]).resolve(),
                                 (run_path / "logs" / name).resolve())
        entries = result["results"]
        self.assertEqual([(entry["algorithm"], entry["transport"]) for entry in entries],
                         [(name, transport) for name in algorithms for transport in TRANSPORTS])
        for entry in entries:
            with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"]):
                self.assertEntry(entry, entry["algorithm"], entry["transport"],
                                 result["proxy_url"], result["app_url"], manifest)
        nonces = [entry[step]["nonce"] for entry in entries for step in ("issue", "verify",
                                                                          "direct")]
        self.assertEqual(len(nonces), len(set(nonces)), "a nonce was reused")
        self.assertEqual(result["ok"], all(entry["ok"] for entry in entries)
                         and browser["version"] == self.layers["browser"]["version"])


class ApplicationTests(unittest.TestCase):
    """Call scripts.transport_app.application in process with plain WSGI environs (R4-R9)."""

    tokens: dict[str, str] = {}

    @classmethod
    def issued(cls, name: str) -> str:
        """Return a token the in-process application issued in a JSON body."""
        if name not in cls.tokens:
            response = call(f"/api/token/issue?alg={name}&delivery=body")
            if response.status != 200:
                raise AssertionError(f"issuing {name} returned {response.status}: "
                                     f"{response.body!r}")
            cls.tokens[name] = json.loads(response.body)["token"]
        return cls.tokens[name]

    def assertJson(self, response: SimpleNamespace) -> dict:
        content_type = dict(zip(response.names, (value for _, value in response.headers)))
        self.assertTrue(content_type.get("content-type", "").startswith("application/json"),
                        response.headers)
        if "content-length" in content_type:
            self.assertEqual(int(content_type["content-length"]), len(response.body))
        return json.loads(response.body)

    def sizes(self, headers=()) -> dict:
        """Return the R7 sizes for headers, from the echo of the same headers."""
        response = call("/api/echo", headers)
        self.assertEqual(response.status, 200)
        return received_sizes(json.loads(response.body)["headers"])

    def assertFailure(self, response: SimpleNamespace, status: int, source, headers) -> dict:
        self.assertEqual(response.status, status, response.body)
        body = self.assertJson(response)
        self.assertEqual(set(body), FAILED_KEYS)
        self.assertEqual(body["layer"], "application")
        self.assertIs(body["verified"], False)
        self.assertEqual(body["source"], source)
        self.assertIsInstance(body["error"], str)
        self.assertTrue(body["error"].strip())
        self.assertIs(body["experiment_key"], True)
        self.assertEqual(body["received"], self.sizes(headers))
        return body

    def invalid_tokens(self) -> dict[str, str]:
        es256, rs256 = self.issued("ES256"), self.issued("RS256")
        header, payload, signature = es256.split(".")
        rs_signature = rs256.split(".")[2]
        cases = {
            "changed payload": f"{header}.{json_segment({**CLAIMS, 'role': 'admin'})}.{signature}",
            "changed signature": tampered(es256),
            "signature of another configuration": f"{header}.{payload}.{rs_signature}",
            "alg none": f"{json_segment({'alg': 'none', 'typ': 'JWT'})}.{payload}.",
            "alg none with a signature": f"{json_segment({'alg': 'none'})}.{payload}.{signature}",
            "HS256": hs256_token(CLAIMS),
            "HS256 header": f"{json_segment({'alg': 'HS256', 'typ': 'JWT'})}.{payload}.{signature}",
            "alg outside ADAPTERS": f"{json_segment({'alg': 'RS512'})}.{payload}.{signature}",
            "unknown ML-DSA set": f"{json_segment({'alg': 'ML-DSA-65'})}.{payload}.{signature}",
            "lowercase alg": f"{json_segment({'alg': 'es256'})}.{payload}.{signature}",
            "no alg": f"{json_segment({'typ': 'JWT'})}.{payload}.{signature}",
            "alg list": f"{json_segment({'alg': ['ES256']})}.{payload}.{signature}",
            "alg number": f"{json_segment({'alg': 256})}.{payload}.{signature}",
            "header not JSON": f"{b64url(b'not json')}.{payload}.{signature}",
            "header JSON array": f"{json_segment(['ES256'])}.{payload}.{signature}",
            "header not UTF-8": f"{b64url(bytes([0xff, 0xfe]))}.{payload}.{signature}",
            "header not base64url": f"!!!.{payload}.{signature}",
            "signature not base64url": f"{header}.{payload}.***",
            "payload not JSON": f"{header}.{b64url(b'not json')}.{signature}",
            "one segment": "abc",
            "two segments": f"{header}.{payload}",
            "four segments": f"{es256}.{signature}",
            "empty segments": "..",
            "expired exp under the test's own key":
                own_key_token("ES256", {**CLAIMS, "exp": int(time.time()) - 3600}),
            "garbage": "not-a-token",
            "long garbage": "A" * 20000,
        }
        for name in NAMES:
            cases[f"{name} signed with the test's own key"] = own_key_token(name, CLAIMS)
        return cases

    def test_issue_cookie_delivery(self):
        for name in NAMES:
            for target in (f"/api/token/issue?alg={name}",
                           f"/api/token/issue?alg={name}&delivery=cookie"):
                with self.subTest(target=target):
                    response = call(target)
                    self.assertEqual(response.status, 200, response.body)
                    self.assertEqual(sorted(response.names),
                                     ["content-length", "content-type", "set-cookie"])
                    values = values_of(response, "set-cookie")
                    self.assertEqual(len(values), 1)
                    match = SET_COOKIE.fullmatch(values[0])
                    self.assertIsNotNone(match, values[0])
                    token = match["token"]
                    body = self.assertJson(response)
                    self.assertEqual(body, {"layer": "application", "algorithm": name,
                                            "delivery": "cookie", "cookie_name": "jwt",
                                            "token_bytes": len(token),
                                            "set_cookie_bytes": len(values[0]),
                                            "experiment_key": True})
                    self.assertEqual(len(token), TOKEN_BYTES[name])
                    self.assertEqual(len(values[0]),
                                     len("jwt=") + TOKEN_BYTES[name] + len(COOKIE_ATTRIBUTES))
                    text = response.body.decode("utf-8")
                    self.assertNotIn(token, text)
                    self.assertNotIn(token.split(".")[2], text)
                    self.assertEqual(jose_header(token)["alg"], name)
                    self.assertEqual(jose_claims(token), CLAIMS)

    def test_issued_cookie_verifies(self):
        for name in NAMES:
            with self.subTest(algorithm=name):
                values = values_of(call(f"/api/token/issue?alg={name}"), "set-cookie")
                self.assertEqual(len(values), 1)
                token = SET_COOKIE.fullmatch(values[0])["token"]
                response = call("/api/token/verify", [("Cookie", f"jwt={token}")])
                self.assertEqual(response.status, 200, response.body)
                body = self.assertJson(response)
                self.assertIs(body["verified"], True)
                self.assertEqual(body["source"], "cookie")
                self.assertEqual(body["claims"], CLAIMS)

    def test_issue_body_delivery(self):
        for name in NAMES:
            with self.subTest(algorithm=name):
                response = call(f"/api/token/issue?alg={name}&delivery=body")
                self.assertEqual(response.status, 200, response.body)
                self.assertNotIn("set-cookie", response.names)
                body = self.assertJson(response)
                token = body.get("token")
                self.assertIsInstance(token, str)
                self.assertIsNotNone(JWS.fullmatch(token), token)
                self.assertEqual(body, {"layer": "application", "algorithm": name,
                                        "delivery": "body", "token": token,
                                        "token_bytes": len(token), "experiment_key": True})
                self.assertEqual(len(token), TOKEN_BYTES[name])
                self.assertEqual(jose_header(token)["alg"], name)
                self.assertEqual(jose_claims(token), CLAIMS)

    def test_issue_ignores_other_query_parameters(self):
        nonce = secrets.token_hex(16)
        for target, delivery in ((f"/api/token/issue?nonce={nonce}&alg=ES256&delivery=body&x=1",
                                  "body"),
                                 (f"/api/token/issue?alg=ES256&nonce={nonce}", "cookie")):
            with self.subTest(target=target):
                response = call(target)
                self.assertEqual(response.status, 200, response.body)
                body = self.assertJson(response)
                self.assertEqual(body["algorithm"], "ES256")
                self.assertEqual(body["delivery"], delivery)
                self.assertEqual(body["token_bytes"], TOKEN_BYTES["ES256"])

    def test_issue_errors(self):
        targets = ["/api/token/issue", "/api/token/issue?delivery=body",
                   "/api/token/issue?nonce=0123abcd", "/api/token/issue?alg=",
                   "/api/token/issue?alg=HS256", "/api/token/issue?alg=none",
                   "/api/token/issue?alg=rs256", "/api/token/issue?alg=ML-DSA-65",
                   "/api/token/issue?alg=RS256%20", "/api/token/issue?alg=%FF",
                   "/api/token/issue?alg=HS256&delivery=body",
                   "/api/token/issue?alg=ES256&delivery=header",
                   "/api/token/issue?alg=ES256&delivery=bearer",
                   "/api/token/issue?alg=ES256&delivery=cookies"]
        for target in targets:
            with self.subTest(target=target):
                response = call(target)
                self.assertEqual(response.status, 400, response.body)
                self.assertNotIn("set-cookie", response.names)
                body = self.assertJson(response)
                self.assertEqual(set(body), {"layer", "error", "algorithms", "experiment_key"})
                self.assertEqual(body["layer"], "application")
                self.assertIsInstance(body["error"], str)
                self.assertTrue(body["error"].strip())
                self.assertEqual(body["algorithms"], NAMES)
                self.assertIs(body["experiment_key"], True)

    def test_verify_every_configuration_from_cookie_and_bearer(self):
        for name in NAMES:
            token = self.issued(name)
            for source, headers in (("cookie", [("Cookie", f"jwt={token}")]),
                                    ("bearer", [("Authorization", f"Bearer {token}")])):
                with self.subTest(algorithm=name, source=source):
                    response = call(f"/api/token/verify?nonce={secrets.token_hex(16)}", headers)
                    self.assertEqual(response.status, 200, response.body)
                    self.assertNotIn("set-cookie", response.names)
                    body = self.assertJson(response)
                    self.assertEqual(set(body), VERIFIED_KEYS)
                    self.assertEqual(body["layer"], "application")
                    self.assertIs(body["verified"], True)
                    self.assertEqual(body["algorithm"], name)
                    self.assertEqual(body["source"], source)
                    self.assertEqual(body["token_bytes"], len(token))
                    self.assertEqual(body["claims"], CLAIMS)
                    self.assertIs(body["experiment_key"], True)
                    self.assertEqual(body["received"], self.sizes(headers))

    def test_verify_finds_jwt_cookie_among_others(self):
        token = self.issued("EdDSA")
        for cookie in (f"a=1; jwt={token}; b=2", f"session=abc;jwt={token}",
                       f"  jwt={token}  ;  z=9",
                       f"xjwt=bad; jwt_old=bad; JWT=bad; jwt2=bad; jwt={token}",
                       f"other=a=b; jwt={token}", f"jwt={token}; empty=; flag"):
            with self.subTest(cookie=cookie[:40]):
                response = call("/api/token/verify", [("Cookie", cookie)])
                self.assertEqual(response.status, 200, response.body)
                body = self.assertJson(response)
                self.assertEqual(body["source"], "cookie")
                self.assertEqual(body["algorithm"], "EdDSA")

    def test_verify_bearer_scheme_is_case_insensitive(self):
        token = self.issued("ML-DSA-44")
        for value in (f"Bearer {token}", f"bearer {token}", f"BEARER {token}",
                      f"BeArEr {token}", f"Bearer   {token}"):
            with self.subTest(value=value[:12]):
                response = call("/api/token/verify", [("Authorization", value)])
                self.assertEqual(response.status, 200, response.body)
                body = self.assertJson(response)
                self.assertEqual(body["source"], "bearer")
                self.assertEqual(body["algorithm"], "ML-DSA-44")

    def test_verify_ignores_other_authorization_schemes(self):
        token = self.issued("ES256")
        for value in ("Basic dXNlcjpwYXNz", f"Token {token}", f"JWT {token}",
                      f"Bearerx {token}", f"Digest {token}"):
            with self.subTest(value=value[:12]):
                alone = [("Authorization", value)]
                self.assertFailure(call("/api/token/verify", alone), 401, None, alone)
                with_cookie = [("Authorization", value), ("Cookie", f"jwt={token}")]
                response = call("/api/token/verify", with_cookie)
                self.assertEqual(response.status, 200, response.body)
                self.assertEqual(self.assertJson(response)["source"], "cookie")

    def test_verify_bearer_without_jwt_cookie_ignores_other_cookies(self):
        token = self.issued("RS256")
        headers = [("Cookie", "session=abc; theme=dark"), ("Authorization", f"Bearer {token}")]
        response = call("/api/token/verify", headers)
        self.assertEqual(response.status, 200, response.body)
        self.assertEqual(self.assertJson(response)["source"], "bearer")

    def test_more_than_one_token_is_400(self):
        token, other = self.issued("ES256"), self.issued("EdDSA")
        cases = [[("Cookie", f"jwt={token}"), ("Authorization", f"Bearer {token}")],
                 [("Cookie", f"jwt={token}"), ("Authorization", f"bearer {other}")],
                 [("Cookie", f"jwt={token}; jwt={token}")],
                 [("Cookie", f"jwt={token}; a=1; jwt=garbage")],
                 [("Cookie", f"jwt=garbage; jwt={other}"), ("Authorization", "Basic dXNlcjpwYXNz")]]
        for headers in cases:
            with self.subTest(headers=[name for name, _ in headers]):
                self.assertFailure(call("/api/token/verify", headers), 400, None, headers)

    def test_no_token_is_401(self):
        cases = [[], [("Cookie", "a=1; b=2")], [("Cookie", "xjwt=1; JWT=2")],
                 [("Cookie", "jwtx=1; xjwt=2; jwt2=3")], [("Authorization", "Basic dXNlcjpwYXNz")]]
        for headers in cases:
            with self.subTest(headers=headers):
                self.assertFailure(call("/api/token/verify", headers), 401, None, headers)

    def test_invalid_tokens_are_401(self):
        for label, token in self.invalid_tokens().items():
            for source, headers in (("cookie", [("Cookie", f"jwt={token}")]),
                                    ("bearer", [("Authorization", f"Bearer {token}")])):
                with self.subTest(case=label, source=source):
                    self.assertFailure(call("/api/token/verify", headers), 401, source, headers)

    def test_malformed_input_never_500(self):
        cases = [[("Cookie", value)] for value in
                 ("jwt", "jwt=", "=", "=jwt", ";;;", "jwt==", "jwt=\x00", "jwt=\xff\xfe", "\x00",
                  "jwt=a b c", "jwt=...", "jwt=a.b.c; jwt", "jwt=" + "\xff" * 10)]
        cases += [[("Authorization", value)] for value in
                  ("", "Bearer", "Bearer ", "Bearer \xff\xfe", "\x00", "Bearer a.b.c", "Bearer .",
                   "Bearer " + "%" * 5000, "Bearer a.b.c d.e.f")]
        cases += [[("Cookie", ""), ("Authorization", "")]]
        for headers in cases:
            with self.subTest(headers=repr(headers)[:60]):
                response = call("/api/token/verify", headers)
                self.assertIn(response.status, (400, 401), response.body)
                body = self.assertJson(response)
                self.assertEqual(set(body), FAILED_KEYS)
                self.assertEqual(body["layer"], "application")
                self.assertIs(body["verified"], False)
                self.assertIs(body["experiment_key"], True)
                # Whether an empty header counts as 0 bytes or none is left open.
                if all(value for _, value in headers):
                    self.assertEqual(body["received"], self.sizes(headers))

    def test_received_sizes_match_the_echo(self):
        token = self.issued("ES256")
        cases = [[], [("Cookie", f"a=1; jwt={token}; b=2"), ("X-Transport-Probe", "caf\u00e9")],
                 [("Authorization", f"Bearer {token}"), ("User-Agent", "probe agent/1.0")],
                 [("Cookie", f"jwt={token}"), ("Authorization", f"Bearer {token}")],
                 [("Authorization", "Basic dXNlcjpwYXNz")],
                 [("X-Transport-Repeat", "one"), ("X-Transport-Repeat", "two")],
                 [("Content-Type", "text/plain"), ("Content-Length", "0")]]
        for headers in cases:
            with self.subTest(headers=[name for name, _ in headers]):
                received = self.assertJson(call("/api/token/verify", headers))["received"]
                self.assertEqual(set(received), set(SIZE_FIELDS))
                self.assertEqual(received, self.sizes(headers))

    def test_received_sizes_by_hand(self):
        # Testing defaults add host: 127.0.0.1 (4 + 9 + 4 bytes); "café" is 4 latin-1 bytes.
        cases = [([("X-Transport-Probe", "caf\u00e9"), ("Cookie", "jwt=abc")],
                  {"headers": 3, "header_bytes": 17 + 25 + 17, "cookie_bytes": 7,
                   "authorization_bytes": None}),
                 ([("Authorization", "Bearer x")],
                  {"headers": 2, "header_bytes": 17 + 25, "cookie_bytes": None,
                   "authorization_bytes": 8})]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                response = call("/api/token/verify", headers)
                self.assertEqual(response.status, 401)
                self.assertEqual(self.assertJson(response)["received"], expected)

    def test_one_log_line_per_request(self):
        token = self.issued("ES256")
        cases = [("/", []), ("/api/echo?x=1", [("X-Transport-Probe", "p")]),
                 ("/api/does-not-exist", []), ("/api/echo/extra", []),
                 ("/api/token/issue?alg=ES256&delivery=body", []),
                 ("/api/token/issue?alg=ES256", [("Cookie", "a=1")]), ("/api/token/issue", []),
                 ("/api/token/verify", []), ("/api/token/verify", [("Cookie", f"jwt={token}")]),
                 ("/api/token/verify?nonce=1", [("Authorization", f"Bearer {token}")]),
                 ("/api/token/verify", [("Authorization", f"Bearer {tampered(token)}")])]
        for target, headers in cases:
            with self.subTest(target=target, headers=[name for name, _ in headers]):
                sizes = self.sizes(headers)
                with self.assertLogs("transport_app", logging.INFO) as captured:
                    response = call(target, headers)
                records = [record for record in captured.records
                           if record.name == "transport_app" and record.levelno == logging.INFO]
                self.assertEqual(len(records), 1, captured.output)
                message = records[0].getMessage()
                match = LOG_LINE.fullmatch(message)
                self.assertIsNotNone(match, message)
                self.assertEqual(match["remote"], "127.0.0.1")
                self.assertEqual(match["method"], "GET")
                self.assertEqual(match["target"], target)
                self.assertEqual(match["protocol"], "HTTP/1.1")
                self.assertEqual(int(match["status"]), response.status)
                fields = log_fields(match["fields"])
                keys = [key for key, _ in fields]
                self.assertEqual(keys[:4], SIZE_FIELDS)
                self.assertEqual(dict(fields[:4]),
                                 {key: logged(sizes[key]) for key in SIZE_FIELDS})
                path = target.partition("?")[0]
                values = dict(fields)
                if path in ("/api/token/issue", "/api/token/verify"):
                    self.assertEqual([key for key in keys[4:] if key in ("alg", "token_bytes")],
                                     ["alg", "token_bytes"])
                if path == "/api/token/verify":
                    self.assertIn("verified", keys[4:])
                    self.assertEqual(values["verified"],
                                     "true" if response.status == 200 else "false")

    def test_log_fields_for_token_requests(self):
        token = self.issued("ES256")
        size = TOKEN_BYTES["ES256"]
        cases = [
            ("/api/token/issue?alg=ES256&delivery=body", [],
             {"alg": "ES256", "token_bytes": str(size)}),
            ("/api/token/issue?alg=ES256", [], {"alg": "ES256", "token_bytes": str(size)}),
            ("/api/token/issue", [], {"alg": "-", "token_bytes": "-"}),
            ("/api/token/verify", [("Cookie", f"jwt={token}")],
             {"alg": "ES256", "token_bytes": str(size), "verified": "true",
              "cookie_bytes": str(4 + size), "authorization_bytes": "-"}),
            ("/api/token/verify", [("Authorization", f"Bearer {token}")],
             {"alg": "ES256", "token_bytes": str(size), "verified": "true", "cookie_bytes": "-",
              "authorization_bytes": str(7 + size)}),
            ("/api/token/verify", [], {"alg": "-", "token_bytes": "-", "verified": "false",
                                       "cookie_bytes": "-", "authorization_bytes": "-"}),
            ("/api/token/verify", [("Cookie", f"jwt={tampered(token)}")], {"verified": "false"}),
        ]
        for target, headers, expected in cases:
            with self.subTest(target=target, headers=[name for name, _ in headers]):
                with self.assertLogs("transport_app", logging.INFO) as captured:
                    call(target, headers)
                match = LOG_LINE.fullmatch(captured.records[-1].getMessage())
                self.assertIsNotNone(match, captured.output)
                values = dict(log_fields(match["fields"]))
                self.assertEqual({key: values.get(key) for key in expected}, expected)

    def test_log_never_contains_header_values_or_tokens(self):
        token = self.issued("ES256")
        probe, agent = secrets.token_hex(16), f"probe-agent-{secrets.token_hex(8)}"
        cases = [("/api/token/issue?alg=ES256", [("X-Transport-Probe", probe),
                                                 ("User-Agent", agent)]),
                 ("/api/token/issue?alg=ES256&delivery=body", [("X-Transport-Probe", probe)]),
                 ("/api/token/verify", [("Cookie", f"jwt={token}; other={probe}"),
                                        ("User-Agent", agent)]),
                 ("/api/token/verify", [("Authorization", f"Bearer {token}"),
                                        ("X-Transport-Probe", probe)]),
                 ("/api/echo", [("Authorization", f"Bearer {token}"),
                                ("Cookie", f"jwt={token}")])]
        for target, headers in cases:
            with self.subTest(target=target):
                with self.assertLogs("transport_app", logging.INFO) as captured:
                    response = call(target, headers)
                secrets_sent = [probe, agent, token, token.split(".")[2]]
                for value in values_of(response, "set-cookie"):
                    issued = SET_COOKIE.fullmatch(value)["token"]
                    secrets_sent += [issued, issued.split(".")[2]]
                if response.names and "token" in response.body.decode("utf-8"):
                    body = json.loads(response.body)
                    if isinstance(body.get("token"), str):
                        secrets_sent += [body["token"], body["token"].split(".")[2]]
                message = "\n".join(captured.output)
                for secret in secrets_sent:
                    self.assertNotIn(secret, message)

    def test_s2_01_endpoints_unchanged(self):
        page = call("/")
        self.assertEqual(page.status, 200)
        content_type = values_of(page, "content-type")
        self.assertTrue(content_type and content_type[0].lower().startswith("text/html"))
        echo = call("/api/echo?alpha=1", [("X-Transport-Probe", "probe")])
        self.assertEqual(echo.status, 200)
        body = self.assertJson(echo)
        self.assertEqual(set(body), {"layer", "method", "path", "query", "headers"})
        self.assertEqual(body["layer"], "application")
        self.assertEqual(body["path"], "/api/echo")
        self.assertEqual(body["query"], {"alpha": "1"})
        self.assertEqual(body["headers"]["x-transport-probe"], "probe")
        for path in ("/api/does-not-exist", "/api/echo/extra", "/api/token",
                     "/api/token/issue/extra", "/api/token/verify/extra", "/api/tokens"):
            with self.subTest(path=path):
                response = call(path)
                self.assertEqual(response.status, 404)
                self.assertEqual(self.assertJson(response)["layer"], "application")

    def test_one_key_pair_per_configuration(self):
        # RS256 and Ed25519 signatures are deterministic, so one key gives identical tokens.
        for name in ("RS256", "EdDSA"):
            with self.subTest(algorithm=name):
                first = json.loads(call(f"/api/token/issue?alg={name}&delivery=body").body)
                second = json.loads(call(f"/api/token/issue?alg={name}&delivery=body").body)
                cookie = values_of(call(f"/api/token/issue?alg={name}"), "set-cookie")
                self.assertEqual(first["token"], second["token"])
                self.assertEqual(SET_COOKIE.fullmatch(cookie[0])["token"], first["token"])
        for name in NAMES:
            with self.subTest(algorithm=name):
                later = json.loads(call(f"/api/token/issue?alg={name}&delivery=body").body)
                for token in (self.issued(name), later["token"]):
                    response = call("/api/token/verify", [("Authorization", f"Bearer {token}")])
                    self.assertEqual(response.status, 200, response.body)

    def test_concurrent_requests_in_process(self):
        def issue_and_verify(name: str) -> tuple[int, int]:
            issue = call(f"/api/token/issue?alg={name}&delivery=body")
            token = json.loads(issue.body).get("token", "missing")
            verify = call("/api/token/verify", [("Cookie", f"jwt={token}")])
            return issue.status, verify.status

        with ThreadPoolExecutor(12) as pool:
            statuses = list(pool.map(issue_and_verify, NAMES * 3))
        self.assertEqual(statuses, [(200, 200)] * len(statuses))


class ScriptTests(unittest.TestCase):
    """Import and run the scripts in fresh processes (R9, R10, R3)."""

    def test_import_starts_no_server(self):
        with tempfile.TemporaryDirectory(prefix="import cwd ") as cwd:
            result = run_python(IMPORT_ONLY, str(REPO), cwd=cwd, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "imported")

    def test_token_check_importable_without_import_cycles(self):
        from scripts.transport_stack import run_token_check

        self.assertTrue(callable(run_token_check))
        parameters = list(inspect.signature(run_token_check).parameters.values())
        self.assertEqual([parameter.name for parameter in parameters[:3]],
                         ["stack", "algorithms", "timeout"])
        self.assertIsNone(parameters[1].default)
        self.assertEqual(parameters[2].default, 60.0)
        orders = [[]]
        if (REPO / "scripts" / "transport_tokens.py").exists():
            orders.append(["scripts.transport_tokens"])
        for order in orders:
            with self.subTest(first=order), \
                    tempfile.TemporaryDirectory(prefix="import cwd ") as cwd:
                result = run_python(IMPORT_CHECK, str(REPO), *order, cwd=cwd, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "True")

    def test_concurrent_first_requests_share_one_key_pair(self):
        with tempfile.TemporaryDirectory(prefix="first use ") as cwd:
            result = run_python(FIRST_USE, str(REPO), cwd=cwd, timeout=CLI_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(data["errors"], [])
        self.assertEqual([status for status, _ in data["issued"]], [200] * 8)
        # RS256 signatures are deterministic: one shared key pair gives one token.
        self.assertEqual(len({body["token"] for _, body in data["issued"]}), 1)
        self.assertEqual([status for status, _ in data["verified"]], [200] * 8)
        self.assertTrue(all(body["verified"] is True for _, body in data["verified"]))

    def test_expired_token_under_the_application_key_is_401(self):
        with tempfile.TemporaryDirectory(prefix="expired check ") as cwd:
            result = run_python(EXPIRED_CHECK, str(REPO), json.dumps(CLAIMS), cwd=cwd,
                                timeout=CLI_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout.strip().splitlines()[-1])
        # A valid exp verifies, so the 401s below come from exp, not from the key.
        status, body = data["valid"]
        self.assertEqual(status, 200, body)
        self.assertIs(body["verified"], True)
        for case in ("expired", "exp not a number"):
            with self.subTest(case=case):
                status, body = data[case]
                self.assertEqual(status, 401, body)
                self.assertIs(body["verified"], False)
                self.assertEqual(body["source"], "bearer")
                self.assertIsInstance(body["error"], str)
                self.assertTrue(body["error"].strip())
                self.assertIs(body["experiment_key"], True)

    def test_app_script_runs_from_another_directory(self):
        (port,) = free_ports(1)
        base = f"http://127.0.0.1:{port}"

        def answers() -> bool:
            try:
                return fetch(f"{base}/api/echo", timeout=5).status == 200
            except (OSError, http.client.HTTPException):
                return False

        with tempfile.TemporaryDirectory(prefix="app script cwd ",
                                         ignore_cleanup_errors=True) as cwd:
            log_path = Path(cwd) / "app stderr.log"
            with log_path.open("w", encoding="utf-8") as log:
                process = subprocess.Popen([sys.executable, str(APP_SCRIPT), "--port", str(port)],
                                           cwd=cwd, env=without_pythonpath(),
                                           stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT)
            try:
                self.assertTrue(eventually(lambda: process.poll() is not None or answers(),
                                           grace=120))
                self.assertIsNone(process.poll(), read_text(log_path))
                issue, body = fetch_json(f"{base}/api/token/issue?alg=EdDSA&delivery=body")
                self.assertEqual(issue.status, 200, issue.body)
                token = body["token"]
                verify, verified = fetch_json(f"{base}/api/token/verify",
                                              [("Authorization", f"Bearer {token}")])
                self.assertEqual(verify.status, 200, verify.body)
                self.assertIs(verified["verified"], True)
            finally:
                stop(process)
            self.assertTrue(refused(port))
            log = read_text(log_path)
            self.assertIn("alg=EdDSA", log)
            self.assertIn("verified=true", log)
            self.assertNotIn(token, log)


class LimitsAndPinsTests(unittest.TestCase):
    """Static checks that limits, pins, and loopback binding stay as in S2-01 (R2)."""

    def test_nginx_template_keeps_default_limits(self):
        text = NGINX_TEMPLATE.read_text(encoding="utf-8")
        statements = nginx_statements(text)
        for words in statements:
            name = words[0]
            with self.subTest(directive=name):
                # Size directives end in _size or _buffers (large_client_header_buffers, ...).
                self.assertFalse(name.endswith(("_size", "_buffers")), " ".join(words))
        self.assertIn("timer_resolution 100ms;", text)
        error_logs = [words for words in statements if words[0] == "error_log"]
        self.assertTrue(error_logs)
        for words in error_logs:
            self.assertEqual(words[-1], "info")
        listens = [words for words in statements if words[0] == "listen"]
        self.assertTrue(listens)
        for words in listens:
            self.assertTrue(words[1].startswith("127.0.0.1:"), words)
        formats = [statement for statement in re.split(r"[;{}]", without_comments(text))
                   if statement.split() and statement.split()[0] == "log_format"]
        self.assertEqual(len(formats), 1)
        self.assertTrue("".join(re.findall(r"'([^']*)'", formats[0])).startswith(LOG_FORMAT),
                        formats[0])

    def test_waitress_serve_call_keeps_defaults(self):
        tree = ast.parse(APP_SCRIPT.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "serve"
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == "waitress"]
        self.assertEqual(len(calls), 1)
        (serve,) = calls
        keywords = {keyword.arg: keyword.value for keyword in serve.keywords}
        self.assertNotIn(None, keywords, "waitress.serve(**...) hides its arguments")
        self.assertEqual(keywords.keys() & WAITRESS_SIZE_ARGUMENTS, set())
        self.assertLessEqual(len(serve.args), 1)
        host = keywords.get("host")
        self.assertIsNotNone(host)
        if isinstance(host, ast.Name):
            self.assertEqual(getattr(transport_app, host.id), "127.0.0.1")
        else:
            self.assertIsInstance(host, ast.Constant)
            self.assertEqual(host.value, "127.0.0.1")
        proxy_headers = keywords.get("clear_untrusted_proxy_headers")
        self.assertIsInstance(proxy_headers, ast.Constant)
        self.assertIs(proxy_headers.value, False)
        self.assertEqual(transport_app.HOST, "127.0.0.1")

    def test_pinned_files_unchanged(self):
        for name, pins in PINS.items():
            with self.subTest(file=name):
                lines = [line.strip() for line in
                         (REPO / name).read_text(encoding="utf-8").splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
                self.assertEqual(lines, pins)
        for name, digest in UNCHANGED.items():
            with self.subTest(unchanged=name):
                self.assertEqual(normalized_sha256(REPO / name), digest, f"{name} changed")

    def test_documented_limits_unchanged(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual([layer["role"] for layer in manifest["layers"]], list(DOCUMENTED))
        for layer in manifest["layers"]:
            with self.subTest(role=layer["role"]):
                limits = layer["limits"]
                self.assertEqual((layer["version"], limits["cookie"]["bytes"],
                                  limits["single_header"]["bytes"],
                                  limits["total_headers"]["bytes"]), DOCUMENTED[layer["role"]])

    def test_s2_01_interface_still_available(self):
        self.assertEqual(MANIFEST_PATH.resolve(), MANIFEST.resolve())
        self.assertEqual(load_manifest(), json.loads(MANIFEST.read_text(encoding="utf-8")))
        for function in (start_stack, run_check, installed_versions, http_get):
            self.assertTrue(callable(function))
        self.assertLessEqual({"proxy_url", "app_url", "run_dir"},
                             {field.name for field in dataclasses.fields(Stack)})
        self.assertEqual(transport_stack.HOST, "127.0.0.1")


class DocumentationTests(unittest.TestCase):
    """Check TRANSPORT.md, the application docstring, and PROGRESS.md (R3, R19, R20)."""

    @classmethod
    def setUpClass(cls):
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.progress = PROGRESS.read_text(encoding="utf-8")

    def doc_section(self, title: str) -> str:
        body = section(self.doc, title)
        self.assertIsNotNone(body, f"missing heading: ## {title}")
        return body

    def progress_section(self, task: str) -> str:
        body = section(self.progress, task, level=3)
        self.assertIsNotNone(body, f"missing heading: ### {task}")
        return body

    def test_transport_doc_keeps_required_headings(self):
        found = [name for depth, name, _ in headings(self.doc.splitlines())
                 if depth == 2 and name in HEADINGS]
        self.assertEqual(found, list(HEADINGS))

    def test_transport_doc_describes_token_endpoints_and_keys(self):
        for term in ("/api/token/issue", "/api/token/verify", "delivery", "jwt",
                     "Path=/; HttpOnly; SameSite=Strict", "experiment_key"):
            with self.subTest(term=term):
                self.assertIn(term, self.doc)
        lowered = self.doc.lower()
        for term in ("ephemeral", "experiment", "production"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_transport_doc_describes_logs(self):
        for term in ("app.log", "browser.log", "header_bytes", "cookie_bytes",
                     "authorization_bytes", "token_bytes", "received_bytes", "proxy-access.log",
                     "proxy-error.log"):
            with self.subTest(term=term):
                self.assertIn(term, self.doc)

    def test_transport_doc_documents_tokens_command(self):
        command = re.compile(r"transport_stack\.py[\"']?\s+tokens\b")
        self.assertRegex("\n".join(code_blocks(self.doc)), command)
        for term in ("--alg", "run_token_check", "rejected_by", "outcome", "expected"):
            with self.subTest(term=term):
                self.assertIn(term, self.doc)
        # An excerpt of real output shows at least one pair's outcome for a named configuration.
        # The output may share a block with the command; the command line itself does not count.
        outputs = ["\n".join(line for line in block.splitlines() if not command.search(line))
                   for block in code_blocks(self.doc)]
        excerpts = [text for text in outputs if any(name in text for name in NAMES)
                    and re.search(r"\b(?:verified|rejected)\b", text)]
        self.assertTrue(excerpts, "no excerpt from a real tokens run")

    def test_transport_doc_explains_slh_dsa_expectation(self):
        for name in SLH_DSA:
            with self.subTest(name=name):
                self.assertIn(name, self.doc)
        for number in (4096, 8192, 10613, 22922):
            with self.subTest(number=number):
                self.assertTrue(contains_number(self.doc, number))
        for term in ("proxy_buffer_size", "WSL2"):
            with self.subTest(term=term):
                self.assertIn(term, self.doc)
        for size in (16, 4):
            with self.subTest(buffer=f"{size} KiB"):
                self.assertRegex(self.doc, rf"(?<![\d.]){size}\s?(?:KiB|KB|K)\b")
        self.assertIn("observ", self.doc.lower())

    def test_transport_doc_updates_sprint_2_support_and_limitations(self):
        support = [line.strip() for line in
                   self.doc_section("Support for Sprint 2 tasks").splitlines() if "S2-02" in line]
        self.assertTrue(support)
        # R19 asks for the bullet to be updated, not for particular words in it.
        digests = {hashlib.sha256(line.encode("utf-8")).hexdigest() for line in support}
        self.assertNotIn(S2_02_BULLET_BEFORE, digests, "the S2-02 bullet was not updated")
        self.assertTrue(any("token" in line.lower() for line in support), support)
        self.assertNotIn("Minimal logs", self.doc_section("Limitations"))

    def test_app_docstring_names_experiment_keys(self):
        lowered = (transport_app.__doc__ or "").lower()
        for term in ("ephemeral", "experiment", "production"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_progress_s2_02(self):
        body = self.progress_section("S2-02")
        lines = body.splitlines()
        for item in S2_02_ITEMS:
            with self.subTest(item=item[:40]):
                self.assertIn(f"- [x] {item}", lines)
        self.assertNotIn("- [ ]", body)
        self.assertEqual([line for line in lines if line.startswith("**Done when:**")],
                         [DONE_WHEN])
        status = [line for line in lines if line.startswith("**Status:**")]
        self.assertEqual(len(status), 1)
        for term in ("tokens", "macOS", "WSL2", "SLH-DSA", "ML-DSA-44"):
            with self.subTest(term=term):
                self.assertIn(term, status[0])
        self.assertIn("direct", status[0].lower())

    def test_progress_other_tasks_unchanged(self):
        # Only checks that later progress cannot invalidate: the other tasks' "Done when" lines
        # are intact and Sprint 1 stays complete. A whole-file hash, S2-01's checkbox count, and
        # "S2-03 to S3-03 have no checked box" were checked here before; each froze PROGRESS.md
        # as of S2-02 and broke, or would break, on legitimate progress updates.
        lines = self.progress.splitlines()
        for line in OTHER_DONE_WHEN:
            with self.subTest(done_when=line[:50]):
                self.assertIn(line, lines)
        for task in ("S1-01", "S1-02", "S1-03", "S1-04", "S1-05", "S1-06"):
            with self.subTest(task=task):
                self.assertNotIn("- [ ]", self.progress_section(task))


class TokenCheckTests(TokenCase):
    """One run_token_check over all six configurations against a running stack (R3-R16)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.git_before = git_status()
        directory = cls.enterClassContext(tempfile.TemporaryDirectory(
            prefix="token check ", ignore_cleanup_errors=True))
        cls.stack = cls.enterClassContext(start_stack(run_dir=Path(directory) / "run dir"))
        cls.log_dir = cls.stack.run_dir / "logs"
        try:
            cls.concurrent, cls.concurrent_error = concurrent_tokens(cls.stack.app_url,
                                                                     "RS256"), None
        except Exception as error:  # Reported by the test that uses it.
            cls.concurrent, cls.concurrent_error = None, error
        cls.nginx_conf = read_text(cls.stack.run_dir / "nginx" / "nginx.conf")
        cls.baseline = descendants()
        try:
            cls.result, cls.check_error = transport_stack.run_token_check(cls.stack), None
        except Exception as error:  # Reported by the tests that use the result.
            cls.result, cls.check_error = None, error
        cls.snapshot = {key: read_text(cls.log_dir / name) for key, name in LOG_FILES.items()}
        try:
            cls.events, cls.events_error = browser_events(cls.log_dir / "browser.log"), None
        except (OSError, UnicodeDecodeError, ValueError) as error:
            cls.events, cls.events_error = None, error

    def require_result(self) -> dict:
        if self.check_error is not None:
            self.fail(f"run_token_check failed: {self.check_error!r}")
        return self.result

    def require_events(self) -> list:
        self.require_result()
        if self.events_error is not None:
            self.fail(f"browser.log is not UTF-8 JSON Lines: {self.events_error!r}")
        return self.events

    def entries(self, outcome: str | None = None) -> list[dict]:
        return [entry for entry in self.require_result()["results"]
                if outcome is None or entry["outcome"] == outcome]

    def pair(self, name: str, transport: str) -> dict:
        return next(entry for entry in self.entries()
                    if (entry["algorithm"], entry["transport"]) == (name, transport))

    def pair_events(self, name: str, transport: str) -> list[dict]:
        return [event for event in self.require_events() if isinstance(event, dict)
                and (event.get("algorithm"), event.get("transport")) == (name, transport)]

    def find(self, events: list[dict], kind: str, nonce: str) -> list[dict]:
        return [event for event in events
                if event.get("event") == kind and nonce in str(event.get("url", ""))]

    def maybe_unsent(self, entry: dict, step: str) -> bool:
        """A cookie pair whose issue failed may skip its verify; nothing else may be skipped."""
        return (step == "verify" and entry["transport"] == "cookie"
                and entry["outcome"] == "rejected" and entry["verify"]["status"] is None)

    def app_lines(self) -> dict[str | None, list[SimpleNamespace]]:
        found = {}
        for request in app_requests(self.snapshot["app"]):
            found.setdefault(nonce_of(request), []).append(request)
        return found

    def test_result_shape_and_order(self):
        result = self.require_result()
        self.assertResult(result, NAMES, self.stack.proxy_url, self.stack.app_url,
                          self.stack.run_dir)
        self.assertEqual(result["run_dir"], str(self.stack.run_dir))

    def test_unchanged_stack_outcomes(self):
        result = self.require_result()
        verified = {(entry["algorithm"], entry["transport"]) for entry in self.entries("verified")}
        self.assertEqual(verified, {(name, transport) for name in NAMES if name not in SLH_DSA
                                    for transport in TRANSPORTS})
        for entry in self.entries():
            with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"]):
                self.assertEqual(entry["expected"],
                                 "rejected" if entry["algorithm"] in SLH_DSA else "verified")
                self.assertIs(entry["ok"], True, entry["evidence"])
                self.assertIs(entry["direct"]["verified"], True)
        self.assertIs(result["ok"], True)

    def test_verified_pairs_meet_every_condition(self):
        for entry in self.entries("verified"):
            name, transport, size = entry["algorithm"], entry["transport"], entry["token_bytes"]
            with self.subTest(algorithm=name, transport=transport):
                self.assertEqual(entry["page_status"], 200)
                self.assertEqual(entry["issue"]["status"], 200)
                self.assertIs(entry["cookie_stored"], True if transport == "cookie" else None)
                self.assertEqual(entry["verify"]["status"], 200)
                body = entry["verify"]["body"]
                self.assertEqual(body["layer"], "application")
                self.assertIs(body["verified"], True)
                self.assertEqual(body["algorithm"], name)
                self.assertEqual(body["source"], transport)
                self.assertEqual(body["token_bytes"], size)
                self.assertEqual(body["claims"], CLAIMS)
                self.assertIs(body["experiment_key"], True)
                received = body["received"]
                self.assertEqual(set(received), set(SIZE_FIELDS))
                if transport == "cookie":
                    self.assertEqual((received["cookie_bytes"], received["authorization_bytes"]),
                                     (4 + size, None))
                else:
                    self.assertEqual((received["cookie_bytes"], received["authorization_bytes"]),
                                     (None, 7 + size))
                for step in ("issue", "verify"):
                    for log in ("browser", "proxy_access", "app"):
                        self.assertIs(entry[step]["logs"][log], True, f"{step} not in {log}")

    def test_slh_dsa_pairs_rejected_by_first_failing_layer(self):
        for name in SLH_DSA:
            with self.subTest(algorithm=name, transport="bearer"):
                bearer = self.pair(name, "bearer")
                self.assertEqual((bearer["expected"], bearer["outcome"]), ("rejected", "rejected"))
                self.assertEqual(bearer["rejected_by"], "proxy")
                self.assertIs(bearer["ok"], True)
                self.assertEqual(bearer["issue"]["status"], 200)
                self.assertEqual(bearer["verify"]["status"], 400)
                self.assertIs(bearer["verify"]["logs"]["proxy_access"], True)
                # "client sent too long header line" at info level names the request (R2).
                self.assertIs(bearer["verify"]["logs"]["proxy_error"], True)
                self.assertIs(bearer["verify"]["logs"]["app"], False)
                self.assertNamesLayer(bearer["evidence"], "proxy")
            with self.subTest(algorithm=name, transport="cookie"):
                cookie = self.pair(name, "cookie")
                self.assertEqual((cookie["expected"], cookie["outcome"]), ("rejected", "rejected"))
                self.assertIs(cookie["ok"], True)
                self.assertIs(cookie["cookie_stored"], False)
                self.assertIs(cookie["issue"]["logs"]["proxy_access"], True)
                # The application signed and answered 200 before nginx or Chromium refused it.
                self.assertIs(cookie["issue"]["logs"]["app"], True)
                lines = self.app_lines().get(cookie["issue"]["nonce"], [])
                self.assertEqual([line.status for line in lines], [200])
                # nginx's proxy_buffer_size (one memory page) decides which layer refuses the
                # SLH-DSA-SHA2-128s Set-Cookie; the 128f one is larger than 16 KiB.
                allowed = ("proxy",) if name == "SLH-DSA-SHA2-128f" else ("browser", "proxy")
                self.assertIn(cookie["rejected_by"], allowed)
                if cookie["rejected_by"] == "browser":
                    self.assertEqual(cookie["issue"]["status"], 200)
                    responses = self.find(self.pair_events(name, "cookie"), "response",
                                          cookie["issue"]["nonce"])
                    self.assertTrue(responses)
                    self.assertIn("jwt=", responses[0]["headers"].get("set-cookie", ""))
                else:
                    self.assertEqual(cookie["issue"]["status"], 502)
                    # "upstream sent too big header" names the request.
                    self.assertIs(cookie["issue"]["logs"]["proxy_error"], True)
                for event in self.pair_events(name, "cookie"):
                    if event.get("event") == "cookies":
                        self.assertNotIn("jwt", [item["name"] for item in event["cookies"]])
                self.assertNamesLayer(cookie["evidence"], cookie["rejected_by"])

    def test_every_pair_attempted_and_verified_directly(self):
        for entry in self.entries():
            with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"]):
                self.assertEqual(entry["page_status"], 200)
                self.assertIs(type(entry["issue"]["status"]), int)
                self.assertIs(entry["issue"]["logs"]["browser"], True)
                self.assertIs(entry["issue"]["logs"]["proxy_access"], True)
                # Every Bearer issue succeeds at default limits, so every Bearer verify is sent.
                if entry["transport"] == "bearer" or entry["outcome"] == "verified":
                    self.assertIs(entry["verify"]["logs"]["browser"], True)
                    self.assertIs(type(entry["verify"]["status"]), int)
                self.assertEqual(entry["direct"]["status"], 200)
                self.assertIs(entry["direct"]["verified"], True)

    def test_direct_requests_bypass_browser_and_proxy(self):
        events = self.require_events()
        for entry in self.entries():
            with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"]):
                nonce = entry["direct"]["nonce"]
                self.assertIn(nonce, self.snapshot["app"])
                self.assertEqual(self.find(events, "request", nonce), [])
                self.assertNotIn(nonce, self.snapshot["proxy_access"])

    def test_log_flags_match_log_files(self):
        for entry in self.entries():
            for step in ("issue", "verify"):
                with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"],
                                  step=step):
                    nonce = entry[step]["nonce"]
                    self.assertEqual({key: entry[step]["logs"][key] for key in LOG_FILES},
                                     {key: nonce in text for key, text in self.snapshot.items()})

    def test_direct_issues_reach_only_the_application(self):
        self.require_result()
        proxied = self.snapshot["proxy_access"]
        requests = app_requests(self.snapshot["app"])
        direct_verifies = {entry["direct"]["nonce"] for entry in self.entries()}
        for name in NAMES:
            with self.subTest(algorithm=name):
                direct = [request for request in requests
                          if request.path == "/api/token/issue"
                          and request.query.get("alg") == [name]
                          and request.query.get("delivery") == ["body"]
                          and nonce_of(request) and nonce_of(request) not in proxied]
                self.assertEqual(len(direct), 2)
                self.assertEqual([request.status for request in direct], [200, 200])
        verified_directly = [request for request in requests
                             if request.path == "/api/token/verify"
                             and nonce_of(request) in direct_verifies]
        self.assertEqual(len(verified_directly), len(direct_verifies))
        for nonce in direct_verifies:
            self.assertNotIn(nonce, proxied)

    def test_every_request_has_a_fresh_nonce(self):
        events = self.require_events()
        logged_nonces = [nonce_of(request) for request in app_requests(self.snapshot["app"])
                         if nonce_of(request)]
        self.assertEqual(len(logged_nonces), len(set(logged_nonces)))
        for entry in self.entries():
            for step in ("issue", "verify"):
                with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"],
                                  step=step):
                    sent = len(self.find(events, "request", entry[step]["nonce"]))
                    self.assertIn(sent, (0, 1) if self.maybe_unsent(entry, step) else (1,))

    def test_browser_log_events(self):
        events = self.require_events()
        self.assertTrue(events)
        for event in events:
            with self.subTest(event=str(event)[:80]):
                self.assertIsInstance(event, dict)
                for key in ("event", "algorithm", "transport"):
                    self.assertIn(key, event)
                if event["event"] in ("request", "response", "cookies"):
                    self.assertIn(event["algorithm"], NAMES)
                    self.assertIn(event["transport"], TRANSPORTS)
                if event["event"] in ("request", "response"):
                    self.assertIsInstance(event["url"], str)
                    self.assertIsInstance(event["headers"], dict)
                    for header, value in event["headers"].items():
                        self.assertEqual(header, header.lower())
                        self.assertIsInstance(value, str)
                if event["event"] == "request":
                    self.assertIsInstance(event["method"], str)
                elif event["event"] == "response":
                    self.assertIs(type(event["status"]), int)
                elif event["event"] == "cookies":
                    self.assertIn(event["step"], ("after_issue", "after_verify"))
                    self.assertIsInstance(event["cookies"], list)
                    for item in event["cookies"]:
                        self.assertLessEqual(COOKIE_KEYS, set(item))
        self.assertLessEqual({"request", "response", "cookies"},
                             {event["event"] for event in events})
        proxy = self.result["proxy_url"]
        for entry in self.entries():
            name, transport = entry["algorithm"], entry["transport"]
            with self.subTest(algorithm=name, transport=transport):
                pair = self.pair_events(name, transport)
                pages = [event for event in pair if event["event"] == "request"
                         and urlsplit(event["url"]).path == "/"
                         and event["url"].startswith(f"{proxy}/")]
                self.assertTrue(pages, "no page load request")
                for step in ("issue", "verify"):
                    nonce, status = entry[step]["nonce"], entry[step]["status"]
                    sent = len(self.find(pair, "request", nonce))
                    self.assertIn(sent, (0, 1) if self.maybe_unsent(entry, step) else (1,), step)
                    responses = self.find(pair, "response", nonce)
                    if status is None:
                        self.assertEqual(responses, [], step)
                    else:
                        self.assertEqual(len(responses), 1, step)
                        self.assertEqual(responses[0]["status"], status)
                if transport == "cookie":
                    steps = [event["step"] for event in pair if event["event"] == "cookies"]
                    self.assertIn("after_issue", steps)
                    # A verify that may be skipped (maybe_unsent) may skip the jar read after it.
                    if (self.find(pair, "request", entry["verify"]["nonce"])
                            or not self.maybe_unsent(entry, "verify")):
                        self.assertIn("after_verify", steps)

    def test_browser_log_shows_cookie_jar_and_sent_headers(self):
        for entry in self.entries("verified"):
            name, transport, size = entry["algorithm"], entry["transport"], entry["token_bytes"]
            with self.subTest(algorithm=name, transport=transport):
                pair = self.pair_events(name, transport)
                self.assertEqual(len(self.find(pair, "request", entry["issue"]["nonce"])), 1)
                verify_request = self.find(pair, "request", entry["verify"]["nonce"])[0]
                verify_response = self.find(pair, "response", entry["verify"]["nonce"])[0]
                self.assertIn("x-transport-proxy", verify_response["headers"])
                if transport == "cookie":
                    after_issue = [event for event in pair if event["event"] == "cookies"
                                   and event["step"] == "after_issue"][0]
                    jar = [item for item in after_issue["cookies"] if item["name"] == "jwt"]
                    self.assertEqual(len(jar), 1)
                    cookie = jar[0]
                    self.assertEqual(len(cookie["value"]), size)
                    self.assertEqual((cookie["domain"], cookie["path"], cookie["expires"],
                                      cookie["httpOnly"], cookie["secure"], cookie["sameSite"]),
                                     ("127.0.0.1", "/", -1, True, False, "Strict"))
                    self.assertEqual(verify_request["headers"].get("cookie"),
                                     f"jwt={cookie['value']}")
                    # The jar's cookie came from the application's Set-Cookie response.
                    issue_response = self.find(pair, "response", entry["issue"]["nonce"])[0]
                    self.assertIn(f"jwt={cookie['value']}{COOKIE_ATTRIBUTES}",
                                  issue_response["headers"].get("set-cookie", ""))
                else:
                    authorization = verify_request["headers"].get("authorization", "")
                    self.assertTrue(authorization.startswith("Bearer "), authorization[:20])
                    token = authorization[len("Bearer "):]
                    self.assertEqual(len(token), size)
                    self.assertIsNotNone(JWS.fullmatch(token))

    def test_browser_requests_come_from_the_page_through_the_proxy(self):
        events = self.require_events()
        proxy, agent = self.result["proxy_url"], self.result["browser"]["user_agent"]
        for event in events:
            if event.get("event") == "request":
                self.assertTrue(event["url"].startswith(f"{proxy}/"), event["url"])
        for entry in self.entries():
            for step in ("issue", "verify"):
                with self.subTest(algorithm=entry["algorithm"], transport=entry["transport"],
                                  step=step):
                    found = self.find(events, "request", entry[step]["nonce"])
                    if not found and self.maybe_unsent(entry, step):
                        continue
                    (request,) = found
                    self.assertEqual(request["method"], "GET")
                    # fetch() from the page: same-origin CORS mode, referred by the test page.
                    self.assertEqual(request["headers"].get("sec-fetch-mode"), "cors")
                    self.assertTrue(request["headers"].get("referer", "").startswith(f"{proxy}/"))
                    self.assertEqual(request["headers"].get("user-agent"), agent)

    def test_no_cookie_carries_over_between_pairs(self):
        for entry in self.entries():
            name, transport = entry["algorithm"], entry["transport"]
            with self.subTest(algorithm=name, transport=transport):
                for event in self.pair_events(name, transport):
                    if event["event"] != "request":
                        continue
                    before_issue = (urlsplit(event["url"]).path == "/"
                                    or entry["issue"]["nonce"] in event["url"])
                    if transport == "bearer" or before_issue:
                        self.assertNotIn("jwt=", event["headers"].get("cookie", ""), event["url"])

    def test_app_log_records_check_requests(self):
        requests = app_requests(self.snapshot["app"])
        self.assertTrue(requests)
        for request in requests:
            self.assertEqual([key for key, _ in request.fields[:4]], SIZE_FIELDS, request.line)
        lines = self.app_lines()
        for entry in self.entries():
            name, transport, size = entry["algorithm"], entry["transport"], entry["token_bytes"]
            with self.subTest(algorithm=name, transport=transport):
                issue = lines.get(entry["issue"]["nonce"], [])
                self.assertEqual(len(issue), 1)
                values = dict(issue[0].fields)
                self.assertEqual((values.get("alg"), values.get("token_bytes")), (name, str(size)))
                if entry["outcome"] != "verified":
                    continue
                verify = lines.get(entry["verify"]["nonce"], [])
                self.assertEqual(len(verify), 1)
                values = dict(verify[0].fields)
                received = entry["verify"]["body"]["received"]
                self.assertEqual({key: values.get(key) for key in SIZE_FIELDS},
                                 {key: logged(received[key]) for key in SIZE_FIELDS})
                self.assertEqual((values.get("alg"), values.get("token_bytes"),
                                  values.get("verified")), (name, str(size), "true"))
                expected = ((str(4 + size), "-") if transport == "cookie"
                            else ("-", str(7 + size)))
                self.assertEqual((values["cookie_bytes"], values["authorization_bytes"]),
                                 expected)

    def test_app_log_has_no_tokens_or_header_values(self):
        tokens = set()
        for event in self.require_events():
            if event.get("event") == "cookies":
                tokens |= {item["value"] for item in event["cookies"] if item["name"] == "jwt"}
            elif event.get("event") == "request":
                authorization = event["headers"].get("authorization", "")
                if authorization.lower().startswith("bearer "):
                    tokens.add(authorization[len("bearer "):])
        self.assertTrue(tokens)
        application = self.snapshot["app"]
        for token in tokens:
            self.assertNotIn(token, application)
            self.assertNotIn(token.split(".")[-1], application)
        self.assertNotIn(self.result["browser"]["user_agent"], application)

    def test_browser_closed_after_check(self):
        self.require_result()
        self.assertTrue(eventually(lambda: descendants() <= self.baseline))

    def test_stack_still_serves_after_check(self):
        self.require_result()
        for url in (self.stack.proxy_url, self.stack.app_url):
            with self.subTest(url=url):
                self.assertEqual(fetch(f"{url}/api/echo").status, 200)
        self.assertEqual(read_text(self.stack.run_dir / "nginx" / "nginx.conf"), self.nginx_conf)
        self.assertIs(run_check(self.stack)["ok"], True)

    def test_selected_algorithms_keep_order_and_append_to_browser_log(self):
        first = self.require_result()
        browser_log = self.log_dir / "browser.log"
        before = browser_log.read_bytes()
        baseline = descendants()
        second = transport_stack.run_token_check(self.stack, algorithms=("ML-DSA-44", "ES256"),
                                                 timeout=60.0)
        self.assertResult(second, ["ML-DSA-44", "ES256"], self.stack.proxy_url,
                          self.stack.app_url, self.stack.run_dir)
        self.assertIs(second["ok"], True)
        self.assertEqual([entry["outcome"] for entry in second["results"]], ["verified"] * 4)
        old = {entry[step]["nonce"] for entry in first["results"]
               for step in ("issue", "verify", "direct")}
        new = {entry[step]["nonce"] for entry in second["results"]
               for step in ("issue", "verify", "direct")}
        self.assertEqual(old & new, set())
        after = browser_log.read_bytes()
        self.assertTrue(after.startswith(before), "browser.log was not appended to")
        added = browser_events_from(after[len(before):])
        self.assertTrue(added)
        self.assertLessEqual({event["algorithm"] for event in added}, {"ML-DSA-44", "ES256"})
        self.assertTrue(eventually(lambda: descendants() <= baseline))

    def test_invalid_arguments_raise_value_error_before_a_browser_starts(self):
        browser_log = self.log_dir / "browser.log"
        before = read_text(browser_log)
        baseline = descendants()
        cases = [{"algorithms": []}, {"algorithms": ()}, {"algorithms": ["RS999"]},
                 {"algorithms": ["rs256"]}, {"algorithms": ["none"]}, {"algorithms": ["HS256"]},
                 {"algorithms": ["ES256", "ES256"]},
                 {"algorithms": ["ES256", "ML-DSA-44", "ES256"]}, {"timeout": 0},
                 {"timeout": 0.0}, {"timeout": -1}, {"timeout": -0.5}, {"timeout": math.nan},
                 {"algorithms": ["ES256"], "timeout": 0}]
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                transport_stack.run_token_check(self.stack, **arguments)
        self.assertTrue(eventually(lambda: descendants() <= baseline))
        self.assertEqual(read_text(browser_log), before)

    def test_application_rejection_is_reported(self):
        self.require_result()
        baseline = descendants()
        with TamperingProxy(self.stack.proxy_url, "application") as tamper:
            fake = SimpleNamespace(proxy_url=tamper.url, app_url=self.stack.app_url,
                                   run_dir=self.stack.run_dir)
            result = transport_stack.run_token_check(fake, algorithms=["ES256"], timeout=60.0)
        self.assertResult(result, ["ES256"], tamper.url, self.stack.app_url, self.stack.run_dir)
        self.assertIs(result["ok"], False)
        for entry in result["results"]:
            with self.subTest(transport=entry["transport"]):
                self.assertEqual((entry["expected"], entry["outcome"]), ("verified", "rejected"))
                self.assertEqual(entry["rejected_by"], "application")
                self.assertIs(entry["ok"], False)
                self.assertEqual(entry["verify"]["status"], 401)
                body = entry["verify"]["body"]
                self.assertEqual((body["layer"], body["verified"], body["source"]),
                                 ("application", False, entry["transport"]))
                self.assertIs(entry["verify"]["logs"]["proxy_access"], True)
                self.assertIs(entry["verify"]["logs"]["app"], True)
                self.assertIs(entry["direct"]["verified"], True)
                self.assertNamesLayer(entry["evidence"], "application")
        self.assertTrue(eventually(lambda: descendants() <= baseline))

    def test_browser_rejection_is_reported(self):
        self.require_result()
        baseline = descendants()
        with TamperingProxy(self.stack.proxy_url, "browser") as tamper:
            fake = SimpleNamespace(proxy_url=tamper.url, app_url=self.stack.app_url,
                                   run_dir=self.stack.run_dir)
            result = transport_stack.run_token_check(fake, algorithms=["ES256"], timeout=60.0)
        self.assertResult(result, ["ES256"], tamper.url, self.stack.app_url, self.stack.run_dir)
        self.assertIs(result["ok"], False)
        cookie, bearer = result["results"]
        self.assertEqual((cookie["expected"], cookie["outcome"]), ("verified", "rejected"))
        self.assertEqual(cookie["rejected_by"], "browser")
        self.assertIs(cookie["cookie_stored"], False)
        self.assertEqual(cookie["issue"]["status"], 200)
        self.assertIs(cookie["ok"], False)
        self.assertIs(cookie["direct"]["verified"], True)
        self.assertNamesLayer(cookie["evidence"], "browser")
        self.assertEqual(bearer["outcome"], "verified")
        self.assertIs(bearer["ok"], True)
        self.assertTrue(eventually(lambda: descendants() <= baseline))

    def test_verify_without_proxy_marker_is_not_verified(self):
        self.require_result()
        baseline = descendants()
        with TamperingProxy(self.stack.proxy_url, "unmarked") as tamper:
            fake = SimpleNamespace(proxy_url=tamper.url, app_url=self.stack.app_url,
                                   run_dir=self.stack.run_dir)
            result = transport_stack.run_token_check(fake, algorithms=["EdDSA"], timeout=60.0)
        self.assertResult(result, ["EdDSA"], tamper.url, self.stack.app_url, self.stack.run_dir)
        self.assertIs(result["ok"], False)
        for entry in result["results"]:
            with self.subTest(transport=entry["transport"]):
                self.assertEqual((entry["expected"], entry["outcome"]), ("verified", "rejected"))
                # Every status was 200, so R14 names no layer; "proxy" for the missing marker
                # is also accepted.
                self.assertIn(entry["rejected_by"], (None, "proxy"))
                self.assertIs(entry["ok"], False)
                self.assertEqual(entry["verify"]["status"], 200)
                self.assertIs(entry["verify"]["body"]["verified"], True)
                self.assertIs(entry["direct"]["verified"], True)
        self.assertTrue(eventually(lambda: descendants() <= baseline))

    def tampered_check(self, mode: str, name: str, replacement: str | None = None) -> dict:
        """Run the check for one configuration through a TamperingProxy in front of nginx."""
        baseline = descendants()
        with TamperingProxy(self.stack.proxy_url, mode, replacement) as tamper:
            fake = SimpleNamespace(proxy_url=tamper.url, app_url=self.stack.app_url,
                                   run_dir=self.stack.run_dir)
            result = transport_stack.run_token_check(fake, algorithms=[name], timeout=60.0)
        self.assertResult(result, [name], tamper.url, self.stack.app_url, self.stack.run_dir)
        self.assertIs(result["ok"], False)
        self.assertTrue(eventually(lambda: descendants() <= baseline))
        return result

    def test_verify_of_another_configuration_is_not_verified(self):
        self.require_result()
        # The EdDSA and ES256 fixture tokens have the same size, so only `algorithm` is wrong.
        issue, issued = fetch_json(f"{self.stack.app_url}/api/token/issue?alg=EdDSA&delivery=body")
        self.assertEqual(issue.status, 200, issue.body)
        result = self.tampered_check("swapped", "ES256", issued["token"])
        for entry in result["results"]:
            with self.subTest(transport=entry["transport"]):
                self.assertEqual((entry["expected"], entry["outcome"]), ("verified", "rejected"))
                self.assertIs(entry["ok"], False)
                self.assertEqual(entry["verify"]["status"], 200)
                body = entry["verify"]["body"]
                self.assertEqual((body["verified"], body["algorithm"], body["source"]),
                                 (True, "EdDSA", entry["transport"]))
                self.assertIs(entry["direct"]["verified"], True)

    def test_unexpected_received_sizes_are_not_verified(self):
        self.require_result()
        result = self.tampered_check("resized", "EdDSA")
        for entry in result["results"]:
            size = entry["token_bytes"]
            with self.subTest(transport=entry["transport"]):
                self.assertEqual((entry["expected"], entry["outcome"]), ("verified", "rejected"))
                self.assertIs(entry["ok"], False)
                self.assertEqual(entry["verify"]["status"], 200)
                body = entry["verify"]["body"]
                self.assertEqual((body["verified"], body["algorithm"], body["source"]),
                                 (True, "EdDSA", entry["transport"]))
                sizes = (body["received"]["cookie_bytes"], body["received"]["authorization_bytes"])
                self.assertEqual(sizes, (4 + size + len("; pad=1"), None)
                                 if entry["transport"] == "cookie" else (None, 8 + size))
                self.assertIs(entry["direct"]["verified"], True)

    def test_request_that_never_reaches_the_proxy_is_a_browser_rejection(self):
        self.require_result()
        result = self.tampered_check("dropped", "ES256")
        for entry in result["results"]:
            with self.subTest(transport=entry["transport"]):
                self.assertEqual((entry["expected"], entry["outcome"]), ("verified", "rejected"))
                self.assertEqual(entry["verify"]["status"], 502)
                self.assertIs(entry["verify"]["logs"]["proxy_access"], False)
                self.assertIs(entry["verify"]["logs"]["app"], False)
                self.assertEqual(entry["rejected_by"], "browser")
                self.assertIs(entry["ok"], False)
                self.assertIs(entry["direct"]["verified"], True)
                self.assertNamesLayer(entry["evidence"], "browser")

    def test_concurrent_first_requests_share_one_key_pair(self):
        if self.concurrent_error is not None:
            self.fail(f"concurrent requests failed: {self.concurrent_error!r}")
        self.assertEqual(self.concurrent.issue_statuses, [200] * 8)
        # RS256 signatures are deterministic: one shared key pair gives one token.
        self.assertEqual(len(set(self.concurrent.tokens)), 1)
        self.assertEqual(self.concurrent.verify_statuses, [200] * 8)
        self.assertTrue(all(body["verified"] is True for body in self.concurrent.verify_bodies))

    def test_keys_belong_to_one_process(self):
        app = self.stack.app_url
        for name in NAMES:
            with self.subTest(algorithm=name):
                local = json.loads(call(f"/api/token/issue?alg={name}&delivery=body").body)
                issue, remote = fetch_json(f"{app}/api/token/issue?alg={name}&delivery=body")
                self.assertEqual(issue.status, 200, issue.body)
                for token, status in ((remote["token"], 200), (local["token"], 401),
                                      (own_key_token(name, CLAIMS), 401)):
                    response, body = fetch_json(f"{app}/api/token/verify",
                                                [("Authorization", f"Bearer {token}")])
                    self.assertEqual(response.status, status, response.body)
                    self.assertIs(body["experiment_key"], True)
                elsewhere = call("/api/token/verify",
                                 [("Authorization", f"Bearer {remote['token']}")])
                self.assertEqual(elsewhere.status, 401)

    def test_no_key_material_written(self):
        self.require_result()
        for path in self.stack.run_dir.rglob("*"):
            if path.is_file():
                with self.subTest(path=path.name):
                    text = path.read_bytes().decode("latin-1")
                    self.assertNotIn("-----BEGIN", text)
                    self.assertNotIn("PRIVATE KEY", text)

    def test_repository_unchanged(self):
        self.require_result()
        self.assertEqual(git_status(), self.git_before)

    def test_token_endpoints_through_the_proxy(self):
        proxy, marker = self.stack.proxy_url, self.layers["proxy"]["component"]
        issue, body = fetch_json(f"{proxy}/api/token/issue?alg=ES256&delivery=body")
        self.assertEqual(issue.status, 200, issue.body)
        self.assertEqual(issue.headers.get("X-Transport-Proxy"), marker)
        verify, verified = fetch_json(f"{proxy}/api/token/verify",
                                      [("Authorization", f"Bearer {body['token']}")])
        self.assertEqual(verify.status, 200, verify.body)
        self.assertEqual(verify.headers.get("X-Transport-Proxy"), marker)
        self.assertEqual((verified["source"], verified["received"]["authorization_bytes"]),
                         ("bearer", 7 + TOKEN_BYTES["ES256"]))
        cookie_issue = fetch(f"{proxy}/api/token/issue?alg=ML-DSA-44")
        self.assertEqual(cookie_issue.status, 200, cookie_issue.body)
        values = cookie_issue.headers.get_all("Set-Cookie") or []
        self.assertEqual(len(values), 1)
        match = SET_COOKIE.fullmatch(values[0])
        self.assertIsNotNone(match, values[0][:80])
        self.assertEqual(len(match["token"]), TOKEN_BYTES["ML-DSA-44"])
        verify, verified = fetch_json(f"{proxy}/api/token/verify",
                                      [("Cookie", f"jwt={match['token']}")])
        self.assertEqual(verify.status, 200, verify.body)
        self.assertEqual((verified["source"], verified["received"]["cookie_bytes"]),
                         ("cookie", 4 + TOKEN_BYTES["ML-DSA-44"]))
        error = fetch(f"{proxy}/api/token/issue?alg=HS256")
        self.assertEqual(error.status, 400)
        self.assertIsNone(error.headers.get("Set-Cookie"))
        self.assertIs(json.loads(error.body)["experiment_key"], True)
        missing = fetch(f"{proxy}/api/token/verify")
        self.assertEqual(missing.status, 401)
        self.assertEqual(missing.headers.get("X-Transport-Proxy"), marker)

    def test_received_sizes_through_waitress_match_the_echo(self):
        app = self.stack.app_url
        _, body = fetch_json(f"{app}/api/token/issue?alg=EdDSA&delivery=body")
        token, probe = body["token"], secrets.token_hex(8)
        headers = [("Cookie", f"a=1; jwt={token}; b=2"), ("Authorization", "Basic dXNlcjpwYXNz"),
                   ("X-Transport-Repeat", "one"), ("X-Transport-Repeat", "two"),
                   ("X-Transport-Probe", "  padded value  ")]
        _, echo = fetch_json(f"{app}/api/echo?probe={probe}", headers)
        response, verified = fetch_json(f"{app}/api/token/verify?probe={probe}", headers)
        self.assertEqual(response.status, 200, response.body)
        self.assertEqual(verified["source"], "cookie")
        self.assertEqual(verified["received"], received_sizes(echo["headers"]))
        lines = [request for request in app_requests(read_text(self.log_dir / "app.log"))
                 if request.path == "/api/token/verify"
                 and request.query.get("probe") == [probe]]
        self.assertEqual(len(lines), 1)
        values = dict(lines[0].fields)
        self.assertEqual({key: values.get(key) for key in SIZE_FIELDS},
                         {key: logged(verified["received"][key]) for key in SIZE_FIELDS})
        self.assertEqual((values.get("alg"), values.get("verified")), ("EdDSA", "true"))

    def test_waitress_rejection_line_reports_received_bytes(self):
        limit = self.layers["app_server"]["limits"]["total_headers"]["bytes"]
        nonce = secrets.token_hex(16)
        try:
            response = fetch(f"{self.stack.app_url}/api/echo?nonce={nonce}",
                             [("X-Transport-Padding", padding(2 * limit))])
        except (OSError, http.client.HTTPException):
            response = None
        if response is not None:
            self.assertEqual(response.status, 431)
        app_log = self.log_dir / "app.log"

        def rejection() -> str | None:
            return next((line for line in read_text(app_log).splitlines()
                         if nonce in line and "rejected by waitress" in line), None)

        self.assertTrue(eventually(lambda: rejection() is not None))
        line = rejection()
        self.assertRegex(line, rf'"GET /api/echo\?nonce={nonce} HTTP/1\.[01]" 431 '
                               r"rejected by waitress: ")
        match = re.search(r"\breceived_bytes=(\d+)\b", line)
        self.assertIsNotNone(match, line)
        self.assertGreaterEqual(int(match[1]), limit)
        self.assertEqual(fetch(f"{self.stack.app_url}/api/echo").status, 200)

    def test_listens_on_loopback_only(self):
        for url in (self.stack.proxy_url, self.stack.app_url):
            with self.subTest(url=url):
                self.assertTrue(accepts("127.0.0.1", port_of(url)))
                self.assertFalse(accepts("::1", port_of(url), socket.AF_INET6))


def browser_events_from(data: bytes) -> list:
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


class RuntimeFailureTests(unittest.TestCase):
    """run_token_check raises RuntimeError when Playwright or the browser is missing (R10)."""

    def assertRaisesRuntimeError(self, shadow: str, environment: dict) -> None:
        proxy_port, app_port = free_ports(2)
        with tempfile.TemporaryDirectory(prefix="failing check ",
                                         ignore_cleanup_errors=True) as directory, \
                tempfile.TemporaryDirectory(prefix="tokens tmp ",
                                            ignore_cleanup_errors=True) as marker:
            environment = {**without_pythonpath(), **environment, "TMPDIR": marker}
            result = run_python(RAISING_CHECK, shadow, str(REPO), str(proxy_port), str(app_port),
                                str(Path(directory) / "run dir"), cwd=directory,
                                environment=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RuntimeError:", result.stdout, result.stderr)
            self.assertTrue(refused(proxy_port))
            self.assertTrue(refused(app_port))
            self.assertTrue(eventually(lambda: not processes_mentioning(marker)))

    def test_missing_playwright(self):
        with tempfile.TemporaryDirectory(prefix="no playwright ") as shadow:
            package = Path(shadow) / "playwright"
            package.mkdir()
            (package / "__init__.py").write_text(
                'raise ImportError("Playwright hidden by the test")\n', encoding="utf-8")
            self.assertRaisesRuntimeError(shadow, {})

    def test_browser_launch_failure(self):
        with tempfile.TemporaryDirectory(prefix="no browsers ") as browsers:
            self.assertRaisesRuntimeError("", {"PLAYWRIGHT_BROWSERS_PATH": browsers})


class TokensCommandTests(TokenCase):
    """Run `scripts/transport_stack.py tokens` as a subprocess (R17, R18)."""

    def test_tokens_from_another_directory_with_unactivated_environment(self):
        before = git_status()
        environment_before = environment_files()
        with tempfile.TemporaryDirectory(prefix="tokens cwd ") as cwd, \
                tempfile.TemporaryDirectory(prefix="tokens tmp ",
                                            ignore_cleanup_errors=True) as marker:
            environment = {**unactivated_environment(), "TMPDIR": marker}
            result = run_cli("tokens", "--alg", "ES256", "--alg", "ML-DSA-44", cwd=cwd,
                             environment=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(result.stdout, json.dumps(data, indent=2) + "\n")
            self.assertResult(data, ["ES256", "ML-DSA-44"])
            self.assertIs(data["ok"], True)
            self.assertEqual([entry["outcome"] for entry in data["results"]], ["verified"] * 4)
            run_dir = Path(data["run_dir"])
            self.addCleanup(shutil.rmtree, run_dir, True)
            self.assertTrue(is_under(run_dir, Path(marker)), run_dir)
            self.assertFalse(is_under(run_dir, REPO))
            self.assertTrue((run_dir / "logs" / "browser.log").is_file())
            for key in ("proxy_url", "app_url"):
                self.assertTrue(refused(port_of(data[key])))
            # nginx's prefix and Chromium's profile both live under TMPDIR, orphans included.
            self.assertTrue(eventually(lambda: not processes_mentioning(marker)),
                            processes_mentioning(marker))
        self.assertEqual(changed_paths(environment_before, environment_files()), [],
                         f"tokens wrote into the environment at {sys.prefix}")
        self.assertEqual(git_status(), before)

    def test_tokens_reports_mismatches_and_exits_1(self):
        with tempfile.TemporaryDirectory(prefix="tokens mismatch ",
                                         ignore_cleanup_errors=True) as directory, \
                tempfile.TemporaryDirectory(prefix="other cwd ") as cwd:
            checkout = copy_checkout(Path(directory) / "repo copy")
            path = checkout / "transport" / "stack.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            for layer in manifest["layers"]:
                if layer["role"] == "browser":
                    layer["limits"]["cookie"]["bytes"] = 100
                if layer["role"] == "proxy":
                    layer["limits"]["single_header"]["bytes"] = None
            path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            listing = tree_listing(checkout)
            proxy_port, app_port = free_ports(2)
            run_dir = Path(directory) / "run dir"
            result = run_cli("tokens", "--proxy-port", str(proxy_port), "--app-port",
                             str(app_port), "--run-dir", str(run_dir), "--timeout", "120",
                             "--alg", "ES256", "--alg", "SLH-DSA-SHA2-128f",
                             script=checkout / "scripts" / "transport_stack.py", cwd=cwd,
                             environment=unactivated_environment())
            self.assertEqual(result.returncode, 1, result.stderr)
            data = json.loads(result.stdout)
            self.assertResult(data, ["ES256", "SLH-DSA-SHA2-128f"],
                              f"http://127.0.0.1:{proxy_port}", f"http://127.0.0.1:{app_port}",
                              run_dir, manifest=manifest)
            self.assertIs(data["ok"], False)
            table = {(entry["algorithm"], entry["transport"]):
                     (entry["expected"], entry["outcome"], entry["ok"])
                     for entry in data["results"]}
            self.assertEqual(table, {("ES256", "cookie"): ("rejected", "verified", False),
                                     ("ES256", "bearer"): ("verified", "verified", True),
                                     ("SLH-DSA-SHA2-128f", "cookie"):
                                         ("rejected", "rejected", True),
                                     ("SLH-DSA-SHA2-128f", "bearer"):
                                         ("verified", "rejected", False)})
            errors = "\n".join(line for line in result.stderr.splitlines()
                               if line.startswith("Error:"))
            self.assertTrue(errors, result.stderr)
            for term in ("ES256", "SLH-DSA-SHA2-128f", "cookie", "bearer"):
                self.assertIn(term.lower(), errors.lower())
            for port in (proxy_port, app_port):
                self.assertTrue(refused(port))
            self.assertTrue((run_dir / "logs" / "browser.log").is_file())
            self.assertEqual(tree_listing(checkout), listing)

    def test_tokens_usage_errors(self):
        (port,) = free_ports(1)
        cases = [["tokens", "--alg", "RS999"], ["tokens", "--alg", "rs256"],
                 ["tokens", "--alg", "none"], ["tokens", "--alg", "ES256", "--alg", "ES256"],
                 ["tokens", "--alg"], ["tokens", "--proxy-port", "0"],
                 ["tokens", "--app-port", "65536"], ["tokens", "--app-port", "abc"],
                 ["tokens", "--timeout", "0"], ["tokens", "--timeout", "-2"],
                 ["tokens", "--timeout", "soon"],
                 ["tokens", "--proxy-port", str(port), "--app-port", str(port)],
                 ["tokens", "--bogus"]]
        with tempfile.TemporaryDirectory(prefix="usage cwd ") as directory:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = run_cli(*arguments, cwd=directory, timeout=120)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("usage:", result.stderr.lower())
                    self.assertFalse(accepts("127.0.0.1", port))
            result = run_cli("tokens", "--help", cwd=directory, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--alg", result.stdout)

    def test_tokens_busy_port_fails_and_stops_started_processes(self):
        with socket.socket() as holder, tempfile.TemporaryDirectory(
                prefix="tokens busy ", ignore_cleanup_errors=True) as directory:
            holder.bind(("127.0.0.1", 0))
            holder.listen()
            busy = holder.getsockname()[1]
            (app_port,) = free_ports(1)
            result = run_cli("tokens", "--proxy-port", str(busy), "--app-port", str(app_port),
                             "--run-dir", str(Path(directory) / "run dir"), "--timeout", "30",
                             "--alg", "ES256", cwd=directory)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(result.stderr, ERROR_LINE)
            self.assertTrue(refused(app_port))

    def test_tokens_stops_cleanly_on_signal(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum.name), tempfile.TemporaryDirectory(
                    prefix="tokens signal ", ignore_cleanup_errors=True) as directory, \
                    tempfile.TemporaryDirectory(prefix="tokens tmp ",
                                                ignore_cleanup_errors=True) as marker:
                proxy_port, app_port = free_ports(2)
                environment = {**unactivated_environment(), "TMPDIR": marker}
                output = Path(directory) / "tokens output.txt"
                with output.open("w", encoding="utf-8") as sink:
                    process = subprocess.Popen(
                        [sys.executable, str(SCRIPT), "tokens", "--proxy-port", str(proxy_port),
                         "--app-port", str(app_port), "--run-dir", str(Path(directory) / "run"),
                         "--timeout", "120"],
                        cwd=directory, env=environment, stdin=subprocess.DEVNULL, stdout=sink,
                        stderr=subprocess.STDOUT)
                try:
                    # The run directory is outside TMPDIR, so only the browser mentions it.
                    self.assertTrue(eventually(lambda: process.poll() is not None
                                               or bool(processes_mentioning(marker)),
                                               grace=CLI_TIMEOUT))
                    self.assertIsNone(process.poll(), read_text(output))
                    process.send_signal(signum)
                    try:
                        returncode = process.wait(timeout=120)
                    except subprocess.TimeoutExpired:
                        self.fail(f"tokens did not stop after {signum.name}")
                finally:
                    stop(process)
                self.assertGreaterEqual(returncode, 0, f"killed by the signal: {read_text(output)}")
                for port in (proxy_port, app_port):
                    self.assertTrue(refused(port))
                self.assertTrue(eventually(lambda: not processes_mentioning(marker)),
                                processes_mentioning(marker))


if __name__ == "__main__":
    unittest.main()
