"""Check S3-02's reference tokens without a stack or a browser: the reference format, the memory
store, the application's reference and revoke endpoints and its reference sources (in-process
WSGI calls with transport_app.REF_STORE patched, compared with the 2129d99 application), the
load workload's reference carrier, the refs plan, the refs run's settings and interface,
summary_lines, where the code goes, and what stays unchanged; no timing thresholds."""

import ast
import base64
from contextlib import contextmanager
import importlib.util
import inspect
import json
import logging
import math
import os
from pathlib import Path
import random
import re
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

from scripts import transport_app, transport_load
from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.token_sizing import claim_set, pad_for_target, padded_claims, token_bytes
from scripts.transport_stack import load_manifest

try:
    from scripts import transport_refs
    REFS_IMPORT_ERROR = None
except Exception as error:  # Before S3-02's reference tokens are built: tests fail, not vanish.
    transport_refs, REFS_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
# The commit reference tokens build on: unchanged files and the reference application come
# from it.
BASE_COMMIT = "2129d9958ab810185a3556bc4fb4c62378182231"
REFS_MODULE = REPO / "scripts" / "transport_refs.py"
COOKIES_UNITS = REPO / "tests" / "test_transport_cookies_units.py"
HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
REFERENCE_PATH = "/api/token/reference"
REVOKE_PATH = "/api/token/revoke"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
CLAIM_SET_NAMES = ("minimal", "oidc", "essential")

REF_PREFIX = "ref_"
REF_RANDOM_BYTES = 32
REF_BYTES = 47
REF_COOKIE_NAME = "jwt_ref"
REF_DEFAULT_TTL = 3600
REF_MAX_TTL = 86400
REF_FORMAT = re.compile(r"ref_[A-Za-z0-9_-]{43}")
REF_ALPHABET = string.ascii_letters + string.digits + "-_"
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
DEFAULT_ATTRIBUTES = "Path=/; HttpOnly; SameSite=Strict"
TOKEN_BYTES_OIDC = {"RS256": 1204, "ES256": 948, "EdDSA": 948, "ML-DSA-44": 4095,
                    "SLH-DSA-SHA2-128s": 11353, "SLH-DSA-SHA2-128f": 23662}
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
NONCE = "0123456789abcdef" * 2

# Sprint 2's verify response bodies, and the issue endpoint's 400 body.
VERIFIED_KEYS = {"layer", "verified", "algorithm", "source", "token_bytes", "claims",
                 "experiment_key", "received"}
FAILED_KEYS = {"layer", "verified", "source", "error", "experiment_key", "received"}
ISSUE_ERROR_KEYS = {"layer", "error", "algorithms", "experiment_key"}
# R5's bodies of GET /api/token/reference, R7's of a revoke, and R6's ref object.
REF_COOKIE_KEYS = {"layer", "algorithm", "delivery", "cookie_name", "reference_bytes",
                   "token_bytes", "set_cookie_bytes", "claims", "pad", "attrs", "ttl", "store",
                   "experiment_key"}
REF_BODY_KEYS = {"layer", "algorithm", "delivery", "reference", "reference_bytes", "token_bytes",
                 "claims", "pad", "ttl", "store", "experiment_key"}
STORE_ERROR_KEYS = {"layer", "error", "store", "experiment_key"}
REVOKED_KEYS = {"layer", "revoked", "ref", "experiment_key"}
REF_OBJECT_KEYS = {"status", "store", "reference_bytes"}
REF_TIMING_KEYS = {"verify_ns", "handler_ns", "lookup_ns"}
PLAIN_TIMING_KEYS = {"verify_ns", "handler_ns"}
APP_LOG_MESSAGE = re.compile(r'^(?P<remote>\S+) "(?P<method>\S+) (?P<target>\S+) '
                             r'(?P<protocol>\S+)" (?P<status>\d{3}) ?(?P<fields>.*)$')

SETTING_NAMES = ("algorithms", "claims", "clients", "concurrency", "duration", "warmup",
                 "timeout", "header_buffers", "upstream_keepalive")
RUN_REFS_DEFAULTS = {"algorithms": None, "claims": "oidc", "clients": None,
                     "concurrency": [1, 4], "duration": 5.0, "warmup": 1.0, "timeout": 60.0,
                     "header_buffers": "32k", "upstream_keepalive": None, "run_dir": None}
LOAD_DEFAULTS = {"algorithms": None, "transport": "bearer", "clients": None,
                 "concurrency": (1, 4), "duration": 5.0, "warmup": 1.0, "claims": "minimal",
                 "reference": "ES256", "size_controls": True, "timeout": 60.0,
                 "proxy_buffers": None, "header_buffers": None, "upstream_keepalive": None}
LOAD_SETTINGS_KEYS = {"algorithms", "transport", "clients", "claims", "concurrency", "duration",
                      "warmup", "reference", "size_controls", "timeout", "proxy_buffers",
                      "header_buffers", "upstream_keepalive"}
# transport_load's names as of BASE_COMMIT, which R11 keeps.
LATENCY_COMPONENTS = ("total", "transfer", "other_handling", "verification")
REF_COMPONENTS = ("total", "transfer", "other_handling", "lookup", "verification")
RAW_FIELDS = ("client", "concurrency", "algorithm", "variant", "signed_with", "pad",
              "token_bytes", "worker", "sequence", "nonce", "start_ns", "total_ns", "handler_ns",
              "verify_ns", "status", "verified", "error")
NETWORK_PROFILES = ({"uplink_mbps": 100, "rtt_ms": 10}, {"uplink_mbps": 10, "rtt_ms": 50},
                    {"uplink_mbps": 1, "rtt_ms": 100})
RUNS = ("jwt", "ref_memory", "ref_remote")

PLAN_KEYS = {"algorithm", "token_bytes", "reference_bytes", "name_value_bytes",
             "set_cookie_bytes", "cookie_line_bytes", "authorization_line_bytes", "fits"}
ML_DSA_44_ROW = {
    "algorithm": "ML-DSA-44", "token_bytes": 4095, "reference_bytes": 47,
    "name_value_bytes": {"jwt": 4098, "ref": 54},
    "set_cookie_bytes": {"jwt": 4170, "ref": 126},
    "cookie_line_bytes": {"jwt": 4109, "ref": 65},
    "authorization_line_bytes": {"jwt": 4119, "ref": 71},
    "fits": {"jwt": {"per_cookie": False, "cookie_line": True, "authorization_line": True},
             "ref": {"per_cookie": True, "cookie_line": True, "authorization_line": True}},
}
PROBE_TARGETS = (65536, 300000)
PROBE_ALGORITHM = "SLH-DSA-SHA2-128f"

# R15's cases: name, status, source, ref status, lookup called, verify_token called.
HANDLING_CASES = (
    ("cookie", 200, "ref_cookie", "found", True, True),
    ("bearer", 200, "ref_bearer", "found", True, True),
    ("among_other_cookies", 200, "ref_cookie", "found", True, True),
    ("unknown", 401, "ref_bearer", "unknown", True, False),
    ("malformed_cookie", 401, "ref_cookie", "malformed", False, False),
    ("expired", 401, "ref_bearer", "expired", True, False),
    ("revoked", 401, "ref_bearer", "revoked", True, False),
    ("two_references", 400, None, None, False, False),
    ("reference_and_jwt", 400, None, None, False, False),
    ("reference_as_jwt", 401, "cookie", None, False, False),
    ("store_unavailable", 503, "ref_bearer", "unavailable", True, False),
    ("jwt_without_store", 200, "bearer", None, False, True),
    ("issue_without_store", 503, None, None, False, False),
)
CASE_NAMES = tuple(case[0] for case in HANDLING_CASES)

# R1: transport_cookies names transport_refs must not define again, and the imports it needs.
COOKIES_HELPERS = ("launched_browser", "issue_at_application", "DirectIssue",
                   "documented_limits", "set_cookie_line_bytes", "app_header_bytes")
REQUIRED_IMPORTS = {
    "scripts.transport_claims": ("check_output_dir", "without_tokens", "save_stack_evidence",
                                 "phase_run_dir", "require_playwright"),
    "scripts.transport_load": ("run_load", "write_load_results", "run_environment"),
    "scripts.transport_stack": ("start_stack",),
    "scripts.transport_cookies": ("launched_browser",),
}
OWN_NAMES = {"checked_settings"}
COOKIES_API = ("run_cookies", "default_settings", "checked_settings", "read_saved_settings",
               "chunk_plan", "summary_lines")

IMPORT_CHECK = """\
import json
import os
import subprocess
import sys
import threading
sys.path.insert(0, sys.argv[1])
import scripts.transport_refs as refs
rows = len(refs.ref_plan(["ML-DSA-44"])) if sys.argv[2] == "plan" else None
listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True)
output, _ = listing.communicate()
children = [fields[0] for fields in (line.split() for line in output.splitlines())
            if len(fields) == 2 and fields[1] == str(os.getpid())
            and fields[0] != str(listing.pid)]
playwright = any(name == "playwright" or name.startswith("playwright.") for name in sys.modules)
print(json.dumps({"children": len(children), "threads": threading.active_count(),
                  "playwright": playwright, "rows": rows}))
"""
STACK_IMPORT_CHECK = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
import scripts.transport_stack
print(json.dumps(sorted(name for name in ("scripts.transport_refs", "scripts.transport_cookies",
                                          "scripts.transport_load", "scripts.transport_claims",
                                          "scripts.token_sizing", "scripts.algorithms",
                                          "cryptography", "playwright")
                        if name in sys.modules)))
"""
MODULE_IMPORT_CHECK = """\
import importlib
import json
import os
import subprocess
import sys
import threading
sys.path.insert(0, sys.argv[1])
importlib.import_module(sys.argv[2])
listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True)
output, _ = listing.communicate()
children = [fields[0] for fields in (line.split() for line in output.splitlines())
            if len(fields) == 2 and fields[1] == str(os.getpid())
            and fields[0] != str(listing.pid)]
print(json.dumps({"children": len(children), "threads": threading.active_count()}))
"""
APP_IMPORT_CHECK = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
import scripts.transport_app as app
print(json.dumps({"memory": isinstance(app.REF_STORE, app.MemoryRefStore),
                  "kind": app.REF_STORE.kind}))
"""


# ---- the modules under test --------------------------------------------------------------

def module():
    """Return scripts.transport_refs, failing the calling test when it cannot be imported."""
    if transport_refs is None:
        raise AssertionError(f"scripts/transport_refs.py cannot be imported: "
                             f"{REFS_IMPORT_ERROR!r}")
    return transport_refs


def app_api(name: str):
    """An attribute R2-R8 add to scripts/transport_app.py, failing the test when it is missing."""
    if not hasattr(transport_app, name):
        raise AssertionError(f"scripts/transport_app.py has no {name}")
    return getattr(transport_app, name)


def ref_carrier():
    """transport_load.REF_CARRIER, failing the calling test when it is missing."""
    carrier = getattr(transport_load, "REF_CARRIER", None)
    if carrier is None:
        raise AssertionError("scripts/transport_load.py has no REF_CARRIER")
    return carrier


def shared_helpers() -> dict[str, tuple]:
    """SHARED_HELPERS of tests/test_transport_cookies_units.py, read from its source."""
    tree = ast.parse(COOKIES_UNITS.read_text(encoding="utf-8"))
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "SHARED_HELPERS"):
            return ast.literal_eval(node.value)
    raise AssertionError("tests/test_transport_cookies_units.py has no SHARED_HELPERS")


# ---- what the spec says, computed independently ---------------------------------------------

def random_reference(seed: int) -> str:
    """A string of the reference format, from REF_ALPHABET."""
    generator = random.Random(seed)
    return REF_PREFIX + "".join(generator.choice(REF_ALPHABET) for _ in range(43))


def manifest_limits() -> tuple[int, int]:
    """transport/stack.json's browser cookie limit and proxy single_header limit."""
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return (layers["browser"]["limits"]["cookie"]["bytes"],
            layers["proxy"]["limits"]["single_header"]["bytes"])


def expected_plan_row(algorithm: str, claims: str = "oidc") -> dict:
    """R13's row for one configuration, computed from the spec's formulas."""
    cookie_limit, line_limit = manifest_limits()
    total, ref = token_bytes(algorithm, claim_set(claims)), REF_BYTES
    name_value = {"jwt": 3 + total, "ref": 7 + ref}
    set_cookie = {"jwt": len(f"Set-Cookie: jwt=; {FULL_ATTRIBUTES}\r\n") + total,
                  "ref": len(f"Set-Cookie: jwt_ref=; {FULL_ATTRIBUTES}\r\n") + ref}
    cookie_line = {"jwt": len("Cookie: jwt=\r\n") + total, "ref": len("Cookie: jwt_ref=\r\n") + ref}
    authorization = {"jwt": len("Authorization: Bearer \r\n") + total,
                     "ref": len("Authorization: Bearer \r\n") + ref}
    return {
        "algorithm": algorithm, "token_bytes": total, "reference_bytes": ref,
        "name_value_bytes": name_value, "set_cookie_bytes": set_cookie,
        "cookie_line_bytes": cookie_line, "authorization_line_bytes": authorization,
        "fits": {side: {"per_cookie": name_value[side] <= cookie_limit,
                        "cookie_line": cookie_line[side] <= line_limit,
                        "authorization_line": authorization[side] <= line_limit}
                 for side in ("jwt", "ref")},
    }


def git(*arguments: str) -> str | None:
    """Run git in the repository and return its stdout, or None when git or a commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), *arguments], capture_output=True,
                              text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def git_show(path: str) -> str | None:
    """Return a file as committed at BASE_COMMIT, or None when git or the commit is missing."""
    return git("show", f"{BASE_COMMIT}:{path}")


def run_python(code: str, *arguments: str) -> subprocess.CompletedProcess:
    """Run code in a fresh interpreter from the repository root; return the finished process."""
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, "-c", code, *arguments], cwd=REPO, env=environment,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def closed_port() -> int:
    """A port on 127.0.0.1 that nothing listens on a moment later."""
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


# ---- in-process WSGI calls ---------------------------------------------------------------

class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep the record's message."""
        self.messages.append(record.getMessage())


def wsgi_call(application, target: str, headers: dict | None = None,
              method: str = "GET") -> SimpleNamespace:
    """Call a WSGI application in process; return its status, headers, body, and log lines."""
    path, _, query = target.partition("?")
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
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
        body = b"".join(application(environ, start_response))
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
        path = Path(directory) / "transport_app_2129d99.py"
        path.write_text(text, encoding="utf-8")
        # A name inside the scripts package, so the module does not change sys.path.
        spec = importlib.util.spec_from_file_location("scripts._transport_app_2129d99", path)
        base = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(base)
    for name in ("EXPERIMENT_KEYS", "EXPERIMENT_KEYS_LOCK", "TEST_PAGE"):
        setattr(base, name, getattr(transport_app, name))
    return base


def json_body(data: bytes) -> dict:
    """A response body's JSON object; raises AssertionError otherwise."""
    value = json.loads(data)
    if not isinstance(value, dict):
        raise AssertionError(f"not a JSON object: {data[:200]!r}")
    return value


def log_fields(message: str) -> tuple[str, list[str]]:
    """Split an app.log message into its target and its key=value fields, in order."""
    match = APP_LOG_MESSAGE.match(message)
    if match is None:
        raise AssertionError(f"unexpected app.log line: {message!r}")
    return match["target"], match["fields"].split()


def set_cookies(response: SimpleNamespace) -> list[str]:
    """The response's Set-Cookie header values, in order."""
    return [value for name, value in response.headers if name.lower() == "set-cookie"]


def header_values(response: SimpleNamespace, wanted: str) -> list[str]:
    """The response's values of one header, in order."""
    return [value for name, value in response.headers if name.lower() == wanted.lower()]


def cookie_value(set_cookie: str) -> tuple[str, str]:
    """The cookie name and value of a Set-Cookie header value."""
    name, _, value = set_cookie.split(";", 1)[0].partition("=")
    return name, value


def response_token(response: SimpleNamespace) -> str | None:
    """The token a cookie or body issue response delivered, for masking."""
    body = json.loads(response.body)
    if isinstance(body, dict) and isinstance(body.get("token"), str):
        return body["token"]
    for value in set_cookies(response):
        if value.startswith("jwt="):
            return value[len("jwt="):].split(";", 1)[0]
    return None


def normalized(response: SimpleNamespace) -> tuple:
    """A response with its token replaced by its length, so two signings compare equal."""
    token = response_token(response)

    def masked(text: str) -> str:
        return text.replace(token, f"<token of {len(token)} bytes>") if token else text
    return (response.status, [(name, masked(value)) for name, value in response.headers],
            masked(response.body.decode("utf-8")), response.log)


def tampered(token: str) -> str:
    """Change one character in the middle of the signature segment."""
    header, payload, signature = token.split(".")
    middle = len(signature) // 2
    changed = "A" if signature[middle] != "A" else "B"
    return f"{header}.{payload}.{signature[:middle]}{changed}{signature[middle + 1:]}"


def b64(value) -> str:
    """Unpadded base64url of bytes, or of a value's JSON."""
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def foreign_alg_token() -> str:
    """A well-formed token whose header names HS256, which no adapter handles."""
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': 'x'})}.c2ln"


# ---- reference stores the tests control ------------------------------------------------------

class FakeClock:
    """A clock for MemoryRefStore that moves only when a test moves it."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the clock forward by seconds."""
        self.now += seconds


def memory_store(clock=None):
    """A new MemoryRefStore, on a fake clock unless one is given."""
    return app_api("MemoryRefStore")(clock=FakeClock() if clock is None else clock)


class RecordingStore:
    """Wraps a reference store and records every call the application makes to it."""

    def __init__(self, inner, kind: str | None = None, before_get=None):
        self.inner = inner
        self.kind = kind or inner.kind
        self.before_get = before_get
        self.calls: list[tuple] = []

    def put(self, ref, token, ttl):
        self.calls.append(("put", ref, token, ttl))
        return self.inner.put(ref, token, ttl)

    def get(self, ref):
        self.calls.append(("get", ref))
        if self.before_get is not None:
            self.before_get()
        return self.inner.get(ref)

    def revoke(self, ref):
        self.calls.append(("revoke", ref))
        return self.inner.revoke(ref)

    def count(self, name: str) -> int:
        """How many calls of one method the store received."""
        return sum(call[0] == name for call in self.calls)

    def puts(self) -> list[tuple]:
        """Every put call, in order."""
        return [call for call in self.calls if call[0] == "put"]


class UnavailableStore:
    """A remote store whose every call fails as if the store process were stopped."""

    kind = "remote"

    def __init__(self, before_raise=None):
        self.before_raise = before_raise
        self.calls: list[str] = []

    def fail(self, name: str):
        """Record the call and raise RefStoreUnavailable."""
        self.calls.append(name)
        if self.before_raise is not None:
            self.before_raise()
        raise app_api("RefStoreUnavailable")("the store process is stopped")

    def put(self, ref, token, ttl):
        self.fail("put")

    def get(self, ref):
        self.fail("get")

    def revoke(self, ref):
        self.fail("revoke")


@contextmanager
def patched_store(store):
    """Make the application use store as REF_STORE while the context lasts."""
    app_api("REF_STORE")
    with mock.patch.object(transport_app, "REF_STORE", store):
        yield store


class StepCounter:
    """Stands in for time.perf_counter_ns: one nanosecond per call, plus any jump a test makes."""

    def __init__(self):
        self.value = 10**12

    def __call__(self) -> int:
        self.value += 1
        return self.value

    def jump(self, amount: int) -> None:
        """Move the counter forward by amount nanoseconds."""
        self.value += amount


LOOKUP_JUMP = 10**15


# ---- R2: the reference format ------------------------------------------------------------

class ReferenceFormatTests(unittest.TestCase):
    def test_constants(self):
        expected = {"REF_PREFIX": REF_PREFIX, "REF_RANDOM_BYTES": REF_RANDOM_BYTES,
                    "REF_BYTES": REF_BYTES, "REF_COOKIE_NAME": REF_COOKIE_NAME,
                    "REF_DEFAULT_TTL": REF_DEFAULT_TTL, "REF_MAX_TTL": REF_MAX_TTL,
                    "REFERENCE_PATH": REFERENCE_PATH, "REVOKE_PATH": REVOKE_PATH}
        for name, value in expected.items():
            with self.subTest(constant=name):
                self.assertEqual(app_api(name), value)
        self.assertEqual(tuple(app_api("REF_SOURCES")), ("ref_cookie", "ref_bearer"))

    def test_new_reference_format(self):
        new_reference = app_api("new_reference")
        for _ in range(200):
            reference = new_reference()
            self.assertIsInstance(reference, str)
            self.assertEqual(len(reference), REF_BYTES)
            self.assertRegex(reference, rf"\A{REF_FORMAT.pattern}\Z")
            # 43 base64url characters without padding are exactly 32 random bytes.
            raw = base64.urlsafe_b64decode(reference[len(REF_PREFIX):] + "=")
            self.assertEqual(len(raw), REF_RANDOM_BYTES)
            self.assertEqual(base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
                             reference[len(REF_PREFIX):])

    def test_new_reference_is_random_every_call(self):
        new_reference = app_api("new_reference")
        references = [new_reference() for _ in range(2000)]
        self.assertEqual(len(set(references)), len(references))
        # Nothing about a token or claims: no fixed text after the prefix.
        tails = [reference[len(REF_PREFIX):] for reference in references]
        self.assertGreater(len({tail[:4] for tail in tails}), 1000)
        self.assertGreater(len({tail[-8:] for tail in tails}), 1000)

    def test_new_reference_takes_no_argument(self):
        self.assertEqual(list(inspect.signature(app_api("new_reference")).parameters), [])

    def test_is_reference_accepts_the_format(self):
        is_reference = app_api("is_reference")
        accepted = [app_api("new_reference")(), random_reference(1), random_reference(2),
                    "ref_" + "A" * 43, "ref_" + "-" * 43, "ref_" + "_" * 43,
                    "ref_" + "z9" * 21 + "Q"]
        for value in accepted:
            with self.subTest(value=value):
                self.assertIs(is_reference(value), True)

    def test_is_reference_rejects_everything_else(self):
        is_reference = app_api("is_reference")
        good = random_reference(3)
        jwt = f"{b64({'alg': 'ES256'})}.{b64({'sub': 'x'})}.c2ln"
        rejected = [
            None, 1, 47.0, True, b"ref_" + b"A" * 43, bytearray(good.encode()), [good], (good,),
            {good: 1}, "", "ref_", good[:-1], good + "A", "ref_" + "A" * 42, "ref_" + "A" * 44,
            good[:20] + "." + good[21:], good[:-1] + ".", good[:-1] + "=", good[:-2] + "==",
            "REF_" + good[4:], "Ref_" + good[4:], "ref-" + good[4:], "jwt_" + good[4:],
            " " + good, good + " ", good + "\n", "\n" + good, good[:30] + " " + good[31:],
            good[:-1] + "é", good[:-1] + "١", good[:-1] + "+", good[:-1] + "/", jwt,
            foreign_alg_token(), "Bearer " + good, "jwt_ref=" + good, good + good,
            "ref_" + "A" * 4000,
        ]
        for value in rejected:
            with self.subTest(value=repr(value)[:60]):
                self.assertIs(is_reference(value), False)

    def test_is_reference_never_raises(self):
        is_reference = app_api("is_reference")
        generator = random.Random(47)
        alphabet = REF_ALPHABET + ".=+/ \x00ÿ١\t"
        values = [generator.choice(["ref_", "", "re", "ref"])
                  + "".join(generator.choice(alphabet) for _ in range(generator.randint(0, 60)))
                  for _ in range(2000)]
        values += [object(), 10**100, float("nan"), "\udcff" * 47, "ref_" + "\udcff" * 43]
        for value in values:
            with self.subTest(value=repr(value)[:60]):
                result = is_reference(value)
                self.assertIsInstance(result, bool)
                if result:
                    self.assertRegex(value, rf"\A{REF_FORMAT.pattern}\Z")


# ---- R3: the reference stores ------------------------------------------------------------

class MemoryRefStoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = memory_store(self.clock)

    def test_interface(self):
        self.assertEqual(self.store.kind, "memory")
        parameters = inspect.signature(app_api("MemoryRefStore")).parameters
        self.assertEqual(list(parameters), ["clock"])
        self.assertIs(parameters["clock"].default, time.monotonic)
        for name, arguments in (("put", ["ref", "token", "ttl"]), ("get", ["ref"]),
                                ("revoke", ["ref"])):
            with self.subTest(method=name):
                self.assertEqual(list(inspect.signature(getattr(self.store, name)).parameters),
                                 arguments)

    def test_found_until_the_ttl_then_expired(self):
        reference = random_reference(10)
        self.assertIsNone(self.store.put(reference, "a.b.c", 10))
        self.assertEqual(tuple(self.store.get(reference)), ("found", "a.b.c"))
        self.clock.advance(9.75)
        self.assertEqual(tuple(self.store.get(reference)), ("found", "a.b.c"))
        self.clock.advance(0.25)  # Exactly ttl seconds after the put.
        self.assertEqual(tuple(self.store.get(reference)), ("expired", None))
        self.clock.advance(10**6)
        self.assertEqual(tuple(self.store.get(reference)), ("expired", None))

    def test_unknown_references(self):
        self.assertEqual(tuple(self.store.get(random_reference(11))), ("unknown", None))
        self.store.put(random_reference(12), "token", 60)
        self.assertEqual(tuple(self.store.get(random_reference(13))), ("unknown", None))
        self.assertEqual(tuple(self.store.get(app_api("new_reference")())), ("unknown", None))

    def test_revoke_returns_the_status_before(self):
        found, expired = random_reference(20), random_reference(21)
        self.store.put(found, "token-1", 100)
        self.store.put(expired, "token-2", 1)
        self.clock.advance(5)
        self.assertEqual(self.store.revoke(found), "found")
        self.assertEqual(tuple(self.store.get(found)), ("revoked", None))
        self.assertEqual(self.store.revoke(found), "revoked")
        self.assertEqual(tuple(self.store.get(found)), ("revoked", None))
        self.assertEqual(self.store.revoke(expired), "expired")
        self.assertEqual(tuple(self.store.get(expired)), ("revoked", None))
        self.clock.advance(10**6)  # Revoked stays revoked, never expired.
        self.assertEqual(tuple(self.store.get(found)), ("revoked", None))

    def test_revoking_an_unknown_reference_stores_nothing(self):
        reference = random_reference(22)
        self.assertEqual(self.store.revoke(reference), "unknown")
        self.assertEqual(tuple(self.store.get(reference)), ("unknown", None))
        self.assertEqual(self.store.revoke(reference), "unknown")

    def test_put_again_replaces_the_token_and_ttl(self):
        reference = random_reference(23)
        self.store.put(reference, "first", 10)
        self.clock.advance(5)
        self.store.put(reference, "second", 100)
        self.assertEqual(tuple(self.store.get(reference)), ("found", "second"))
        self.clock.advance(45)  # Past the first TTL, within the second.
        self.assertEqual(tuple(self.store.get(reference)), ("found", "second"))
        self.store.put(reference, "third", 1)
        self.clock.advance(200)
        self.assertEqual(tuple(self.store.get(reference)), ("expired", None))

    def test_ttl_bounds(self):
        for ttl in (1, 2, 3600, REF_MAX_TTL):
            with self.subTest(ttl=ttl):
                reference = random_reference(ttl)
                self.store.put(reference, "token", ttl)
                self.assertEqual(tuple(self.store.get(reference)), ("found", "token"))

    def test_put_validates_its_arguments(self):
        good = random_reference(30)
        bad_references = ["", "ref_", good[:-1], good + "A", good[:-1] + ".", "REF_" + good[4:],
                          None, 47, b"ref_" + b"A" * 43, "not-a-reference"]
        for reference in bad_references:
            with self.subTest(ref=repr(reference)[:60]), self.assertRaises(ValueError):
                self.store.put(reference, "token", 60)
        for token in ("", None, 1, b"a.b.c", ["a.b.c"]):
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.store.put(good, token, 60)
        for ttl in (0, -1, REF_MAX_TTL + 1, 10**9, True, False, 1.0, 60.5, "60", None):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.store.put(good, "token", ttl)
        self.assertEqual(tuple(self.store.get(good)), ("unknown", None))

    def test_thread_safe_puts_and_gets(self):
        errors, references = [], {}

        def worker(index: int) -> None:
            try:
                for item in range(200):
                    reference = app_api("new_reference")()
                    token = f"token-{index}-{item}"
                    self.store.put(reference, token, 3600)
                    references[reference] = token
                    if tuple(self.store.get(reference)) != ("found", token):
                        errors.append(reference)
            except Exception as error:  # Reported below.
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(references), 1600)
        for reference, token in references.items():
            self.assertEqual(tuple(self.store.get(reference)), ("found", token))

    def test_concurrent_revokes_see_found_once(self):
        store = memory_store(time.monotonic)
        reference = random_reference(31)
        store.put(reference, "token", 3600)
        barrier, statuses = threading.Barrier(16), []

        def worker() -> None:
            barrier.wait()
            statuses.append(store.revoke(reference))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(statuses), ["found"] + ["revoked"] * 15)

    def test_default_clock_is_monotonic(self):
        store = app_api("MemoryRefStore")()
        reference = random_reference(32)
        store.put(reference, "token", 3600)
        self.assertEqual(tuple(store.get(reference)), ("found", "token"))


class RemoteRefStoreUnitTests(unittest.TestCase):
    """R3: RemoteRefStore's interface, and a store nothing answers for."""

    def setUp(self):
        self.store = app_api("RemoteRefStore")(f"http://{HOST}:{closed_port()}")

    def test_interface(self):
        parameters = inspect.signature(app_api("RemoteRefStore")).parameters
        self.assertEqual(list(parameters), ["url", "timeout"])
        self.assertEqual(parameters["timeout"].default, 5.0)
        self.assertEqual(self.store.kind, "remote")
        self.assertTrue(issubclass(app_api("RefStoreUnavailable"), Exception))

    def test_unreachable_store_raises_ref_store_unavailable(self):
        unavailable = app_api("RefStoreUnavailable")
        reference = random_reference(40)
        for name, call in (("get", lambda: self.store.get(reference)),
                           ("revoke", lambda: self.store.revoke(reference)),
                           ("put", lambda: self.store.put(reference, "a.b.c", 60))):
            with self.subTest(method=name), self.assertRaises(unavailable):
                call()

    def test_put_still_validates_its_arguments(self):
        good = random_reference(41)
        for arguments in (("not-a-reference", "token", 60), (good, "", 60), (good, "t", 0),
                          (good, "t", True), (good, "t", REF_MAX_TTL + 1)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.store.put(*arguments)

    def test_ref_store_is_a_memory_store_on_import(self):
        result = run_python(APP_IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"memory": True, "kind": "memory"})

    def test_store_application_is_a_wsgi_callable(self):
        self.assertTrue(callable(app_api("store_application")))


# ---- R5-R9: the application, in process --------------------------------------------------

class ApplicationCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = base_application()

    def require_base(self):
        """The BASE_COMMIT application, or skip without it."""
        if self.base is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return self.base

    @staticmethod
    def call(target: str, headers: dict | None = None, method: str = "GET") -> SimpleNamespace:
        """Call the application in process; return what wsgi_call returns."""
        return wsgi_call(transport_app.application, target, headers, method)

    def reference_call(self, store, **query) -> tuple[SimpleNamespace, dict]:
        """GET /api/token/reference with query, with store as REF_STORE."""
        with patched_store(store):
            response = self.call(f"{REFERENCE_PATH}?{urlencode(query)}")
        return response, json_body(response.body)

    def new_reference(self, store, algorithm: str = "ES256", **query) -> str:
        """Issue a reference into store with delivery=body and return it."""
        response, body = self.reference_call(store, alg=algorithm, delivery="body", **query)
        self.assertEqual(response.code, 200, body)
        return body["reference"]

    def body_token(self, algorithm: str, **query) -> str:
        """A token issued in the response body with query."""
        query = {"alg": algorithm, "delivery": "body", **query}
        response = self.call(f"{ISSUE_PATH}?{urlencode(query)}")
        self.assertEqual(response.code, 200)
        return json_body(response.body)["token"]

    def verify(self, store, headers: dict,
               query: str = "?timing=1") -> tuple[SimpleNamespace, dict]:
        """GET /api/token/verify with headers, with store as REF_STORE."""
        with patched_store(store):
            response = self.call(f"{VERIFY_PATH}{query}", headers)
        return response, json_body(response.body)

    def revoke(self, store, headers: dict, method: str = "POST") -> SimpleNamespace:
        """A request to /api/token/revoke (POST by default), with store as REF_STORE."""
        with patched_store(store):
            return self.call(REVOKE_PATH, headers, method)

    def assertNoSecret(self, response: SimpleNamespace, *secrets: str) -> None:
        """Neither the body, nor a header, nor the log line holds any of the secrets."""
        text = response.body.decode("utf-8", errors="replace")
        for secret in secrets:
            self.assertNotIn(secret, text)
            for name, value in response.headers:
                if name.lower() != "set-cookie":
                    self.assertNotIn(secret, value)
            for line in response.log:
                self.assertNotIn(secret, line)

    def assertJsonHeaders(self, response: SimpleNamespace, cookies: int) -> None:
        """A JSON body of the stated length and exactly `cookies` Set-Cookie headers; R5 and R6
        leave any other header (Cache-Control, say) open."""
        (content_type,) = header_values(response, "Content-Type")
        self.assertTrue(content_type.startswith("application/json"), content_type)
        self.assertEqual(header_values(response, "Content-Length"), [str(len(response.body))])
        self.assertEqual(len(set_cookies(response)), cookies, response.headers)

    def check_ref(self, body: dict, status: str, kind: str, received: str) -> None:
        """Fail unless body's ref object is exactly this one."""
        self.assertEqual(body.get("ref"), {"status": status, "store": kind,
                                           "reference_bytes": len(received)}, body)


class ReferenceEndpointTests(ApplicationCase):
    """R5: GET /api/token/reference."""

    def check_stored(self, store: RecordingStore, reference: str, algorithm: str, claims: str,
                     pad: int, ttl: int) -> str:
        """The single put of an issue: reference, a token that verifies, and its ttl."""
        puts = store.puts()
        self.assertEqual(len(puts), 1, puts)
        _, put_reference, token, put_ttl = puts[0]
        self.assertEqual(put_reference, reference)
        self.assertIs(type(put_ttl), int)
        self.assertEqual(put_ttl, ttl)
        expected_claims = padded_claims(claim_set(claims), pad)
        self.assertEqual(len(token), token_bytes(algorithm, expected_claims))
        verified = json_body(self.call(VERIFY_PATH, {"Authorization": f"Bearer {token}"}).body)
        self.assertIs(verified["verified"], True, verified)
        self.assertEqual(verified["algorithm"], algorithm)
        self.assertEqual(verified["claims"], expected_claims)
        return token

    def test_cookie_delivery_by_default(self):
        store = RecordingStore(memory_store())
        response, body = self.reference_call(store, alg="ES256")
        self.assertEqual(response.code, 200, body)
        self.assertJsonHeaders(response, cookies=1)
        (set_cookie,) = set_cookies(response)
        name, reference = cookie_value(set_cookie)
        self.assertEqual(name, REF_COOKIE_NAME)
        self.assertRegex(reference, rf"\A{REF_FORMAT.pattern}\Z")
        self.assertEqual(set_cookie, f"jwt_ref={reference}; {DEFAULT_ATTRIBUTES}")
        self.assertEqual(set(body), REF_COOKIE_KEYS)
        expected = {"layer": "application", "algorithm": "ES256", "delivery": "cookie",
                    "cookie_name": "jwt_ref", "reference_bytes": REF_BYTES,
                    "token_bytes": token_bytes("ES256", claim_set("minimal")),
                    "claims": "minimal", "pad": 0, "attrs": "default", "ttl": REF_DEFAULT_TTL,
                    "store": "memory", "experiment_key": True}
        self.assertEqual({key: value for key, value in body.items() if key != "set_cookie_bytes"},
                         expected)
        self.assertIs(type(body["set_cookie_bytes"]), int)
        self.assertIn(body["set_cookie_bytes"],
                      (len(set_cookie), len(f"Set-Cookie: {set_cookie}\r\n")))
        token = self.check_stored(store, reference, "ES256", "minimal", 0, REF_DEFAULT_TTL)
        self.assertNoSecret(response, token)
        self.assertNotIn(reference, response.body.decode("utf-8"))

    def test_cookie_delivery_with_sizing_and_full_attributes(self):
        for query in ({"alg": "ML-DSA-44", "claims": "oidc", "attrs": "full"},
                      {"alg": "SLH-DSA-SHA2-128f", "claims": "essential", "pad": "25",
                       "attrs": "full", "ttl": "60", "delivery": "cookie"},
                      {"alg": "RS256", "pad": "3", "attrs": "default", "ttl": "86400"}):
            with self.subTest(query=query):
                store = RecordingStore(memory_store())
                response, body = self.reference_call(store, **query)
                self.assertEqual(response.code, 200, body)
                (set_cookie,) = set_cookies(response)
                _, reference = cookie_value(set_cookie)
                attrs = query.get("attrs", "default")
                attributes = FULL_ATTRIBUTES if attrs == "full" else DEFAULT_ATTRIBUTES
                self.assertEqual(set_cookie, f"jwt_ref={reference}; {attributes}")
                claims, pad = query.get("claims", "minimal"), int(query.get("pad", "0"))
                ttl = int(query.get("ttl", REF_DEFAULT_TTL))
                self.assertEqual((body["algorithm"], body["claims"], body["pad"], body["attrs"],
                                  body["ttl"], body["store"]),
                                 (query["alg"], claims, pad, attrs, ttl, "memory"))
                self.assertEqual(body["token_bytes"],
                                 token_bytes(query["alg"], padded_claims(claim_set(claims), pad)))
                token = self.check_stored(store, reference, query["alg"], claims, pad, ttl)
                self.assertNoSecret(response, token)

    def test_body_delivery(self):
        for query in ({"alg": "ES256"}, {"alg": "ML-DSA-44", "claims": "oidc", "ttl": "1"},
                      {"alg": "EdDSA", "claims": "essential", "pad": "100", "attrs": "full"}):
            with self.subTest(query=query):
                store = RecordingStore(memory_store())
                response, body = self.reference_call(store, delivery="body", **query)
                self.assertEqual(response.code, 200, body)
                self.assertJsonHeaders(response, cookies=0)
                self.assertEqual(set(body), REF_BODY_KEYS)
                reference = body["reference"]
                self.assertRegex(reference, rf"\A{REF_FORMAT.pattern}\Z")
                claims, pad = query.get("claims", "minimal"), int(query.get("pad", "0"))
                ttl = int(query.get("ttl", REF_DEFAULT_TTL))
                self.assertEqual({key: value for key, value in body.items()
                                  if key != "reference"},
                                 {"layer": "application", "algorithm": query["alg"],
                                  "delivery": "body", "reference_bytes": REF_BYTES,
                                  "token_bytes": token_bytes(query["alg"],
                                                             padded_claims(claim_set(claims),
                                                                           pad)),
                                  "claims": claims, "pad": pad, "ttl": ttl, "store": "memory",
                                  "experiment_key": True})
                token = self.check_stored(store, reference, query["alg"], claims, pad, ttl)
                self.assertNoSecret(response, token)

    def test_every_issue_gets_a_new_reference(self):
        store = RecordingStore(memory_store())
        references = [self.new_reference(store, "EdDSA") for _ in range(5)]
        self.assertEqual(len(set(references)), 5)
        tokens = [call[2] for call in store.puts()]
        self.assertEqual(len(tokens), 5)
        for reference, token in zip(references, tokens):
            self.assertNotIn(reference, token)

    def test_ttl_is_stored(self):
        clock = FakeClock()
        store = RecordingStore(memory_store(clock))
        short = self.new_reference(store, ttl="2")
        default = self.new_reference(store)
        clock.advance(1.5)
        self.assertEqual(store.inner.get(short)[0], "found")
        clock.advance(0.5)
        self.assertEqual(store.inner.get(short)[0], "expired")
        clock.advance(REF_DEFAULT_TTL - 2.5)
        self.assertEqual(store.inner.get(default)[0], "found")
        clock.advance(1)
        self.assertEqual(store.inner.get(default)[0], "expired")

    def test_ttl_values(self):
        for value, ttl in (("1", 1), ("00001", 1), ("07200", 7200), ("86400", 86400),
                           ("3600", 3600)):
            with self.subTest(ttl=value):
                store = RecordingStore(memory_store())
                response, body = self.reference_call(store, alg="ES256", delivery="body",
                                                     ttl=value)
                self.assertEqual(response.code, 200, body)
                self.assertEqual(body["ttl"], ttl)
                self.assertEqual(store.puts()[0][3], ttl)

    def test_invalid_parameters_get_400(self):
        cases = [{}, {"alg": "HS256"}, {"alg": ""}, {"alg": "es256"},
                 {"alg": "ES256", "delivery": "split"}, {"alg": "ES256", "delivery": "bearer"},
                 {"alg": "ES256", "delivery": ""}, {"alg": "ES256", "delivery": "Cookie"},
                 {"alg": "ES256", "delivery": "body "}, {"alg": "ES256", "claims": "huge"},
                 {"alg": "ES256", "claims": ""}, {"alg": "ES256", "pad": "-1"},
                 {"alg": "ES256", "pad": "1000001"}, {"alg": "ES256", "pad": "abc"},
                 {"alg": "ES256", "attrs": "bogus"}]
        cases += [{"alg": "ES256", "ttl": value}
                  for value in ("0", "00000", "86401", "99999", "100000", "000001", "", "-1",
                                "+1", " 1", "1 ", "1.0", "1e3", "١", "abc", "0x10", "1_000",
                                "9" * 5000)]
        for delivery in ("cookie", "body"):
            for query in cases:
                query = {"delivery": delivery, **query}
                with self.subTest(query=query):
                    store = RecordingStore(memory_store())
                    response, body = self.reference_call(store, **query)
                    self.assertEqual(response.code, 400, body)
                    self.assertEqual(set(body), ISSUE_ERROR_KEYS)
                    self.assertEqual(body["layer"], "application")
                    self.assertEqual(body["algorithms"], NAMES)
                    self.assertIs(body["experiment_key"], True)
                    self.assertEqual(set_cookies(response), [])
                    self.assertEqual(store.calls, [])

    def test_other_parameters_are_ignored(self):
        for delivery in ("cookie", "body"):
            with self.subTest(delivery=delivery):
                plain, plain_body = self.reference_call(RecordingStore(memory_store()),
                                                        alg="EdDSA", delivery=delivery)
                extra, extra_body = self.reference_call(
                    RecordingStore(memory_store()), alg="EdDSA", delivery=delivery,
                    nonce=NONCE, chunks="3", timing="1", source="ref_bearer")
                self.assertEqual((plain.code, extra.code), (200, 200))
                self.assertEqual({key: value for key, value in plain_body.items()
                                  if key != "reference"},
                                 {key: value for key, value in extra_body.items()
                                  if key != "reference"})
                self.assertEqual(len(set_cookies(plain)), len(set_cookies(extra)))

    def test_store_kind_is_reported(self):
        store = RecordingStore(memory_store(), kind="remote")
        for delivery in ("cookie", "body"):
            with self.subTest(delivery=delivery):
                response, body = self.reference_call(store, alg="ES256", delivery=delivery)
                self.assertEqual(response.code, 200, body)
                self.assertEqual(body["store"], "remote")

    def test_failed_signing_gets_500_without_a_token(self):
        # A public key that does not match the private key makes the issued token fail its own
        # verification, so the application must answer 500, store nothing, and send no token.
        adapter = ADAPTERS["ES256"]
        private_key, _ = adapter.generate_keypair()
        _, other_public_key = adapter.generate_keypair()
        for delivery in ("cookie", "body"):
            with self.subTest(delivery=delivery):
                store = RecordingStore(memory_store())
                with mock.patch.dict(transport_app.EXPERIMENT_KEYS,
                                     {"ES256": (private_key, other_public_key)}):
                    response, body = self.reference_call(store, alg="ES256", claims="oidc",
                                                         delivery=delivery)
                self.assertEqual(response.code, 500, body)
                self.assertEqual(set_cookies(response), [])
                self.assertNotIn("token", body)
                self.assertNotIn("reference", body)
                self.assertEqual(store.puts(), [])
                self.assertIsNone(TOKEN_LIKE.search(response.body.decode("utf-8")))

    def test_unreachable_store_gets_503(self):
        stores = {"stand-in": UnavailableStore(),
                  "closed port": app_api("RemoteRefStore")(f"http://{HOST}:{closed_port()}")}
        for name, store in stores.items():
            for delivery in ("cookie", "body"):
                with self.subTest(store=name, delivery=delivery):
                    response, body = self.reference_call(store, alg="ES256", delivery=delivery,
                                                         claims="oidc")
                    self.assertEqual(response.code, 503, body)
                    self.assertEqual(set(body), STORE_ERROR_KEYS)
                    self.assertEqual(body["layer"], "application")
                    self.assertTrue(body["error"].startswith("reference store unavailable"),
                                    body["error"])
                    self.assertEqual(body["store"], "remote")
                    self.assertIs(body["experiment_key"], True)
                    self.assertEqual(set_cookies(response), [])
                    self.assertIsNone(TOKEN_LIKE.search(response.body.decode("utf-8")))


class VerifyReferenceTests(ApplicationCase):
    """R6: references in a jwt_ref cookie or a Bearer header, and every outcome of a lookup."""

    def setUp(self):
        self.clock = FakeClock()
        self.store = RecordingStore(memory_store(self.clock))

    def check_found(self, response: SimpleNamespace, body: dict, source: str, sent: str,
                    algorithm: str, token: str, claims: dict) -> None:
        """Fail unless a verify response is R6's 200 for a found reference."""
        self.assertEqual(response.code, 200, body)
        self.assertEqual(set(body), VERIFIED_KEYS | {"ref", "timing"})
        self.assertEqual((body["verified"], body["source"], body["algorithm"]),
                         (True, source, algorithm))
        self.assertEqual(body["token_bytes"], len(token))
        self.assertEqual(body["claims"], claims)
        self.check_ref(body, "found", "memory", sent)
        self.assertJsonHeaders(response, cookies=0)
        self.assertNoSecret(response, token, sent)

    def test_jwt_ref_cookie_and_bearer(self):
        for algorithm in ("ES256", "ML-DSA-44"):
            reference = self.new_reference(self.store, algorithm, claims="oidc")
            token = self.store.puts()[-1][2]
            for source, headers in (
                    ("ref_cookie", {"Cookie": f"jwt_ref={reference}"}),
                    ("ref_cookie", {"Cookie": f"a=1; jwt_ref={reference}; theme=dark"}),
                    ("ref_cookie", {"Cookie": f"  jwt_ref={reference}  ;jwt_old=x"}),
                    ("ref_cookie", {"Cookie": f"jwt_ref2=x; jwt_ref={reference}; jwtx=y"}),
                    ("ref_bearer", {"Authorization": f"Bearer {reference}"}),
                    ("ref_bearer", {"Authorization": f"bearer {reference}"}),
                    ("ref_bearer", {"Authorization": f"Bearer {reference}",
                                    "Cookie": "theme=dark; jwt_old=x"})):
                with self.subTest(algorithm=algorithm, headers=sorted(headers)):
                    gets = self.store.count("get")
                    response, body = self.verify(self.store, headers)
                    self.check_found(response, body, source, reference, algorithm, token,
                                     claim_set("oidc"))
                    self.assertEqual(self.store.count("get"), gets + 1)

    def test_found_tokens_are_verified_like_bearer_tokens(self):
        reference = self.new_reference(self.store, "ML-DSA-44", claims="essential", pad="7")
        token = self.store.puts()[-1][2]
        _, by_reference = self.verify(self.store, {"Authorization": f"Bearer {reference}"})
        _, by_token = self.verify(self.store, {"Authorization": f"Bearer {token}"})
        self.assertEqual(by_token["source"], "bearer")
        for key in set(by_token) - {"source", "received", "timing"}:
            self.assertEqual(by_reference[key], by_token[key], key)

    def test_stored_tokens_are_verified_again(self):
        # The store is not trusted: a stored token that fails verification gets 401.
        token = self.body_token("ES256", claims="oidc")
        cases = {"tampered": (tampered(token), True), "foreign alg": (foreign_alg_token(), False),
                 "not a token": ("not-a-token", False)}
        for name, (stored, verify_called) in cases.items():
            with self.subTest(stored=name):
                reference = app_api("new_reference")()
                self.store.inner.put(reference, stored, 60)
                response, body = self.verify(self.store, {"Cookie": f"jwt_ref={reference}"})
                self.assertEqual(response.code, 401, body)
                self.assertEqual(set(body), FAILED_KEYS | {"ref", "timing"})
                self.assertEqual(body["source"], "ref_cookie")
                self.check_ref(body, "found", "memory", reference)
                self.assertIs(body["timing"]["verify_ns"] is not None, verify_called)
                self.assertNoSecret(response, stored if len(stored) > 12 else "\0", reference)

    def test_malformed_jwt_ref_values_get_401_without_a_lookup(self):
        good = self.new_reference(self.store)
        token = self.body_token("ES256")
        for value in ("not-a-reference", "", "ref_", good[:-1], good + "A", good[:-1] + ".",
                      "REF_" + good[4:], token, f"{good}=", "x" * 5000, good + good):
            with self.subTest(value=value[:60]):
                gets = self.store.count("get")
                response, body = self.verify(self.store, {"Cookie": f"jwt_ref={value}"})
                self.assertEqual(response.code, 401, body)
                self.assertEqual(set(body), FAILED_KEYS | {"ref", "timing"})
                self.assertEqual((body["verified"], body["source"]), (False, "ref_cookie"))
                self.check_ref(body, "malformed", "memory", value)
                self.assertEqual(self.store.count("get"), gets)
                self.assertEqual(body["timing"],
                                 {**body["timing"], "verify_ns": None, "lookup_ns": None})
                if len(value) >= 12:
                    self.assertNoSecret(response, value)

    def test_unknown_expired_and_revoked_get_401(self):
        expired = self.new_reference(self.store, ttl="5")
        revoked = self.new_reference(self.store)
        self.assertEqual(self.store.inner.revoke(revoked), "found")
        self.clock.advance(5)
        for status, reference in (("unknown", app_api("new_reference")()),
                                  ("expired", expired), ("revoked", revoked)):
            for headers in ({"Authorization": f"Bearer {reference}"},
                            {"Cookie": f"jwt_ref={reference}"}):
                with self.subTest(status=status, headers=sorted(headers)):
                    gets = self.store.count("get")
                    response, body = self.verify(self.store, headers)
                    self.assertEqual(response.code, 401, body)
                    self.assertEqual(set(body), FAILED_KEYS | {"ref", "timing"})
                    source = "ref_bearer" if "Authorization" in headers else "ref_cookie"
                    self.assertEqual((body["verified"], body["source"]), (False, source))
                    self.assertIn(status, body["error"])
                    self.check_ref(body, status, "memory", reference)
                    self.assertEqual(self.store.count("get"), gets + 1)
                    self.assertIsNone(body["timing"]["verify_ns"])
                    self.assertIs(type(body["timing"]["lookup_ns"]), int)
                    self.assertNoSecret(response, reference)

    def test_unreachable_store_gets_503(self):
        reference = app_api("new_reference")()
        stores = {"stand-in": UnavailableStore(),
                  "closed port": app_api("RemoteRefStore")(f"http://{HOST}:{closed_port()}")}
        for name, store in stores.items():
            for headers in ({"Authorization": f"Bearer {reference}"},
                            {"Cookie": f"jwt_ref={reference}"}):
                with self.subTest(store=name, headers=sorted(headers)):
                    response, body = self.verify(store, headers)
                    self.assertEqual(response.code, 503, body)
                    self.assertEqual(set(body), FAILED_KEYS | {"ref", "timing"})
                    self.assertIs(body["verified"], False)
                    self.assertTrue(body["error"].startswith("reference store unavailable"),
                                    body["error"])
                    self.check_ref(body, "unavailable", "remote", reference)
                    self.assertIsNone(body["timing"]["verify_ns"])
                    self.assertIs(type(body["timing"]["lookup_ns"]), int)
                    self.assertNoSecret(response, reference)

    def test_a_reference_with_another_token_gets_400(self):
        reference = self.new_reference(self.store)
        other = self.new_reference(self.store)
        token = self.body_token("ES256")
        requests = {
            "two jwt_ref": {"Cookie": f"jwt_ref={reference}; jwt_ref={reference}"},
            "two different jwt_ref": {"Cookie": f"jwt_ref={reference}; jwt_ref={other}"},
            "malformed and good jwt_ref": {"Cookie": f"jwt_ref=bad; jwt_ref={reference}"},
            "jwt_ref and jwt": {"Cookie": f"jwt_ref={reference}; jwt={token}"},
            "malformed jwt_ref and jwt": {"Cookie": f"jwt_ref=bad; jwt={token}"},
            "jwt_ref and chunk": {"Cookie": f"jwt.0.1={token}; jwt_ref={reference}"},
            "jwt_ref and bearer jwt": {"Cookie": f"jwt_ref={reference}",
                                       "Authorization": f"Bearer {token}"},
            "jwt_ref and bearer reference": {"Cookie": f"jwt_ref={reference}",
                                             "Authorization": f"Bearer {other}"},
            "bearer reference and jwt": {"Cookie": f"jwt={token}",
                                         "Authorization": f"Bearer {reference}"},
            "bearer reference and chunks": {"Cookie": f"jwt.0.2={token[:500]}; "
                                                      f"jwt.1.2={token[500:]}",
                                            "Authorization": f"Bearer {reference}"},
        }
        for name, headers in requests.items():
            for query in ("", "?timing=1"):
                with self.subTest(request=name, query=query):
                    gets = self.store.count("get")
                    response, body = self.verify(self.store, headers, query)
                    self.assertEqual(response.code, 400, body)
                    self.assertTrue(body["error"].startswith("more than one token"), body)
                    self.assertIsNone(body["source"])
                    self.assertEqual(set(body), FAILED_KEYS | ({"timing"} if query else set()))
                    if query:
                        self.assertEqual(body["timing"]["verify_ns"], None)
                        self.assertEqual(set(body["timing"]), PLAIN_TIMING_KEYS)
                    self.assertEqual(self.store.count("get"), gets)
                    self.assertNoSecret(response, reference, other)

    def test_a_reference_as_a_jwt_cookie_is_a_jwt(self):
        reference = self.new_reference(self.store)
        response, body = self.verify(self.store, {"Cookie": f"jwt={reference}"})
        self.assertEqual(response.code, 401, body)
        self.assertEqual(body["source"], "cookie")
        self.assertNotIn("ref", body)
        self.assertEqual(set(body["timing"]), PLAIN_TIMING_KEYS)
        self.assertIsNone(body["timing"]["verify_ns"])
        self.assertEqual(self.store.count("get"), 0)

    def test_other_bearer_values_are_jwts(self):
        reference = random_reference(50)
        for value in (reference[:-1], reference + "A", reference[:-1] + ".", "REF_" + reference[4:],
                      "ref_" + "A" * 42 + "=", "not-a-token"):
            with self.subTest(value=value):
                response, body = self.verify(self.store, {"Authorization": f"Bearer {value}"})
                self.assertEqual(response.code, 401, body)
                self.assertEqual(body["source"], "bearer")
                self.assertNotIn("ref", body)
                self.assertEqual(self.store.count("get"), 0)

    def test_responses_without_timing(self):
        reference = self.new_reference(self.store)
        for headers, code in (({"Cookie": f"jwt_ref={reference}"}, 200),
                              ({"Authorization": f"Bearer {app_api('new_reference')()}"}, 401),
                              ({"Cookie": "jwt_ref=bad"}, 401)):
            with self.subTest(headers=sorted(headers)):
                plain, plain_body = self.verify(self.store, headers, "")
                other, other_body = self.verify(self.store, headers, "?timing=0")
                self.assertEqual((plain.code, other.code), (code, code))
                self.assertNotIn("timing", plain_body)
                self.assertEqual(plain_body, other_body)
                base = VERIFIED_KEYS if code == 200 else FAILED_KEYS
                self.assertEqual(set(plain_body), base | {"ref"})

    def test_malformed_input_never_gets_500(self):
        generator = random.Random(503)
        alphabet = REF_ALPHABET + ".=;, \x7fÿ%"
        values = ["ref_" + "".join(generator.choice(alphabet) for _ in range(generator.randint(
            0, 60))) for _ in range(300)]
        values += ["", "=", "ref_" + "A" * 43 + ";", "\x00" * 47]
        for value in values:
            for headers in ({"Cookie": f"jwt_ref={value}"},
                            {"Authorization": f"Bearer {value}"}):
                with self.subTest(headers=repr(headers)[:80]):
                    response, body = self.verify(self.store, headers)
                    self.assertIn(response.code, (400, 401), body)
                    self.assertEqual(body["layer"], "application")


class TimingTests(ApplicationCase):
    """R8: lookup_ns next to verify_ns and handler_ns."""

    def setUp(self):
        self.store = RecordingStore(memory_store())

    def check_invariant(self, timing: dict) -> None:
        """Fail unless timing has R8's keys and its invariant holds."""
        self.assertEqual(set(timing), REF_TIMING_KEYS)
        self.assertIs(type(timing["handler_ns"]), int)
        for key in ("lookup_ns", "verify_ns"):
            self.assertTrue(timing[key] is None or type(timing[key]) is int, timing)
        total = (timing["lookup_ns"] or 0) + (timing["verify_ns"] or 0)
        self.assertLessEqual(0, total)
        self.assertLessEqual(total, timing["handler_ns"])

    def test_keys_and_invariant_for_every_reference_outcome(self):
        found = self.new_reference(self.store)
        revoked = self.new_reference(self.store)
        self.store.inner.revoke(revoked)
        cases = [(self.store, {"Cookie": f"jwt_ref={found}"}, 200, True, True),
                 (self.store, {"Authorization": f"Bearer {found}"}, 200, True, True),
                 (self.store, {"Authorization": f"Bearer {revoked}"}, 401, True, False),
                 (self.store, {"Cookie": f"jwt_ref={app_api('new_reference')()}"}, 401, True,
                  False),
                 (self.store, {"Cookie": "jwt_ref=not-a-reference"}, 401, False, False),
                 (UnavailableStore(), {"Authorization": f"Bearer {found}"}, 503, True, False)]
        for store, headers, code, looked_up, verified in cases:
            with self.subTest(headers=sorted(headers), code=code):
                response, body = self.verify(store, headers)
                self.assertEqual(response.code, code, body)
                timing = body["timing"]
                self.check_invariant(timing)
                self.assertIs(timing["lookup_ns"] is not None, looked_up)
                self.assertIs(timing["verify_ns"] is not None, verified)

    def test_lookup_ns_times_only_the_store_lookup(self):
        counter = StepCounter()
        found = self.new_reference(self.store)
        revoked = self.new_reference(self.store)
        self.store.inner.revoke(revoked)
        jumping = RecordingStore(self.store.inner, before_get=lambda: counter.jump(LOOKUP_JUMP))
        failing = UnavailableStore(before_raise=lambda: counter.jump(LOOKUP_JUMP))
        for store, headers, verified in ((jumping, {"Authorization": f"Bearer {found}"}, True),
                                         (jumping, {"Cookie": f"jwt_ref={revoked}"}, False),
                                         (failing, {"Cookie": f"jwt_ref={found}"}, False)):
            with self.subTest(headers=sorted(headers), store=store.kind):
                with mock.patch("time.perf_counter_ns", counter):
                    _, body = self.verify(store, headers)
                timing = body["timing"]
                self.check_invariant(timing)
                self.assertGreaterEqual(timing["lookup_ns"], LOOKUP_JUMP)
                if verified:
                    self.assertLess(timing["verify_ns"], LOOKUP_JUMP)
                else:
                    self.assertIsNone(timing["verify_ns"])
                self.assertGreaterEqual(timing["handler_ns"], LOOKUP_JUMP)

    def test_other_sources_keep_two_timing_keys(self):
        token = self.body_token("ES256")
        reference = self.new_reference(self.store)
        for headers in ({"Authorization": f"Bearer {token}"}, {"Cookie": f"jwt={token}"},
                        {"Cookie": f"jwt.0.1={token}"}, {}, {"Cookie": "jwt=a; jwt=b"},
                        {"Cookie": f"jwt_ref={reference}; jwt={token}"},
                        {"Cookie": f"jwt={reference}"}):
            with self.subTest(headers=sorted(headers)):
                _, body = self.verify(self.store, headers)
                self.assertEqual(set(body["timing"]), PLAIN_TIMING_KEYS)


class RevokeTests(ApplicationCase):
    """R7: POST /api/token/revoke."""

    def setUp(self):
        self.clock = FakeClock()
        self.store = RecordingStore(memory_store(self.clock))

    def check_revoked(self, response: SimpleNamespace, status: str, sent: str) -> None:
        """Fail unless a revoke response is R7's 200 body."""
        body = json_body(response.body)
        self.assertEqual(response.code, 200, body)
        self.assertEqual(set(body), REVOKED_KEYS)
        self.assertEqual(body, {"layer": "application", "revoked": True,
                                "ref": {"status": status, "store": "memory",
                                        "reference_bytes": len(sent)},
                                "experiment_key": True})
        self.assertNoSecret(response, sent)

    def test_revoke_by_bearer_and_by_cookie(self):
        for headers_of in (lambda ref: {"Authorization": f"Bearer {ref}"},
                           lambda ref: {"Cookie": f"theme=dark; jwt_ref={ref}"}):
            reference = self.new_reference(self.store)
            headers = headers_of(reference)
            with self.subTest(headers=sorted(headers)):
                response = self.revoke(self.store, headers)
                self.check_revoked(response, "found", reference)
                _, body = self.verify(self.store, {"Authorization": f"Bearer {reference}"})
                self.assertEqual(body["ref"]["status"], "revoked")
                self.check_revoked(self.revoke(self.store, headers), "revoked", reference)

    def test_revoke_an_expired_reference(self):
        reference = self.new_reference(self.store, ttl="1")
        self.clock.advance(1)
        self.check_revoked(self.revoke(self.store, {"Authorization": f"Bearer {reference}"}),
                           "expired", reference)
        self.assertEqual(self.store.inner.get(reference)[0], "revoked")

    def test_unknown_reference_gets_401(self):
        reference = app_api("new_reference")()
        response = self.revoke(self.store, {"Authorization": f"Bearer {reference}"})
        body = json_body(response.body)
        self.assertEqual(response.code, 401, body)
        self.assertEqual(body["ref"]["status"], "unknown")
        self.assertEqual(self.store.inner.get(reference)[0], "unknown")
        self.assertNoSecret(response, reference)

    def test_no_token_gets_401(self):
        for headers in ({}, {"Cookie": "theme=dark; jwt_old=x"}, {"Authorization": "Basic eA=="}):
            with self.subTest(headers=sorted(headers)):
                response = self.revoke(self.store, headers)
                self.assertEqual(response.code, 401, response.body)
                self.assertEqual(self.store.count("revoke"), 0)

    def test_more_than_one_token_gets_400(self):
        reference, other = self.new_reference(self.store), self.new_reference(self.store)
        token = self.body_token("ES256")
        for headers in ({"Cookie": f"jwt_ref={reference}; jwt_ref={other}"},
                        {"Cookie": f"jwt_ref={reference}", "Authorization": f"Bearer {other}"},
                        {"Cookie": f"jwt_ref={reference}; jwt={token}"},
                        {"Cookie": f"jwt={token}", "Authorization": f"Bearer {reference}"},
                        {"Cookie": f"jwt.0.1={token}", "Authorization": f"Bearer {reference}"}):
            with self.subTest(headers=sorted(headers)):
                response = self.revoke(self.store, headers)
                body = json_body(response.body)
                self.assertEqual(response.code, 400, body)
                self.assertTrue(body["error"].startswith("more than one token"), body)
                self.assertEqual(self.store.count("revoke"), 0)
                self.assertNoSecret(response, reference, other)
        self.assertEqual(self.store.inner.get(reference)[0], "found")

    def test_one_jwt_gets_400(self):
        token = self.body_token("ES256")
        reference = self.new_reference(self.store)
        for headers in ({"Cookie": f"jwt={token}"}, {"Authorization": f"Bearer {token}"},
                        {"Cookie": f"jwt.0.2={token[:400]}; jwt.1.2={token[400:]}"},
                        {"Cookie": f"jwt={reference}"}):
            with self.subTest(headers=sorted(headers)):
                response = self.revoke(self.store, headers)
                self.assertEqual(response.code, 400, response.body)
                self.assertEqual(self.store.count("revoke"), 0)
        self.assertEqual(self.store.inner.get(reference)[0], "found")

    def test_malformed_reference_gets_401(self):
        for value in ("not-a-reference", "", random_reference(60)[:-1]):
            with self.subTest(value=value):
                response = self.revoke(self.store, {"Cookie": f"jwt_ref={value}"})
                self.assertEqual(response.code, 401, response.body)
                self.assertEqual(self.store.count("revoke"), 0)

    def test_unreachable_store_gets_503(self):
        reference = app_api("new_reference")()
        for store in (UnavailableStore(),
                      app_api("RemoteRefStore")(f"http://{HOST}:{closed_port()}")):
            with self.subTest(store=type(store).__name__):
                response = self.revoke(store, {"Authorization": f"Bearer {reference}"})
                self.assertEqual(response.code, 503, response.body)
                self.assertNoSecret(response, reference)

    def test_other_methods_get_405_and_revoke_nothing(self):
        reference = self.new_reference(self.store)
        for method in ("GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            for headers in ({"Authorization": f"Bearer {reference}"},
                            {"Cookie": f"jwt_ref={reference}"}, {}):
                with self.subTest(method=method, headers=sorted(headers)):
                    response = self.revoke(self.store, headers, method)
                    self.assertEqual(response.code, 405, response.body)
                    self.assertEqual(header_values(response, "Allow"), ["POST"])
                    self.assertEqual(self.store.count("revoke"), 0)
                    self.assertNotIn(reference, response.body.decode("utf-8", "replace"))
        self.assertEqual(self.store.inner.get(reference)[0], "found")


class HandlingCasesInProcessTests(ApplicationCase):
    """R15's cases against the application in process, with a store the test controls."""

    def test_the_cases(self):
        clock = FakeClock()
        store = RecordingStore(memory_store(clock))
        a = self.new_reference(store, "ML-DSA-44", claims="oidc")
        b = self.new_reference(store, "ML-DSA-44", claims="oidc", ttl="1")
        c = self.new_reference(store, "ML-DSA-44", claims="oidc")
        j = self.body_token("ML-DSA-44", claims="oidc")
        clock.advance(2)  # B has expired; A and C have not.
        revoked = self.revoke(store, {"Authorization": f"Bearer {c}"})
        self.assertEqual(revoked.code, 200, revoked.body)
        running = {
            "cookie": {"Cookie": f"jwt_ref={a}"},
            "bearer": {"Authorization": f"Bearer {a}"},
            "among_other_cookies": {"Cookie": f"a=1; jwt_ref={a}; theme=dark"},
            "unknown": {"Authorization": f"Bearer {app_api('new_reference')()}"},
            "malformed_cookie": {"Cookie": "jwt_ref=not-a-reference"},
            "expired": {"Authorization": f"Bearer {b}"},
            "revoked": {"Authorization": f"Bearer {c}"},
            "two_references": {"Cookie": f"jwt_ref={a}; jwt_ref={a}"},
            "reference_and_jwt": {"Cookie": f"jwt_ref={a}", "Authorization": f"Bearer {j}"},
            "reference_as_jwt": {"Cookie": f"jwt={a}"},
        }
        observed = {}
        for name, headers in running.items():
            observed[name] = self.verify(store, headers)
        stopped = UnavailableStore()
        observed["store_unavailable"] = self.verify(stopped, {"Authorization": f"Bearer {a}"})
        observed["jwt_without_store"] = self.verify(stopped, {"Authorization": f"Bearer {j}"})
        observed["issue_without_store"] = self.reference_call(stopped, alg="ML-DSA-44",
                                                              delivery="cookie", claims="oidc")
        self.assertEqual(set_cookies(observed["issue_without_store"][0]), [])
        for name, status, source, ref_status, lookup, verify in HANDLING_CASES:
            response, body = observed[name]
            with self.subTest(case=name):
                self.assertEqual(response.code, status, body)
                self.assertEqual(body.get("source"), source)
                self.assertEqual((body.get("ref") or {}).get("status"), ref_status)
                timing = body.get("timing") or {}
                self.assertIs(timing.get("lookup_ns") is not None, lookup)
                self.assertIs(timing.get("verify_ns") is not None, verify)
                self.assertNoSecret(response, a, b, c, j)


class LogTests(ApplicationCase):
    """R9: the ref= and store= fields of app.log, and no reference or token in any line."""

    def setUp(self):
        self.clock = FakeClock()
        self.store = RecordingStore(memory_store(self.clock))

    def assertClean(self, line: str, *secrets: str) -> None:
        """Fail if a log line holds a secret or anything token-like."""
        for secret in secrets:
            self.assertNotIn(secret, line)
        self.assertIsNone(TOKEN_LIKE.search(line), line)
        self.assertNotIn("eyJ", line)

    def test_reference_lines(self):
        cases = [(self.store, {"alg": "ES256", "delivery": "body"}, ["alg=ES256",
                  f"token_bytes={token_bytes('ES256', claim_set('minimal'))}", "ref=issued",
                  "store=memory"]),
                 (self.store, {"alg": "ML-DSA-44", "claims": "oidc"},
                  ["alg=ML-DSA-44", "token_bytes=4095", "ref=issued", "store=memory"]),
                 (UnavailableStore(), {"alg": "ES256", "delivery": "body"},
                  [None, None, "ref=unavailable", "store=remote"])]
        for store, query, expected in cases:
            with self.subTest(query=query, store=store.kind):
                response, body = self.reference_call(store, **query)
                self.assertEqual(len(response.log), 1, response.log)
                target, fields = log_fields(response.log[0])
                self.assertTrue(target.startswith(REFERENCE_PATH))
                self.assertGreaterEqual(len(fields), 4)
                for field, wanted in zip(fields[-4:], expected):
                    if wanted is not None:
                        self.assertEqual(field, wanted)
                self.assertTrue(fields[-4].startswith("alg="))
                self.assertTrue(fields[-3].startswith("token_bytes="))
                puts = store.puts() if isinstance(store, RecordingStore) else []
                secrets = [call[2] for call in puts]
                self.assertClean(response.log[0], *secrets, body.get("reference") or "\0")

    def test_reference_error_lines(self):
        for query, unsigned in (({"alg": "HS256"}, True), ({}, True),
                                ({"alg": "ES256", "ttl": "0"}, False)):
            with self.subTest(query=query):
                response, _ = self.reference_call(self.store, **query)
                self.assertEqual(response.code, 400)
                self.assertEqual(len(response.log), 1)
                _, fields = log_fields(response.log[0])
                self.assertEqual(fields[-2:], ["ref=-", "store=memory"])
                self.assertTrue(fields[-3].startswith("token_bytes="))
                if unsigned:
                    self.assertEqual(fields[-4:-2], ["alg=-", "token_bytes=-"])
                self.assertTrue(fields[-4].startswith("alg="))

    def test_verify_lines_end_with_ref_and_store(self):
        found = self.new_reference(self.store)
        revoked = self.new_reference(self.store)
        self.store.inner.revoke(revoked)
        cases = [(self.store, {"Cookie": f"jwt_ref={found}"}, "found", "memory", "true"),
                 (self.store, {"Authorization": f"Bearer {found}"}, "found", "memory", "true"),
                 (self.store, {"Authorization": f"Bearer {revoked}"}, "revoked", "memory",
                  "false"),
                 (self.store, {"Cookie": "jwt_ref=bad"}, "malformed", "memory", "false"),
                 (self.store, {"Authorization": f"Bearer {app_api('new_reference')()}"},
                  "unknown", "memory", "false"),
                 (UnavailableStore(), {"Cookie": f"jwt_ref={found}"}, "unavailable", "remote",
                  "false")]
        token = self.store.puts()[0][2]
        for store, headers, status, kind, verified in cases:
            with self.subTest(status=status, headers=sorted(headers)):
                with patched_store(store):
                    response = self.call(f"{VERIFY_PATH}?nonce={NONCE}", headers)
                self.assertEqual(len(response.log), 1)
                _, fields = log_fields(response.log[0])
                self.assertEqual(fields[-2:], [f"ref={status}", f"store={kind}"])
                self.assertEqual(fields[-3], f"verified={verified}")
                self.assertClean(response.log[0], found, revoked, token)

    def test_verify_lines_for_other_sources_keep_their_fields(self):
        base = self.require_base()
        token = self.body_token("ES256")
        reference = self.new_reference(self.store)
        reference_line = wsgi_call(base.application, VERIFY_PATH, {"Cookie": "jwt=a; jwt=b"})
        _, reference_fields = log_fields(reference_line.log[0])
        for headers in ({"Cookie": f"jwt_ref={reference}; jwt={token}"},
                        {"Cookie": f"jwt_ref={reference}", "Authorization": f"Bearer {token}"},
                        {"Cookie": f"jwt_ref={reference}; jwt_ref={reference}"}):
            with self.subTest(headers=sorted(headers)):
                with patched_store(self.store):
                    response = self.call(VERIFY_PATH, headers)
                _, fields = log_fields(response.log[0])
                self.assertEqual([field.split("=")[0] for field in fields][
                    :len(reference_fields)], [field.split("=")[0] for field in reference_fields])
                self.assertClean(response.log[0], reference, token)

    def test_revoke_lines_end_with_ref_and_store(self):
        found = self.new_reference(self.store)
        expired = self.new_reference(self.store, ttl="1")
        self.clock.advance(1)
        cases = [({"Authorization": f"Bearer {found}"}, "POST", "found"),
                 ({"Authorization": f"Bearer {found}"}, "POST", "revoked"),
                 ({"Cookie": f"jwt_ref={expired}"}, "POST", "expired"),
                 ({"Authorization": f"Bearer {app_api('new_reference')()}"}, "POST", "unknown"),
                 ({}, "POST", "-"), ({"Cookie": f"jwt_ref={found}; jwt_ref={found}"}, "POST",
                                     "-"),
                 ({"Authorization": f"Bearer {found}"}, "GET", "-")]
        for headers, method, status in cases:
            with self.subTest(method=method, status=status, headers=sorted(headers)):
                response = self.revoke(self.store, headers, method)
                self.assertEqual(len(response.log), 1)
                _, fields = log_fields(response.log[0])
                self.assertEqual(fields[-2:], [f"ref={status}", "store=memory"])
                self.assertClean(response.log[0], found, expired)


# ---- R10: unchanged application behavior ----------------------------------------------------

class UnchangedApplicationTests(ApplicationCase):
    def test_requests_without_a_reference_are_unchanged(self):
        base = self.require_base()
        es256, eddsa = self.body_token("ES256"), self.body_token("EdDSA")
        reference = random_reference(70)
        cookie_values = [
            f"jwt={es256}", f"jwt={eddsa}; jwt={es256}", "jwt_ref2=x", f"JWT_REF={reference}",
            f"xjwt_ref={reference}", f"jwt_refx={reference}; jwt={eddsa}", "jwt_ref",
            f"jwt_ref ={reference}", f"Jwt_ref={reference}; jwt={es256}", "theme=dark", "jwt=",
            f"jwt.0.1={es256}", f"jwt={reference}", "jwt.0.2=a; jwt.1.2=b",
        ]
        requests = [(VERIFY_PATH, {"Cookie": value}, "GET") for value in cookie_values]
        requests += [
            (VERIFY_PATH, {}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Bearer {es256}"}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Bearer {reference[:-1]}"}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Bearer {reference}A"}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Bearer REF_{reference[4:]}"}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Basic {reference}"}, "GET"),
            (VERIFY_PATH, {"Authorization": f"Bearer {es256}", "Cookie": f"jwt={eddsa}"}, "GET"),
            (f"{VERIFY_PATH}?timing=0&nonce={NONCE}", {"Authorization": f"Bearer {eddsa}"},
             "GET"),
            (VERIFY_PATH, {"Cookie": f"jwt={es256}"}, "POST"),
            ("/api/echo?x=y", {"Cookie": f"jwt_ref={reference}", "X-Test": "1"}, "GET"),
            ("/api/echo", {"Authorization": f"Bearer {reference}"}, "POST"),
            ("/", {}, "GET"), ("/missing", {"Cookie": f"jwt_ref={reference}"}, "GET"),
            ("/missing", {}, "POST"),
        ]
        requests += [(path, {}, method)
                     for path in ("/api/token", "/api/tokens", "/api/token/issue/extra",
                                  "/api/token/verify/extra", "/api/token/reference/extra",
                                  "/api/token/revoke/extra", "/api/token/references")
                     for method in ("GET", "POST")]
        for target, headers, method in requests:
            with self.subTest(target=target, method=method, headers=sorted(headers)):
                store = RecordingStore(memory_store())
                with patched_store(store):
                    new = self.call(target, headers, method)
                old = wsgi_call(base.application, target, headers, method)
                self.assertEqual((new.status, new.headers, new.body),
                                 (old.status, old.headers, old.body))
                self.assertEqual(new.log, old.log)
                self.assertEqual(store.calls, [])

    def test_404_paths(self):
        for path in ("/api/token", "/api/tokens", "/api/token/issue/extra",
                     "/api/token/verify/extra", "/api/token/reference/extra",
                     "/api/token/revoke/extra"):
            with self.subTest(path=path):
                response = self.call(path)
                self.assertEqual(response.code, 404)
                self.assertEqual(json_body(response.body),
                                 {"layer": "application", "error": "not found", "path": path})

    def test_timed_requests_without_a_reference_are_unchanged(self):
        base = self.require_base()
        es256 = self.body_token("ES256")
        for headers in ({"Authorization": f"Bearer {es256}"}, {"Cookie": f"jwt={es256}"},
                        {"Cookie": "jwt=a; jwt=b"}, {}):
            with self.subTest(headers=sorted(headers)):
                new = self.call(f"{VERIFY_PATH}?timing=1", headers)
                old = wsgi_call(base.application, f"{VERIFY_PATH}?timing=1", headers)
                self.assertEqual(new.status, old.status)
                new_body, old_body = json_body(new.body), json_body(old.body)
                self.assertEqual(set(new_body["timing"]), set(old_body["timing"]))
                self.assertEqual({key: value for key, value in new_body.items()
                                  if key != "timing"},
                                 {key: value for key, value in old_body.items()
                                  if key != "timing"})
                self.assertEqual(new.log, old.log)

    def test_issue_responses_unchanged(self):
        base = self.require_base()
        queries = ["", "&delivery=body", "&delivery=cookie", "&claims=oidc&attrs=full",
                   "&delivery=split&claims=oidc", "&delivery=reference", "&delivery=ref",
                   "&delivery=bearer", "&ttl=60&delivery=body"]
        for name in ("ES256", "ML-DSA-44"):
            for query in queries:
                target = f"{ISSUE_PATH}?alg={name}{query}&nonce=abc"
                with self.subTest(target=target):
                    new = self.call(target)
                    old = wsgi_call(base.application, target)
                    self.assertEqual(new.code, old.code)
                    if "split" in query:
                        self.assertEqual(len(set_cookies(new)), len(set_cookies(old)))
                        self.assertEqual(new.log, old.log)
                    else:
                        self.assertEqual(normalized(new), normalized(old))

    def test_deliveries_and_no_token_message(self):
        self.assertEqual(tuple(app_api("DELIVERIES")), ("cookie", "body", "split"))
        response = self.call(VERIFY_PATH)
        self.assertEqual(json_body(response.body)["error"],
                         "no token: send a jwt cookie or an Authorization: Bearer header")

    def test_single_waitress_serve_call(self):
        tree = ast.parse((REPO / "scripts" / "transport_app.py").read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Attribute) and node.func.attr == "serve")
                      or (isinstance(node.func, ast.Name) and node.func.id == "serve"))]
        self.assertEqual(len(calls), 1, [ast.unparse(call) for call in calls])
        call = calls[0]
        self.assertEqual(ast.unparse(call.func), "waitress.serve")
        self.assertLessEqual(len(call.args), 1)
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        self.assertNotIn(None, keywords, "no **keywords")
        self.assertIn(ast.unparse(keywords.get("host", ast.Constant(None))),
                      ("HOST", "'127.0.0.1'"))
        self.assertEqual(ast.unparse(keywords.get("clear_untrusted_proxy_headers",
                                                  ast.Constant(None))), "False")
        self.assertFalse([name for name in keywords if "size" in name], keywords)

    def test_docstring(self):
        lowered = (transport_app.__doc__ or "").lower()
        for term in ("split", "reassembl", "ephemeral", "experiment", "production", "reference",
                     "store", "memory", "process"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)


# ---- R11: the load workload's reference carrier ----------------------------------------------

class ReferenceCarrierTests(unittest.TestCase):
    def test_carrier(self):
        carrier = ref_carrier()
        self.assertIsInstance(carrier, transport_load.Carrier)
        self.assertEqual(carrier.name, "ref_bearer")
        self.assertEqual(carrier.header_name, "Authorization")
        for seed in range(5):
            reference = random_reference(seed)
            with self.subTest(reference=reference):
                expected = {"Authorization": f"Bearer {reference}"}
                self.assertEqual(carrier.direct_headers(reference), expected)
                self.assertEqual(carrier.browser_headers(reference), expected)

    def test_header_line_bytes(self):
        carrier = ref_carrier()
        self.assertEqual(len("Authorization: Bearer \r\n") + REF_BYTES, 71)
        for size in (0, 1, 47, 208, 948, 4095, 23662, 300000):
            with self.subTest(token_bytes=size):
                self.assertEqual(carrier.header_line_bytes(size), 71)
        line = f"Authorization: {carrier.direct_headers(random_reference(9))['Authorization']}\r\n"
        self.assertEqual(len(line), 71)

    def test_carriers_unchanged(self):
        self.assertNotIn("ref_bearer", transport_load.CARRIERS)
        self.assertEqual(list(transport_load.CARRIERS), ["bearer", "cookie", "split"])
        self.assertNotIn(ref_carrier(), transport_load.CARRIERS.values())
        bearer, cookie = transport_load.CARRIERS["bearer"], transport_load.CARRIERS["cookie"]
        self.assertEqual((bearer.name, bearer.issue_delivery), ("bearer", "body"))
        self.assertEqual((cookie.name, cookie.issue_delivery), ("cookie", "cookie"))
        self.assertEqual(bearer.direct_headers("t.o.k"), {"Authorization": "Bearer t.o.k"})
        self.assertEqual(bearer.header_line_bytes(100), len("Authorization: Bearer \r\n") + 100)

    def test_load_interfaces_unchanged(self):
        self.assertEqual(transport_load.default_settings(), LOAD_DEFAULTS)
        self.assertEqual(list(inspect.signature(transport_load.run_load).parameters),
                         ["stack", *LOAD_DEFAULTS])
        self.assertEqual(list(inspect.signature(transport_load.checked_settings).parameters),
                         ["algorithms", "transport", "clients", "concurrency", "duration",
                          "warmup", "claims", "reference", "size_controls", "timeout",
                          "proxy_buffers", "header_buffers", "upstream_keepalive"])
        self.assertEqual(tuple(transport_load.LATENCY_COMPONENTS), LATENCY_COMPONENTS)
        self.assertEqual(tuple(transport_load.RAW_FIELDS), RAW_FIELDS)
        self.assertEqual(tuple(transport_load.NETWORK_PROFILES), NETWORK_PROFILES)
        self.assertEqual(transport_load.RESULT_FILE, "load.json")
        for function, names in ((transport_load.read_saved_settings, ["path"]),
                                (transport_load.write_load_results, ["result", "output_dir"]),
                                (transport_load.summary_lines, ["result"])):
            with self.subTest(function=function.__name__):
                self.assertEqual(list(inspect.signature(function).parameters), names)

    def test_load_settings_still_reject_the_reference_carrier(self):
        settings = transport_load.checked_settings(**{**LOAD_DEFAULTS, "transport": "split"})
        self.assertEqual(set(settings), LOAD_SETTINGS_KEYS)
        for transport in ("ref_bearer", "ref", "reference"):
            with self.subTest(transport=transport), self.assertRaises(ValueError):
                transport_load.checked_settings(**{**LOAD_DEFAULTS, "transport": transport})

    def test_read_saved_settings_rejects_ref_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "load.json"
            settings = {"algorithms": ["ES256"], "transport": "bearer", "duration": 1.0}
            path.write_text(json.dumps({"settings": settings}), encoding="utf-8")
            self.assertEqual(transport_load.read_saved_settings(path), settings)
            for store in ("memory", "remote"):
                with self.subTest(ref_store=store):
                    path.write_text(json.dumps({"settings": {**settings, "ref_store": store}}),
                                    encoding="utf-8")
                    with self.assertRaises(ValueError):
                        transport_load.read_saved_settings(path)

    def test_docstring_mentions_the_reference_carrier(self):
        lowered = (transport_load.__doc__ or "").lower()
        self.assertTrue(any(term in lowered for term in ("ref_bearer", "reference token",
                                                         "opaque reference", "jwt_ref",
                                                         "reference carrier")), lowered[-600:])


# ---- R13: the plan ---------------------------------------------------------------------------

class JsonCase(unittest.TestCase):
    def assertJsonClose(self, actual, expected, where: str = "result") -> None:
        """Compare JSON-like values exactly, except floats, which may differ by rounding."""
        if isinstance(expected, dict):
            self.assertIsInstance(actual, dict, where)
            self.assertEqual(set(actual), set(expected), where)
            for key in expected:
                self.assertJsonClose(actual[key], expected[key], f"{where}.{key}")
        elif isinstance(expected, (list, tuple)):
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


class RefPlanTests(JsonCase):
    def test_signature(self):
        parameters = inspect.signature(module().ref_plan).parameters
        self.assertEqual(list(parameters), ["algorithms", "claims"])
        self.assertIsNone(parameters["algorithms"].default)
        self.assertEqual(parameters["claims"].default, "oidc")

    def test_the_ml_dsa_44_row(self):
        rows = module().ref_plan(["ML-DSA-44"])
        self.assertJsonClose(rows, [ML_DSA_44_ROW], "plan")
        self.assertJsonClose(rows, [expected_plan_row("ML-DSA-44")], "plan")

    def test_every_configuration(self):
        rows = module().ref_plan()
        self.assertIsInstance(rows, list)
        self.assertEqual([row["algorithm"] for row in rows], NAMES)
        for row in rows:
            with self.subTest(algorithm=row["algorithm"]):
                self.assertEqual(set(row), PLAN_KEYS)
                self.assertEqual(row["token_bytes"], TOKEN_BYTES_OIDC[row["algorithm"]])
        self.assertJsonClose(rows, [expected_plan_row(name) for name in NAMES], "plan")

    def test_fits(self):
        fits = {row["algorithm"]: row["fits"] for row in module().ref_plan()}
        every = {"per_cookie": True, "cookie_line": True, "authorization_line": True}
        for name in NAMES:
            with self.subTest(algorithm=name):
                self.assertEqual(fits[name]["ref"], every)
        for name in ("RS256", "ES256", "EdDSA"):
            self.assertEqual(fits[name]["jwt"], every)
        for name in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"):
            self.assertEqual(fits[name]["jwt"], {"per_cookie": False, "cookie_line": False,
                                                 "authorization_line": False})
        self.assertEqual(fits["ML-DSA-44"], ML_DSA_44_ROW["fits"])

    def test_claims_and_selection(self):
        plan = module().ref_plan
        for claims in CLAIM_SET_NAMES:
            with self.subTest(claims=claims):
                self.assertJsonClose(plan(None, claims),
                                     [expected_plan_row(name, claims) for name in NAMES])
        # Only the selection, in its own or in ADAPTER_LIST order; no reference is added.
        rows = plan(["SLH-DSA-SHA2-128f", "EdDSA"], "essential")
        self.assertIn([row["algorithm"] for row in rows],
                      (["EdDSA", "SLH-DSA-SHA2-128f"], ["SLH-DSA-SHA2-128f", "EdDSA"]))
        self.assertJsonClose(rows, [expected_plan_row(row["algorithm"], "essential")
                                    for row in rows])
        self.assertJsonClose(plan(algorithms=["RS256"], claims="minimal"),
                             [expected_plan_row("RS256", "minimal")])

    def test_invalid_arguments_raise(self):
        plan = module().ref_plan
        for algorithms in ([], ["HS256"], ["ES256", "ES256"], ["ES256", None], "ES256"):
            with self.subTest(algorithms=algorithms), self.assertRaises(ValueError):
                plan(algorithms)
        for claims in ("huge", "", "OIDC", None):
            with self.subTest(claims=claims), self.assertRaises(ValueError):
                plan(None, claims)


# ---- R1, R12: the module, its settings, and its interface ---------------------------------

class InterfaceTests(unittest.TestCase):
    def test_result_file(self):
        self.assertEqual(module().RESULT_FILE, "refs.json")

    def test_run_refs_signature_and_defaults(self):
        parameters = inspect.signature(module().run_refs).parameters
        self.assertEqual(list(parameters), ["output_dir", *RUN_REFS_DEFAULTS])
        self.assertIs(parameters["output_dir"].default, inspect.Parameter.empty)
        for name, default in RUN_REFS_DEFAULTS.items():
            with self.subTest(parameter=name):
                value = parameters[name].default
                if name == "concurrency":
                    self.assertEqual(list(value), default)
                elif default is None:
                    self.assertIsNone(value)
                else:
                    self.assertEqual(value, default)

    def test_default_settings(self):
        settings = module().default_settings()
        self.assertEqual(set(settings), set(SETTING_NAMES))
        self.assertEqual(list(settings["concurrency"]), [1, 4])
        self.assertEqual({key: value for key, value in settings.items() if key != "concurrency"},
                         {key: value for key, value in RUN_REFS_DEFAULTS.items()
                          if key not in ("concurrency", "run_dir")})

    def test_other_public_functions(self):
        refs = module()
        for function, names in ((refs.checked_settings, list(SETTING_NAMES)),
                                (refs.read_saved_settings, ["path"]),
                                (refs.summary_lines, ["result"]),
                                (refs.default_settings, [])):
            with self.subTest(function=function.__name__):
                self.assertEqual(list(inspect.signature(function).parameters), names)

    def test_module_docstring(self):
        text = module().__doc__ or ""
        self.assertGreater(len(text.strip()), 200)
        lowered = text.lower()
        for term in ("refs.json", "reference", "store", "latency", "limit", "ephemeral",
                     "experiment", "production"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_import_and_plan_start_nothing(self):
        module()
        for mode in ("import", "plan"):
            with self.subTest(mode=mode):
                result = run_python(IMPORT_CHECK, str(REPO), mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout),
                                 {"children": 0, "threads": 1, "playwright": False,
                                  "rows": 1 if mode == "plan" else None})

    def test_stack_module_imports_nothing_heavy(self):
        result = run_python(STACK_IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])


class SharedHelperTests(unittest.TestCase):
    """R1: transport_refs imports the shared helpers and never copies them."""

    @classmethod
    def setUpClass(cls):
        cls.tree = None
        if REFS_MODULE.is_file():
            cls.tree = ast.parse(REFS_MODULE.read_text(encoding="utf-8"))

    def setUp(self):
        module()
        self.assertIsNotNone(self.tree, "scripts/transport_refs.py is missing")
        tree = self.tree
        self.defined = {node.name for node in tree.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                             ast.ClassDef))}
        self.defined |= {target.id for node in tree.body if isinstance(node, ast.Assign)
                         for target in node.targets if isinstance(target, ast.Name)}
        self.defined |= {node.target.id for node in tree.body if isinstance(node, ast.AnnAssign)
                         and isinstance(node.target, ast.Name)}
        self.imported, aliases = {}, {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.imported.setdefault(node.module, set()).add(alias.name)
                    if node.module == "scripts":
                        aliases[alias.asname or alias.name] = f"scripts.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name
        self.attributes = {(aliases.get(node.value.id), node.attr) for node in ast.walk(tree)
                           if isinstance(node, ast.Attribute)
                           and isinstance(node.value, ast.Name)}
        self.used = {node.id for node in ast.walk(tree)
                     if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}

    def taken(self, source: str, name: str) -> bool:
        """True when name is imported from source or used as its attribute."""
        return name in self.imported.get(source, set()) or (source, name) in self.attributes

    def test_required_imports(self):
        for source, names in REQUIRED_IMPORTS.items():
            for name in names:
                with self.subTest(helper=f"{source}.{name}"):
                    self.assertIn(name, self.imported.get(source, set()),
                                  f"{name} is not imported from {source}")

    def test_shared_helpers_are_not_defined_again(self):
        for source, names in shared_helpers().items():
            for name in names:
                with self.subTest(helper=f"{source}.{name}"):
                    if name not in OWN_NAMES:
                        self.assertNotIn(name, self.defined, "a shared helper is defined again")
                    if name in self.used and name not in OWN_NAMES:
                        self.assertTrue(self.taken(source, name),
                                        f"{name} is used but not taken from {source}")
        self.assertIn("checked_settings", self.defined)

    def test_cookies_helpers_are_not_defined_again(self):
        for name in COOKIES_HELPERS:
            with self.subTest(helper=name):
                self.assertNotIn(name, self.defined)
                if name in self.used:
                    self.assertTrue(self.taken("scripts.transport_cookies", name),
                                    f"{name} is used but not taken from transport_cookies")

    def test_public_names_are_defined_here(self):
        for name in ("RESULT_FILE", "run_refs", "default_settings", "checked_settings",
                     "read_saved_settings", "ref_plan", "summary_lines"):
            with self.subTest(name=name):
                self.assertIn(name, self.defined)


class CheckedSettingsTests(unittest.TestCase):
    VALID = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct"],
             "concurrency": [1], "duration": 0.1, "warmup": 0.0, "timeout": 30.0,
             "header_buffers": "32k", "upstream_keepalive": 8}
    INVALID = [
        {"algorithms": "ES256"}, {"algorithms": []}, {"algorithms": ["HS256"]},
        {"algorithms": ["ES256", "ES256"]}, {"algorithms": ["ES256", None]},
        {"claims": "huge"}, {"claims": ""}, {"claims": None}, {"claims": "OIDC"},
        {"claims": ["oidc"]},
        {"clients": "direct"}, {"clients": []}, {"clients": ["curl"]},
        {"clients": ["direct", "direct"]},
        {"concurrency": 1}, {"concurrency": []}, {"concurrency": [0]}, {"concurrency": [65]},
        {"concurrency": [True]}, {"concurrency": [1, 1]}, {"concurrency": [2.0]},
        {"duration": 0}, {"duration": -1}, {"duration": float("nan")},
        {"duration": float("inf")}, {"duration": True}, {"duration": "5"},
        {"warmup": -0.5}, {"warmup": float("nan")}, {"warmup": float("inf")},
        {"warmup": False}, {"warmup": "1"},
        {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")}, {"timeout": float("inf")},
        {"timeout": True},
        {"header_buffers": None}, {"header_buffers": "big"}, {"header_buffers": "32 k"},
        {"header_buffers": ""}, {"header_buffers": 32}, {"header_buffers": "0k"},
        {"header_buffers": "16kb"},
        {"upstream_keepalive": 0}, {"upstream_keepalive": 1025}, {"upstream_keepalive": True},
        {"upstream_keepalive": "8"}, {"upstream_keepalive": 8.0},
    ]

    def checked(self, **given) -> dict:
        """checked_settings of VALID with given values replaced."""
        return module().checked_settings(**{**self.VALID, **given})

    def test_valid_settings(self):
        self.assertEqual(self.checked(), self.VALID)

    def test_algorithms_add_es256_in_adapter_order(self):
        settings = self.checked(algorithms=("SLH-DSA-SHA2-128f", "RS256"))
        self.assertEqual(settings["algorithms"], ["RS256", "ES256", "SLH-DSA-SHA2-128f"])
        self.assertEqual(self.checked(algorithms=None)["algorithms"], NAMES)
        self.assertEqual(self.checked(algorithms=["ML-DSA-44"])["algorithms"],
                         ["ES256", "ML-DSA-44"])

    def test_sequences_become_lists(self):
        settings = self.checked(algorithms=("EdDSA",), clients=("browser", "direct"),
                                concurrency=(4, 1))
        self.assertEqual(settings["algorithms"], ["ES256", "EdDSA"])
        self.assertEqual(settings["clients"], ["browser", "direct"])
        self.assertEqual(settings["concurrency"], [4, 1])
        for key in ("algorithms", "clients", "concurrency"):
            self.assertIsInstance(settings[key], list)
        self.assertEqual(self.checked(clients=None)["clients"], ["direct", "browser"])

    def test_defaults_are_valid(self):
        settings = module().checked_settings(**module().default_settings())
        self.assertEqual(settings, {"algorithms": NAMES, "claims": "oidc",
                                    "clients": ["direct", "browser"], "concurrency": [1, 4],
                                    "duration": 5.0, "warmup": 1.0, "timeout": 60.0,
                                    "header_buffers": "32k", "upstream_keepalive": None})

    def test_every_claim_set_and_other_values(self):
        for claims in CLAIM_SET_NAMES:
            with self.subTest(claims=claims):
                self.assertEqual(self.checked(claims=claims)["claims"], claims)
        settings = self.checked(header_buffers="64k", upstream_keepalive=None)
        self.assertEqual((settings["header_buffers"], settings["upstream_keepalive"]),
                         ("64k", None))
        self.assertEqual(self.checked(upstream_keepalive=1024)["upstream_keepalive"], 1024)
        self.assertEqual(self.checked(concurrency=[64, 1])["concurrency"], [64, 1])

    def test_invalid_settings_raise(self):
        for case in self.INVALID:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.checked(**case)


class SavedSettingsTests(unittest.TestCase):
    def write(self, directory: str, text: str, name: str = "refs.json") -> Path:
        """Write text to a file in directory; return its path."""
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_reads_the_settings_object(self):
        read = module().read_saved_settings
        with tempfile.TemporaryDirectory() as directory:
            saved = {**CheckedSettingsTests.VALID, "duration": 2.0}
            self.assertEqual(read(self.write(directory, json.dumps({"settings": saved,
                                                                    "plan": []}))), saved)
            partial = {"header_buffers": "64k", "claims": "essential"}
            self.assertEqual(read(self.write(directory, json.dumps({"settings": partial}))),
                             partial)

    def test_settings_repeat_the_run(self):
        refs = module()
        settings = refs.checked_settings(**CheckedSettingsTests.VALID)
        bound = inspect.signature(refs.run_refs).bind("out", **settings)
        self.assertEqual(set(bound.arguments), {"output_dir", *SETTING_NAMES})
        self.assertEqual(refs.checked_settings(**settings), settings)

    def test_rejects_unusable_files(self):
        read = module().read_saved_settings
        with tempfile.TemporaryDirectory() as directory:
            for text in ("not json", "[]", "null", '{"results": []}', '{"settings": [1]}',
                         '{"settings": "x"}', '{"settings": null}', '{"settings": {"bogus": 1}}',
                         '{"settings": {"transport": "bearer"}}',
                         '{"settings": {"proxy_buffers": "32k"}}',
                         '{"settings": {"ref_store": "memory"}}',
                         '{"settings": {"output_dir": "x"}}', '{"settings": {"run_dir": "x"}}'):
                with self.subTest(text=text), self.assertRaises(ValueError):
                    read(self.write(directory, text))
            with self.assertRaises(ValueError):
                read(Path(directory) / "missing.json")
            binary = Path(directory) / "binary.json"
            binary.write_bytes(b"\xff\xfe\x00")
            with self.assertRaises(ValueError):
                read(binary)
            with self.assertRaises(ValueError):
                read(Path(directory))


class RunRefsArgumentTests(unittest.TestCase):
    def test_invalid_arguments_raise_before_anything_starts(self):
        run_refs = module().run_refs
        with tempfile.TemporaryDirectory() as directory:
            for index, case in enumerate(CheckedSettingsTests.INVALID):
                output = Path(directory) / f"out-{index}" / "nested"
                run_dir = Path(directory) / f"run-{index}"
                with self.subTest(case=case):
                    with self.assertRaises(ValueError):
                        run_refs(output, **{**CheckedSettingsTests.VALID, **case,
                                            "run_dir": run_dir})
                    self.assertFalse(output.parent.exists(), "the output directory was created")
                    self.assertFalse(run_dir.exists(), "a stack was started")

    def test_output_dir_must_be_new_or_empty(self):
        run_refs = module().run_refs
        with tempfile.TemporaryDirectory() as directory:
            occupied = Path(directory) / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("keep", encoding="utf-8")
            a_file = Path(directory) / "a-file"
            a_file.write_text("file", encoding="utf-8")
            for index, output in enumerate((occupied, a_file)):
                run_dir = Path(directory) / f"run-{index}"
                with self.subTest(output=output.name):
                    with self.assertRaises(ValueError):
                        run_refs(output, run_dir=run_dir, **CheckedSettingsTests.VALID)
                    self.assertFalse(run_dir.exists(), "a stack was started")
            self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
            self.assertEqual(a_file.read_text(encoding="utf-8"), "file")


# ---- R1, R25: where the code goes, and transport_cookies keeps its API -----------------------

def top_level_names(source: str) -> set[str]:
    """Every name a module defines at its top level: functions, classes, and assignments."""
    names = set()
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {target.id for target in node.targets if isinstance(target, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def parameters(node: ast.FunctionDef) -> tuple[list, dict, str | None, str | None]:
    """A function's positional (name, default) pairs, keyword-only defaults, *args, **kwargs."""
    arguments = node.args
    positional = arguments.posonlyargs + arguments.args
    defaults = [None] * (len(positional) - len(arguments.defaults)) + [
        ast.unparse(default) for default in arguments.defaults]
    keyword_only = {argument.arg: None if default is None else ast.unparse(default)
                    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)}
    return ([(argument.arg, default) for argument, default in zip(positional, defaults)],
            keyword_only, arguments.vararg.arg if arguments.vararg else None,
            arguments.kwarg.arg if arguments.kwarg else None)


def functions(source: str) -> dict[str, ast.FunctionDef]:
    """A module's top-level functions, by name."""
    return {node.name: node for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef)}


class PlacementTests(unittest.TestCase):
    def require(self, value):
        """value, or skip the test when BASE_COMMIT is not available."""
        if value is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return value

    def test_refs_module_added_and_nothing_removed(self):
        # Later Sprint 3 items add their own modules, so scripts/ must hold the earlier files
        # plus transport_refs.py, not exactly those.
        listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:scripts")).split()
        entries = [path for path in (REPO / "scripts").iterdir()
                   if not path.name.startswith(".") and path.name != "__pycache__"]
        self.assertLessEqual({*listing, "transport_refs.py"},
                             {path.name for path in entries if path.is_file()})
        self.assertEqual([path.name for path in entries if path.is_dir()], [],
                         "no package or subdirectory under scripts/")

    def test_fixtures_unchanged(self):
        listing = self.require(git("ls-tree", "--name-only", f"{BASE_COMMIT}:fixtures")).split()
        on_disk = {path.name for path in (REPO / "fixtures").iterdir()
                   if not path.name.startswith(".")}
        self.assertEqual(on_disk, set(listing))
        changed = self.require(git("diff", "--name-only", BASE_COMMIT, "--", "fixtures"))
        self.assertEqual(changed.split(), [])

    def test_transport_cookies_keeps_its_docstring_names_and_signatures(self):
        before = self.require(git_show("scripts/transport_cookies.py"))
        after = (REPO / "scripts" / "transport_cookies.py").read_text(encoding="utf-8")
        self.assertEqual(ast.get_docstring(ast.parse(after), clean=False),
                         ast.get_docstring(ast.parse(before), clean=False))
        self.assertEqual(top_level_names(after), top_level_names(before))
        old, new = functions(before), functions(after)
        for name in COOKIES_API:
            with self.subTest(function=name):
                self.assertIn(name, new)
                self.assertEqual(parameters(new[name]), parameters(old[name]))

    def test_other_cookies_helpers_only_gain_optional_keywords(self):
        before = self.require(git_show("scripts/transport_cookies.py"))
        after = (REPO / "scripts" / "transport_cookies.py").read_text(encoding="utf-8")
        old, new = functions(before), functions(after)
        for name, node in old.items():
            with self.subTest(function=name):
                self.assertIn(name, new)
                old_positional, old_keywords, old_args, old_kwargs = parameters(node)
                positional, keywords, args, kwargs = parameters(new[name])
                self.assertEqual(positional[:len(old_positional)], old_positional)
                self.assertTrue(all(default is not None
                                    for _, default in positional[len(old_positional):]))
                for keyword, default in old_keywords.items():
                    self.assertEqual(keywords.get(keyword, "<missing>"), default)
                self.assertTrue(all(default is not None for keyword, default in keywords.items()
                                    if keyword not in old_keywords))
                self.assertEqual((args, kwargs), (old_args, old_kwargs))

    def test_transport_claims_keeps_its_names_and_signatures(self):
        before = self.require(git_show("scripts/transport_claims.py"))
        after = (REPO / "scripts" / "transport_claims.py").read_text(encoding="utf-8")
        self.assertEqual(top_level_names(after), top_level_names(before))
        old, new = functions(before), functions(after)
        for name, node in old.items():
            with self.subTest(function=name):
                self.assertIn(name, new)
                old_positional, old_keywords, old_args, old_kwargs = parameters(node)
                positional, keywords, args, kwargs = parameters(new[name])
                self.assertEqual(positional[:len(old_positional)], old_positional)
                self.assertTrue(all(default is not None
                                    for _, default in positional[len(old_positional):]))
                for keyword, default in old_keywords.items():
                    self.assertEqual(keywords.get(keyword, "<missing>"), default)
                self.assertEqual((args, kwargs), (old_args, old_kwargs))

    def test_imports_start_nothing(self):
        for name in ("scripts.transport_load", "scripts.transport_app"):
            with self.subTest(module=name):
                result = run_python(MODULE_IMPORT_CHECK, str(REPO), name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"children": 0, "threads": 1})

    def test_cookies_and_claims_results_and_names_unchanged(self):
        from scripts.token_sizing import CLAIM_SET_NAMES as NAMES_NOW
        self.assertEqual(tuple(NAMES_NOW), CLAIM_SET_NAMES)
        from scripts import transport_cookies
        self.assertEqual(transport_cookies.RESULT_FILE, "cookies.json")


# ---- R18: summary_lines ----------------------------------------------------------------------

DISPLAYED_NUMBER = re.compile(r"(?<![\w.])[-−+]?\d[\d,]*(?:\.\d+)?")
# R18's 'moved' marker; "not moved" or "unmoved" on a line whose pair did not move is fine.
MOVED_WORD = re.compile(r"(?<!not )(?<![\w-])moved\b")


def shows_ms(text: str, value: float) -> bool:
    """True when text shows value in ms with exactly 3 decimals."""
    for name in NAMES:  # "ML-DSA-44" and "SHA2-128f" are names, not numbers.
        text = text.replace(name, " ")
    for match in DISPLAYED_NUMBER.finditer(text):
        shown = match.group().replace("−", "-").replace("+", "").replace(",", "")
        if len(shown.partition(".")[2]) == 3 and abs(float(shown) - value) <= 0.0005 + 1e-9:
            return True
    return False


def shows_bytes(text: str, value: int) -> bool:
    """True when text shows a byte count, with or without thousands separators."""
    return re.search(rf"(?<![\d,.])(?:{value}|{value:,})(?![\d,]*\d)", text) is not None


def synthetic_result(names=("ES256", "ML-DSA-44"), claims: str = "oidc") -> dict:
    """A refs.json-shaped result with every R17 key, as summary_lines would read it back."""
    nonces = iter(f"{value:032x}" for value in range(1, 10_000))
    derived_rejections = {("ML-DSA-44", "cookie"), ("SLH-DSA-SHA2-128s", "cookie"),
                          ("SLH-DSA-SHA2-128s", "bearer"), ("SLH-DSA-SHA2-128f", "cookie"),
                          ("SLH-DSA-SHA2-128f", "bearer")}

    def pair(name: str, transport: str, outcome: str = "verified", layer: str | None = None,
             pad: int = 0) -> dict:
        """One synthetic limits result or probe."""
        return {"algorithm": name, "transport": transport,
                "token_bytes": token_bytes(name, padded_claims(claim_set(claims), pad)),
                "reference_bytes": REF_BYTES, "outcome": outcome, "rejected_by": layer,
                "verified_directly": True,
                "cookie_stored": (outcome == "verified") if transport == "cookie" else None,
                "issue_status": 200, "verify_status": 200 if outcome == "verified" else 400,
                "bytes": {"header_line": 65 if transport == "cookie" else 71,
                          "app_received_headers": 812},
                "issue_nonce": next(nonces), "verify_nonce": next(nonces),
                "evidence": f"{outcome}: a synthetic pair"}

    results = [pair(name, transport, *(("rejected", "proxy") if (name, transport)
                                       == ("ES256", "bearer") else ()))
               for name in names for transport in ("cookie", "bearer")]
    jwt_results = []
    for entry in results:
        rejected = (entry["algorithm"], entry["transport"]) in derived_rejections
        jwt_results.append({"algorithm": entry["algorithm"], "transport": entry["transport"],
                            "token_bytes": entry["token_bytes"],
                            "outcome": "rejected" if rejected else "verified",
                            "rejected_by": "browser" if rejected else None})
    moved = [{"algorithm": entry["algorithm"], "transport": entry["transport"],
              "jwt": derived["outcome"], "ref": entry["outcome"],
              "moved": derived["outcome"] == "rejected" and entry["outcome"] == "verified"}
             for entry, derived in zip(results, jwt_results)]
    probes = []
    for target in PROBE_TARGETS:
        pad = pad_for_target(PROBE_ALGORITHM, claim_set(claims), target)
        for transport in ("cookie", "bearer"):
            entry = pair(PROBE_ALGORITHM, transport, pad=pad)
            del entry["verified_directly"]
            probes.append({**entry, "target_bytes": target, "pad": pad})
    cases = [{"name": name, "method": "GET",
              "path": REFERENCE_PATH if name == "issue_without_store" else VERIFY_PATH,
              "sent": ["bearer"], "store": "stopped" if index >= 10 else "running",
              "status": status, "verified": status == 200, "source": source,
              "ref_status": ref_status, "lookup_called": lookup, "verify_called": verify,
              "revoke_status": 200 if name == "revoked" else None, "set_cookie": False,
              "error": None if status == 200 else f"synthetic {name}", "nonce": next(nonces)}
             for index, (name, status, source, ref_status, lookup, verify)
             in enumerate(HANDLING_CASES)]
    rows = []
    for client_index, client in enumerate(("direct", "browser")):
        for index, name in enumerate(names):
            base = 0.250 + 0.100 * index + 0.500 * client_index
            undelivered = client == "browser" and name == "ML-DSA-44"
            means = {}
            for run, extra in (("jwt", 0.0), ("ref_memory", 0.012), ("ref_remote", 0.141)):
                total = round(base + extra, 3)
                means[run] = {"total": total, "transfer": round(total * 0.6, 4),
                              "other_handling": 0.0123,
                              "lookup": 0.0 if run == "jwt" else round(extra * 0.5, 4),
                              "verification": 0.0456}
            if undelivered:
                means["ref_remote"] = None
            difference = {run: None if means[run] is None else
                          {component: means[run][component] - means["jwt"][component]
                           for component in REF_COMPONENTS}
                          for run in ("ref_memory", "ref_remote")}
            rows.append({
                "client": client, "concurrency": 1, "algorithm": name,
                "token_bytes": TOKEN_BYTES_OIDC[name], "reference_bytes": REF_BYTES,
                "delivered": {run: not (undelivered and run == "ref_remote") for run in RUNS},
                "verified": {run: 0 if means[run] is None else 900 for run in RUNS},
                "failed": {run: 0 for run in RUNS},
                "throughput_rps": {run: 0.0 if means[run] is None else 4500.5 for run in RUNS},
                "median_ms": {run: None if means[run] is None else means[run]["total"] - 0.0071
                              for run in RUNS},
                "p95_ms": {run: None if means[run] is None else means[run]["total"] + 0.0377
                           for run in RUNS},
                "mean_ms": means, "difference_ms": difference})
    network = [{"algorithm": name,
                "request_bytes": {"jwt": 150 + 24 + TOKEN_BYTES_OIDC[name], "ref": 150 + 71},
                "saved_bytes": TOKEN_BYTES_OIDC[name] - REF_BYTES,
                "modeled": [{**profile, "saved_ms": 0.001 * (index + 1)}
                            for index, profile in enumerate(NETWORK_PROFILES)]}
               for name in names]
    return {
        "schema_version": 1,
        "started_utc": "2026-11-18T20:00:00+00:00",
        "finished_utc": "2026-11-18T20:03:00+00:00",
        "recorded_utc": "2026-11-18T20:03:01+00:00",
        "settings": {"algorithms": list(names), "claims": claims, "clients": ["direct", "browser"],
                     "concurrency": [1], "duration": 0.2, "warmup": 0.0, "timeout": 60.0,
                     "header_buffers": "32k", "upstream_keepalive": 8},
        "environment": {"python": "3.15.2", "platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                        "page_size_bytes": 16384, "waitress_threads": 4,
                        "git_commit": "0" * 40, "git_dirty_scripts_or_fixtures": False},
        "layers": [],
        "browser": {"version": "156.0.8078.4", "user_agent": "Mozilla/5.0 HeadlessChrome"},
        "experiment_keys": True,
        "format": {"reference_prefix": REF_PREFIX, "random_bytes": REF_RANDOM_BYTES,
                   "reference_bytes": REF_BYTES, "cookie_name": REF_COOKIE_NAME,
                   "cookie_attributes": FULL_ATTRIBUTES, "default_ttl_seconds": REF_DEFAULT_TTL,
                   "max_ttl_seconds": REF_MAX_TTL, "stores": ["memory", "remote"]},
        "plan": [expected_plan_row(name, claims) for name in names],
        "limits": {"stack": "limits", "header_buffers": None, "proxy_buffers": None,
                   "ref_store": "memory", "cookie_attributes": FULL_ATTRIBUTES,
                   "results": results,
                   "jwt": {"source": "results/claims/20261118T053507Z-macos/claims.json",
                           "claims": claims, "results": jwt_results},
                   "moved": moved},
        "probes": probes,
        "handling": {"algorithm": "ML-DSA-44", "claims": claims,
                     "token_bytes": token_bytes("ML-DSA-44", claim_set(claims)),
                     "stack": "behavior", "ref_store": "remote", "expired_ttl_seconds": 1,
                     "cases": cases},
        "latency": {"transport": "bearer", "reference": "ES256", "size_controls": False,
                    "runs": {"jwt": "latency-jwt/load.json",
                             "ref_memory": "latency-ref-memory/load.json",
                             "ref_remote": "latency-ref-remote/load.json"},
                    "rows": rows, "network_model": network},
        "evidence": {"limits": {"logs": {}, "nginx_conf": "limits/nginx.conf"}},
    }


class SummaryLinesTests(unittest.TestCase):
    def check_lines(self, result: dict) -> list[str]:
        """Check summary_lines(result) against R18; return the lines."""
        lines = module().summary_lines(result)
        self.assertIsInstance(lines, list)
        limits, rows = result["limits"]["results"], result["latency"]["rows"]
        words = (["plan"] * len(result["plan"]) + ["limits"] * len(limits)
                 + ["probe"] * len(result["probes"])
                 + ["handling"] * len(result["handling"]["cases"]) + ["latency"] * len(rows))
        self.assertEqual(len(lines), len(words), "\n".join(lines))
        for line, word in zip(lines, words):
            with self.subTest(line=line):
                self.assertIsInstance(line, str)
                self.assertTrue(line.startswith(word), f"expected {word!r}")
        position = 0
        for row in result["plan"]:
            self.assertIn(row["algorithm"], lines[position])
            position += 1
        for entry, moved in zip(limits, result["limits"]["moved"]):
            line = lines[position]
            with self.subTest(line=line):
                self.assertIn(entry["algorithm"], line)
                self.assertIn(entry["outcome"], line)
                if moved["jwt"] is not None:
                    self.assertIn(moved["jwt"], line)
                if moved["moved"] is True:
                    self.assertRegex(line, MOVED_WORD)
            position += 1
        limits_lines = lines[len(result["plan"]):len(result["plan"]) + len(limits)]
        self.assertEqual(sum(MOVED_WORD.search(line) is not None for line in limits_lines),
                         sum(entry["moved"] is True for entry in result["limits"]["moved"]),
                         "'moved' on a line whose pair did not move")
        for probe in result["probes"]:
            line = lines[position]
            with self.subTest(line=line):
                self.assertIn(probe["algorithm"], line)
                self.assertIn(probe["transport"], line)
                self.assertTrue(shows_bytes(line, probe["token_bytes"]), probe["token_bytes"])
            position += 1
        for case in result["handling"]["cases"]:
            line = lines[position]
            with self.subTest(line=line):
                self.assertIn(case["name"], line)
                self.assertRegex(line, rf"(?<!\d){case['status']}(?!\d)")
            position += 1
        for row in rows:
            line = lines[position]
            with self.subTest(line=line):
                self.assertIn(row["algorithm"], line)
                self.assertIn(row["client"], line)
                if all(row["mean_ms"][run] is not None for run in RUNS):
                    for run in RUNS:
                        self.assertTrue(shows_ms(line, row["mean_ms"][run]["total"]), run)
                    for run in ("ref_memory", "ref_remote"):
                        self.assertTrue(shows_ms(line, row["difference_ms"][run]["total"]), run)
            position += 1
        return lines

    def test_lines_for_every_phase(self):
        self.check_lines(synthetic_result())

    def test_every_configuration(self):
        self.check_lines(synthetic_result(tuple(NAMES)))

    def test_moved_lines(self):
        result = synthetic_result(("ES256", "ML-DSA-44", "SLH-DSA-SHA2-128f"))
        self.assertTrue(any(entry["moved"] for entry in result["limits"]["moved"]))
        self.assertTrue(any(not entry["moved"] for entry in result["limits"]["moved"]))
        self.check_lines(result)

    def test_without_derived_jwt_verdicts(self):
        result = synthetic_result(claims="minimal")
        result["limits"]["jwt"] = None
        for entry in result["limits"]["moved"]:
            entry.update(jwt=None, moved=None)
        lines = self.check_lines(result)
        self.assertEqual(sum(line.startswith("limits") for line in lines), 4)

    def test_reads_only_the_saved_json(self):
        result = synthetic_result()
        text = json.dumps(result)
        lines = module().summary_lines(json.loads(text))
        self.assertEqual(json.dumps(result), text, "summary_lines changed its argument")
        self.assertEqual(module().summary_lines(json.loads(text)), lines)


if __name__ == "__main__":
    unittest.main()
