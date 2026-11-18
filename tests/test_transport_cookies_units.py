"""Check S3-02's cookie splitting without a stack or a browser: the chunk format, Cookie header
parsing, reassembly, the application's split delivery and split source (in-process WSGI calls
compared with the 6f50c93 application), the load workload's split carrier, the chunk plan, the
cookies run's settings and interface, summary_lines, and what stays unchanged; no timing
thresholds."""

import ast
import base64
import importlib.util
import inspect
import json
import logging
import math
import os
from pathlib import Path
import random
import re
import string
import subprocess
import sys
import tempfile
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
    from scripts import transport_cookies
    COOKIES_IMPORT_ERROR = None
except Exception as error:  # Before S3-02's cookie splitting is built: tests fail, not vanish.
    transport_cookies, COOKIES_IMPORT_ERROR = None, error

try:
    from scripts import transport_claims
    CLAIMS_IMPORT_ERROR = None
except Exception as error:
    transport_claims, CLAIMS_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
# The commit cookie splitting builds on: unchanged files and the reference application come
# from it.
BASE_COMMIT = "6f50c937af37d9dfb19db421a4693aabee95cfe8"
HOST = "127.0.0.1"
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
CLAIM_SET_NAMES = ("minimal", "oidc", "essential")

SPLIT_CHUNK_BYTES = 4000
SPLIT_MAX_CHUNKS = 1000
DOMAIN_MAX_COOKIES = 180
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
DEFAULT_ATTRIBUTES = "Path=/; HttpOnly; SameSite=Strict"
TOKEN_BYTES_OIDC = {"RS256": 1204, "ES256": 948, "EdDSA": 948, "ML-DSA-44": 4095,
                    "SLH-DSA-SHA2-128s": 11353, "SLH-DSA-SHA2-128f": 23662}
DEFAULT_CHUNKS_OIDC = {"RS256": 1, "ES256": 1, "EdDSA": 1, "ML-DSA-44": 2,
                       "SLH-DSA-SHA2-128s": 3, "SLH-DSA-SHA2-128f": 6}
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")

PLAN_KEYS = {"algorithm", "token_bytes", "chunks", "chunk_bytes", "cookie_names",
             "name_value_bytes", "set_cookie_bytes", "cookie_line_bytes", "fits"}
ML_DSA_44_ROW = {
    "algorithm": "ML-DSA-44", "token_bytes": 4095, "chunks": 2, "chunk_bytes": [2048, 2047],
    "cookie_names": ["jwt.0.2", "jwt.1.2"],
    "name_value_bytes": {"cookie": 4098, "split": 2055},
    "set_cookie_bytes": {"cookie": 4170, "split": 4253},
    "cookie_line_bytes": {"cookie": 4109, "split": 4123},
    "fits": {"cookie": {"per_cookie": False, "cookie_line": True},
             "split": {"per_cookie": True, "cookie_count": True, "cookie_line": True}},
}
SETTING_NAMES = ("algorithms", "claims", "clients", "concurrency", "duration", "warmup",
                 "timeout", "header_buffers", "proxy_buffers", "upstream_keepalive")
RUN_COOKIES_DEFAULTS = {"algorithms": None, "claims": "oidc", "clients": None,
                        "concurrency": [1, 4], "duration": 5.0, "warmup": 1.0, "timeout": 60.0,
                        "header_buffers": "32k", "proxy_buffers": "32k",
                        "upstream_keepalive": None, "run_dir": None}
LOAD_DEFAULTS = {"algorithms": None, "transport": "bearer", "clients": None,
                 "concurrency": (1, 4), "duration": 5.0, "warmup": 1.0, "claims": "minimal",
                 "reference": "ES256", "size_controls": True, "timeout": 60.0,
                 "proxy_buffers": None, "header_buffers": None, "upstream_keepalive": None}
LOAD_SETTINGS_KEYS = {"algorithms", "transport", "clients", "claims", "concurrency", "duration",
                      "warmup", "reference", "size_controls", "timeout", "proxy_buffers",
                      "header_buffers", "upstream_keepalive"}
COMPONENTS = ("total", "transfer", "other_handling", "verification")

# Sprint 2's verify response bodies (scripts/transport_app.py before S3-02).
VERIFIED_KEYS = {"layer", "verified", "algorithm", "source", "token_bytes", "claims",
                 "experiment_key", "received"}
FAILED_KEYS = {"layer", "verified", "source", "error", "experiment_key", "received"}
ISSUE_ERROR_KEYS = {"layer", "error", "algorithms", "experiment_key"}
SPLIT_ISSUE_KEYS = {"layer", "algorithm", "delivery", "cookie_names", "token_bytes", "chunks",
                    "chunk_bytes", "set_cookie_bytes", "claims", "pad", "attrs",
                    "experiment_key"}
APP_LOG_MESSAGE = re.compile(r'^(?P<remote>\S+) "(?P<method>\S+) (?P<target>\S+) '
                             r'(?P<protocol>\S+)" (?P<status>\d{3}) ?(?P<fields>.*)$')

# R12's cases: name, expected status, source, whether verify_token runs, and the expected
# chunks object (None when the body has none).
CASE_NAMES = ("in_order", "reversed", "rotated", "among_other_cookies", "missing_0",
              "missing_1", "missing_2", "duplicate", "conflicting_count", "out_of_range_index",
              "mixed_tokens", "with_jwt_cookie", "with_bearer")
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
# The helpers R23 says transport_cookies imports, by the module that defines them.
SHARED_HELPERS = {
    "scripts.transport_claims": ("check_output_dir", "without_tokens", "save_stack_evidence",
                                 "phase_run_dir", "require_playwright", "total_ms",
                                 "mean_components_ms"),
    "scripts.transport_tokens": ("run_pair", "judge", "failed_request_layer", "BrowserLog",
                                 "PageTraffic", "BrowserRequest", "nonce_url", "send_fetch",
                                 "load_test_page", "read_cookie_jar", "browser_identity",
                                 "wait_for_proxy_log", "read_lines", "lines_mentioning",
                                 "quote", "json_object", "selected_algorithms"),
    "scripts.transport_load": ("checked_settings", "check_seconds", "run_load",
                               "write_load_results", "save_logs", "run_environment",
                               "LATENCY_COMPONENTS", "NETWORK_PROFILES"),
    "scripts.transport_stack": ("start_stack", "nginx_size", "load_manifest",
                                "manifest_layers", "http_get", "BROWSER_CHANNEL"),
}
# R8 has transport_cookies define its own checked_settings, built on transport_load's.
OWN_NAMES = {"checked_settings"}
# Helpers every cookies run needs (R8, R10-R14): these must be imported. The others in
# SHARED_HELPERS must come from their module whenever the module uses them.
CORE_HELPERS = {
    "scripts.transport_claims": ("check_output_dir", "without_tokens", "save_stack_evidence",
                                 "phase_run_dir", "require_playwright"),
    "scripts.transport_tokens": ("run_pair", "judge", "failed_request_layer"),
    "scripts.transport_load": ("checked_settings", "run_load", "write_load_results",
                               "run_environment"),
    "scripts.transport_stack": ("start_stack",),
}
CLAIMS_API = ("run_claims", "default_settings", "checked_settings", "read_saved_settings",
              "token_sizes", "sprint2_boundaries", "summary_lines")

IMPORT_CHECK = """\
import json
import os
import subprocess
import sys
import threading
sys.path.insert(0, sys.argv[1])
import scripts.transport_cookies as cookies
rows = len(cookies.chunk_plan(["ML-DSA-44"])) if sys.argv[2] == "plan" else None
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
print(json.dumps(sorted(name for name in ("scripts.transport_cookies", "scripts.transport_load",
                                          "scripts.transport_claims", "scripts.token_sizing",
                                          "scripts.algorithms", "cryptography", "playwright")
                        if name in sys.modules)))
"""


# ---- the modules under test --------------------------------------------------------------

def module():
    """Return scripts.transport_cookies, failing the calling test when it cannot be imported."""
    if transport_cookies is None:
        raise AssertionError(f"scripts/transport_cookies.py cannot be imported: "
                             f"{COOKIES_IMPORT_ERROR!r}")
    return transport_cookies


def claims_module():
    """Return scripts.transport_claims, failing the calling test when it cannot be imported."""
    if transport_claims is None:
        raise AssertionError(f"scripts/transport_claims.py cannot be imported: "
                             f"{CLAIMS_IMPORT_ERROR!r}")
    return transport_claims


def app_api(name: str):
    """An attribute R1-R5 add to scripts/transport_app.py, failing the test when it is missing."""
    if not hasattr(transport_app, name):
        raise AssertionError(f"scripts/transport_app.py has no {name}")
    return getattr(transport_app, name)


def split_carrier():
    """transport_load.CARRIERS['split'], failing the calling test when it is missing."""
    carrier = transport_load.CARRIERS.get("split")
    if carrier is None:
        raise AssertionError("transport_load.CARRIERS has no 'split' carrier")
    return carrier


# ---- what the spec says, computed independently ---------------------------------------------

def default_count(total: int) -> int:
    """R1's default number of chunks for a token of total characters."""
    return max(1, math.ceil(total / SPLIT_CHUNK_BYTES))


def chunk_sizes(total: int, count: int | None = None) -> list[int]:
    """R1's near-equal chunk sizes: the first total % count chunks carry one more character."""
    count = default_count(total) if count is None else count
    return [total // count + (1 if index < total % count else 0) for index in range(count)]


def chunk_names(count: int) -> list[str]:
    return [f"jwt.{index}.{count}" for index in range(count)]


def expected_chunks(token: str, count: int | None = None) -> list[tuple[str, str]]:
    """R1's (name, value) pairs for a token, from the spec alone."""
    sizes = chunk_sizes(len(token), count)
    pairs, start = [], 0
    for name, size in zip(chunk_names(len(sizes)), sizes):
        pairs.append((name, token[start:start + size]))
        start += size
    return pairs


def split_line_bytes(total: int, count: int | None = None) -> int:
    """R7's Cookie header line, CRLF included, for the split of a total-byte token."""
    names = chunk_names(len(chunk_sizes(total, count)))
    return (len("Cookie: \r\n") + total + sum(len(name) + 1 for name in names)
            + 2 * (len(names) - 1))


def split_set_cookie_bytes(total: int, count: int | None = None,
                           attributes: str = FULL_ATTRIBUTES) -> int:
    """R9's sum of every chunk's Set-Cookie line, CRLF included."""
    sizes = chunk_sizes(total, count)
    return sum(len(f"Set-Cookie: {name}=; {attributes}\r\n") + size
               for name, size in zip(chunk_names(len(sizes)), sizes))


def largest_name_value(total: int, count: int | None = None) -> int:
    sizes = chunk_sizes(total, count)
    return max(len(name) + size for name, size in zip(chunk_names(len(sizes)), sizes))


def manifest_limits() -> tuple[int, int]:
    """transport/stack.json's browser cookie limit and proxy single_header limit."""
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return (layers["browser"]["limits"]["cookie"]["bytes"],
            layers["proxy"]["limits"]["single_header"]["bytes"])


def expected_plan_row(algorithm: str, claims: str = "oidc") -> dict:
    """R9's row for one configuration, computed from the spec's formulas."""
    cookie_limit, line_limit = manifest_limits()
    total = token_bytes(algorithm, claim_set(claims))
    count = default_count(total)
    name_value = {"cookie": len("jwt") + total, "split": largest_name_value(total)}
    set_cookie = {"cookie": len(f"Set-Cookie: jwt=; {FULL_ATTRIBUTES}\r\n") + total,
                  "split": split_set_cookie_bytes(total)}
    cookie_line = {"cookie": len("Cookie: jwt=\r\n") + total, "split": split_line_bytes(total)}
    return {
        "algorithm": algorithm, "token_bytes": total, "chunks": count,
        "chunk_bytes": chunk_sizes(total), "cookie_names": chunk_names(count),
        "name_value_bytes": name_value, "set_cookie_bytes": set_cookie,
        "cookie_line_bytes": cookie_line,
        "fits": {"cookie": {"per_cookie": name_value["cookie"] <= cookie_limit,
                            "cookie_line": cookie_line["cookie"] <= line_limit},
                 "split": {"per_cookie": name_value["split"] <= cookie_limit,
                           "cookie_count": count <= DOMAIN_MAX_COOKIES,
                           "cookie_line": cookie_line["split"] <= line_limit}},
    }


def random_token(length: int, seed: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_."
    generator = random.Random(seed)
    return "".join(generator.choice(alphabet) for _ in range(length))


def git_show(path: str) -> str | None:
    """Return a file as committed at BASE_COMMIT, or None when git or the commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), "show", f"{BASE_COMMIT}:{path}"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def run_python(code: str, *arguments: str) -> subprocess.CompletedProcess:
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, "-c", code, *arguments], cwd=REPO, env=environment,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


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
        path = Path(directory) / "transport_app_6f50c93.py"
        path.write_text(text, encoding="utf-8")
        # A name inside the scripts package, so the module does not change sys.path.
        spec = importlib.util.spec_from_file_location("scripts._transport_app_6f50c93", path)
        base = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(base)
    for name in ("EXPERIMENT_KEYS", "EXPERIMENT_KEYS_LOCK", "TEST_PAGE"):
        setattr(base, name, getattr(transport_app, name))
    return base


def json_body(data: bytes) -> dict:
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
    return [value for name, value in response.headers if name.lower() == "set-cookie"]


def issued_chunks(response: SimpleNamespace) -> list[tuple[str, str]]:
    """The (name, value) pair of every Set-Cookie header of a split issue response, in order."""
    pairs = []
    for value in set_cookies(response):
        name, _, rest = value.split(";", 1)[0].partition("=")
        pairs.append((name, rest))
    return pairs


def cookie_header(pairs) -> str:
    return "; ".join(f"{name}={value}" for name, value in pairs)


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
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def foreign_alg_token() -> str:
    """A well-formed token whose header names HS256, which no adapter handles."""
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': 'x'})}.c2ln"


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


# ---- R1: the chunk format ----------------------------------------------------------------

class SplitTokenTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(app_api("SPLIT_CHUNK_BYTES"), SPLIT_CHUNK_BYTES)
        self.assertEqual(app_api("SPLIT_MAX_CHUNKS"), SPLIT_MAX_CHUNKS)

    def test_signature(self):
        parameters = inspect.signature(app_api("split_token")).parameters
        self.assertEqual(list(parameters), ["token", "chunks"])
        self.assertIsNone(parameters["chunks"].default)

    def test_the_spec_example(self):
        split_token = app_api("split_token")
        self.assertEqual(split_token("abcdefghij", 3),
                         [("jwt.0.3", "abcd"), ("jwt.1.3", "efg"), ("jwt.2.3", "hij")])

    def test_default_value_sizes(self):
        split_token = app_api("split_token")
        for total, sizes in ((1, [1]), (4000, [4000]), (4001, [2001, 2000]),
                             (4095, [2048, 2047]), (11353, [3785, 3784, 3784]),
                             (23662, [3944, 3944, 3944, 3944, 3943, 3943])):
            with self.subTest(token_bytes=total):
                token = random_token(total, total)
                pairs = split_token(token)
                self.assertIsInstance(pairs, list)
                self.assertEqual([len(value) for _, value in pairs], sizes)
                self.assertEqual([name for name, _ in pairs], chunk_names(len(sizes)))
                self.assertEqual("".join(value for _, value in pairs), token)
                self.assertEqual(split_token(token, None), pairs)

    def test_names_sizes_and_round_trips(self):
        split_token = app_api("split_token")
        generator = random.Random(628)
        totals = [2, 3, 7, 999, 1000, 1001, 3999, 8000, 8001, 12345, 40001, 123457]
        for total in totals:
            token = random_token(total, total)
            counts = {1, 2, min(total, SPLIT_MAX_CHUNKS), min(total, 11),
                      generator.randint(1, min(total, SPLIT_MAX_CHUNKS))}
            for count in sorted(counts):
                with self.subTest(token_bytes=total, chunks=count):
                    pairs = split_token(token, count)
                    self.assertEqual(pairs, expected_chunks(token, count))
                    for pair in pairs:
                        self.assertIsInstance(pair, tuple)
                        self.assertEqual(len(pair), 2)
                    self.assertEqual("".join(value for _, value in pairs), token)
                    sizes = [len(value) for _, value in pairs]
                    self.assertLessEqual(max(sizes) - min(sizes), 1)
                    self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_tokens_of_4000_bytes_or_less_are_one_chunk(self):
        split_token = app_api("split_token")
        for total in (1, 208, 948, 1204, 3999, 4000):
            with self.subTest(token_bytes=total):
                token = random_token(total, total)
                self.assertEqual(split_token(token), [("jwt.0.1", token)])

    def test_invalid_chunk_counts_raise(self):
        split_token = app_api("split_token")
        short, long = random_token(5, 1), random_token(5000, 2)
        cases = [(short, 0), (short, 6), (short, -1), (short, True), (short, False),
                 (short, 2.0), (short, "2"), (long, 0), (long, SPLIT_MAX_CHUNKS + 1),
                 (long, 5001), (long, 3.5), (long, [2])]
        for token, count in cases:
            with self.subTest(token_bytes=len(token), chunks=count):
                with self.assertRaises(ValueError):
                    split_token(token, count)
        self.assertEqual(len(split_token(short, 5)), 5)
        self.assertEqual(len(split_token(long, SPLIT_MAX_CHUNKS)), SPLIT_MAX_CHUNKS)

    def test_empty_token_raises(self):
        split_token = app_api("split_token")
        for count in (None, 1):
            with self.subTest(chunks=count), self.assertRaises(ValueError):
                split_token("", count)


# ---- R2: parsing chunk cookies -----------------------------------------------------------

class ChunkCookiesTests(unittest.TestCase):
    def test_parses_in_header_order_and_keeps_repeats(self):
        chunk_cookies = app_api("chunk_cookies")
        header = "jwt.1.2=b; a=1; jwt.0.2=a; jwt.1.2=c;jwt.0.1=x=y; theme=dark"
        self.assertEqual(chunk_cookies(header),
                         [(1, 2, "b"), (0, 2, "a"), (1, 2, "c"), (0, 1, "x=y")])

    def test_returns_a_list_of_int_int_str(self):
        result = app_api("chunk_cookies")("jwt.0.1=abc")
        self.assertEqual(result, [(0, 1, "abc")])
        index, count, value = result[0]
        self.assertIs(type(index), int)
        self.assertIs(type(count), int)
        self.assertIsInstance(value, str)

    def test_strips_pairs_and_splits_at_the_first_equals(self):
        chunk_cookies = app_api("chunk_cookies")
        self.assertEqual(chunk_cookies("  jwt.0.2=ab==  ;   jwt.1.2=  "),
                         [(0, 2, "ab=="), (1, 2, "")])

    def test_number_forms(self):
        chunk_cookies = app_api("chunk_cookies")
        accepted = {"jwt.0.0=v": (0, 0), "jwt.9999999.1=v": (9999999, 1),
                    "jwt.0.9999999=v": (0, 9999999), "jwt.1234567.7654321=v": (1234567, 7654321),
                    "jwt.10.20=v": (10, 20)}
        for header, (index, count) in accepted.items():
            with self.subTest(header=header):
                self.assertEqual(chunk_cookies(header), [(index, count, "v")])

    def test_other_names_are_ignored(self):
        chunk_cookies = app_api("chunk_cookies")
        ignored = ["jwt", "JWT", "xjwt", "jwt_old", "jwt2", "jwtx", "jwt.1", "jwt.01.3",
                   "jwt.1.03", "jwt.00.1", "jwt.1.3.x", "jwt.1.3.", ".jwt.1.3", "jwt..1.3",
                   "jwt.1..3", "JWT.0.1", "Jwt.0.1", "jwt.10000000.1", "jwt.1.10000000",
                   "jwt.12345678.12345678", "jwt.+1.3", "jwt.-1.3", "jwt.1.-3", "jwt. 1.3",
                   "jwt.1_0.30", "jwt.1.3_0", "jwt.0x1.3", "jwt.1e2.3", "jwt.1.3x", "jwt.a.3",
                   "jwt.².3", "xjwt.0.1", "jwt.0.1x", "jwt-0-1", "jwt.0,1",
                   "jwt." + "1" * 5000 + ".3", "jwt.1." + "9" * 5000,
                   "jwt." + "0" * 5000 + ".1"]
        for name in ignored:
            with self.subTest(name=name[:40]):
                self.assertEqual(chunk_cookies(f"{name}=value"), [])
                self.assertEqual(chunk_cookies(f"{name}=value; jwt.0.1=kept"), [(0, 1, "kept")])

    def test_pairs_without_equals_are_ignored(self):
        chunk_cookies = app_api("chunk_cookies")
        for header in ("jwt.0.1", "jwt.0.1;", ";jwt.0.1", "jwt.0.1 ; jwt.1.2"):
            with self.subTest(header=header):
                self.assertEqual(chunk_cookies(header), [])
        self.assertEqual(chunk_cookies("jwt.0.1; jwt.1.2=b"), [(1, 2, "b")])

    def test_none_and_empty_input(self):
        chunk_cookies = app_api("chunk_cookies")
        for header in (None, "", ";", ";;;", "   ", "=", "==", "; = ;"):
            with self.subTest(header=header):
                self.assertEqual(chunk_cookies(header), [])

    def test_never_raises_and_returns_what_the_header_holds(self):
        chunk_cookies = app_api("chunk_cookies")
        generator = random.Random(4096)
        alphabet = "jwt.0123456789;= ,_-+xJ\x00ÿ١²\t"
        headers = ["".join(generator.choice(alphabet) for _ in range(generator.randint(0, 40)))
                   for _ in range(2000)]
        headers += ["jwt.١.٣=x", "jwt.0.١=x", "jwt.².3=x",
                    "jwt." + "١" * 5000 + ".1=x", "\udcff=jwt.0.1", "jwt.0.1=\udcff"]
        for header in headers:
            with self.subTest(header=header[:40]):
                result = chunk_cookies(header)
                self.assertIsInstance(result, list)
                for index, count, value in result:
                    self.assertIs(type(index), int)
                    self.assertIs(type(count), int)
                    self.assertTrue(0 <= index < 10_000_000 and 0 <= count < 10_000_000)
                    self.assertIn(f"jwt.{index}.{count}={value}", header)


# ---- R3: reassembly ----------------------------------------------------------------------

class ReassembleChunksTests(unittest.TestCase):
    def reassemble(self, chunks):
        return app_api("reassemble_chunks")(chunks)

    def raised(self, chunks):
        error_class = app_api("ChunkError")
        with self.assertRaises(error_class) as raised:
            self.reassemble(chunks)
        return raised.exception

    def test_chunk_error_is_a_value_error(self):
        self.assertTrue(issubclass(app_api("ChunkError"), ValueError))

    def test_joins_in_index_order_whatever_the_arrival_order(self):
        token = random_token(1000, 7)
        pairs = expected_chunks(token, 5)
        chunks = [(index, 5, value) for index, (_, value) in enumerate(pairs)]
        generator = random.Random(5)
        for _ in range(20):
            shuffled = list(chunks)
            generator.shuffle(shuffled)
            with self.subTest(order=[index for index, _, _ in shuffled]):
                self.assertEqual(self.reassemble(shuffled), token)
        self.assertEqual(self.reassemble([(0, 1, "only")]), "only")
        self.assertEqual(self.reassemble(((1, 2, "b"), (0, 2, "a"))), "ab")

    def test_disagreeing_counts_are_400_without_a_count(self):
        for chunks in ([(0, 2, "a"), (1, 3, "b")], [(0, 3, "a"), (1, 3, "b"), (2, 3, "c"),
                                                     (0, 2, "a")],
                       [(0, 2, "a"), (0, 2, "a"), (5, 9, "b")],  # Also repeated and out of range.
                       [(0, 0, "a"), (0, 1, "b")]):
            with self.subTest(chunks=chunks):
                error = self.raised(chunks)
                self.assertEqual(error.status, 400)
                self.assertIsNone(error.count)
                self.assertEqual(list(error.received), [index for index, _, _ in chunks])
                self.assertEqual(error.missing, [])

    def test_counts_out_of_range_are_400_with_the_count(self):
        for count in (0, SPLIT_MAX_CHUNKS + 1, 9999999):
            chunks = [(0, count, "a"), (5, count, "b")]
            with self.subTest(count=count):
                error = self.raised(chunks)
                self.assertEqual(error.status, 400)
                self.assertEqual(error.count, count)
                self.assertEqual(list(error.received), [0, 5])
                self.assertEqual(error.missing, [])

    def test_indices_out_of_range_are_400(self):
        for chunks in ([(0, 2, "a"), (2, 2, "b")], [(3, 3, "x"), (0, 3, "a")],
                       [(0, 3, "a"), (7, 3, "b")]):  # Out of range, not missing chunks.
            with self.subTest(chunks=chunks):
                error = self.raised(chunks)
                self.assertEqual(error.status, 400)
                self.assertEqual(error.count, chunks[0][1])
                self.assertEqual(list(error.received), [index for index, _, _ in chunks])
                self.assertEqual(error.missing, [])

    def test_repeated_indices_are_400(self):
        for chunks in ([(0, 2, "a"), (0, 2, "a"), (1, 2, "b")], [(0, 3, "a"), (0, 3, "x")],
                       [(1, 2, "b"), (0, 2, "a"), (1, 2, "b")]):  # Repeated, also incomplete.
            with self.subTest(chunks=chunks):
                error = self.raised(chunks)
                self.assertEqual(error.status, 400)
                self.assertEqual(error.count, chunks[0][1])
                self.assertEqual(list(error.received), [index for index, _, _ in chunks])
                self.assertEqual(error.missing, [])

    def test_missing_indices_are_401_and_named(self):
        for chunks, missing in (([(1, 3, "b"), (2, 3, "c")], [0]),
                                ([(2, 3, "c"), (0, 3, "a")], [1]),
                                ([(0, 3, "a")], [1, 2]),
                                ([(4, 6, "e"), (1, 6, "b")], [0, 2, 3, 5]),
                                ([(0, 1000, "a")], list(range(1, 1000)))):
            with self.subTest(received=[index for index, _, _ in chunks]):
                error = self.raised(chunks)
                self.assertEqual(error.status, 401)
                self.assertEqual(error.count, chunks[0][1])
                self.assertEqual(list(error.received), [index for index, _, _ in chunks])
                self.assertEqual(error.missing, missing)
                self.assertIsInstance(error.missing, list)
                text = str(error)
                self.assertIn("missing", text)
                if len(missing) <= 10:
                    for index in missing:
                        self.assertRegex(text, rf"(?<!\d){index}(?!\d)")


# ---- R4-R6: the application, in process --------------------------------------------------

class ApplicationCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = base_application()

    def require_base(self):
        if self.base is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        return self.base

    @staticmethod
    def call(target: str, headers: dict | None = None) -> SimpleNamespace:
        return wsgi_call(transport_app.application, target, headers)

    def issue_split(self, **query) -> tuple[SimpleNamespace, dict]:
        response = self.call(f"{ISSUE_PATH}?{urlencode({**query, 'delivery': 'split'})}")
        return response, json_body(response.body)

    def split_chunks(self, algorithm: str, count: int, **query) -> list[tuple[str, str]]:
        response, body = self.issue_split(alg=algorithm, chunks=str(count), **query)
        self.assertEqual(response.code, 200, body)
        return issued_chunks(response)

    def body_token(self, algorithm: str, **query) -> str:
        query = {"alg": algorithm, "delivery": "body", **query}
        response = self.call(f"{ISSUE_PATH}?{urlencode(query)}")
        self.assertEqual(response.code, 200)
        return json_body(response.body)["token"]


class VerifySplitTests(ApplicationCase):
    """R4: the split source, R12's cases in process, and the other sources unchanged."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cases, cls.token_a, cls.error = None, None, None
        try:
            cls.prepare()
        except Exception as error:  # Reported by every test instead of failing setUpClass.
            cls.error = error

    @classmethod
    def prepare(cls):
        query = {"alg": "ML-DSA-44", "claims": "oidc", "delivery": "split", "chunks": "3"}
        a = cls.call(f"{ISSUE_PATH}?{urlencode(query)}")
        b = cls.call(f"{ISSUE_PATH}?{urlencode({**query, 'pad': '1'})}")
        if a.code != 200 or b.code != 200:
            raise AssertionError(f"the split issue answered {a.code} and {b.code}")
        a_chunks, b_chunks = issued_chunks(a), issued_chunks(b)
        cls.token_a = "".join(value for _, value in a_chunks)
        a0, a1, a2 = a_chunks
        extra = ("jwt.0.2", cls.token_a[:chunk_sizes(len(cls.token_a), 2)[0]])
        cls.cases = {
            "in_order": ([a0, a1, a2], False),
            "reversed": ([a2, a1, a0], False),
            "rotated": ([a1, a2, a0], False),
            "among_other_cookies": ([("a", "1"), a2, ("jwt_old", "x"), a0, ("theme", "dark"),
                                     a1], False),
            "missing_0": ([a1, a2], False),
            "missing_1": ([a0, a2], False),
            "missing_2": ([a0, a1], False),
            "duplicate": ([a0, a1, a1, a2], False),
            "conflicting_count": ([a0, a1, a2, extra], False),
            "out_of_range_index": ([a0, a1, a2, ("jwt.3.3", "x")], False),
            "mixed_tokens": ([a0, b_chunks[1], a2], False),
            "with_jwt_cookie": ([a0, a1, a2, ("jwt", cls.token_a)], False),
            "with_bearer": ([a0, a1, a2], True),
        }

    def setUp(self):
        self.assertIsNone(self.error, f"preparing the cases raised {self.error!r}")

    def case_headers(self, name: str) -> dict:
        pairs, bearer = self.cases[name]
        headers = {"Cookie": cookie_header(pairs)}
        if bearer:
            headers["Authorization"] = f"Bearer {self.token_a}"
        return headers

    def check_timing(self, timing, verify_called: bool) -> None:
        self.assertIsInstance(timing, dict)
        self.assertEqual(set(timing), {"verify_ns", "handler_ns"})
        self.assertIs(type(timing["handler_ns"]), int)
        if verify_called:
            self.assertIs(type(timing["verify_ns"]), int)
            self.assertLessEqual(timing["verify_ns"], timing["handler_ns"])
        else:
            self.assertIsNone(timing["verify_ns"])

    def test_the_issued_chunks_follow_r1(self):
        self.assertEqual(len(self.token_a), TOKEN_BYTES_OIDC["ML-DSA-44"])
        self.assertEqual(self.cases["in_order"][0], app_api("split_token")(self.token_a, 3))

    def test_cases_statuses_and_bodies(self):
        self.assertEqual(list(self.cases), list(CASE_NAMES))
        for name in CASE_NAMES:
            with self.subTest(case=name):
                response = self.call(f"{VERIFY_PATH}?timing=1&nonce={'a' * 32}",
                                     self.case_headers(name))
                body = json_body(response.body)
                self.assertEqual(response.code, CASE_STATUSES[name], body)
                self.assertEqual([header for header, _ in response.headers],
                                 ["Content-Type", "Content-Length"])
                self.check_timing(body.get("timing"), name in VERIFY_CALLED)
                chunks = CASE_CHUNKS[name]
                if response.code == 200:
                    self.assertEqual(set(body), VERIFIED_KEYS | {"chunks", "timing"})
                    self.assertIs(body["verified"], True)
                    self.assertEqual(body["algorithm"], "ML-DSA-44")
                    self.assertEqual(body["token_bytes"], len(self.token_a))
                    self.assertEqual(body["claims"], claim_set("oidc"))
                elif chunks is not None:
                    self.assertEqual(set(body), FAILED_KEYS | {"chunks", "timing"})
                    self.assertIs(body["verified"], False)
                else:
                    self.assertEqual(set(body), FAILED_KEYS | {"timing"})
                    self.assertIsNone(body["source"])
                    self.assertTrue(body["error"].startswith("more than one token"),
                                    body["error"])
                if chunks is not None:
                    self.assertEqual(body["source"], "split")
                    self.assertEqual(body["chunks"], chunks)
                self.assertEqual(body["layer"], "application")
                self.assertIs(body["experiment_key"], True)

    def test_chunk_errors_are_reported_as_raised(self):
        chunk_cookies, reassemble = app_api("chunk_cookies"), app_api("reassemble_chunks")
        for name in ("missing_0", "missing_1", "missing_2", "duplicate", "conflicting_count",
                     "out_of_range_index"):
            with self.subTest(case=name):
                headers = self.case_headers(name)
                with self.assertRaises(app_api("ChunkError")) as raised:
                    reassemble(chunk_cookies(headers["Cookie"]))
                response = self.call(VERIFY_PATH, headers)
                body = json_body(response.body)
                self.assertEqual(response.code, raised.exception.status)
                self.assertEqual(body["error"], str(raised.exception))
                self.assertEqual(body["chunks"], {"count": raised.exception.count,
                                                  "received": list(raised.exception.received),
                                                  "missing": raised.exception.missing})
                if name.startswith("missing_"):
                    self.assertIn("missing", body["error"])
                    self.assertIn(name[-1], body["error"])

    def test_mixed_tokens_fail_verification(self):
        response = self.call(f"{VERIFY_PATH}?timing=1", self.case_headers("mixed_tokens"))
        body = json_body(response.body)
        self.assertEqual(response.code, 401)
        self.assertIs(type(body["timing"]["verify_ns"]), int)
        self.assertEqual(body["chunks"], CASE_CHUNKS["mixed_tokens"])
        self.assertEqual(body["source"], "split")

    def test_failure_keys_without_timing(self):
        for name in CASE_NAMES:
            with self.subTest(case=name):
                body = json_body(self.call(VERIFY_PATH, self.case_headers(name)).body)
                self.assertNotIn("timing", body)
                extra = set() if CASE_CHUNKS[name] is None else {"chunks"}
                base = VERIFIED_KEYS if CASE_STATUSES[name] == 200 else FAILED_KEYS
                self.assertEqual(set(body), base | extra)

    def test_timing_works_as_for_other_sources(self):
        headers = self.case_headers("in_order")
        plain = self.call(VERIFY_PATH, headers)
        timed = self.call(f"{VERIFY_PATH}?timing=1", headers)
        other = self.call(f"{VERIFY_PATH}?timing=0", headers)
        body = json_body(timed.body)
        self.assertEqual({key: value for key, value in body.items() if key != "timing"},
                         json_body(plain.body))
        self.assertEqual((other.status, other.headers, other.body),
                         (plain.status, plain.headers, plain.body))

    def test_chunk_cookies_with_another_source_are_400(self):
        token = self.token_a
        chunk = self.cases["in_order"][0][0]
        requests = {
            "valid chunks and jwt": {"Cookie": cookie_header([*self.cases["in_order"][0],
                                                              ("jwt", token)])},
            "one chunk and jwt": {"Cookie": f"{chunk[0]}={chunk[1]}; jwt={token}"},
            "jwt before chunks": {"Cookie": f"jwt={token}; " + cookie_header(
                self.cases["in_order"][0])},
            "incomplete chunks and bearer": {"Cookie": f"{chunk[0]}={chunk[1]}",
                                             "Authorization": f"Bearer {token}"},
            "bad count and jwt": {"Cookie": f"jwt.0.0=x; jwt={token}"},
            "chunk and two jwt": {"Cookie": "jwt=a; jwt.0.1=b; jwt=c"},
            "chunk, jwt, and bearer": {"Cookie": f"jwt.0.1={token}; jwt={token}",
                                       "Authorization": f"Bearer {token}"},
        }
        for name, headers in requests.items():
            for query in ("", "?timing=1"):
                with self.subTest(request=name, query=query):
                    response = self.call(f"{VERIFY_PATH}{query}", headers)
                    body = json_body(response.body)
                    self.assertEqual(response.code, 400)
                    self.assertTrue(body["error"].startswith("more than one token"), body)
                    self.assertIsNone(body["source"])
                    self.assertEqual(set(body), FAILED_KEYS | ({"timing"} if query else set()))
                    if query:
                        self.assertIsNone(body["timing"]["verify_ns"])

    def test_split_tokens_are_checked_like_other_sources(self):
        es256 = self.body_token("ES256")
        mldsa = self.body_token("ML-DSA-44", claims="oidc")
        tokens = {"ES256": es256, "ML-DSA-44 oidc": mldsa, "tampered": tampered(es256),
                  "tampered ML-DSA-44": tampered(mldsa), "foreign alg": foreign_alg_token(),
                  "not a token": "not-a-token", "empty": "", "header only": b64({"alg": "ES256"}),
                  "deep header": b64(b"[" * 50000) + ".e30.c2ln"}
        split_token = app_api("split_token")
        for name, token in tokens.items():
            counts = [None] if len(token) < 3 else [None, 3]
            for count in counts:
                with self.subTest(token=name, chunks=count):
                    pairs = (split_token(token, count) if token else [("jwt.0.1", "")])
                    split = self.call(f"{VERIFY_PATH}?timing=1",
                                      {"Cookie": cookie_header(pairs)})
                    cookie = self.call(f"{VERIFY_PATH}?timing=1", {"Cookie": f"jwt={token}"})
                    self.assertEqual(split.code, cookie.code)
                    split_body, cookie_body = json_body(split.body), json_body(cookie.body)
                    self.assertEqual(split_body["source"], "split")
                    self.assertEqual(split_body["chunks"], {
                        "count": len(pairs), "received": list(range(len(pairs))),
                        "missing": []})
                    for key in set(cookie_body) - {"source", "received", "timing"}:
                        self.assertEqual(split_body[key], cookie_body[key], key)
                    self.assertEqual(set(split_body), set(cookie_body) | {"chunks"})
                    self.assertEqual(split_body["timing"]["verify_ns"] is None,
                                     cookie_body["timing"]["verify_ns"] is None)

    def test_basic_authorization_is_not_another_token(self):
        headers = {"Cookie": cookie_header(self.cases["rotated"][0]),
                   "Authorization": "Basic dXNlcjpwYXNz"}
        response = self.call(VERIFY_PATH, headers)
        body = json_body(response.body)
        self.assertEqual(response.code, 200, body)
        self.assertEqual(body["source"], "split")

    def test_malformed_input_never_gets_500(self):
        header = b64({"alg": "ES256", "typ": "JWT"})
        cookies = [
            "jwt.0.1=", "jwt.0.1===", "jwt.0.1=a.b.c", "jwt.0.1=" + "A" * 5000,
            "jwt.0.2=eyJ; jwt.1.2=..", "jwt.0.0=x", "jwt.0.1000=x", "jwt.0.1001=x",
            "jwt.999.1000=x", "jwt.9999999.9999999=x", "jwt.1.1=x", "jwt.0.2=x; jwt.0.3=y",
            "jwt.0.1=%00%ff", "jwt.0.1=ÿþ", "jwt.0.1=\x7f", "jwt.0.2=e30; jwt.1.2=.e30.",
            f"jwt.0.2={header}.; jwt.1.2=!!!.c2ln", f"jwt.0.1={header}.{b64(b'[' * 50000)}.x",
            "jwt.1.2=a; jwt.1.2=a", "jwt.0.1=a; jwt.0.1=a", "jwt.0.3=a; jwt.5.3=b; jwt.5.3=c",
            "jwt.0.2=a; jwt.1.2=b; jwt.2.2=c; jwt.0.3=d",
        ]
        for value in cookies:
            for query in ("", "?timing=1"):
                with self.subTest(cookie=value[:60], query=query):
                    response = self.call(f"{VERIFY_PATH}{query}", {"Cookie": value})
                    self.assertIn(response.code, (400, 401), response.body[:300])
                    body = json_body(response.body)
                    self.assertEqual(body["layer"], "application")
                    self.assertEqual(body["source"], "split")
                    self.assertIn("chunks", body)


class UnchangedVerifyTests(ApplicationCase):
    """R4: every request without a chunk cookie gets 6f50c93's response and log line."""

    def test_requests_without_chunk_cookies_are_unchanged(self):
        base = self.require_base()
        es256, eddsa = self.body_token("ES256"), self.body_token("EdDSA")
        cookie_values = [
            f"jwt={es256}", f"jwt={eddsa}; jwt={es256}", f"jwt.01.3=x; jwt={es256}",
            f"jwt.1=x; jwt={eddsa}", f"jwt.1.3.x=y; jwt={es256}", "JWT.0.1=x", "xjwt.0.1=x",
            f"jwt_old=x; jwt2=y; jwtx=z; jwt={eddsa}", "jwt.12345678.1=x", "jwt.+1.2=x",
            "jwt.1_0.20=x", "jwt.0.1", f"a=1; jwt={tampered(es256)}", "jwt=not-a-token",
            f"jwt={foreign_alg_token()}", "theme=dark", "jwt=",
        ]
        requests = [(VERIFY_PATH, {"Cookie": value}) for value in cookie_values]
        requests += [
            (VERIFY_PATH, {}),
            (VERIFY_PATH, {"Authorization": f"Bearer {es256}"}),
            (VERIFY_PATH, {"Authorization": f"Bearer {es256}", "Cookie": f"jwt={eddsa}"}),
            (VERIFY_PATH, {"Authorization": f"Bearer {es256}", "Cookie": "jwt.01.2=x"}),
            (f"{VERIFY_PATH}?timing=0&nonce={'b' * 32}", {"Authorization": f"Bearer {eddsa}"}),
            ("/api/echo?x=y", {"Cookie": "jwt.0.1=abc", "X-Test": "1"}),
            ("/", {}), ("/missing", {"Cookie": "jwt.0.1=abc"}),
        ]
        for target, headers in requests:
            with self.subTest(target=target, headers=sorted(headers.items())):
                new = self.call(target, headers)
                old = wsgi_call(base.application, target, headers)
                self.assertEqual((new.status, new.headers, new.body),
                                 (old.status, old.headers, old.body))
                self.assertEqual(new.log, old.log)

    def test_timed_requests_without_chunk_cookies_are_unchanged(self):
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


class IssueSplitTests(ApplicationCase):
    """R5: delivery=split, the chunks parameter, and the other deliveries unchanged."""

    def check_split_response(self, response: SimpleNamespace, body: dict, query: dict) -> None:
        algorithm = query["alg"]
        claims = query.get("claims", "minimal")
        pad = int(query.get("pad", "0"))
        attrs = query.get("attrs", "default")
        expected_claims = padded_claims(claim_set(claims), pad)
        total = token_bytes(algorithm, expected_claims)
        count = int(query["chunks"]) if "chunks" in query else default_count(total)
        attributes = FULL_ATTRIBUTES if attrs == "full" else DEFAULT_ATTRIBUTES
        self.assertEqual(response.code, 200, body)
        self.assertEqual([name for name, _ in response.headers],
                         ["Content-Type", "Content-Length", *["Set-Cookie"] * count])
        self.assertEqual(dict(response.headers[:2])["Content-Length"], str(len(response.body)))
        self.assertEqual(set(body), SPLIT_ISSUE_KEYS)
        pairs = issued_chunks(response)
        token = "".join(value for _, value in pairs)
        self.assertEqual(len(token), total)
        self.assertEqual(pairs, expected_chunks(token, count))
        for value, (name, chunk) in zip(set_cookies(response), pairs):
            self.assertEqual(value, f"{name}={chunk}; {attributes}")
        self.assertEqual(body, {
            "layer": "application", "algorithm": algorithm, "delivery": "split",
            "cookie_names": chunk_names(count), "token_bytes": total, "chunks": count,
            "chunk_bytes": chunk_sizes(total, count),
            "set_cookie_bytes": [len(value) for value in set_cookies(response)],
            "claims": claims, "pad": pad, "attrs": attrs, "experiment_key": True})
        self.assertNotIn(token, response.body.decode("utf-8"))
        verified = self.call(VERIFY_PATH, {"Cookie": cookie_header(pairs)})
        verified_body = json_body(verified.body)
        self.assertEqual(verified.code, 200, verified_body)
        self.assertEqual(verified_body["source"], "split")
        self.assertEqual(verified_body["claims"], expected_claims)
        self.assertEqual(verified_body["token_bytes"], total)
        self.assertEqual(verified_body["chunks"], {"count": count,
                                                   "received": list(range(count)),
                                                   "missing": []})
        bearer = json_body(self.call(VERIFY_PATH, {"Authorization": f"Bearer {token}"}).body)
        self.assertIs(bearer["verified"], True)

    def test_split_delivery(self):
        queries = [{"alg": "ML-DSA-44", "claims": "oidc"},
                   {"alg": "ES256", "claims": "minimal", "attrs": "full"},
                   {"alg": "ES256", "claims": "oidc", "pad": "5", "attrs": "default",
                    "chunks": "3"},
                   {"alg": "EdDSA"},
                   {"alg": "RS256", "claims": "essential", "chunks": "2", "attrs": "full"},
                   {"alg": "ML-DSA-44", "claims": "essential", "chunks": "1"},
                   {"alg": "ML-DSA-44", "claims": "oidc", "pad": "4100", "attrs": "full"},
                   {"alg": "SLH-DSA-SHA2-128s", "claims": "oidc", "attrs": "full"},
                   {"alg": "SLH-DSA-SHA2-128f", "claims": "oidc"}]
        for query in queries:
            with self.subTest(query=query):
                response, body = self.issue_split(**query)
                self.check_split_response(response, body, query)

    def test_default_counts_for_oidc_tokens(self):
        for name, count in DEFAULT_CHUNKS_OIDC.items():
            with self.subTest(algorithm=name):
                response, body = self.issue_split(alg=name, claims="oidc")
                self.assertEqual(response.code, 200, body)
                self.assertEqual(body["chunks"], count)
                self.assertEqual(body["token_bytes"], TOKEN_BYTES_OIDC[name])
                self.assertEqual(len(set_cookies(response)), count)

    def test_chunks_parameter_bounds(self):
        accepted = [("ML-DSA-44", "oidc", "1000"), ("ES256", "minimal", "208"),
                    ("ES256", "oidc", "180"), ("ES256", "oidc", "181"), ("ES256", "oidc", "1")]
        for algorithm, claims, chunks in accepted:
            with self.subTest(algorithm=algorithm, chunks=chunks):
                query = {"alg": algorithm, "claims": claims, "chunks": chunks, "attrs": "full"}
                response, body = self.issue_split(**query)
                self.check_split_response(response, body, query)

    def test_invalid_chunks_get_400(self):
        cases = [("ML-DSA-44", "oidc", value) for value in
                 ("", "0", "1001", "9999", "10000", "-1", "abc", "1.5", "+3", " 3", "3 ",
                  "1e2", "٣", "1_0", "0x10", "3,4", "99999999999999999999")]
        cases += [("ES256", "minimal", "209"), ("ES256", "oidc", "949"),
                  ("ES256", "oidc", "1000")]
        for algorithm, claims, chunks in cases:
            with self.subTest(algorithm=algorithm, chunks=chunks):
                response, body = self.issue_split(alg=algorithm, claims=claims, chunks=chunks)
                self.assertEqual(response.code, 400, body)
                self.assertEqual(set(body), ISSUE_ERROR_KEYS)
                self.assertEqual(body["layer"], "application")
                self.assertEqual(body["algorithms"], NAMES)
                self.assertIs(body["experiment_key"], True)
                self.assertEqual(set_cookies(response), [])
                self.assertEqual(len(response.log), 1)
                self.assertTrue(response.log[0].endswith("chunks=-"), response.log[0])

    def test_other_problems_still_get_400(self):
        for query in ({"alg": "HS256"}, {}, {"alg": "ES256", "claims": "huge"},
                      {"alg": "ES256", "pad": "-1"}, {"alg": "ES256", "attrs": "bogus"}):
            with self.subTest(query=query):
                response, body = self.issue_split(**query)
                self.assertEqual(response.code, 400, body)
                self.assertEqual(set(body), ISSUE_ERROR_KEYS)
                self.assertEqual(set_cookies(response), [])
                self.assertTrue(response.log[0].endswith("chunks=-"), response.log[0])

    def test_failed_signing_gets_500_without_a_token(self):
        # A public key that does not match the private key makes the issued token fail its own
        # verification, so the application must answer 500 and send no token.
        adapter = ADAPTERS["ES256"]
        private_key, _ = adapter.generate_keypair()
        _, other_public_key = adapter.generate_keypair()
        mismatched = mock.patch.dict(transport_app.EXPERIMENT_KEYS,
                                     {"ES256": (private_key, other_public_key)})
        with mismatched:
            cookie = self.call(f"{ISSUE_PATH}?alg=ES256&claims=oidc&delivery=cookie")
            response, body = self.issue_split(alg="ES256", claims="oidc")
        self.assertEqual(cookie.code, 500, "the mismatched keys did not make signing fail")
        self.assertEqual(response.code, 500, body)
        self.assertEqual([name for name, _ in response.headers],
                         ["Content-Type", "Content-Length"])
        self.assertEqual(set_cookies(response), [])
        self.assertNotIn("token", body)
        self.assertNotIn("cookie_names", body)
        self.assertIs(body.get("experiment_key"), True)
        self.assertEqual(len(response.log), 1)
        self.assertTrue(response.log[0].endswith("chunks=-"), response.log[0])

    def test_other_deliveries_ignore_chunks(self):
        base = self.require_base()
        for delivery in ("cookie", "body"):
            for extra in ({}, {"claims": "oidc", "attrs": "full"}, {"pad": "3"}):
                for chunks in ("3", "abc", "0", "5000", ""):
                    query = {"alg": "EdDSA", "delivery": delivery, **extra, "chunks": chunks,
                             "nonce": "abc"}
                    target = f"{ISSUE_PATH}?{urlencode(query)}"
                    with self.subTest(target=target):
                        new = self.call(target)
                        old = wsgi_call(base.application, target)
                        self.assertEqual(normalized(new), normalized(old))

    def test_cookie_and_body_responses_unchanged(self):
        base = self.require_base()
        queries = ["", "&delivery=body", "&delivery=cookie", "&claims=oidc&attrs=full",
                   "&claims=essential&pad=5&delivery=body", "&delivery=cookies",
                   "&delivery=header", "&delivery=bearer", "&delivery=Split",
                   "&delivery=split%20", "&delivery="]
        for name in ("ES256", "ML-DSA-44"):
            for query in queries:
                target = f"{ISSUE_PATH}?alg={name}{query}&nonce=abc"
                with self.subTest(target=target):
                    new = self.call(target)
                    old = wsgi_call(base.application, target)
                    self.assertEqual(new.code, old.code)
                    if new.code == 400:
                        self.assertEqual(set(json_body(new.body)), ISSUE_ERROR_KEYS)
                        self.assertEqual(set_cookies(new), [])
                        self.assertEqual(new.log, old.log)
                    else:
                        self.assertEqual(normalized(new), normalized(old))
        for value in ("cookies", "header", "bearer"):
            with self.subTest(delivery=value):
                response = self.call(f"{ISSUE_PATH}?alg=ES256&delivery={value}")
                self.assertEqual(response.code, 400)

    def test_deliveries(self):
        self.assertEqual(tuple(app_api("DELIVERIES")), ("cookie", "body", "split"))


class SplitLogTests(ApplicationCase):
    """R6: the chunks field of app.log, and no value in any line."""

    def test_issue_lines_end_with_the_chunk_count(self):
        for algorithm, extra, count in (("ML-DSA-44", {"claims": "oidc"}, 2),
                                        ("ES256", {}, 1), ("ES256", {"chunks": "7"}, 7),
                                        ("SLH-DSA-SHA2-128s", {"claims": "oidc"}, 3)):
            with self.subTest(algorithm=algorithm, **extra):
                response, body = self.issue_split(alg=algorithm, **extra)
                self.assertEqual(response.code, 200, body)
                self.assertEqual(len(response.log), 1)
                target, fields = log_fields(response.log[0])
                self.assertTrue(target.startswith(ISSUE_PATH))
                self.assertEqual(fields[-1], f"chunks={count}")
                self.assertIn(f"alg={algorithm}", fields)
                self.assertIn(f"token_bytes={body['token_bytes']}", fields)
                for _, value in issued_chunks(response):
                    self.assertNotIn(value, response.log[0])
                self.assertIsNone(TOKEN_LIKE.search(response.log[0]), response.log[0])

    def test_verify_lines_end_with_received_and_count(self):
        pairs = self.split_chunks("ML-DSA-44", 3, claims="oidc")
        a0, a1, a2 = pairs
        token = "".join(value for _, value in pairs)
        cases = [([a0, a1, a2], "chunks=3/3"), ([a2, a0, a1], "chunks=3/3"),
                 ([a0, a2], "chunks=2/3"), ([a0, a1, a1, a2], "chunks=4/3"),
                 ([a0, a1, a2, ("jwt.0.2", "x")], "chunks=4/-"),
                 ([a0, a1, a2, ("jwt.3.3", "x")], "chunks=4/3"),
                 ([("jwt.0.1", "not-a-token")], "chunks=1/1"),
                 ([("jwt.0.0", "x")], "chunks=1/0")]
        for cookies, field in cases:
            with self.subTest(field=field, cookies=[name for name, _ in cookies]):
                response = self.call(f"{VERIFY_PATH}?nonce={'c' * 32}",
                                     {"Cookie": cookie_header(cookies)})
                self.assertEqual(len(response.log), 1)
                _, fields = log_fields(response.log[0])
                self.assertEqual(fields[-1], field)
                self.assertNotIn(token, response.log[0])
                for _, value in cookies:
                    if len(value) > 2:
                        self.assertNotIn(value, response.log[0])
                self.assertIsNone(TOKEN_LIKE.search(response.log[0]), response.log[0])

    def test_lines_for_other_sources_keep_their_fields(self):
        base = self.require_base()
        pairs = self.split_chunks("ES256", 2)
        token = "".join(value for _, value in pairs)
        requests = [{"Cookie": cookie_header([*pairs, ("jwt", token)])},
                    {"Cookie": cookie_header(pairs), "Authorization": f"Bearer {token}"}]
        reference = wsgi_call(base.application, VERIFY_PATH, {"Cookie": "jwt=a; jwt=b"})
        _, reference_fields = log_fields(reference.log[0])
        for headers in requests:
            with self.subTest(headers=sorted(headers)):
                response = self.call(VERIFY_PATH, headers)
                _, fields = log_fields(response.log[0])
                self.assertEqual([field.split("=")[0] for field in fields],
                                 [field.split("=")[0] for field in reference_fields])
                self.assertNotIn(token, response.log[0])
                for _, value in pairs:
                    self.assertNotIn(value, response.log[0])

    def test_docstring(self):
        text = transport_app.__doc__ or ""
        lowered = text.lower()
        for term in ("split", "reassembl", "ephemeral", "experiment", "production"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)


# ---- R7: the load workload's split carrier -----------------------------------------------

class UnreachableStack:
    """A stack whose URLs nothing listens on, so every request sent to it fails at once."""

    def __init__(self, run_dir: Path):
        self.proxy_url = self.app_url = "http://127.0.0.1:9"
        self.run_dir = run_dir


class FakeResponse:
    status = 200


class FakePage:
    """Stands in for a Playwright page: the test page loads, and every fetch() gets one reply."""

    def __init__(self, reply: dict):
        self.reply = reply

    def goto(self, url, timeout=None):
        return FakeResponse()

    def evaluate(self, script, arguments=None):
        return self.reply

    def set_default_timeout(self, timeout):
        pass


class FakeContext:
    """Stands in for a browser context whose cookie jar holds the given names."""

    def __init__(self, names):
        self.names = list(names)

    def cookies(self, *urls):
        return [{"name": name, "value": "SECRETCHUNKVALUE", "domain": "127.0.0.1", "path": "/"}
                for name in self.names]


class SplitCarrierTests(unittest.TestCase):
    def test_carrier_names(self):
        carrier = split_carrier()
        self.assertEqual(carrier.name, "split")
        self.assertEqual(carrier.issue_delivery, "split")
        self.assertEqual(set(transport_load.CARRIERS), {"bearer", "cookie", "split"})

    def test_direct_headers(self):
        carrier = split_carrier()
        split_token = app_api("split_token")
        for total in (1, 948, 4000, 4001, 4095, 11353, 23662, 40001):
            token = random_token(total, total + 1)
            with self.subTest(token_bytes=total):
                headers = carrier.direct_headers(token)
                expected = "; ".join(f"{name}={value}" for name, value in split_token(token))
                self.assertEqual(headers, {"Cookie": expected})
                self.assertEqual(headers["Cookie"], cookie_header(expected_chunks(token)))

    def test_browser_headers_are_empty(self):
        carrier = split_carrier()
        self.assertEqual(carrier.browser_headers(random_token(4095, 3)), {})
        self.assertEqual(carrier.browser_headers(None), {})

    def test_header_line_bytes(self):
        carrier = split_carrier()
        self.assertEqual(carrier.header_line_bytes(4095), 4123)
        self.assertEqual(carrier.header_line_bytes(23662), 23730)
        for total in (1, 208, 948, 4000, 4001, 11353, 36000, 36001, 40001, 123456):
            with self.subTest(token_bytes=total):
                token = random_token(total, total + 2)
                line = f"Cookie: {carrier.direct_headers(token)['Cookie']}\r\n"
                self.assertEqual(carrier.header_line_bytes(total), len(line))
                self.assertEqual(carrier.header_line_bytes(total), split_line_bytes(total))

    def test_other_carriers_unchanged(self):
        bearer, cookie = transport_load.CARRIERS["bearer"], transport_load.CARRIERS["cookie"]
        self.assertEqual((bearer.name, bearer.issue_delivery), ("bearer", "body"))
        self.assertEqual((cookie.name, cookie.issue_delivery), ("cookie", "cookie"))
        self.assertEqual(bearer.direct_headers("t.o.k"), {"Authorization": "Bearer t.o.k"})
        self.assertEqual(bearer.browser_headers("t.o.k"), {"Authorization": "Bearer t.o.k"})
        self.assertEqual(cookie.direct_headers("t.o.k"), {"Cookie": "jwt=t.o.k"})
        self.assertEqual(cookie.browser_headers("t.o.k"), {})
        self.assertEqual(bearer.header_line_bytes(100), len("Authorization: Bearer \r\n") + 100)
        self.assertEqual(cookie.header_line_bytes(100), len("Cookie: jwt=\r\n") + 100)

    def test_checked_settings_accept_split(self):
        settings = transport_load.checked_settings(**{**LOAD_DEFAULTS, "transport": "split"})
        self.assertEqual(settings["transport"], "split")
        self.assertEqual(set(settings), LOAD_SETTINGS_KEYS)
        for transport in ("query", "cookies", "Split", None):
            with self.subTest(transport=transport), self.assertRaises(ValueError):
                transport_load.checked_settings(**{**LOAD_DEFAULTS, "transport": transport})

    def test_run_load_interface_unchanged(self):
        self.assertEqual(transport_load.default_settings(), LOAD_DEFAULTS)
        parameters = inspect.signature(transport_load.run_load).parameters
        self.assertEqual(list(parameters), ["stack", *LOAD_DEFAULTS])

    def test_run_load_plans_split_cells(self):
        results = {}
        for transport in ("cookie", "split"):
            with tempfile.TemporaryDirectory() as directory:
                results[transport] = transport_load.run_load(
                    UnreachableStack(Path(directory) / "run"), algorithms=["ML-DSA-44"],
                    transport=transport, clients=["direct"], concurrency=[1], duration=0.1,
                    warmup=0.0, claims="oidc", size_controls=False, timeout=5.0)
        split = results["split"]
        self.assertEqual(split["settings"]["transport"], "split")
        self.assertEqual(set(split["settings"]), LOAD_SETTINGS_KEYS)
        for cell in split["results"]:
            with self.subTest(algorithm=cell["algorithm"]):
                total = TOKEN_BYTES_OIDC[cell["algorithm"]]
                self.assertEqual(cell["token_bytes"], total)
                self.assertEqual(cell["bytes"]["header_line"], split_line_bytes(total))
                self.assertFalse(cell["issue"]["delivered"])  # Nothing listens at the stack.
        rows = {transport: {row["algorithm"]: row for row in result["network_model"]["rows"]}
                for transport, result in results.items()}
        for name in ("ES256", "ML-DSA-44"):
            with self.subTest(model=name):
                total = TOKEN_BYTES_OIDC[name]
                self.assertEqual(rows["split"][name]["request_bytes"]
                                 - rows["cookie"][name]["request_bytes"],
                                 split_line_bytes(total) - len("Cookie: jwt=\r\n") - total)

    def browser_issue(self, reply: dict, stored, directory: str):
        """BrowserClient's issue step for the split carrier, with a stand-in page and jar."""
        log_path = Path(directory) / "browser.log"
        settings = transport_load.checked_settings(**{
            **LOAD_DEFAULTS, "algorithms": ["ES256"], "transport": "split",
            "clients": ["browser"], "concurrency": [1], "claims": "oidc",
            "size_controls": False, "timeout": 5.0})
        client = transport_load.BrowserClient(None, UnreachableStack(Path(directory)),
                                              split_carrier(), settings, log_path)
        plan = transport_load.CellPlan("browser", 1, "ES256", "token", "ES256", 0,
                                       TOKEN_BYTES_OIDC["ES256"])
        issue = client.issue(FakeContext(stored), FakePage(reply), plan)
        text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
        # The load_issue events only: R7 keeps them to cookie names.
        return issue, "\n".join(line for line in text.splitlines()
                                if json.loads(line).get("event") == "load_issue")

    @staticmethod
    def issue_reply(status: int, names) -> dict:
        body = {"layer": "application", "algorithm": "ES256", "delivery": "split",
                "experiment_key": True}
        if names is not None:
            body["cookie_names"] = list(names)
        return {"status": status, "headers": {}, "text": json.dumps(body), "error": None}

    def test_browser_cell_delivered_only_with_every_chunk(self):
        names = chunk_names(7)
        with tempfile.TemporaryDirectory() as directory:
            issue, log = self.browser_issue(self.issue_reply(200, names),
                                            ["theme", *reversed(names)], directory)
            self.assertEqual((issue.status, issue.delivered), (200, True))
            self.assertIn("load_issue", log)
            self.assertNotIn("SECRETCHUNKVALUE", log)
            record = json.loads(log.splitlines()[0])
            self.assertEqual(sorted(record["cookie_names"]), sorted(["theme", *names]))
        with tempfile.TemporaryDirectory() as directory:
            issue, log = self.browser_issue(self.issue_reply(200, names), names[:3], directory)
            self.assertEqual((issue.status, issue.delivered), (200, False))
            # The error says how many of the expected chunk cookies were stored.
            self.assertRegex(issue.error or "", r"(?<![\d.])3(?![\d.])")
            self.assertNotIn("SECRETCHUNKVALUE", log)
            self.assertNotIn("SECRETCHUNKVALUE", issue.error or "")
        for case, reply, stored in (("empty names", self.issue_reply(200, []), ["jwt.0.1"]),
                                    ("no names", self.issue_reply(200, None), ["jwt.0.1"]),
                                    ("502", self.issue_reply(502, ["jwt.0.1"]), ["jwt.0.1"]),
                                    ("empty jar", self.issue_reply(200, ["jwt.0.1"]), [])):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                issue, _ = self.browser_issue(reply, stored, directory)
                self.assertIs(issue.delivered, False)
                self.assertTrue(issue.error)


# ---- R9: the chunk plan ------------------------------------------------------------------

class ChunkPlanTests(JsonCase):
    def test_signature(self):
        parameters = inspect.signature(module().chunk_plan).parameters
        self.assertEqual(list(parameters), ["algorithms", "claims"])
        self.assertIsNone(parameters["algorithms"].default)
        self.assertEqual(parameters["claims"].default, "oidc")

    def test_the_ml_dsa_44_row(self):
        rows = module().chunk_plan(["ML-DSA-44"])
        self.assertJsonClose(rows, [ML_DSA_44_ROW], "plan")
        self.assertJsonClose(rows, [expected_plan_row("ML-DSA-44")], "plan")

    def test_every_configuration(self):
        rows = module().chunk_plan()
        self.assertIsInstance(rows, list)
        self.assertEqual([row["algorithm"] for row in rows], NAMES)
        for row in rows:
            with self.subTest(algorithm=row["algorithm"]):
                self.assertEqual(set(row), PLAN_KEYS)
                self.assertEqual(row["token_bytes"], TOKEN_BYTES_OIDC[row["algorithm"]])
                self.assertEqual(row["chunks"], DEFAULT_CHUNKS_OIDC[row["algorithm"]])
        self.assertJsonClose(rows, [expected_plan_row(name) for name in NAMES], "plan")

    def test_fits(self):
        fits = {row["algorithm"]: row["fits"] for row in module().chunk_plan()}
        for name in ("RS256", "ES256", "EdDSA"):
            self.assertEqual(fits[name], {"cookie": {"per_cookie": True, "cookie_line": True},
                                          "split": {"per_cookie": True, "cookie_count": True,
                                                    "cookie_line": True}})
        for name in ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"):
            self.assertEqual(fits[name], {"cookie": {"per_cookie": False, "cookie_line": False},
                                          "split": {"per_cookie": True, "cookie_count": True,
                                                    "cookie_line": False}})
        self.assertEqual(fits["ML-DSA-44"], ML_DSA_44_ROW["fits"])

    def test_claims_and_selection(self):
        plan = module().chunk_plan
        for claims in CLAIM_SET_NAMES:
            with self.subTest(claims=claims):
                self.assertJsonClose(plan(None, claims),
                                     [expected_plan_row(name, claims) for name in NAMES])
        self.assertJsonClose(plan(["SLH-DSA-SHA2-128f", "EdDSA"], "essential"),
                             [expected_plan_row(name, "essential")
                              for name in ("EdDSA", "SLH-DSA-SHA2-128f")])
        self.assertJsonClose(plan(algorithms=["RS256"], claims="minimal"),
                             [expected_plan_row("RS256", "minimal")])

    def test_invalid_arguments_raise(self):
        plan = module().chunk_plan
        for algorithms in ([], ["HS256"], ["ES256", "ES256"], ["ES256", None], "ES256"):
            with self.subTest(algorithms=algorithms), self.assertRaises(ValueError):
                plan(algorithms)
        for claims in ("huge", "", "OIDC", None):
            with self.subTest(claims=claims), self.assertRaises(ValueError):
                plan(None, claims)


# ---- R8: the module, its settings, and its interface -------------------------------------

class InterfaceTests(unittest.TestCase):
    def test_constants(self):
        cookies = module()
        self.assertEqual(cookies.RESULT_FILE, "cookies.json")
        self.assertEqual(cookies.DOMAIN_MAX_COOKIES, DOMAIN_MAX_COOKIES)

    def test_run_cookies_signature_and_defaults(self):
        parameters = inspect.signature(module().run_cookies).parameters
        self.assertEqual(list(parameters), ["output_dir", *RUN_COOKIES_DEFAULTS])
        self.assertIs(parameters["output_dir"].default, inspect.Parameter.empty)
        for name, default in RUN_COOKIES_DEFAULTS.items():
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
        expected = {name: value for name, value in RUN_COOKIES_DEFAULTS.items()
                    if name != "run_dir"}
        self.assertEqual(set(settings), set(SETTING_NAMES))
        self.assertEqual(list(settings["concurrency"]), [1, 4])
        self.assertEqual({key: value for key, value in settings.items() if key != "concurrency"},
                         {key: value for key, value in expected.items() if key != "concurrency"})

    def test_other_public_functions(self):
        cookies = module()
        for function, names in ((cookies.checked_settings, list(SETTING_NAMES)),
                                (cookies.read_saved_settings, ["path"]),
                                (cookies.summary_lines, ["result"]),
                                (cookies.default_settings, [])):
            with self.subTest(function=function.__name__):
                self.assertEqual(list(inspect.signature(function).parameters), names)

    def test_module_docstring(self):
        text = module().__doc__ or ""
        self.assertGreater(len(text.strip()), 200)
        lowered = text.lower()
        for term in ("cookies.json", "split", "latency", "limit", "ephemeral", "experiment",
                     "production"):
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

    def test_shared_helpers_are_imported_not_copied(self):
        module()
        tree = ast.parse((REPO / "scripts" / "transport_cookies.py").read_text(encoding="utf-8"))
        defined = {node.name for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        defined |= {target.id for node in tree.body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        imported, aliases = {}, {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imported.setdefault(node.module, set()).add(alias.name)
                    if node.module == "scripts":
                        aliases[alias.asname or alias.name] = f"scripts.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name
        attributes = {(aliases.get(node.value.id), node.attr) for node in ast.walk(tree)
                      if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)}
        used = {node.id for node in ast.walk(tree)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        for source, names in SHARED_HELPERS.items():
            for name in names:
                with self.subTest(helper=f"{source}.{name}"):
                    if name not in OWN_NAMES:
                        self.assertNotIn(name, defined, "a shared helper is defined again")
                    taken = (name in imported.get(source, set())
                             or (source, name) in attributes)
                    if name in CORE_HELPERS[source]:
                        self.assertTrue(taken, f"{name} is not taken from {source}")
                    elif name in used and name not in OWN_NAMES:
                        self.assertTrue(taken, f"{name} is used but not taken from {source}")


class CheckedSettingsTests(unittest.TestCase):
    VALID = {"algorithms": ["ES256"], "claims": "oidc", "clients": ["direct"],
             "concurrency": [1], "duration": 0.1, "warmup": 0.0, "timeout": 30.0,
             "header_buffers": "32k", "proxy_buffers": "32k", "upstream_keepalive": 8}
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
        {"proxy_buffers": None}, {"proxy_buffers": "big"}, {"proxy_buffers": "32 k"},
        {"proxy_buffers": ""}, {"proxy_buffers": 32}, {"proxy_buffers": "16kb"},
        {"upstream_keepalive": 0}, {"upstream_keepalive": 1025}, {"upstream_keepalive": True},
        {"upstream_keepalive": "8"}, {"upstream_keepalive": 8.0},
    ]

    def checked(self, **given) -> dict:
        return module().checked_settings(**{**self.VALID, **given})

    def test_valid_settings(self):
        self.assertEqual(self.checked(), self.VALID)

    def test_algorithms_add_es256_in_adapter_order(self):
        settings = self.checked(algorithms=("SLH-DSA-SHA2-128f", "RS256"))
        self.assertEqual(settings["algorithms"], ["RS256", "ES256", "SLH-DSA-SHA2-128f"])
        self.assertEqual(self.checked(algorithms=None)["algorithms"], NAMES)

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
                                    "header_buffers": "32k", "proxy_buffers": "32k",
                                    "upstream_keepalive": None})

    def test_every_claim_set_and_other_values(self):
        for claims in CLAIM_SET_NAMES:
            with self.subTest(claims=claims):
                self.assertEqual(self.checked(claims=claims)["claims"], claims)
        settings = self.checked(header_buffers="64k", proxy_buffers="16k",
                                upstream_keepalive=None)
        self.assertEqual((settings["header_buffers"], settings["proxy_buffers"],
                          settings["upstream_keepalive"]), ("64k", "16k", None))

    def test_invalid_settings_raise(self):
        for case in self.INVALID:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.checked(**case)


class SavedSettingsTests(unittest.TestCase):
    def write(self, directory: str, text: str, name: str = "cookies.json") -> Path:
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_reads_the_settings_object(self):
        read = module().read_saved_settings
        with tempfile.TemporaryDirectory() as directory:
            saved = {**CheckedSettingsTests.VALID, "duration": 2.0}
            self.assertEqual(read(self.write(directory, json.dumps({"settings": saved,
                                                                    "plan": []}))), saved)
            partial = {"proxy_buffers": "64k", "claims": "essential"}
            self.assertEqual(read(self.write(directory, json.dumps({"settings": partial}))),
                             partial)

    def test_settings_repeat_the_run(self):
        cookies = module()
        settings = cookies.checked_settings(**CheckedSettingsTests.VALID)
        bound = inspect.signature(cookies.run_cookies).bind("out", **settings)
        self.assertEqual(set(bound.arguments), {"output_dir", *SETTING_NAMES})
        self.assertEqual(cookies.checked_settings(**settings), settings)

    def test_rejects_unusable_files(self):
        read = module().read_saved_settings
        with tempfile.TemporaryDirectory() as directory:
            for text in ("not json", "[]", "null", '{"results": []}', '{"settings": [1]}',
                         '{"settings": "x"}', '{"settings": {"bogus": 1}}',
                         '{"settings": {"transport": "split"}}',
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


class RunCookiesArgumentTests(unittest.TestCase):
    def test_invalid_arguments_raise_before_anything_starts(self):
        run_cookies = module().run_cookies
        with tempfile.TemporaryDirectory() as directory:
            for index, case in enumerate(CheckedSettingsTests.INVALID):
                output = Path(directory) / f"out-{index}" / "nested"
                run_dir = Path(directory) / f"run-{index}"
                with self.subTest(case=case):
                    with self.assertRaises(ValueError):
                        run_cookies(output, **{**CheckedSettingsTests.VALID, **case,
                                               "run_dir": run_dir})
                    self.assertFalse(output.parent.exists(), "the output directory was created")
                    self.assertFalse(run_dir.exists(), "a stack was started")

    def test_output_dir_must_be_new_or_empty(self):
        run_cookies = module().run_cookies
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
                        run_cookies(output, run_dir=run_dir, **CheckedSettingsTests.VALID)
                    self.assertFalse(run_dir.exists(), "a stack was started")
            self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
            self.assertEqual(a_file.read_text(encoding="utf-8"), "file")


# ---- R8: transport_claims keeps its API --------------------------------------------------

def function_signatures(source: str) -> dict[str, tuple]:
    """Each top-level function's parameter names and default expressions, from its source."""
    found = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef):
            arguments = node.args
            found[node.name] = (
                [argument.arg for argument in arguments.posonlyargs + arguments.args],
                [ast.unparse(default) for default in arguments.defaults],
                [(argument.arg, None if default is None else ast.unparse(default))
                 for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)],
                arguments.vararg.arg if arguments.vararg else None,
                arguments.kwarg.arg if arguments.kwarg else None)
    return found


class ClaimsApiTests(unittest.TestCase):
    def test_public_api_and_docstring_unchanged(self):
        before = git_show("scripts/transport_claims.py")
        if before is None:
            self.skipTest("BASE_COMMIT is not available in this checkout")
        after = (REPO / "scripts" / "transport_claims.py").read_text(encoding="utf-8")
        old, new = function_signatures(before), function_signatures(after)
        for name in CLAIMS_API:
            with self.subTest(function=name):
                self.assertIn(name, new)
                self.assertEqual(new[name], old[name])
        for name in old:
            if not name.startswith("_"):
                with self.subTest(public=name):
                    self.assertTrue(callable(getattr(claims_module(), name, None)), name)
        self.assertEqual(ast.get_docstring(ast.parse(after), clean=False),
                         ast.get_docstring(ast.parse(before), clean=False))
        self.assertEqual(claims_module().RESULT_FILE, "claims.json")

    def test_default_settings_unchanged(self):
        self.assertEqual(claims_module().default_settings(), {
            "algorithms": None, "clients": None, "concurrency": (1, 4), "duration": 5.0,
            "warmup": 1.0, "timeout": 60.0, "header_buffers": None, "upstream_keepalive": None})


# ---- R15: summary_lines ------------------------------------------------------------------

def synthetic_result(names=("ES256", "ML-DSA-44")) -> dict:
    """A cookies.json-shaped result with every R14 key, as summary_lines would read it back."""
    nonces = iter(f"{value:032x}" for value in range(1, 10_000))

    def pair(name: str, transport: str, stack: str, **extra) -> dict:
        total = extra.pop("token_bytes", TOKEN_BYTES_OIDC[name])
        count = extra.pop("chunks", default_count(total)) if transport == "split" else None
        rejected = (name in ("ML-DSA-44", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f")
                    and transport == "cookie")
        outcome, layer = ("rejected", "browser") if rejected else ("verified", None)
        outcome, layer = extra.pop("outcome", outcome), extra.pop("rejected_by", layer)
        expected = 1 if transport == "cookie" else count
        stored = expected if outcome == "verified" else max(0, expected - 1)
        line = (len("Cookie: jwt=\r\n") + total if transport == "cookie"
                else split_line_bytes(total, count))
        return {"algorithm": name, "transport": transport, "token_bytes": total,
                "chunks": count, "outcome": outcome, "rejected_by": layer,
                "verified_directly": True, "cookies_expected": expected,
                "cookies_stored": stored,
                "chunk_order": (list(range(count)) if transport == "split"
                                and outcome == "verified" else None),
                "issue_status": 200, "verify_status": 200 if outcome == "verified" else 401,
                "bytes": {"largest_name_value": (3 + total if transport == "cookie"
                                                 else largest_name_value(total, count)),
                          "cookie_line": line, "upstream_response_headers": line + 200,
                          "browser_request_headers": line + 500,
                          "app_received_headers": line + 100},
                "issue_nonce": next(nonces), "verify_nonce": next(nonces),
                "evidence": f"{outcome}: a synthetic {stack} pair", **extra}

    limits = {}
    for stack in ("default", "raised"):
        results = [pair(name, transport, stack) for name in names
                   for transport in ("cookie", "split")]
        moved = []
        for name in names:
            cookie, split = (entry["outcome"] for entry in results if entry["algorithm"] == name)
            moved.append({"algorithm": name, "cookie": cookie, "split": split,
                          "moved": cookie != split})
        limits[stack] = {"stack": f"limits-{stack}",
                         "header_buffers": None if stack == "default" else "32k",
                         "proxy_buffers": None if stack == "default" else "32k",
                         "results": results, "moved": moved}
    boundary_probes = []
    for pad, outcome in ((0, "verified"), (9200, "rejected"), (4600, "rejected"),
                         (2300, "verified"), (3450, "verified"), (3451, "rejected")):
        total = token_bytes("ML-DSA-44", padded_claims(claim_set("oidc"), pad))
        entry = pair("ML-DSA-44", "split", "default", token_bytes=total, outcome=outcome,
                     rejected_by=None if outcome == "verified" else "proxy")
        boundary_probes.append({key: entry[key] for key in (
            "token_bytes", "chunks", "outcome", "rejected_by", "cookies_stored",
            "verify_status", "bytes", "issue_nonce", "verify_nonce", "evidence")} | {"pad": pad})
    per_cookie_pad = pad_for_target("ML-DSA-44", claim_set("oidc"), 8178)
    probes = {"stack": "limits-raised", "per_cookie": [], "cookie_count": []}
    for kind, name, pad, count, outcome in (
            ("per_cookie", "at_limit", per_cookie_pad, 2, "verified"),
            ("per_cookie", "over_limit", per_cookie_pad + 1, 2, "rejected"),
            ("cookie_count", "at_limit", 0, 180, "verified"),
            ("cookie_count", "over_limit", 0, 181, "rejected")):
        algorithm = "ML-DSA-44" if kind == "per_cookie" else "ES256"
        total = token_bytes(algorithm, padded_claims(claim_set("oidc"), pad))
        probes[kind].append(pair(algorithm, "split", "raised", token_bytes=total, chunks=count,
                                 outcome=outcome,
                                 rejected_by=None if outcome == "verified" else "browser")
                            | {"name": name, "pad": pad})
    cases = []
    for name in CASE_NAMES:
        status = CASE_STATUSES[name]
        cases.append({"name": name, "cookies": ["jwt.0.3", "jwt.1.3", "jwt.2.3"],
                      "bearer": name == "with_bearer", "status": status,
                      "verified": status == 200,
                      "source": None if CASE_CHUNKS[name] is None else "split",
                      "error": None if status == 200 else f"synthetic {name}",
                      "verify_called": name in VERIFY_CALLED, "chunks": CASE_CHUNKS[name],
                      "nonce": next(nonces)})
    rows = []
    for client in ("direct", "browser"):
        for index, name in enumerate(names):
            undelivered = client == "browser" and name == "ML-DSA-44"
            means = {"cookie": None if undelivered else
                     {component: 0.2 + 0.01 * index for component in COMPONENTS},
                     "split": {component: 0.21 + 0.01 * index for component in COMPONENTS}}
            rows.append({
                "client": client, "concurrency": 1, "algorithm": name,
                "token_bytes": TOKEN_BYTES_OIDC[name],
                "chunks": default_count(TOKEN_BYTES_OIDC[name]),
                "delivered": {"cookie": not undelivered, "split": True},
                "verified": {"cookie": 0 if undelivered else 900, "split": 880},
                "failed": {"cookie": 0, "split": 0},
                "throughput_rps": {"cookie": 0.0 if undelivered else 4500.5, "split": 4400.25},
                "median_ms": {"cookie": None if undelivered else 0.201, "split": 0.211},
                "p95_ms": {"cookie": None if undelivered else 0.251, "split": 0.261},
                "mean_ms": means,
                "difference_ms": None if undelivered else {
                    component: means["split"][component] - means["cookie"][component]
                    for component in COMPONENTS}})
    network = [{"algorithm": name,
                "request_bytes": {"cookie": 120 + 14 + TOKEN_BYTES_OIDC[name],
                                  "split": 120 + split_line_bytes(TOKEN_BYTES_OIDC[name])},
                "extra_bytes": split_line_bytes(TOKEN_BYTES_OIDC[name])
                - 14 - TOKEN_BYTES_OIDC[name],
                "modeled": [{**profile, "extra_ms": 0.001}
                            for profile in transport_load.NETWORK_PROFILES]}
               for name in names]
    return {
        "schema_version": 1,
        "started_utc": "2026-11-18T05:00:00+00:00",
        "finished_utc": "2026-11-18T05:03:00+00:00",
        "recorded_utc": "2026-11-18T05:03:01+00:00",
        "settings": {"algorithms": list(names), "claims": "oidc",
                     "clients": ["direct", "browser"], "concurrency": [1], "duration": 0.2,
                     "warmup": 0.0, "timeout": 60.0, "header_buffers": "32k",
                     "proxy_buffers": "32k", "upstream_keepalive": 8},
        "environment": {"python": "3.15.2", "platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                        "page_size_bytes": 16384, "waitress_threads": 4,
                        "git_commit": "0" * 40, "git_dirty_scripts_or_fixtures": False},
        "layers": [],
        "browser": {"version": "156.0.8078.4", "user_agent": "Mozilla/5.0 HeadlessChrome"},
        "experiment_keys": True,
        "format": {"cookie_name": "jwt.<index>.<count>", "chunk_bytes": SPLIT_CHUNK_BYTES,
                   "max_chunks": SPLIT_MAX_CHUNKS, "domain_max_cookies": DOMAIN_MAX_COOKIES,
                   "cookie_attributes": FULL_ATTRIBUTES},
        "plan": [expected_plan_row(name) for name in names],
        "limits": limits,
        "boundary": {"algorithm": "ML-DSA-44", "claims": "oidc", "stack": "limits-default",
                     "low_pad": 0, "high_pad": 9200, "largest_verified": boundary_probes[4],
                     "first_rejected": boundary_probes[5], "probes": boundary_probes},
        "probes": probes,
        "handling": {"algorithm": "ML-DSA-44", "claims": "oidc", "token_bytes": 4095,
                     "chunks": 3, "stack": "limits-raised", "cases": cases},
        "latency": {"transports": ["cookie", "split"], "reference": "ES256",
                    "size_controls": False,
                    "runs": {"cookie": "latency-cookie/load.json",
                             "split": "latency-split/load.json"},
                    "rows": rows, "network_model": network},
        "evidence": {"cookies": "cookies.json"},
    }


class SummaryLinesTests(unittest.TestCase):
    def check_lines(self, result: dict) -> None:
        lines = module().summary_lines(result)
        self.assertIsInstance(lines, list)
        names = result["settings"]["algorithms"]
        rows = result["latency"]["rows"]
        words = (["plan"] * len(result["plan"]) + ["limits"] * (2 * len(names)) + ["boundary"]
                 + ["probe"] * 4 + ["handling"] * len(CASE_NAMES) + ["latency"] * len(rows))
        self.assertEqual(len(lines), len(words), "\n".join(lines))
        for line, word in zip(lines, words):
            with self.subTest(line=line):
                self.assertIsInstance(line, str)
                self.assertTrue(line.startswith(word), f"expected {word!r}")
        plan, rest = lines[:len(names)], lines[len(names):]
        for line, row in zip(plan, result["plan"]):
            self.assertIn(row["algorithm"], line)
        limits, rest = rest[:2 * len(names)], rest[2 * len(names):]
        expected = [(stack, entry) for stack in ("default", "raised")
                    for entry in result["limits"][stack]["moved"]]
        for line, (stack, moved) in zip(limits, expected):
            with self.subTest(line=line):
                self.assertIn(stack, line)
                self.assertIn(moved["algorithm"], line)
                for entry in result["limits"][stack]["results"]:
                    if entry["algorithm"] != moved["algorithm"]:
                        continue
                    self.assertIn(entry["outcome"], line)
                    if entry["rejected_by"]:
                        self.assertIn(entry["rejected_by"], line)
                if moved["moved"]:
                    self.assertRegex(line, r"\bmoved\b")
                else:
                    self.assertNotRegex(line, r"\bmoved\b")
        self.assertIn("ML-DSA-44", rest[0])
        probe_lines = rest[1:5]
        self.assertEqual(sum("ML-DSA-44" in line for line in probe_lines), 2, probe_lines)
        self.assertEqual(sum("ES256" in line for line in probe_lines), 2, probe_lines)
        handling = rest[5:5 + len(CASE_NAMES)]
        for line, case in zip(handling, result["handling"]["cases"]):
            with self.subTest(line=line):
                self.assertIn(case["name"], line)
                self.assertRegex(line, rf"(?<!\d){case['status']}(?!\d)")
        for line, row in zip(rest[5 + len(CASE_NAMES):], rows):
            with self.subTest(line=line):
                self.assertIn(row["algorithm"], line)
                self.assertIn(row["client"], line)

    def test_lines_for_every_phase(self):
        self.check_lines(synthetic_result())

    def test_every_configuration(self):
        self.check_lines(synthetic_result(tuple(NAMES)))

    def test_reads_only_the_saved_json(self):
        result = synthetic_result()
        text = json.dumps(result)
        lines = module().summary_lines(json.loads(text))
        self.assertEqual(json.dumps(result), text, "summary_lines changed its argument")
        self.assertEqual(module().summary_lines(json.loads(text)), lines)

    def test_null_boundary_ends(self):
        result = synthetic_result()
        result["boundary"]["first_rejected"] = None
        result["boundary"]["largest_verified"] = None
        lines = module().summary_lines(result)
        self.assertEqual(sum(line.startswith("boundary") for line in lines), 1)


if __name__ == "__main__":
    unittest.main()
