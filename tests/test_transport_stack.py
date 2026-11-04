"""Run the transport stack through its stack-independent interface and CLI; no timing thresholds."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import signal
import socket
import string
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit

from scripts.transport_stack import (MANIFEST_PATH, installed_versions, load_manifest, main,
                                     run_check, start_stack)


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "transport_stack.py"
MANIFEST = REPO / "transport" / "stack.json"
URL = re.compile(r"http://127\.0\.0\.1:(\d+)")
NONCE = re.compile(r"[0-9a-f]{16,}")
ERROR_LINE = re.compile(r"^Error:", re.MULTILINE)
LABELS = {"automation": "browser automation", "browser": "browser engine",
          "proxy": "reverse proxy", "app_server": "application server",
          "app_framework": "application framework"}
CLI_TIMEOUT = 300
GRACE = 15.0
PADDING_CAP = 8 * 1024 * 1024
REQUEST_SKIP = {"host", "connection", "keep-alive", "proxy-connection", "te", "trailer",
                "transfer-encoding", "upgrade", "accept-encoding"}
RESPONSE_SKIP = {"connection", "keep-alive", "transfer-encoding", "content-length", "server",
                 "date"}


class Interrupted(Exception):
    pass


def read_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


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
    """Poll a condition for a short shutdown grace period."""
    deadline = time.monotonic() + grace
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.2)
    return True


def refused(port: int) -> bool:
    return eventually(lambda: not accepts("127.0.0.1", port))


def lan_address() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
    except OSError:
        return None
    return None if address.startswith("127.") or address == "0.0.0.0" else address


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


def unactivated_environment() -> dict:
    """Drop conda activation so the script must find the stack from its interpreter alone."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CONDA_PREFIX", "CONDA_DEFAULT_ENV", "CONDA_SHLVL",
                                          "CONDA_PROMPT_MODIFIER"))}
    environment["PATH"] = os.pathsep.join(["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    return environment


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


def is_git_checkout() -> bool:
    try:
        subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                       check=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def extract_checkout(destination: Path) -> Path:
    """Extract the committed tree (git archive HEAD) into a directory without .git."""
    archive = subprocess.run(["git", "-C", str(REPO), "archive", "HEAD"], capture_output=True,
                             check=True).stdout
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(destination, filter="data")
    return destination


def tree_listing(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*")
            if "__pycache__" not in path.relative_to(root).parts}


def is_under(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


class TamperingProxy:
    """Forward requests to the real stack and break one property that run_check must verify."""

    def __init__(self, target_url: str):
        self.target = urlsplit(target_url)
        self.mode = None
        self.release = threading.Event()
        tamper = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                tamper.forward(self)

            def log_message(self, *arguments):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.handle_error = lambda request, address: None
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exception):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()

    def forward(self, request: BaseHTTPRequestHandler) -> None:
        path = urlsplit(request.path).path
        if self.mode == "slow_echo" and path == "/api/echo":
            self.release.wait(60)
        connection = http.client.HTTPConnection(self.target.hostname, self.target.port,
                                                timeout=60)
        connection.putrequest("GET", request.path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", self.target.netloc)
        for name, value in request.headers.items():
            if name.lower() not in REQUEST_SKIP:
                connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        status, body = response.status, response.read()
        headers = [(name, value) for name, value in response.getheaders()
                   if name.lower() not in RESPONSE_SKIP]
        connection.close()
        if path == "/" and self.mode == "page_status":
            status = 500
        elif path == "/api/echo" and self.mode == "echo_status":
            status = 500
        elif path == "/api/echo" and self.mode == "missing_proxy_header":
            headers = [(name, value) for name, value in headers
                       if name.lower() != "x-transport-proxy"]
        elif path == "/api/echo" and self.mode == "wrong_nonce":
            echo = json.loads(body)
            wrong = "0" * 32 if echo["query"].get("nonce") != "0" * 32 else "1" * 32
            echo["query"]["nonce"] = wrong
            body = json.dumps(echo).encode("utf-8")
        request.send_response(status)
        for name, value in headers:
            request.send_header(name, value)
        request.send_header("Content-Length", str(len(body)))
        request.send_header("Connection", "close")
        request.end_headers()
        request.wfile.write(body)


class TransportCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = read_manifest()
        cls.layers = {layer["role"]: layer for layer in cls.manifest["layers"]}

    def names_role(self, text: str, role: str) -> bool:
        lowered = text.lower()
        names = [role, LABELS[role], self.layers[role]["component"].lower()]
        if role == "proxy":
            names.append("proxy")
        if role in ("app_server", "app_framework"):
            names += [self.layers[other]["component"].lower()
                      for other in ("app_server", "app_framework") if other in self.layers]
            if re.search(r"\bapp", lowered):
                return True
        return any(name in lowered for name in names)

    def assertCheckResult(self, result: dict, proxy_url=None, app_url=None, run_dir=None) -> str:
        """Check an R16 result and return its nonce."""
        json.dumps(result)
        self.assertIs(result["ok"], True)
        for key, expected in (("proxy_url", proxy_url), ("app_url", app_url)):
            self.assertIsNotNone(URL.fullmatch(result[key]), result[key])
            if expected is not None:
                self.assertEqual(result[key], expected)
        self.assertIsInstance(result["run_dir"], str)
        self.assertTrue(Path(result["run_dir"]).is_absolute())
        if isinstance(run_dir, str):
            self.assertEqual(result["run_dir"], run_dir)
        elif run_dir is not None:
            self.assertEqual(Path(result["run_dir"]).resolve(), run_dir.resolve())
        self.assertEqual(result["layers"], [{key: layer[key] for key in
                                             ("role", "component", "version")}
                                            for layer in self.manifest["layers"]])

        browser = result["browser"]
        self.assertEqual(browser["version"], self.layers["browser"]["version"])
        self.assertIsInstance(browser["user_agent"], str)
        self.assertTrue(browser["user_agent"])

        proxy = result["proxy_url"]
        self.assertEqual(result["page"]["url"], f"{proxy}/")
        self.assertEqual(result["page"]["status"], 200)
        nonce = result["request"]["nonce"]
        self.assertIsInstance(nonce, str)
        self.assertIsNotNone(NONCE.fullmatch(nonce), nonce)
        self.assertEqual(result["request"]["url"], f"{proxy}/api/echo?nonce={nonce}")

        response = result["response"]
        self.assertEqual(response["status"], 200)
        self.assertIsInstance(response["headers"], dict)
        for name in response["headers"]:
            self.assertEqual(name, name.lower())
        self.assertEqual(response["headers"].get("x-transport-proxy"),
                         self.layers["proxy"]["component"])
        body = response["body"]
        self.assertEqual(body["layer"], "application")
        self.assertEqual(body["method"], "GET")
        self.assertEqual(body["path"], "/api/echo")
        self.assertEqual(body["query"]["nonce"], nonce)
        self.assertEqual(body["headers"]["user-agent"], browser["user_agent"])
        return nonce

    def assertLogsContain(self, run_dir: Path, proxy_targets, app_targets) -> None:
        logs = run_dir / "logs"
        for name in ("proxy-access.log", "proxy-error.log", "app.log"):
            self.assertTrue((logs / name).is_file(), name)
        access = (logs / "proxy-access.log").read_text(encoding="utf-8", errors="replace")
        application = (logs / "app.log").read_text(encoding="utf-8", errors="replace")
        for target in proxy_targets:
            self.assertIn(target, access)
        for target in app_targets:
            self.assertIn(target, application)


class ModuleTests(TransportCase):
    def test_manifest_path_and_loader(self):
        self.assertIsInstance(MANIFEST_PATH, Path)
        self.assertTrue(MANIFEST_PATH.is_absolute())
        self.assertEqual(MANIFEST_PATH.resolve(), MANIFEST.resolve())
        self.assertEqual(load_manifest(), self.manifest)
        for function in (installed_versions, start_stack, run_check, main):
            self.assertTrue(callable(function))

    def test_installed_versions_match_manifest(self):
        versions = installed_versions()
        self.assertIsInstance(versions, dict)
        self.assertEqual(sorted(versions), sorted(self.layers))
        for role, layer in self.layers.items():
            with self.subTest(role=role):
                self.assertEqual(versions[role], layer["version"])


class RunningStackTests(TransportCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        directory = cls.enterClassContext(tempfile.TemporaryDirectory(
            prefix="transport stack ", ignore_cleanup_errors=True))
        cls.requested_run_dir = Path(directory) / "run dir" / "nested"
        cls.stack = cls.enterClassContext(start_stack(run_dir=cls.requested_run_dir))
        try:
            cls.first_echo = fetch(f"{cls.stack.proxy_url}/api/echo")
        except (OSError, http.client.HTTPException) as error:
            cls.first_echo = error
        cls.baseline = descendants()
        try:
            cls.result, cls.check_error = run_check(cls.stack), None
        except Exception as error:  # Reported by the tests that use the result.
            cls.result, cls.check_error = None, error

    def smallest_header_limit(self, roles) -> int | None:
        sizes = [layer["limits"][key]["bytes"] for role, layer in self.layers.items()
                 if role in roles for key in ("single_header", "total_headers")]
        sizes = [size for size in sizes if type(size) is int]
        return min(sizes) if sizes else None

    def assertRejected(self, url: str, value: str) -> None:
        try:
            response = fetch(url, [("X-Transport-Padding", value)])
        except TimeoutError:
            self.fail("neither a response nor a closed connection before the client timeout")
        except (OSError, http.client.HTTPException):
            return
        self.assertGreaterEqual(response.status, 400)

    def test_stack_object(self):
        for name in ("proxy_url", "app_url"):
            with self.subTest(attribute=name):
                url = getattr(self.stack, name)
                self.assertIsInstance(url, str)
                match = URL.fullmatch(url)
                self.assertIsNotNone(match, url)
                self.assertTrue(1 <= int(match[1]) <= 65535)
        self.assertNotEqual(port_of(self.stack.proxy_url), port_of(self.stack.app_url))
        self.assertIsInstance(self.stack.run_dir, Path)
        self.assertTrue(self.stack.run_dir.is_absolute())
        self.assertEqual(self.stack.run_dir.resolve(), self.requested_run_dir.resolve())
        self.assertTrue(self.requested_run_dir.is_dir())

    def test_ready_when_yielded(self):
        self.assertNotIsInstance(self.first_echo, Exception)
        self.assertEqual(self.first_echo.status, 200)
        self.assertEqual(json.loads(self.first_echo.body)["layer"], "application")

    def test_listens_on_ipv4_loopback_only(self):
        address = lan_address()
        for name in ("proxy_url", "app_url"):
            port = port_of(getattr(self.stack, name))
            with self.subTest(url=name, host="127.0.0.1"):
                self.assertTrue(accepts("127.0.0.1", port))
            if address:
                with self.subTest(url=name, host=address):
                    self.assertFalse(accepts(address, port))
            with self.subTest(url=name, host="::1"):
                self.assertFalse(accepts("::1", port, socket.AF_INET6))

    def test_endpoints_through_proxy(self):
        page = fetch(f"{self.stack.proxy_url}/")
        self.assertEqual(page.status, 200)
        self.assertTrue(page.headers.get("Content-Type", "").lower().startswith("text/html"))
        for query in ("", "?alpha=1", "?empty=&flag"):
            with self.subTest(query=query):
                response = fetch(f"{self.stack.proxy_url}/api/echo{query}")
                self.assertEqual(response.status, 200)
                self.assertTrue(response.headers.get("Content-Type", "").lower()
                                .startswith("application/json"))
                echo = json.loads(response.body)
                self.assertEqual(echo["layer"], "application")
                self.assertEqual(echo["path"], "/api/echo")
        for path in ("/api/does-not-exist", "/api/does-not-exist?x=1", "/api/echo/extra"):
            with self.subTest(path=path):
                response = fetch(f"{self.stack.proxy_url}{path}")
                self.assertEqual(response.status, 404)
                self.assertEqual(response.headers.get("X-Transport-Proxy"),
                                 self.layers["proxy"]["component"])

    def test_direct_application_matches_proxy_without_marker(self):
        target = "/api/echo?alpha=1&beta=two"
        through_proxy = fetch(f"{self.stack.proxy_url}{target}")
        direct = fetch(f"{self.stack.app_url}{target}")
        self.assertEqual(direct.status, 200)
        self.assertTrue(direct.headers.get("Content-Type", "").lower()
                        .startswith("application/json"))
        self.assertIsNone(direct.headers.get("X-Transport-Proxy"))
        proxied, echoed = json.loads(through_proxy.body), json.loads(direct.body)
        for key in ("layer", "method", "path", "query"):
            self.assertEqual(echoed[key], proxied[key])
        missing = fetch(f"{self.stack.app_url}/api/does-not-exist")
        self.assertEqual(missing.status, 404)
        self.assertIsNone(missing.headers.get("X-Transport-Proxy"))

    def test_echo_body(self):
        response = fetch(f"{self.stack.proxy_url}/api/echo?alpha=1&beta=two&alpha=3",
                         [("X-Transport-Probe", "probe-value")])
        self.assertEqual(response.status, 200)
        echo = json.loads(response.body)
        self.assertEqual(echo["layer"], "application")
        self.assertEqual(echo["method"], "GET")
        self.assertEqual(echo["path"], "/api/echo")
        self.assertEqual(echo["query"], {"alpha": "3", "beta": "two"})
        self.assertIsInstance(echo["headers"], dict)
        for name, value in echo["headers"].items():
            self.assertEqual(name, name.lower())
            self.assertIsInstance(value, str)
        self.assertEqual(echo["headers"]["x-transport-probe"], "probe-value")

    def test_repeated_headers_joined(self):
        response = fetch(f"{self.stack.app_url}/api/echo",
                         [("X-Transport-Repeat", "one"), ("X-Transport-Repeat", "two")])
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body)["headers"]["x-transport-repeat"], "one, two")

    def test_proxy_marker_and_header_pass_through(self):
        token = secrets.token_urlsafe(32)
        sent = {"Cookie": f"transport_probe={token}; second=value",
                "Authorization": f"Bearer {token}.{token}",
                "X-Transport-Padding": padding(100),
                "X-Transport-Custom-Header": token}
        response = fetch(f"{self.stack.proxy_url}/api/echo", list(sent.items()))
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers.get("X-Transport-Proxy"),
                         self.layers["proxy"]["component"])
        received = json.loads(response.body)["headers"]
        for name, value in sent.items():
            with self.subTest(header=name):
                self.assertEqual(received.get(name.lower()), value)

    def test_quarter_of_smallest_documented_limit_passes(self):
        limit = self.smallest_header_limit({"proxy", "app_server", "app_framework"})
        value = padding(limit // 4 if limit is not None else 1024)
        response = fetch(f"{self.stack.proxy_url}/api/echo", [("X-Transport-Padding", value)])
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body)["headers"]["x-transport-padding"], value)

    def test_twice_proxy_limit_is_rejected(self):
        limit = self.smallest_header_limit({"proxy"})
        if limit is None or 2 * limit > PADDING_CAP:
            self.skipTest("no numeric proxy header limit within the padding cap")
        self.assertRejected(f"{self.stack.proxy_url}/api/echo", padding(2 * limit))
        self.assertEqual(fetch(f"{self.stack.proxy_url}/api/echo").status, 200)

    def test_twice_application_limit_is_rejected(self):
        limit = self.smallest_header_limit({"app_server", "app_framework"})
        if limit is None or 2 * limit > PADDING_CAP:
            self.skipTest("no numeric application header limit within the padding cap")
        self.assertRejected(f"{self.stack.app_url}/api/echo", padding(2 * limit))
        self.assertEqual(fetch(f"{self.stack.app_url}/api/echo").status, 200)

    def test_check_result(self):
        if self.check_error is not None:
            self.fail(f"run_check failed: {self.check_error!r}")
        self.assertCheckResult(self.result, self.stack.proxy_url, self.stack.app_url,
                               str(self.stack.run_dir))

    def test_browser_closed_after_check(self):
        self.assertTrue(eventually(lambda: descendants() <= self.baseline))

    def test_check_nonce_is_fresh_and_stack_keeps_running(self):
        if self.check_error is not None:
            self.fail(f"run_check failed: {self.check_error!r}")
        second = run_check(self.stack)
        nonce = self.assertCheckResult(second, self.stack.proxy_url, self.stack.app_url)
        self.assertNotEqual(nonce, self.result["request"]["nonce"])
        self.assertEqual(fetch(f"{self.stack.proxy_url}/api/echo").status, 200)

    def test_check_rejects_non_positive_timeout(self):
        for timeout in (0, 0.0, -1, -0.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                run_check(self.stack, timeout=timeout)
        self.assertEqual(fetch(f"{self.stack.proxy_url}/api/echo").status, 200)

    def test_check_detects_bad_responses_and_closes_browser(self):
        baseline = descendants()
        cases = (("page_status", 60.0), ("echo_status", 60.0), ("missing_proxy_header", 60.0),
                 ("wrong_nonce", 60.0), ("slow_echo", 5.0))
        with TamperingProxy(self.stack.proxy_url) as tamper:
            fake = SimpleNamespace(proxy_url=tamper.url, app_url=self.stack.app_url,
                                   run_dir=self.stack.run_dir)
            for mode, timeout in cases:
                with self.subTest(mode=mode):
                    tamper.mode = mode
                    try:
                        with self.assertRaises(RuntimeError):
                            run_check(fake, timeout=timeout)
                    finally:
                        if mode == "slow_echo":
                            tamper.release.set()
                    self.assertTrue(eventually(lambda: descendants() <= baseline))


class StackLifecycleTests(TransportCase):
    def test_invalid_arguments_raise_value_error_before_starting(self):
        proxy_port, app_port = free_ports(2)
        cases = [{"proxy_port": str(proxy_port)}, {"app_port": float(app_port)},
                 {"proxy_port": True}, {"app_port": False}, {"proxy_port": 0},
                 {"app_port": 65536}, {"proxy_port": -1},
                 {"proxy_port": proxy_port, "app_port": proxy_port},
                 {"proxy_port": proxy_port, "app_port": app_port, "timeout": 0},
                 {"proxy_port": proxy_port, "app_port": app_port, "timeout": -1.5}]
        with tempfile.TemporaryDirectory(prefix="invalid arguments ",
                                         ignore_cleanup_errors=True) as directory:
            for index, arguments in enumerate(cases):
                with self.subTest(arguments=arguments):
                    with self.assertRaises(ValueError):
                        with start_stack(run_dir=Path(directory) / f"case {index}", **arguments):
                            pass
                    self.assertFalse(accepts("127.0.0.1", proxy_port))
                    self.assertFalse(accepts("127.0.0.1", app_port))

    def test_explicit_ports_existing_run_dir_and_exit_on_exception(self):
        proxy_port, app_port = free_ports(2)
        with tempfile.TemporaryDirectory(prefix="existing run dir ",
                                         ignore_cleanup_errors=True) as directory:
            run_dir = Path(directory)
            with self.assertRaises(Interrupted):
                with start_stack(proxy_port=proxy_port, app_port=app_port,
                                 run_dir=run_dir) as stack:
                    self.assertEqual(stack.proxy_url, f"http://127.0.0.1:{proxy_port}")
                    self.assertEqual(stack.app_url, f"http://127.0.0.1:{app_port}")
                    self.assertEqual(stack.run_dir.resolve(), run_dir.resolve())
                    self.assertEqual(fetch(f"{stack.proxy_url}/api/echo").status, 200)
                    raise Interrupted
            self.assertTrue(refused(proxy_port))
            self.assertTrue(refused(app_port))

    def test_default_run_dir_logs_and_normal_exit(self):
        before = git_status()
        probe = secrets.token_hex(8)
        proxy_targets = [f"/api/echo?probe={probe}", f"/api/does-not-exist?probe={probe}"]
        app_targets = [*proxy_targets, f"/api/echo?direct={probe}"]
        temporary = Path(tempfile.gettempdir())
        with start_stack() as stack:
            run_dir = stack.run_dir
            self.assertTrue(run_dir.is_absolute())
            self.assertTrue(is_under(run_dir, temporary), run_dir)
            self.addCleanup(shutil.rmtree, run_dir, True)
            self.assertFalse(is_under(run_dir, REPO))
            for target in proxy_targets:
                fetch(f"{stack.proxy_url}{target}")
            fetch(f"{stack.app_url}/api/echo?direct={probe}")
            ports = [port_of(stack.proxy_url), port_of(stack.app_url)]
        for port in ports:
            self.assertTrue(refused(port))
        self.assertTrue(run_dir.is_dir())
        self.assertLogsContain(run_dir, proxy_targets, app_targets)
        self.assertEqual(git_status(), before)

    def test_busy_port_raises_runtime_error_naming_layer(self):
        for busy_role in ("proxy", "app_server"):
            with self.subTest(busy=busy_role), socket.socket() as holder, \
                    tempfile.TemporaryDirectory(prefix="busy port ",
                                                ignore_cleanup_errors=True) as directory:
                holder.bind(("127.0.0.1", 0))
                holder.listen()
                busy = holder.getsockname()[1]
                (other,) = free_ports(1)
                ports = ({"proxy_port": busy, "app_port": other} if busy_role == "proxy"
                         else {"proxy_port": other, "app_port": busy})
                with self.assertRaises(RuntimeError) as caught:
                    with start_stack(run_dir=Path(directory) / "run", timeout=30, **ports):
                        pass
                self.assertTrue(self.names_role(str(caught.exception), busy_role),
                                str(caught.exception))
                self.assertTrue(refused(other))


class CommandLineTests(TransportCase):
    @contextmanager
    def serving(self, arguments: list[str], cwd: str):
        """Start `serve`, yield the process and its first stdout line, and stop it afterwards."""
        stderr_path = Path(cwd) / "serve stderr.txt"
        with stderr_path.open("w", encoding="utf-8") as stderr:
            process = subprocess.Popen([sys.executable, str(SCRIPT), "serve", *arguments],
                                       cwd=cwd, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=stderr, text=True)
        lines = queue.Queue()

        def read_stdout():
            with process.stdout:
                for line in process.stdout:
                    lines.put(line)
            lines.put(None)

        threading.Thread(target=read_stdout, daemon=True).start()
        try:
            try:
                first = lines.get(timeout=CLI_TIMEOUT)
            except queue.Empty:
                self.fail("serve printed nothing")
            if first is None:
                self.fail(f"serve exited early: {stderr_path.read_text(encoding='utf-8')}")
            yield process, first, lines
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def test_check_with_defaults_from_another_directory(self):
        before = git_status()
        environment_before = environment_files()
        with tempfile.TemporaryDirectory(prefix="check cwd ") as cwd:
            result = run_cli("check", cwd=cwd, environment=unactivated_environment())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(changed_paths(environment_before, environment_files()), [],
                         f"check wrote into the environment at {sys.prefix}")
        data = json.loads(result.stdout)
        run_dir = Path(data["run_dir"])
        temporary = Path(tempfile.gettempdir())
        self.assertTrue(is_under(run_dir, temporary), run_dir)
        self.addCleanup(shutil.rmtree, run_dir, True)
        self.assertFalse(is_under(run_dir, REPO))
        nonce = self.assertCheckResult(data)
        self.assertLogsContain(run_dir, [nonce], [nonce])
        for key in ("proxy_url", "app_url"):
            self.assertTrue(refused(port_of(data[key])))
        self.assertEqual(git_status(), before)

    def test_check_failure_stops_started_processes(self):
        with socket.socket() as holder, tempfile.TemporaryDirectory(
                prefix="check busy ", ignore_cleanup_errors=True) as directory:
            holder.bind(("127.0.0.1", 0))
            holder.listen()
            busy = holder.getsockname()[1]
            (app_port,) = free_ports(1)
            result = run_cli("check", "--proxy-port", str(busy), "--app-port", str(app_port),
                             "--run-dir", str(Path(directory) / "run dir"), "--timeout", "30",
                             cwd=directory)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(result.stderr, ERROR_LINE)
            self.assertTrue(refused(app_port))

    def test_serve_until_signal(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum.name), tempfile.TemporaryDirectory(
                    prefix="serve ", ignore_cleanup_errors=True) as directory:
                run_dir = Path(directory) / "run dir"
                arguments = ["--run-dir", str(run_dir)]
                if signum == signal.SIGTERM:
                    proxy_port, app_port = free_ports(2)
                    arguments += ["--proxy-port", str(proxy_port), "--app-port", str(app_port),
                                  "--timeout", "120"]
                with self.serving(arguments, directory) as (process, first, lines):
                    info = json.loads(first)
                    for key in ("proxy_url", "app_url"):
                        self.assertIsNotNone(URL.fullmatch(info[key]), info[key])
                    if signum == signal.SIGTERM:
                        self.assertEqual(info["proxy_url"], f"http://127.0.0.1:{proxy_port}")
                        self.assertEqual(info["app_url"], f"http://127.0.0.1:{app_port}")
                    self.assertEqual(Path(info["run_dir"]).resolve(), run_dir.resolve())
                    response = fetch(f"{info['proxy_url']}/api/echo")
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get("X-Transport-Proxy"),
                                     self.layers["proxy"]["component"])
                    process.send_signal(signum)
                    self.assertEqual(process.wait(timeout=60), 0)
                    try:
                        self.assertIsNone(lines.get(timeout=GRACE), "more than one stdout line")
                    except queue.Empty:
                        self.fail("stdout still open after serve exited")
                for key in ("proxy_url", "app_url"):
                    self.assertTrue(refused(port_of(info[key])))

    def test_serve_startup_failure(self):
        with socket.socket() as holder, tempfile.TemporaryDirectory(
                prefix="serve busy ", ignore_cleanup_errors=True) as directory:
            holder.bind(("127.0.0.1", 0))
            holder.listen()
            busy = holder.getsockname()[1]
            (app_port,) = free_ports(1)
            result = run_cli("serve", "--proxy-port", str(busy), "--app-port", str(app_port),
                             "--run-dir", str(Path(directory) / "run dir"), "--timeout", "30",
                             cwd=directory)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(result.stderr, ERROR_LINE)
            self.assertTrue(refused(app_port))

    def test_versions(self):
        with tempfile.TemporaryDirectory(prefix="versions cwd ") as cwd:
            result = run_cli("versions", cwd=cwd, environment=unactivated_environment())
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertIs(data["ok"], True)
        self.assertEqual([entry["role"] for entry in data["layers"]], list(self.layers))
        for entry, layer in zip(data["layers"], self.manifest["layers"]):
            with self.subTest(role=layer["role"]):
                self.assertEqual(entry["component"], layer["component"])
                self.assertEqual(entry["documented"], layer["version"])
                self.assertEqual(entry["installed"], layer["version"])

    def test_versions_reports_mismatches_from_installed_tools(self):
        if not is_git_checkout():
            self.skipTest("not a git checkout")
        # Every role, so that no layer's installed version can be copied from the manifest.
        documented = {role: f"0.0.0.{index}" for index, role in enumerate(self.layers, 1)}
        with tempfile.TemporaryDirectory(prefix="versions mismatch ") as directory:
            checkout = extract_checkout(Path(directory) / "clean checkout")
            manifest_path = checkout / "transport" / "stack.json"
            changed = json.loads(manifest_path.read_text(encoding="utf-8"))
            for layer in changed["layers"]:
                layer["version"] = documented.get(layer["role"], layer["version"])
            manifest_path.write_text(json.dumps(changed, indent=2) + "\n", encoding="utf-8")
            result = run_cli("versions", script=checkout / "scripts" / "transport_stack.py",
                             cwd=directory)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, ERROR_LINE)
        for role in documented:
            with self.subTest(named=role):
                self.assertTrue(self.names_role(result.stderr, role), result.stderr)
        data = json.loads(result.stdout)
        self.assertIs(data["ok"], False)
        entries = {entry["role"]: entry for entry in data["layers"]}
        for role, layer in self.layers.items():
            with self.subTest(role=role):
                self.assertEqual(entries[role]["documented"],
                                 documented.get(role, layer["version"]))
                self.assertEqual(entries[role]["installed"], layer["version"])

    def test_usage_errors(self):
        (port,) = free_ports(1)
        cases = [[], ["bogus"], ["check", "--proxy-port", "0"],
                 ["check", "--proxy-port", "65536"], ["check", "--app-port", "-1"],
                 ["check", "--app-port", "abc"], ["check", "--proxy-port", "1.5"],
                 ["check", "--proxy-port", str(port), "--app-port", str(port)],
                 ["check", "--timeout", "0"], ["check", "--timeout", "-2"],
                 ["check", "--timeout", "soon"], ["serve", "--app-port", "70000"],
                 ["serve", "--timeout", "0"],
                 ["serve", "--proxy-port", str(port), "--app-port", str(port)]]
        with tempfile.TemporaryDirectory(prefix="usage cwd ") as directory:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = run_cli(*arguments, cwd=directory, timeout=120)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("usage:", result.stderr.lower())
                    self.assertFalse(accepts("127.0.0.1", port))

    def test_clean_checkout_check(self):
        if not is_git_checkout():
            self.skipTest("not a git checkout")
        with tempfile.TemporaryDirectory(prefix="clean checkout ",
                                         ignore_cleanup_errors=True) as directory, \
                tempfile.TemporaryDirectory(prefix="other cwd ") as cwd:
            checkout = extract_checkout(Path(directory) / "repo copy")
            self.assertFalse((checkout / ".git").exists())
            before = tree_listing(checkout)
            run_dir = Path(directory) / "run dir"
            result = run_cli("check", "--run-dir", str(run_dir), "--timeout", "120",
                             script=checkout / "scripts" / "transport_stack.py", cwd=cwd,
                             environment=unactivated_environment())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertCheckResult(json.loads(result.stdout), run_dir=run_dir)
            self.assertEqual(tree_listing(checkout), before)


if __name__ == "__main__":
    unittest.main()
