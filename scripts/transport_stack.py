"""Run the browser -> reverse proxy -> application stack and check real browser requests.

check starts the stack, loads the test page in headless Chromium through nginx, sends one
fetch() to /api/echo from that page, prints the result as JSON, and stops the stack. tokens does
the same with the fixture token of every configuration, once as a cookie and once as a Bearer
header, and names the layer that rejected any token that did not verify (see
scripts/transport_tokens.py). sweep sends cookie-carried tokens of growing size and narrows
each layer's rejection boundary (see scripts/transport_sweep.py). load measures the latency and
throughput of authenticated requests through the stack for every configuration and saves the
raw timings (see scripts/transport_load.py). claims measures the smaller-claim-set mitigation
(S3-02): token sizes, Sprint 2 boundaries, size limits at the defaults, and load latency with
oidc and essential claims (see scripts/transport_claims.py). serve starts the stack and keeps it
running until SIGINT or SIGTERM. versions compares the installed component versions with
transport/stack.json.
"""

import argparse
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import http.client
from importlib.metadata import PackageNotFoundError, version
import json
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
import tempfile
import time
from urllib.parse import urlsplit

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


REPO = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO / "transport" / "stack.json"
NGINX_TEMPLATE = REPO / "transport" / "nginx.conf.template"
APP_SCRIPT = REPO / "scripts" / "transport_app.py"
HOST = "127.0.0.1"
# "chromium" selects the full Chrome for Testing build in new headless mode, not the headless shell.
BROWSER_CHANNEL = "chromium"
PROXY_MARKER = "X-Transport-Proxy"
STOP_GRACE_SECONDS = 5.0
FETCH_ECHO = """async ({url, timeout}) => {
  const response = await fetch(url, {cache: "no-store", signal: AbortSignal.timeout(timeout)});
  const headers = {};
  response.headers.forEach((value, name) => { headers[name] = value; });
  return {status: response.status, headers, text: await response.text()};
}"""


@dataclass(frozen=True)
class Stack:
    proxy_url: str
    app_url: str
    run_dir: Path
    upstream_keepalive: int | None = None  # See upstream_keepalive_config; None is the default.


def load_manifest() -> dict:
    """Return transport/stack.json parsed."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def manifest_layers(manifest: dict) -> list[dict]:
    """Return each layer's role, component, and version, as the check results list them."""
    return [{key: layer[key] for key in ("role", "component", "version")}
            for layer in manifest["layers"]]


def find_executable(name: str) -> str | None:
    """Find an executable in the running interpreter's environment first, then on PATH."""
    for directory in (Path(sys.prefix) / "bin", Path(sys.executable).parent):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def nginx_version() -> str | None:
    nginx = find_executable("nginx")
    if nginx is None:
        return None
    try:
        # nginx -v prints to stderr and exits before opening any log or config file.
        output = subprocess.run([nginx, "-v"], capture_output=True, text=True, timeout=30,
                                stdin=subprocess.DEVNULL).stderr
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"nginx/(\S+)", output)
    return match.group(1) if match else None


def browser_version(timeout: float = 60.0) -> str | None:
    """Launch the browser headless and return the version it reports, or None."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=timeout * 1000)
            try:
                return browser.version
            finally:
                browser.close()
    except Exception:  # Not installed, browser missing, or launch failure all mean "not found".
        return None


def installed_versions() -> dict:
    """Query each installed component for its version; None when it cannot be found."""
    queries = {
        "automation": lambda: package_version("playwright"),
        "browser": browser_version,
        "proxy": nginx_version,
        "app_server": lambda: package_version("waitress"),
    }
    roles = [layer["role"] for layer in load_manifest()["layers"]]
    return {role: queries[role]() if role in queries else None for role in roles}


def http_get(url: str, headers: dict | None = None, timeout: float = 10.0) -> tuple[int, dict, bytes]:
    """Send one GET with http.client (no proxy settings) and return status, headers, body."""
    parts = urlsplit(url)
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        connection.request("GET", target or "/", headers=headers or {})
        response = connection.getresponse()
        return (response.status, {name.lower(): value for name, value in response.getheaders()},
                response.read())
    finally:
        connection.close()


def valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def check_timeout(timeout: object) -> None:
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or math.isnan(timeout) or timeout <= 0):
        raise ValueError(f"timeout must be a positive number of seconds, got {timeout!r}")


def free_port(exclude: set[int]) -> int:
    while True:
        with socket.socket() as probe:
            probe.bind((HOST, 0))
            port = probe.getsockname()[1]
        if port not in exclude:
            return port


def port_in_use(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.5):
            return True
    except OSError:
        pass
    with socket.socket() as probe:
        # Same option the servers set, so a closed port in TIME_WAIT still counts as free.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((HOST, port))
        except OSError:
            return True
    return False


def nginx_string(path: Path) -> str:
    """Escape a path for use inside a double-quoted nginx string."""
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def log_tail(path: Path, lines: int = 5) -> str:
    try:
        tail = path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return ""
    return "".join(f"\n  {line}" for line in tail)


def stop_process(process: subprocess.Popen) -> None:
    """Stop a process and every process in its session, such as nginx workers."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + STOP_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()  # Reap the leader so an exited group really disappears.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def launch(command: list[str], run_dir: Path, log_path: Path) -> subprocess.Popen:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    with log_path.open("ab") as log:
        # A new session gives each layer its own process group for stop_process.
        return subprocess.Popen(command, cwd=run_dir, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)


def wait_ready(layer: str, process: subprocess.Popen, base_url: str, deadline: float,
               timeout: float, log_path: Path, proxied: bool) -> None:
    """Wait until GET <base_url>/api/echo returns the application's echo."""
    while True:
        status = process.poll()
        if status is not None:
            raise RuntimeError(f"{layer} exited with status {status} during startup; "
                               f"see {log_path}{log_tail(log_path)}")
        try:
            attempt = min(1.0, max(0.05, deadline - time.monotonic()))
            code, headers, body = http_get(f"{base_url}/api/echo", timeout=attempt)
            if (code == 200 and json.loads(body).get("layer") == "application"
                    and (not proxied or PROXY_MARKER.lower() in headers)):
                return
        except (OSError, http.client.HTTPException, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{layer} was not ready within {timeout:g} s; "
                               f"see {log_path}{log_tail(log_path)}")
        time.sleep(0.05)


# nginx size syntax accepted by --proxy-buffers: a number of bytes, or of k or m units.
NGINX_SIZE = re.compile(r"[1-9][0-9]*[km]?")
# Anchors in the rendered config after which --proxy-buffers (location level) and
# --header-buffers (server level) insert their directives.
PROXY_BUFFERS_ANCHOR = 'add_header X-Transport-Proxy'
HEADER_BUFFERS_ANCHOR = 'listen 127.0.0.1:'


def nginx_size(name: str, size: str) -> str:
    if not isinstance(size, str) or not NGINX_SIZE.fullmatch(size):
        raise ValueError(f"{name} must be an nginx size such as 16k, got {size!r}")
    return size


def proxy_buffer_directives(size: str) -> list[str]:
    """nginx directives that set the upstream response buffers to `size`.

    proxy_buffer_size alone is not enough on 4 KiB-page systems: nginx then refuses to start,
    because the default proxy_busy_buffers_size (two buffers) must stay below all proxy_buffers
    minus one. Raising proxy_buffers to 8 buffers of the same size is valid everywhere, and
    with 16k it reproduces the defaults of a 16 KiB-page system such as Apple Silicon macOS.
    """
    nginx_size("proxy_buffers", size)
    return [f"proxy_buffer_size {size};", f"proxy_buffers 8 {size};"]


def header_buffer_directives(size: str) -> list[str]:
    """nginx directive that raises the request header line limit to `size`.

    Keeps the default count of 4 buffers, so the total request header limit is about 4 x size.
    large_client_header_buffers is valid only at http or server level, not in a location.
    """
    nginx_size("header_buffers", size)
    return [f"large_client_header_buffers 4 {size};"]


def insert_directives(config: str, anchor: str, option: str, value: str,
                      directives: list[str]) -> str:
    """Add directives after the line containing anchor, with a comment naming the option."""
    line = next(line for line in config.splitlines() if anchor in line)
    indent = line[:len(line) - len(line.lstrip())]
    added = [f"# Not a default: {option} {value}.", *directives]
    return config.replace(line, "\n".join([line, *(indent + a for a in added)]), 1)


UPSTREAM_NAME = "transport_app"
MAX_UPSTREAM_KEEPALIVE = 1024


def check_upstream_keepalive(connections: object) -> None:
    """Raise ValueError unless connections is an int from 1 to MAX_UPSTREAM_KEEPALIVE."""
    if (isinstance(connections, bool) or not isinstance(connections, int)
            or not 1 <= connections <= MAX_UPSTREAM_KEEPALIVE):
        raise ValueError(f"upstream_keepalive must be an int in 1-{MAX_UPSTREAM_KEEPALIVE}, "
                         f"got {connections!r}")


def upstream_keepalive_config(config: str, app_port: int, connections: int) -> str:
    """Send nginx's requests to waitress over up to `connections` kept-alive connections.

    By default nginx opens a new connection to waitress for every request and closes it, which
    leaves a TIME_WAIT socket on an ephemeral port for twice the maximum segment lifetime. On
    macOS (16,384 ephemeral ports, 30 s in TIME_WAIT) a few thousand requests per second use
    them all up within seconds, and later connections fail. An upstream block with `keepalive`
    reuses connections instead; it needs HTTP/1.1 and an empty Connection header. Host stays
    127.0.0.1:<app_port>, what nginx sends by default, so only Connection differs at the app.
    """
    check_upstream_keepalive(connections)
    server = f"{HOST}:{app_port}"
    config = config.replace(f"proxy_pass http://{server};", f"proxy_pass http://{UPSTREAM_NAME};",
                            1)
    config = insert_directives(config, f"proxy_pass http://{UPSTREAM_NAME};",
                               "--upstream-keepalive", str(connections),
                               ["proxy_http_version 1.1;", 'proxy_set_header Connection "";',
                                f"proxy_set_header Host {server};"])
    server_line = next(line for line in config.splitlines() if line.strip() == "server {")
    indent = server_line[:len(server_line) - len(server_line.lstrip())]
    block = [f"# Not a default: --upstream-keepalive {connections}.",
             f"upstream {UPSTREAM_NAME} {{", f"    server {server};",
             f"    keepalive {connections};", "}", ""]
    return config.replace(server_line, "\n".join([*(indent + line if line else line
                                                    for line in block), server_line]), 1)


@contextmanager
def start_stack(proxy_port: int | None = None, app_port: int | None = None,
                run_dir: str | Path | None = None, timeout: float = 60.0,
                proxy_buffers: str | None = None, header_buffers: str | None = None,
                upstream_keepalive: int | None = None):
    """Start the application server and the reverse proxy; yield a Stack and stop both on exit.

    proxy_buffers, such as "16k", sets nginx's upstream response buffers (see
    proxy_buffer_directives), header_buffers, such as "512k", raises nginx's request header
    line limit (see header_buffer_directives), and upstream_keepalive, such as 64, keeps that
    many idle connections from nginx to waitress open (see upstream_keepalive_config); None
    keeps nginx's defaults, as transport/nginx.conf.template does.
    """
    for name, port in (("proxy_port", proxy_port), ("app_port", app_port)):
        if port is not None and not valid_port(port):
            raise ValueError(f"{name} must be an int in 1-65535, got {port!r}")
    if proxy_port is not None and proxy_port == app_port:
        raise ValueError("proxy_port and app_port must differ")
    check_timeout(timeout)
    buffer_directives = None if proxy_buffers is None else proxy_buffer_directives(proxy_buffers)
    header_directives = None if header_buffers is None else header_buffer_directives(header_buffers)
    if upstream_keepalive is not None:
        check_upstream_keepalive(upstream_keepalive)

    manifest = {layer["role"]: layer for layer in load_manifest()["layers"]}
    # Error messages name the layer by role and component, e.g. "proxy (nginx)".
    names = {role: f"{role} ({layer['component']})" for role, layer in manifest.items()}
    if run_dir is None:
        run_dir = Path(tempfile.mkdtemp(prefix="transport-stack-"))
    run_dir = Path(run_dir).absolute()
    for directory in (run_dir / "logs", run_dir / "nginx"):
        directory.mkdir(parents=True, exist_ok=True)
    logs = run_dir / "logs"
    if proxy_port is None:
        proxy_port = free_port({app_port})
    if app_port is None:
        app_port = free_port({proxy_port})
    proxy_url, app_url = f"http://{HOST}:{proxy_port}", f"http://{HOST}:{app_port}"
    deadline = time.monotonic() + timeout

    processes = []
    try:
        for role, port in (("proxy", proxy_port), ("app_server", app_port)):
            if port_in_use(port):
                raise RuntimeError(f"{names[role]}: port {port} on {HOST} is already in use")
        nginx = find_executable("nginx")
        if nginx is None:
            raise RuntimeError(f"{names['proxy']}: nginx executable not found")

        processes.append(launch([sys.executable, str(APP_SCRIPT), "--port", str(app_port)],
                                run_dir, logs / "app.log"))
        wait_ready(names["app_server"], processes[-1], app_url, deadline, timeout,
                   logs / "app.log", False)

        config = NGINX_TEMPLATE.read_text(encoding="utf-8")
        for token, value in {"@RUN_DIR@": nginx_string(run_dir), "@PROXY_PORT@": str(proxy_port),
                             "@APP_PORT@": str(app_port),
                             "@PROXY_COMPONENT@": manifest["proxy"]["component"]}.items():
            config = config.replace(token, value)
        # Changed on purpose, so the rendered nginx.conf says so where each applies.
        if buffer_directives is not None:
            config = insert_directives(config, PROXY_BUFFERS_ANCHOR, "--proxy-buffers",
                                       proxy_buffers, buffer_directives)
        if header_directives is not None:
            config = insert_directives(config, HEADER_BUFFERS_ANCHOR, "--header-buffers",
                                       header_buffers, header_directives)
        if upstream_keepalive is not None:
            config = upstream_keepalive_config(config, app_port, upstream_keepalive)
        config_path = run_dir / "nginx" / "nginx.conf"
        config_path.write_text(config, encoding="utf-8")
        error_log = logs / "proxy-error.log"
        processes.append(launch([nginx, "-p", f"{run_dir / 'nginx'}/", "-c", str(config_path),
                                 "-e", str(error_log)], run_dir, error_log))
        wait_ready(names["proxy"], processes[-1], proxy_url, deadline, timeout, error_log, True)

        yield Stack(proxy_url=proxy_url, app_url=app_url, run_dir=run_dir,
                    upstream_keepalive=upstream_keepalive)
    finally:
        for process in reversed(processes):
            stop_process(process)


def run_check(stack, timeout: float = 60.0) -> dict:
    """Load the test page in headless Chromium and fetch /api/echo from it through the proxy."""
    check_timeout(timeout)
    try:
        from playwright.sync_api import Error as PlaywrightError, sync_playwright
    except ImportError as error:
        raise RuntimeError(f"automation: Playwright is not installed ({error})") from error

    manifest = load_manifest()
    documented_browser = next(layer["version"] for layer in manifest["layers"]
                              if layer["role"] == "browser")
    nonce = secrets.token_hex(16)
    page_url = f"{stack.proxy_url}/"
    echo_url = f"{stack.proxy_url}/api/echo?nonce={nonce}"
    milliseconds = timeout * 1000

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=milliseconds)
            try:
                reported_version = browser.version
                page = browser.new_page()
                page.set_default_timeout(milliseconds)
                page_response = page.goto(page_url, timeout=milliseconds)
                page_status = page_response.status if page_response else None
                if page_status != 200:
                    raise RuntimeError(f"page {page_url} returned status {page_status}")
                user_agent = page.evaluate("navigator.userAgent")
                # fetch() from inside the page, so the request leaves through the browser.
                echo = page.evaluate(FETCH_ECHO, {"url": echo_url, "timeout": milliseconds})
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error

    if echo["status"] != 200:
        raise RuntimeError(f"{echo_url} returned status {echo['status']}")
    if PROXY_MARKER.lower() not in echo["headers"]:
        raise RuntimeError(f"the echo response has no {PROXY_MARKER} header")
    try:
        body = json.loads(echo["text"])
    except ValueError as error:
        raise RuntimeError(f"the echo response is not JSON: {error}") from error
    if body.get("query", {}).get("nonce") != nonce:
        raise RuntimeError("the echoed nonce differs from the one sent")
    if body.get("headers", {}).get("user-agent") != user_agent:
        raise RuntimeError("the echoed User-Agent differs from navigator.userAgent")
    if reported_version != documented_browser:
        raise RuntimeError(f"browser reports version {reported_version}, "
                           f"manifest documents {documented_browser}")

    return {
        "ok": True,
        "proxy_url": stack.proxy_url,
        "app_url": stack.app_url,
        "run_dir": str(stack.run_dir),
        "layers": manifest_layers(manifest),
        "browser": {"version": reported_version, "user_agent": user_agent},
        "page": {"url": page_url, "status": page_status},
        "request": {"url": echo_url, "nonce": nonce},
        "response": {"status": echo["status"], "headers": echo["headers"], "body": body},
    }


def run_token_check(stack, algorithms: Sequence[str] | None = None,
                    timeout: float = 60.0) -> dict:
    """Send each configuration's fixture token as a cookie and a Bearer header through the stack."""
    # Imported on first use, so check, serve, and versions never load the crypto libraries.
    from scripts.transport_tokens import run_token_check as run_tokens

    return run_tokens(stack, algorithms, timeout)


def port_number(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {text!r}") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port must be in 1-65535, got {port}")
    return port


def positive_seconds(text: str) -> float:
    try:
        seconds = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid timeout: {text!r}") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(f"timeout must be a positive number, got {text}")
    return seconds


def algorithm_name(text: str) -> str:
    from scripts.algorithms import ADAPTERS  # Only the tokens command loads the crypto libraries.

    if text not in ADAPTERS:
        raise argparse.ArgumentTypeError(f"unknown algorithm {text!r}; "
                                         f"choose from {', '.join(ADAPTERS)}")
    return text


def finite_seconds(text: str, name: str, allow_zero: bool) -> float:
    """Parse a finite number of seconds above zero (or at zero, with allow_zero) for `name`."""
    try:
        seconds = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid {name}: {text!r}") from None
    if not math.isfinite(seconds) or seconds < 0 or (seconds == 0 and not allow_zero):
        bound = "at least 0" if allow_zero else "more than 0"
        raise argparse.ArgumentTypeError(f"{name} must be a finite number of seconds {bound}, "
                                         f"got {text}")
    return seconds


def duration_seconds(text: str) -> float:
    """Parse --duration: the measured seconds of each load cell, more than zero."""
    return finite_seconds(text, "duration", allow_zero=False)


def warmup_seconds(text: str) -> float:
    """Parse --warmup: the unrecorded seconds before each load cell, zero or more."""
    return finite_seconds(text, "warmup", allow_zero=True)


def concurrency_level(text: str) -> int:
    """Parse a number of closed-loop workers, from 1 to the load command's maximum."""
    from scripts.transport_load import MAX_CONCURRENCY  # Only load loads the crypto libraries.

    try:
        level = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid concurrency: {text!r}") from None
    if not 1 <= level <= MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(f"concurrency must be from 1 to {MAX_CONCURRENCY}, "
                                         f"got {level}")
    return level


def keepalive_connections(text: str) -> int:
    """Parse --upstream-keepalive: a number of idle connections nginx may keep to waitress."""
    try:
        connections = int(text)
        check_upstream_keepalive(connections)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None
    return connections


def header_buffer_size(text: str) -> str:
    """Parse the claims command's --header-buffers: an nginx size such as 32k."""
    try:
        return nginx_size("header_buffers", text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def reject_repeated_values(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Exit 2 if --alg, --client, or --concurrency repeats a value."""
    for option, values in (("--alg", args.alg), ("--client", args.client),
                           ("--concurrency", args.concurrency)):
        if values and len(set(values)) != len(values):
            parser.error(f"{option} must not repeat a value, got {' '.join(map(str, values))}")


def reject_used_output_dir(parser: argparse.ArgumentParser, output_dir: Path) -> None:
    """Exit 2 if --output-dir exists and is not an empty directory, so no run is overwritten."""
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        parser.error(f"--output-dir {output_dir} exists and is not empty; choose a new directory")


# Each run_load setting, mapped to the attribute of the load command's option that sets it.
LOAD_SETTING_OPTIONS = {
    "algorithms": "alg", "transport": "transport", "clients": "client", "claims": "claims",
    "concurrency": "concurrency", "duration": "duration", "warmup": "warmup",
    "reference": "reference", "size_controls": "size_controls", "timeout": "timeout",
    "proxy_buffers": "proxy_buffers", "header_buffers": "header_buffers",
    "upstream_keepalive": "upstream_keepalive",
}


def load_command_settings(parser: argparse.ArgumentParser, args: argparse.Namespace) -> dict:
    """Return the load command's run_load settings; exit 2 on a usage error, before any start.

    Each setting comes from its option when it was given, else from the --settings file, else
    from run_load's default. The load command's options default to None, so a value given on
    the command line is never mistaken for a default. Ports, --run-dir, and --output-dir are
    never taken from the file.
    """
    from scripts.transport_load import default_settings, checked_settings, read_saved_settings

    reject_repeated_values(parser, args)
    reject_used_output_dir(parser, args.output_dir)

    settings = default_settings()
    if args.settings is not None:
        try:
            settings.update(read_saved_settings(args.settings))
        except ValueError as error:
            parser.error(f"--settings: {error}")
    given = {name: getattr(args, option) for name, option in LOAD_SETTING_OPTIONS.items()}
    settings.update({name: value for name, value in given.items() if value is not None})
    try:
        return checked_settings(**settings)
    except ValueError as error:  # Options are checked as they are parsed, so a saved value.
        parser.error(f"--settings: {error}")


# Each run_claims setting, mapped to the attribute of the claims command's option that sets it.
CLAIMS_SETTING_OPTIONS = {
    "algorithms": "alg", "clients": "client", "concurrency": "concurrency",
    "duration": "duration", "warmup": "warmup", "timeout": "timeout",
    "header_buffers": "header_buffers", "upstream_keepalive": "upstream_keepalive",
}


def claims_command_settings(parser: argparse.ArgumentParser, args: argparse.Namespace) -> dict:
    """Return the claims command's run_claims settings; exit 2 on a usage error, before any start.

    As for load, each setting comes from its option when it was given, else from the --settings
    file (an earlier claims.json), else from run_claims's default. --output-dir and --run-dir
    are never taken from the file.
    """
    from scripts.transport_claims import checked_settings, default_settings, read_saved_settings

    reject_repeated_values(parser, args)
    reject_used_output_dir(parser, args.output_dir)

    settings = default_settings()
    if args.settings is not None:
        try:
            settings.update(read_saved_settings(args.settings))
        except ValueError as error:
            parser.error(f"--settings: {error}")
    given = {name: getattr(args, option) for name, option in CLAIMS_SETTING_OPTIONS.items()}
    settings.update({name: value for name, value in given.items() if value is not None})
    try:
        return checked_settings(**settings)
    except ValueError as error:  # Options are checked as they are parsed, so a saved value.
        parser.error(f"--settings: {error}")


def run_claims_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Run every phase of the claims command, print its summary, and say where it was saved.

    Usage errors exit 2 before any process starts. Runtime failures and SIGINT or SIGTERM print
    'Error: ...' and exit 1, after every started process has been stopped. Rejected pairs are
    results, not failures, so they still exit 0.
    """
    settings = claims_command_settings(parser, args)
    from scripts.transport_claims import run_claims, summary_lines

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        result = run_claims(args.output_dir, run_dir=args.run_dir, **settings)
    except KeyboardInterrupt:
        parser.exit(1, "Error: interrupted\n")
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    sys.stdout.write("".join(f"{line}\n" for line in summary_lines(result)))
    sys.stdout.write(f"Saved the results to {args.output_dir}\n")


def report_token_check(parser: argparse.ArgumentParser, result: dict) -> None:
    """Summarize each pair on stderr, and exit 1 if a pair did not match the documented limits."""
    from scripts.transport_tokens import mismatch_message, summary_lines

    sys.stderr.write("".join(f"{line}\n" for line in summary_lines(result)))
    if not result["ok"]:
        parser.exit(1, f"Error: {mismatch_message(result)}\n")


def interrupt(signum: int, frame) -> None:
    # A second signal must not interrupt the shutdown of the stack or the browser.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


def stack_options(timeout_default: float | None = 60.0) -> argparse.ArgumentParser:
    """Return the parent parser of the options shared by every command that starts the stack.

    load uses timeout_default=None, so it can tell a --timeout given on the command line from
    one it should take from --settings; it then falls back to 60 seconds itself.
    """
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--proxy-port", type=port_number, help="proxy port (default: a free port)")
    options.add_argument("--app-port", type=port_number,
                         help="application port (default: a free port)")
    options.add_argument("--run-dir", type=Path,
                         help="directory for configs and logs (default: a new temporary directory)")
    options.add_argument("--timeout", type=positive_seconds, default=timeout_default,
                         help="seconds allowed for startup and for each browser step (default: 60)")
    options.add_argument("--proxy-buffers", metavar="SIZE",
                         help="set nginx's proxy_buffer_size to SIZE and proxy_buffers to 8 SIZE, "
                              "e.g. 16k (default: nginx's defaults, one memory page)")
    options.add_argument("--header-buffers", metavar="SIZE",
                         help="set nginx's large_client_header_buffers to 4 SIZE, raising the "
                              "request header line limit, e.g. 512k (default: 4 8k)")
    return options


def add_load_command(commands) -> None:
    """Add the load command; its options default to None so --settings can fill them in."""
    load = commands.add_parser("load", parents=[stack_options(timeout_default=None)],
                               help="measure end-to-end latency and throughput of authenticated "
                                    "requests through the stack")
    load.add_argument("--transport", choices=("bearer", "cookie"),
                      help="carry the token in an Authorization: Bearer header (default) or a "
                           "jwt cookie")
    load.add_argument("--client", action="extend", nargs="+", choices=("direct", "browser"),
                      help="send from http.client threads (direct), from Chromium's test page "
                           "(browser), or both (default: direct browser)")
    load.add_argument("--alg", action="extend", nargs="+", type=algorithm_name, metavar="NAME",
                      help="configuration to measure; repeat or list several (default: all six; "
                           "the reference is always measured)")
    # Literal names, so importing this module never loads scripts.token_sizing.
    load.add_argument("--claims", choices=("minimal", "oidc", "essential"),
                      help="claims fixture of every token (default: minimal)")
    load.add_argument("--concurrency", action="extend", nargs="+", type=concurrency_level,
                      metavar="N", help="closed-loop workers, 1-64; repeat or list several "
                                        "(default: 1 4)")
    load.add_argument("--duration", type=duration_seconds, metavar="SECONDS",
                      help="measured seconds per cell (default: 5)")
    load.add_argument("--warmup", type=warmup_seconds, metavar="SECONDS",
                      help="unrecorded seconds before each cell's measurement (default: 1)")
    load.add_argument("--reference", type=algorithm_name, metavar="NAME",
                      help="configuration every other one is compared with (default: ES256)")
    load.add_argument("--no-size-controls", dest="size_controls", action="store_const",
                      const=False, help="skip the size-matched control cells (the reference's "
                                        "token padded to each configuration's size)")
    load.add_argument("--settings", type=Path, metavar="PATH",
                      help="reuse the settings of an earlier run's load.json; options given here "
                           "override the saved values")
    load.add_argument("--upstream-keepalive", type=keepalive_connections, metavar="N",
                      help="not a default: let nginx keep up to N idle connections to waitress, "
                           "so a sustained load does not run out of ephemeral ports on macOS "
                           "(default: a new connection per request)")
    load.add_argument("--output-dir", type=Path, required=True, metavar="DIR",
                      help="save load.json, raw.csv.gz, the logs, and nginx.conf here; it must "
                           "not exist yet or be empty")


def add_claims_command(commands) -> None:
    """Add the claims command; its options default to None so --settings can fill them in.

    It starts its own stacks, so it takes none of the shared stack options except --timeout,
    --header-buffers, and --run-dir.
    """
    claims = commands.add_parser("claims",
                                 help="measure the smaller-claim-set mitigation (S3-02): token "
                                      "sizes, Sprint 2 boundaries, size limits, and latency")
    claims.add_argument("--output-dir", type=Path, required=True, metavar="DIR",
                        help="save claims.json, limits/, latency-oidc/, and latency-essential/ "
                             "here; it must not exist yet or be empty")
    claims.add_argument("--settings", type=Path, metavar="PATH",
                        help="reuse the settings of an earlier run's claims.json; options given "
                             "here override the saved values")
    claims.add_argument("--alg", action="extend", nargs="+", type=algorithm_name, metavar="NAME",
                        help="configuration to measure; repeat or list several (default: all "
                             "six; ES256, the latency reference, is always measured)")
    claims.add_argument("--client", action="extend", nargs="+", choices=("direct", "browser"),
                        help="latency clients: http.client threads (direct), Chromium's test "
                             "page (browser), or both (default: direct browser)")
    claims.add_argument("--concurrency", action="extend", nargs="+", type=concurrency_level,
                        metavar="N", help="latency closed-loop workers, 1-64; repeat or list "
                                          "several (default: 1 4)")
    claims.add_argument("--duration", type=duration_seconds, metavar="SECONDS",
                        help="measured seconds per latency cell (default: 5)")
    claims.add_argument("--warmup", type=warmup_seconds, metavar="SECONDS",
                        help="unrecorded seconds before each latency cell (default: 1)")
    claims.add_argument("--timeout", type=positive_seconds, metavar="SECONDS",
                        help="seconds allowed for startup and for each browser step (default: 60)")
    claims.add_argument("--header-buffers", type=header_buffer_size, metavar="SIZE",
                        help="latency stacks only: set nginx's large_client_header_buffers to 4 "
                             "SIZE, e.g. 32k (default: 4 8k); the size-limits stack always "
                             "keeps the defaults")
    claims.add_argument("--upstream-keepalive", type=keepalive_connections, metavar="N",
                        help="latency stacks only, not a default: let nginx keep up to N idle "
                             "connections to waitress (default: a new connection per request)")
    claims.add_argument("--run-dir", type=Path, metavar="DIR",
                        help="put the three stacks' run directories (limits, latency-oidc, "
                             "latency-essential) here (default: a new temporary directory each)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    options = stack_options()
    commands.add_parser("check", parents=[options],
                        help="start the stack, send one browser request through it, and stop it")
    tokens = commands.add_parser("tokens", parents=[options],
                                 help="send every configuration's fixture token through the stack "
                                      "as a cookie and as a Bearer header")
    tokens.add_argument("--alg", action="extend", nargs="+", type=algorithm_name, metavar="NAME",
                        help="configuration to run, from scripts/algorithms.py; repeat or list "
                             "several (default: all six)")
    sweep = commands.add_parser("sweep", parents=[options],
                                help="sweep token sizes as a cookie or Bearer header and find "
                                     "where each layer rejects them")
    sweep.add_argument("--transport", choices=("cookie", "bearer"), default="cookie",
                       help="carry the token in a cookie (default) or an Authorization: Bearer "
                            "header")
    sweep.add_argument("--client", action="extend", nargs="+", choices=("browser", "direct"),
                       help="bearer only: send from Chromium, from http.client, or both "
                            "(default: both)")
    sweep.add_argument("--alg", action="extend", nargs="+", type=algorithm_name, metavar="NAME",
                       help="configuration to sweep; repeat or list several (default: all six)")
    sweep.add_argument("--claims", choices=("minimal", "oidc"), default="minimal",
                       help="claims fixture to pad (default: minimal)")
    sweep.add_argument("--attrs", choices=("default", "full"), default="default",
                       help="cookie attributes: default (Path, HttpOnly, SameSite) or full "
                            "(adds Secure and Max-Age)")
    sweep.add_argument("--step", type=int, default=512,
                       help="coarse step in token bytes before narrowing (default: 512)")
    sweep.add_argument("--max-bytes", type=int, default=24_576,
                       help="largest token to probe (default: 24,576)")
    sweep.add_argument("--output-dir", type=Path,
                       help="save sweep.json, the logs, and nginx.conf here")
    add_load_command(commands)
    add_claims_command(commands)
    commands.add_parser("serve", parents=[options], help="start the stack until SIGINT or SIGTERM")
    commands.add_parser("versions", help="compare installed versions with transport/stack.json")
    args = parser.parse_args()

    if args.command == "versions":
        installed = installed_versions()
        layers = [{"role": layer["role"], "component": layer["component"],
                   "documented": layer["version"], "installed": installed[layer["role"]]}
                  for layer in load_manifest()["layers"]]
        mismatched = [f"{layer['role']} (documented {layer['documented']}, "
                      f"installed {layer['installed'] or 'not found'})"
                      for layer in layers if layer["installed"] != layer["documented"]]
        sys.stdout.write(json.dumps({"ok": not mismatched, "layers": layers}, indent=2) + "\n")
        if mismatched:
            parser.exit(1, f"Error: version mismatch: {', '.join(mismatched)}\n")
        return
    if args.command == "claims":  # It starts its own stacks, one per phase.
        run_claims_command(parser, args)
        return

    if args.proxy_port is not None and args.proxy_port == args.app_port:
        parser.error("--proxy-port and --app-port must differ")
    if args.command in ("tokens", "sweep") and args.alg and len(set(args.alg)) != len(args.alg):
        parser.error(f"--alg must not repeat a configuration, got {' '.join(args.alg)}")
    upstream_keepalive = None
    if args.command == "load":
        settings = load_command_settings(parser, args)
        # These configure the new stack too, and may have come from --settings.
        args.timeout = settings["timeout"]
        args.proxy_buffers = settings["proxy_buffers"]
        args.header_buffers = settings["header_buffers"]
        upstream_keepalive = settings["upstream_keepalive"]
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        with start_stack(args.proxy_port, args.app_port, args.run_dir, args.timeout,
                         args.proxy_buffers, args.header_buffers,
                         upstream_keepalive=upstream_keepalive) as stack:
            if args.command == "check":
                result = run_check(stack, args.timeout)
            elif args.command == "tokens":
                result = run_token_check(stack, args.alg, args.timeout)
            elif args.command == "sweep":
                from scripts.transport_sweep import run_sweep, write_results

                result = run_sweep(stack, args.transport, args.alg, args.client, args.claims,
                                   args.attrs, args.step, args.max_bytes, args.timeout,
                                   args.proxy_buffers, args.header_buffers)
                if args.output_dir:
                    write_results(result, args.output_dir)
            elif args.command == "load":
                from scripts.transport_load import run_load, write_load_results

                result = run_load(stack, **settings)
                write_load_results(result, args.output_dir)
            else:
                print(json.dumps({"proxy_url": stack.proxy_url, "app_url": stack.app_url,
                                  "run_dir": str(stack.run_dir)}), flush=True)
                try:
                    while True:
                        signal.pause()
                except KeyboardInterrupt:
                    pass  # The signal that ends serve; interrupt() ignores any later one.
                return
    except KeyboardInterrupt:
        parser.exit(1, "Error: interrupted\n")
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    if args.command == "sweep":
        from scripts.transport_sweep import summary_lines as sweep_summary

        sys.stdout.write("".join(f"{line}\n" for line in sweep_summary(result)))
        return
    if args.command == "load":
        from scripts.transport_load import summary_lines as load_summary

        sys.stdout.write("".join(f"{line}\n" for line in load_summary(result)))
        sys.stdout.write(f"Saved the results to {args.output_dir}\n")
        return
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    if args.command == "tokens":
        report_token_check(parser, result)


if __name__ == "__main__":
    main()
