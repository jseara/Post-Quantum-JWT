"""Run the browser -> reverse proxy -> application stack and check real browser requests.

check starts the stack, loads the test page in headless Chromium through nginx, sends one
fetch() to /api/echo from that page, prints the result as JSON, and stops the stack. tokens does
the same with the fixture token of every configuration, once as a cookie and once as a Bearer
header, and names the layer that rejected any token that did not verify (see
scripts/transport_tokens.py). sweep sends cookie-carried tokens of growing size and narrows
each layer's rejection boundary (see scripts/transport_sweep.py). serve starts the stack and keeps it running until SIGINT or
SIGTERM. versions compares the installed component versions with transport/stack.json.
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
# The anchor in the rendered config after which --proxy-buffers inserts its directives.
PROXY_BUFFERS_ANCHOR = 'add_header X-Transport-Proxy'


def proxy_buffer_directives(size: str) -> list[str]:
    """nginx directives that set the upstream response buffers to `size`.

    proxy_buffer_size alone is not enough on 4 KiB-page systems: nginx then refuses to start,
    because the default proxy_busy_buffers_size (two buffers) must stay below all proxy_buffers
    minus one. Raising proxy_buffers to 8 buffers of the same size is valid everywhere, and
    with 16k it reproduces the defaults of a 16 KiB-page system such as Apple Silicon macOS.
    """
    if not isinstance(size, str) or not NGINX_SIZE.fullmatch(size):
        raise ValueError(f"proxy_buffers must be an nginx size such as 16k, got {size!r}")
    return [f"proxy_buffer_size {size};", f"proxy_buffers 8 {size};"]


@contextmanager
def start_stack(proxy_port: int | None = None, app_port: int | None = None,
                run_dir: str | Path | None = None, timeout: float = 60.0,
                proxy_buffers: str | None = None):
    """Start the application server and the reverse proxy; yield a Stack and stop both on exit.

    proxy_buffers, such as "16k", sets nginx's upstream response buffers (see
    proxy_buffer_directives); None keeps nginx's defaults, as transport/nginx.conf.template does.
    """
    for name, port in (("proxy_port", proxy_port), ("app_port", app_port)):
        if port is not None and not valid_port(port):
            raise ValueError(f"{name} must be an int in 1-65535, got {port!r}")
    if proxy_port is not None and proxy_port == app_port:
        raise ValueError("proxy_port and app_port must differ")
    check_timeout(timeout)
    buffer_directives = None if proxy_buffers is None else proxy_buffer_directives(proxy_buffers)

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
        if buffer_directives is not None:
            # Changed on purpose, so the rendered nginx.conf says so where it applies.
            line = next(line for line in config.splitlines() if PROXY_BUFFERS_ANCHOR in line)
            indent = line[:len(line) - len(line.lstrip())]
            added = [f"# Not a default: --proxy-buffers {proxy_buffers}.", *buffer_directives]
            config = config.replace(line, "\n".join([line, *(indent + a for a in added)]), 1)
        config_path = run_dir / "nginx" / "nginx.conf"
        config_path.write_text(config, encoding="utf-8")
        error_log = logs / "proxy-error.log"
        processes.append(launch([nginx, "-p", f"{run_dir / 'nginx'}/", "-c", str(config_path),
                                 "-e", str(error_log)], run_dir, error_log))
        wait_ready(names["proxy"], processes[-1], proxy_url, deadline, timeout, error_log, True)

        yield Stack(proxy_url=proxy_url, app_url=app_url, run_dir=run_dir)
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--proxy-port", type=port_number, help="proxy port (default: a free port)")
    options.add_argument("--app-port", type=port_number,
                         help="application port (default: a free port)")
    options.add_argument("--run-dir", type=Path,
                         help="directory for configs and logs (default: a new temporary directory)")
    options.add_argument("--timeout", type=positive_seconds, default=60.0,
                         help="seconds allowed for startup and for each browser step (default: 60)")
    options.add_argument("--proxy-buffers", metavar="SIZE",
                         help="set nginx's proxy_buffer_size to SIZE and proxy_buffers to 8 SIZE, "
                              "e.g. 16k (default: nginx's defaults, one memory page)")
    commands.add_parser("check", parents=[options],
                        help="start the stack, send one browser request through it, and stop it")
    tokens = commands.add_parser("tokens", parents=[options],
                                 help="send every configuration's fixture token through the stack "
                                      "as a cookie and as a Bearer header")
    tokens.add_argument("--alg", action="extend", nargs="+", type=algorithm_name, metavar="NAME",
                        help="configuration to run, from scripts/algorithms.py; repeat or list "
                             "several (default: all six)")
    sweep = commands.add_parser("sweep", parents=[options],
                                help="sweep cookie-carried token sizes and find where each layer "
                                     "rejects them")
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

    if args.proxy_port is not None and args.proxy_port == args.app_port:
        parser.error("--proxy-port and --app-port must differ")
    if args.command in ("tokens", "sweep") and args.alg and len(set(args.alg)) != len(args.alg):
        parser.error(f"--alg must not repeat a configuration, got {' '.join(args.alg)}")
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        with start_stack(args.proxy_port, args.app_port, args.run_dir, args.timeout,
                         args.proxy_buffers) as stack:
            if args.command == "check":
                result = run_check(stack, args.timeout)
            elif args.command == "tokens":
                result = run_token_check(stack, args.alg, args.timeout)
            elif args.command == "sweep":
                from scripts.transport_sweep import run_cookie_sweep, write_results

                result = run_cookie_sweep(stack, args.alg, args.claims, args.attrs, args.step,
                                          args.max_bytes, args.timeout, args.proxy_buffers)
                if args.output_dir:
                    write_results(result, args.output_dir)
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
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    if args.command == "tokens":
        report_token_check(parser, result)


if __name__ == "__main__":
    main()
