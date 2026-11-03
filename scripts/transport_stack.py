"""Start the Sprint 2 transport stack and check it end to end from Chromium.

The stack is nginx (reverse proxy) in front of Gunicorn serving the Flask app in
scripts/transport_app.py, all bound to 127.0.0.1. Every layer runs with its default
header and cookie limits. Run as a script to print each layer's version and send one
request from Playwright's Chromium through nginx to the application.
"""

import argparse
from contextlib import contextmanager
from importlib.metadata import version
import json
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from playwright.sync_api import Error as PlaywrightError, sync_playwright


REPO =Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
APP = "scripts.transport_app:app"

# Deliberately no client_header_buffer_size or large_client_header_buffers: the
# defaults are what Sprint 2 measures. Paths are quoted because they may contain spaces.
NGINX_CONF = """\
worker_processes 1;
daemon off;
pid "{prefix}/nginx.pid";
error_log "{prefix}/error.log" info;

events {{
    worker_connections 64;
}}

http {{
    access_log "{prefix}/access.log";
    client_body_temp_path "{prefix}/client_body";
    proxy_temp_path "{prefix}/proxy";
    fastcgi_temp_path "{prefix}/fastcgi";
    uwsgi_temp_path "{prefix}/uwsgi";
    scgi_temp_path "{prefix}/scgi";

    server {{
        listen {host}:{port};

        location / {{
            proxy_pass http://{host}:{app_port};
            proxy_set_header X-Proxied-By nginx;
        }}
    }}
}}
"""


def nginx_binary() -> str:
    """Prefer the nginx installed next to this Python (the conda environment's)."""
    beside_python = Path(sys.executable).with_name("nginx")
    found = str(beside_python) if beside_python.exists() else shutil.which("nginx")
    if not found:
        raise RuntimeError("nginx not found; install it with conda (see environment.yml)")
    return found


def nginx_version() -> str:
    # `nginx -v` prints "nginx version: nginx/1.31.8" to stderr.
    output = subprocess.run([nginx_binary(), "-v"], capture_output=True, text=True,
                            check=True).stderr
    return output.strip().rsplit("/", 1)[-1]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        return probe.getsockname()[1]


def wait_for_port(port: int, process: subprocess.Popen, log: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{process.args[0]} exited early:\n{log.read_text()}")
        try:
            with socket.create_connection((HOST, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on port {port} after {timeout} s:\n{log.read_text()}")


@contextmanager
def running(command: list[str], port: int, log: Path, cwd: Path | None = None):
    """Run a server process until the block exits, waiting first until it accepts connections."""
    with log.open("w") as output:
        process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
        try:
            wait_for_port(port, process, log)
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@contextmanager
def transport_stack():
    """Start Gunicorn and nginx with default limits; yield the proxy URL and log paths."""
    with tempfile.TemporaryDirectory(prefix="cis628-transport-") as directory:
        prefix = Path(directory)
        app_port, proxy_port = free_port(), free_port()
        config = prefix / "nginx.conf"
        config.write_text(NGINX_CONF.format(prefix=prefix, host=HOST, port=proxy_port,
                                            app_port=app_port), encoding="utf-8")
        app_command = [sys.executable, "-m", "gunicorn", "--bind", f"{HOST}:{app_port}",
                       "--workers", "1", APP]
        nginx_command = [nginx_binary(), "-p", str(prefix), "-c", str(config),
                         "-e", str(prefix / "error.log")]
        with running(app_command, app_port, prefix / "gunicorn.log", cwd=REPO), \
                running(nginx_command, proxy_port, prefix / "nginx-stdout.log"):
            yield {
                "url": f"http://{HOST}:{proxy_port}",
                "app_url": f"http://{HOST}:{app_port}",
                "logs": {
                    "nginx_access": prefix / "access.log",
                    "nginx_error": prefix / "error.log",
                    "gunicorn": prefix / "gunicorn.log",
                },
            }


def versions(chromium: str) -> dict:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "playwright": version("playwright"),
        "chromium": chromium,
        "nginx": nginx_version(),
        "gunicorn": version("gunicorn"),
        "flask": version("Flask"),
        "werkzeug": version("Werkzeug"),
    }


def check() -> dict:
    """Load /health in headless Chromium through nginx and report each layer's version."""
    with transport_stack() as stack, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            response = browser.new_page().goto(f"{stack['url']}/health")
            status, body = response.status, response.json()
            chromium = browser.version
        finally:
            browser.close()
    return {
        "versions": versions(chromium),
        "request": {"path": "/health", "status": status, "body": body},
        "ok": status == 200 and body == {"status": "ok", "proxied_by": "nginx"},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        report = check()
    except (OSError, RuntimeError, subprocess.CalledProcessError, PlaywrightError) as error:
        parser.exit(1, f"Error: {error}\n")
    print(json.dumps(report, indent=2))
    if not report["ok"]:
        parser.exit(1, "Error: the request did not travel Chromium → nginx → application\n")


if __name__ == "__main__":
    main()
