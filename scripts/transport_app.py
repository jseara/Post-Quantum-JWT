"""Serve the transport test page and the /api/echo endpoint with waitress on 127.0.0.1."""

import argparse
import json
import logging
from pathlib import Path
import sys
from urllib.parse import parse_qsl

import waitress
from waitress.channel import HTTPChannel
from waitress.parser import HTTPRequestParser


HOST = "127.0.0.1"
TEST_PAGE = Path(__file__).resolve().parents[1] / "transport" / "static" / "index.html"
LOG = logging.getLogger("transport_app")
MAX_LOGGED_LINE = 65536


class LoggingParser(HTTPRequestParser):
    """Waitress's request parser, plus a log line for each request rejected before the app runs."""

    start = b""

    def received(self, data: bytes) -> int:
        # waitress replaces the target of a rejected request (e.g. 431) with "/", so keep the
        # original request line.
        if b"\n" not in self.start.lstrip():
            self.start = (self.start + data)[:MAX_LOGGED_LINE]
        was_completed = self.completed
        consumed = super().received(data)
        if self.error is not None and not was_completed:
            request_line = self.start.lstrip().split(b"\n", 1)[0].rstrip(b"\r")
            LOG.info('"%s" %s rejected by waitress: %s', request_line.decode("latin-1"),
                     self.error.code, self.error.body)
        return consumed


def received_headers(environ: dict) -> dict:
    """Map each request header the server passed on, lowercased, to its value."""
    headers = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            # waitress drops header names containing "_", so "_" here always was "-".
            headers[key[5:].replace("_", "-").lower()] = value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            headers[key.replace("_", "-").lower()] = value
    return headers


def echo(environ: dict) -> dict:
    """Describe the request as the application received it."""
    return {
        "layer": "application",
        "method": environ["REQUEST_METHOD"],
        "path": environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", ""),
        "query": dict(parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True)),
        "headers": received_headers(environ),
    }


def json_response(status: str, body: dict) -> tuple[str, list, bytes]:
    data = (json.dumps(body, indent=2) + "\n").encode("utf-8")
    return status, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))], data


def route(environ: dict) -> tuple[str, list, bytes]:
    path = environ.get("PATH_INFO", "")
    if path == "/":
        data = TEST_PAGE.read_bytes()
        return "200 OK", [("Content-Type", "text/html; charset=utf-8"),
                          ("Content-Length", str(len(data)))], data
    if path == "/api/echo":
        return json_response("200 OK", echo(environ))
    return json_response("404 Not Found", {"layer": "application", "error": "not found",
                                           "path": path})


def application(environ: dict, start_response) -> list[bytes]:
    """WSGI entry point; logs one line per request with its target and status."""
    status, headers, body = route(environ)
    start_response(status, headers)
    target = environ.get("REQUEST_URI") or environ.get("PATH_INFO", "")
    LOG.info('%s "%s %s %s" %s', environ.get("REMOTE_ADDR"), environ["REQUEST_METHOD"], target,
             environ.get("SERVER_PROTOCOL"), status.split()[0])
    return [body]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True, help=f"TCP port on {HOST}")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # Only adds logging; parsing and its limits are waitress's own.
    HTTPChannel.parser_class = LoggingParser
    # Size limits stay at waitress defaults; only proxy-header clearing is off so the
    # echo reports every header that arrived.
    waitress.serve(application, host=HOST, port=args.port, clear_untrusted_proxy_headers=False)


if __name__ == "__main__":
    main()
