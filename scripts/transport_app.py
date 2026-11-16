"""Serve the transport test page, the echo, and the token endpoints with waitress on 127.0.0.1.

GET / returns the test page and GET /api/echo describes the request as the application received
it. GET /api/token/issue signs a claims fixture (fixtures/claims.json by default), padded to a
chosen size if asked, with one configuration from scripts/algorithms.py, verifies it, and delivers
the token in a `jwt` Set-Cookie header or in a JSON body; GET
/api/token/verify verifies the token sent in the `jwt` cookie or an Authorization: Bearer header.
Tokens are signed with ephemeral experiment keys: one key pair per configuration, generated in
memory by this process on first use and never stored, logged, or returned. They are not
production credentials, and a token from another process does not verify here. Every request
the application handles writes one log line with the sizes of the headers it received.
"""

import argparse
import json
import logging
from pathlib import Path
import sys
import threading
from urllib.parse import parse_qsl

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
import waitress
from waitress.channel import HTTPChannel
from waitress.parser import HTTPRequestParser

from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.compact_jws import decode_json_object
from scripts.token_sizing import CLAIM_SETS, MAX_PAD, claim_set, padded_token


REPO = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
TEST_PAGE = REPO / "transport" / "static" / "index.html"
LOG = logging.getLogger("transport_app")
MAX_LOGGED_LINE = 65536
COOKIE_NAME = "jwt"
COOKIE_ATTRIBUTES = "Path=/; HttpOnly; SameSite=Strict"
# attrs=full adds the attributes a production session cookie typically carries (S2-04).
COOKIE_ATTRIBUTE_SETS = {"default": COOKIE_ATTRIBUTES,
                         "full": "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"}
# The audience the application expects in tokens that carry an aud claim (claims=oidc).
APP_AUDIENCE = "cis628-transport-client"
DELIVERIES = ("cookie", "body")
ALGORITHM_NAMES = [adapter.name for adapter in ADAPTER_LIST]

Response = tuple[str, list, bytes]  # WSGI status, headers, and body.

# One ephemeral key pair per configuration, shared by every waitress thread of this process.
EXPERIMENT_KEYS: dict[str, tuple] = {}
EXPERIMENT_KEYS_LOCK = threading.Lock()


class LoggingParser(HTTPRequestParser):
    """Waitress's request parser, plus a log line for each request rejected before the app runs."""

    start = b""
    received_bytes = 0

    def received(self, data: bytes) -> int:
        # waitress replaces the target of a rejected request (e.g. 431) with "/", so keep the
        # original request line.
        if b"\n" not in self.start.lstrip():
            self.start = (self.start + data)[:MAX_LOGGED_LINE]
        was_completed = self.completed
        consumed = super().received(data)
        self.received_bytes += consumed
        if self.error is not None and not was_completed:
            request_line = self.start.lstrip().split(b"\n", 1)[0].rstrip(b"\r")
            LOG.info('"%s" %s rejected by waitress: %s received_bytes=%d',
                     request_line.decode("latin-1"), self.error.code, self.error.body,
                     self.received_bytes)
        return consumed


def experiment_keypair(algorithm: str) -> tuple:
    """Return this process's (private, public) key pair for an algorithm, creating it once."""
    with EXPERIMENT_KEYS_LOCK:
        if algorithm not in EXPERIMENT_KEYS:
            EXPERIMENT_KEYS[algorithm] = ADAPTERS[algorithm].generate_keypair()
        return EXPERIMENT_KEYS[algorithm]


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


def received_sizes(headers: dict) -> dict:
    """Count the received headers and their bytes, each as one `name: value\\r\\n` line."""
    # WSGI passes header values as latin-1 decoded strings, so len() is their size in bytes.
    return {
        "headers": len(headers),
        "header_bytes": sum(len(name) + len(": ") + len(value) + len("\r\n")
                            for name, value in headers.items()),
        "cookie_bytes": len(headers["cookie"]) if "cookie" in headers else None,
        "authorization_bytes": (len(headers["authorization"]) if "authorization" in headers
                                else None),
    }


def query_parameters(environ: dict) -> dict:
    """Map each query parameter to its last value."""
    return dict(parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True))


def echo(environ: dict) -> dict:
    """Describe the request as the application received it."""
    return {
        "layer": "application",
        "method": environ["REQUEST_METHOD"],
        "path": environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", ""),
        "query": query_parameters(environ),
        "headers": received_headers(environ),
    }


def json_response(status: str, body: dict) -> Response:
    data = (json.dumps(body, indent=2) + "\n").encode("utf-8")
    return status, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))], data


def issue_problem(algorithm: str | None, delivery: str, claims: str = "minimal",
                  pad: str = "0", attrs: str = "default") -> str | None:
    """Say what is wrong with an issue request's parameters, or return None."""
    if algorithm is None:
        return "missing alg parameter"
    if algorithm not in ADAPTERS:
        return f"unknown alg {algorithm!r}"
    if delivery not in DELIVERIES:
        return f"delivery must be one of {', '.join(DELIVERIES)}, got {delivery!r}"
    if claims not in CLAIM_SETS:
        return f"claims must be one of {', '.join(CLAIM_SETS)}, got {claims!r}"
    # Check the length before int(), which raises ValueError on strings of over 4,300 digits.
    if not (pad.isascii() and pad.isdigit() and len(pad) <= len(str(MAX_PAD))
            and int(pad) <= MAX_PAD):
        return f"pad must be an integer from 0 to {MAX_PAD:,}, got {pad!r}"
    if attrs not in COOKIE_ATTRIBUTE_SETS:
        return f"attrs must be one of {', '.join(COOKIE_ATTRIBUTE_SETS)}, got {attrs!r}"
    return None


def issue_endpoint(environ: dict) -> tuple[Response, dict]:
    """Sign a claims fixture, padded if asked, and deliver it in a Set-Cookie header or the body.

    Optional parameters: claims (minimal, the default, or oidc), pad (characters in a `pad`
    claim, default 0, see scripts/token_sizing.py), and attrs (default or full cookie attributes).
    """
    query = query_parameters(environ)
    algorithm, delivery = query.get("alg"), query.get("delivery", "cookie")
    claims_name, pad, attrs = (query.get("claims", "minimal"), query.get("pad", "0"),
                               query.get("attrs", "default"))
    problem = issue_problem(algorithm, delivery, claims_name, pad, attrs)
    if problem is not None:
        known = algorithm if algorithm in ADAPTERS else None
        return json_response("400 Bad Request", {
            "layer": "application", "error": problem, "algorithms": ALGORITHM_NAMES,
            "experiment_key": True,
        }), {"alg": known, "token_bytes": None}

    private_key, public_key = experiment_keypair(algorithm)
    try:
        token = padded_token(algorithm, claim_set(claims_name), int(pad), private_key,
                             public_key)
    except RuntimeError as error:  # The token failed its own checks, so it is never sent.
        return json_response("500 Internal Server Error", {
            "layer": "application", "error": f"no token was issued: {error}",
            "experiment_key": True,
        }), {"alg": algorithm, "token_bytes": None}
    log_fields = {"alg": algorithm, "token_bytes": len(token)}
    # Requests that use the sizing parameters get them echoed; default responses are unchanged.
    sizing = ({"claims": claims_name, "pad": int(pad)}
              if any(key in query for key in ("claims", "pad", "attrs")) else {})
    if delivery == "body":
        return json_response("200 OK", {
            "layer": "application", "algorithm": algorithm, "delivery": "body", "token": token,
            "token_bytes": len(token), **sizing, "experiment_key": True,
        }), log_fields

    # The body leaves the token out so the response headers stay small for nginx's buffer.
    set_cookie = f"{COOKIE_NAME}={token}; {COOKIE_ATTRIBUTE_SETS[attrs]}"
    status, headers, data = json_response("200 OK", {
        "layer": "application", "algorithm": algorithm, "delivery": "cookie",
        "cookie_name": COOKIE_NAME, "token_bytes": len(token),
        "set_cookie_bytes": len(set_cookie), **sizing, **({"attrs": attrs} if sizing else {}),
        "experiment_key": True,
    })
    return (status, [*headers, ("Set-Cookie", set_cookie)], data), log_fields


def jwt_cookies(cookie_header: str | None) -> list[str]:
    """Return the value of every cookie named exactly `jwt` in a Cookie header."""
    values = []
    for pair in (cookie_header or "").split(";"):
        name, separator, value = pair.strip().partition("=")
        if separator and name == COOKIE_NAME:
            values.append(value)
    return values


def bearer_token(authorization: str | None) -> str | None:
    """Return the token of an Authorization header using the Bearer scheme, otherwise None."""
    parts = (authorization or "").split(None, 1)
    if not parts or parts[0].lower() != "bearer":
        return None
    return parts[1] if len(parts) == 2 else ""


def unverified_claims(token: str) -> dict:
    """Read the payload without verifying, only to choose the audience; {} if unreadable."""
    try:
        return decode_json_object(token.split(".")[1], "payload")
    except (IndexError, jwt.PyJWTError, RecursionError):
        return {}


def unverified_algorithm(token: str) -> str | None:
    """Read `alg` from the token's JOSE header without verifying; None unless it is an adapter."""
    try:
        header = decode_json_object(token.split(".", 1)[0], "header")
    except (jwt.PyJWTError, RecursionError):  # RecursionError: deeply nested header JSON.
        return None
    algorithm = header.get("alg")
    return algorithm if isinstance(algorithm, str) and algorithm in ADAPTERS else None


def verify_failure(status: str, source: str | None, error: str, received: dict) -> Response:
    """Build a 400 or 401 verify response that says why no token was verified."""
    return json_response(status, {
        "layer": "application", "verified": False, "source": source, "error": error,
        "experiment_key": True, "received": received,
    })


def verify_endpoint(environ: dict) -> tuple[Response, dict]:
    """Verify the one token sent in the jwt cookie or an Authorization: Bearer header."""
    headers = received_headers(environ)
    received = received_sizes(headers)
    tokens = [("cookie", value) for value in jwt_cookies(headers.get("cookie"))]
    bearer = bearer_token(headers.get("authorization"))
    if bearer is not None:
        tokens.append(("bearer", bearer))
    log_fields = {"alg": None, "token_bytes": None, "verified": False}
    if not tokens:
        return verify_failure("401 Unauthorized", None, "no token: send a jwt cookie or an "
                              "Authorization: Bearer header", received), log_fields
    if len(tokens) > 1:
        return verify_failure("400 Bad Request", None, "more than one token: send one jwt "
                              "cookie or one Bearer header, not both", received), log_fields

    source, token = tokens[0]
    algorithm = unverified_algorithm(token)
    log_fields.update(alg=algorithm, token_bytes=len(token))
    if algorithm is None:
        return verify_failure("401 Unauthorized", source, "the token header has no readable "
                              f"alg naming one of {', '.join(ALGORITHM_NAMES)}",
                              received), log_fields
    _, public_key = experiment_keypair(algorithm)
    try:
        # An experiment shortcut: tokens with an aud claim must name APP_AUDIENCE, and tokens
        # without one (claims=minimal) are verified without an audience.
        audience = APP_AUDIENCE if "aud" in unverified_claims(token) else None
        claims = ADAPTERS[algorithm].verify_token(token, public_key, audience=audience)
    except Exception as error:  # Untrusted input: any failure means "not verified", never a 500.
        reason = str(error) or type(error).__name__
        return verify_failure("401 Unauthorized", source, f"verification failed: {reason}",
                              received), log_fields

    log_fields["verified"] = True
    return json_response("200 OK", {
        "layer": "application", "verified": True, "algorithm": algorithm, "source": source,
        "token_bytes": len(token), "claims": claims, "experiment_key": True,
        "received": received,
    }), log_fields


def route(environ: dict) -> tuple[Response, dict]:
    """Answer one request; also return the token fields for its log line (empty for others)."""
    path = environ.get("PATH_INFO", "")
    if path == "/":
        data = TEST_PAGE.read_bytes()
        return ("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                           ("Content-Length", str(len(data)))], data), {}
    if path == "/api/echo":
        return json_response("200 OK", echo(environ)), {}
    if path == "/api/token/issue":
        return issue_endpoint(environ)
    if path == "/api/token/verify":
        return verify_endpoint(environ)
    return json_response("404 Not Found", {"layer": "application", "error": "not found",
                                           "path": path}), {}


def format_log_fields(fields: dict) -> str:
    """Write fields as space-separated key=value pairs, with "-" for None."""
    def text(value) -> str:
        if value is None:
            return "-"
        return str(value).lower() if isinstance(value, bool) else str(value)

    return " ".join(f"{name}={text(value)}" for name, value in fields.items())


def application(environ: dict, start_response) -> list[bytes]:
    """WSGI entry point; logs one line per request with its target, status, and header sizes."""
    (status, headers, body), token_fields = route(environ)
    start_response(status, headers)
    target = environ.get("REQUEST_URI") or environ.get("PATH_INFO", "")
    # Sizes only: header values and tokens never go into the log.
    fields = {**received_sizes(received_headers(environ)), **token_fields}
    LOG.info('%s "%s %s %s" %s %s', environ.get("REMOTE_ADDR"), environ["REQUEST_METHOD"], target,
             environ.get("SERVER_PROTOCOL"), status.split()[0], format_log_fields(fields))
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
