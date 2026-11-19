"""Serve the transport test page, the echo, and the token endpoints with waitress on 127.0.0.1.

GET / returns the test page and GET /api/echo describes the request as the application received
it. GET /api/token/issue signs a claims fixture (fixtures/claims.json by default; claims=oidc or
claims=essential chooses another), padded to a chosen size if asked, with one configuration
from scripts/algorithms.py, verifies it, and delivers the token in a `jwt` Set-Cookie header, in
a JSON body, or, with delivery=split (S3-02's cookie splitting), as several chunk cookies named
`jwt.<index>.<count>`: near-equal pieces of the token, at most SPLIT_CHUNK_BYTES characters each
by default (split_token), each in its own Set-Cookie header. GET /api/token/verify verifies the
token sent in the `jwt` cookie, in an Authorization: Bearer header, or in chunk cookies, which it
reassembles in index order whatever order they arrive in (source "split"). An incomplete chunk
set gets 401 and an ambiguous one (a repeated index, disagreeing counts, an index out of range)
400, before anything is verified; chunk cookies sent together with a jwt cookie or a Bearer
header get 400. With timing=1 the verify response also reports how long verification and the
whole handler took.

S3-02's reference tokens: GET /api/token/reference signs and verifies a token as the issue
endpoint does, keeps it in a reference store, and delivers only a short opaque reference,
`ref_` plus 43 base64url characters from 32 random bytes (new_reference), in a `jwt_ref` cookie
or a JSON body. On verify, a jwt_ref cookie (source "ref_cookie") or a Bearer value in that
exact format (source "ref_bearer") is looked up in the store, and the token found is verified
again like any other; timing=1 then also reports the lookup's duration (lookup_ns). POST
/api/token/revoke revokes a reference. The store is either this process's memory
(MemoryRefStore, the default) or a separate store process, `--serve-store`, that serves
store_application on 127.0.0.1 and keeps its entries in memory too; with --store-port, the
application reaches it over loopback HTTP on persistent connections (RemoteRefStore).
References are random values that mean nothing once the store stops, and they never appear in a
URL, a response next to the token, or a log line.

Tokens are signed with ephemeral experiment keys: one key pair per configuration, generated in
memory by this process on first use and never stored, logged, or returned. They are not
production credentials, and a token from another process does not verify here. Every request
the application handles writes one log line with the sizes of the headers it received; no
cookie value, chunk, reference, token, or key is ever logged.
"""

import argparse
from collections import Counter
from collections.abc import Callable, Sequence
import http.client
import json
import logging
import math
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
import waitress
from waitress.channel import HTTPChannel
from waitress.parser import HTTPRequestParser

from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.compact_jws import decode_json_object
from scripts.token_sizing import CLAIM_SET_NAMES, MAX_PAD, claim_set, padded_token


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
# The audience the application expects in tokens that carry an aud claim (claims=oidc or
# claims=essential).
APP_AUDIENCE = "cis628-transport-client"
DELIVERIES = ("cookie", "body", "split")
ALGORITHM_NAMES = [adapter.name for adapter in ADAPTER_LIST]
# delivery=split (S3-02): the token travels in cookies named jwt.<index>.<count>. Every name
# carries the count, so a missing chunk is named before anything is verified, and the dots keep
# chunk names apart from jwt_old, jwt2, jwtx, and the other names the application ignores.
SPLIT_CHUNK_BYTES = 4000
SPLIT_MAX_CHUNKS = 1000
# A chunk cookie's whole name. Each number is 0 or starts with 1-9, with at most 7 digits, so no
# name ever makes the application parse a huge integer.
CHUNK_NAME = re.compile(r"jwt\.(0|[1-9][0-9]{0,6})\.(0|[1-9][0-9]{0,6})")
# The issue endpoint's chunks parameter: 1-4 ASCII digits.
CHUNKS_PARAMETER = re.compile(r"[0-9]{1,4}")
STATUS_LINES = {400: "400 Bad Request", 401: "401 Unauthorized"}

# S3-02's reference tokens: ref_ plus secrets.token_urlsafe(32), 43 base64url characters. The
# format has no dot, so a reference can never be mistaken for a JWT, or a JWT for a reference.
REF_PREFIX = "ref_"
REF_RANDOM_BYTES = 32
REF_BYTES = 47
REF_COOKIE_NAME = "jwt_ref"
REF_DEFAULT_TTL = 3600  # The production cookie's Max-Age.
REF_MAX_TTL = 86400
REFERENCE_PATH = "/api/token/reference"
REVOKE_PATH = "/api/token/revoke"
REF_SOURCES = ("ref_cookie", "ref_bearer")
REF_DELIVERIES = ("cookie", "body")
REFERENCE_FORMAT = re.compile(r"ref_[A-Za-z0-9_-]{43}")
# The reference endpoint's ttl parameter: 1-5 ASCII digits.
TTL_PARAMETER = re.compile(r"[0-9]{1,5}")
# What a store answers for a reference (get), or answered just before a revoke.
REF_STATUSES = ("found", "unknown", "expired", "revoked")
# The store process's operations; each is a POST of a JSON body, so no reference or token is
# ever part of a target.
STORE_OPERATIONS = ("/put", "/get", "/revoke")
STORE_LAYER = "reference_store"
STORE_LOG = logging.getLogger("transport_store")

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


def default_chunk_count(token_bytes: int) -> int:
    """The number of chunks split_token uses by default for a token of token_bytes characters."""
    return max(1, math.ceil(token_bytes / SPLIT_CHUNK_BYTES))


def chunk_cookie_name(index: int, count: int) -> str:
    """The cookie name of chunk `index` of `count`: jwt.<index>.<count>."""
    return f"{COOKIE_NAME}.{index}.{count}"


def chunk_sizes(token_bytes: int, chunks: int | None = None) -> list[int]:
    """The value lengths split_token gives a token of token_bytes characters, in index order.

    The sizes are near-equal: the first token_bytes % chunks chunks have one character more than
    the others. chunks=None means default_chunk_count(token_bytes). Raises ValueError unless
    chunks is an int (not a bool) from 1 to min(token_bytes, SPLIT_MAX_CHUNKS).
    """
    if isinstance(token_bytes, bool) or not isinstance(token_bytes, int) or token_bytes < 0:
        raise ValueError(f"token_bytes must be an int >= 0, got {token_bytes!r}")
    if chunks is None:
        chunks = default_chunk_count(token_bytes)
    largest = min(token_bytes, SPLIT_MAX_CHUNKS)
    if isinstance(chunks, bool) or not isinstance(chunks, int) or not 1 <= chunks <= largest:
        raise ValueError(f"chunks must be an int from 1 to {largest:,} for a "
                         f"{token_bytes:,}-character token, got {chunks!r}")
    size, larger = divmod(token_bytes, chunks)
    return [size + 1 if index < larger else size for index in range(chunks)]


def split_token(token: str, chunks: int | None = None) -> list[tuple[str, str]]:
    """Split a token into (cookie name, value) pairs, in index order, named jwt.<index>.<count>.

    Joining the values in index order gives back the token; see chunk_sizes for the sizes, the
    default count, and the ValueError raised for a count out of range (so for an empty token).
    """
    if not isinstance(token, str):
        raise ValueError(f"token must be a str, got {type(token).__name__}")
    sizes = chunk_sizes(len(token), chunks)
    pairs, start = [], 0
    for index, size in enumerate(sizes):
        pairs.append((chunk_cookie_name(index, len(sizes)), token[start:start + size]))
        start += size
    return pairs


def chunk_cookie_line_bytes(token_bytes: int, chunks: int | None = None) -> int:
    """Bytes of a `Cookie:` header line, CRLF included, that carries only a token's chunks.

    That is each name=value of split_token(token, chunks), joined with "; ", as the load
    command's direct client sends them. Raises ValueError as chunk_sizes does.
    """
    sizes = chunk_sizes(token_bytes, chunks)
    names = sum(len(chunk_cookie_name(index, len(sizes))) + len("=")
                for index in range(len(sizes)))
    return len("Cookie: \r\n") + token_bytes + names + len("; ") * (len(sizes) - 1)


def chunk_cookies(cookie_header: str | None) -> list[tuple[int, int, str]]:
    """Return (index, count, value) for every chunk cookie in a Cookie header, in header order.

    The header is parsed as jwt_cookies parses it. A chunk cookie's whole name is
    jwt.<index>.<count> (CHUNK_NAME); every other name is ignored, and repeats are kept. Never
    raises: anything other than a str has no chunk cookie.
    """
    if not isinstance(cookie_header, str):
        return []
    chunks = []
    for pair in cookie_header.split(";"):
        name, separator, value = pair.strip().partition("=")
        match = CHUNK_NAME.fullmatch(name) if separator else None
        if match is not None:
            chunks.append((int(match[1]), int(match[2]), value))
    return chunks


class ChunkError(ValueError):
    """Why chunk cookies cannot be reassembled: status 400 when ambiguous, 401 when incomplete.

    count is the count every chunk names (even out of range), or None when they disagree;
    received lists the indices in the order given, and missing the absent indices, sorted (empty
    for every 400).
    """

    def __init__(self, message: str, status: int, count: int | None, received: list[int],
                 missing: list[int] | None = None):
        super().__init__(message)
        self.status, self.count, self.received = status, count, received
        self.missing = sorted(missing or [])


def reassemble_chunks(chunks: Sequence[tuple[int, int, str]]) -> str:
    """Join chunk values in index order, whatever order they came in; raise ChunkError if not.

    The checks run in this order: chunks that do not share one count, a count outside
    1..SPLIT_MAX_CHUNKS, an index out of range, and a repeated index are ambiguous (400); a set
    with an index of range(count) absent is incomplete (401), and the error names every missing
    index. Raises ValueError for anything that is not a sequence of (int, int, str).
    """
    chunks = list(chunks)
    for chunk in chunks:
        if (not isinstance(chunk, tuple) or len(chunk) != 3
                or any(isinstance(number, bool) or not isinstance(number, int)
                       for number in chunk[:2]) or not isinstance(chunk[2], str)):
            raise ValueError(f"each chunk must be an (index, count, value) tuple, got {chunk!r}")
    received = [index for index, _, _ in chunks]
    counts = sorted({count for _, count, _ in chunks})
    if len(counts) != 1:
        found = ", ".join(map(str, counts)) if counts else "no chunk cookie"
        raise ChunkError(f"ambiguous chunks: the chunk cookies do not share one count ({found})",
                         400, None, received)
    count = counts[0]
    if not 1 <= count <= SPLIT_MAX_CHUNKS:
        raise ChunkError(f"ambiguous chunks: the count {count} is outside 1-{SPLIT_MAX_CHUNKS}",
                         400, count, received)
    outside = [index for index in received if not 0 <= index < count]
    if outside:
        raise ChunkError(f"ambiguous chunks: index {outside[0]} is out of range for {count} "
                         "chunks", 400, count, received)
    times = Counter(received)
    repeated = sorted(index for index, seen in times.items() if seen > 1)
    if repeated:
        raise ChunkError(f"ambiguous chunks: index {repeated[0]} was sent more than once",
                         400, count, received)
    missing = [index for index in range(count) if index not in times]
    if missing:
        raise ChunkError(f"incomplete chunks: {len(missing)} of {count} missing, index "
                         f"{', '.join(map(str, missing))}", 401, count, received, missing)
    values = {index: value for index, _, value in chunks}
    return "".join(values[index] for index in range(count))


def new_reference() -> str:
    """Return a new random reference: REF_PREFIX plus 43 base64url characters, 47 in all.

    It comes from secrets.token_urlsafe(REF_RANDOM_BYTES) alone, so it encodes nothing about the
    token or its claims, and every call returns a new value.
    """
    return REF_PREFIX + secrets.token_urlsafe(REF_RANDOM_BYTES)


def is_reference(value: object) -> bool:
    """True exactly when value is a str that fully matches ref_[A-Za-z0-9_-]{43}; never raises."""
    return isinstance(value, str) and REFERENCE_FORMAT.fullmatch(value) is not None


def check_entry(ref: object, token: object, ttl: object) -> None:
    """Raise ValueError unless ref is a reference, token a non-empty str, and ttl an int (not a
    bool) from 1 to REF_MAX_TTL; the message never holds the reference or the token."""
    if not is_reference(ref):
        raise ValueError("ref must be a reference: ref_ and 43 base64url characters")
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty str")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= REF_MAX_TTL:
        raise ValueError(f"ttl must be an int from 1 to {REF_MAX_TTL:,}, got {ttl!r}")


class RefStoreUnavailable(Exception):
    """The reference store cannot be reached, or it answered unexpectedly."""


# The error every 503 response carries. The exception's own text names the store's address and
# the connection error, which stay inside the application rather than going to the client.
STORE_UNAVAILABLE_ERROR = "reference store unavailable"


class MemoryRefStore:
    """A reference store in this process's memory; thread-safe, and gone when the process stops.

    Expired and revoked entries are kept (a revoked entry without its token), so get can tell
    'expired' and 'revoked' apart from 'unknown', as the experiment needs.
    """

    kind = "memory"

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        # Each reference's token (None once revoked), put time, ttl, and whether it is revoked.
        self.entries: dict[str, tuple[str | None, float, int, bool]] = {}

    def put(self, ref: str, token: str, ttl: int) -> None:
        """Store token under ref for ttl seconds, replacing any earlier entry.

        Raises ValueError (see check_entry) for an invalid ref, token, or ttl.
        """
        check_entry(ref, token, ttl)
        with self.lock:
            self.entries[ref] = (token, self.clock(), ttl, False)

    def lookup(self, ref: object) -> tuple[str, str | None]:
        """get's answer, for a caller that already holds the lock."""
        entry = self.entries.get(ref) if isinstance(ref, str) else None
        if entry is None:
            return "unknown", None
        token, stored_at, ttl, revoked = entry
        if revoked:
            return "revoked", None
        if self.clock() - stored_at >= ttl:
            return "expired", None
        return "found", token

    def get(self, ref: object) -> tuple[str, str | None]:
        """Return ('found', token) while ref is younger than its ttl, else ('expired', None),
        ('revoked', None) after a revoke, or ('unknown', None) for a reference never put."""
        with self.lock:
            return self.lookup(ref)

    def revoke(self, ref: object) -> str:
        """Revoke ref and return the status get gave just before; an unknown ref stays unknown."""
        with self.lock:
            status, _ = self.lookup(ref)
            if status != "unknown":
                _, stored_at, ttl, _ = self.entries[ref]
                self.entries[ref] = (None, stored_at, ttl, True)
            return status


class RemoteRefStore:
    """The store process (store_application) at url, reached over loopback HTTP/1.1.

    Each calling thread keeps one persistent connection to the store, so a sustained load does
    not open a connection per lookup, and a connection the store has closed is reopened once
    before a call gives up. References and tokens travel only in JSON request bodies, never in a
    target. Every call raises RefStoreUnavailable when the store cannot be reached or answers
    unexpectedly; put also raises ValueError as MemoryRefStore's does, before anything is sent.
    """

    kind = "remote"

    def __init__(self, url: str, timeout: float = 5.0):
        parts = urlsplit(url)
        if parts.scheme != "http" or not parts.hostname or parts.port is None:
            raise ValueError(f"url must be http://<host>:<port>, got {url!r}")
        self.url, self.timeout = url, timeout
        self.host, self.port = parts.hostname, parts.port
        self.local = threading.local()

    def connection(self) -> http.client.HTTPConnection:
        """This thread's connection to the store, created on its first call."""
        connection = getattr(self.local, "connection", None)
        if connection is None:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            self.local.connection = connection
        return connection

    @staticmethod
    def send(connection: http.client.HTTPConnection, operation: str,
             data: bytes) -> tuple[int, bytes]:
        """POST data to one operation on the connection; return the status and the body."""
        connection.request("POST", operation, body=data,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read()
        if response.will_close:
            connection.close()
        return response.status, body

    def unavailable(self, reason: str) -> RefStoreUnavailable:
        """The error for a failed call; it names the store, never a reference or a token."""
        return RefStoreUnavailable(f"the store at {self.url} {reason}")

    def call(self, operation: str, payload: dict) -> dict:
        """Send one operation and return the store's JSON object; raise RefStoreUnavailable."""
        data = json.dumps(payload).encode("utf-8")
        connection = self.connection()
        reused = connection.sock is not None
        try:
            status, body = self.send(connection, operation, data)
        except (OSError, http.client.HTTPException) as error:
            connection.close()
            if not reused:
                raise self.unavailable(f"could not be reached: {type(error).__name__}: "
                                       f"{error}") from None
            try:  # The store closed the idle connection: reopen it once.
                status, body = self.send(connection, operation, data)
            except (OSError, http.client.HTTPException) as retry_error:
                connection.close()
                raise self.unavailable(f"could not be reached again: "
                                       f"{type(retry_error).__name__}: {retry_error}") from None
        try:
            reply = json.loads(body)
        except ValueError:
            reply = None
        if status != 200 or not isinstance(reply, dict):
            raise self.unavailable(f"answered {operation} with status {status}")
        return reply

    def put(self, ref: str, token: str, ttl: int) -> None:
        """Store token under ref in the store process for ttl seconds."""
        check_entry(ref, token, ttl)
        if self.call("/put", {"ref": ref, "token": token, "ttl": ttl}).get("stored") is not True:
            raise self.unavailable("did not confirm the /put")

    def get(self, ref: object) -> tuple[str, str | None]:
        """Return the store process's (status, token or None) for ref, as MemoryRefStore.get."""
        if not isinstance(ref, str):
            return "unknown", None
        reply = self.call("/get", {"ref": ref})
        status, token = reply.get("status"), reply.get("token")
        if status not in REF_STATUSES or (status == "found") != isinstance(token, str):
            raise self.unavailable("answered /get with an unexpected object")
        return status, token if status == "found" else None

    def revoke(self, ref: object) -> str:
        """Revoke ref in the store process and return its status just before."""
        if not isinstance(ref, str):
            return "unknown"
        status = self.call("/revoke", {"ref": ref}).get("status")
        if status not in REF_STATUSES:
            raise self.unavailable("answered /revoke with an unexpected object")
        return status


# The application's reference store. Endpoints read it at request time, so tests can patch it;
# main() replaces it with a RemoteRefStore when the application is started with --store-port.
REF_STORE: MemoryRefStore | RemoteRefStore = MemoryRefStore()
# What the store process (--serve-store) keeps, in its own memory.
STORE_BACKEND = MemoryRefStore()


def issue_problem(algorithm: str | None, delivery: str, claims: str = "minimal",
                  pad: str = "0", attrs: str = "default", chunks: str | None = None) -> str | None:
    """Say what is wrong with an issue request's parameters, or return None.

    chunks, the number of chunk cookies, is checked only for delivery=split, and only its form
    and range here; a count larger than the token is refused once the token's length is known.
    """
    if algorithm is None:
        return "missing alg parameter"
    if algorithm not in ADAPTERS:
        return f"unknown alg {algorithm!r}"
    if delivery not in DELIVERIES:
        return f"delivery must be one of {', '.join(DELIVERIES)}, got {delivery!r}"
    if claims not in CLAIM_SET_NAMES:
        return f"claims must be one of {', '.join(CLAIM_SET_NAMES)}, got {claims!r}"
    # Check the length before int(), which raises ValueError on strings of over 4,300 digits.
    if not (pad.isascii() and pad.isdigit() and len(pad) <= len(str(MAX_PAD))
            and int(pad) <= MAX_PAD):
        return f"pad must be an integer from 0 to {MAX_PAD:,}, got {pad!r}"
    if attrs not in COOKIE_ATTRIBUTE_SETS:
        return f"attrs must be one of {', '.join(COOKIE_ATTRIBUTE_SETS)}, got {attrs!r}"
    if (delivery == "split" and chunks is not None
            and not (CHUNKS_PARAMETER.fullmatch(chunks) and 1 <= int(chunks) <= SPLIT_MAX_CHUNKS)):
        return f"chunks must be an integer from 1 to {SPLIT_MAX_CHUNKS:,}, got {chunks!r}"
    return None


def issue_error(problem: str) -> Response:
    """The 400 response to an issue request whose parameters are wrong; it sets no cookie."""
    return json_response("400 Bad Request", {
        "layer": "application", "error": problem, "algorithms": ALGORITHM_NAMES,
        "experiment_key": True,
    })


def split_delivery(algorithm: str, token: str, claims_name: str, pad: int, attrs: str,
                   chunks: str | None) -> tuple[Response, dict]:
    """Deliver a verified token as chunk cookies, one Set-Cookie header each, in index order.

    The body names the cookies and their sizes but never holds the token. A chunk count larger
    than the token gets the standard 400 issue error and no cookie.
    """
    try:
        pairs = split_token(token, None if chunks is None else int(chunks))
    except ValueError as error:
        return issue_error(str(error)), {"alg": algorithm, "token_bytes": None, "chunks": None}
    set_cookies = [f"{name}={value}; {COOKIE_ATTRIBUTE_SETS[attrs]}" for name, value in pairs]
    status, headers, data = json_response("200 OK", {
        "layer": "application", "algorithm": algorithm, "delivery": "split",
        "cookie_names": [name for name, _ in pairs], "token_bytes": len(token),
        "chunks": len(pairs), "chunk_bytes": [len(value) for _, value in pairs],
        "set_cookie_bytes": [len(line) for line in set_cookies], "claims": claims_name,
        "pad": pad, "attrs": attrs, "experiment_key": True,
    })
    response = (status, [*headers, *(("Set-Cookie", line) for line in set_cookies)], data)
    return response, {"alg": algorithm, "token_bytes": len(token), "chunks": len(pairs)}


def issue_endpoint(environ: dict) -> tuple[Response, dict]:
    """Sign a claims fixture, padded if asked, and deliver it in Set-Cookie headers or the body.

    Optional parameters: claims (minimal, the default, oidc, or essential), pad (characters in a
    `pad` claim, default 0, see scripts/token_sizing.py), attrs (default or full cookie
    attributes), and, with delivery=split, chunks (the number of chunk cookies, by default
    default_chunk_count of the token's length).
    """
    query = query_parameters(environ)
    algorithm, delivery = query.get("alg"), query.get("delivery", "cookie")
    claims_name, pad, attrs = (query.get("claims", "minimal"), query.get("pad", "0"),
                               query.get("attrs", "default"))
    chunks = query.get("chunks") if delivery == "split" else None
    # Split issue lines end with the number of chunks, "-" when no token was issued.
    no_chunks = {"chunks": None} if delivery == "split" else {}
    problem = issue_problem(algorithm, delivery, claims_name, pad, attrs, chunks)
    if problem is not None:
        known = algorithm if algorithm in ADAPTERS else None
        return issue_error(problem), {"alg": known, "token_bytes": None, **no_chunks}

    private_key, public_key = experiment_keypair(algorithm)
    try:
        token = padded_token(algorithm, claim_set(claims_name), int(pad), private_key,
                             public_key)
    except RuntimeError as error:  # The token failed its own checks, so it is never sent.
        return json_response("500 Internal Server Error", {
            "layer": "application", "error": f"no token was issued: {error}",
            "experiment_key": True,
        }), {"alg": algorithm, "token_bytes": None, **no_chunks}
    if delivery == "split":
        return split_delivery(algorithm, token, claims_name, int(pad), attrs, chunks)
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


def reference_problem(algorithm: str | None, delivery: str, claims: str, pad: str, attrs: str,
                      ttl: str) -> str | None:
    """Say what is wrong with a reference request's parameters, or return None.

    alg, claims, pad, and attrs are checked as issue_problem checks them; delivery must be
    cookie or body, and ttl 1-5 ASCII digits with a value from 1 to REF_MAX_TTL.
    """
    problem = issue_problem(algorithm, "cookie", claims, pad, attrs)
    if problem is not None:
        return problem
    if delivery not in REF_DELIVERIES:
        return f"delivery must be one of {', '.join(REF_DELIVERIES)}, got {delivery!r}"
    if not (TTL_PARAMETER.fullmatch(ttl) and 1 <= int(ttl) <= REF_MAX_TTL):
        return f"ttl must be an integer from 1 to {REF_MAX_TTL:,}, got {ttl!r}"
    return None


def store_unavailable() -> Response:
    """The 503 response to a reference request whose store cannot be reached; it sets no cookie."""
    return json_response("503 Service Unavailable", {
        "layer": "application", "error": STORE_UNAVAILABLE_ERROR,
        "store": REF_STORE.kind, "experiment_key": True,
    })


def reference_endpoint(environ: dict) -> tuple[Response, dict]:
    """Sign and verify a token as issue_endpoint does, store it, and deliver only its reference.

    Parameters: alg (required), delivery (cookie, the default, or body), claims, pad, and attrs
    (as for the issue endpoint), and ttl (the reference's seconds to live, default
    REF_DEFAULT_TTL). The token is kept in REF_STORE under new_reference(); the response holds
    the reference, in a jwt_ref Set-Cookie header or the body, and never the token. Answers 400
    for invalid parameters, 500 when the token fails its own checks, and 503 when the store
    cannot be reached; none of them sets a cookie.
    """
    query = query_parameters(environ)
    algorithm, delivery = query.get("alg"), query.get("delivery", "cookie")
    claims_name, pad, attrs = (query.get("claims", "minimal"), query.get("pad", "0"),
                               query.get("attrs", "default"))
    ttl = query.get("ttl", str(REF_DEFAULT_TTL))
    store = REF_STORE
    log_fields = {"alg": algorithm if algorithm in ADAPTERS else None, "token_bytes": None,
                  "ref": None, "store": store.kind}
    problem = reference_problem(algorithm, delivery, claims_name, pad, attrs, ttl)
    if problem is not None:
        return issue_error(problem), log_fields

    private_key, public_key = experiment_keypair(algorithm)
    try:
        token = padded_token(algorithm, claim_set(claims_name), int(pad), private_key,
                             public_key)
    except RuntimeError as error:  # The token failed its own checks, so it is never stored.
        return json_response("500 Internal Server Error", {
            "layer": "application", "error": f"no token was issued: {error}",
            "experiment_key": True,
        }), log_fields
    log_fields["token_bytes"] = len(token)
    reference = new_reference()
    try:
        store.put(reference, token, int(ttl))
    except RefStoreUnavailable:
        log_fields["ref"] = "unavailable"
        return store_unavailable(), log_fields
    log_fields["ref"] = "issued"
    described = {"reference_bytes": len(reference), "token_bytes": len(token),
                 "claims": claims_name, "pad": int(pad)}
    if delivery == "body":
        return json_response("200 OK", {
            "layer": "application", "algorithm": algorithm, "delivery": "body",
            "reference": reference, **described, "ttl": int(ttl), "store": store.kind,
            "experiment_key": True,
        }), log_fields
    set_cookie = f"{REF_COOKIE_NAME}={reference}; {COOKIE_ATTRIBUTE_SETS[attrs]}"
    status, headers, data = json_response("200 OK", {
        "layer": "application", "algorithm": algorithm, "delivery": "cookie",
        "cookie_name": REF_COOKIE_NAME, "reference_bytes": len(reference),
        "token_bytes": len(token), "set_cookie_bytes": len(set_cookie), "claims": claims_name,
        "pad": int(pad), "attrs": attrs, "ttl": int(ttl), "store": store.kind,
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


def reference_cookies(cookie_header: str | None) -> list[str]:
    """Return the value of every cookie named exactly `jwt_ref`, parsed as jwt_cookies parses."""
    values = []
    for pair in (cookie_header or "").split(";"):
        name, separator, value = pair.strip().partition("=")
        if separator and name == REF_COOKIE_NAME:
            values.append(value)
    return values


def request_references(headers: dict, bearer: str | None) -> list[tuple[str, str]]:
    """Every reference a request carries, as (source, value): jwt_ref cookies, then a Bearer
    value in the reference format. Any other Bearer value is a JWT, as before S3-02."""
    references = [("ref_cookie", value) for value in reference_cookies(headers.get("cookie"))]
    if is_reference(bearer):
        references.append(("ref_bearer", bearer))
    return references


def other_tokens(headers: dict, bearer: str | None) -> int:
    """How many tokens other than references a request carries: jwt cookies, a Bearer JWT, and
    a set of chunk cookies, which counts as one."""
    cookie = headers.get("cookie")
    bearer_jwt = bearer is not None and not is_reference(bearer)
    return len(jwt_cookies(cookie)) + bearer_jwt + bool(chunk_cookies(cookie))


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


def failure_body(source: str | None, error: str, received: dict) -> dict:
    """Build the body of a 400 or 401 verify response that says why no token was verified."""
    return {
        "layer": "application", "verified": False, "source": source, "error": error,
        "experiment_key": True, "received": received,
    }


VerifyResult = tuple[str, dict, dict, int | None]  # Status, body, log fields, verify_ns.
# A verify request's result plus lookup_ns, the duration of the REF_STORE.get call (None when no
# lookup ran).
LookupResult = tuple[str, dict, dict, int | None, int | None]


def verify_request(environ: dict) -> LookupResult:
    """Verify the one token sent in the jwt cookie, a Bearer header, chunk cookies, or by
    reference (a jwt_ref cookie or a Bearer reference).

    Returns the response status, the response body, the token fields for the log line, how
    long the adapter's verify_token call took in nanoseconds (None when it was not called), and
    how long the reference lookup took (None when none ran). A request without a reference gets
    exactly what it got before reference tokens were added.
    """
    headers = received_headers(environ)
    received = received_sizes(headers)
    log_fields = {"alg": None, "token_bytes": None, "verified": False}
    bearer = bearer_token(headers.get("authorization"))
    references = request_references(headers, bearer)
    if references:
        return verify_reference(references, other_tokens(headers, bearer), received, log_fields)
    return (*verify_token_request(headers, received), None)


def verify_reference(references: list[tuple[str, str]], others: int, received: dict,
                     log_fields: dict) -> LookupResult:
    """Look one reference up in REF_STORE and verify the token it names.

    A reference sent with any other token (another reference, a jwt cookie, chunk cookies, or a
    Bearer JWT) gets 400 and no lookup. A jwt_ref value that is not in the reference format gets
    401 ('malformed') and no lookup; an unknown, expired, or revoked reference gets 401, and an
    unreachable store 503, with nothing verified. A found token is checked and verified exactly
    like a cookie or Bearer token. Every response whose source is a reference has a ref object,
    and its log line ends with ref=<status> store=<kind>.
    """
    if len(references) + others > 1:
        body = failure_body(None, "more than one token: send one jwt_ref cookie or one Bearer "
                            "reference alone, without another reference, a jwt cookie, chunk "
                            "cookies, or a Bearer token", received)
        return "400 Bad Request", body, log_fields, None, None
    store = REF_STORE
    source, value = references[0]
    ref = {"status": None, "store": store.kind, "reference_bytes": len(value)}
    log_fields.update(ref=None, store=store.kind)

    def refused(line: str, ref_status: str, error: str, lookup_ns: int | None) -> LookupResult:
        """A failure response for the reference, with nothing verified."""
        ref["status"] = log_fields["ref"] = ref_status
        body = failure_body(source, error, received)
        body["ref"] = ref
        return line, body, log_fields, None, lookup_ns

    if not is_reference(value):
        return refused("401 Unauthorized", "malformed",
                       f"malformed reference: a {REF_COOKIE_NAME} cookie must hold "
                       f"{REF_PREFIX} and 43 base64url characters", None)
    lookup_started = time.perf_counter_ns()
    try:
        status, token = store.get(value)
    except RefStoreUnavailable:
        lookup_ns = time.perf_counter_ns() - lookup_started  # A failed lookup is timed too.
        return refused("503 Service Unavailable", "unavailable", STORE_UNAVAILABLE_ERROR,
                       lookup_ns)
    lookup_ns = time.perf_counter_ns() - lookup_started
    if status != "found":
        reasons = {"unknown": "the store holds no token for it",
                   "expired": "its time to live has passed", "revoked": "it was revoked"}
        return refused("401 Unauthorized", status, f"{status} reference: {reasons[status]}",
                       lookup_ns)
    ref["status"] = log_fields["ref"] = "found"
    line, body, log_fields, verify_ns = verify_one_token(source, token, received, log_fields)
    body["ref"] = ref
    return line, body, log_fields, verify_ns, lookup_ns


def verify_token_request(headers: dict, received: dict) -> VerifyResult:
    """Verify the one token sent in the jwt cookie, a Bearer header, or chunk cookies (the
    verify endpoint before reference tokens)."""
    tokens = [("cookie", value) for value in jwt_cookies(headers.get("cookie"))]
    bearer = bearer_token(headers.get("authorization"))
    if bearer is not None:
        tokens.append(("bearer", bearer))
    log_fields = {"alg": None, "token_bytes": None, "verified": False}
    chunks = chunk_cookies(headers.get("cookie"))
    if chunks:
        return verify_split(chunks, tokens, received, log_fields)
    if not tokens:
        body = failure_body(None, "no token: send a jwt cookie or an Authorization: Bearer "
                            "header", received)
        return "401 Unauthorized", body, log_fields, None
    if len(tokens) > 1:
        body = failure_body(None, "more than one token: send one jwt cookie or one Bearer "
                            "header, not both", received)
        return "400 Bad Request", body, log_fields, None
    source, token = tokens[0]
    return verify_one_token(source, token, received, log_fields)


def verify_split(chunks: list[tuple[int, int, str]], tokens: list[tuple[str, str]],
                 received: dict, log_fields: dict) -> VerifyResult:
    """Reassemble chunk cookies and verify the token they carry (source "split").

    Chunk cookies sent with a jwt cookie or a Bearer header are more than one token (400). An
    incomplete or ambiguous chunk set is refused with ChunkError's status before anything is
    verified. Every response with source "split" has a chunks object, and its log line ends with
    chunks=<chunk cookies received>/<count, or "-" when they disagree>.
    """
    if tokens:
        body = failure_body(None, "more than one token: send the jwt.<index>.<count> chunk "
                            "cookies alone, without a jwt cookie or a Bearer header", received)
        return "400 Bad Request", body, log_fields, None
    counts = {count for _, count, _ in chunks}
    shared = next(iter(counts)) if len(counts) == 1 else None
    log_fields["chunks"] = f"{len(chunks)}/{'-' if shared is None else shared}"
    try:
        token = reassemble_chunks(chunks)
    except ChunkError as error:
        body = failure_body("split", str(error), received)
        body["chunks"] = {"count": error.count, "received": error.received,
                          "missing": error.missing}
        return STATUS_LINES[error.status], body, log_fields, None
    status, body, log_fields, verify_ns = verify_one_token("split", token, received, log_fields)
    body["chunks"] = {"count": shared, "received": [index for index, _, _ in chunks],
                      "missing": []}
    return status, body, log_fields, verify_ns


def verify_one_token(source: str, token: str, received: dict, log_fields: dict) -> VerifyResult:
    """Verify one token from a source with the adapter its unverified header names."""
    algorithm = unverified_algorithm(token)
    log_fields.update(alg=algorithm, token_bytes=len(token))
    if algorithm is None:
        body = failure_body(source, "the token header has no readable alg naming one of "
                            f"{', '.join(ALGORITHM_NAMES)}", received)
        return "401 Unauthorized", body, log_fields, None
    _, public_key = experiment_keypair(algorithm)
    verify_ns = None
    try:
        # An experiment shortcut: tokens with an aud claim (claims=oidc or essential) must name
        # APP_AUDIENCE, and tokens without one (claims=minimal) are verified without an audience.
        audience = APP_AUDIENCE if "aud" in unverified_claims(token) else None
        verify_started = time.perf_counter_ns()
        try:
            claims = ADAPTERS[algorithm].verify_token(token, public_key, audience=audience)
        finally:  # A failed verification is timed too.
            verify_ns = time.perf_counter_ns() - verify_started
    except Exception as error:  # Untrusted input: any failure means "not verified", never a 500.
        reason = str(error) or type(error).__name__
        body = failure_body(source, f"verification failed: {reason}", received)
        return "401 Unauthorized", body, log_fields, verify_ns

    log_fields["verified"] = True
    return "200 OK", {
        "layer": "application", "verified": True, "algorithm": algorithm, "source": source,
        "token_bytes": len(token), "claims": claims, "experiment_key": True,
        "received": received,
    }, log_fields, verify_ns


def verify_endpoint(environ: dict) -> tuple[Response, dict]:
    """Answer GET /api/token/verify; with timing=1, the body also reports server timings.

    The timing object holds verify_ns, the duration of the adapter's verify_token call (null
    when it was not called), and handler_ns, the duration of this whole handler up to just before
    the body is serialized, both from time.perf_counter_ns. It is opt-in, like the issue
    endpoint's sizing parameters, so responses to requests without timing=1 are unchanged. A
    response whose source is a reference also has lookup_ns, the duration of the REF_STORE.get
    call (null when no lookup ran), so 0 <= lookup_ns + verify_ns <= handler_ns.
    """
    handler_started = time.perf_counter_ns()
    status, body, log_fields, verify_ns, lookup_ns = verify_request(environ)
    if query_parameters(environ).get("timing") == "1":
        body["timing"] = {"verify_ns": verify_ns,
                          "handler_ns": time.perf_counter_ns() - handler_started}
        if body.get("source") in REF_SOURCES:
            body["timing"]["lookup_ns"] = lookup_ns
    return json_response(status, body), log_fields


def revoke_endpoint(environ: dict) -> tuple[Response, dict]:
    """Answer POST /api/token/revoke: revoke the one reference the request carries.

    The request must carry exactly one token, a jwt_ref cookie or a Bearer reference: no token
    gets 401, more than one 400, one JWT (a jwt cookie, a Bearer JWT, or chunk cookies) 400, and
    a malformed reference 401. A reference that was found, expired, or already revoked is
    revoked (200); an unknown one gets 401 and an unreachable store 503. Any other method gets
    405 with Allow: POST and revokes nothing. No body holds the reference.
    """
    store = REF_STORE
    log_fields = {"ref": None, "store": store.kind}
    if environ["REQUEST_METHOD"] != "POST":
        status, headers, data = json_response("405 Method Not Allowed", {
            "layer": "application", "revoked": False, "error": "method not allowed: use POST",
            "experiment_key": True})
        return (status, [*headers, ("Allow", "POST")], data), log_fields
    headers = received_headers(environ)
    bearer = bearer_token(headers.get("authorization"))
    references = request_references(headers, bearer)
    others = other_tokens(headers, bearer)

    def answer(status: str, error: str | None, ref: dict | None = None) -> tuple[Response, dict]:
        body = {"layer": "application", "revoked": error is None}
        if error is not None:
            body["error"] = error
        if ref is not None:
            body["ref"] = ref
            # The log names the store's own answer, the status before; "-" when it gave none.
            log_fields["ref"] = ref["status"] if ref["status"] in REF_STATUSES else None
        return json_response(status, {**body, "experiment_key": True}), log_fields

    if len(references) + others == 0:
        return answer("401 Unauthorized", "no token: send a jwt_ref cookie or an "
                      "Authorization: Bearer reference")
    if len(references) + others > 1:
        return answer("400 Bad Request", "more than one token: send one jwt_ref cookie or one "
                      "Bearer reference alone")
    if not references:
        return answer("400 Bad Request", "not a reference: only a jwt_ref cookie or a Bearer "
                      "reference can be revoked; a JWT stays valid until it expires")
    _, value = references[0]
    ref = {"status": "malformed", "store": store.kind, "reference_bytes": len(value)}
    if not is_reference(value):
        return answer("401 Unauthorized", f"malformed reference: a {REF_COOKIE_NAME} cookie "
                      f"must hold {REF_PREFIX} and 43 base64url characters", ref)
    try:
        ref["status"] = store.revoke(value)
    except RefStoreUnavailable:
        ref["status"] = "unavailable"
        return answer("503 Service Unavailable", STORE_UNAVAILABLE_ERROR, ref)
    if ref["status"] == "unknown":
        return answer("401 Unauthorized", "unknown reference: the store holds no token for it",
                      ref)
    return answer("200 OK", None, ref)


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
    if path == REFERENCE_PATH:
        return reference_endpoint(environ)
    if path == REVOKE_PATH:
        return revoke_endpoint(environ)
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


def request_body(environ: dict) -> bytes:
    """The request body, as long as its Content-Length says; empty without one."""
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    return environ["wsgi.input"].read(length) if length > 0 else b""


def store_route(method: str, path: str, data: bytes) -> tuple[str, list, dict]:
    """Answer one store request: GET / says the store is ready, and POST /put, /get, and
    /revoke act on STORE_BACKEND with the reference and token in the JSON body.

    Returns the status, extra headers, and the JSON body; a request the store cannot use gets
    400, 404, or 405, never a 500.
    """
    if path == "/":
        return "200 OK", [], {"layer": STORE_LAYER, "store": STORE_BACKEND.kind}
    if path not in STORE_OPERATIONS:
        return "404 Not Found", [], {"layer": STORE_LAYER, "error": "not found"}
    if method != "POST":
        return "405 Method Not Allowed", [("Allow", "POST")], {"layer": STORE_LAYER,
                                                               "error": "use POST"}
    try:
        request = json.loads(data)
    except ValueError:
        request = None
    if not isinstance(request, dict):
        return "400 Bad Request", [], {"layer": STORE_LAYER, "error": "send a JSON object"}
    ref = request.get("ref")
    try:
        if path == "/put":
            STORE_BACKEND.put(ref, request.get("token"), request.get("ttl"))
            return "200 OK", [], {"layer": STORE_LAYER, "stored": True}
        if path == "/get":
            status, token = STORE_BACKEND.get(ref)
            return "200 OK", [], {"layer": STORE_LAYER, "status": status, "token": token}
        return "200 OK", [], {"layer": STORE_LAYER, "status": STORE_BACKEND.revoke(ref)}
    except (ValueError, TypeError) as error:  # TypeError: a JSON list or object as the ref.
        return "400 Bad Request", [], {"layer": STORE_LAYER, "error": str(error)}


def store_application(environ: dict, start_response) -> list[bytes]:
    """WSGI entry point of the store process (--serve-store); everything stays in memory.

    Logs one line per request with the method, the operation's path, the status, and the byte
    sizes of the request and response bodies. The line never holds a target, a reference, a
    token, or a body.
    """
    method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "")
    data = request_body(environ)
    status, extra, body = store_route(method, path, data)
    status, headers, payload = json_response(status, body)
    start_response(status, [*headers, *extra])
    logged_path = path if path in ("/", *STORE_OPERATIONS) else "-"
    STORE_LOG.info('%s "%s %s %s" %s request_bytes=%d response_bytes=%d',
                   environ.get("REMOTE_ADDR"), method, logged_path,
                   environ.get("SERVER_PROTOCOL"), status.split()[0], len(data), len(payload))
    return [payload]


def main() -> None:
    global REF_STORE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True, help=f"TCP port on {HOST}")
    parser.add_argument("--serve-store", action="store_true",
                        help="serve the reference store (store_application) instead of the "
                             "application")
    parser.add_argument("--store-port", type=int, metavar="PORT",
                        help=f"keep references in the store process on {HOST}:PORT instead of "
                             "this process's memory")
    args = parser.parse_args()
    if args.serve_store and args.store_port is not None:
        parser.error("--serve-store and --store-port cannot be combined")

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    served = store_application
    if not args.serve_store:
        served = application
        # Only adds logging; parsing and its limits are waitress's own.
        HTTPChannel.parser_class = LoggingParser
        if args.store_port is not None:
            REF_STORE = RemoteRefStore(f"http://{HOST}:{args.store_port}")
    # Size limits stay at waitress defaults; only proxy-header clearing is off so the
    # echo reports every header that arrived.
    waitress.serve(served, host=HOST, port=args.port, clear_untrusted_proxy_headers=False)


if __name__ == "__main__":
    main()
