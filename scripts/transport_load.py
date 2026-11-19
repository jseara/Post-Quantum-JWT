"""Measure end-to-end latency and throughput of authenticated requests through the stack (S3-01).

The workload is a closed loop of authenticated `GET /api/token/verify` requests (100% of the
request mix) sent through nginx to waitress and the application, from two clients on the same
machine as the stack, over loopback 127.0.0.1: http.client threads in this process, each with its
own persistent HTTP/1.1 connection to nginx ("direct"), and concurrent fetch() loops in the test
page of headless Chromium, loaded through nginx ("browser"). Each of `concurrency` workers sends
its next request only after reading the previous response body. Requests started during the
first `warmup` seconds are not recorded; requests started during the next `duration` seconds are
measured, and no request starts after that.

The run measures one cell per client, concurrency level, and configuration. A "token" cell sends
the configuration's own token. A "size_control" cell sends the reference configuration's token
(ES256 by default) padded with the `pad` claim of scripts/token_sizing.py to the configuration's
token size, so it has the configuration's size but the reference's verification cost. Each cell
gets its token once, through nginx, before its warm-up and outside the timed window, and then
sends it on every request, as an Authorization: Bearer header (the default), a `jwt` cookie, or
the `jwt.<index>.<count>` chunk cookies of S3-02's cookie splitting (transport "split").
S3-02's reference tokens add the reference carrier, REF_CARRIER ("ref_bearer"), outside the
load command's choices: each cell gets a 47-byte `ref_` reference from /api/token/reference, and
sends it as a Bearer header, so the application looks the token up in its reference store before
it verifies it (run_reference_load). Such a run's raw rows end with lookup_ns, and its latency
has a fourth server component, lookup, taken out of other_handling.

Every timed request asks the application for its server timings with timing=1, which splits each
request's client-measured total into three components: verification (the adapter's verify_token
call), other_handling (the rest of the verify handler), and transfer (everything outside the
handler: the client, the token's bytes on the wire, nginx, and waitress). Differences from the
reference's means show how much of each configuration's end-to-end difference comes from token
size and how much from verification, and the size-control cells check the split directly. Since
loopback makes token transfer nearly free, network_model adds a calculated, not measured, upload
time of each configuration's request at a few illustrative uplink and round-trip profiles.

Raw per-request timings are integer nanoseconds; summaries are in milliseconds, with the median
and nearest-rank p95 of scripts/rsa_jwt.py, as in Sprint 1. Use run_load with a stack from
scripts.transport_stack.start_stack, or `scripts/transport_stack.py load`.
"""

from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import http.client
import inspect
import io
import itertools
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import statistics
import threading
import time
from urllib.parse import urlsplit

from waitress.adjustments import Adjustments

from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.benchmark import environment
from scripts.rsa_jwt import summarize
from scripts.token_sizing import (CLAIM_SET_NAMES, claim_set, pad_for_target, padded_claims,
                                  token_bytes)
from scripts.transport_app import (COOKIE_NAME, REF_BYTES, REFERENCE_PATH,
                                   chunk_cookie_line_bytes, split_token)
from scripts.transport_stack import (BROWSER_CHANNEL, PROXY_MARKER, check_timeout,
                                     check_upstream_keepalive, http_get, load_manifest,
                                     manifest_layers, nginx_size)
from scripts.transport_tokens import (ISSUE_PATH, LOG_FILES, LOG_GRACE_SECONDS, VERIFY_PATH,
                                      BrowserLog, browser_identity, json_object,
                                      load_test_page, nonce_url, selected_algorithms, send_fetch)


SCHEMA_VERSION = 1
CLIENTS = ("direct", "browser")
MAX_CONCURRENCY = 64
VARIANTS = ("token", "size_control")
# Every timed request is this path plus a 32-hex-digit nonce, so cells differ only in the token.
TIMED_TARGET = f"{VERIFY_PATH}?timing=1&nonce="
LATENCY_COMPONENTS = ("total", "transfer", "other_handling", "verification")
RAW_FIELDS = ("client", "concurrency", "algorithm", "variant", "signed_with", "pad",
              "token_bytes", "worker", "sequence", "nonce", "start_ns", "total_ns", "handler_ns",
              "verify_ns", "status", "verified", "error")
RAW_FILE = "raw.csv.gz"
RESULT_FILE = "load.json"
# A reference run's extra raw column and latency component: the application's REF_STORE.get.
LOOKUP_FIELD = "lookup_ns"
REF_LATENCY_COMPONENTS = ("total", "transfer", "other_handling", "lookup", "verification")
# The last requests of a run are near the end of proxy-access.log; read only that much of it.
LOG_TAIL_BYTES = 256 * 1024

# R22, a team decision: a calculated network model, because loopback makes transfer nearly free.
MSS_BYTES = 1460
INITIAL_WINDOW_SEGMENTS = 10  # RFC 6928.
# Illustrative uplink and round-trip profiles chosen by the team, not measurements.
NETWORK_PROFILES = ({"uplink_mbps": 100, "rtt_ms": 10}, {"uplink_mbps": 10, "rtt_ms": 50},
                    {"uplink_mbps": 1, "rtt_ms": 100})
NETWORK_BASIS = (
    "Calculated, not measured. Modeled upload time of the request header block the direct "
    "client sends (request line, Host, Accept-Encoding, the token's header line, and every "
    "CRLF) on a new or idle TCP connection: its bytes at the uplink rate, plus one round trip "
    "for every slow-start round after the first, where the first round carries the initial "
    f"window of {INITIAL_WINDOW_SEGMENTS} segments of {MSS_BYTES:,} bytes (RFC 6928) and each "
    "later round twice the previous one. Assumes upload only (no response or server time), no "
    "packet loss, and no TLS, TCP/IP, or HTTP/2 framing overhead; a browser's request carries "
    "several hundred bytes more of other headers than the direct client's. The profiles are "
    "illustrative values chosen by the team, not measurements."
)

WORKLOAD_CLIENTS = {
    "direct": "http.client threads in the load process, on the same machine as the stack; each "
              "worker keeps its own persistent HTTP/1.1 connection to nginx at 127.0.0.1 and "
              "opens a new one only when the server closed it",
    "browser": "headless Chromium (Playwright, channel chromium) on the same machine as the "
               "stack; concurrent fetch() loops in the test page loaded through nginx at "
               "127.0.0.1, one new browser context per cell; Chromium opens at most 6 HTTP/1.1 "
               "connections per origin, so higher concurrency queues inside Chromium",
}
WORKLOAD_TIMERS = {
    "server": "time.perf_counter_ns in the application, reported with timing=1: verify_ns times "
              "the adapter's verify_token call, handler_ns the whole verify handler up to just "
              "before the response body is serialized",
    "direct": "time.perf_counter_ns in each worker thread, from just before sending the request "
              "to after reading the whole response body",
    "browser": "performance.now() in the page, from just before fetch() to after reading the "
               "response body, converted to integer nanoseconds; Chromium coarsens it to about "
               "100 microseconds in a page that is not cross-origin isolated",
}
WORKLOAD_NETWORK = ("loopback 127.0.0.1: the clients, nginx, and waitress run on one machine, so "
                    "no real network bandwidth or round trip is part of the measurement")

# Runs inside the test page. Each loop sends its next fetch() only after reading the previous
# body; bodies are parsed after every loop has finished, outside the timed window.
BROWSER_LOOP = """async ({target, prefix, headers, concurrency, warmupMs, durationMs,
                     timeoutMs}) => {
  let counter = 0;
  const nextNonce = () => prefix + (counter++).toString(16).padStart(16, "0");
  const measuredStart = performance.now() + warmupMs;
  const measuredEnd = measuredStart + durationMs;
  const measured = [];
  async function worker(index) {
    let sequence = 0;
    for (;;) {
      const nonce = nextNonce();
      const start = performance.now();
      if (start >= measuredEnd) return;
      let status = null, proxied = false, text = null, error = null;
      try {
        const response = await fetch(target + nonce, {cache: "no-store", headers,
                                                      signal: AbortSignal.timeout(timeoutMs)});
        status = response.status;
        proxied = response.headers.has("x-transport-proxy");
        text = await response.text();
      } catch (failure) {
        status = null;
        error = String(failure);
      }
      const end = performance.now();
      if (start >= measuredStart) {
        sequence += 1;
        measured.push({worker: index, sequence, nonce, startMs: start - measuredStart,
                       totalMs: end - start, status, proxied, text, error});
      }
    }
  }
  await Promise.all(Array.from({length: concurrency}, (_, index) => worker(index)));
  const encoder = new TextEncoder();
  return measured.map(({text, ...request}) => {
    let body = null;
    try { body = JSON.parse(text); } catch (ignored) { /* nginx error pages are HTML. */ }
    const slim = body && typeof body === "object" ? {
      verified: body.verified, algorithm: body.algorithm, source: body.source,
      timing: body.timing ?? null,
      received: body.received ? {header_bytes: body.received.header_bytes} : null,
    } : null;
    return {...request, body: slim, bodyBytes: text === null ? null : encoder.encode(text).length};
  });
}"""


@dataclass(frozen=True)
class Carrier:
    """How the timed requests carry a token: an Authorization: Bearer header or a jwt cookie.

    S3-02 adds carriers, such as split cookies (SplitCarrier), without changing the loop.
    """

    name: str
    header_name: str  # The request header the direct client sends.
    header_prefix: str  # Text before the token in that header's value.
    issue_delivery: str  # How the browser asks /api/token/issue to deliver the token.
    # Class attributes, not fields: where the untimed issue step asks for the cell's credential,
    # and the key of the JSON body that holds it with delivery=body.
    issue_path = ISSUE_PATH
    issued_key = "token"

    def direct_headers(self, token: str) -> dict:
        """Request headers that carry the token from the direct client."""
        return {self.header_name: f"{self.header_prefix}{token}"}

    def browser_headers(self, token: str | None) -> dict:
        """Headers the page adds to fetch(); a cookie is sent by the browser from its own jar."""
        return {} if self.issue_delivery == "cookie" else self.direct_headers(token)

    def header_line_bytes(self, token_size: int) -> int:
        """Bytes of the header line that carries a token of token_size bytes, CRLF included."""
        return len(f"{self.header_name}: {self.header_prefix}\r\n") + token_size


@dataclass(frozen=True)
class SplitCarrier(Carrier):
    """S3-02's cookie splitting: the token in jwt.<index>.<count> chunk cookies (split_token).

    The direct client sends every chunk of the default split in one Cookie header; the browser
    sends the chunk cookies it stored from the issue response's Set-Cookie headers.
    """

    def direct_headers(self, token: str) -> dict:
        """A Cookie header with every chunk of the token's default split, in index order."""
        return {"Cookie": "; ".join(f"{name}={value}" for name, value in split_token(token))}

    def browser_headers(self, token: str | None) -> dict:
        """No headers: the browser sends the chunk cookies from its own jar."""
        return {}

    def header_line_bytes(self, token_size: int) -> int:
        """Bytes of the Cookie line that carries the default split of a token, CRLF included."""
        return chunk_cookie_line_bytes(token_size)


@dataclass(frozen=True)
class RefCarrier(Carrier):
    """S3-02's reference tokens: a ref_ reference, not the token, in an Authorization: Bearer
    header.

    Both clients get the reference in the JSON body of /api/token/reference (delivery=body), and
    the application looks the token up by it before verifying; the header line is the same 71
    bytes whatever the token's size.
    """

    issue_path = REFERENCE_PATH
    issued_key = "reference"

    def header_line_bytes(self, token_size: int) -> int:
        """Bytes of the Authorization line that carries a reference, CRLF included: always 71."""
        return len(f"{self.header_name}: {self.header_prefix}\r\n") + REF_BYTES


CARRIERS = {
    "bearer": Carrier("bearer", "Authorization", "Bearer ", issue_delivery="body"),
    "cookie": Carrier("cookie", "Cookie", f"{COOKIE_NAME}=", issue_delivery="cookie"),
    "split": SplitCarrier("split", "Cookie", "", issue_delivery="split"),
}
# Not one of the load command's transports: run_reference_load measures it.
REF_CARRIER = RefCarrier("ref_bearer", "Authorization", "Bearer ", issue_delivery="body")


def carrier_of(transport: str) -> Carrier:
    """The carrier of a run's transport: one of CARRIERS, or REF_CARRIER for a reference run."""
    return REF_CARRIER if transport == REF_CARRIER.name else CARRIERS[transport]


@dataclass(frozen=True)
class CellPlan:
    """One cell to measure: a client, a concurrency level, a configuration, and a variant."""

    client: str
    concurrency: int
    algorithm: str  # The configuration the cell belongs to.
    variant: str  # "token" or "size_control".
    signed_with: str  # The configuration whose token is sent.
    pad: int
    token_bytes: int


@dataclass
class Issue:
    """The untimed issue step of a cell: whether a token was delivered, and why not."""

    status: int | None
    delivered: bool
    error: str | None = None
    token: str | None = None  # Kept out of every result; only the timed requests use it.

    def entry(self) -> dict:
        """The cell's issue entry, without the token."""
        return {"status": self.status, "delivered": self.delivered, "error": self.error}


@dataclass
class Sample:
    """One measured request as its client saw it, before it is judged."""

    worker: int
    sequence: int
    nonce: str
    start_ns: int  # Since the start of the measured phase.
    total_ns: int
    status: int | None
    proxied: bool  # The response carried nginx's X-Transport-Proxy header.
    # The response body's JSON object. The direct client keeps the raw bytes here during its
    # timed loop and parses them afterwards (parse_direct_bodies).
    body: dict | bytes | None
    body_bytes: int | None
    error: str | None


# --- Settings ---------------------------------------------------------------------------------


def default_settings() -> dict:
    """run_load's keyword defaults, by setting name (the load command's defaults too)."""
    parameters = inspect.signature(run_load).parameters
    return {name: parameter.default for name, parameter in parameters.items() if name != "stack"}


def distinct_list(name: str, values: object) -> list:
    """Return values as a list; raise ValueError unless it is a non-empty, non-str sequence."""
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
        raise ValueError(f"{name} must be a non-empty sequence, got {values!r}")
    return list(values)


def check_distinct(name: str, values: list) -> None:
    """Raise ValueError if values repeats an item."""
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not repeat a value, got {values!r}")


def client_list(clients: object) -> list[str]:
    """Return the clients to run, in order; None means both."""
    if clients is None:
        return list(CLIENTS)
    clients = distinct_list("clients", clients)
    unknown = [client for client in clients if not isinstance(client, str) or client not in CLIENTS]
    if unknown:
        raise ValueError(f"clients must be from {', '.join(CLIENTS)}, got {unknown!r}")
    check_distinct("clients", clients)
    return clients


def concurrency_levels(concurrency: object) -> list[int]:
    """Return the concurrency levels to run, in order: distinct ints from 1 to MAX_CONCURRENCY."""
    levels = distinct_list("concurrency", concurrency)
    invalid = [level for level in levels
               if type(level) is not int or not 1 <= level <= MAX_CONCURRENCY]  # No bools.
    if invalid:
        raise ValueError(f"concurrency levels must be ints from 1 to {MAX_CONCURRENCY}, "
                         f"got {invalid!r}")
    check_distinct("concurrency", levels)
    return levels


def check_seconds(name: str, value: object, allow_zero: bool) -> None:
    """Raise ValueError unless value is a finite number of seconds above (or at) zero."""
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
            or value < 0 or (value == 0 and not allow_zero)):
        bound = ">= 0" if allow_zero else "> 0"
        raise ValueError(f"{name} must be a finite number of seconds {bound}, got {value!r}")


def check_name(name: str, value: object, choices) -> None:
    """Raise ValueError unless value is one of the names in choices."""
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{name} must be one of {', '.join(choices)}, got {value!r}")


def checked_settings(algorithms, transport, clients, concurrency, duration, warmup, claims,
                     reference, size_controls, timeout, proxy_buffers, header_buffers,
                     upstream_keepalive=None) -> dict:
    """Check run_load's arguments and return them as the run's recorded settings.

    Raises ValueError for any invalid argument. The returned settings use lists for sequences
    and list the measured configurations: the selected ones plus the reference, in ADAPTER_LIST
    order. Passing them back as run_load(stack, **settings) repeats the workload.
    """
    selected = selected_algorithms(algorithms)
    check_name("transport", transport, CARRIERS)
    clients = client_list(clients)
    levels = concurrency_levels(concurrency)
    check_seconds("duration", duration, allow_zero=False)
    check_seconds("warmup", warmup, allow_zero=True)
    check_name("claims", claims, CLAIM_SET_NAMES)
    check_name("reference", reference, ADAPTERS)
    if not isinstance(size_controls, bool):
        raise ValueError(f"size_controls must be a bool, got {size_controls!r}")
    check_timeout(timeout)
    if upstream_keepalive is not None:
        check_upstream_keepalive(upstream_keepalive)
    measured = [adapter.name for adapter in ADAPTER_LIST
                if adapter.name in selected or adapter.name == reference]
    return {"algorithms": measured, "transport": transport, "clients": clients, "claims": claims,
            "concurrency": levels, "duration": duration, "warmup": warmup,
            "reference": reference, "size_controls": size_controls, "timeout": timeout,
            "proxy_buffers": proxy_buffers, "header_buffers": header_buffers,
            "upstream_keepalive": upstream_keepalive}


def read_saved_settings(path: Path) -> dict:
    """Return the settings object of a load.json written by an earlier run.

    Raises ValueError when the file cannot be read, is not such a load.json, names a setting
    run_load does not take, or records nginx buffers that are not an nginx size or an upstream
    keepalive count out of range. Every other
    value is checked by checked_settings once it is combined with the command line.
    """
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from None
    settings = saved.get("settings") if isinstance(saved, dict) else None
    if not isinstance(settings, dict):
        raise ValueError(f"{path} has no settings object; give the load.json of an earlier run")
    unknown = sorted(set(settings) - set(default_settings()))
    if unknown:
        raise ValueError(f"{path} has unknown settings {', '.join(map(repr, unknown))}")
    for name in ("proxy_buffers", "header_buffers"):
        if settings.get(name) is not None:
            nginx_size(name, settings[name])
    if settings.get("upstream_keepalive") is not None:
        check_upstream_keepalive(settings["upstream_keepalive"])
    return settings


# --- Cells ------------------------------------------------------------------------------------


def configuration_variants(algorithm: str, settings: dict) -> list[tuple[str, str, int]]:
    """Return (variant, signed_with, pad) for each cell of one configuration.

    The token cell sends the configuration's own token. The size-control cell, when enabled and
    possible, sends the reference's token padded to the configuration's size or one byte less.
    """
    claims, reference = claim_set(settings["claims"]), settings["reference"]
    variants = [("token", algorithm, 0)]
    if settings["size_controls"] and algorithm != reference:
        pad = pad_for_target(reference, claims, token_bytes(algorithm, claims))
        if pad is not None:
            variants.append(("size_control", reference, pad))
    return variants


def plan_cells(settings: dict) -> list[CellPlan]:
    """List every cell in measurement order: client, concurrency, configuration, variant."""
    claims = claim_set(settings["claims"])
    variants = {name: configuration_variants(name, settings) for name in settings["algorithms"]}
    return [CellPlan(client, level, name, variant, signed_with, pad,
                     token_bytes(signed_with, padded_claims(claims, pad)))
            for client in settings["clients"]
            for level in settings["concurrency"]
            for name in settings["algorithms"]
            for variant, signed_with, pad in variants[name]]


def cell_nonce_prefix(run_prefix: str, cell_index: int) -> str:
    """The first 16 of a cell's 32-hex-digit nonces; a 16-digit request counter completes them.

    A random prefix per run and sequential counters keep nonces unique within the run and in a
    shared log, and compress well in the saved logs.
    """
    return f"{run_prefix}{cell_index:08x}"


class NonceCounter:
    """Thread-safe source of one cell's nonces: the cell's prefix plus a 16-hex-digit counter."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.counter = itertools.count()
        self.lock = threading.Lock()

    def next(self) -> str:
        with self.lock:
            value = next(self.counter)
        return f"{self.prefix}{value:016x}"


@dataclass(frozen=True)
class Phases:
    """When a cell's measured phase starts and ends, on the time.perf_counter_ns clock."""

    measured_start_ns: int
    measured_end_ns: int

    @classmethod
    def starting_now(cls, warmup: float, duration: float) -> "Phases":
        """The phases of a cell whose warm-up starts now."""
        start = time.perf_counter_ns() + round(warmup * 1e9)
        return cls(start, start + round(duration * 1e9))


# --- Direct client ----------------------------------------------------------------------------


class DirectClient:
    """http.client threads in this process, each with a persistent HTTP/1.1 connection to nginx."""

    name = "direct"

    def __init__(self, stack, carrier: Carrier, settings: dict):
        self.stack, self.carrier, self.settings = stack, carrier, settings
        self.stop = threading.Event()  # Set when the run is interrupted.

    def issue(self, plan: CellPlan) -> Issue:
        """Get the cell's token (or, for REF_CARRIER, its reference) in the JSON body through
        nginx; this step is not timed."""
        url, _ = nonce_url(self.stack.proxy_url, self.carrier.issue_path, alg=plan.signed_with,
                           delivery="body", claims=self.settings["claims"], pad=str(plan.pad))
        try:
            status, _, body = http_get(url, timeout=self.settings["timeout"])
        except (OSError, http.client.HTTPException) as error:
            return Issue(None, False, f"no response: {type(error).__name__}: {error}")
        token = (json_object(body) or {}).get(self.carrier.issued_key)
        if status != 200:
            return Issue(status, False, f"the issue request got status {status}")
        if not isinstance(token, str):
            return Issue(status, False, f"the issue response carried no {self.carrier.issued_key}")
        return Issue(status, True, token=token)

    def measure(self, plan: CellPlan, nonce_prefix: str) -> tuple[Issue, list[Sample]]:
        """Issue the cell's token, then run the closed loop with one thread per worker."""
        issue = self.issue(plan)
        if not issue.delivered:
            return issue, []
        headers = self.carrier.direct_headers(issue.token)
        nonces = NonceCounter(nonce_prefix)
        phases = Phases.starting_now(self.settings["warmup"], self.settings["duration"])
        per_worker = [[] for _ in range(plan.concurrency)]
        failures = []  # An unexpected error in a worker, so the cell fails instead of losing rows.
        threads = [threading.Thread(target=self.worker, daemon=True,
                                    args=(index, headers, nonces, phases, per_worker[index],
                                          failures))
                   for index in range(plan.concurrency)]
        for thread in threads:
            thread.start()
        try:
            for thread in threads:
                thread.join()
        except BaseException:  # Such as KeyboardInterrupt from SIGINT: let the workers stop.
            self.stop.set()
            raise
        if failures:
            raise RuntimeError(f"direct client: a worker failed: {failures[0]!r}")
        samples = [sample for worker in per_worker for sample in worker]
        parse_direct_bodies(samples)  # After the loop, so parsing never delays a request.
        return issue, sorted(samples, key=lambda sample: (sample.start_ns, sample.worker))

    def worker(self, index: int, headers: dict, nonces: NonceCounter, phases: Phases,
               samples: list[Sample], failures: list[BaseException]) -> None:
        """Send requests one after another until the measured phase ends; record measured ones."""
        parts = urlsplit(self.stack.proxy_url)
        connection = http.client.HTTPConnection(parts.hostname, parts.port,
                                                timeout=self.settings["timeout"])
        sequence = 0
        try:
            while not self.stop.is_set():
                nonce = nonces.next()
                started = time.perf_counter_ns()
                if started >= phases.measured_end_ns:
                    return
                status, proxied, body, error = self.send(connection, nonce, headers)
                finished = time.perf_counter_ns()
                if started >= phases.measured_start_ns:
                    sequence += 1
                    samples.append(Sample(index, sequence, nonce,
                                          started - phases.measured_start_ns, finished - started,
                                          status, proxied, body, None, error))
        except Exception as error:  # Not a request failure (send() records those): a bug.
            failures.append(error)
        finally:
            connection.close()

    @staticmethod
    def send(connection: http.client.HTTPConnection, nonce: str,
             headers: dict) -> tuple[int | None, bool, bytes | None, str | None]:
        """Send one timed request and read its whole body; return status, marker, body, error.

        http.client reopens the connection on the next request when the server closed it; after
        an error, closing it here does the same.
        """
        try:
            connection.request("GET", f"{TIMED_TARGET}{nonce}", headers=headers)
            response = connection.getresponse()
            body = response.read()
            return response.status, response.getheader(PROXY_MARKER) is not None, body, None
        except (OSError, http.client.HTTPException) as error:
            connection.close()
            return None, False, None, f"{type(error).__name__}: {error}"


def parse_direct_bodies(samples: list[Sample]) -> None:
    """Replace each sample's raw body bytes with their JSON object, and record their length."""
    for sample in samples:
        raw = sample.body
        sample.body = json_object(raw) if raw is not None else None
        sample.body_bytes = len(raw) if raw is not None else None


# --- Browser client ---------------------------------------------------------------------------


class BrowserClient:
    """Concurrent fetch() loops in the test page of one headless Chromium, one context per cell."""

    name = "browser"

    def __init__(self, browser, stack, carrier: Carrier, settings: dict, log_path: Path):
        self.browser, self.stack, self.carrier = browser, stack, carrier
        self.settings, self.log_path = settings, log_path

    def measure(self, plan: CellPlan, nonce_prefix: str) -> tuple[Issue, list[Sample]]:
        """In a new context, load the page, issue the cell's token from it, and run the loop."""
        context = self.browser.new_context()  # A new context per cell, so no cookie carries over.
        try:
            page = context.new_page()
            page.set_default_timeout(self.settings["timeout"] * 1000)
            issue = self.issue(context, page, plan)
            if not issue.delivered:
                return issue, []
            return issue, self.run_loop(page, plan, issue, nonce_prefix)
        finally:
            context.close()

    def issue(self, context, page, plan: CellPlan) -> Issue:
        """Load the test page through nginx and fetch() the token from it; this is not timed.

        For the cookie and split carriers, the browser stores the token, or its chunks, from the
        Set-Cookie response itself.
        """
        timeout = self.settings["timeout"]
        page_url, _ = nonce_url(self.stack.proxy_url, "/")
        page_status, page_error = load_test_page(page, page_url, timeout)
        if page_status != 200:
            return Issue(None, False, f"the test page returned {page_status or page_error}")
        url, nonce = nonce_url(self.stack.proxy_url, self.carrier.issue_path,
                               alg=plan.signed_with, delivery=self.carrier.issue_delivery,
                               claims=self.settings["claims"], pad=str(plan.pad))
        reply = send_fetch(page, url, nonce, timeout)
        cookie_names = [cookie["name"] for cookie in context.cookies()]
        # Cookie names only, never values or headers, so browser.log holds no token from a load.
        BrowserLog(self.log_path, plan.algorithm, self.carrier.name).write(
            "load_issue", variant=plan.variant, signed_with=plan.signed_with, pad=plan.pad,
            concurrency=plan.concurrency, url=url, page_status=page_status, status=reply.status,
            error=reply.error, cookie_names=cookie_names)
        if reply.status is None:
            return Issue(None, False, f"no response: {reply.error}")
        if reply.status != 200:
            return Issue(reply.status, False, f"the issue request got status {reply.status}")
        if self.carrier.issue_delivery == "cookie":
            if COOKIE_NAME not in cookie_names:
                return Issue(reply.status, False, f"the browser stored no {COOKIE_NAME} cookie")
            return Issue(reply.status, True)
        if self.carrier.issue_delivery == "split":
            return split_issue(reply, cookie_names)
        token = (reply.body or {}).get(self.carrier.issued_key)
        if not isinstance(token, str):
            return Issue(reply.status, False,
                         f"the issue response carried no {self.carrier.issued_key}")
        return Issue(reply.status, True, token=token)

    def run_loop(self, page, plan: CellPlan, issue: Issue, nonce_prefix: str) -> list[Sample]:
        """Run BROWSER_LOOP in the page; no Playwright handler is attached while it runs."""
        measured = page.evaluate(BROWSER_LOOP, {
            "target": f"{self.stack.proxy_url}{TIMED_TARGET}", "prefix": nonce_prefix,
            "headers": self.carrier.browser_headers(issue.token),
            "concurrency": plan.concurrency, "warmupMs": self.settings["warmup"] * 1000,
            "durationMs": self.settings["duration"] * 1000,
            "timeoutMs": self.settings["timeout"] * 1000,
        })
        samples = [Sample(request["worker"], request["sequence"], request["nonce"],
                          round(request["startMs"] * 1_000_000),
                          round(request["totalMs"] * 1_000_000), request["status"],
                          request["proxied"], request["body"], request["bodyBytes"],
                          request["error"])
                   for request in measured]
        return sorted(samples, key=lambda sample: (sample.start_ns, sample.worker))


def split_issue(reply, stored_names: list[str]) -> Issue:
    """Judge a browser cell's split issue: delivered only when the jar holds every chunk cookie.

    reply is the 200 issue response; its body's cookie_names lists the chunk cookies the
    application set. An empty or unreadable list counts as nothing delivered.
    """
    expected = (reply.body or {}).get("cookie_names")
    if not (isinstance(expected, list) and expected
            and all(isinstance(name, str) for name in expected)):
        return Issue(reply.status, False, "the browser stored 0 of 0 expected chunk cookies: "
                                          "the issue response listed no cookie_names")
    stored = len(set(expected) & set(stored_names))
    if stored != len(set(expected)):
        return Issue(reply.status, False, f"the browser stored {stored:,} of the "
                                          f"{len(set(expected)):,} expected chunk cookies")
    return Issue(reply.status, True)


@contextmanager
def started_clients(stack, settings: dict) -> Iterator[tuple[dict, dict | None]]:
    """Yield the clients by name and the browser's identity (None without the browser client).

    Headless Chromium is launched only when the browser client runs, and closed on exit.
    Playwright errors become RuntimeError("browser: ...").
    """
    carrier = carrier_of(settings["transport"])
    clients = {}
    if "direct" in settings["clients"]:
        clients["direct"] = DirectClient(stack, carrier, settings)
    if "browser" not in settings["clients"]:
        yield clients, None
        return
    from playwright.sync_api import Error as PlaywrightError, sync_playwright  # Checked first.

    log_path = Path(stack.run_dir) / "logs" / LOG_FILES["browser"]
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=settings["timeout"] * 1000)
            try:
                identity = browser_identity(browser)
                clients["browser"] = BrowserClient(browser, stack, carrier, settings, log_path)
                yield clients, identity
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error


# --- Judging requests and summarizing cells ---------------------------------------------------


def is_verified(sample: Sample, plan: CellPlan, transport: str) -> bool:
    """A request counts as verified only with 200, nginx's marker, and a body that confirms it."""
    body = sample.body or {}
    return (sample.status == 200 and sample.proxied and body.get("verified") is True
            and body.get("algorithm") == plan.signed_with and body.get("source") == transport)


def server_timing(body: dict | None) -> tuple[int | None, int | None]:
    """Return handler_ns and verify_ns from a verify body's timing object, or None for each."""
    timing = (body or {}).get("timing")
    if not isinstance(timing, dict):
        return None, None
    handler_ns, verify_ns = timing.get("handler_ns"), timing.get("verify_ns")
    return (handler_ns if type(handler_ns) is int else None,
            verify_ns if type(verify_ns) is int else None)


def lookup_timing(body: dict | None) -> int | None:
    """Return lookup_ns from a verify body's timing object, or None."""
    timing = (body or {}).get("timing")
    lookup_ns = timing.get(LOOKUP_FIELD) if isinstance(timing, dict) else None
    return lookup_ns if type(lookup_ns) is int else None


def raw_row(plan: CellPlan, sample: Sample, transport: str) -> dict:
    """One raw row (RAW_FIELDS, in order) for one measured request; a reference run's row ends
    with lookup_ns."""
    handler_ns, verify_ns = server_timing(sample.body)
    row = {"client": plan.client, "concurrency": plan.concurrency, "algorithm": plan.algorithm,
           "variant": plan.variant, "signed_with": plan.signed_with, "pad": plan.pad,
           "token_bytes": plan.token_bytes, "worker": sample.worker, "sequence": sample.sequence,
           "nonce": sample.nonce, "start_ns": sample.start_ns, "total_ns": sample.total_ns,
           "handler_ns": handler_ns, "verify_ns": verify_ns, "status": sample.status,
           "verified": is_verified(sample, plan, transport), "error": sample.error}
    if transport == REF_CARRIER.name:
        row[LOOKUP_FIELD] = lookup_timing(sample.body)
    return row


def component_ns(row: dict) -> dict[str, int]:
    """Split one verified request's total into transfer, other handling, and verification, and
    for a reference run's row also the lookup, which is taken out of other handling."""
    if (row["handler_ns"] is None or row["verify_ns"] is None
            or (LOOKUP_FIELD in row and row[LOOKUP_FIELD] is None)):
        raise RuntimeError(f"application: the verify response for nonce {row['nonce']} has no "
                           "timing; the application must support timing=1")
    if LOOKUP_FIELD not in row:
        return {"total": row["total_ns"],
                "transfer": row["total_ns"] - row["handler_ns"],
                "other_handling": row["handler_ns"] - row["verify_ns"],
                "verification": row["verify_ns"]}
    return {"total": row["total_ns"],
            "transfer": row["total_ns"] - row["handler_ns"],
            "other_handling": row["handler_ns"] - row["verify_ns"] - row[LOOKUP_FIELD],
            "lookup": row[LOOKUP_FIELD],
            "verification": row["verify_ns"]}


def describe_ns(samples: list[int]) -> dict:
    """Median and nearest-rank p95 (scripts/rsa_jwt.py) and the arithmetic mean, in ms."""
    return {**summarize(samples), "mean_ms": statistics.fmean(samples) / 1_000_000}


def latency_summary(rows: list[dict]) -> dict | None:
    """Summarize each latency component (LATENCY_COMPONENTS, or REF_LATENCY_COMPONENTS for a
    reference run) over a cell's verified rows; None if none verified."""
    components = [component_ns(row) for row in rows if row["verified"]]
    if not components:
        return None
    return {name: describe_ns([values[name] for values in components])
            for name in components[0]}


def cell_entry(plan: CellPlan, settings: dict, issue: Issue, rows: list[dict],
               samples: list[Sample]) -> dict:
    """Summarize one cell from its raw rows; byte counts come from its first verified request."""
    verified = sum(row["verified"] for row in rows)
    statuses = Counter("error" if row["status"] is None else str(row["status"]) for row in rows)
    measured_seconds = (max(row["start_ns"] + row["total_ns"] for row in rows) / 1e9
                        if rows else 0.0)
    first_verified = next((sample for sample, row in zip(samples, rows) if row["verified"]), None)
    received = ((first_verified.body or {}).get("received") or {}) if first_verified else {}
    carrier = carrier_of(settings["transport"])
    # A reference run's cells also say how long the reference itself is.
    reference = {"reference_bytes": REF_BYTES} if carrier is REF_CARRIER else {}
    return {
        "client": plan.client,
        "concurrency": plan.concurrency,
        "algorithm": plan.algorithm,
        "variant": plan.variant,
        "signed_with": plan.signed_with,
        "claims": settings["claims"],
        "pad": plan.pad,
        "token_bytes": plan.token_bytes,
        **reference,
        "issue": issue.entry(),
        "requests": len(rows),
        "verified": verified,
        "failed": len(rows) - verified,
        "statuses": dict(sorted(statuses.items())),
        "measured_seconds": measured_seconds,
        "throughput_rps": verified / measured_seconds if measured_seconds else 0.0,
        "latency": latency_summary(rows),
        "bytes": {
            "header_line": carrier.header_line_bytes(plan.token_bytes),
            "app_received_headers": received.get("header_bytes"),
            "response_body": first_verified.body_bytes if first_verified else None,
        },
    }


# --- Comparisons with the reference -----------------------------------------------------------


def mean_ms(cell: dict, component: str) -> float:
    """A measured cell's mean latency for one component, in ms."""
    return cell["latency"][component]["mean_ms"]


def difference_from_reference(cell: dict, reference: dict) -> dict | None:
    """Each component's mean minus the reference's, and the token-size part of the total."""
    if cell["latency"] is None or reference["latency"] is None:
        return None
    difference = {component: mean_ms(cell, component) - mean_ms(reference, component)
                  for component in LATENCY_COMPONENTS}
    # Whatever is not verification comes from the token's size: transfer + other_handling.
    difference["token_size"] = difference["total"] - difference["verification"]
    return difference


def size_control_check(cell: dict, control: dict | None, reference: dict) -> dict | None:
    """Split the total difference with the size-matched control instead of the server timings.

    The control has the configuration's size and the reference's verification, so control minus
    reference is the token-size effect and configuration minus control the verification effect.
    """
    if control is None:
        return None
    measured = all(entry["latency"] is not None for entry in (cell, control, reference))
    return {"token_bytes": control["token_bytes"], "pad": control["pad"],
            "difference_ms": None if not measured else {
                "token_size": mean_ms(control, "total") - mean_ms(reference, "total"),
                "verification": mean_ms(cell, "total") - mean_ms(control, "total")}}


def compare_with_reference(results: list[dict], reference: str) -> list[dict]:
    """One comparison per token cell with the reference's token cell of the same client and
    concurrency, in results order."""
    cells = {(cell["client"], cell["concurrency"], cell["algorithm"], cell["variant"]): cell
             for cell in results}
    comparisons = []
    for cell in results:
        if cell["variant"] != "token":
            continue
        key = (cell["client"], cell["concurrency"])
        baseline = cells[(*key, reference, "token")]
        control = cells.get((*key, cell["algorithm"], "size_control"))
        comparisons.append({
            "client": cell["client"],
            "concurrency": cell["concurrency"],
            "algorithm": cell["algorithm"],
            "reference": reference,
            "token_bytes": cell["token_bytes"],
            "reference_token_bytes": baseline["token_bytes"],
            "throughput_rps": cell["throughput_rps"],
            "reference_throughput_rps": baseline["throughput_rps"],
            "difference_ms": difference_from_reference(cell, baseline),
            "size_control": size_control_check(cell, control, baseline),
        })
    return comparisons


# --- Modeled network cost (R22) ---------------------------------------------------------------


def slow_start_flights(request_bytes: int) -> int:
    """Slow-start rounds needed to send request_bytes on a new or idle connection, without loss."""
    window, sent, flights = INITIAL_WINDOW_SEGMENTS * MSS_BYTES, 0, 0
    while sent < request_bytes:
        sent += window
        window *= 2
        flights += 1
    return flights


def modeled_transfer_ms(request_bytes: int, uplink_mbps: float, rtt_ms: float) -> float:
    """Calculated (not measured) upload time of request_bytes: serialization at the uplink rate
    plus one round trip for each slow-start round after the first."""
    if isinstance(request_bytes, bool) or not isinstance(request_bytes, int) or request_bytes < 1:
        raise ValueError(f"request_bytes must be an int >= 1, got {request_bytes!r}")
    for name, value, allow_zero in (("uplink_mbps", uplink_mbps, False),
                                    ("rtt_ms", rtt_ms, True)):
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero)):
            bound = ">= 0" if allow_zero else "> 0"
            raise ValueError(f"{name} must be a finite number {bound}, got {value!r}")
    serialization_ms = request_bytes * 8 / (uplink_mbps * 10**6) * 1000
    return serialization_ms + (slow_start_flights(request_bytes) - 1) * rtt_ms


def direct_request_bytes(proxy_url: str, carrier: Carrier, token_size: int) -> int:
    """Bytes of the request header block the direct client sends with a token of token_size.

    The request line, Host, Accept-Encoding: identity (both added by http.client), the token's
    header line, and every CRLF including the final one, as Sprint 2's direct Bearer probe
    counts them.
    """
    host = urlsplit(proxy_url).netloc
    head = (f"GET {TIMED_TARGET}{'0' * 32} HTTP/1.1\r\nHost: {host}\r\n"
            "Accept-Encoding: identity\r\n")
    return len(head.encode("latin-1")) + carrier.header_line_bytes(token_size) + len("\r\n")


def network_model(settings: dict, proxy_url: str) -> dict:
    """Modeled upload time of each configuration's request at every profile, and its difference
    from the reference's; calculated, not measured."""
    carrier, claims = carrier_of(settings["transport"]), claim_set(settings["claims"])
    # Each configuration's token cell; it does not depend on which clients ran.
    sizes = {name: direct_request_bytes(proxy_url, carrier, token_bytes(name, claims))
             for name in settings["algorithms"]}
    reference = sizes[settings["reference"]]
    rows = []
    for name in settings["algorithms"]:
        modeled = []
        for profile in NETWORK_PROFILES:
            transfer_ms = modeled_transfer_ms(sizes[name], **profile)
            reference_ms = modeled_transfer_ms(reference, **profile)
            modeled.append({**profile, "transfer_ms": transfer_ms,
                            "difference_ms": transfer_ms - reference_ms})
        rows.append({"algorithm": name, "request_bytes": sizes[name],
                     "extra_request_bytes": sizes[name] - reference, "modeled": modeled})
    return {
        "basis": NETWORK_BASIS,
        "mss_bytes": MSS_BYTES,
        "initial_window_segments": INITIAL_WINDOW_SEGMENTS,
        "profiles": [dict(profile) for profile in NETWORK_PROFILES],
        "rows": rows,
    }


# --- The run ----------------------------------------------------------------------------------


def network_description(keepalive: int | None) -> str:
    """Where the requests travel, including how nginx connects to waitress."""
    if keepalive is None:
        return f"{WORKLOAD_NETWORK}; nginx opens a new connection to waitress for every request"
    return (f"{WORKLOAD_NETWORK}; nginx reuses up to {keepalive} idle connections to waitress "
            f"(--upstream-keepalive {keepalive}, not a default; see nginx.conf)")


def workload(keepalive: int | None, clients: Sequence[str]) -> dict:
    """Describe the request mix, the loop, where each client runs, and its timer."""
    return {
        "request_mix": [{"method": "GET", "path": VERIFY_PATH, "fraction": 1.0}],
        "loop": "closed",
        "client_location": {"network": network_description(keepalive),
                            **{client: WORKLOAD_CLIENTS[client] for client in clients}},
        "timers": {"server": WORKLOAD_TIMERS["server"],
                   **{client: WORKLOAD_TIMERS[client] for client in clients}},
    }


def run_environment() -> dict:
    """Sprint 1's environment record plus the page size and waitress's thread count."""
    return {**environment(), "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
            "waitress_threads": Adjustments.threads}  # transport_app.py keeps the default.


def last_answered_nonces(samples: list[Sample]) -> list[str]:
    """The nonce of each worker's last request that got a response."""
    last = {}
    for sample in samples:
        if sample.status is not None:
            last[sample.worker] = sample.nonce
    return list(last.values())


def wait_for_access_log(path: Path, nonces: list[str]) -> None:
    """Wait briefly until nginx has logged the last requests; it logs after each response."""
    deadline = time.monotonic() + LOG_GRACE_SECONDS
    while nonces and time.monotonic() < deadline:
        try:
            with path.open("rb") as log:
                log.seek(max(0, path.stat().st_size - LOG_TAIL_BYTES))
                tail = log.read().decode("utf-8", errors="replace")
        except OSError:
            tail = ""
        if all(nonce in tail for nonce in nonces):
            return
        time.sleep(0.05)


def run_load(stack, algorithms: Sequence[str] | None = None, transport: str = "bearer",
             clients: Sequence[str] | None = None, concurrency: Sequence[int] = (1, 4),
             duration: float = 5.0, warmup: float = 1.0, claims: str = "minimal",
             reference: str = "ES256", size_controls: bool = True, timeout: float = 60.0,
             proxy_buffers: str | None = None, header_buffers: str | None = None,
             upstream_keepalive: int | None = None) -> dict:
    """Measure every cell's latency and throughput through the stack; leave the stack running.

    stack is any object with proxy_url, app_url, and run_dir, such as the one start_stack
    yields. proxy_buffers, header_buffers, and upstream_keepalive only record the settings the
    stack was started with; upstream_keepalive None takes the stack's own (start_stack's
    option), so the record always matches the stack. Raises ValueError for invalid arguments
    before any request is sent, and RuntimeError ("automation: ..." or "browser: ...") when
    Playwright is missing or fails.
    """
    stack_keepalive = getattr(stack, "upstream_keepalive", None)
    if upstream_keepalive is None:
        upstream_keepalive = stack_keepalive
    elif stack_keepalive is not None and upstream_keepalive != stack_keepalive:
        raise ValueError(f"upstream_keepalive {upstream_keepalive!r} does not match the stack's "
                         f"{stack_keepalive!r}")
    settings = checked_settings(algorithms, transport, clients, concurrency, duration, warmup,
                                claims, reference, size_controls, timeout, proxy_buffers,
                                header_buffers, upstream_keepalive)
    return measure_load(stack, settings)


def stack_upstream_keepalive(stack, upstream_keepalive: int | None) -> int | None:
    """The upstream_keepalive to record: the given one, or the stack's own when None.

    Raises ValueError when both are given and differ, so the record always matches the stack.
    """
    stack_keepalive = getattr(stack, "upstream_keepalive", None)
    if upstream_keepalive is None:
        return stack_keepalive
    if stack_keepalive is not None and upstream_keepalive != stack_keepalive:
        raise ValueError(f"upstream_keepalive {upstream_keepalive!r} does not match the stack's "
                         f"{stack_keepalive!r}")
    return upstream_keepalive


def run_reference_load(stack, algorithms: Sequence[str] | None = None,
                       clients: Sequence[str] | None = None, concurrency: Sequence[int] = (1, 4),
                       duration: float = 5.0, warmup: float = 1.0, claims: str = "minimal",
                       reference: str = "ES256", size_controls: bool = True,
                       timeout: float = 60.0, proxy_buffers: str | None = None,
                       header_buffers: str | None = None,
                       upstream_keepalive: int | None = None) -> dict:
    """Measure the workload with REF_CARRIER: a Bearer reference instead of the token.

    Takes run_load's arguments except transport, checks them as run_load checks a Bearer run,
    and returns what run_load returns, with settings.transport "ref_bearer" and
    settings.ref_store, the stack's store ("memory" or "remote"). Its raw rows end with
    lookup_ns, and each verified cell's latency has a lookup component. write_load_results saves
    it; the load command does not take ref_bearer, so `load --settings` cannot repeat it.
    """
    upstream_keepalive = stack_upstream_keepalive(stack, upstream_keepalive)
    settings = checked_settings(algorithms, "bearer", clients, concurrency, duration, warmup,
                                claims, reference, size_controls, timeout, proxy_buffers,
                                header_buffers, upstream_keepalive)
    settings = {**settings, "transport": REF_CARRIER.name,
                "ref_store": getattr(stack, "ref_store", "memory")}
    return measure_load(stack, settings)


def measure_load(stack, settings: dict) -> dict:
    """Measure every cell of checked settings through the stack; run_load's result.

    Raises RuntimeError when the browser client runs and Playwright is missing or fails.
    """
    if "browser" in settings["clients"]:
        try:
            import playwright.sync_api  # noqa: F401  Only checks that it can be imported.
        except ImportError as error:
            raise RuntimeError(f"automation: Playwright is not installed ({error})") from error
    plans = plan_cells(settings)
    manifest = load_manifest()
    log_dir = Path(stack.run_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    run_prefix = secrets.token_hex(4)

    started = datetime.now(timezone.utc)
    results, raw, last_nonces = [], [], []
    with started_clients(stack, settings) as (clients_by_name, browser):
        for index, plan in enumerate(plans):
            client = clients_by_name[plan.client]
            issue, samples = client.measure(plan, cell_nonce_prefix(run_prefix, index))
            rows = [raw_row(plan, sample, settings["transport"]) for sample in samples]
            results.append(cell_entry(plan, settings, issue, rows, samples))
            raw.extend(rows)
            last_nonces = last_answered_nonces(samples) or last_nonces
    wait_for_access_log(log_dir / LOG_FILES["proxy_access"], last_nonces)
    finished = datetime.now(timezone.utc)

    return {
        "schema_version": SCHEMA_VERSION,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "settings": settings,
        "workload": workload(settings["upstream_keepalive"], settings["clients"]),
        "environment": run_environment(),
        "layers": manifest_layers(manifest),
        "browser": browser,
        "proxy_url": stack.proxy_url,
        "app_url": stack.app_url,
        "run_dir": str(stack.run_dir),
        "experiment_keys": True,
        "results": results,
        "comparisons": compare_with_reference(results, settings["reference"]),
        "network_model": network_model(settings, stack.proxy_url),
        "raw": raw,
    }


# --- Output -----------------------------------------------------------------------------------


def csv_field(value) -> str | int:
    """A raw value as a CSV field: null is empty and booleans are true or false."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def gzip_writer(file) -> gzip.GzipFile:
    """A gzip stream into file with no name and mtime 0, so equal input compresses identically."""
    return gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0)


def write_raw_csv(raw: list[dict], target: Path,
                  fields: Sequence[str] = RAW_FIELDS) -> None:
    """Write the raw rows as a gzip-compressed CSV with fields (RAW_FIELDS) as its header."""
    with target.open("wb") as file:
        with io.TextIOWrapper(gzip_writer(file), encoding="utf-8", newline="") as text:
            writer = csv.writer(text)
            writer.writerow(fields)
            for row in raw:
                writer.writerow([csv_field(row[field]) for field in fields])


def save_logs(log_dir: Path, target_dir: Path) -> dict[str, str]:
    """Save a gzip copy of every log as <name>.gz; return each saved path by log name."""
    target_dir.mkdir(parents=True, exist_ok=True)
    saved = {}
    for log in sorted(log_dir.iterdir()):
        target = target_dir / f"{log.name}.gz"
        with log.open("rb") as source, target.open("wb") as file:
            with gzip_writer(file) as compressed:
                shutil.copyfileobj(source, compressed)
        saved[log.name] = f"{target_dir.name}/{target.name}"
    return saved


def write_load_results(result: dict, output_dir: Path) -> Path:
    """Save load.json, raw.csv.gz, gzip copies of the run's logs, and its rendered nginx.conf.

    load.json is the result without its raw rows, plus recorded_utc and evidence, which names
    every saved file. Logs are compressed because a saved result is evidence rather than a
    runtime log (git ignores *.log). A reference run's raw.csv.gz has one more last column,
    lookup_ns.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(result["run_dir"])
    saved_logs = save_logs(run_dir / "logs", output_dir / "logs")
    shutil.copy2(run_dir / "nginx" / "nginx.conf", output_dir / "nginx.conf")
    fields = RAW_FIELDS
    if result["settings"]["transport"] == REF_CARRIER.name:
        fields = (*RAW_FIELDS, LOOKUP_FIELD)
    write_raw_csv(result["raw"], output_dir / RAW_FILE, fields)
    saved = {key: value for key, value in result.items() if key != "raw"}
    saved["recorded_utc"] = datetime.now(timezone.utc).isoformat()
    saved["evidence"] = {"raw": RAW_FILE, "logs": saved_logs, "nginx_conf": "nginx.conf"}
    (output_dir / RESULT_FILE).write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    return output_dir


def summary_lines(result: dict) -> list[str]:
    """One line per comparison: the cell's size, latency, and throughput, and its difference
    from the reference split into token size and verification."""
    cells = {(cell["client"], cell["concurrency"], cell["algorithm"], cell["variant"]): cell
             for cell in result["results"]}
    width = max(len(entry["algorithm"]) for entry in result["comparisons"])
    lines = []
    for entry in result["comparisons"]:
        cell = cells[(entry["client"], entry["concurrency"], entry["algorithm"], "token")]
        label = (f"{entry['client']:<7} c={entry['concurrency']:<3} "
                 f"{entry['algorithm']:<{width}} {entry['token_bytes']:>6,} B")
        if cell["latency"] is None:
            statuses = ", ".join(f"{status} x{count:,}"
                                 for status, count in cell["statuses"].items())
            reason = cell["issue"]["error"] or f"statuses {statuses or 'none'}"
            lines.append(f"{label}  no verified request ({reason})")
            continue
        total = cell["latency"]["total"]
        line = (f"{label}  median {total['median_ms']:7.3f} ms  p95 {total['p95_ms']:7.3f} ms  "
                f"{cell['throughput_rps']:9,.1f} req/s")
        difference = entry["difference_ms"]
        if difference is not None:
            line += (f"  vs {entry['reference']} {difference['total']:+.3f} ms = size "
                     f"{difference['token_size']:+.3f} + verification "
                     f"{difference['verification']:+.3f}")
        control = (entry["size_control"] or {}).get("difference_ms")
        if control is not None:
            line += (f"  (control: size {control['token_size']:+.3f} + verification "
                     f"{control['verification']:+.3f})")
        if cell["failed"]:
            line += f"  {cell['failed']:,} failed"
        lines.append(line)
    return lines
