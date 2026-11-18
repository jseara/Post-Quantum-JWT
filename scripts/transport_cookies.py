"""Measure S3-02's second mitigation, cookie splitting, in one run.

The application can issue a token as several chunk cookies named jwt.<index>.<count>
(delivery=split in scripts/transport_app.py): near-equal pieces of at most 4,000 characters by
default, one Set-Cookie header each. On GET /api/token/verify it reassembles them in index order
whatever order they arrive in (source "split"), and it refuses an incomplete chunk set (401) or
an ambiguous one (400) before anything is verified. A run compares split cookies with the single
jwt cookie in five phases:

1. Chunk plan, calculated: for each configuration's unpadded token, the default chunk count,
   each chunk's size and name, and the bytes each limit counts (one cookie's name + value, the
   Set-Cookie lines, and the Cookie line), checked against Chromium's documented 4,096-byte
   cookie limit, its 180 cookies per domain (DOMAIN_MAX_COOKIES), and nginx's 8,192-byte header
   line. Nothing is sent in this phase.
2. Size limits at the documented defaults, measured: one stack with no raised limit and headless
   Chromium send each configuration's token once as a single jwt cookie and once split, both
   with production cookie attributes, browser -> nginx -> waitress, and the layer that rejected a
   pair is named from every layer's log (run_pair and judge in scripts/transport_tokens.py for
   the cookie, run_split_pair and judge_split here for the split). A boundary search then finds
   the largest split ML-DSA-44 token that gets through.
3. Raised limits and probes, measured: a stack with nginx's header and proxy buffers raised
   sends the same pairs, plus per-cookie probes (a chunk at and just over Chromium's 4,096 bytes
   of name + value) and cookie-count probes (180 and 181 chunks).
4. Chunk handling, measured: on the raised stack, http.client sends chunk sets through nginx in
   order, reversed, rotated, among other cookies, with a chunk missing, repeated, from another
   count, out of range, from another token, and together with a jwt cookie or a Bearer header,
   and records each status. The run records what it observes and never fails on a mismatch.
5. Latency: the S3-01 workload (scripts/transport_load.py) runs once with a single jwt cookie
   and once with split cookies, each on a new stack, and the two runs are compared cell by
   cell. The network model's extra upload time per profile is calculated, not measured.

Outputs, in output_dir: cookies.json (settings, environment, the chunk format and plan, the
measured limits, boundary, probes, chunk handling, the latency comparison, and evidence),
written last; limits-default/ and limits-raised/ (gzip copies of each stack's logs, and its
nginx.conf); and latency-cookie/ and latency-split/, each exactly what `load --output-dir`
writes. cookies.json, load.json, raw.csv.gz, app.log, and proxy-access.log hold no token, chunk,
or cookie value; browser.log holds the tokens of the size-limit phases, and proxy-error.log may
hold nginx's truncated prefix of a rejected header line.

Every signing key is an ephemeral experiment key, generated in memory by each stack's
application (and by this process for the calculated sizes) and never saved; none is a
production credential. Use run_cookies, or `scripts/transport_stack.py cookies`.
"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import http.client
import inspect
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import claim_set, pad_for_target, padded_claims, token_bytes
from scripts.transport_app import (COOKIE_ATTRIBUTE_SETS, COOKIE_NAME, SPLIT_CHUNK_BYTES,
                                   SPLIT_MAX_CHUNKS, chunk_cookie_line_bytes, chunk_cookie_name,
                                   chunk_sizes, default_chunk_count, split_token)
from scripts.transport_claims import (check_output_dir, mean_components_ms, phase_run_dir,
                                      require_playwright, save_stack_evidence, total_ms,
                                      without_tokens)
from scripts.transport_load import (LATENCY_COMPONENTS, NETWORK_PROFILES,
                                    RESULT_FILE as LOAD_FILE, check_seconds,
                                    checked_settings as checked_load_settings, run_environment,
                                    run_load, save_logs, write_load_results)
from scripts.transport_stack import (BROWSER_CHANNEL, PROXY_MARKER, http_get, load_manifest,
                                     manifest_layers, nginx_size, start_stack)
from scripts.transport_sweep import browser_request_bytes
from scripts.transport_tokens import (EVIDENCE_LIMIT, ISSUE_PATH, LOG_FILES, VERIFY_PATH,
                                      BrowserLog, BrowserRequest, PageTraffic, PairRun,
                                      browser_identity, failed_request_layer, json_object, judge,
                                      lines_mentioning, load_test_page, nonce_url, quote,
                                      read_cookie_jar, read_lines, run_pair, selected_algorithms,
                                      send_fetch, wait_for_proxy_log)


SCHEMA_VERSION = 1
RESULT_FILE = "cookies.json"
# Chromium's kDomainMaxCookies (net/cookies/cookie_monster.h at the pinned release): the most
# cookies it keeps per domain. It is not in transport/stack.json; the cookie-count probe
# measures it.
DOMAIN_MAX_COOKIES = 180
# The single jwt cookie, then the split cookies, in every comparison.
TRANSPORTS = ("cookie", "split")
SPLIT = "split"
# The latency workload's reference configuration, measured in every run, as in S3-01.
REFERENCE = "ES256"
# Production cookie attributes for every size-limit pair and probe, as in S2-04.
COOKIE_ATTRIBUTES = "full"
LIMITS_DIRS = {"default": "limits-default", "raised": "limits-raised"}
LATENCY_DIRS = {"cookie": "latency-cookie", "split": "latency-split"}

# Fixed configurations, whatever the run's --alg selects. The boundary search pads ML-DSA-44's
# split token from pad 0 up to the largest pad whose token is at most BOUNDARY_MAX_TOKEN_BYTES.
BOUNDARY_ALGORITHM = "ML-DSA-44"
BOUNDARY_MAX_TOKEN_BYTES = 16_384
PER_COOKIE_ALGORITHM = "ML-DSA-44"
PER_COOKIE_CHUNKS = 2
COOKIE_COUNT_ALGORITHM = "ES256"
COOKIE_COUNT_CHUNKS = {"at_limit": DOMAIN_MAX_COOKIES, "over_limit": DOMAIN_MAX_COOKIES + 1}
HANDLING_ALGORITHM = "ML-DSA-44"
HANDLING_CHUNKS = 3
PROBE_NAMES = ("at_limit", "over_limit")

# The application's own log line for a request: its status, header count, and header bytes.
APP_HEADER_BYTES = re.compile(r'" \d{3} headers=\d+ header_bytes=(\d+)')
# Direct issues read every chunk's Set-Cookie header, beyond http.client's default of 100.
MAX_RESPONSE_HEADERS = SPLIT_MAX_CHUNKS + 100


# --- Settings ---------------------------------------------------------------------------------


def default_settings() -> dict:
    """run_cookies's keyword defaults, by setting name (the cookies command's defaults too)."""
    parameters = inspect.signature(run_cookies).parameters
    return {name: parameter.default for name, parameter in parameters.items()
            if name not in ("output_dir", "run_dir")}


def checked_settings(algorithms, claims, clients, concurrency, duration, warmup, timeout,
                     header_buffers, proxy_buffers, upstream_keepalive) -> dict:
    """Check run_cookies's settings and return them as cookies.json records them.

    Raises ValueError for any invalid value. Algorithms, claims, clients, concurrency, duration,
    and warm-up are checked as the load command checks them for the split transport, so the
    measured configurations are the selected ones plus the reference ES256, in ADAPTER_LIST
    order. header_buffers and proxy_buffers must be nginx sizes (they raise the limits of the
    raised-limits and latency stacks). Passing the result back as run_cookies(output_dir,
    **settings) repeats the run.
    """
    check_seconds("timeout", timeout, allow_zero=False)  # Finite, unlike check_timeout.
    nginx_size("header_buffers", header_buffers)
    nginx_size("proxy_buffers", proxy_buffers)
    # The two latency runs differ only in their transport, so checking one checks both.
    workload = checked_load_settings(algorithms, SPLIT, clients, concurrency, duration, warmup,
                                     claims, REFERENCE, False, timeout, proxy_buffers,
                                     header_buffers, upstream_keepalive)
    return {"algorithms": workload["algorithms"], "claims": claims,
            "clients": workload["clients"], "concurrency": workload["concurrency"],
            "duration": duration, "warmup": warmup, "timeout": timeout,
            "header_buffers": header_buffers, "proxy_buffers": proxy_buffers,
            "upstream_keepalive": upstream_keepalive}


def read_saved_settings(path: Path) -> dict:
    """Return the settings object of a cookies.json written by an earlier run.

    Raises ValueError when the file cannot be read, has no settings object, or names a setting
    run_cookies does not take. The values are checked by checked_settings once they are combined
    with the command line.
    """
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from None
    settings = saved.get("settings") if isinstance(saved, dict) else None
    if not isinstance(settings, dict):
        raise ValueError(f"{path} has no settings object; give the cookies.json of an earlier "
                         "run")
    unknown = sorted(set(settings) - set(default_settings()))
    if unknown:
        raise ValueError(f"{path} has unknown settings {', '.join(map(repr, unknown))}")
    return settings


# --- Phase 1: chunk plan, calculated ----------------------------------------------------------


def documented_limits() -> dict:
    """The documented limits splitting runs into, from transport/stack.json, in bytes."""
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return {"cookie": layers["browser"]["limits"]["cookie"]["bytes"],
            "line": layers["proxy"]["limits"]["single_header"]["bytes"]}


def largest_name_value(size: int, chunks: int | None = None) -> int:
    """The largest chunk cookie's name + value bytes for a token of `size` characters."""
    sizes = chunk_sizes(size, chunks)
    return max(len(chunk_cookie_name(index, len(sizes))) + value
               for index, value in enumerate(sizes))


def set_cookie_line_bytes(name: str, value_bytes: int) -> int:
    """Bytes of one `Set-Cookie: <name>=<value>; <full attributes>` line, CRLF included."""
    return (len(f"Set-Cookie: {name}=; {COOKIE_ATTRIBUTE_SETS[COOKIE_ATTRIBUTES]}\r\n")
            + value_bytes)


def plan_row(algorithm: str, claims: str, limits: dict) -> dict:
    """One configuration's calculated chunk plan, and which documented limits each carrier fits."""
    size = token_bytes(algorithm, claim_set(claims))
    sizes = chunk_sizes(size)
    names = [chunk_cookie_name(index, len(sizes)) for index in range(len(sizes))]
    name_value = {"cookie": len(COOKIE_NAME) + size, SPLIT: largest_name_value(size)}
    cookie_line = {"cookie": len(f"Cookie: {COOKIE_NAME}=\r\n") + size,
                   SPLIT: chunk_cookie_line_bytes(size)}
    return {
        "algorithm": algorithm,
        "token_bytes": size,
        "chunks": len(sizes),
        "chunk_bytes": sizes,
        "cookie_names": names,
        "name_value_bytes": name_value,
        "set_cookie_bytes": {"cookie": set_cookie_line_bytes(COOKIE_NAME, size),
                             SPLIT: sum(set_cookie_line_bytes(name, value)
                                        for name, value in zip(names, sizes))},
        "cookie_line_bytes": cookie_line,
        "fits": {"cookie": {"per_cookie": name_value["cookie"] <= limits["cookie"],
                            "cookie_line": cookie_line["cookie"] <= limits["line"]},
                 SPLIT: {"per_cookie": name_value[SPLIT] <= limits["cookie"],
                         "cookie_count": len(sizes) <= DOMAIN_MAX_COOKIES,
                         "cookie_line": cookie_line[SPLIT] <= limits["line"]}},
    }


def chunk_plan(algorithms: Sequence[str] | None = None, claims: str = "oidc") -> list[dict]:
    """Return one calculated chunk-plan row per configuration, in ADAPTER_LIST order.

    Each row describes the unpadded token of the claims fixture (token_sizing.token_bytes), split
    at the default count. None means all six. Raises ValueError for an unknown, repeated, or
    empty selection, or an unknown claims name; no reference configuration is added and nothing
    is started.
    """
    selected = selected_algorithms(algorithms)
    claim_set(claims)  # Raises ValueError for an unknown name before any row is computed.
    limits = documented_limits()
    return [plan_row(adapter.name, claims, limits) for adapter in ADAPTER_LIST
            if adapter.name in selected]


# --- Phase 2: limits at the documented defaults, and the boundary -----------------------------


@dataclass
class SplitRun(PairRun):
    """One split pair as observed, before the logs are read (transport "split")."""

    # Filled in from the issue straight from the application, before the browser runs.
    chunks: int = 0
    cookie_names: list = field(default_factory=list)
    # Filled in by send_split_through_browser: how many of cookie_names the jar held.
    cookies_stored: int = 0


@dataclass
class SentPair:
    """One cookie or split pair as sent, with the bytes measured while its stack ran."""

    run: PairRun
    upstream_response_headers: int | None
    name: str | None = None  # A probe's name (at_limit or over_limit).
    pad: int | None = None


@contextmanager
def launched_browser(timeout: float) -> Iterator:
    """Launch headless Chromium for one stack's pairs; Playwright errors become RuntimeError."""
    from playwright.sync_api import Error as PlaywrightError, sync_playwright  # Checked first.

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=timeout * 1000)
            try:
                yield browser
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error


@dataclass
class DirectIssue:
    """An issue response straight from the application, bypassing browser and proxy."""

    url: str
    status: int
    # The status line, every header line, and the final CRLF: what proxy_buffer_size must hold.
    header_bytes: int
    cookies: list[tuple[str, str]]  # Each Set-Cookie header's cookie name and value, in order.
    body: dict | None


def issue_at_application(app_url: str, algorithm: str, delivery: str, issue_query: dict,
                         timeout: float) -> DirectIssue:
    """Send one issue request straight to the application and measure its response headers.

    http.client's default of 100 response headers is raised, so a split into up to
    SPLIT_MAX_CHUNKS cookies can be read. Raises RuntimeError if the request fails.
    """
    url, _ = nonce_url(app_url, ISSUE_PATH, alg=algorithm, delivery=delivery, **issue_query)
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout,
                                            max_response_headers=MAX_RESPONSE_HEADERS)
    try:
        connection.request("GET", f"{parts.path}?{parts.query}")
        response = connection.getresponse()
        headers, data = response.getheaders(), response.read()
    except (OSError, http.client.HTTPException) as error:
        raise RuntimeError(f"application: {url} failed: {error}") from error
    finally:
        connection.close()
    block = (f"HTTP/1.1 {response.status} {response.reason}\r\n"
             + "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n")
    cookies = []
    for name, value in headers:
        if name.lower() == "set-cookie":
            cookie, _, chunk = value.split(";", 1)[0].partition("=")
            cookies.append((cookie, chunk))
    return DirectIssue(url=url, status=response.status, header_bytes=len(block.encode("latin-1")),
                       cookies=cookies, body=json_object(data))


def issue_split_directly(app_url: str, algorithm: str, issue_query: dict,
                         timeout: float) -> DirectIssue:
    """Issue a split token straight from the application; its cookies are the chunks, in order.

    Raises RuntimeError unless the application answers 200 with the chunk cookies its body
    names.
    """
    issue = issue_at_application(app_url, algorithm, SPLIT, issue_query, timeout)
    names = (issue.body or {}).get("cookie_names")
    if issue.status != 200 or not issue.cookies or names != [name for name, _ in issue.cookies]:
        raise RuntimeError(f"application: {issue.url} returned status {issue.status} without "
                           "the chunk cookies its body names")
    return issue


def chunk_cookie_header(chunks: Sequence[tuple[str, str]]) -> str:
    """A Cookie header value with these cookies, in this order."""
    return "; ".join(f"{name}={value}" for name, value in chunks)


def verify_split_directly(app_url: str, chunks: list[tuple[str, str]], timeout: float) -> dict:
    """Send chunk cookies straight to the application's verify endpoint, bypassing the proxy."""
    url, nonce = nonce_url(app_url, VERIFY_PATH)
    try:
        status, _, body = http_get(url, headers={"Cookie": chunk_cookie_header(chunks)},
                                   timeout=timeout)
    except (OSError, http.client.HTTPException):
        status, body = None, None
    reply = json_object(body) or {}
    verified = status == 200 and reply.get("verified") is True and reply.get("source") == SPLIT
    return {"url": url, "nonce": nonce, "status": status, "verified": verified}


def send_split_through_browser(context, stack, run: SplitRun, timeout: float,
                               log: BrowserLog) -> None:
    """Load the test page, fetch() a split issue, read the jar, and fetch() the verify."""
    page = context.new_page()
    page.set_default_timeout(timeout * 1000)
    traffic = PageTraffic(page, log)
    page_url, _ = nonce_url(stack.proxy_url, "/")
    run.page_status, run.page_error = load_test_page(page, page_url, timeout)
    traffic.flush()

    issue_url, issue_nonce = nonce_url(stack.proxy_url, ISSUE_PATH, alg=run.algorithm,
                                       delivery=SPLIT, **run.issue_query)
    run.issue = send_fetch(page, issue_url, issue_nonce, timeout)
    # Playwright joins repeated response headers with "\n", so this holds every Set-Cookie.
    run.issue.set_cookie = traffic.flush().get(issue_url, {}).get("set-cookie")
    stored = {cookie["name"] for cookie in read_cookie_jar(context, log, "after_issue")}
    run.cookies_stored = sum(name in stored for name in run.cookie_names)
    run.cookie_stored = bool(run.cookie_names) and run.cookies_stored == len(run.cookie_names)

    # The browser sends whatever chunk cookies it stored; the run never adds one itself.
    verify_url, verify_nonce = nonce_url(stack.proxy_url, VERIFY_PATH)
    run.verify = send_fetch(page, verify_url, verify_nonce, timeout)
    traffic.flush()
    read_cookie_jar(context, log, "after_verify")


def run_split_pair(browser, stack, algorithm: str, timeout: float, log_path: Path,
                   issue_query: dict) -> SplitRun:
    """Send one configuration's token as chunk cookies through the browser, then directly.

    As run_pair does for a single cookie: the application first issues the same split straight
    from app_url, so the expected chunk cookies are known; a new browser context then issues and
    verifies through nginx; finally those direct chunks are sent straight back to verify.
    """
    issue_query = {key: str(value) for key, value in issue_query.items()}
    chunks = issue_split_directly(stack.app_url, algorithm, issue_query, timeout).cookies
    run = SplitRun(algorithm=algorithm, transport=SPLIT,
                   token_bytes=sum(len(value) for _, value in chunks), issue_query=issue_query,
                   chunks=len(chunks), cookie_names=[name for name, _ in chunks])
    context = browser.new_context()  # A new context per pair, so no cookie carries over.
    try:
        send_split_through_browser(context, stack, run, timeout,
                                   BrowserLog(log_path, algorithm, SPLIT))
    finally:
        context.close()
    run.direct = verify_split_directly(stack.app_url, chunks, timeout)
    return run


def send_pair(browser, stack, algorithm: str, transport: str, issue_query: dict,
              timeout: float) -> SentPair:
    """Send one cookie or split pair, then measure the application's issue response headers.

    The header block is measured from a direct issue at app_url with the same parameters and
    delivery: the bytes nginx's proxy_buffer_size must hold.
    """
    log_path = Path(stack.run_dir) / "logs" / LOG_FILES["browser"]
    if transport == SPLIT:
        run = run_split_pair(browser, stack, algorithm, timeout, log_path, issue_query)
    else:
        run = run_pair(browser, stack, algorithm, transport, timeout, log_path, issue_query)
    issue = issue_at_application(stack.app_url, algorithm, transport, run.issue_query, timeout)
    return SentPair(run=run, upstream_response_headers=issue.header_bytes)


def limit_query(claims: str) -> dict:
    """The issue parameters of every size-limit pair: the run's claims, production attributes."""
    return {"claims": claims, "attrs": COOKIE_ATTRIBUTES}


def send_limit_pairs(browser, stack, settings: dict) -> list[SentPair]:
    """Send every configuration's single-cookie pair, then its split pair."""
    return [send_pair(browser, stack, algorithm, transport, limit_query(settings["claims"]),
                      settings["timeout"])
            for algorithm in settings["algorithms"] for transport in TRANSPORTS]


def split_problems(run: SplitRun, issue_lines: dict, verify_lines: dict) -> list[str]:
    """List every reason a split pair does not count as verified; empty means it verified."""
    problems = []
    if run.page_status != 200:
        problems.append(f"the test page returned {run.page_status or run.page_error}")
    if run.issue.status != 200:
        problems.append(f"the issue request got status {run.issue.status}")
    if not run.cookie_stored:
        problems.append(f"the browser stored {run.cookies_stored} of the "
                        f"{len(run.cookie_names)} chunk cookies")
    body = run.verify.body or {}
    sent = ((body.get("received") or {}).get("cookie_bytes"),
            chunk_cookie_line_bytes(run.token_bytes, run.chunks) - len("Cookie: \r\n"))
    if run.verify.status != 200:
        problems.append(f"the verify request got status {run.verify.status}")
    elif PROXY_MARKER.lower() not in run.verify.headers:
        problems.append(f"the verify response has no {PROXY_MARKER} header")
    elif (body.get("verified") is not True or body.get("algorithm") != run.algorithm
          or body.get("source") != SPLIT or body.get("token_bytes") != run.token_bytes):
        problems.append(f"the verify body does not confirm the {run.algorithm} split token")
    elif sent[0] != sent[1]:
        problems.append(f"the application received a {sent[0]}-byte Cookie header, expected "
                        f"{sent[1]} bytes of chunk cookies")
    for step, lines in (("issue", issue_lines), ("verify", verify_lines)):
        missing = [LOG_FILES[key] for key in ("browser", "proxy_access", "app") if not lines[key]]
        if missing:
            problems.append(f"the {step} nonce is missing from {', '.join(missing)}")
    return problems


def split_rejecting_layer(run: SplitRun, issue_lines: dict,
                          verify_lines: dict) -> tuple[str | None, str]:
    """Walk issue, cookie jar, and verify in order; blame the first layer that failed."""
    if run.issue.status != 200 or not issue_lines["proxy_access"]:
        return failed_request_layer("issue", run.issue, issue_lines)
    if not run.cookie_stored:
        headers = len(run.issue.set_cookie.split("\n")) if run.issue.set_cookie else 0
        return "browser", (f"browser: the issue response reached the browser (proxy-access.log: "
                           f"{quote(issue_lines['proxy_access'][0])}) with {headers} Set-Cookie "
                           f"header(s) (browser.log) for {len(run.cookie_names)} chunk cookies "
                           "whose largest name + value is "
                           f"{largest_name_value(run.token_bytes, run.chunks):,} bytes, but "
                           f"BrowserContext.cookies() lists only {run.cookies_stored} of them "
                           "afterwards")
    if run.verify.status != 200 or not verify_lines["proxy_access"]:
        return failed_request_layer("verify", run.verify, verify_lines)
    # Every request got through, yet split_problems found something wrong: name the layer whose
    # answer or log is wrong, so that every rejected pair names a layer (R18).
    body = run.verify.body or {}
    if PROXY_MARKER.lower() not in run.verify.headers:
        return "proxy", f"proxy: the verify response has no {PROXY_MARKER} header"
    if (body.get("verified") is not True or body.get("algorithm") != run.algorithm
            or body.get("source") != SPLIT or body.get("token_bytes") != run.token_bytes):
        return "application", ("application: it answered 200 to the verify request, but its body "
                               f"does not confirm the {run.algorithm} split token (verified "
                               f"{body.get('verified')!r}, source {body.get('source')!r}, "
                               f"token_bytes {body.get('token_bytes')!r})")
    for step, lines in (("issue", issue_lines), ("verify", verify_lines)):
        for key, layer in (("browser", "browser"), ("app", "application")):
            if not lines[key]:
                return layer, f"{layer}: the {step} nonce is missing from {LOG_FILES[key]}"
    problems = split_problems(run, issue_lines, verify_lines)
    return "browser", f"browser: {problems[0] if problems else 'the pair did not verify'}"


def judge_split(run: SplitRun, logs: dict[str, list[str]]) -> dict:
    """Combine one split pair's observations with every layer's log into its outcome."""
    issue_lines = lines_mentioning(run.issue.nonce, logs)
    verify_lines = lines_mentioning(run.verify.nonce, logs)
    problems = split_problems(run, issue_lines, verify_lines)
    if not problems:
        outcome, rejected_by = "verified", None
        evidence = (f"verified: the browser sent the {run.token_bytes:,}-byte token as "
                    f"{run.chunks} jwt.<index>.{run.chunks} chunk cookies through nginx, and the "
                    "application reassembled and verified it; both nonces are in browser.log, "
                    "proxy-access.log, and app.log")
    else:
        outcome = "rejected"
        rejected_by, evidence = split_rejecting_layer(run, issue_lines, verify_lines)
        if rejected_by is None:  # A request was not sent, or no layer's log explains it.
            evidence = f"no rejecting layer identified: {evidence or problems[0]}"
    return {"outcome": outcome, "rejected_by": rejected_by, "evidence": evidence[:EVIDENCE_LIMIT]}


def app_header_bytes(lines: list[str]) -> int | None:
    """header_bytes from the application's own log line for a request, or None."""
    for line in lines:
        match = APP_HEADER_BYTES.search(line)
        if match:
            return int(match[1])
    return None


def chunk_order(run: PairRun) -> list[int] | None:
    """The chunk indices in the order the application received them (its chunks.received)."""
    received = ((run.verify.body or {}).get("chunks") or {}).get("received")
    if run.transport != SPLIT or not isinstance(received, list):
        return None
    return received if all(type(index) is int for index in received) else None


def pair_bytes(pair: SentPair, logs: dict[str, list[str]], browser_log: Path) -> dict:
    """The bytes each limit counts for one pair: calculated, measured directly, and as logged."""
    run = pair.run
    if run.transport == SPLIT:
        largest = largest_name_value(run.token_bytes, run.chunks)
        line = chunk_cookie_line_bytes(run.token_bytes, run.chunks)
    else:
        largest = len(COOKIE_NAME) + run.token_bytes
        line = len(f"Cookie: {COOKIE_NAME}=\r\n") + run.token_bytes
    return {"largest_name_value": largest, "cookie_line": line,
            "upstream_response_headers": pair.upstream_response_headers,
            "browser_request_headers": (browser_request_bytes(browser_log, run.verify.url)
                                        if run.verify.sent else None),
            "app_received_headers": app_header_bytes(lines_mentioning(run.verify.nonce,
                                                                      logs)["app"])}


def pair_result(pair: SentPair, logs: dict[str, list[str]], layers: dict,
                browser_log: Path) -> dict:
    """One pair's entry in cookies.json, judged from every layer's log, with tokens removed."""
    run = pair.run
    split = run.transport == SPLIT
    judged = judge_split(run, logs) if split else judge(run, logs, layers)
    entry = {
        "algorithm": run.algorithm,
        "transport": run.transport,
        "token_bytes": run.token_bytes,
        "chunks": run.chunks if split else None,
        "outcome": judged["outcome"],
        "rejected_by": judged["rejected_by"],
        "verified_directly": run.direct["verified"],
        "cookies_expected": len(run.cookie_names) if split else 1,
        "cookies_stored": run.cookies_stored if split else int(run.cookie_stored),
        "chunk_order": chunk_order(run),
        "issue_status": run.issue.status,
        "verify_status": run.verify.status,
        "bytes": pair_bytes(pair, logs, browser_log),
        "issue_nonce": run.issue.nonce,
        "verify_nonce": run.verify.nonce,
        "evidence": without_tokens(judged["evidence"]),
    }
    if pair.name is not None:
        entry = {"name": pair.name, "pad": pair.pad, **entry}
    return entry


def judge_pairs(stack, pairs: list[SentPair], layers: dict) -> list[dict]:
    """Judge pairs from every layer's log, once nginx has logged every answered request."""
    log_dir = Path(stack.run_dir) / "logs"
    answered = [request.nonce for pair in pairs for request in (pair.run.issue, pair.run.verify)
                if request.status is not None]
    wait_for_proxy_log(log_dir / LOG_FILES["proxy_access"], answered)
    logs = {key: read_lines(log_dir / name) for key, name in LOG_FILES.items()}
    return [pair_result(pair, logs, layers, log_dir / LOG_FILES["browser"]) for pair in pairs]


def moved_entries(results: list[dict]) -> list[dict]:
    """One entry per configuration: its single-cookie and split outcomes, and if they differ."""
    outcomes = {(entry["algorithm"], entry["transport"]): entry["outcome"] for entry in results}
    entries = []
    for algorithm in dict.fromkeys(entry["algorithm"] for entry in results):
        cookie, split = (outcomes[(algorithm, transport)] for transport in TRANSPORTS)
        entries.append({"algorithm": algorithm, "cookie": cookie, "split": split,
                        "moved": cookie != split})
    return entries


def limits_entry(stack_name: str, settings: dict, results: list[dict], raised: bool) -> dict:
    """cookies.json's entry for one size-limits stack."""
    return {"stack": stack_name,
            "header_buffers": settings["header_buffers"] if raised else None,
            "proxy_buffers": settings["proxy_buffers"] if raised else None,
            "results": results, "moved": moved_entries(results)}


BOUNDARY_PROBE_KEYS = ("pad", "token_bytes", "chunks", "outcome", "rejected_by", "cookies_stored",
                       "verify_status", "bytes", "issue_nonce", "verify_nonce", "evidence")


def search_boundary(browser, stack, settings: dict, layers: dict) -> dict:
    """Find the largest split ML-DSA-44 token that gets through this stack.

    Probes pad 0 and the largest pad whose token is at most BOUNDARY_MAX_TOKEN_BYTES, then
    bisects the padding to one character, assuming the outcome changes once. Each probe is a
    split pair at the default count with production attributes, judged before the next is sent.
    """
    claims = settings["claims"]
    high_pad = pad_for_target(BOUNDARY_ALGORITHM, claim_set(claims), BOUNDARY_MAX_TOKEN_BYTES)
    if high_pad is None:
        raise RuntimeError(f"{BOUNDARY_ALGORITHM}'s {claims} token is larger than "
                           f"{BOUNDARY_MAX_TOKEN_BYTES:,} bytes without padding")
    probes = {}

    def probe(pad: int) -> str:
        query = {**limit_query(claims), "pad": pad}
        sent = send_pair(browser, stack, BOUNDARY_ALGORITHM, SPLIT, query, settings["timeout"])
        [result] = judge_pairs(stack, [sent], layers)
        probes[pad] = {key: pad if key == "pad" else result[key] for key in BOUNDARY_PROBE_KEYS}
        return result["outcome"]

    low, high = 0, high_pad
    low_outcome = probe(low)
    if high != low and probe(high) != low_outcome:
        while high - low > 1:
            middle = (low + high) // 2
            if probe(middle) == low_outcome:
                low = middle
            else:
                high = middle
    ordered = [probes[pad] for pad in sorted(probes)]
    verified = [entry for entry in ordered if entry["outcome"] == "verified"]
    largest = verified[-1] if verified else None
    first_rejected = next((entry for entry in ordered if entry["outcome"] != "verified"
                           and (largest is None or entry["pad"] > largest["pad"])), None)
    return {"algorithm": BOUNDARY_ALGORITHM, "claims": claims, "stack": LIMITS_DIRS["default"],
            "low_pad": 0, "high_pad": high_pad, "largest_verified": largest,
            "first_rejected": first_rejected, "probes": ordered}


def run_default_limits(output_dir: Path, settings: dict, layers: dict,
                       run_dir: Path | None) -> tuple[dict, dict, dict, dict]:
    """Phase 2: every pair, then the boundary search, on a stack at the documented defaults.

    Returns cookies.json's limits entry for the stack, the boundary, the browser's identity, and
    the saved evidence.
    """
    with start_stack(run_dir=run_dir, timeout=settings["timeout"]) as stack:  # No raised limit.
        with launched_browser(settings["timeout"]) as browser:
            identity = browser_identity(browser)
            pairs = send_limit_pairs(browser, stack, settings)
            boundary = search_boundary(browser, stack, settings, layers)
        results = judge_pairs(stack, pairs, layers)
        evidence = save_stack_evidence(stack.run_dir, output_dir / LIMITS_DIRS["default"])
    return (limits_entry(LIMITS_DIRS["default"], settings, results, raised=False), boundary,
            identity, evidence)


# --- Phase 3: raised limits, per-cookie and cookie-count probes -------------------------------


def per_cookie_pads(claims: str, cookie_limit: int) -> dict[str, int]:
    """The per-cookie probes' pads, calculated with token_sizing: at and just over the limit.

    at_limit is the largest pad whose larger chunk (of PER_COOKIE_CHUNKS) has a name + value of
    at most cookie_limit bytes; over_limit is one more character, so its larger chunk exceeds it.
    """
    fixture = claim_set(claims)
    target = next(size for size in range(PER_COOKIE_CHUNKS * cookie_limit,
                                         PER_COOKIE_CHUNKS - 1, -1)
                  if largest_name_value(size, PER_COOKIE_CHUNKS) <= cookie_limit)
    pad = pad_for_target(PER_COOKIE_ALGORITHM, fixture, target)

    def larger_chunk(pad: int) -> int:
        size = token_bytes(PER_COOKIE_ALGORITHM, padded_claims(fixture, pad))
        return largest_name_value(size, PER_COOKIE_CHUNKS)

    if pad is None or larger_chunk(pad) > cookie_limit or larger_chunk(pad + 1) <= cookie_limit:
        raise RuntimeError(f"no {PER_COOKIE_ALGORITHM} {claims} token puts a chunk at Chromium's "
                           f"{cookie_limit:,}-byte cookie limit")
    return {"at_limit": pad, "over_limit": pad + 1}


def send_probes(browser, stack, settings: dict, cookie_limit: int) -> dict[str, list[SentPair]]:
    """Send the per-cookie probes, then the cookie-count probes, all split with full attributes."""
    claims, timeout = settings["claims"], settings["timeout"]
    sent = {"per_cookie": [], "cookie_count": []}
    for name, pad in per_cookie_pads(claims, cookie_limit).items():
        query = {**limit_query(claims), "pad": pad, "chunks": PER_COOKIE_CHUNKS}
        pair = send_pair(browser, stack, PER_COOKIE_ALGORITHM, SPLIT, query, timeout)
        pair.name, pair.pad = name, pad
        sent["per_cookie"].append(pair)
    for name in PROBE_NAMES:
        query = {**limit_query(claims), "pad": 0, "chunks": COOKIE_COUNT_CHUNKS[name]}
        pair = send_pair(browser, stack, COOKIE_COUNT_ALGORITHM, SPLIT, query, timeout)
        pair.name, pair.pad = name, 0
        sent["cookie_count"].append(pair)
    return sent


def run_raised_limits(output_dir: Path, settings: dict, layers: dict,
                      run_dir: Path | None) -> tuple[dict, dict, dict, dict]:
    """Phases 3 and 4 on one stack with nginx's header and proxy buffers raised.

    Returns cookies.json's limits entry for the stack, the probes, the chunk handling, and the
    saved evidence.
    """
    cookie_limit = layers["browser"]["limits"]["cookie"]["bytes"]
    with start_stack(run_dir=run_dir, timeout=settings["timeout"],
                     header_buffers=settings["header_buffers"],
                     proxy_buffers=settings["proxy_buffers"]) as stack:
        with launched_browser(settings["timeout"]) as browser:
            pairs = send_limit_pairs(browser, stack, settings)
            probes = send_probes(browser, stack, settings, cookie_limit)
        handling = run_handling(stack, settings)
        results = judge_pairs(stack, pairs, layers)
        probe_results = {group: judge_pairs(stack, sent, layers) for group, sent in probes.items()}
        evidence = save_stack_evidence(stack.run_dir, output_dir / LIMITS_DIRS["raised"])
    return (limits_entry(LIMITS_DIRS["raised"], settings, results, raised=True),
            {"stack": LIMITS_DIRS["raised"], **probe_results}, handling, evidence)


# --- Phase 4: chunk handling ------------------------------------------------------------------


def handling_cases(token: list[tuple[str, str]], other: list[tuple[str, str]],
                   two_chunk: tuple[str, str], whole: str) -> list[tuple[str, list, bool]]:
    """The 13 chunk-handling cases, in order: (name, cookies to send, whether to add Bearer).

    token and other are tokens A and B split in three; two_chunk is the first chunk of A split
    in two (another count), and whole is A itself.
    """
    a0, a1, a2 = token
    return [
        ("in_order", [a0, a1, a2], False),
        ("reversed", [a2, a1, a0], False),
        ("rotated", [a1, a2, a0], False),
        ("among_other_cookies", [("a", "1"), a2, ("jwt_old", "x"), a0, ("theme", "dark"), a1],
         False),
        ("missing_0", [a1, a2], False),
        ("missing_1", [a0, a2], False),
        ("missing_2", [a0, a1], False),
        ("duplicate", [a0, a1, a1, a2], False),
        ("conflicting_count", [a0, a1, a2, two_chunk], False),
        ("out_of_range_index", [a0, a1, a2, (chunk_cookie_name(3, 3), "x")], False),
        ("mixed_tokens", [a0, other[1], a2], False),
        ("with_jwt_cookie", [a0, a1, a2, (COOKIE_NAME, whole)], False),
        ("with_bearer", [a0, a1, a2], True),
    ]


def send_case(stack, name: str, cookies: list[tuple[str, str]], bearer: str | None,
              timeout: float) -> dict:
    """Send one chunk-handling case through nginx with http.client; record names, never values."""
    url, nonce = nonce_url(stack.proxy_url, VERIFY_PATH, timing="1")
    headers = {"Cookie": chunk_cookie_header(cookies)}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        status, response_headers, data = http_get(url, headers=headers, timeout=timeout)
        reply = BrowserRequest(url=url, nonce=nonce, status=status, headers=response_headers,
                               body=json_object(data))
    except (OSError, http.client.HTTPException) as error:
        reply = BrowserRequest(url=url, nonce=nonce, error=f"{type(error).__name__}: {error}")
    body = reply.body or {}
    chunks = body.get("chunks")
    error = body.get("error")
    return {
        "name": name,
        "cookies": [cookie for cookie, _ in cookies],
        "bearer": bearer is not None,
        "status": reply.status,
        "verified": (reply.status == 200 and PROXY_MARKER.lower() in reply.headers
                     and body.get("verified") is True and body.get("source") == SPLIT),
        "source": body.get("source"),
        "error": without_tokens(error) if isinstance(error, str) else None,
        "verify_called": (body.get("timing") or {}).get("verify_ns") is not None,
        "chunks": chunks if isinstance(chunks, dict) else None,
        "nonce": nonce,
    }


def run_handling(stack, settings: dict) -> dict:
    """Phase 4: send every chunk-handling case through the raised stack's nginx.

    Tokens A (the run's claims) and B (one character of padding more) are issued straight from
    the application split in three, and their chunks are read from the Set-Cookie headers.
    """
    claims, timeout = settings["claims"], settings["timeout"]
    query = {"claims": claims, "chunks": str(HANDLING_CHUNKS)}
    token = issue_split_directly(stack.app_url, HANDLING_ALGORITHM, query, timeout).cookies
    other = issue_split_directly(stack.app_url, HANDLING_ALGORITHM, {**query, "pad": "1"},
                                 timeout).cookies
    if len(token) != HANDLING_CHUNKS or len(other) != HANDLING_CHUNKS:
        raise RuntimeError(f"application: a {HANDLING_ALGORITHM} split did not have "
                           f"{HANDLING_CHUNKS} chunks")
    whole = "".join(value for _, value in token)
    cases = [send_case(stack, name, cookies, whole if bearer else None, timeout)
             for name, cookies, bearer in handling_cases(token, other, split_token(whole, 2)[0],
                                                         whole)]
    return {"algorithm": HANDLING_ALGORITHM, "claims": claims, "token_bytes": len(whole),
            "chunks": HANDLING_CHUNKS, "stack": LIMITS_DIRS["raised"], "cases": cases}


# --- Phase 5: latency, the S3-01 workload -----------------------------------------------------


def run_latency(output_dir: Path, settings: dict, transport: str, run_dir: Path | None) -> dict:
    """Run the S3-01 workload with one transport on a new stack; return its load.json.

    The results are saved exactly as `load --output-dir` saves them, so `load --settings
    <dir>/load.json` repeats the run. The stack is stopped before this returns.
    """
    target = output_dir / LATENCY_DIRS[transport]
    with start_stack(run_dir=run_dir, timeout=settings["timeout"],
                     proxy_buffers=settings["proxy_buffers"],
                     header_buffers=settings["header_buffers"],
                     upstream_keepalive=settings["upstream_keepalive"]) as stack:
        result = run_load(stack, algorithms=settings["algorithms"], transport=transport,
                          clients=settings["clients"], concurrency=settings["concurrency"],
                          duration=settings["duration"], warmup=settings["warmup"],
                          claims=settings["claims"], reference=REFERENCE, size_controls=False,
                          timeout=settings["timeout"], proxy_buffers=settings["proxy_buffers"],
                          header_buffers=settings["header_buffers"],
                          upstream_keepalive=settings["upstream_keepalive"])
        write_load_results(result, target)
    return json.loads((target / LOAD_FILE).read_text(encoding="utf-8"))


def by_transport(cookie, split) -> dict:
    """One value from the single-cookie run and one from the split run, keyed by transport."""
    return {"cookie": cookie, SPLIT: split}


def latency_row(cookie_cell: dict, split_cell: dict) -> dict:
    """Compare one configuration's token cell across the two runs (split minus cookie)."""
    def paired(key: str) -> dict:
        return by_transport(cookie_cell[key], split_cell[key])

    means = by_transport(mean_components_ms(cookie_cell), mean_components_ms(split_cell))
    difference = None
    if means["cookie"] is not None and means[SPLIT] is not None:
        difference = {component: means[SPLIT][component] - means["cookie"][component]
                      for component in LATENCY_COMPONENTS}
    return {"client": cookie_cell["client"], "concurrency": cookie_cell["concurrency"],
            "algorithm": cookie_cell["algorithm"], "token_bytes": cookie_cell["token_bytes"],
            "chunks": default_chunk_count(cookie_cell["token_bytes"]),
            "delivered": by_transport(cookie_cell["issue"]["delivered"],
                                      split_cell["issue"]["delivered"]),
            "verified": paired("verified"), "failed": paired("failed"),
            "throughput_rps": paired("throughput_rps"),
            "median_ms": by_transport(total_ms(cookie_cell, "median_ms"),
                                      total_ms(split_cell, "median_ms")),
            "p95_ms": by_transport(total_ms(cookie_cell, "p95_ms"), total_ms(split_cell, "p95_ms")),
            "mean_ms": means, "difference_ms": difference}


def network_extra(cookie_run: dict, split_run: dict) -> list[dict]:
    """Per configuration, both runs' request bytes and the modeled extra upload time of split.

    The upload times come from each load.json's network model, so they are calculated, not
    measured.
    """
    split_rows = {row["algorithm"]: row for row in split_run["network_model"]["rows"]}
    entries = []
    for cookie_row in cookie_run["network_model"]["rows"]:
        split_row = split_rows[cookie_row["algorithm"]]
        cookie_ms, split_ms = ({(item["uplink_mbps"], item["rtt_ms"]): item["transfer_ms"]
                                for item in row["modeled"]} for row in (cookie_row, split_row))
        modeled = []
        for profile in NETWORK_PROFILES:
            key = (profile["uplink_mbps"], profile["rtt_ms"])
            modeled.append({**profile, "extra_ms": split_ms[key] - cookie_ms[key]})
        entries.append({"algorithm": cookie_row["algorithm"],
                        "request_bytes": by_transport(cookie_row["request_bytes"],
                                                      split_row["request_bytes"]),
                        "extra_bytes": split_row["request_bytes"] - cookie_row["request_bytes"],
                        "modeled": modeled})
    return entries


def compare_latency(cookie_run: dict, split_run: dict) -> dict:
    """Compare the single-cookie and split load.json results cell by cell."""
    split_cells = {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
                   for cell in split_run["results"] if cell["variant"] == "token"}
    rows = [latency_row(cell, split_cells[(cell["client"], cell["concurrency"],
                                           cell["algorithm"])])
            for cell in cookie_run["results"] if cell["variant"] == "token"]
    return {"transports": list(TRANSPORTS), "reference": REFERENCE, "size_controls": False,
            "runs": {transport: f"{LATENCY_DIRS[transport]}/{LOAD_FILE}"
                     for transport in TRANSPORTS},
            "rows": rows, "network_model": network_extra(cookie_run, split_run)}


def latency_evidence(transport: str, load: dict) -> dict:
    """Every file one latency run saved, relative to the cookies run's output directory."""
    directory = LATENCY_DIRS[transport]
    saved = load["evidence"]
    return {"load": f"{directory}/{LOAD_FILE}", "raw": f"{directory}/{saved['raw']}",
            "logs": {name: f"{directory}/{path}" for name, path in saved["logs"].items()},
            "nginx_conf": f"{directory}/{saved['nginx_conf']}"}


# --- The run ----------------------------------------------------------------------------------


def chunk_format() -> dict:
    """cookies.json's format: the chunk names, sizes, and attributes, and Chromium's count limit."""
    return {"cookie_name": f"{COOKIE_NAME}.<index>.<count>", "chunk_bytes": SPLIT_CHUNK_BYTES,
            "max_chunks": SPLIT_MAX_CHUNKS, "domain_max_cookies": DOMAIN_MAX_COOKIES,
            "cookie_attributes": COOKIE_ATTRIBUTE_SETS[COOKIE_ATTRIBUTES]}


def run_cookies(output_dir, algorithms: Sequence[str] | None = None, claims: str = "oidc",
                clients: Sequence[str] | None = None, concurrency: Sequence[int] = (1, 4),
                duration: float = 5.0, warmup: float = 1.0, timeout: float = 60.0,
                header_buffers: str = "32k", proxy_buffers: str = "32k",
                upstream_keepalive: int | None = None, run_dir=None) -> dict:
    """Run all five phases into output_dir, write cookies.json last, and return what it holds.

    algorithms, claims, clients, concurrency, duration, and warmup mean what they mean for
    run_load; the boundary search, the probes, and the chunk handling use their fixed
    configurations whatever algorithms selects. header_buffers and proxy_buffers raise nginx's
    limits on the raised-limits stack and both latency stacks, and upstream_keepalive applies to
    the latency stacks only; the default-limits stack keeps every documented default. run_dir,
    if given, holds the four stacks' run directories (limits-default, limits-raised,
    latency-cookie, and latency-split). Raises ValueError for any invalid argument, or an
    output_dir that exists and is not empty, before any process starts or output_dir is
    created, and RuntimeError when a layer or Playwright fails. Every started process is stopped
    before this returns or raises.
    """
    settings = checked_settings(algorithms, claims, clients, concurrency, duration, warmup,
                                timeout, header_buffers, proxy_buffers, upstream_keepalive)
    output_dir = check_output_dir(output_dir)
    require_playwright()

    started = datetime.now(timezone.utc)
    environment = run_environment()  # Includes the git commit the run starts from.
    plan = chunk_plan(settings["algorithms"], settings["claims"])
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    output_dir.mkdir(parents=True, exist_ok=True)
    default, boundary, browser, default_evidence = run_default_limits(
        output_dir, settings, layers, phase_run_dir(run_dir, LIMITS_DIRS["default"]))
    raised, probes, handling, raised_evidence = run_raised_limits(
        output_dir, settings, layers, phase_run_dir(run_dir, LIMITS_DIRS["raised"]))
    latency_runs = {transport: run_latency(output_dir, settings, transport,
                                           phase_run_dir(run_dir, LATENCY_DIRS[transport]))
                    for transport in TRANSPORTS}
    finished = datetime.now(timezone.utc)

    result = {
        "schema_version": SCHEMA_VERSION,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "environment": environment,
        "layers": manifest_layers(load_manifest()),
        "browser": browser,
        "experiment_keys": True,
        "format": chunk_format(),
        "plan": plan,
        "limits": {"default": default, "raised": raised},
        "boundary": boundary,
        "probes": probes,
        "handling": handling,
        "latency": compare_latency(latency_runs["cookie"], latency_runs[SPLIT]),
        "evidence": {"limits": {"default": default_evidence, "raised": raised_evidence},
                     "latency": {transport: latency_evidence(transport, latency_runs[transport])
                                 for transport in TRANSPORTS}},
    }
    write_cookies_results(result, output_dir)
    return result


# --- Output -----------------------------------------------------------------------------------


def write_cookies_results(result: dict, output_dir: Path) -> Path:
    """Save the result as cookies.json in output_dir and return its path."""
    path = Path(output_dir) / RESULT_FILE
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path


def describe_fits(fits: dict) -> str:
    """'fits', or 'over' and the documented limits a carrier exceeds."""
    over = [name.replace("_", "-") for name, fit in fits.items() if not fit]
    return "fits" if not over else f"over {'+'.join(over)}"


def observed(entry: dict) -> str:
    """A pair's outcome, with the rejecting layer when it was rejected."""
    if entry["outcome"] == "verified":
        return "verified"
    return f"rejected by {entry['rejected_by'] or 'no identified layer'}"


def plan_lines(result: dict, width: int) -> list[str]:
    """One line per configuration: its chunks, and each carrier's bytes and fit (calculated)."""
    lines = []
    for row in result["plan"]:
        name_value, line = row["name_value_bytes"], row["cookie_line_bytes"]
        set_cookie, fits = row["set_cookie_bytes"], row["fits"]
        lines.append(f"plan     {row['algorithm']:<{width}}  {row['token_bytes']:>6,} B  "
                     f"{row['chunks']:>2} chunks  name+value {name_value['cookie']:>6,} -> "
                     f"{name_value[SPLIT]:>5,} B  Cookie line {line['cookie']:>6,} -> "
                     f"{line[SPLIT]:>6,} B  Set-Cookie {set_cookie['cookie']:>6,} -> "
                     f"{set_cookie[SPLIT]:>6,} B  cookie {describe_fits(fits['cookie'])}, "
                     f"split {describe_fits(fits[SPLIT])}")
    return lines


def limits_lines(result: dict, width: int) -> list[str]:
    """One line per stack and configuration: the measured single-cookie and split outcomes."""
    lines = []
    for key in ("default", "raised"):
        entry = result["limits"][key]
        pairs = {(item["algorithm"], item["transport"]): item for item in entry["results"]}
        for moved in entry["moved"]:
            cookie, split = (pairs[(moved["algorithm"], transport)] for transport in TRANSPORTS)
            line = (f"limits   {entry['stack']:<14}  {moved['algorithm']:<{width}}  "
                    f"{cookie['token_bytes']:>6,} B  cookie {observed(cookie):<23}  "
                    f"split x{split['chunks']:<2} {observed(split):<23}  "
                    f"stored {split['cookies_stored']}/{split['cookies_expected']}")
            lines.append(line + ("  moved" if moved["moved"] else ""))
    return lines


def boundary_lines(result: dict) -> list[str]:
    """The boundary search in one line: the largest verified and the first rejected probe."""
    boundary = result["boundary"]

    def probe(entry: dict | None) -> str:
        if entry is None:
            return "none"
        return f"{entry['token_bytes']:,} B (pad {entry['pad']:,}, {entry['chunks']} chunks)"

    rejected = boundary["first_rejected"]
    layer = f" {observed(rejected)}" if rejected is not None else ""
    return [f"boundary {boundary['algorithm']}  {boundary['stack']}  split, {boundary['claims']} "
            f"claims  largest verified {probe(boundary['largest_verified'])}  first rejected "
            f"{probe(rejected)}{layer}  {len(boundary['probes'])} probes"]


def probe_lines(result: dict) -> list[str]:
    """One line per probe: its token, its largest chunk, what the jar held, and the outcome."""
    lines = []
    for group in ("per_cookie", "cookie_count"):
        for entry in result["probes"][group]:
            lines.append(f"probe    {group:<12}  {entry['name']:<10}  {entry['algorithm']:<9}  "
                         f"pad {entry['pad']:>5,}  {entry['token_bytes']:>6,} B  "
                         f"{entry['chunks']:>3} chunks  largest name+value "
                         f"{entry['bytes']['largest_name_value']:>5,} B  stored "
                         f"{entry['cookies_stored']}/{entry['cookies_expected']}  "
                         f"{observed(entry)}")
    return lines


def handling_lines(result: dict) -> list[str]:
    """One line per chunk-handling case: its status and what the application did."""
    lines = []
    for case in result["handling"]["cases"]:
        chunks = case["chunks"] or {}
        missing = chunks.get("missing")
        line = (f"handling {case['name']:<20}  status {case['status'] or '-'}  "
                f"{'verified' if case['verified'] else 'not verified':<12}  "
                f"source {case['source'] or '-':<5}  "
                f"verify_token {'called' if case['verify_called'] else 'not called'}")
        if chunks.get("received") is not None:
            line += f"  received {chunks['received']}"
        if missing:
            line += f"  missing {missing}"
        lines.append(line)
    return lines


def unverified(row: dict, transport: str) -> str:
    """Why one side of a latency row has no verified request."""
    return "none verified" if row["delivered"][transport] else "not delivered"


def latency_lines(result: dict, width: int) -> list[str]:
    """One line per latency row: cookie -> split mean, median, p95, and throughput."""
    lines = []
    for row in result["latency"]["rows"]:
        label = (f"latency  {row['client']:<7} c={row['concurrency']:<3} "
                 f"{row['algorithm']:<{width}}  {row['token_bytes']:>6,} B x{row['chunks']}")
        difference = row["difference_ms"]
        if difference is None:
            reasons = [f"{transport} {unverified(row, transport)}" for transport in TRANSPORTS
                       if row["mean_ms"][transport] is None]
            lines.append(f"{label}  no verified request: {', '.join(reasons)}")
            continue
        means, medians, p95s = row["mean_ms"], row["median_ms"], row["p95_ms"]
        throughput = row["throughput_rps"]
        line = (f"{label}  mean {means['cookie']['total']:.3f} -> {means[SPLIT]['total']:.3f} ms "
                f"({difference['total']:+.3f})  median {medians['cookie']:.3f} -> "
                f"{medians[SPLIT]:.3f}  p95 {p95s['cookie']:.3f} -> {p95s[SPLIT]:.3f}  "
                f"{throughput['cookie']:,.1f} -> {throughput[SPLIT]:,.1f} req/s")
        failed = row["failed"]["cookie"] + row["failed"][SPLIT]
        if failed:
            line += f"  {failed:,} failed"
        lines.append(line)
    return lines


def summary_lines(result: dict) -> list[str]:
    """The cookies command's printed summary, from a cookies.json object alone.

    In order: plan, limits (default, then raised), boundary, probe, handling, and latency
    lines; each starts with its phase word and names its configuration or case.
    """
    width = max(len(row["algorithm"]) for row in result["plan"])
    return [*plan_lines(result, width), *limits_lines(result, width), *boundary_lines(result),
            *probe_lines(result), *handling_lines(result), *latency_lines(result, width)]
