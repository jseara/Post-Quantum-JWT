"""Send each configuration's fixture token through the stack as a cookie and as a Bearer header.

For each configuration and transport, the check first gets a token straight from the
application. In a new browser context it then loads the test page through nginx, has the page
fetch() a token from /api/token/issue (as a Set-Cookie for the cookie transport, in the JSON
body for Bearer), and fetch() /api/token/verify with that cookie or header. What the browser sent,
received, and stored goes to <run_dir>/logs/browser.log. Each request's nonce is then looked up in
every layer's log to name the layer that rejected a pair that did not verify, and the same token
is sent straight to the application to show that it verifies there. Each pair's expected outcome
comes from the documented default limits in transport/stack.json; it is reported next to the
observed outcome and never used to skip a request. Use run_token_check from scripts.transport_stack.

With a TLS stack (start_tls_stack, S3-04), every browser context accepts the stack's self-signed
certificate, and each request also records the proxy-error.log lines nginx appended while it
was in flight, so a request that nginx rejected over HTTP/2 without an access-log line is still
attributed to the proxy. Plain stacks are judged exactly as before.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
import http.client
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlencode

from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.transport_app import COOKIE_NAME
from scripts.transport_stack import (BROWSER_CHANNEL, PROXY_MARKER, browser_context_options,
                                     check_timeout, http_get, is_tls_stack, load_manifest,
                                     manifest_layers)


TRANSPORTS = ("cookie", "bearer")
ISSUE_PATH = "/api/token/issue"
VERIFY_PATH = "/api/token/verify"
# Keys of the result's `logs` objects, mapped to the file names under <run_dir>/logs.
LOG_FILES = {"browser": "browser.log", "proxy_access": "proxy-access.log",
             "proxy_error": "proxy-error.log", "app": "app.log"}
# nginx writes an access log line only once the response is finished, so allow it a moment.
LOG_GRACE_SECONDS = 5.0
EVIDENCE_LIMIT = 1000
QUOTE_LIMIT = 280  # Three quoted log lines and their text stay within EVIDENCE_LIMIT.
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")  # Base64url runs: the token parts of a line.
APP_STATUS = re.compile(r'" (\d{3}) headers=')
# proxy-error.log text of a request nginx rejected; over HTTP/2 nginx may reject a request
# without writing an access-log line for it (TLS stacks only, see unlogged_proxy_rejection).
PROXY_REJECTION = re.compile(r"client sent|too large|too long|too big|exceeded", re.IGNORECASE)
FETCH_TOKEN = """async ({url, timeout, headers}) => {
  try {
    const response = await fetch(url, {cache: "no-store", headers,
                                       signal: AbortSignal.timeout(timeout)});
    const visible = {};
    response.headers.forEach((value, name) => { visible[name] = value; });
    return {status: response.status, headers: visible, text: await response.text(), error: null};
  } catch (error) {
    return {status: null, headers: {}, text: null, error: String(error)};
  }
}"""


@dataclass
class BrowserRequest:
    """One fetch() sent from the test page, as the browser saw it."""

    url: str
    nonce: str
    sent: bool = True
    status: int | None = None
    headers: dict = field(default_factory=dict)  # Response headers visible to the page.
    set_cookie: str | None = None  # From Response.all_headers(); fetch() hides Set-Cookie.
    body: dict | None = None
    error: str | None = None
    # TLS stacks only: the proxy-error.log lines nginx appended while the request was in flight.
    proxy_errors: list[str] | None = None


@dataclass
class PairRun:
    """Everything one (algorithm, transport) pair observed, before the logs are read."""

    algorithm: str
    transport: str
    token_bytes: int
    # Extra issue parameters (claims, pad, attrs; see transport_app.issue_endpoint); {} = fixture.
    issue_query: dict = field(default_factory=dict)
    # Filled in by send_through_browser and verify_directly.
    page_status: int | None = None
    page_error: str | None = None
    issue: BrowserRequest | None = None
    cookie_stored: bool = False
    verify: BrowserRequest | None = None
    direct: dict = field(default_factory=dict)


class BrowserLog:
    """Append one pair's browser-side events to browser.log as JSON Lines."""

    def __init__(self, path: Path, algorithm: str, transport: str):
        self.path, self.algorithm, self.transport = path, algorithm, transport

    def write(self, event: str, **fields) -> None:
        record = {"event": event, "algorithm": self.algorithm, "transport": self.transport,
                  **fields}
        with self.path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record) + "\n")


class PageTraffic:
    """Collect a page's requests and responses, and log them after each step of the pair."""

    def __init__(self, page, log: BrowserLog):
        self.log = log
        self.requests, self.responses, self.failures = [], [], []
        # Playwright needs Python functions as handlers; it cannot wrap a builtin list.append.
        page.on("request", lambda request: self.requests.append(request))
        page.on("response", lambda response: self.responses.append(response))
        page.on("requestfailed", lambda request: self.failures.append(request))

    def flush(self) -> dict[str, dict]:
        """Log what arrived since the last flush; return the response headers by URL."""
        # all_headers() needs the event loop, so it runs here, after the fetch returned, and
        # never inside the sync-API event handlers.
        requests, self.requests = self.requests, []
        responses, self.responses = self.responses, []
        failures, self.failures = self.failures, []
        for request in requests:
            self.log.write("request", url=request.url, method=request.method,
                           headers=request.all_headers())
        headers_by_url = {}
        for response in responses:
            headers_by_url[response.url] = response.all_headers()
            self.log.write("response", url=response.url, status=response.status,
                           headers=headers_by_url[response.url])
        for request in failures:
            self.log.write("request_failed", url=request.url, failure=request.failure)
        return headers_by_url


def selected_algorithms(algorithms: Sequence[str] | None) -> list[str]:
    """Return the configuration names to run, in order; raise ValueError for a bad selection."""
    if algorithms is None:
        return [adapter.name for adapter in ADAPTER_LIST]
    if isinstance(algorithms, str):
        raise ValueError(f"algorithms must be a sequence of names, not the string {algorithms!r}")
    try:
        names = list(algorithms)
    except TypeError:
        raise ValueError(f"algorithms must be a sequence of names, got {algorithms!r}") from None
    if not names:
        raise ValueError("algorithms must name at least one configuration")
    unknown = [name for name in names if not isinstance(name, str) or name not in ADAPTERS]
    if unknown:
        raise ValueError(f"unknown algorithms {unknown!r}; choose from {', '.join(ADAPTERS)}")
    if len(set(names)) != len(names):
        raise ValueError(f"algorithms must not repeat a name, got {names!r}")
    return names


def nonce_url(base_url: str, path: str, **query: str) -> tuple[str, str]:
    """Return base_url + path with the query and a fresh nonce, and the nonce itself."""
    nonce = secrets.token_hex(16)
    return f"{base_url}{path}?{urlencode({**query, 'nonce': nonce})}", nonce


def token_header(transport: str, token: str) -> dict:
    """Return the request header that carries a token in the given transport."""
    if transport == "cookie":
        return {"Cookie": f"{COOKIE_NAME}={token}"}
    return {"Authorization": f"Bearer {token}"}


def json_object(text: str | bytes | None) -> dict | None:
    """Parse a response body as a JSON object, or return None."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def issue_directly(app_url: str, algorithm: str, timeout: float,
                   issue_query: dict | None = None) -> str:
    """Get a token in the JSON body straight from the application, bypassing browser and proxy."""
    url, _ = nonce_url(app_url, ISSUE_PATH, alg=algorithm, delivery="body", **(issue_query or {}))
    try:
        status, _, body = http_get(url, timeout=timeout)
    except (OSError, http.client.HTTPException) as error:
        raise RuntimeError(f"application: {url} failed: {error}") from error
    token = (json_object(body) or {}).get("token")
    if status != 200 or not isinstance(token, str):
        raise RuntimeError(f"application: {url} returned status {status} without a token")
    return token


def verify_directly(app_url: str, transport: str, token: str, timeout: float) -> dict:
    """Send a token straight to the application's verify endpoint, bypassing browser and proxy."""
    url, nonce = nonce_url(app_url, VERIFY_PATH)
    try:
        status, _, body = http_get(url, headers=token_header(transport, token), timeout=timeout)
    except (OSError, http.client.HTTPException):
        status, body = None, None
    verified = status == 200 and (json_object(body) or {}).get("verified") is True
    return {"url": url, "nonce": nonce, "status": status, "verified": verified}


def load_test_page(page, url: str, timeout: float) -> tuple[int | None, str | None]:
    """Load the test page through the proxy; return its status, or None and the error."""
    from playwright.sync_api import Error as PlaywrightError  # run_token_check checked it.

    try:
        response = page.goto(url, timeout=timeout * 1000)
    except PlaywrightError as error:
        return None, str(error)
    return (response.status if response else None), None


def send_fetch(page, url: str, nonce: str, timeout: float,
               headers: dict | None = None) -> BrowserRequest:
    """fetch() a URL from inside the page, so the request leaves through the browser."""
    reply = page.evaluate(FETCH_TOKEN, {"url": url, "timeout": timeout * 1000,
                                        "headers": headers or {}})
    return BrowserRequest(url=url, nonce=nonce, status=reply["status"], headers=reply["headers"],
                          body=json_object(reply["text"]), error=reply["error"])


def read_cookie_jar(context, log: BrowserLog, step: str) -> list[dict]:
    """Read the browser context's cookie jar and log it."""
    cookies = context.cookies()
    log.write("cookies", step=step, cookies=cookies)
    return cookies


def send_verify(page, run: PairRun, proxy_url: str, timeout: float) -> BrowserRequest:
    """fetch() the verify endpoint with the jwt cookie the browser stored, or a Bearer header."""
    url, nonce = nonce_url(proxy_url, VERIFY_PATH)
    if run.transport == "cookie":
        # The browser sends whatever jwt cookie it stored; the check never adds one itself.
        return send_fetch(page, url, nonce, timeout)
    token = (run.issue.body or {}).get("token")
    if not isinstance(token, str):
        return BrowserRequest(url=url, nonce=nonce, sent=False,
                              error="not sent: the issue response carried no token")
    return send_fetch(page, url, nonce, timeout, token_header("bearer", token))


def error_log_offset(stack) -> int | None:
    """Size of a TLS stack's proxy-error.log before a request is sent; None for a plain stack,
    whose requests are judged as they always were."""
    if not is_tls_stack(stack):
        return None
    try:
        return (Path(stack.run_dir) / "logs" / LOG_FILES["proxy_error"]).stat().st_size
    except OSError:
        return 0


def error_lines_since(stack, offset: int | None) -> list[str] | None:
    """The proxy-error.log lines appended since offset (see error_log_offset)."""
    if offset is None:
        return None
    try:
        with (Path(stack.run_dir) / "logs" / LOG_FILES["proxy_error"]).open("rb") as log:
            log.seek(offset)
            return log.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []


def send_through_browser(context, stack, run: PairRun, timeout: float, log: BrowserLog) -> None:
    """Load the test page, then issue and verify a token from it; record what was observed."""
    page = context.new_page()
    page.set_default_timeout(timeout * 1000)
    traffic = PageTraffic(page, log)
    page_url, _ = nonce_url(stack.proxy_url, "/")
    run.page_status, run.page_error = load_test_page(page, page_url, timeout)
    traffic.flush()

    delivery = "cookie" if run.transport == "cookie" else "body"
    issue_url, issue_nonce = nonce_url(stack.proxy_url, ISSUE_PATH, alg=run.algorithm,
                                       delivery=delivery, **run.issue_query)
    offset = error_log_offset(stack)
    run.issue = send_fetch(page, issue_url, issue_nonce, timeout)
    run.issue.proxy_errors = error_lines_since(stack, offset)
    run.issue.set_cookie = traffic.flush().get(issue_url, {}).get("set-cookie")
    jar = read_cookie_jar(context, log, "after_issue")
    run.cookie_stored = any(cookie["name"] == COOKIE_NAME for cookie in jar)

    offset = error_log_offset(stack)
    run.verify = send_verify(page, run, stack.proxy_url, timeout)
    run.verify.proxy_errors = error_lines_since(stack, offset)
    traffic.flush()
    read_cookie_jar(context, log, "after_verify")


def run_pair(browser, stack, algorithm: str, transport: str, timeout: float,
             log_path: Path, issue_query: dict | None = None) -> PairRun:
    """Send one configuration's token in one transport through the browser, then directly."""
    issue_query = {key: str(value) for key, value in (issue_query or {}).items()}
    token = issue_directly(stack.app_url, algorithm, timeout, issue_query)
    run = PairRun(algorithm=algorithm, transport=transport, token_bytes=len(token),
                  issue_query=issue_query)
    log = BrowserLog(log_path, algorithm, transport)
    # A new context per pair, so no cookie carries over; a TLS stack's accepts its certificate.
    context = browser.new_context(**browser_context_options(stack))
    try:
        send_through_browser(context, stack, run, timeout, log)
    finally:
        context.close()
    run.direct = verify_directly(stack.app_url, transport, token, timeout)
    return run


def browser_identity(browser) -> dict:
    """Return the version the browser reports and the user agent its pages send."""
    context = browser.new_context()
    try:
        user_agent = context.new_page().evaluate("navigator.userAgent")
    finally:
        context.close()
    return {"version": browser.version, "user_agent": user_agent}


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def wait_for_proxy_log(path: Path, nonces: list[str]) -> None:
    """Wait briefly until nginx has logged every request whose response reached the browser."""
    deadline = time.monotonic() + LOG_GRACE_SECONDS
    while time.monotonic() < deadline:
        text = "\n".join(read_lines(path))
        if all(nonce in text for nonce in nonces):
            return
        time.sleep(0.05)


def lines_mentioning(nonce: str, logs: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return, for each layer's log, the lines that contain a request's nonce."""
    return {key: [line for line in lines if nonce in line] for key, lines in logs.items()}


def quote(line: str) -> str:
    """Quote a log line as evidence, shortening token-like runs and long lines."""
    text = TOKEN_LIKE.sub(lambda match: f"{match[0][:12]}[...]", line.strip())
    if len(text) > QUOTE_LIMIT:
        text = f"{text[:QUOTE_LIMIT - 3]}..."
    return f'"{text}"'


def describe_reply(request: BrowserRequest) -> str:
    if request.status is not None:
        return f"status {request.status}"
    return f"no response ({request.error})" if request.error else "no response"


def application_line(app_lines: list[str]) -> str | None:
    """Return the line the application itself wrote for a request, if any."""
    return next((line for line in app_lines if APP_STATUS.search(line)), None)


def expected_outcome(transport: str, token_bytes: int, layers: dict) -> str:
    """Predict a pair's outcome from the documented default limits; None bytes means no limit."""
    cookie_limit = layers["browser"]["limits"]["cookie"]["bytes"]
    header_limit = layers["proxy"]["limits"]["single_header"]["bytes"]
    if transport == "cookie":
        sizes = [(len(COOKIE_NAME) + token_bytes, cookie_limit),
                 (len(f"Cookie: {COOKIE_NAME}=") + token_bytes, header_limit)]
    else:
        sizes = [(len("Authorization: Bearer ") + token_bytes, header_limit)]
    fits = all(limit is None or size <= limit for size, limit in sizes)
    return "verified" if fits else "rejected"


def expected_received(run: PairRun) -> dict:
    """Return the Cookie and Authorization sizes the application should report for the token."""
    if run.transport == "cookie":
        return {"cookie_bytes": len(f"{COOKIE_NAME}=") + run.token_bytes,
                "authorization_bytes": None}
    return {"cookie_bytes": None, "authorization_bytes": len("Bearer ") + run.token_bytes}


def verification_problems(run: PairRun, issue_lines: dict, verify_lines: dict) -> list[str]:
    """List every reason the pair does not count as verified; empty means it verified."""
    problems = []
    if run.page_status != 200:
        problems.append(f"the test page returned {run.page_status or run.page_error}")
    if run.issue.status != 200:
        problems.append(f"the issue request got {describe_reply(run.issue)}")
    if run.transport == "cookie" and not run.cookie_stored:
        problems.append(f"the browser stored no {COOKIE_NAME} cookie")
    body, received = run.verify.body or {}, (run.verify.body or {}).get("received") or {}
    if run.verify.status != 200:
        problems.append(f"the verify request got {describe_reply(run.verify)}")
    elif PROXY_MARKER.lower() not in run.verify.headers:
        problems.append(f"the verify response has no {PROXY_MARKER} header")
    elif (body.get("verified") is not True or body.get("algorithm") != run.algorithm
          or body.get("source") != run.transport):
        problems.append(f"the verify body does not confirm {run.algorithm} from the "
                        f"{run.transport}: {json.dumps(body)[:200]}")
    elif {key: received.get(key) for key in expected_received(run)} != expected_received(run):
        problems.append(f"the application received {received}, expected {expected_received(run)}")
    for step, lines in (("issue", issue_lines), ("verify", verify_lines)):
        missing = [LOG_FILES[key] for key in ("browser", "proxy_access", "app") if not lines[key]]
        if missing:
            problems.append(f"the {step} nonce is missing from {', '.join(missing)}")
    return problems


def unlogged_proxy_rejection(request: BrowserRequest) -> str | None:
    """The proxy-error.log line that explains a failed request nginx did not log, or None.

    Only TLS stacks record proxy_errors: over HTTP/2 nginx can reject a request, for example
    with a connection-level error, without writing an access-log line for it.
    """
    if request.proxy_errors is None or (request.status is not None and request.status < 400):
        return None
    return next((line for line in request.proxy_errors if PROXY_REJECTION.search(line)), None)


def failed_request_layer(step: str, request: BrowserRequest, lines: dict) -> tuple[str | None, str]:
    """Name the first layer that did not pass a failed request, or its response, on."""
    reply = describe_reply(request)
    if not request.sent:
        return None, f"the {step} request was {request.error}"
    if not lines["proxy_access"]:
        rejection = unlogged_proxy_rejection(request)
        if rejection is not None:
            return "proxy", (f"proxy: the {step} request got {reply}, and nginx wrote no "
                             f"access-log line for it (its nonce is not in proxy-access.log); "
                             f"proxy-error.log while it was in flight: {quote(rejection)}")
        return "browser", (f"browser: the {step} request never reached nginx (its nonce is not in "
                           f"proxy-access.log); the page got {reply}")
    access = quote(lines["proxy_access"][0])
    app_line = application_line(lines["app"])
    app_status = int(APP_STATUS.search(app_line)[1]) if app_line else None
    browser_error = request.status is None or request.status >= 400
    if browser_error and (not lines["app"] or app_status == 200):
        if lines["app"]:
            why = f"app.log shows the application answered 200: {quote(app_line)}"
        else:
            why = "its nonce is not in app.log, so nginx did not forward it"
        error_line = (f"; proxy-error.log: {quote(lines['proxy_error'][0])}"
                      if lines["proxy_error"] else "")
        return "proxy", (f"proxy: the browser got {reply} for the {step} request; "
                         f"proxy-access.log: {access}{error_line}; {why}")
    waitress_lines = [line for line in lines["app"] if "rejected by waitress" in line]
    if waitress_lines:
        return "app_server", (f"app_server: waitress rejected the {step} request before the "
                              f"application ran; app.log: {quote(waitress_lines[0])}")
    if app_status is not None and app_status >= 400:
        error = (request.body or {}).get("error")
        return "application", (f"application: it answered {app_status} to the {step} request "
                               f"({error}); app.log: {quote(app_line)}")
    return None, f"the {step} request got {reply}, and no layer's log explains it"


def rejecting_layer(run: PairRun, issue_lines: dict, verify_lines: dict) -> tuple[str | None, str]:
    """Walk issue, cookie jar, and verify in order; blame the first layer that failed."""
    if run.issue.status != 200 or not issue_lines["proxy_access"]:
        return failed_request_layer("issue", run.issue, issue_lines)
    if run.transport == "cookie" and not run.cookie_stored:
        if run.issue.set_cookie is None:
            return None, "the issue response returned 200, but browser.log shows no Set-Cookie"
        return "browser", (f"browser: the issue response carried a {len(run.issue.set_cookie):,}"
                           f"-byte Set-Cookie (browser.log) whose name + value is "
                           f"{len(COOKIE_NAME) + run.token_bytes:,} bytes, but "
                           f"BrowserContext.cookies() lists no {COOKIE_NAME} cookie afterwards")
    if run.verify.status != 200 or not verify_lines["proxy_access"]:
        return failed_request_layer("verify", run.verify, verify_lines)
    return None, ""


def judge(run: PairRun, logs: dict[str, list[str]], layers: dict) -> dict:
    """Combine one pair's observations with every layer's log into its result."""
    issue_lines = lines_mentioning(run.issue.nonce, logs)
    verify_lines = lines_mentioning(run.verify.nonce, logs)
    problems = verification_problems(run, issue_lines, verify_lines)
    if not problems:
        outcome, rejected_by = "verified", None
        carrier = (f"a {COOKIE_NAME} cookie" if run.transport == "cookie"
                   else "an Authorization: Bearer header")
        evidence = (f"verified: the browser sent the {run.token_bytes:,}-byte token as {carrier} "
                    f"through nginx, and the application verified it; both nonces are in "
                    f"browser.log, proxy-access.log, and app.log")
    else:
        outcome = "rejected"
        rejected_by, evidence = rejecting_layer(run, issue_lines, verify_lines)
        if rejected_by is None:
            evidence = f"no rejecting layer identified: {evidence or problems[0]}"
    expected = expected_outcome(run.transport, run.token_bytes, layers)
    return {
        "algorithm": run.algorithm,
        "transport": run.transport,
        "token_bytes": run.token_bytes,
        "expected": expected,
        "outcome": outcome,
        "rejected_by": rejected_by,
        "ok": (outcome == expected and (outcome == "verified" or rejected_by is not None)
               and run.direct["verified"]),
        "page_status": run.page_status,
        "cookie_stored": run.cookie_stored if run.transport == "cookie" else None,
        "evidence": evidence[:EVIDENCE_LIMIT],
        "issue": {"url": run.issue.url, "nonce": run.issue.nonce, "status": run.issue.status,
                  "logs": {key: bool(found) for key, found in issue_lines.items()}},
        "verify": {"url": run.verify.url, "nonce": run.verify.nonce,
                   "status": run.verify.status, "body": run.verify.body,
                   "logs": {key: bool(found) for key, found in verify_lines.items()}},
        "direct": run.direct,
    }


def run_token_check(stack, algorithms: Sequence[str] | None = None,
                    timeout: float = 60.0) -> dict:
    """Send each configuration's fixture token as a cookie and a Bearer header; judge each pair."""
    names = selected_algorithms(algorithms)
    check_timeout(timeout)
    try:
        from playwright.sync_api import Error as PlaywrightError, sync_playwright
    except ImportError as error:
        raise RuntimeError(f"automation: Playwright is not installed ({error})") from error

    manifest = load_manifest()
    layers = {layer["role"]: layer for layer in manifest["layers"]}
    log_dir = Path(stack.run_dir).absolute() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=timeout * 1000)
            try:
                identity = browser_identity(browser)
                runs = [run_pair(browser, stack, name, transport, timeout,
                                 log_dir / LOG_FILES["browser"])
                        for name in names for transport in TRANSPORTS]
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error

    answered = [request.nonce for run in runs for request in (run.issue, run.verify)
                if request.status is not None]
    wait_for_proxy_log(log_dir / LOG_FILES["proxy_access"], answered)
    logs = {key: read_lines(log_dir / name) for key, name in LOG_FILES.items()}
    results = [judge(run, logs, layers) for run in runs]
    return {
        "ok": (all(result["ok"] for result in results)
               and identity["version"] == layers["browser"]["version"]),
        "proxy_url": stack.proxy_url,
        "app_url": stack.app_url,
        "run_dir": str(stack.run_dir),
        "layers": manifest_layers(manifest),
        "browser": identity,
        "algorithms": names,
        "logs": {key: str(log_dir / name) for key, name in LOG_FILES.items()},
        "results": results,
    }


def summary_lines(result: dict) -> list[str]:
    """Describe each pair in one line, for people reading the command's stderr."""
    width = max(len(entry["algorithm"]) for entry in result["results"])
    lines = []
    for entry in result["results"]:
        observed = (f"rejected by {entry['rejected_by']}" if entry["rejected_by"]
                    else entry["outcome"])
        direct = "verified" if entry["direct"]["verified"] else "NOT verified"
        lines.append(f"{entry['algorithm']:<{width}}  {entry['transport']:<6}  "
                     f"{entry['token_bytes']:>6,} bytes  {observed:<24}  "
                     f"expected {entry['expected']:<8}  direct {direct}")
    return lines


def mismatch_message(result: dict) -> str:
    """Explain why `ok` is false: the pairs that did not match, or the browser version."""
    reasons = []
    for entry in result["results"]:
        if entry["ok"]:
            continue
        reason = f"{entry['algorithm']} {entry['transport']}: expected {entry['expected']}, "
        reason += f"observed {entry['outcome']}"
        if entry["outcome"] == "rejected" and entry["rejected_by"] is None:
            reason += " with no rejecting layer identified"
        if not entry["direct"]["verified"]:
            reason += ", and it did not verify directly at the application"
        reasons.append(reason)
    documented = next(layer["version"] for layer in result["layers"] if layer["role"] == "browser")
    if result["browser"]["version"] != documented:
        reasons.append(f"browser reports version {result['browser']['version']}, "
                       f"manifest documents {documented}")
    return "token check did not match the documented limits: " + "; ".join(reasons)
