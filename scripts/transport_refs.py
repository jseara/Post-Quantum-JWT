"""Measure S3-02's third mitigation, reference tokens, in one run.

The application can issue a short opaque reference in place of the signed JWT
(GET /api/token/reference in scripts/transport_app.py): `ref_` plus 43 base64url characters from
32 random bytes, 47 bytes in all, in a `jwt_ref` cookie or a JSON body. The verified JWT stays in
a reference store, either the application's own memory ("memory") or a separate store process
that start_stack runs on 127.0.0.1 and the application reaches over loopback HTTP on persistent
connections ("remote"). On GET /api/token/verify the application looks the JWT up by its
reference (timing.lookup_ns) and verifies it again, as before. A run compares references with
JWTs in four phases:

1. Plan, calculated: for each configuration, the bytes each size limit counts for its JWT and
   for a reference (one cookie's name + value, the Set-Cookie line, the Cookie line, and the
   Authorization line), checked against Chromium's documented 4,096-byte cookie limit and
   nginx's 8,192-byte header line. Nothing is sent in this phase.
2. Size limits at the documented defaults, measured: one stack with no raised limit and the
   memory store, and headless Chromium, send each configuration's reference as a jwt_ref cookie
   and as a Bearer header, browser -> nginx -> waitress, plus probes of SLH-DSA-SHA2-128f tokens
   padded to 65,536 and 300,000 bytes; the rejecting layer is named from every layer's log. The
   JWT verdicts are derived from the newest committed claims run of this kind of machine, not
   measured, so no JWT that nginx would reject is sent.
3. Reference handling, measured: on a stack with the remote store, http.client sends found,
   unknown, malformed, expired, revoked, doubled, and mixed references through nginx, then stops
   the store process and sends a reference, a JWT, and a reference request again. This shows
   what the design gives up. The run records what it observes and never fails on a mismatch.
4. Latency: the S3-01 workload (scripts/transport_load.py) runs with Bearer JWTs, then with
   Bearer references backed by the memory store and by the remote store, each on a new stack,
   and the three runs are compared cell by cell, lookup apart from verification. The network
   model's saved upload time per profile is calculated, not measured.

Outputs, in output_dir: refs.json (settings, environment, the reference format, the plan, the
measured limits and probes with the derived JWT verdicts, the handling cases, the latency
comparison, and evidence), written last; limits/ and behavior/ (gzip copies of each stack's
logs, store.log included, and its nginx.conf); and latency-jwt/, latency-ref-memory/, and
latency-ref-remote/, each what `load --output-dir` writes. refs.json, load.json, raw.csv.gz,
app.log, proxy-access.log, proxy-error.log, store.log, and the latency runs' browser.log hold
no token or reference; only limits/'s browser.log holds the references Chromium handled.

Every signing key is an ephemeral experiment key, generated in memory by each stack's
application (and by this process for the calculated sizes) and never saved; none is a
production credential. Each reference is a random value held only in its stack's memory and
meaningless once that stack stops. Use run_refs, or `scripts/transport_stack.py refs`.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import inspect
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import REPO, claim_set, pad_for_target, token_bytes
from scripts.transport_app import (COOKIE_ATTRIBUTE_SETS, COOKIE_NAME, REF_BYTES,
                                   REF_COOKIE_NAME, REF_DEFAULT_TTL, REF_MAX_TTL, REF_PREFIX,
                                   REF_RANDOM_BYTES, REFERENCE_PATH, REVOKE_PATH, new_reference)
from scripts.transport_claims import (check_output_dir, mean_components_ms, phase_run_dir,
                                      require_playwright, save_stack_evidence, total_ms,
                                      without_tokens)
from scripts.transport_cookies import (app_header_bytes, describe_fits, documented_limits,
                                       launched_browser, observed, set_cookie_line_bytes)
from scripts.transport_load import (CARRIERS, NETWORK_PROFILES, REF_LATENCY_COMPONENTS,
                                    RESULT_FILE as LOAD_FILE,
                                    check_seconds, checked_settings as checked_load_settings,
                                    run_environment, run_load, run_reference_load,
                                    write_load_results)
from scripts.transport_stack import (PROXY_MARKER, http_get, load_manifest, manifest_layers,
                                     nginx_size, start_stack, stop_store)
from scripts.transport_tokens import (EVIDENCE_LIMIT, LOG_FILES, VERIFY_PATH, BrowserLog,
                                      BrowserRequest, PageTraffic, PairRun, browser_identity,
                                      describe_reply, failed_request_layer, issue_directly,
                                      json_object, lines_mentioning, load_test_page, nonce_url,
                                      quote, read_cookie_jar, read_lines, selected_algorithms,
                                      send_fetch, wait_for_proxy_log)


SCHEMA_VERSION = 1
RESULT_FILE = "refs.json"
# Each size-limit pair sends the reference in one of these, as Sprint 2 sent the JWT.
TRANSPORTS = ("cookie", "bearer")
SOURCES = {"cookie": "ref_cookie", "bearer": "ref_bearer"}
# The latency workload's reference configuration, measured in every run, as in S3-01.
LATENCY_REFERENCE = "ES256"
LATENCY_TRANSPORT = "bearer"
# Production cookie attributes for every size-limit pair and probe, as in S2-04.
COOKIE_ATTRIBUTES = "full"
LIMITS_DIR = "limits"
BEHAVIOR_DIR = "behavior"
# The three latency runs, in the fixed order they run in, and the store each one uses.
LATENCY_RUNS = ("jwt", "ref_memory", "ref_remote")
LATENCY_DIRS = {"jwt": "latency-jwt", "ref_memory": "latency-ref-memory",
                "ref_remote": "latency-ref-remote"}
LATENCY_STORES = {"jwt": "memory", "ref_memory": "memory", "ref_remote": "remote"}
REF_STORES = ["memory", "remote"]

# Fixed configurations, whatever the run's --alg selects. The probes pad SLH-DSA-SHA2-128f, the
# largest token, to each target; 300,000 bytes is beyond waitress's 262,144-byte header limit.
PROBE_ALGORITHM = "SLH-DSA-SHA2-128f"
PROBE_TARGETS = (65_536, 300_000)
# ML-DSA-44 is the largest configuration whose Bearer JWT fits the defaults, so the JWT still
# verifies once the store is stopped.
HANDLING_ALGORITHM = "ML-DSA-44"
EXPIRED_TTL_SECONDS = 1
EXPIRY_MARGIN_SECONDS = 0.25  # Waited beyond the ttl, so the store's clock has passed it too.
# The committed claims runs whose measured JWT verdicts the size limits are compared with.
CLAIMS_RUNS = Path("results") / "claims"


# --- Settings ---------------------------------------------------------------------------------


def default_settings() -> dict:
    """run_refs's keyword defaults, by setting name (the refs command's defaults too)."""
    parameters = inspect.signature(run_refs).parameters
    return {name: parameter.default for name, parameter in parameters.items()
            if name not in ("output_dir", "run_dir")}


def checked_settings(algorithms, claims, clients, concurrency, duration, warmup, timeout,
                     header_buffers, upstream_keepalive) -> dict:
    """Check run_refs's settings and return them as refs.json records them.

    Raises ValueError for any invalid value. Algorithms, claims, clients, concurrency, duration,
    and warm-up are checked as the load command checks them for a Bearer run, so the measured
    configurations are the selected ones plus the reference ES256, in ADAPTER_LIST order, and
    sequences become lists. header_buffers must be an nginx size (it raises the latency stacks'
    header line limit), and upstream_keepalive None or an int from 1 to 1024. Passing the result
    back as run_refs(output_dir, **settings) repeats the run.
    """
    check_seconds("timeout", timeout, allow_zero=False)  # Finite, unlike check_timeout.
    nginx_size("header_buffers", header_buffers)
    # The three latency runs differ only in what the Bearer header carries, so checking one
    # checks all three.
    workload = checked_load_settings(algorithms, LATENCY_TRANSPORT, clients, concurrency,
                                     duration, warmup, claims, LATENCY_REFERENCE, False, timeout,
                                     None, header_buffers, upstream_keepalive)
    return {"algorithms": workload["algorithms"], "claims": claims,
            "clients": workload["clients"], "concurrency": workload["concurrency"],
            "duration": duration, "warmup": warmup, "timeout": timeout,
            "header_buffers": header_buffers, "upstream_keepalive": upstream_keepalive}


def read_saved_settings(path: Path) -> dict:
    """Return the settings object of a refs.json written by an earlier run.

    Raises ValueError when the file cannot be read (missing, a directory, binary, or not JSON),
    has no settings object, or names a setting run_refs does not take, such as output_dir,
    run_dir, transport, or proxy_buffers. The values are checked by checked_settings once they
    are combined with the command line.
    """
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from None
    settings = saved.get("settings") if isinstance(saved, dict) else None
    if not isinstance(settings, dict):
        raise ValueError(f"{path} has no settings object; give the refs.json of an earlier run")
    unknown = sorted(set(settings) - set(default_settings()))
    if unknown:
        raise ValueError(f"{path} has unknown settings {', '.join(map(repr, unknown))}")
    return settings


# --- Phase 1: the plan, calculated ------------------------------------------------------------


def cookie_attributes() -> str:
    """The production cookie attributes of every size-limit pair and probe."""
    return COOKIE_ATTRIBUTE_SETS[COOKIE_ATTRIBUTES]


def by_carrier(jwt, ref) -> dict:
    """One value for the JWT and one for its reference, keyed jwt and ref."""
    return {"jwt": jwt, "ref": ref}


def plan_row(algorithm: str, claims: str, limits: dict) -> dict:
    """One configuration's calculated bytes for its JWT and a reference, and which documented
    limits each fits."""
    size = token_bytes(algorithm, claim_set(claims))
    bearer = CARRIERS["bearer"]
    name_value = by_carrier(len(COOKIE_NAME) + size, len(REF_COOKIE_NAME) + REF_BYTES)
    cookie_line = by_carrier(CARRIERS["cookie"].header_line_bytes(size),
                             len(f"Cookie: {REF_COOKIE_NAME}=\r\n") + REF_BYTES)
    authorization_line = by_carrier(bearer.header_line_bytes(size),
                                    bearer.header_line_bytes(REF_BYTES))

    def fits(carrier: str) -> dict:
        return {"per_cookie": name_value[carrier] <= limits["cookie"],
                "cookie_line": cookie_line[carrier] <= limits["line"],
                "authorization_line": authorization_line[carrier] <= limits["line"]}

    return {
        "algorithm": algorithm,
        "token_bytes": size,
        "reference_bytes": REF_BYTES,
        "name_value_bytes": name_value,
        "set_cookie_bytes": by_carrier(set_cookie_line_bytes(COOKIE_NAME, size),
                                       set_cookie_line_bytes(REF_COOKIE_NAME, REF_BYTES)),
        "cookie_line_bytes": cookie_line,
        "authorization_line_bytes": authorization_line,
        "fits": by_carrier(fits("jwt"), fits("ref")),
    }


def ref_plan(algorithms: Sequence[str] | None = None, claims: str = "oidc") -> list[dict]:
    """Return one calculated plan row per configuration, in ADAPTER_LIST order.

    Each row compares the unpadded token of the claims fixture (token_sizing.token_bytes) with a
    47-byte reference. None means all six. Raises ValueError for an unknown, repeated, or empty
    selection, or an unknown claims name; no reference configuration is added and nothing is
    started.
    """
    selected = selected_algorithms(algorithms)
    claim_set(claims)  # Raises ValueError for an unknown name before any row is computed.
    limits = documented_limits()
    return [plan_row(adapter.name, claims, limits) for adapter in ADAPTER_LIST
            if adapter.name in selected]


# --- Phase 2: size limits at the documented defaults ------------------------------------------


@dataclass
class RefPairRun(PairRun):
    """One reference pair as observed, before the logs are read (transport cookie or bearer).

    token_bytes is the size of the JWT the reference names, as the application reported it.
    """

    reference_bytes: int = REF_BYTES


def limit_query(claims: str, pad: int = 0) -> dict:
    """The parameters of every size-limit reference: the run's claims, production attributes."""
    query = {"claims": claims, "attrs": COOKIE_ATTRIBUTES}
    return {**query, "pad": pad} if pad else query


def issue_reference_directly(app_url: str, algorithm: str, query: dict, timeout: float) -> dict:
    """Get a reference in the JSON body straight from the application; return the body.

    Raises RuntimeError unless the application answers 200 with a reference and token_bytes.
    """
    url, _ = nonce_url(app_url, REFERENCE_PATH, alg=algorithm, delivery="body", **query)
    try:
        status, _, data = http_get(url, timeout=timeout)
    except (OSError, http.client.HTTPException) as error:
        raise RuntimeError(f"application: {url} failed: {error}") from error
    body = json_object(data) or {}
    if (status != 200 or not isinstance(body.get("reference"), str)
            or type(body.get("token_bytes")) is not int):
        raise RuntimeError(f"application: {url} returned status {status} without a reference")
    return body


def reference_headers(transport: str, reference: str) -> dict:
    """The request header that carries a reference: a jwt_ref cookie or a Bearer header."""
    if transport == "cookie":
        return {"Cookie": f"{REF_COOKIE_NAME}={reference}"}
    return {"Authorization": f"Bearer {reference}"}


def verify_reference_directly(app_url: str, transport: str, reference: str,
                              timeout: float) -> dict:
    """Send a reference straight back to the application's verify endpoint, bypassing nginx."""
    url, nonce = nonce_url(app_url, VERIFY_PATH)
    try:
        status, _, body = http_get(url, headers=reference_headers(transport, reference),
                                   timeout=timeout)
    except (OSError, http.client.HTTPException):
        status, body = None, None
    reply = json_object(body) or {}
    verified = (status == 200 and reply.get("verified") is True
                and reply.get("source") == SOURCES[transport])
    return {"url": url, "nonce": nonce, "status": status, "verified": verified}


def send_reference_through_browser(context, stack, run: RefPairRun, timeout: float,
                                   log: BrowserLog) -> None:
    """Load the test page, fetch() a reference, read the jar, and fetch() the verify."""
    page = context.new_page()
    page.set_default_timeout(timeout * 1000)
    traffic = PageTraffic(page, log)
    page_url, _ = nonce_url(stack.proxy_url, "/")
    run.page_status, run.page_error = load_test_page(page, page_url, timeout)
    traffic.flush()

    delivery = "cookie" if run.transport == "cookie" else "body"
    issue_url, issue_nonce = nonce_url(stack.proxy_url, REFERENCE_PATH, alg=run.algorithm,
                                       delivery=delivery, **run.issue_query)
    run.issue = send_fetch(page, issue_url, issue_nonce, timeout)
    run.issue.set_cookie = traffic.flush().get(issue_url, {}).get("set-cookie")
    jar = read_cookie_jar(context, log, "after_issue")
    run.cookie_stored = any(cookie["name"] == REF_COOKIE_NAME for cookie in jar)

    url, nonce = nonce_url(stack.proxy_url, VERIFY_PATH)
    if run.transport == "cookie":
        # The browser sends whatever jwt_ref cookie it stored; the run never adds one itself.
        run.verify = send_fetch(page, url, nonce, timeout)
    else:
        reference = (run.issue.body or {}).get("reference")
        if isinstance(reference, str):
            run.verify = send_fetch(page, url, nonce, timeout,
                                    reference_headers("bearer", reference))
        else:
            run.verify = BrowserRequest(url=url, nonce=nonce, sent=False,
                                        error="not sent: the reference response carried no "
                                              "reference")
    traffic.flush()
    read_cookie_jar(context, log, "after_verify")


def run_ref_pair(browser, stack, algorithm: str, transport: str, query: dict, timeout: float,
                 log_path: Path) -> RefPairRun:
    """Send one configuration's reference in one transport through the browser, then directly.

    As run_pair does for a JWT: a reference issued straight from app_url gives the token's size;
    a new browser context then issues and verifies a reference through nginx; finally the direct
    reference is sent straight back to verify (verified_directly).
    """
    query = {key: str(value) for key, value in query.items()}
    issued = issue_reference_directly(stack.app_url, algorithm, query, timeout)
    run = RefPairRun(algorithm=algorithm, transport=transport, token_bytes=issued["token_bytes"],
                     issue_query=query, reference_bytes=len(issued["reference"]))
    context = browser.new_context()  # A new context per pair, so no cookie carries over.
    try:
        send_reference_through_browser(context, stack, run, timeout,
                                       BrowserLog(log_path, algorithm, SOURCES[transport]))
    finally:
        context.close()
    run.direct = verify_reference_directly(stack.app_url, transport, issued["reference"],
                                           timeout)
    return run


def expected_received(run: RefPairRun) -> dict:
    """The Cookie and Authorization sizes the application should report for the reference."""
    if run.transport == "cookie":
        return {"cookie_bytes": len(f"{REF_COOKIE_NAME}=") + run.reference_bytes,
                "authorization_bytes": None}
    return {"cookie_bytes": None, "authorization_bytes": len("Bearer ") + run.reference_bytes}


def confirms(run: RefPairRun) -> bool:
    """Whether the verify body confirms the run's JWT, found by its reference."""
    body = run.verify.body or {}
    return (body.get("verified") is True and body.get("algorithm") == run.algorithm
            and body.get("source") == SOURCES[run.transport]
            and body.get("token_bytes") == run.token_bytes
            and (body.get("ref") or {}).get("status") == "found")


def ref_problems(run: RefPairRun, issue_lines: dict, verify_lines: dict) -> list[str]:
    """List every reason a reference pair does not count as verified; empty means it verified."""
    problems = []
    if run.page_status != 200:
        problems.append(f"the test page returned {run.page_status or run.page_error}")
    if run.issue.status != 200:
        problems.append(f"the reference request got {describe_reply(run.issue)}")
    if run.transport == "cookie" and not run.cookie_stored:
        problems.append(f"the browser stored no {REF_COOKIE_NAME} cookie")
    received = (run.verify.body or {}).get("received") or {}
    expected = expected_received(run)
    if run.verify.status != 200:
        problems.append(f"the verify request got {describe_reply(run.verify)}")
    elif PROXY_MARKER.lower() not in run.verify.headers:
        problems.append(f"the verify response has no {PROXY_MARKER} header")
    elif not confirms(run):
        problems.append(f"the verify body does not confirm the {run.algorithm} token found by "
                        "its reference")
    elif {key: received.get(key) for key in expected} != expected:
        problems.append(f"the application received {received}, expected {expected}")
    for step, lines in (("issue", issue_lines), ("verify", verify_lines)):
        missing = [LOG_FILES[key] for key in ("browser", "proxy_access", "app") if not lines[key]]
        if missing:
            problems.append(f"the {step} nonce is missing from {', '.join(missing)}")
    return problems


def ref_rejecting_layer(run: RefPairRun, issue_lines: dict,
                        verify_lines: dict) -> tuple[str | None, str]:
    """Walk issue, cookie jar, and verify in order; blame the first layer that failed."""
    if run.issue.status != 200 or not issue_lines["proxy_access"]:
        return failed_request_layer("issue", run.issue, issue_lines)
    if run.transport == "cookie" and not run.cookie_stored:
        return "browser", (f"browser: the reference response reached the browser "
                           f"(proxy-access.log: {quote(issue_lines['proxy_access'][0])}), but "
                           f"BrowserContext.cookies() lists no {REF_COOKIE_NAME} cookie "
                           "afterwards")
    if run.verify.status != 200 or not verify_lines["proxy_access"]:
        return failed_request_layer("verify", run.verify, verify_lines)
    # Every request got through, yet ref_problems found something wrong: name the layer whose
    # answer or log is wrong, so that every rejected pair names a layer.
    body = run.verify.body or {}
    if PROXY_MARKER.lower() not in run.verify.headers:
        return "proxy", f"proxy: the verify response has no {PROXY_MARKER} header"
    if not confirms(run):
        return "application", ("application: it answered 200 to the verify request, but its body "
                               f"does not confirm the {run.algorithm} token (verified "
                               f"{body.get('verified')!r}, source {body.get('source')!r})")
    for step, lines in (("issue", issue_lines), ("verify", verify_lines)):
        for key, layer in (("browser", "browser"), ("app", "application")):
            if not lines[key]:
                return layer, f"{layer}: the {step} nonce is missing from {LOG_FILES[key]}"
    problems = ref_problems(run, issue_lines, verify_lines)
    return "browser", f"browser: {problems[0] if problems else 'the pair did not verify'}"


def judge_ref(run: RefPairRun, logs: dict[str, list[str]]) -> dict:
    """Combine one reference pair's observations with every layer's log into its outcome."""
    issue_lines = lines_mentioning(run.issue.nonce, logs)
    verify_lines = lines_mentioning(run.verify.nonce, logs)
    problems = ref_problems(run, issue_lines, verify_lines)
    if not problems:
        carrier = (f"a {REF_COOKIE_NAME} cookie" if run.transport == "cookie"
                   else "an Authorization: Bearer header")
        outcome, rejected_by = "verified", None
        evidence = (f"verified: the browser sent the {run.reference_bytes}-byte reference to a "
                    f"{run.token_bytes:,}-byte token as {carrier} through nginx, and the "
                    "application looked the token up and verified it; both nonces are in "
                    "browser.log, proxy-access.log, and app.log")
    else:
        outcome = "rejected"
        rejected_by, evidence = ref_rejecting_layer(run, issue_lines, verify_lines)
        if rejected_by is None:  # A request was not sent, or no layer's log explains it.
            evidence = f"no rejecting layer identified: {evidence or problems[0]}"
    return {"outcome": outcome, "rejected_by": rejected_by, "evidence": evidence[:EVIDENCE_LIMIT]}


def header_line_bytes(run: RefPairRun) -> int:
    """Calculated bytes of the header line that carries the reference, CRLF included."""
    if run.transport == "cookie":
        return len(f"Cookie: {REF_COOKIE_NAME}=\r\n") + run.reference_bytes
    return CARRIERS["bearer"].header_line_bytes(run.reference_bytes)


def pair_result(run: RefPairRun, logs: dict[str, list[str]]) -> dict:
    """The common keys of a size-limit result or probe, judged from every layer's log."""
    judged = judge_ref(run, logs)
    return {
        "algorithm": run.algorithm,
        "transport": run.transport,
        "token_bytes": run.token_bytes,
        "reference_bytes": run.reference_bytes,
        "outcome": judged["outcome"],
        "rejected_by": judged["rejected_by"],
        "verified_directly": run.direct["verified"],
        "cookie_stored": run.cookie_stored if run.transport == "cookie" else None,
        "issue_status": run.issue.status,
        "verify_status": run.verify.status,
        "bytes": {"header_line": header_line_bytes(run),
                  "app_received_headers": app_header_bytes(
                      lines_mentioning(run.verify.nonce, logs)["app"])},
        "issue_nonce": run.issue.nonce,
        "verify_nonce": run.verify.nonce,
        "evidence": without_tokens(judged["evidence"]),
    }


PROBE_KEYS = ("algorithm", "target_bytes", "pad", "token_bytes", "transport", "reference_bytes",
              "outcome", "rejected_by", "cookie_stored", "issue_status", "verify_status", "bytes",
              "issue_nonce", "verify_nonce", "evidence")


def probe_result(target: int, pad: int, run: RefPairRun, logs: dict[str, list[str]]) -> dict:
    """One probe's entry in refs.json: a padded token's reference, judged like any pair."""
    entry = {**pair_result(run, logs), "target_bytes": target, "pad": pad}
    return {key: entry[key] for key in PROBE_KEYS}


def probe_pads(claims: str) -> dict[int, int]:
    """Each probe target's pad: the largest whose SLH-DSA-SHA2-128f token is at most it."""
    pads = {}
    for target in PROBE_TARGETS:
        pad = pad_for_target(PROBE_ALGORITHM, claim_set(claims), target)
        if pad is None:
            raise RuntimeError(f"{PROBE_ALGORITHM}'s {claims} token is larger than {target:,} "
                               "bytes without padding")
        pads[target] = pad
    return pads


def read_judged_logs(stack, runs: list[RefPairRun]) -> dict[str, list[str]]:
    """Every layer's log, once nginx has logged every answered request of the runs."""
    log_dir = Path(stack.run_dir) / "logs"
    answered = [request.nonce for run in runs for request in (run.issue, run.verify)
                if request.status is not None]
    wait_for_proxy_log(log_dir / LOG_FILES["proxy_access"], answered)
    return {key: read_lines(log_dir / name) for key, name in LOG_FILES.items()}


def derived_jwt_verdicts(algorithms: list[str], claims: str, environment: dict) -> dict | None:
    """The JWT verdicts of the newest committed claims run recorded on this kind of machine.

    That run (results/claims/<run>/claims.json) must have this machine's page size and the same
    platform text before its first '-'. Returns {source, claims, results}, with one result per
    measured configuration and transport for the run's claims, or None when no such run exists
    or it has no result for these claims. Nothing is sent: the verdicts are derived, not
    measured.
    """
    platform = str(environment.get("platform") or "").split("-")[0]
    runs = sorted((REPO / CLAIMS_RUNS).glob("*/claims.json"),
                  key=lambda path: path.parent.name, reverse=True)
    for path in runs:
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        recorded = saved.get("environment") if isinstance(saved, dict) else None
        if (not isinstance(recorded, dict)
                or recorded.get("page_size_bytes") != environment.get("page_size_bytes")
                or str(recorded.get("platform") or "").split("-")[0] != platform):
            continue
        entries = {(entry.get("algorithm"), entry.get("transport")): entry
                   for entry in (saved.get("limits") or {}).get("results") or []
                   if isinstance(entry, dict) and entry.get("claims") == claims}
        results = [{key: entries[(algorithm, transport)][key]
                    for key in ("algorithm", "transport", "token_bytes", "outcome",
                                "rejected_by")}
                   for algorithm in algorithms for transport in TRANSPORTS
                   if (algorithm, transport) in entries]
        if not results:
            return None
        return {"source": path.relative_to(REPO).as_posix(), "claims": claims,
                "results": results}
    return None


def moved_entries(results: list[dict], jwt: dict | None) -> list[dict]:
    """One entry per result: the derived JWT outcome, the measured reference outcome, and
    whether the reference got through where the JWT did not (None without a JWT verdict)."""
    derived = {(entry["algorithm"], entry["transport"]): entry["outcome"]
               for entry in (jwt or {}).get("results", [])}
    entries = []
    for entry in results:
        jwt_outcome = derived.get((entry["algorithm"], entry["transport"]))
        moved = (None if jwt_outcome is None
                 else jwt_outcome == "rejected" and entry["outcome"] == "verified")
        entries.append({"algorithm": entry["algorithm"], "transport": entry["transport"],
                        "jwt": jwt_outcome, "ref": entry["outcome"], "moved": moved})
    return entries


def run_limits(output_dir: Path, settings: dict, jwt: dict | None,
               run_dir: Path | None) -> tuple[dict, list[dict], dict, dict]:
    """Phase 2: every reference pair, then the probes, on a stack at the documented defaults.

    Returns refs.json's limits object, the probes, the browser's identity, and the saved
    evidence.
    """
    claims, timeout = settings["claims"], settings["timeout"]
    pads = probe_pads(claims)
    # No raised limit and the memory store, so nginx.conf has no "Not a default" line.
    with start_stack(run_dir=run_dir, timeout=timeout) as stack:
        log_path = Path(stack.run_dir) / "logs" / LOG_FILES["browser"]
        with launched_browser(timeout) as browser:
            identity = browser_identity(browser)
            pairs = [run_ref_pair(browser, stack, algorithm, transport, limit_query(claims),
                                  timeout, log_path)
                     for algorithm in settings["algorithms"] for transport in TRANSPORTS]
            probes = [(target, pad, run_ref_pair(browser, stack, PROBE_ALGORITHM, transport,
                                                 limit_query(claims, pad), timeout, log_path))
                      for target, pad in pads.items() for transport in TRANSPORTS]
        logs = read_judged_logs(stack, [*pairs, *(run for _, _, run in probes)])
        results = [pair_result(run, logs) for run in pairs]
        probe_results = [probe_result(target, pad, run, logs) for target, pad, run in probes]
        evidence = save_stack_evidence(stack.run_dir, output_dir / LIMITS_DIR)
    limits = {"stack": LIMITS_DIR, "header_buffers": None, "proxy_buffers": None,
              "ref_store": "memory", "cookie_attributes": cookie_attributes(),
              "results": results, "jwt": jwt, "moved": moved_entries(results, jwt)}
    return limits, probe_results, identity, evidence


# --- Phase 3: reference handling --------------------------------------------------------------


def request(method: str, url: str, headers: dict, timeout: float) -> tuple[int, dict, bytes]:
    """Send one request with http.client and return status, lowercased headers, and body."""
    if method == "GET":
        return http_get(url, headers=headers, timeout=timeout)
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        connection.request(method, f"{parts.path}?{parts.query}", headers=headers)
        response = connection.getresponse()
        return (response.status, {name.lower(): value for name, value in response.getheaders()},
                response.read())
    finally:
        connection.close()


def case_headers(cookies: Sequence[tuple[str, str]], bearer: str | None) -> dict:
    """The request headers of a handling case: its cookies, in order, and a Bearer value."""
    headers = {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies)
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def send_case(stack, name: str, cookies: Sequence[tuple[str, str]], bearer: str | None,
              store: str, timeout: float, path: str = VERIFY_PATH,
              query: dict | None = None) -> dict:
    """Send one handling case through nginx with http.client; record names, never values.

    A verify case asks for timing=1, so lookup_called and verify_called come from the timing
    object (false when it is absent).
    """
    url, nonce = nonce_url(stack.proxy_url, path, **(query or {"timing": "1"}))
    try:
        status, headers, data = request("GET", url, case_headers(cookies, bearer), timeout)
        reply = BrowserRequest(url=url, nonce=nonce, status=status, headers=headers,
                               body=json_object(data))
    except (OSError, http.client.HTTPException) as error:
        reply = BrowserRequest(url=url, nonce=nonce, error=f"{type(error).__name__}: {error}")
    body = reply.body or {}
    timing = body.get("timing") if isinstance(body.get("timing"), dict) else {}
    ref = body.get("ref") if isinstance(body.get("ref"), dict) else {}
    error = body.get("error")
    return {
        "name": name,
        "method": "GET",
        "path": path,
        "sent": [cookie for cookie, _ in cookies] + (["bearer"] if bearer is not None else []),
        "store": store,
        "status": reply.status,
        "verified": (reply.status == 200 and PROXY_MARKER.lower() in reply.headers
                     and body.get("verified") is True),
        "source": body.get("source"),
        "ref_status": ref.get("status"),
        "lookup_called": timing.get("lookup_ns") is not None,
        "verify_called": timing.get("verify_ns") is not None,
        "revoke_status": None,
        "set_cookie": "set-cookie" in reply.headers,
        "error": without_tokens(error) if isinstance(error, str) else None,
        "nonce": nonce,
    }


def revoke_through_proxy(stack, reference: str, timeout: float) -> int | None:
    """POST /api/token/revoke with a Bearer reference through nginx; return its status."""
    url, _ = nonce_url(stack.proxy_url, REVOKE_PATH)
    try:
        status, _, _ = request("POST", url, case_headers((), reference), timeout)
    except (OSError, http.client.HTTPException):
        return None
    return status


def run_handling(stack, settings: dict) -> dict:
    """Phase 3: send every handling case through the behavior stack's nginx, in order.

    References A, B (ttl=1), and C and the JWT J are issued straight from the application with
    delivery=body. After reference_as_jwt, the store process is stopped while nginx and the
    application keep running, and the last three cases are sent.
    """
    claims, timeout = settings["claims"], settings["timeout"]
    query = {"claims": claims}
    first = issue_reference_directly(stack.app_url, HANDLING_ALGORITHM, query, timeout)
    a = first["reference"]
    b = issue_reference_directly(stack.app_url, HANDLING_ALGORITHM,
                                 {**query, "ttl": str(EXPIRED_TTL_SECONDS)}, timeout)["reference"]
    b_issued = time.monotonic()
    c = issue_reference_directly(stack.app_url, HANDLING_ALGORITHM, query, timeout)["reference"]
    jwt = issue_directly(stack.app_url, HANDLING_ALGORITHM, timeout, query)
    cases = []

    def case(name: str, cookies=(), bearer: str | None = None, store: str = "running",
             **request_options) -> dict:
        cases.append(send_case(stack, name, list(cookies), bearer, store, timeout,
                               **request_options))
        return cases[-1]

    case("cookie", [(REF_COOKIE_NAME, a)])
    case("bearer", bearer=a)
    case("among_other_cookies", [("a", "1"), (REF_COOKIE_NAME, a), ("theme", "dark")])
    case("unknown", bearer=new_reference())  # Never stored.
    case("malformed_cookie", [(REF_COOKIE_NAME, "not-a-reference")])
    time.sleep(max(0.0, b_issued + EXPIRED_TTL_SECONDS + EXPIRY_MARGIN_SECONDS
                   - time.monotonic()))
    case("expired", bearer=b)
    revoke_status = revoke_through_proxy(stack, c, timeout)
    case("revoked", bearer=c)["revoke_status"] = revoke_status
    case("two_references", [(REF_COOKIE_NAME, a), (REF_COOKIE_NAME, a)])
    case("reference_and_jwt", [(REF_COOKIE_NAME, a)], bearer=jwt)
    case("reference_as_jwt", [(COOKIE_NAME, a)])
    stop_store(stack)
    case("store_unavailable", bearer=a, store="stopped")
    case("jwt_without_store", bearer=jwt, store="stopped")
    case("issue_without_store", store="stopped", path=REFERENCE_PATH,
         query={"alg": HANDLING_ALGORITHM, "delivery": "cookie", "claims": claims})
    return {"algorithm": HANDLING_ALGORITHM, "claims": claims, "token_bytes": len(jwt),
            "stack": BEHAVIOR_DIR, "ref_store": "remote",
            "expired_ttl_seconds": EXPIRED_TTL_SECONDS, "cases": cases}


def run_behavior(output_dir: Path, settings: dict, run_dir: Path | None) -> tuple[dict, dict]:
    """Phase 3 on its own stack, with the remote store and no raised limit.

    Returns refs.json's handling object and the saved evidence, store.log included.
    """
    with start_stack(run_dir=run_dir, timeout=settings["timeout"], ref_store="remote") as stack:
        handling = run_handling(stack, settings)
        answered = [case["nonce"] for case in handling["cases"] if case["status"] is not None]
        wait_for_proxy_log(Path(stack.run_dir) / "logs" / LOG_FILES["proxy_access"], answered)
        evidence = save_stack_evidence(stack.run_dir, output_dir / BEHAVIOR_DIR)
    return handling, evidence


# --- Phase 4: latency, the S3-01 workload -----------------------------------------------------


def run_latency(output_dir: Path, settings: dict, name: str, run_dir: Path | None) -> dict:
    """Run one of the three latency runs on a new stack; return its load.json.

    jwt runs run_load with Bearer JWTs, and ref_memory and ref_remote run run_reference_load
    with Bearer references, on a stack with that store. The results are saved as `load
    --output-dir` saves them, so `load --settings latency-jwt/load.json` repeats the jwt run.
    The stack is stopped before this returns.
    """
    target = output_dir / LATENCY_DIRS[name]
    workload = {"algorithms": settings["algorithms"], "clients": settings["clients"],
                "concurrency": settings["concurrency"], "duration": settings["duration"],
                "warmup": settings["warmup"], "claims": settings["claims"],
                "reference": LATENCY_REFERENCE, "size_controls": False,
                "timeout": settings["timeout"], "proxy_buffers": None,
                "header_buffers": settings["header_buffers"],
                "upstream_keepalive": settings["upstream_keepalive"]}
    with start_stack(run_dir=run_dir, timeout=settings["timeout"],
                     header_buffers=settings["header_buffers"],
                     upstream_keepalive=settings["upstream_keepalive"],
                     ref_store=LATENCY_STORES[name]) as stack:
        if name == "jwt":
            result = run_load(stack, transport=LATENCY_TRANSPORT, **workload)
        else:
            result = run_reference_load(stack, **workload)
        write_load_results(result, target)
    return json.loads((target / LOAD_FILE).read_text(encoding="utf-8"))


def by_run(jwt, ref_memory, ref_remote) -> dict:
    """One value from each latency run, keyed by run."""
    return {"jwt": jwt, "ref_memory": ref_memory, "ref_remote": ref_remote}


def run_means(cell: dict) -> dict | None:
    """A cell's mean of each component in ms, lookup included (0.0 for a JWT run); None if no
    request verified."""
    means = mean_components_ms(cell)
    if means is None:
        return None
    lookup = (cell["latency"].get("lookup") or {}).get("mean_ms", 0.0)
    return {component: lookup if component == "lookup" else means[component]
            for component in REF_LATENCY_COMPONENTS}


def latency_row(cells: dict) -> dict:
    """Compare one configuration's token cell across the three runs (each ref run minus jwt)."""
    def paired(key: str) -> dict:
        return {run: cells[run][key] for run in LATENCY_RUNS}

    jwt = cells["jwt"]
    means = {run: run_means(cells[run]) for run in LATENCY_RUNS}
    difference = {}
    for run in LATENCY_RUNS[1:]:
        difference[run] = None
        if means["jwt"] is not None and means[run] is not None:
            difference[run] = {component: means[run][component] - means["jwt"][component]
                               for component in REF_LATENCY_COMPONENTS}
    return {"client": jwt["client"], "concurrency": jwt["concurrency"],
            "algorithm": jwt["algorithm"], "token_bytes": jwt["token_bytes"],
            "reference_bytes": cells["ref_memory"].get("reference_bytes", REF_BYTES),
            "delivered": {run: cells[run]["issue"]["delivered"] for run in LATENCY_RUNS},
            "verified": paired("verified"), "failed": paired("failed"),
            "throughput_rps": paired("throughput_rps"),
            "median_ms": {run: total_ms(cells[run], "median_ms") for run in LATENCY_RUNS},
            "p95_ms": {run: total_ms(cells[run], "p95_ms") for run in LATENCY_RUNS},
            "mean_ms": means, "difference_ms": difference}


def network_savings(jwt_run: dict, ref_run: dict) -> list[dict]:
    """Per configuration, the request bytes of a JWT and of a reference, and the modeled upload
    time a reference saves.

    The upload times come from each load.json's network model, so they are calculated, not
    measured.
    """
    ref_rows = {row["algorithm"]: row for row in ref_run["network_model"]["rows"]}
    entries = []
    for jwt_row in jwt_run["network_model"]["rows"]:
        ref_row = ref_rows[jwt_row["algorithm"]]
        jwt_ms, ref_ms = ({(item["uplink_mbps"], item["rtt_ms"]): item["transfer_ms"]
                           for item in row["modeled"]} for row in (jwt_row, ref_row))
        modeled = []
        for profile in NETWORK_PROFILES:
            key = (profile["uplink_mbps"], profile["rtt_ms"])
            modeled.append({**profile, "saved_ms": jwt_ms[key] - ref_ms[key]})
        entries.append({"algorithm": jwt_row["algorithm"],
                        "request_bytes": by_carrier(jwt_row["request_bytes"],
                                                    ref_row["request_bytes"]),
                        "saved_bytes": jwt_row["request_bytes"] - ref_row["request_bytes"],
                        "modeled": modeled})
    return entries


def compare_latency(runs: dict) -> dict:
    """Compare the three load.json results cell by cell; refs.json's latency."""
    cells = {run: {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
                   for cell in runs[run]["results"] if cell["variant"] == "token"}
             for run in LATENCY_RUNS}
    rows = [latency_row({run: cells[run][key] for run in LATENCY_RUNS})
            for key in cells["jwt"]]
    return {"transport": LATENCY_TRANSPORT, "reference": LATENCY_REFERENCE,
            "size_controls": False,
            "runs": {run: f"{LATENCY_DIRS[run]}/{LOAD_FILE}" for run in LATENCY_RUNS},
            "rows": rows, "network_model": network_savings(runs["jwt"], runs["ref_memory"])}


def latency_evidence(name: str, load: dict) -> dict:
    """Every file one latency run saved, relative to the refs run's output directory."""
    directory = LATENCY_DIRS[name]
    saved = load["evidence"]
    return {"load": f"{directory}/{LOAD_FILE}", "raw": f"{directory}/{saved['raw']}",
            "logs": {log: f"{directory}/{path}" for log, path in saved["logs"].items()},
            "nginx_conf": f"{directory}/{saved['nginx_conf']}"}


# --- The run ----------------------------------------------------------------------------------


def reference_format() -> dict:
    """refs.json's format: the reference, its cookie, its time to live, and the stores."""
    return {"reference_prefix": REF_PREFIX, "random_bytes": REF_RANDOM_BYTES,
            "reference_bytes": REF_BYTES, "cookie_name": REF_COOKIE_NAME,
            "cookie_attributes": cookie_attributes(), "default_ttl_seconds": REF_DEFAULT_TTL,
            "max_ttl_seconds": REF_MAX_TTL, "stores": list(REF_STORES)}


def run_refs(output_dir, algorithms: Sequence[str] | None = None, claims: str = "oidc",
             clients: Sequence[str] | None = None, concurrency: Sequence[int] = (1, 4),
             duration: float = 5.0, warmup: float = 1.0, timeout: float = 60.0,
             header_buffers: str = "32k", upstream_keepalive: int | None = None,
             run_dir=None) -> dict:
    """Run all four phases into output_dir, write refs.json last, and return what it holds.

    algorithms, claims, clients, concurrency, duration, and warmup mean what they mean for
    run_load; the probes and the reference handling use their fixed configurations whatever
    algorithms selects. header_buffers and upstream_keepalive apply to the three latency stacks
    only; the size-limits and behavior stacks keep every documented default. run_dir, if given,
    holds the five stacks' run directories (limits, behavior, latency-jwt, latency-ref-memory,
    and latency-ref-remote). Raises ValueError for any invalid argument, or an output_dir that
    exists and is not empty, before any process starts or output_dir is created, and
    RuntimeError when a layer or Playwright fails. Every started process (nginx, waitress, the
    store, and Chromium) is stopped before this returns or raises.
    """
    settings = checked_settings(algorithms, claims, clients, concurrency, duration, warmup,
                                timeout, header_buffers, upstream_keepalive)
    output_dir = check_output_dir(output_dir)
    require_playwright()

    started = datetime.now(timezone.utc)
    environment = run_environment()  # Includes the git commit the run starts from.
    plan = ref_plan(settings["algorithms"], settings["claims"])
    jwt = derived_jwt_verdicts(settings["algorithms"], settings["claims"], environment)
    output_dir.mkdir(parents=True, exist_ok=True)
    limits, probes, browser, limits_evidence = run_limits(
        output_dir, settings, jwt, phase_run_dir(run_dir, LIMITS_DIR))
    handling, behavior_evidence = run_behavior(output_dir, settings,
                                               phase_run_dir(run_dir, BEHAVIOR_DIR))
    latency_runs = {name: run_latency(output_dir, settings, name,
                                      phase_run_dir(run_dir, LATENCY_DIRS[name]))
                    for name in LATENCY_RUNS}
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
        "format": reference_format(),
        "plan": plan,
        "limits": limits,
        "probes": probes,
        "handling": handling,
        "latency": compare_latency(latency_runs),
        "evidence": {"limits": limits_evidence, "behavior": behavior_evidence,
                     "latency": {name: latency_evidence(name, latency_runs[name])
                                 for name in LATENCY_RUNS}},
    }
    write_refs_results(result, output_dir)
    return result


# --- Output -----------------------------------------------------------------------------------


def write_refs_results(result: dict, output_dir: Path) -> Path:
    """Save the result as refs.json in output_dir and return its path."""
    path = Path(output_dir) / RESULT_FILE
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path


def plan_lines(result: dict, width: int) -> list[str]:
    """One line per configuration: each limit's bytes, JWT -> reference, and fit (calculated)."""
    lines = []
    for row in result["plan"]:
        name_value, cookie_line = row["name_value_bytes"], row["cookie_line_bytes"]
        authorization, set_cookie = row["authorization_line_bytes"], row["set_cookie_bytes"]
        fits = row["fits"]
        lines.append(f"plan     {row['algorithm']:<{width}}  {row['token_bytes']:>6,} -> "
                     f"{row['reference_bytes']} B  name+value {name_value['jwt']:>6,} -> "
                     f"{name_value['ref']} B  Cookie line {cookie_line['jwt']:>6,} -> "
                     f"{cookie_line['ref']} B  Authorization line {authorization['jwt']:>6,} -> "
                     f"{authorization['ref']} B  Set-Cookie {set_cookie['jwt']:>6,} -> "
                     f"{set_cookie['ref']} B  jwt {describe_fits(fits['jwt'])}, ref "
                     f"{describe_fits(fits['ref'])}")
    return lines


def limits_lines(result: dict, width: int) -> list[str]:
    """One line per configuration and transport: the measured reference outcome, and the JWT
    outcome derived from the claims run."""
    limits = result["limits"]
    derived = {(entry["algorithm"], entry["transport"]): entry
               for entry in (limits["jwt"] or {}).get("results", [])}
    moved = {(entry["algorithm"], entry["transport"]): entry["moved"]
             for entry in limits["moved"]}
    lines = []
    for entry in limits["results"]:
        key = (entry["algorithm"], entry["transport"])
        jwt = f"{observed(derived[key])} (derived)" if key in derived else "not derived"
        line = (f"limits   {entry['transport']:<6} {entry['algorithm']:<{width}}  "
                f"{entry['token_bytes']:>6,} B  ref {entry['reference_bytes']} B "
                f"{observed(entry):<23}  jwt {jwt}")
        lines.append(line + ("  moved" if moved.get(key) else ""))
    return lines


def probe_lines(result: dict) -> list[str]:
    """One line per probe: the padded token, its transport, and the reference's outcome."""
    lines = []
    for entry in result["probes"]:
        lines.append(f"probe    {entry['algorithm']}  target {entry['target_bytes']:>7,} B  "
                     f"pad {entry['pad']:>7,}  {entry['token_bytes']:>7,} B  "
                     f"{entry['transport']:<6}  ref {entry['reference_bytes']} B  "
                     f"{observed(entry)}")
    return lines


def handling_lines(result: dict) -> list[str]:
    """One line per handling case: its status and what the application did."""
    def called(value: bool) -> str:
        return "called" if value else "not called"

    lines = []
    for case in result["handling"]["cases"]:
        line = (f"handling {case['name']:<19}  store {case['store']:<7}  "
                f"status {case['status'] or '-'}  "
                f"{'verified' if case['verified'] else 'not verified':<12}  "
                f"source {case['source'] or '-':<10}  ref {case['ref_status'] or '-':<11}  "
                f"lookup {called(case['lookup_called']):<10}  "
                f"verify_token {called(case['verify_called'])}")
        if case["revoke_status"] is not None:
            line += f"  revoke status {case['revoke_status']}"
        lines.append(line)
    return lines


RUN_LABELS = {"jwt": "jwt", "ref_memory": "ref-memory", "ref_remote": "ref-remote"}


def latency_lines(result: dict, width: int) -> list[str]:
    """One line per latency row: each run's mean, both differences from jwt, the lookups,
    medians, p95s, and throughput."""
    lines = []
    for row in result["latency"]["rows"]:
        label = (f"latency  {row['client']:<7} c={row['concurrency']:<3} "
                 f"{row['algorithm']:<{width}}  {row['token_bytes']:>6,} B")
        means, difference = row["mean_ms"], row["difference_ms"]
        missing = [f"{RUN_LABELS[run]} "
                   f"{'none verified' if row['delivered'][run] else 'not delivered'}"
                   for run in LATENCY_RUNS if means[run] is None]
        if missing:
            lines.append(f"{label}  no verified request: {', '.join(missing)}")
            continue
        medians, p95s, throughput = row["median_ms"], row["p95_ms"], row["throughput_rps"]
        line = (f"{label}  mean jwt {means['jwt']['total']:.3f}, ref-memory "
                f"{means['ref_memory']['total']:.3f} ({difference['ref_memory']['total']:+.3f}), "
                f"ref-remote {means['ref_remote']['total']:.3f} "
                f"({difference['ref_remote']['total']:+.3f}) ms  lookup "
                f"{means['ref_memory']['lookup']:.3f}, {means['ref_remote']['lookup']:.3f}  "
                f"median {' / '.join(f'{medians[run]:.3f}' for run in LATENCY_RUNS)}  "
                f"p95 {' / '.join(f'{p95s[run]:.3f}' for run in LATENCY_RUNS)}  "
                f"{' / '.join(f'{throughput[run]:,.1f}' for run in LATENCY_RUNS)} req/s")
        failed = sum(row["failed"][run] for run in LATENCY_RUNS)
        if failed:
            line += f"  {failed:,} failed"
        lines.append(line)
    return lines


def summary_lines(result: dict) -> list[str]:
    """The refs command's printed summary, from a refs.json object alone.

    In order: plan, limits, probe, handling, and latency lines; each starts with its phase word
    and names its configuration or case.
    """
    width = max(len(row["algorithm"]) for row in result["plan"])
    return [*plan_lines(result, width), *limits_lines(result, width), *probe_lines(result),
            *handling_lines(result), *latency_lines(result, width)]
