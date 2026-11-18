"""Measure S3-02's first mitigation, smaller claim sets, in one run.

The essential claim set (fixtures/claims_essential.json) keeps the five ID Token claims that
OpenID Connect Core 1.0 section 2 marks REQUIRED (iss, sub, aud, exp, iat), with the values of
the oidc fixture (fixtures/claims_oidc.json), and drops its other 17 claims. A run compares the
two claim sets in four phases, with the minimal Sprint 1 fixture (fixtures/claims.json) shown
only as a floor in the first:

1. Token sizes: each configuration signs the unpadded minimal, oidc, and essential fixtures with
   a fresh key and verifies every token before its size is recorded. A token's header and
   signature do not depend on its claims, so every configuration's token shrinks by the same
   number of bytes.
2. Sprint 2 boundaries, derived: each oidc and essential token size is compared with the largest
   token that verified in three committed Sprint 2 sweeps from WSL2 (cookie-default,
   cookie-16k, and bearer-default), which tells whether dropping claims moves a configuration
   across a boundary. Nothing is sent in this phase.
3. Size limits, measured: one stack at the documented default limits and headless Chromium send
   each configuration's oidc and essential token once as a jwt cookie with production
   attributes and once as an Authorization: Bearer header, browser -> nginx -> waitress, and the
   layer that rejected a token is named from every layer's log, as the tokens check does
   (run_pair and judge in scripts/transport_tokens.py).
4. Latency: the S3-01 Bearer load workload (scripts/transport_load.py) runs once with oidc claims
   and once with essential claims, each on a new stack, and the two runs are compared cell by
   cell. The network model's upload time saved per profile is calculated, not measured.

Outputs, in output_dir: claims.json (settings, environment, sizes, derived boundaries, measured
limits, the latency comparison, and evidence), written last; limits/ (gzip copies of the
size-limits stack's logs, and its nginx.conf); and latency-oidc/ and latency-essential/, each
exactly what `load --output-dir` writes. claims.json, load.json, raw.csv.gz, app.log, and
proxy-access.log hold no token; browser.log holds the tokens of the size-limits phase, and
proxy-error.log may hold nginx's truncated prefix of a rejected header line.

Every signing key is an ephemeral experiment key, generated in memory (by this process for the
token sizes, and by each stack's application for every token it sends) and never saved; none is
a production credential. Use run_claims, or `scripts/transport_stack.py claims`.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import re
import shutil

from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.compact_jws import b64url_decode
from scripts.token_sizing import (CLAIM_SET_NAMES, REPO, claim_set, claim_set_path, padded_token,
                                  payload_bytes)
from scripts.transport_app import COOKIE_ATTRIBUTE_SETS
from scripts.transport_load import (LATENCY_COMPONENTS, NETWORK_PROFILES, RESULT_FILE as LOAD_FILE,
                                    check_seconds, checked_settings as checked_load_settings,
                                    run_environment, run_load, save_logs, write_load_results)
from scripts.transport_stack import (BROWSER_CHANNEL, load_manifest, manifest_layers, nginx_size,
                                     start_stack)
from scripts.transport_tokens import (LOG_FILES, TRANSPORTS, PairRun, browser_identity, judge,
                                      read_lines, run_pair, selected_algorithms,
                                      wait_for_proxy_log)


SCHEMA_VERSION = 1
RESULT_FILE = "claims.json"
# The two claim sets the mitigation compares: the realistic fixture, then the smaller one.
COMPARED = ("oidc", "essential")
# The latency workload's reference configuration, measured in every run, as in S3-01.
REFERENCE = "ES256"
LATENCY_TRANSPORT = "bearer"
# Production cookie attributes, as in S2-04's ML-DSA-44 headroom measurement.
COOKIE_ATTRIBUTES = "full"
LIMITS_DIR = "limits"
LATENCY_DIRS = {"oidc": "latency-oidc", "essential": "latency-essential"}

# The committed Sprint 2 sweeps whose boundaries the token sizes are compared with: each run's
# directory and the transport it swept. cookie-16k reproduces the Mac's nginx buffers on WSL2.
SPRINT2_RUN = Path("results") / "transport" / "20261113T074114Z-wsl2"
SPRINT2_SWEEPS = (("cookie-default", "cookie"), ("cookie-16k", "cookie"),
                  ("bearer-default", "bearer"))

# Base64url text in judge's evidence that may be part of a token: a prefix that
# transport_tokens.quote kept before "[...]", any run that starts like base64url-encoded JSON
# ("eyJ"), and any other run of 40 or more characters. Nonces (32 hex digits) are kept.
TOKEN_TEXT = re.compile(r"[A-Za-z0-9_-]*\[\.\.\.\]|eyJ[A-Za-z0-9_-]*|[A-Za-z0-9_-]{40,}")
REMOVED_TOKEN = "[token removed]"


# --- Settings ---------------------------------------------------------------------------------


def default_settings() -> dict:
    """run_claims's keyword defaults, by setting name (the claims command's defaults too)."""
    parameters = inspect.signature(run_claims).parameters
    return {name: parameter.default for name, parameter in parameters.items()
            if name not in ("output_dir", "run_dir")}


def checked_settings(algorithms, clients, concurrency, duration, warmup, timeout,
                     header_buffers, upstream_keepalive) -> dict:
    """Check run_claims's settings and return them as claims.json records them.

    Raises ValueError for any invalid value. Algorithms, clients, concurrency, duration, and
    warm-up are checked as the load command checks them, so the measured configurations are the
    selected ones plus the reference ES256, in ADAPTER_LIST order. Passing the result back as
    run_claims(output_dir, **settings) repeats the run.
    """
    check_seconds("timeout", timeout, allow_zero=False)  # Finite, unlike check_timeout.
    if header_buffers is not None:
        nginx_size("header_buffers", header_buffers)
    # The latency runs differ only in their claim set, so checking one of them checks both.
    workload = checked_load_settings(algorithms, LATENCY_TRANSPORT, clients, concurrency,
                                     duration, warmup, "essential", REFERENCE, False, timeout,
                                     None, header_buffers, upstream_keepalive)
    return {"algorithms": workload["algorithms"], "clients": workload["clients"],
            "concurrency": workload["concurrency"], "duration": duration, "warmup": warmup,
            "timeout": timeout, "header_buffers": header_buffers,
            "upstream_keepalive": upstream_keepalive}


def check_output_dir(output_dir) -> Path:
    """Return output_dir as a Path; raise ValueError if it exists and is not an empty directory."""
    output_dir = Path(output_dir)
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ValueError(f"output_dir {output_dir} exists and is not an empty directory")
    return output_dir


def read_saved_settings(path: Path) -> dict:
    """Return the settings object of a claims.json written by an earlier run.

    Raises ValueError when the file cannot be read, has no settings object, or names a setting
    run_claims does not take. The values are checked by checked_settings once they are combined
    with the command line.
    """
    try:
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from None
    settings = saved.get("settings") if isinstance(saved, dict) else None
    if not isinstance(settings, dict):
        raise ValueError(f"{path} has no settings object; give the claims.json of an earlier run")
    unknown = sorted(set(settings) - set(default_settings()))
    if unknown:
        raise ValueError(f"{path} has unknown settings {', '.join(map(repr, unknown))}")
    return settings


# --- Phase 1: token sizes ---------------------------------------------------------------------


def signature_bytes(token: str) -> int:
    """Length of the raw signature carried in a compact token's third segment."""
    return len(b64url_decode(token.split(".")[2]))


def fixed_bytes(token: str) -> int:
    """Bytes of a compact token outside its payload segment: header, signature, and both dots."""
    return len(token) - len(token.split(".")[1])


def token_size_row(algorithm: str) -> dict:
    """Sign every claims fixture, unpadded, with a fresh experiment key, and record the sizes."""
    adapter = ADAPTERS[algorithm]
    private_key, public_key = adapter.generate_keypair()
    # Given the public key, padded_token verifies each token with its own aud as the audience,
    # and it checks the token's length against token_sizing.token_bytes.
    tokens = {name: padded_token(algorithm, claim_set(name), 0, private_key, public_key)
              for name in CLAIM_SET_NAMES}
    signature = signature_bytes(tokens["essential"])
    if signature != adapter.expected_signature_bytes:
        raise RuntimeError(f"{algorithm}: the signature is {signature} bytes, expected "
                           f"{adapter.expected_signature_bytes}")
    sizes = {name: len(token) for name, token in tokens.items()}
    shrink = sizes["oidc"] - sizes["essential"]
    return {"algorithm": algorithm, "signature_bytes": signature,
            "fixed_bytes": fixed_bytes(tokens["essential"]), "token_bytes": sizes,
            "shrink_bytes": shrink, "shrink_percent": 100 * shrink / sizes["oidc"]}


def token_sizes(algorithms: Sequence[str] | None = None) -> list[dict]:
    """Return one row of token sizes per configuration, in ADAPTER_LIST order.

    None means all six. Raises ValueError for an unknown, repeated, or empty selection; no
    reference configuration is added.
    """
    selected = selected_algorithms(algorithms)
    return [token_size_row(adapter.name) for adapter in ADAPTER_LIST if adapter.name in selected]


# --- Phase 2: Sprint 2 boundaries, derived ----------------------------------------------------


def largest_verified_token_bytes(source: Path) -> int:
    """The largest token that verified anywhere in a committed Sprint 2 sweep.json."""
    try:
        sweep = json.loads((REPO / source).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise RuntimeError(f"cannot read the Sprint 2 sweep {source.as_posix()}: {error}") from None
    results = sweep.get("results") if isinstance(sweep, dict) else None
    verified = [result.get("largest_verified_token_bytes") for result in results or []
                if isinstance(result, dict)]
    verified = [size for size in verified if isinstance(size, int)]
    if not verified:
        raise RuntimeError(f"the Sprint 2 sweep {source.as_posix()} has no verified token")
    return max(verified)


def boundary_row(size_row: dict, largest_verified: int) -> dict:
    """Whether one configuration's oidc and essential tokens fit under a Sprint 2 boundary."""
    token_bytes = size_row["token_bytes"]
    fits = {name: token_bytes[name] <= largest_verified for name in COMPARED}
    return {"algorithm": size_row["algorithm"], "fits": fits,
            "headroom_bytes": {name: largest_verified - token_bytes[name] for name in COMPARED},
            "moved": fits["oidc"] != fits["essential"]}


def sprint2_boundaries(sizes: list[dict]) -> list[dict]:
    """Compare token sizes with the cookie-default, cookie-16k, and bearer-default boundaries.

    Each boundary is the largest token that verified in that committed WSL2 sweep, read from its
    sweep.json, so the verdicts are derived from Sprint 2's measurements, not measured here.
    Raises RuntimeError if a sweep.json is missing or unreadable.
    """
    entries = []
    for name, transport in SPRINT2_SWEEPS:
        source = SPRINT2_RUN / name / "sweep.json"
        largest_verified = largest_verified_token_bytes(source)
        entries.append({"name": name, "transport": transport, "source": source.as_posix(),
                        "largest_verified_token_bytes": largest_verified,
                        "rows": [boundary_row(row, largest_verified) for row in sizes]})
    return entries


# --- Phase 3: size limits, measured at the documented defaults --------------------------------


def issue_query(transport: str, claims: str) -> dict:
    """The issue parameters of one pair: its claim set, plus production attributes for cookies."""
    if transport == "cookie":
        return {"claims": claims, "attrs": COOKIE_ATTRIBUTES}
    return {"claims": claims}


def without_tokens(text: str) -> str:
    """Remove every token-like base64url run from evidence text, kept prefixes included."""
    return TOKEN_TEXT.sub(REMOVED_TOKEN, text)


def send_pairs(stack, algorithms: list[str], timeout: float) -> tuple[dict, list[PairRun]]:
    """Send every configuration's oidc and essential token in both transports from Chromium.

    The order is configuration, then transport, then claim set. Returns the browser's identity
    and the pairs as observed, before any log is read.
    """
    from playwright.sync_api import Error as PlaywrightError, sync_playwright  # Checked first.

    log_path = Path(stack.run_dir) / "logs" / LOG_FILES["browser"]
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=timeout * 1000)
            try:
                identity = browser_identity(browser)
                runs = [run_pair(browser, stack, algorithm, transport, timeout, log_path,
                                 issue_query(transport, claims))
                        for algorithm in algorithms for transport in TRANSPORTS
                        for claims in COMPARED]
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error
    return identity, runs


def judge_pairs(stack, runs: list[PairRun]) -> list[dict]:
    """Judge each pair from every layer's log, once nginx has logged every answered request."""
    log_dir = Path(stack.run_dir) / "logs"
    answered = [request.nonce for run in runs for request in (run.issue, run.verify)
                if request.status is not None]
    wait_for_proxy_log(log_dir / LOG_FILES["proxy_access"], answered)
    logs = {key: read_lines(log_dir / name) for key, name in LOG_FILES.items()}
    layers = {layer["role"]: layer for layer in load_manifest()["layers"]}
    return [judge(run, logs, layers) for run in runs]


def limits_result(run: PairRun, judged: dict) -> dict:
    """One pair's entry in claims.json, with tokens removed from its evidence."""
    return {"algorithm": judged["algorithm"], "transport": judged["transport"],
            "claims": run.issue_query["claims"], "token_bytes": judged["token_bytes"],
            "outcome": judged["outcome"], "rejected_by": judged["rejected_by"],
            "verified_directly": judged["direct"]["verified"],
            "cookie_stored": judged["cookie_stored"], "issue_nonce": judged["issue"]["nonce"],
            "verify_nonce": judged["verify"]["nonce"],
            "evidence": without_tokens(judged["evidence"])}


def moved_entries(results: list[dict]) -> list[dict]:
    """One entry per configuration and transport: its oidc and essential outcomes."""
    outcomes = {(entry["algorithm"], entry["transport"], entry["claims"]): entry["outcome"]
                for entry in results}
    pairs = dict.fromkeys((entry["algorithm"], entry["transport"]) for entry in results)
    entries = []
    for algorithm, transport in pairs:  # In the order the pairs were sent.
        oidc, essential = (outcomes[(algorithm, transport, name)] for name in COMPARED)
        entries.append({"algorithm": algorithm, "transport": transport, "oidc": oidc,
                        "essential": essential, "moved": oidc != essential})
    return entries


def save_stack_evidence(run_dir: Path, target_dir: Path) -> dict:
    """Save gzip copies of a stack's logs and its nginx.conf; return paths relative to target's
    parent, as claims.json's evidence lists them."""
    saved_logs = save_logs(Path(run_dir) / "logs", target_dir / "logs")
    shutil.copy2(Path(run_dir) / "nginx" / "nginx.conf", target_dir / "nginx.conf")
    return {"logs": {name: f"{target_dir.name}/{path}" for name, path in saved_logs.items()},
            "nginx_conf": f"{target_dir.name}/nginx.conf"}


def run_limits(output_dir: Path, settings: dict, run_dir: Path | None) -> tuple[dict, dict, dict]:
    """Phase 3: send every pair through a stack at the documented default limits.

    Returns claims.json's limits object, the browser's identity, and the saved evidence.
    """
    with start_stack(run_dir=run_dir, timeout=settings["timeout"]) as stack:  # No raised limit.
        identity, runs = send_pairs(stack, settings["algorithms"], settings["timeout"])
        judged = judge_pairs(stack, runs)
        evidence = save_stack_evidence(stack.run_dir, output_dir / LIMITS_DIR)
    results = [limits_result(run, entry) for run, entry in zip(runs, judged)]
    limits = {"cookie_attributes": COOKIE_ATTRIBUTE_SETS[COOKIE_ATTRIBUTES], "results": results,
              "moved": moved_entries(results)}
    return limits, identity, evidence


# --- Phase 4: latency, the S3-01 workload -----------------------------------------------------


def run_latency(output_dir: Path, settings: dict, claims: str, run_dir: Path | None) -> dict:
    """Run the S3-01 Bearer workload with one claim set on a new stack; return its load.json.

    The results are saved exactly as `load --output-dir` saves them, so `load --settings
    <dir>/load.json` repeats the run. The stack is stopped before this returns.
    """
    target = output_dir / LATENCY_DIRS[claims]
    with start_stack(run_dir=run_dir, timeout=settings["timeout"],
                     header_buffers=settings["header_buffers"],
                     upstream_keepalive=settings["upstream_keepalive"]) as stack:
        result = run_load(stack, algorithms=settings["algorithms"], transport=LATENCY_TRANSPORT,
                          clients=settings["clients"], concurrency=settings["concurrency"],
                          duration=settings["duration"], warmup=settings["warmup"],
                          claims=claims, reference=REFERENCE, size_controls=False,
                          timeout=settings["timeout"], header_buffers=settings["header_buffers"],
                          upstream_keepalive=settings["upstream_keepalive"])
        write_load_results(result, target)
    return json.loads((target / LOAD_FILE).read_text(encoding="utf-8"))


def by_claim_set(oidc, essential) -> dict:
    """One value from the oidc run and one from the essential run, keyed by claim set."""
    return {"oidc": oidc, "essential": essential}


def total_ms(cell: dict, statistic: str) -> float | None:
    """A cell's median_ms or p95_ms of total latency; None if no request verified."""
    return None if cell["latency"] is None else cell["latency"]["total"][statistic]


def mean_components_ms(cell: dict) -> dict | None:
    """A cell's mean of each latency component, in ms; None if no request verified."""
    if cell["latency"] is None:
        return None
    return {component: cell["latency"][component]["mean_ms"] for component in LATENCY_COMPONENTS}


def latency_row(oidc_cell: dict, essential_cell: dict) -> dict:
    """Compare one configuration's token cell across the two runs (essential minus oidc)."""
    def paired(key: str) -> dict:
        return by_claim_set(oidc_cell[key], essential_cell[key])

    means = by_claim_set(mean_components_ms(oidc_cell), mean_components_ms(essential_cell))
    difference = None
    if means["oidc"] is not None and means["essential"] is not None:
        difference = {component: means["essential"][component] - means["oidc"][component]
                      for component in LATENCY_COMPONENTS}
    return {"client": oidc_cell["client"], "concurrency": oidc_cell["concurrency"],
            "algorithm": oidc_cell["algorithm"], "token_bytes": paired("token_bytes"),
            "verified": paired("verified"), "failed": paired("failed"),
            "throughput_rps": paired("throughput_rps"),
            "median_ms": by_claim_set(total_ms(oidc_cell, "median_ms"),
                                      total_ms(essential_cell, "median_ms")),
            "p95_ms": by_claim_set(total_ms(oidc_cell, "p95_ms"),
                                   total_ms(essential_cell, "p95_ms")),
            "mean_ms": means, "difference_ms": difference}


def network_savings(oidc_run: dict, essential_run: dict) -> list[dict]:
    """Per configuration, the request bytes of both runs and the modeled upload time saved.

    The upload times come from each load.json's network model, so they are calculated, not
    measured.
    """
    essential_rows = {row["algorithm"]: row for row in essential_run["network_model"]["rows"]}
    entries = []
    for oidc_row in oidc_run["network_model"]["rows"]:
        essential_row = essential_rows[oidc_row["algorithm"]]
        oidc_ms, essential_ms = ({(item["uplink_mbps"], item["rtt_ms"]): item["transfer_ms"]
                                  for item in row["modeled"]}
                                 for row in (oidc_row, essential_row))
        modeled = []
        for profile in NETWORK_PROFILES:
            key = (profile["uplink_mbps"], profile["rtt_ms"])
            modeled.append({**profile, "saved_ms": oidc_ms[key] - essential_ms[key]})
        entries.append({"algorithm": oidc_row["algorithm"],
                        "request_bytes": by_claim_set(oidc_row["request_bytes"],
                                                      essential_row["request_bytes"]),
                        "saved_bytes": oidc_row["request_bytes"] - essential_row["request_bytes"],
                        "modeled": modeled})
    return entries


def compare_latency(oidc_run: dict, essential_run: dict) -> dict:
    """Compare the oidc and essential load.json results cell by cell; claims.json's latency."""
    essential_cells = {(cell["client"], cell["concurrency"], cell["algorithm"]): cell
                       for cell in essential_run["results"] if cell["variant"] == "token"}
    rows = [latency_row(cell, essential_cells[(cell["client"], cell["concurrency"],
                                               cell["algorithm"])])
            for cell in oidc_run["results"] if cell["variant"] == "token"]
    return {"transport": LATENCY_TRANSPORT, "reference": REFERENCE, "size_controls": False,
            "runs": {claims: f"{LATENCY_DIRS[claims]}/{LOAD_FILE}" for claims in COMPARED},
            "rows": rows, "network_model": network_savings(oidc_run, essential_run)}


# --- The run ----------------------------------------------------------------------------------


def claim_set_entries() -> list[dict]:
    """Describe the minimal, oidc, and essential fixtures: file, claim names, and payload bytes."""
    entries = []
    for name in CLAIM_SET_NAMES:
        claims = claim_set(name)
        entries.append({"name": name, "file": claim_set_path(name).relative_to(REPO).as_posix(),
                        "claims": list(claims), "payload_bytes": payload_bytes(claims)})
    return entries


def phase_run_dir(run_dir, name: str) -> Path | None:
    """The run directory of one phase's stack under run_dir; None lets start_stack pick one."""
    return None if run_dir is None else Path(run_dir) / name


def require_playwright() -> None:
    """Raise RuntimeError("automation: ...") unless Playwright can be imported."""
    try:
        import playwright.sync_api  # noqa: F401  Only checks that it can be imported.
    except ImportError as error:
        raise RuntimeError(f"automation: Playwright is not installed ({error})") from error


def run_claims(output_dir, algorithms: Sequence[str] | None = None,
               clients: Sequence[str] | None = None, concurrency: Sequence[int] = (1, 4),
               duration: float = 5.0, warmup: float = 1.0, timeout: float = 60.0,
               header_buffers: str | None = None, upstream_keepalive: int | None = None,
               run_dir=None) -> dict:
    """Run all four phases into output_dir, write claims.json last, and return what it holds.

    algorithms, clients, concurrency, duration, and warmup mean what they mean for run_load;
    header_buffers and upstream_keepalive configure only the two latency stacks, because the
    size-limits stack keeps the documented defaults. run_dir, if given, holds the three stacks'
    run directories (limits, latency-oidc, and latency-essential). Raises ValueError for any
    invalid argument, or an output_dir that exists and is not empty, before any process starts,
    and RuntimeError when a layer, Playwright, or a committed Sprint 2 sweep fails.
    """
    settings = checked_settings(algorithms, clients, concurrency, duration, warmup, timeout,
                                header_buffers, upstream_keepalive)
    output_dir = check_output_dir(output_dir)
    require_playwright()

    started = datetime.now(timezone.utc)
    environment = run_environment()  # Includes the git commit the run starts from.
    sizes = token_sizes(settings["algorithms"])
    boundaries = sprint2_boundaries(sizes)
    output_dir.mkdir(parents=True, exist_ok=True)
    limits, browser, limits_evidence = run_limits(output_dir, settings,
                                                  phase_run_dir(run_dir, LIMITS_DIR))
    latency_runs = {claims: run_latency(output_dir, settings, claims,
                                        phase_run_dir(run_dir, LATENCY_DIRS[claims]))
                    for claims in COMPARED}
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
        "claim_sets": claim_set_entries(),
        "sizes": sizes,
        "boundaries": boundaries,
        "limits": limits,
        "latency": compare_latency(latency_runs["oidc"], latency_runs["essential"]),
        "evidence": {"limits": limits_evidence,
                     "latency": {claims: f"{LATENCY_DIRS[claims]}/{LOAD_FILE}"
                                 for claims in COMPARED}},
    }
    write_claims_results(result, output_dir)
    return result


# --- Output -----------------------------------------------------------------------------------


def write_claims_results(result: dict, output_dir: Path) -> Path:
    """Save the result as claims.json in output_dir and return its path."""
    path = Path(output_dir) / RESULT_FILE
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path


def size_lines(result: dict, width: int) -> list[str]:
    """One line per configuration: its token sizes and how much the essential claims save."""
    lines = []
    for row in result["sizes"]:
        sizes = row["token_bytes"]
        lines.append(f"size     {row['algorithm']:<{width}}  minimal {sizes['minimal']:>6,} B  "
                     f"oidc {sizes['oidc']:>6,} B  essential {sizes['essential']:>6,} B  "
                     f"saves {row['shrink_bytes']:,} B ({row['shrink_percent']:.1f}% of oidc)")
    return lines


def boundary_lines(result: dict, width: int) -> list[str]:
    """One line per Sprint 2 boundary and configuration: headroom and fit, derived from WSL2."""
    def verdict(row: dict, name: str) -> str:
        fits = "fits" if row["fits"][name] else "over"
        return f"{name} {row['headroom_bytes'][name]:>+7,} B {fits}"

    labels = [f"{entry['name']} {entry['largest_verified_token_bytes']:,} B"
              for entry in result["boundaries"]]
    label_width = max(map(len, labels), default=0)
    lines = []
    for label, entry in zip(labels, result["boundaries"]):
        for row in entry["rows"]:
            moved = "  moved" if row["moved"] else ""
            lines.append(f"sprint2  {label:<{label_width}}  {row['algorithm']:<{width}}  "
                         f"{verdict(row, 'oidc')}  {verdict(row, 'essential')}{moved}")
    return lines


def limits_lines(result: dict, width: int) -> list[str]:
    """One line per configuration and transport: its measured oidc and essential outcomes."""
    pairs = {(entry["algorithm"], entry["transport"], entry["claims"]): entry
             for entry in result["limits"]["results"]}

    def observed(entry: dict) -> str:
        outcome = (f"rejected by {entry['rejected_by']}" if entry["outcome"] == "rejected"
                   else entry["outcome"])
        return f"{entry['claims']} {entry['token_bytes']:>6,} B {outcome:<23}"

    lines = []
    for entry in result["limits"]["moved"]:
        oidc, essential = (pairs[(entry["algorithm"], entry["transport"], name)]
                           for name in COMPARED)
        moved = "  moved" if entry["moved"] else ""
        lines.append(f"limits   {entry['transport']:<6} {entry['algorithm']:<{width}}  "
                     f"{observed(oidc)} {observed(essential)}".rstrip() + moved)
    return lines


def latency_lines(result: dict, width: int) -> list[str]:
    """One line per latency row: oidc -> essential mean, median, p95, and throughput."""
    lines = []
    for row in result["latency"]["rows"]:
        label = (f"latency  {row['client']:<7} c={row['concurrency']:<3} "
                 f"{row['algorithm']:<{width}}  "
                 f"{row['token_bytes']['oidc']:>6,} -> {row['token_bytes']['essential']:>6,} B")
        difference = row["difference_ms"]
        if difference is None:
            lines.append(f"{label}  no verified request in at least one run")
            continue
        means, medians, p95s = row["mean_ms"], row["median_ms"], row["p95_ms"]
        throughput = row["throughput_rps"]
        line = (f"{label}  mean {means['oidc']['total']:.3f} -> "
                f"{means['essential']['total']:.3f} ms ({difference['total']:+.3f})  "
                f"median {medians['oidc']:.3f} -> {medians['essential']:.3f}  "
                f"p95 {p95s['oidc']:.3f} -> {p95s['essential']:.3f}  "
                f"{throughput['oidc']:,.1f} -> {throughput['essential']:,.1f} req/s")
        failed = row["failed"]["oidc"] + row["failed"]["essential"]
        if failed:
            line += f"  {failed:,} failed"
        lines.append(line)
    return lines


def summary_lines(result: dict) -> list[str]:
    """The claims command's printed summary, from claims.json alone; every line names its
    configuration: sizes, derived Sprint 2 verdicts, measured limits, then latency."""
    width = max(len(row["algorithm"]) for row in result["sizes"])
    return [*size_lines(result, width), *boundary_lines(result, width),
            *limits_lines(result, width), *latency_lines(result, width)]
