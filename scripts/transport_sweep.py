"""Sweep cookie-carried token sizes through the stack and find where each layer rejects them.

For each configuration, the sweep sends tokens grown with the padding claim of
scripts/token_sizing.py through browser -> nginx -> application, each in a new browser context,
using the same steps and the same layer attribution as the token check (run_pair and judge in
scripts/transport_tokens.py). It first probes coarse steps of token size, then binary-searches
the padding between every two neighbouring probes whose outcome or rejecting layer differs, so
each boundary is narrowed to one character of padding. Every probe is verified before it is
sent: the application signs it, and the same token is verified straight at the application.

Each probe records the bytes that each limit counts (S2-03): the token, the cookie's name +
value (Chromium's limit), the Set-Cookie header and the whole upstream response header block
(nginx's proxy_buffer_size), the Cookie header line (nginx's large_client_header_buffers), and
the request header block as Chromium reported it and as the application received it.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import shutil
from urllib.parse import urlsplit

from scripts.token_sizing import claim_set, pad_for_target, token_bytes
from scripts.transport_app import COOKIE_ATTRIBUTE_SETS, COOKIE_NAME
from scripts.transport_stack import BROWSER_CHANNEL, check_timeout, load_manifest, manifest_layers
from scripts.transport_tokens import (ISSUE_PATH, LOG_FILES, judge, nonce_url, read_lines,
                                      run_pair, selected_algorithms, wait_for_proxy_log)


DEFAULT_STEP = 512
DEFAULT_MAX_BYTES = 24_576


def response_header_bytes(url: str, timeout: float) -> tuple[int | None, int | None]:
    """Status code and size of the response header block the application sends for `url`.

    Counted as the status line, each `Name: value` line with CRLF, and the final CRLF: the
    bytes nginx must hold in proxy_buffer_size. Sent straight to the application.
    """
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    try:
        connection.request("GET", f"{parts.path}?{parts.query}")
        response = connection.getresponse()
        response.read()
        status_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
        lines = "".join(f"{name}: {value}\r\n" for name, value in response.getheaders())
        return response.status, len((status_line + lines + "\r\n").encode("latin-1"))
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        connection.close()


def browser_request_bytes(browser_log: Path, url: str) -> int | None:
    """Size of the request header block Chromium reported for `url`, from browser.log.

    Request line plus each `name: value` line with CRLF and the final CRLF. Chromium reports
    names in lowercase and its own order, which does not change the byte count.
    """
    for line in reversed(read_lines(browser_log)):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("event") == "request" and record.get("url") == url:
            parts = urlsplit(url)
            request_line = f"GET {parts.path}?{parts.query} HTTP/1.1\r\n"
            lines = "".join(f"{name}: {value}\r\n" for name, value in record["headers"].items())
            return len((request_line + lines + "\r\n").encode("latin-1"))
    return None


def probe(browser, stack, layers: dict, algorithm: str, query: dict, timeout: float) -> dict:
    """Send one padded token as a cookie through the stack; return its outcome and byte counts."""
    log_dir = Path(stack.run_dir) / "logs"
    run = run_pair(browser, stack, algorithm, "cookie", timeout, log_dir / LOG_FILES["browser"],
                   query)
    answered = [request.nonce for request in (run.issue, run.verify) if request.status is not None]
    wait_for_proxy_log(log_dir / LOG_FILES["proxy_access"], answered)
    logs = {key: read_lines(log_dir / name) for key, name in LOG_FILES.items()}
    result = judge(run, logs, layers)

    direct_url, _ = nonce_url(stack.app_url, ISSUE_PATH, alg=algorithm, delivery="cookie",
                              **run.issue_query)
    upstream_status, upstream_bytes = response_header_bytes(direct_url, timeout)
    set_cookie_bytes = (len(f"{COOKIE_NAME}=; {COOKIE_ATTRIBUTE_SETS[run.issue_query['attrs']]}")
                        + run.token_bytes)
    received = (run.verify.body or {}).get("received") or {}
    sent_cookie = received.get("cookie_bytes") is not None
    return {
        "pad": int(run.issue_query["pad"]),
        "token_bytes": run.token_bytes,
        "outcome": result["outcome"],
        "rejected_by": result["rejected_by"],
        "verified_directly": result["direct"]["verified"],
        "issue_status": result["issue"]["status"],
        # Set when fetch() failed; e.g. nginx forwards the headers but loses the body when the
        # upstream header block exactly fills proxy_buffer_size (browser.log has the net:: error).
        "issue_error": run.issue.error,
        "cookie_stored": result["cookie_stored"],
        "cookie_sent": sent_cookie,
        "verify_status": result["verify"]["status"],
        "bytes": {
            "cookie_name_value": len(COOKIE_NAME) + run.token_bytes,
            "set_cookie_value": set_cookie_bytes,
            "set_cookie_line": len("Set-Cookie: \r\n") + set_cookie_bytes,
            "upstream_response_headers": upstream_bytes,
            "cookie_line": len(f"Cookie: {COOKIE_NAME}=\r\n") + run.token_bytes,
            "browser_request_headers": browser_request_bytes(log_dir / LOG_FILES["browser"],
                                                             run.verify.url),
            "app_received_headers": received.get("header_bytes"),
        },
        "upstream_status": upstream_status,
        "evidence": result["evidence"],
        "issue_nonce": result["issue"]["nonce"],
        "verify_nonce": result["verify"]["nonce"],
    }


def outcome_class(entry: dict) -> tuple:
    return entry["outcome"], entry["rejected_by"]


def sweep_algorithm(send, algorithm: str, claims: dict, step: int, max_bytes: int) -> dict:
    """Probe coarse sizes, then narrow every change of outcome to one character of padding."""
    smallest = token_bytes(algorithm, claims)
    targets = [smallest] + list(range((smallest // step + 1) * step, max_bytes + 1, step))
    pads = sorted({pad_for_target(algorithm, claims, target) for target in targets})
    probes = {pad: send(pad) for pad in pads}

    boundaries = []
    for low, high in zip(pads, pads[1:]):
        if outcome_class(probes[low]) == outcome_class(probes[high]):
            continue
        while high - low > 1:  # Outcomes are assumed to change monotonically with size.
            middle = (low + high) // 2
            probes[middle] = send(middle)
            if outcome_class(probes[middle]) == outcome_class(probes[low]):
                low = middle
            else:
                high = middle
        boundaries.append({"last": probes[low], "first": probes[high]})

    ordered = [probes[pad] for pad in sorted(probes)]
    verified = [entry for entry in ordered if entry["outcome"] == "verified"]
    return {
        "algorithm": algorithm,
        "smallest_token_bytes": smallest,
        "largest_verified_token_bytes": verified[-1]["token_bytes"] if verified else None,
        "first_rejection": next(({"token_bytes": entry["token_bytes"],
                                  "rejected_by": entry["rejected_by"],
                                  "evidence": entry["evidence"]}
                                 for entry in ordered if entry["outcome"] != "verified"), None),
        "boundaries": boundaries,
        "probes": ordered,
    }


def run_cookie_sweep(stack, algorithms: Sequence[str] | None = None, claims: str = "minimal",
                     attrs: str = "default", step: int = DEFAULT_STEP,
                     max_bytes: int = DEFAULT_MAX_BYTES, timeout: float = 60.0,
                     proxy_buffers: str | None = None) -> dict:
    """Sweep each configuration's cookie-carried token sizes; return every probe and boundary."""
    names = selected_algorithms(algorithms)
    check_timeout(timeout)
    base_claims = claim_set(claims)
    if attrs not in COOKIE_ATTRIBUTE_SETS:
        raise ValueError(f"attrs must be one of {', '.join(COOKIE_ATTRIBUTE_SETS)}, got {attrs!r}")
    if isinstance(step, bool) or not isinstance(step, int) or step < 1:
        raise ValueError(f"step must be a positive number of bytes, got {step!r}")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError(f"max_bytes must be a positive number of bytes, got {max_bytes!r}")
    try:
        from playwright.sync_api import Error as PlaywrightError, sync_playwright
    except ImportError as error:
        raise RuntimeError(f"automation: Playwright is not installed ({error})") from error

    manifest = load_manifest()
    layers = {layer["role"]: layer for layer in manifest["layers"]}
    (Path(stack.run_dir) / "logs").mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True,
                                                 timeout=timeout * 1000)
            try:
                results = []
                for name in names:
                    def send(pad: int, name=name) -> dict:
                        query = {"claims": claims, "pad": pad, "attrs": attrs}
                        return probe(browser, stack, layers, name, query, timeout)
                    results.append(sweep_algorithm(send, name, base_claims, step, max_bytes))
                version = browser.version
            finally:
                browser.close()
    except PlaywrightError as error:
        raise RuntimeError(f"browser: {error}") from error

    return {
        "transport": "cookie",
        "settings": {"algorithms": names, "claims": claims, "attrs": attrs,
                     "cookie_attributes": COOKIE_ATTRIBUTE_SETS[attrs], "step": step,
                     "max_bytes": max_bytes, "proxy_buffers": proxy_buffers,
                     "padding": "pad claim of 'x' characters (scripts/token_sizing.py)"},
        "proxy_url": stack.proxy_url,
        "app_url": stack.app_url,
        "run_dir": str(stack.run_dir),
        "layers": manifest_layers(manifest),
        "browser_version": version,
        "results": results,
    }


def summary_lines(result: dict) -> list[str]:
    """One line per configuration: the largest verified token and the first rejection."""
    width = max(len(entry["algorithm"]) for entry in result["results"])
    lines = []
    for entry in result["results"]:
        largest = entry["largest_verified_token_bytes"]
        first = entry["first_rejection"]
        rejected = (f"first rejected {first['token_bytes']:>6,} bytes by {first['rejected_by']}"
                    if first else "no rejection up to the maximum")
        layers = " -> ".join(f"{b['first']['rejected_by']} at {b['first']['token_bytes']:,}"
                             for b in entry["boundaries"])
        lines.append(f"{entry['algorithm']:<{width}}  largest verified "
                     f"{(f'{largest:,}' if largest else 'none'):>6}  {rejected}"
                     f"{f'  (boundaries: {layers})' if layers else ''}")
    return lines


def write_results(result: dict, output_dir: Path) -> Path:
    """Save sweep.json with copies of the run's logs and rendered nginx.conf as its evidence."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(result["run_dir"])
    shutil.copytree(run_dir / "logs", output_dir / "logs", dirs_exist_ok=True)
    shutil.copy2(run_dir / "nginx" / "nginx.conf", output_dir / "nginx.conf")
    saved = {**result, "recorded_utc": datetime.now(timezone.utc).isoformat(),
             "evidence": {"logs": "logs/", "nginx_conf": "nginx.conf"}}
    (output_dir / "sweep.json").write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    return output_dir
