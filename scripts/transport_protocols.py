"""Repeat Sprint 2's cookie and Bearer sweeps over HTTPS and HTTP/2, and compare (S3-04).

A run repeats the four sweeps of `make sweep` (SWEEPS: cookie-default, cookie-16k,
bearer-default, and bearer-512k, each with its own nginx buffers, step, and maximum size) for
each selected protocol: "https" (HTTP/1.1 over TLS), "h2" (HTTP/2 over TLS, negotiated by ALPN
with `http2 on;`), and, only when asked for, "http" (plain HTTP/1.1, as Sprint 2 ran them).
Every (protocol, sweep) pair gets a new stack, start_tls_stack for https and h2 and start_stack
for http, with only that sweep's buffers. run_check runs first, so a TLS stack whose Chromium
request was not logged with the expected HTTP version (HTTP/1.1 for https, HTTP/2.0 for h2)
stops the run instead of recording invalid sweeps. run_sweep then sends the sweep's tokens, and
write_results saves it with its logs and nginx.conf in <output_dir>/<protocol>-<sweep>/.

The direct Bearer client (http.client) offers only HTTP/1.1 by ALPN, so in the h2 runs it is an
HTTP/1.1 control on the same h2-enabled listener, and only Chromium sends HTTP/2. Each run
records the HTTP version nginx logged for every request (negotiated), and compare_sweeps
compares every boundary with the baseline, Sprint 2's plain-HTTP/1.1 runs from WSL2
(DEFAULT_BASELINE), and the h2 boundaries with the https ones on the same machine.
protocols.json, written last, holds the settings, environment, every run's check and
negotiated versions, the certificate's details, the comparison, and links to the evidence.

Every TLS stack's certificate and private key are new, self-signed, and for 127.0.0.1 and
localhost only; the key is an ephemeral experiment key, not a production credential, deleted
when its stack stops and never saved. Tokens are signed with the application's ephemeral
experiment keys. Use run_protocols, or `scripts/transport_stack.py protocols`.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path

from scripts.algorithms import ADAPTER_LIST
from scripts.token_sizing import REPO
from scripts.transport_claims import check_output_dir, phase_run_dir, require_playwright
from scripts.transport_load import check_seconds, run_environment
from scripts.transport_stack import (load_manifest, manifest_layers, run_check, start_stack,
                                     start_tls_stack)
from scripts.transport_sweep import TRANSPORT_CLIENTS, run_sweep, write_results
from scripts.transport_tokens import selected_algorithms


SCHEMA_VERSION = 1
RESULT_FILE = "protocols.json"
PROTOCOLS = ("http", "https", "h2")
DEFAULT_PROTOCOLS = ("https", "h2")
# Sprint 2's plain-HTTP/1.1 runs on WSL2, which every boundary is compared with.
DEFAULT_BASELINE = REPO / "results" / "transport" / "20261113T074114Z-wsl2"
# The four sweeps of `make sweep`, in its order: transport, nginx buffers, step, and maximum.
SWEEPS = {
    "cookie-default": {"transport": "cookie", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24_576},
    "cookie-16k": {"transport": "cookie", "proxy_buffers": "16k", "header_buffers": None,
                   "step": 512, "max_bytes": 24_576},
    "bearer-default": {"transport": "bearer", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24_576},
    "bearer-512k": {"transport": "bearer", "proxy_buffers": None, "header_buffers": "512k",
                    "step": 16_384, "max_bytes": 327_680},
}
# Every sweep pads the minimal claims and uses the default cookie attributes, as make sweep does.
CLAIMS = "minimal"
ATTRS = "default"
CLIENT_ORDER = ("browser", "direct")
SWEEP_FILE = "sweep.json"


# --- Settings ---------------------------------------------------------------------------------


def ordered_names(name: str, values, choices: Sequence[str]) -> list[str]:
    """values as a list in the order of choices; ValueError if empty, unknown, or repeated."""
    if isinstance(values, str):
        raise ValueError(f"{name} must be a sequence of names, not the string {values!r}")
    try:
        values = list(values)
    except TypeError:
        raise ValueError(f"{name} must be a sequence of names, got {values!r}") from None
    if not values:
        raise ValueError(f"{name} must name at least one of {', '.join(choices)}")
    unknown = [value for value in values if not isinstance(value, str) or value not in choices]
    if unknown:
        raise ValueError(f"unknown {name} {unknown!r}; choose from {', '.join(choices)}")
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not repeat a name, got {values!r}")
    return [choice for choice in choices if choice in values]


def positive_bytes(name: str, value) -> int | None:
    """None, or a positive int number of bytes; ValueError otherwise."""
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
        raise ValueError(f"{name} must be a positive number of bytes, got {value!r}")
    return value


def baseline_directory(baseline) -> Path:
    """The baseline run directory as an absolute path; None means DEFAULT_BASELINE."""
    return DEFAULT_BASELINE if baseline is None else Path(baseline).absolute()


def recorded_path(path: Path) -> str:
    """A POSIX path relative to the repository when it is inside it, else absolute."""
    try:
        return path.resolve().relative_to(REPO.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def read_baseline(directory: Path, sweeps: Sequence[str]) -> dict[str, dict]:
    """Each selected sweep's baseline sweep.json; ValueError when one is missing or invalid."""
    baselines = {}
    for sweep in sweeps:
        path = directory / sweep / SWEEP_FILE
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"baseline {path} cannot be read: {error}") from None
        if not isinstance(saved, dict):
            raise ValueError(f"baseline {path} is not a JSON object")
        if saved.get("transport") != SWEEPS[sweep]["transport"]:
            raise ValueError(f"baseline {path} has transport {saved.get('transport')!r}, "
                             f"expected {SWEEPS[sweep]['transport']!r}")
        if not isinstance(saved.get("results"), list):
            raise ValueError(f"baseline {path} has no results list")
        baselines[sweep] = saved
    return baselines


def checked_settings(protocols, sweeps, algorithms, baseline, step, max_bytes,
                     timeout) -> dict:
    """Check run_protocols's settings and return them as protocols.json records them.

    Protocols, sweeps, and algorithms come back in PROTOCOLS, SWEEPS, and ADAPTER_LIST order;
    None means all four sweeps, all six algorithms, and DEFAULT_BASELINE. Raises ValueError
    for any invalid value, including a baseline without a valid <sweep>/sweep.json for every
    selected sweep.
    """
    protocols = ordered_names("protocols", protocols, PROTOCOLS)
    sweeps = ordered_names("sweeps", list(SWEEPS) if sweeps is None else sweeps, list(SWEEPS))
    selected = selected_algorithms(algorithms)
    algorithms = [adapter.name for adapter in ADAPTER_LIST if adapter.name in selected]
    positive_bytes("step", step)
    positive_bytes("max_bytes", max_bytes)
    check_seconds("timeout", timeout, allow_zero=False)
    directory = baseline_directory(baseline)
    read_baseline(directory, sweeps)
    return {"protocols": protocols, "sweeps": sweeps, "algorithms": algorithms,
            "baseline": recorded_path(directory), "step": step, "max_bytes": max_bytes,
            "timeout": timeout}


def sweep_definition(sweep: str, step: int | None, max_bytes: int | None) -> dict:
    """What one sweep runs with: its transport's default clients, the claims and attributes of
    make sweep, its own buffers, and its step and maximum unless overridden."""
    definition = SWEEPS[sweep]
    return {"transport": definition["transport"],
            "clients": list(TRANSPORT_CLIENTS[definition["transport"]]),
            "claims": CLAIMS, "attrs": ATTRS,
            "proxy_buffers": definition["proxy_buffers"],
            "header_buffers": definition["header_buffers"],
            "step": definition["step"] if step is None else step,
            "max_bytes": definition["max_bytes"] if max_bytes is None else max_bytes}


# --- Comparison -------------------------------------------------------------------------------


def entry_summary(entry: dict | None) -> dict | None:
    """One sweep entry's largest verified token, first rejection, and boundaries."""
    if entry is None:
        return None
    first = entry.get("first_rejection")
    return {
        "largest_verified_token_bytes": entry.get("largest_verified_token_bytes"),
        "first_rejection": (None if first is None else
                            {"token_bytes": first.get("token_bytes"),
                             "rejected_by": first.get("rejected_by")}),
        "boundaries": [{"token_bytes": boundary["first"].get("token_bytes"),
                        "outcome": boundary["first"].get("outcome"),
                        "rejected_by": boundary["first"].get("rejected_by")}
                       for boundary in entry.get("boundaries") or []],
    }


def entries_by_row(result: dict | None) -> dict[tuple[str, str], dict]:
    """A sweep result's entries by (algorithm, client); an entry without a client is Chromium's."""
    return {(entry["algorithm"], entry.get("client", "browser")): entry
            for entry in (result or {}).get("results") or []}


def is_bytes(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def differs(one: dict | None, other: dict | None) -> bool | None:
    """Whether two summaries' largest verified token or boundaries differ; None if one is None."""
    if one is None or other is None:
        return None
    return (one["largest_verified_token_bytes"] != other["largest_verified_token_bytes"]
            or one["boundaries"] != other["boundaries"])


def row_order(key: tuple[str, str]) -> tuple:
    names = [adapter.name for adapter in ADAPTER_LIST]
    algorithm, client = key
    return (names.index(algorithm) if algorithm in names else len(names), algorithm,
            CLIENT_ORDER.index(client) if client in CLIENT_ORDER else len(CLIENT_ORDER), client)


def compare_sweeps(sweep: str, baseline: dict | None, measured: dict[str, dict]) -> list[dict]:
    """Compare one sweep's measured boundaries with its baseline and with each other.

    baseline is a sweep.json object, or None; measured maps protocol names to run_sweep results
    or sweep.json objects. One row per (algorithm, client) in any measured result, in
    ADAPTER_LIST order and browser before direct. moved[p] is whether p's largest verified
    token or boundaries differ from the baseline's; difference_bytes[p] is p's largest minus
    the baseline's; moved_by_http2 compares h2 with https on the same machine. Raises
    ValueError for an unknown sweep or protocol, or a result of another transport.
    """
    if sweep not in SWEEPS:
        raise ValueError(f"unknown sweep {sweep!r}; choose from {', '.join(SWEEPS)}")
    unknown = [protocol for protocol in measured if protocol not in PROTOCOLS]
    if unknown:
        raise ValueError(f"unknown protocols {unknown!r}; choose from {', '.join(PROTOCOLS)}")
    transport = SWEEPS[sweep]["transport"]
    for name, result in [("baseline", baseline), *measured.items()]:
        if result is not None and result.get("transport") != transport:
            raise ValueError(f"the {name} result of {sweep} has transport "
                             f"{result.get('transport')!r}, expected {transport!r}")

    protocols = [protocol for protocol in PROTOCOLS if protocol in measured]
    measured_entries = {protocol: entries_by_row(measured[protocol]) for protocol in protocols}
    baseline_entries = entries_by_row(baseline)
    keys = sorted({key for entries in measured_entries.values() for key in entries},
                  key=row_order)
    rows = []
    for algorithm, client in keys:
        base = entry_summary(baseline_entries.get((algorithm, client)))
        summaries = {protocol: entry_summary(measured_entries[protocol].get((algorithm, client)))
                     for protocol in protocols}
        difference = {}
        for protocol, summary in summaries.items():
            largest = None if summary is None else summary["largest_verified_token_bytes"]
            base_largest = None if base is None else base["largest_verified_token_bytes"]
            difference[protocol] = (largest - base_largest
                                    if is_bytes(largest) and is_bytes(base_largest) else None)
        rows.append({
            "sweep": sweep, "algorithm": algorithm, "client": client, "baseline": base,
            "measured": summaries,
            "moved": {protocol: differs(summary, base) for protocol, summary in summaries.items()},
            "difference_bytes": difference,
            "moved_by_http2": differs(summaries.get("h2"), summaries.get("https")),
        })
    return rows


# --- The run ----------------------------------------------------------------------------------


def start_protocol_stack(protocol: str, definition: dict, run_dir: Path | None, timeout: float):
    """A new stack for one (protocol, sweep) pair, with only that sweep's buffers."""
    if protocol == "http":
        return start_stack(run_dir=run_dir, timeout=timeout,
                           proxy_buffers=definition["proxy_buffers"],
                           header_buffers=definition["header_buffers"])
    return start_tls_stack(protocol, run_dir=run_dir, timeout=timeout,
                           proxy_buffers=definition["proxy_buffers"],
                           header_buffers=definition["header_buffers"])


def run_evidence(name: str, saved: dict) -> dict:
    """The saved files of one run, relative to the output directory."""
    return {"sweep": f"{name}/{SWEEP_FILE}",
            "logs": {log: f"{name}/{path}" for log, path in saved["evidence"]["logs"].items()},
            "nginx_conf": f"{name}/{saved['evidence']['nginx_conf']}"}


def run_one(output_dir: Path, protocol: str, sweep: str, definition: dict,
            settings: dict, run_dir) -> tuple[dict, dict, dict]:
    """Check and sweep one (protocol, sweep) pair on its own stack, then save it.

    Returns the saved sweep.json, run_check's result, and the run's entry in protocols.json.
    The stack is stopped before the results are written, so the saved logs are complete.
    """
    name = f"{protocol}-{sweep}"
    with start_protocol_stack(protocol, definition, phase_run_dir(run_dir, name),
                              settings["timeout"]) as stack:
        check = run_check(stack, settings["timeout"])  # A wrong protocol stops the run here.
        result = run_sweep(stack, definition["transport"], settings["algorithms"],
                           definition["clients"], definition["claims"], definition["attrs"],
                           definition["step"], definition["max_bytes"], settings["timeout"],
                           definition["proxy_buffers"], definition["header_buffers"])
    write_results(result, output_dir / name)
    saved = json.loads((output_dir / name / SWEEP_FILE).read_text(encoding="utf-8"))
    entry = {"protocol": protocol, "sweep": sweep, "directory": name,
             "check": {"page_status": check["page"]["status"],
                       "negotiated_protocol": check.get("negotiated_protocol")},
             "negotiated": saved.get("negotiated"),
             "certificate": (saved.get("tls") or {}).get("certificate")}
    return saved, check, entry


def run_protocols(output_dir, protocols: Sequence[str] = DEFAULT_PROTOCOLS,
                  sweeps: Sequence[str] | None = None,
                  algorithms: Sequence[str] | None = None, baseline=None,
                  step: int | None = None, max_bytes: int | None = None,
                  timeout: float = 60.0, run_dir=None) -> dict:
    """Run every selected (protocol, sweep) pair into output_dir, write protocols.json last, and
    return what it holds.

    Protocols run in PROTOCOLS order and sweeps in SWEEPS order, whatever order they are given
    in, and algorithms in ADAPTER_LIST order. step and max_bytes, if given, override every
    sweep's own. run_dir, if given, holds each stack's run directory at
    <run_dir>/<protocol>-<sweep>. Raises ValueError for any invalid argument, or an output_dir
    that exists and is not empty, before any process starts or output_dir is created, and
    RuntimeError when a layer, Playwright, or a TLS stack's negotiated protocol fails. Every
    started process is stopped, and every experiment key deleted, before this returns or raises.
    """
    settings = checked_settings(protocols, sweeps, algorithms, baseline, step, max_bytes,
                                timeout)
    output_dir = check_output_dir(output_dir)
    baselines = read_baseline(baseline_directory(baseline), settings["sweeps"])
    definitions = {sweep: sweep_definition(sweep, step, max_bytes)
                   for sweep in settings["sweeps"]}
    require_playwright()

    started = datetime.now(timezone.utc)
    environment = run_environment()  # Includes the git commit the run starts from.
    output_dir.mkdir(parents=True, exist_ok=True)
    measured = {sweep: {} for sweep in settings["sweeps"]}
    runs, evidence, browser = [], {}, None
    for protocol in settings["protocols"]:
        for sweep in settings["sweeps"]:
            saved, check, entry = run_one(output_dir, protocol, sweep, definitions[sweep],
                                          settings, run_dir)
            if browser is None:
                browser = check["browser"]
            measured[sweep][protocol] = saved
            runs.append(entry)
            evidence[entry["directory"]] = run_evidence(entry["directory"], saved)
    finished = datetime.now(timezone.utc)

    result = {
        "schema_version": SCHEMA_VERSION,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "sweep_definitions": definitions,
        "environment": environment,
        "layers": manifest_layers(load_manifest()),
        "browser": browser,
        "experiment_keys": True,
        "runs": runs,
        "comparison": [row for sweep in settings["sweeps"]
                       for row in compare_sweeps(sweep, baselines[sweep], measured[sweep])],
        "evidence": evidence,
    }
    write_protocols_results(result, output_dir)
    return result


# --- Output -----------------------------------------------------------------------------------


def write_protocols_results(result: dict, output_dir: Path) -> Path:
    """Save the result as protocols.json in output_dir and return its path."""
    path = Path(output_dir) / RESULT_FILE
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path


def bytes_text(summary: dict | None) -> str:
    """A summary's largest verified token with thousands separators, or 'none'."""
    largest = None if summary is None else summary["largest_verified_token_bytes"]
    return f"{largest:,}" if is_bytes(largest) else "none"


def moved_text(row: dict, protocol: str) -> str:
    moved = row["moved"][protocol]
    if moved is None:
        return "no baseline" if row["baseline"] is None else "not measured"
    return "moved" if moved else "unchanged"


def negotiated_text(negotiated: dict | None) -> str:
    if negotiated is None:
        return "not recorded (plain HTTP)"
    return "; ".join(f"{client} " + ", ".join(f"{version} {count:,}"
                                               for version, count in counts.items())
                     for client, counts in negotiated.items())


def summary_lines(result: dict) -> list[str]:
    """The protocols command's printed summary, from a protocols.json object alone.

    One line per run (protocol, sweep, and the HTTP versions nginx logged), then one line per
    comparison row (sweep, algorithm, client, Sprint 2's and each protocol's largest verified
    token, and whether it moved).
    """
    lines = []
    for run in result["runs"]:
        check = run["check"]["negotiated_protocol"]
        lines.append(f"run      {run['protocol']:<5} {run['sweep']:<14}  check "
                     f"{check or 'plain HTTP/1.1'}  "
                     f"negotiated {negotiated_text(run['negotiated'])}")
    width = max((len(row["algorithm"]) for row in result["comparison"]), default=0)
    for row in result["comparison"]:
        parts = [f"{protocol} {bytes_text(summary)} {moved_text(row, protocol)}"
                 for protocol, summary in row["measured"].items()]
        lines.append(f"compare  {row['sweep']:<14} {row['algorithm']:<{width}} "
                     f"{row['client']:<7}  Sprint 2 {bytes_text(row['baseline'])}  "
                     + "  ".join(parts))
    return lines
