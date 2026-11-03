"""Benchmark JWT signing and verification for every configuration and export raw data.

Writes run.json (settings and environment), raw.csv (one row per measured operation),
and summary.json (sizes and median/p95 per algorithm) to one run directory.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter_ns

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.backends.openssl.backend import backend
from jwt.utils import base64url_decode

from scripts.algorithms import ADAPTERS, Adapter
from scripts.rsa_jwt import summarize


REPO = Path(__file__).resolve().parents[1]
DEFAULT_CLAIMS = REPO / "fixtures" / "claims.json"
SCHEMA_VERSION = 1
RAW_FIELDS = ("run_id", "algorithm", "parameter_set", "operation", "iteration", "duration_ns")


def environment() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                                text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "scripts", "fixtures"],
                                    cwd=REPO, capture_output=True, text=True, check=True).stdout)
    except (OSError, subprocess.CalledProcessError):
        commit, dirty = None, None
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "cryptography": version("cryptography"),
        "pyjwt": version("PyJWT"),
        "pqcrypto": version("pqcrypto"),
        "openssl": backend.openssl_version_text(),
        "timer": "perf_counter_ns",
        "git_commit": commit,
        "git_dirty_scripts_or_fixtures": dirty,
    }


def benchmark_adapter(adapter: Adapter, claims: dict, iterations: int, warmup: int) -> dict:
    """Time raw sign/verify over one prepared signing input; keys and JOSE work are untimed."""
    start = perf_counter_ns()
    private_key, public_key = adapter.generate_keypair()
    key_generation_ns = perf_counter_ns() - start

    token = adapter.create_token(claims, private_key)
    if adapter.verify_token(token, public_key) != claims:
        raise ValueError(f"{adapter.name}: verified claims differ from the original fixture")
    header_segment, payload_segment, signature_segment = token.split(".")
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")

    # Every measured signature is verified; verify_raw raises if one is invalid.
    sign_ns, verify_ns = [], []
    for iteration in range(warmup + iterations):
        start = perf_counter_ns()
        signature = adapter.sign_raw(private_key, signing_input)
        signing = perf_counter_ns() - start

        start = perf_counter_ns()
        adapter.verify_raw(public_key, signing_input, signature)
        verification = perf_counter_ns() - start

        if iteration >= warmup:
            sign_ns.append(signing)
            verify_ns.append(verification)

    return {
        **adapter.metadata(),
        "iterations": iterations,
        "warmup": warmup,
        "sizes_bytes": {
            "payload": len(base64url_decode(payload_segment.encode("ascii"))),
            "signature": len(base64url_decode(signature_segment.encode("ascii"))),
            "jwt": len(token.encode("ascii")),
        },
        "key_generation_ms": key_generation_ns / 1_000_000,
        "sign": {**summarize(sign_ns), "n": len(sign_ns)},
        "verify": {**summarize(verify_ns), "n": len(verify_ns)},
        "verified": True,
        "token": token,
        "samples": {"sign": sign_ns, "verify": verify_ns},
    }


def claims_reference(path: Path) -> str:
    resolved = path.resolve()
    return resolved.relative_to(REPO).as_posix() if resolved.is_relative_to(REPO) else str(resolved)


def run(settings: dict, output_dir: Path | None = None) -> Path:
    """Run a benchmark with the given settings and return the run directory."""
    names = settings["algorithms"]
    unknown = [name for name in names if name not in ADAPTERS]
    if unknown:
        raise ValueError(f"unknown algorithms: {', '.join(unknown)}")
    overrides = settings.get("iterations_per_algorithm", {})
    counts = {name: overrides.get(name, settings["iterations"]) for name in names}
    if min(counts.values()) < 1 or settings["warmup"] < 0:
        raise ValueError("iterations must be positive and warmup must be nonnegative")

    claims_path = Path(settings["claims_file"])
    if not claims_path.is_absolute():
        claims_path = REPO / claims_path
    claims_bytes = claims_path.read_bytes()
    claims = json.loads(claims_bytes)
    if not isinstance(claims, dict):
        raise ValueError("claims must contain a JSON object")
    settings = {**settings, "claims_file": claims_reference(claims_path),
                "claims_sha256": hashlib.sha256(claims_bytes).hexdigest()}

    started = datetime.now(timezone.utc)
    run_id = started.strftime("%Y%m%dT%H%M%S%fZ")
    results = [benchmark_adapter(ADAPTERS[name], claims, counts[name], settings["warmup"])
               for name in names]
    finished = datetime.now(timezone.utc)

    # File output happens only after every timed loop has finished.
    output_dir = output_dir or REPO / "results" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    run_info = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "settings": settings,
        "measurement_scope": "raw signature operations on a prepared JWT signing input; "
                             "key generation, JOSE encoding/decoding, and file output excluded",
        "environment": environment(),
    }
    (output_dir / "run.json").write_text(json.dumps(run_info, indent=2) + "\n", encoding="utf-8")
    with (output_dir / "raw.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(RAW_FIELDS)
        for result in results:
            for operation in ("sign", "verify"):
                for iteration, duration in enumerate(result["samples"][operation], start=1):
                    writer.writerow((run_id, result["algorithm"], result["parameter_set"],
                                     operation, iteration, duration))
    summary = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "algorithms": [{key: value for key, value in result.items() if key != "samples"}
                       for result in results],
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n",
                                             encoding="utf-8")
    return output_dir


def parse_override(text: str) -> tuple[str, int]:
    name, separator, count = text.rpartition("=")
    if not separator or not count.isdigit():
        raise argparse.ArgumentTypeError("expected ALGORITHM=ITERATIONS")
    return name, int(count)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--settings", type=Path,
                        help="reuse the settings from a previous run.json; other flags override")
    parser.add_argument("--algorithms", nargs="+", choices=list(ADAPTERS),
                        help="configurations to run (default: all)")
    parser.add_argument("--iterations", type=int, help="measured iterations (default: 100)")
    parser.add_argument("--warmup", type=int, help="unrecorded warm-up iterations (default: 10)")
    parser.add_argument("--iterations-per-algorithm", type=parse_override, nargs="+",
                        metavar="ALG=N", help="override measured iterations for an algorithm")
    parser.add_argument("--claims", type=Path, help="JSON object containing JWT claims")
    parser.add_argument("--output-dir", type=Path,
                        help="directory for the run files (default: results/<run_id>)")
    args = parser.parse_args()

    settings = {"algorithms": list(ADAPTERS), "iterations": 100, "warmup": 10,
                "iterations_per_algorithm": {}, "claims_file": str(DEFAULT_CLAIMS)}
    try:
        if args.settings:
            saved = json.loads(args.settings.read_text(encoding="utf-8"))["settings"]
            settings.update({key: saved[key] for key in settings if key in saved})
        if args.algorithms:
            settings["algorithms"] = args.algorithms
        if args.iterations is not None:
            settings["iterations"] = args.iterations
        if args.warmup is not None:
            settings["warmup"] = args.warmup
        if args.iterations_per_algorithm:
            settings["iterations_per_algorithm"] = dict(args.iterations_per_algorithm)
        if args.claims:
            settings["claims_file"] = str(args.claims.resolve())
        for name in settings["iterations_per_algorithm"]:
            if name not in ADAPTERS:
                parser.error(f"unknown algorithm in --iterations-per-algorithm: {name}")
        output_dir = run(settings, args.output_dir)
    except (OSError, KeyError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    print(f"{'algorithm':<18} {'sig B':>6} {'JWT B':>6} {'n':>5} "
          f"{'sign med ms':>11} {'sign p95':>9} {'verify med':>10} {'verify p95':>10}")
    for row in summary["algorithms"]:
        print(f"{row['algorithm']:<18} {row['sizes_bytes']['signature']:>6} "
              f"{row['sizes_bytes']['jwt']:>6} {row['iterations']:>5} "
              f"{row['sign']['median_ms']:>11.4f} {row['sign']['p95_ms']:>9.4f} "
              f"{row['verify']['median_ms']:>10.4f} {row['verify']['p95_ms']:>10.4f}")
    print(f"Wrote {output_dir}")


if __name__ == "__main__":
    main()
