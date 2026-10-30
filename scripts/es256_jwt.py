"""Create an ES256 JWT and benchmark its ECDSA signing and verification operations."""

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import platform
import statistics
from time import perf_counter_ns

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from jwt.utils import base64url_decode


DEFAULT_CLAIMS = Path(__file__).resolve().parents[1] / "fixtures" / "claims.json"
ALGORITHM = "ES256"


def create_token(claims: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Create a compact JWT using ECDSA over P-256 with SHA-256."""
    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def verify_token(token: str, public_key: ec.EllipticCurvePublicKey) -> dict:
    """Verify the signature and claims, accepting only ES256."""
    return jwt.decode(token, public_key, algorithms=[ALGORITHM])


def summarize(samples: list[int]) -> dict:
    """Summarize nanosecond samples; p95 uses the nearest-rank definition."""
    return {
        "median_ms": statistics.median(samples) / 1_000_000,
        "p95_ms": sorted(samples)[math.ceil(0.95 * len(samples)) - 1] / 1_000_000,
    }


def run_benchmark(claims: dict, iterations: int = 100, warmup: int = 10) -> dict:
    """Time raw ECDSA operations over a prepared JWT signing input, excluding JOSE work."""
    if iterations < 1 or warmup < 0:
        raise ValueError("iterations must be positive and warmup must be nonnegative")

    start = perf_counter_ns()
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_generation_ns = perf_counter_ns() - start
    public_key = private_key.public_key()

    token = create_token(claims, private_key)
    if verify_token(token, public_key) != claims:
        raise ValueError("verified claims differ from the original fixture")
    header_segment, payload_segment, signature_segment = token.split(".")
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    # JWS carries the fixed-width R || S form (RFC 7518, section 3.4), which sets the
    # reported size; the timed loop uses cryptography's variable-length DER form.
    jose_signature = base64url_decode(signature_segment.encode("ascii"))
    signature_algorithm = ec.ECDSA(hashes.SHA256())

    # Key setup, token encoding/decoding, DER <-> R || S conversion, and result
    # collection are outside timings.
    measurements = []
    for iteration in range(warmup + iterations):
        start = perf_counter_ns()
        signature = private_key.sign(signing_input, signature_algorithm)
        signing_ns = perf_counter_ns() - start

        start = perf_counter_ns()
        public_key.verify(signature, signing_input, signature_algorithm)
        verification_ns = perf_counter_ns() - start

        if iteration >= warmup:
            measurements.append({
                "iteration": iteration - warmup + 1,
                "sign_ns": signing_ns,
                "verify_ns": verification_ns,
            })

    return {
        "algorithm": ALGORITHM,
        "curve": "P-256",
        "hash": "SHA-256",
        "iterations": iterations,
        "warmup": warmup,
        "measurement_scope": "raw ECDSA operations on prepared JWT signing input",
        "environment": {
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cryptography": cryptography.__version__,
            "pyjwt": jwt.__version__,
            "openssl": backend.openssl_version_text(),
            "timer": "perf_counter_ns",
        },
        "sizes_bytes": {
            "payload": len(base64url_decode(payload_segment.encode("ascii"))),
            "signature": len(jose_signature),
            "jwt": len(token.encode("ascii")),
        },
        "key_generation_ms": key_generation_ns / 1_000_000,
        "sign": summarize([sample["sign_ns"] for sample in measurements]),
        "verify": summarize([sample["verify_ns"] for sample in measurements]),
        "measurements": measurements,
        "token": token,
        "verified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS,
                        help="JSON object containing JWT claims")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print the full JSON report instead of just the token")
    parser.add_argument("--output", type=Path, help="save the full JSON report to a file")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.warmup < 0:
        parser.error("--warmup cannot be negative")

    try:
        claims = json.loads(args.claims.read_text(encoding="utf-8"))
        if not isinstance(claims, dict):
            parser.error("--claims must contain a JSON object")
        report = run_benchmark(claims, args.iterations, args.warmup)
        report["claims_file"] = str(args.claims.resolve())
        serialized = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
        if args.verbose:
            print(serialized, end="")
        else:
            print(report["token"])
    except (OSError, ValueError, jwt.PyJWTError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
