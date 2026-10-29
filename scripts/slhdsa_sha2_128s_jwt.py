"""Generate one SLH-DSA-SHA2-128s signed token and print only the token."""

import argparse
from base64 import urlsafe_b64encode
import json
from pathlib import Path

from pqcrypto.sign import slh_dsa_sha2_128s as slh_dsa


DEFAULT_CLAIMS = Path(__file__).resolve().parents[1] / "fixtures" / "claims.json"
ALGORITHM = "SLH-DSA-SHA2-128s"  # Experimental JOSE identifier for this project.


def create_token(claims: dict, private_key: bytes) -> str:
    """Sign a compact JWS using pure SLH-DSA-SHA2-128s with an empty context."""
    header = {"alg": ALGORITHM, "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    header_segment = urlsafe_b64encode(header_bytes).rstrip(b"=")
    payload_segment = urlsafe_b64encode(payload_bytes).rstrip(b"=")
    signing_input = header_segment + b"." + payload_segment
    signature = slh_dsa.sign(private_key, signing_input, b"")
    return (signing_input + b"." + urlsafe_b64encode(signature).rstrip(b"=")).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS,
                        help="JSON object containing JWT claims")
    args = parser.parse_args()

    try:
        claims = json.loads(args.claims.read_text(encoding="utf-8"))
        if not isinstance(claims, dict):
            parser.error("--claims must contain a JSON object")
        _, private_key = slh_dsa.keygen()
        print(create_token(claims, private_key))
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
