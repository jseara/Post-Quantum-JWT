"""Generate one SLH-DSA-SHA2-128f signed token and print only the token; verify such tokens."""

import argparse
from base64 import urlsafe_b64encode
import json
from pathlib import Path
import sys

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import slh_dsa_sha2_128f as slh_dsa

from scripts.compact_jws import decode_compact


DEFAULT_CLAIMS = Path(__file__).resolve().parents[1] / "fixtures" / "claims.json"
ALGORITHM = "SLH-DSA-SHA2-128f"  # Experimental JOSE identifier for this project.


def create_token(claims: dict, private_key: bytes) -> str:
    """Sign a compact JWS using pure SLH-DSA-SHA2-128f with an empty context."""
    header = {"alg": ALGORITHM, "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    header_segment = urlsafe_b64encode(header_bytes).rstrip(b"=")
    payload_segment = urlsafe_b64encode(payload_bytes).rstrip(b"=")
    signing_input = header_segment + b"." + payload_segment
    signature = slh_dsa.sign(private_key, signing_input, b"")
    return (signing_input + b"." + urlsafe_b64encode(signature).rstrip(b"=")).decode("ascii")


def verify_token(token: str, public_key: bytes, audience: str | None = None) -> dict:
    """Verify the signature and expiration, accepting only SLH-DSA-SHA2-128f with an empty context."""
    def verify_signature(signing_input: bytes, signature: bytes) -> bool:
        try:
            slh_dsa.verify(public_key, signing_input, signature, b"")
        except (InvalidSignatureError, ValueError):  # ValueError: wrong signature length.
            return False
        return True

    return decode_compact(token, ALGORITHM, verify_signature, audience)


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
