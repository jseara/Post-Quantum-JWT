"""Grow a configuration's JWT to a chosen size with a deterministic padding claim.

A token's size is fixed by its header and signature segments, which do not depend on the claims
for any configuration in scripts/algorithms.py, plus the base64url length of its compact JSON
payload. So the size of a padded token can be computed without signing it; padded_token() signs
the token, checks that the computed size was right, and, given the public key, verifies it.

Padding is one extra claim, `pad`, whose value is `pad` repetitions of "x". `pad=0` leaves the
claims unchanged, so an unpadded token is byte-for-byte the token the fixture produces.
"""

from functools import cache
import json
from pathlib import Path
import sys

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.algorithms import ADAPTERS


REPO = Path(__file__).resolve().parents[1]
CLAIM_SETS = {
    "minimal": REPO / "fixtures" / "claims.json",  # The Sprint 1 fixture.
    "oidc": REPO / "fixtures" / "claims_oidc.json",  # Typical OpenID Connect ID token claims.
}
PAD_CLAIM = "pad"
PAD_CHARACTER = "x"
MAX_PAD = 1_000_000


def claim_set(name: str) -> dict:
    """Return a named claims fixture; raise ValueError for an unknown name."""
    if name not in CLAIM_SETS:
        raise ValueError(f"claims must be one of {', '.join(CLAIM_SETS)}, got {name!r}")
    return json.loads(CLAIM_SETS[name].read_text(encoding="utf-8"))


def padded_claims(claims: dict, pad: int) -> dict:
    """Return the claims with a `pad` claim of `pad` characters; pad=0 returns them unchanged."""
    if isinstance(pad, bool) or not isinstance(pad, int) or not 0 <= pad <= MAX_PAD:
        raise ValueError(f"pad must be an integer from 0 to {MAX_PAD:,}, got {pad!r}")
    if PAD_CLAIM in claims:
        raise ValueError(f"the claims already contain a {PAD_CLAIM!r} claim")
    return claims if pad == 0 else {**claims, PAD_CLAIM: PAD_CHARACTER * pad}


def base64url_length(byte_count: int) -> int:
    """Length of unpadded base64url text for byte_count bytes."""
    return (4 * byte_count + 2) // 3


def payload_bytes(claims: dict) -> int:
    """Bytes of the compact JSON payload, serialized as every token script serializes it."""
    return len(json.dumps(claims, separators=(",", ":")).encode("utf-8"))


@cache
def fixed_overhead(algorithm: str) -> int:
    """Bytes of a token outside its payload segment: header, signature, and both dots."""
    adapter = ADAPTERS[algorithm]
    private_key, _ = adapter.generate_keypair()
    claims = {"sub": "overhead-probe"}
    token = adapter.create_token(claims, private_key)
    return len(token) - base64url_length(payload_bytes(claims))


def token_bytes(algorithm: str, claims: dict) -> int:
    """Size of the compact token the configuration produces for these claims, without signing."""
    return fixed_overhead(algorithm) + base64url_length(payload_bytes(claims))


def pad_for_target(algorithm: str, claims: dict, target_bytes: int) -> int | None:
    """Return the largest pad whose token is at most target_bytes, or None if none fits."""
    if token_bytes(algorithm, claims) > target_bytes:
        return None
    low, high = 0, MAX_PAD  # Token size never decreases as pad grows.
    if token_bytes(algorithm, padded_claims(claims, high)) <= target_bytes:
        return high
    while high - low > 1:
        middle = (low + high) // 2
        if token_bytes(algorithm, padded_claims(claims, middle)) <= target_bytes:
            low = middle
        else:
            high = middle
    return low


def padded_token(algorithm: str, claims: dict, pad: int, private_key, public_key=None) -> str:
    """Sign the padded claims and check the token has the computed size.

    With public_key, also verify the token, with its own `aud` as the audience, and check that
    it returns the padded claims; raise RuntimeError if any check fails.
    """
    padded = padded_claims(claims, pad)
    adapter = ADAPTERS[algorithm]
    token = adapter.create_token(padded, private_key)
    if len(token) != token_bytes(algorithm, padded):
        raise RuntimeError(f"{algorithm}: token is {len(token)} bytes, computed "
                           f"{token_bytes(algorithm, padded)}")
    if public_key is not None:
        try:
            verified = adapter.verify_token(token, public_key, audience=padded.get("aud"))
        except Exception as error:  # Any failure means the token must not be used.
            raise RuntimeError(f"{algorithm}: the padded token did not verify: "
                               f"{str(error) or type(error).__name__}") from error
        if verified != padded:
            raise RuntimeError(f"{algorithm}: the padded token verified with other claims")
    return token
