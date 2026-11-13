"""Verify compact JWS tokens for algorithms that PyJWT does not provide."""

from base64 import urlsafe_b64decode
import binascii
from collections.abc import Callable
import json
import re
import time

import jwt


BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64url_decode(segment: str) -> bytes:
    """Decode unpadded base64url, rejecting padding and characters outside the alphabet."""
    if not BASE64URL.fullmatch(segment) or len(segment) % 4 == 1:
        raise jwt.DecodeError("invalid base64url segment")
    try:
        return urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as error:
        raise jwt.DecodeError("invalid base64url segment") from error


def decode_json_object(segment: str, name: str) -> dict:
    try:
        value = json.loads(b64url_decode(segment))
    except (UnicodeDecodeError, ValueError) as error:
        raise jwt.DecodeError(f"invalid {name} JSON") from error
    if not isinstance(value, dict):
        raise jwt.DecodeError(f"{name} must be a JSON object")
    return value


def check_audience(claims: dict, audience: str | None) -> None:
    """Apply PyJWT's (non-strict) `aud` rules, so every adapter treats audiences alike."""
    present = claims.get("aud")
    if audience is None:
        if present:
            raise jwt.InvalidAudienceError("Invalid audience")
        return
    if not present:
        raise jwt.MissingRequiredClaimError("aud")
    values = [present] if isinstance(present, str) else present
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise jwt.InvalidAudienceError("Invalid claim format in token")
    if audience not in values:
        raise jwt.InvalidAudienceError("Audience doesn't match")


def decode_compact(token: str, algorithm: str,
                   verify_signature: Callable[[bytes, bytes], bool],
                   audience: str | None = None) -> dict:
    """Verify a compact JWS and return its claims, raising PyJWT exceptions on failure.

    Accepts only `algorithm` in the header. Like PyJWT, it rejects a token whose numeric
    `exp` claim is at or before the current time, and it applies PyJWT's `aud` rules: a token
    with an `aud` claim needs a matching `audience`, and an `audience` needs an `aud` claim. No
    other claims are validated.
    """
    segments = token.split(".")
    if len(segments) != 3:
        raise jwt.DecodeError("token must have three segments")
    header_segment, payload_segment, signature_segment = segments

    header = decode_json_object(header_segment, "header")
    if header.get("alg") != algorithm:
        raise jwt.InvalidAlgorithmError("The specified alg value is not allowed")
    signature = b64url_decode(signature_segment)
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    if not verify_signature(signing_input, signature):
        raise jwt.InvalidSignatureError("Signature verification failed")

    claims = decode_json_object(payload_segment, "payload")
    if "exp" in claims:
        expiration = claims["exp"]
        if isinstance(expiration, bool) or not isinstance(expiration, (int, float)):
            raise jwt.DecodeError("Expiration Time claim (exp) must be a number")
        if expiration <= time.time():
            raise jwt.ExpiredSignatureError("Signature has expired")
    check_audience(claims, audience)
    return claims
