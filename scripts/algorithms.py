"""Common interface over every JWT signature configuration in this project.

Each adapter reuses the token functions of its standalone script and adds key generation,
raw signing/verification over a prepared JWT signing input (the operations that are
timed), and metadata identifying the algorithm, parameter set, and backend.
"""

from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
import sys
from typing import Any

if __package__ in (None, ""):  # Allow `python scripts/<name>.py` as well as package imports.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey

from scripts import (ed25519_jwt, es256_jwt, mldsa_jwt, rsa_jwt,
                     slhdsa_sha2_128f_jwt, slhdsa_sha2_128s_jwt)


@dataclass(frozen=True)
class Adapter:
    """One signature configuration. `verify_raw` raises on an invalid signature."""

    name: str  # JOSE `alg` value.
    family: str
    parameter_set: str
    standard: str
    jose_spec: str
    jose_status: str  # "registered" in the IANA JOSE registry, or "experimental".
    backend: str
    expected_signature_bytes: int
    generate_keypair: Callable[[], tuple[Any, Any]]
    create_token: Callable[[dict, Any], str]
    verify_token: Callable[..., dict]  # (token, public_key, audience=None) -> claims
    sign_raw: Callable[[Any, bytes], bytes]
    verify_raw: Callable[[Any, bytes, bytes], None]

    def metadata(self) -> dict:
        return {
            "algorithm": self.name,
            "family": self.family,
            "parameter_set": self.parameter_set,
            "standard": self.standard,
            "jose_spec": self.jose_spec,
            "jose_status": self.jose_status,
            "backend": self.backend,
        }


def keypair(private_key) -> tuple[Any, Any]:
    return private_key, private_key.public_key()


def slh_keypair(module) -> tuple[bytes, bytes]:
    public_key, private_key = module.keygen()
    return private_key, public_key


CRYPTOGRAPHY = f"cryptography {version('cryptography')}"
PQCRYPTO = f"pqcrypto {version('pqcrypto')}"
RSA_PADDING = padding.PKCS1v15()
ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())
SLH_128S = slhdsa_sha2_128s_jwt.slh_dsa
SLH_128F = slhdsa_sha2_128f_jwt.slh_dsa

ADAPTER_LIST = (
    Adapter(
        name="RS256", family="RSA", parameter_set="RSA-2048, e=65537, PKCS#1 v1.5, SHA-256",
        standard="RFC 8017", jose_spec="RFC 7518", jose_status="registered",
        backend=CRYPTOGRAPHY, expected_signature_bytes=256,
        generate_keypair=lambda: keypair(
            rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        create_token=rsa_jwt.create_token, verify_token=rsa_jwt.verify_token,
        sign_raw=lambda key, data: key.sign(data, RSA_PADDING, hashes.SHA256()),
        verify_raw=lambda key, data, sig: key.verify(sig, data, RSA_PADDING, hashes.SHA256()),
    ),
    # Timed ECDSA operations use DER signatures; tokens carry the 64-byte R || S form.
    Adapter(
        name="ES256", family="ECDSA", parameter_set="P-256, SHA-256",
        standard="FIPS 186-5", jose_spec="RFC 7518", jose_status="registered",
        backend=CRYPTOGRAPHY, expected_signature_bytes=64,
        generate_keypair=lambda: keypair(ec.generate_private_key(ec.SECP256R1())),
        create_token=es256_jwt.create_token, verify_token=es256_jwt.verify_token,
        sign_raw=lambda key, data: key.sign(data, ECDSA_SHA256),
        verify_raw=lambda key, data, sig: key.verify(sig, data, ECDSA_SHA256),
    ),
    Adapter(
        name="EdDSA", family="EdDSA", parameter_set="Ed25519",
        standard="RFC 8032", jose_spec="RFC 8037", jose_status="registered",
        backend=CRYPTOGRAPHY, expected_signature_bytes=64,
        generate_keypair=lambda: keypair(Ed25519PrivateKey.generate()),
        create_token=ed25519_jwt.create_token, verify_token=ed25519_jwt.verify_token,
        sign_raw=lambda key, data: key.sign(data),
        verify_raw=lambda key, data, sig: key.verify(sig, data),
    ),
    Adapter(
        name="ML-DSA-44", family="ML-DSA", parameter_set="ML-DSA-44, pure, empty context",
        standard="FIPS 204", jose_spec="RFC 9964", jose_status="registered",
        backend=CRYPTOGRAPHY, expected_signature_bytes=2420,
        generate_keypair=lambda: keypair(MLDSA44PrivateKey.generate()),
        create_token=mldsa_jwt.create_token, verify_token=mldsa_jwt.verify_token,
        sign_raw=lambda key, data: key.sign(data, context=b""),
        verify_raw=lambda key, data, sig: key.verify(sig, data, context=b""),
    ),
    Adapter(
        name="SLH-DSA-SHA2-128s", family="SLH-DSA",
        parameter_set="SLH-DSA-SHA2-128s, pure, empty context",
        standard="FIPS 205", jose_spec="none (project-specific identifier)",
        jose_status="experimental", backend=PQCRYPTO, expected_signature_bytes=7856,
        generate_keypair=lambda: slh_keypair(SLH_128S),
        create_token=slhdsa_sha2_128s_jwt.create_token,
        verify_token=slhdsa_sha2_128s_jwt.verify_token,
        sign_raw=lambda key, data: SLH_128S.sign(key, data, b""),
        verify_raw=lambda key, data, sig: SLH_128S.verify(key, data, sig, b""),
    ),
    Adapter(
        name="SLH-DSA-SHA2-128f", family="SLH-DSA",
        parameter_set="SLH-DSA-SHA2-128f, pure, empty context",
        standard="FIPS 205", jose_spec="none (project-specific identifier)",
        jose_status="experimental", backend=PQCRYPTO, expected_signature_bytes=17088,
        generate_keypair=lambda: slh_keypair(SLH_128F),
        create_token=slhdsa_sha2_128f_jwt.create_token,
        verify_token=slhdsa_sha2_128f_jwt.verify_token,
        sign_raw=lambda key, data: SLH_128F.sign(key, data, b""),
        verify_raw=lambda key, data, sig: SLH_128F.verify(key, data, sig, b""),
    ),
)
ADAPTERS = {adapter.name: adapter for adapter in ADAPTER_LIST}
