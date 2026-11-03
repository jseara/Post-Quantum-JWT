"""Correctness checks for the ML-DSA-44 JWT generator and verifier; no timing thresholds."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
import jwt
from jwt.utils import base64url_decode, base64url_encode

from scripts.mldsa_jwt import ALGORITHM, DEFAULT_CLAIMS, create_token, verify_token


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mldsa_jwt.py"


class MLDSAJWTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = MLDSA44PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()
        cls.claims = json.loads(DEFAULT_CLAIMS.read_text(encoding="utf-8"))

    def setUp(self):
        self.token = create_token(self.claims, self.private_key)

    def test_round_trip_and_sizes(self):
        self.assertEqual(verify_token(self.token, self.public_key), self.claims)
        self.assertEqual(jwt.get_unverified_header(self.token), {"alg": ALGORITHM, "typ": "JWT"})
        self.assertNotIn("=", self.token)
        signature = base64url_decode(self.token.split(".")[2].encode("ascii"))
        self.assertEqual(len(signature), 2420)  # FIPS 204, Table 2.
        self.assertEqual(len(self.token.encode("ascii")), 3355)

    def test_modified_payload_is_rejected(self):
        header, _, signature = self.token.split(".")
        changed = dict(self.claims, role="admin")
        payload = base64url_encode(json.dumps(changed).encode()).decode("ascii")
        with self.assertRaises(jwt.InvalidSignatureError):
            verify_token(f"{header}.{payload}.{signature}", self.public_key)

    def test_modified_signature_is_rejected(self):
        header, payload, encoded_signature = self.token.split(".")
        signature = bytearray(base64url_decode(encoded_signature.encode("ascii")))
        signature[0] ^= 1
        changed = base64url_encode(bytes(signature)).decode("ascii")
        with self.assertRaises(jwt.InvalidSignatureError):
            verify_token(f"{header}.{payload}.{changed}", self.public_key)

    def test_truncated_signature_is_rejected(self):
        header, payload, encoded_signature = self.token.split(".")
        signature = base64url_decode(encoded_signature.encode("ascii"))[:-1]
        changed = base64url_encode(signature).decode("ascii")
        with self.assertRaises(jwt.InvalidSignatureError):
            verify_token(f"{header}.{payload}.{changed}", self.public_key)

    def test_wrong_key_is_rejected(self):
        other_key = MLDSA44PrivateKey.generate()
        with self.assertRaises(jwt.InvalidSignatureError):
            verify_token(self.token, other_key.public_key())

    def test_disallowed_algorithm_is_rejected(self):
        token = jwt.encode(self.claims, "test-only-secret-at-least-32-bytes-long", algorithm="HS256")
        with self.assertRaises(jwt.InvalidAlgorithmError):
            verify_token(token, self.public_key)

    def test_expired_claim_is_rejected(self):
        token = create_token(dict(self.claims, exp=1), self.private_key)
        with self.assertRaises(jwt.ExpiredSignatureError):
            verify_token(token, self.public_key)

    def test_malformed_tokens_are_rejected(self):
        header, payload, signature = self.token.split(".")
        for token in (f"{header}.{payload}", f"{header}.{payload}.{signature}=",
                      f"{header}.{payload}.{signature}!", f"e30.{payload}.{signature}"):
            with self.subTest(token=token[-8:]), self.assertRaises(jwt.InvalidTokenError):
                verify_token(token, self.public_key)

    def test_cli_prints_only_default_token_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(SCRIPT)], cwd=directory,
                capture_output=True, text=True, check=True,
            )
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        token = result.stdout.strip()
        self.assertEqual(len(token), 3355)
        self.assertEqual(json.loads(base64url_decode(token.split(".")[1].encode("ascii"))),
                         self.claims)

    def test_cli_custom_claims_and_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "claims.json"
            command = [sys.executable, str(SCRIPT), "--claims", str(fixture)]
            fixture.write_text('{"sub":"custom-user"}', encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(base64url_decode(result.stdout.split(".")[1].encode("ascii"))),
                             {"sub": "custom-user"})
            fixture.write_text("[]", encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
