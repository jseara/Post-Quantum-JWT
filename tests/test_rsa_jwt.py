"""Correctness checks for the RSA JWT baseline; no timing thresholds."""

import json
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.utils import base64url_decode, base64url_encode

from scripts.rsa_jwt import DEFAULT_CLAIMS, create_token, run_benchmark, verify_token


class RSAJWTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.claims = json.loads(DEFAULT_CLAIMS.read_text(encoding="utf-8"))

    def setUp(self):
        self.token = create_token(self.claims, self.private_key)

    def test_round_trip_and_signature_size(self):
        self.assertEqual(verify_token(self.token, self.public_key), self.claims)
        signature = base64url_decode(self.token.split(".")[2].encode("ascii"))
        self.assertEqual(len(signature), 256)

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

    def test_wrong_key_is_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(jwt.InvalidSignatureError):
            verify_token(self.token, other_key.public_key())

    def test_disallowed_algorithm_is_rejected(self):
        token = jwt.encode(self.claims, self.private_key, algorithm="RS512")
        with self.assertRaises(jwt.InvalidAlgorithmError):
            verify_token(token, self.public_key)

    def test_expired_claim_is_rejected(self):
        token = create_token(dict(self.claims, exp=1), self.private_key)
        with self.assertRaises(jwt.ExpiredSignatureError):
            verify_token(token, self.public_key)

    def test_report_contains_only_measured_iterations(self):
        report = run_benchmark(self.claims, iterations=3, warmup=2)
        self.assertTrue(report["verified"])
        self.assertEqual(report["sizes_bytes"]["signature"], 256)
        self.assertEqual(report["sizes_bytes"]["jwt"], len(report["token"].encode("ascii")))
        self.assertEqual([row["iteration"] for row in report["measurements"]], [1, 2, 3])
        for row in report["measurements"]:
            self.assertGreater(row["sign_ns"], 0)
            self.assertGreater(row["verify_ns"], 0)


if __name__ == "__main__":
    unittest.main()
