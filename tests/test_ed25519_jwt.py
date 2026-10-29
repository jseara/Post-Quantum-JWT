"""Correctness checks for the Ed25519 JWT baseline; no timing thresholds."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt
from jwt.utils import base64url_decode, base64url_encode

from scripts.ed25519_jwt import DEFAULT_CLAIMS, create_token, run_benchmark, verify_token


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ed25519_jwt.py"


class Ed25519JWTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = Ed25519PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()
        cls.claims = json.loads(DEFAULT_CLAIMS.read_text(encoding="utf-8"))

    def setUp(self):
        self.token = create_token(self.claims, self.private_key)

    def test_round_trip_and_signature_size(self):
        self.assertEqual(verify_token(self.token, self.public_key), self.claims)
        self.assertEqual(jwt.get_unverified_header(self.token)["alg"], "EdDSA")
        signature = base64url_decode(self.token.split(".")[2].encode("ascii"))
        self.assertEqual(len(signature), 64)

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
        other_key = Ed25519PrivateKey.generate()
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

    def test_report_contains_only_measured_iterations(self):
        report = run_benchmark(self.claims, iterations=3, warmup=2)
        self.assertTrue(report["verified"])
        self.assertEqual(report["curve"], "Ed25519")
        self.assertEqual(report["sizes_bytes"]["signature"], 64)
        self.assertEqual(report["sizes_bytes"]["jwt"], len(report["token"].encode("ascii")))
        self.assertEqual([row["iteration"] for row in report["measurements"]], [1, 2, 3])
        for row in report["measurements"]:
            self.assertGreater(row["sign_ns"], 0)
            self.assertGreater(row["verify_ns"], 0)

    def test_cli_prints_only_token_and_saves_full_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "report.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--iterations", "1", "--warmup", "0",
                 "--output", str(output)],
                cwd=directory, capture_output=True, text=True, check=True,
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result.stdout, report["token"] + "\n")
            self.assertEqual(result.stderr, "")
            self.assertTrue(report["verified"])

    def test_cli_verbose_prints_full_report(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--iterations", "1", "--warmup", "0", "--verbose"],
            capture_output=True, text=True, check=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["algorithm"], "EdDSA")
        self.assertEqual(report["sizes_bytes"]["signature"], 64)
        self.assertTrue(report["verified"])


if __name__ == "__main__":
    unittest.main()
