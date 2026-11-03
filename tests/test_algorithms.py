"""Check that every adapter behaves the same through the common interface; no timing thresholds."""

import json
import unittest

import jwt
from jwt.utils import base64url_decode, base64url_encode

from scripts.algorithms import ADAPTERS
from scripts.rsa_jwt import DEFAULT_CLAIMS


EXPECTED = {
    "RS256": 256, "ES256": 64, "EdDSA": 64,
    "ML-DSA-44": 2420, "SLH-DSA-SHA2-128s": 7856, "SLH-DSA-SHA2-128f": 17088,
}


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claims = json.loads(DEFAULT_CLAIMS.read_text(encoding="utf-8"))
        cls.cases = {}
        for name, adapter in ADAPTERS.items():
            private_key, public_key = adapter.generate_keypair()
            token = adapter.create_token(cls.claims, private_key)
            cls.cases[name] = (adapter, private_key, public_key, token)

    def test_all_six_configurations_with_standard_signature_sizes(self):
        self.assertEqual(list(ADAPTERS), list(EXPECTED))
        for name, (adapter, _, _, token) in self.cases.items():
            with self.subTest(algorithm=name):
                self.assertEqual(adapter.expected_signature_bytes, EXPECTED[name])
                signature = base64url_decode(token.split(".")[2].encode("ascii"))
                self.assertEqual(len(signature), EXPECTED[name])
                self.assertEqual(jwt.get_unverified_header(token)["alg"], name)
                self.assertEqual(adapter.metadata()["algorithm"], name)

    def test_identical_payload_bytes(self):
        payloads = {name: token.split(".")[1] for name, (*_, token) in self.cases.items()}
        self.assertEqual(len(set(payloads.values())), 1, payloads)

    def test_round_trip_and_raw_operations(self):
        for name, (adapter, private_key, public_key, token) in self.cases.items():
            with self.subTest(algorithm=name):
                self.assertEqual(adapter.verify_token(token, public_key), self.claims)
                data = token.rsplit(".", 1)[0].encode("ascii")
                signature = adapter.sign_raw(private_key, data)
                adapter.verify_raw(public_key, data, signature)
                with self.assertRaises(Exception):
                    adapter.verify_raw(public_key, data + b"changed", signature)

    def test_negative_checks(self):
        hs256 = jwt.encode(self.claims, "test-only-secret-at-least-32-bytes-long", algorithm="HS256")
        changed_payload = base64url_encode(
            json.dumps(dict(self.claims, role="admin"), separators=(",", ":")).encode()).decode()
        for name, (adapter, private_key, public_key, token) in self.cases.items():
            with self.subTest(algorithm=name):
                header, _, signature_segment = token.split(".")
                signature = bytearray(base64url_decode(signature_segment.encode("ascii")))
                signature[-1] ^= 1
                changed_signature = base64url_encode(bytes(signature)).decode("ascii")
                _, wrong_key = adapter.generate_keypair()
                for bad_token, key in (
                    (f"{header}.{changed_payload}.{signature_segment}", public_key),
                    (f"{header}.{token.split('.')[1]}.{changed_signature}", public_key),
                    (token, wrong_key),
                ):
                    with self.assertRaises(jwt.InvalidSignatureError):
                        adapter.verify_token(bad_token, key)
                with self.assertRaises(jwt.InvalidAlgorithmError):
                    adapter.verify_token(hs256, public_key)
                expired = adapter.create_token(dict(self.claims, exp=1), private_key)
                with self.assertRaises(jwt.ExpiredSignatureError):
                    adapter.verify_token(expired, public_key)


if __name__ == "__main__":
    unittest.main()
