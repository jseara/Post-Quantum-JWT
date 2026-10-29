"""Check both SLH-DSA token generators without benchmarking."""

from base64 import urlsafe_b64decode
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pqcrypto import InvalidSignatureError

from scripts import slhdsa_sha2_128s_jwt, slhdsa_sha2_128f_jwt


def decode(segment):
    return urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class SLHDSAJWTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = []
        for script, signature_size, token_size in (
            (slhdsa_sha2_128s_jwt, 7856, 10613),
            (slhdsa_sha2_128f_jwt, 17088, 22922),
        ):
            claims = json.loads(script.DEFAULT_CLAIMS.read_text(encoding="utf-8"))
            public_key, private_key = script.slh_dsa.keygen()
            token = script.create_token(claims, private_key)
            cls.cases.append((script, public_key, claims, token, signature_size, token_size))

    def test_signature_claims_and_sizes(self):
        for script, public_key, claims, token, signature_size, token_size in self.cases:
            with self.subTest(algorithm=script.ALGORITHM):
                header, payload, signature = token.split(".")
                self.assertEqual(json.loads(decode(header)), {"alg": script.ALGORITHM, "typ": "JWT"})
                self.assertEqual(json.loads(decode(payload)), claims)
                self.assertNotIn("=", token)
                self.assertEqual(len(decode(signature)), signature_size)
                self.assertEqual(len(token.encode("ascii")), token_size)
                script.slh_dsa.verify(public_key, f"{header}.{payload}".encode("ascii"),
                                      decode(signature), b"")

    def test_tampering_and_wrong_key_are_rejected(self):
        for script, public_key, _, token, _, _ in self.cases:
            with self.subTest(algorithm=script.ALGORITHM):
                message, signature_segment = token.rsplit(".", 1)
                message = message.encode("ascii")
                signature = decode(signature_segment)
                changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
                wrong_key, _ = script.slh_dsa.keygen()
                for key, data, sig in (
                    (public_key, message + b"changed", signature),
                    (public_key, message, changed_signature),
                    (wrong_key, message, signature),
                ):
                    with self.assertRaises(InvalidSignatureError):
                        script.slh_dsa.verify(key, data, sig, b"")

    def test_cli_prints_only_default_token_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            for script, _, claims, _, signature_size, token_size in self.cases:
                with self.subTest(algorithm=script.ALGORITHM):
                    result = subprocess.run(
                        [sys.executable, str(Path(script.__file__).resolve())],
                        cwd=directory, capture_output=True, text=True, check=True,
                    )
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(len(result.stdout.splitlines()), 1)
                    token = result.stdout.strip()
                    self.assertEqual(len(token), token_size)
                    _, payload, signature = token.split(".")
                    self.assertEqual(json.loads(decode(payload)), claims)
                    self.assertEqual(len(decode(signature)), signature_size)

    def test_cli_custom_claims_and_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "claims.json"
            for script, *_ in self.cases:
                with self.subTest(algorithm=script.ALGORITHM):
                    command = [sys.executable, str(Path(script.__file__).resolve()),
                               "--claims", str(fixture)]
                    fixture.write_text('{"sub":"custom-user"}', encoding="utf-8")
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    self.assertEqual(json.loads(decode(result.stdout.split(".")[1])),
                                     {"sub": "custom-user"})
                    fixture.write_text("[]", encoding="utf-8")
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
