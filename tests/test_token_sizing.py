"""Check that padded tokens reach their computed sizes and verify; no timing thresholds."""

import json
import unittest

import jwt

from scripts.algorithms import ADAPTERS
from scripts.token_sizing import (CLAIM_SETS, MAX_PAD, PAD_CLAIM, claim_set, pad_for_target,
                                  padded_claims, padded_token, token_bytes)


class TokenSizingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {name: adapter.generate_keypair() for name, adapter in ADAPTERS.items()}

    def test_claim_sets(self):
        self.assertEqual(set(CLAIM_SETS), {"minimal", "oidc"})
        self.assertEqual(claim_set("minimal"),
                         json.loads(CLAIM_SETS["minimal"].read_text(encoding="utf-8")))
        oidc = claim_set("oidc")
        for claim in ("iss", "sub", "aud", "exp", "iat", "nonce", "email"):
            self.assertIn(claim, oidc)
        with self.assertRaises(ValueError):
            claim_set("large")

    def test_pad_zero_is_the_unpadded_fixture(self):
        claims = claim_set("minimal")
        self.assertIs(padded_claims(claims, 0), claims)
        self.assertEqual(padded_claims(claims, 3), {**claims, PAD_CLAIM: "xxx"})
        for bad in (-1, MAX_PAD + 1, 1.5, True, "3"):
            with self.subTest(pad=bad), self.assertRaises(ValueError):
                padded_claims(claims, bad)
        with self.assertRaises(ValueError):
            padded_claims({PAD_CLAIM: "x"}, 1)

    def test_computed_sizes_match_signed_tokens_and_verify(self):
        for name, (private_key, public_key) in self.keys.items():
            for set_name in CLAIM_SETS:
                claims = claim_set(set_name)
                for pad in (0, 1, 2, 3, 100, 1001):
                    with self.subTest(algorithm=name, claims=set_name, pad=pad):
                        token = padded_token(name, claims, pad, private_key)
                        self.assertEqual(len(token), token_bytes(name, padded_claims(claims, pad)))
                        self.assertEqual(ADAPTERS[name].verify_token(
                            token, public_key, audience=claims.get("aud")),
                            padded_claims(claims, pad))

    def test_padded_token_verifies_before_returning(self):
        # The issue endpoint passes its public key, so a token that fails is never issued.
        for name in ("ES256", "ML-DSA-44"):
            private_key, public_key = self.keys[name]
            _, other_public_key = ADAPTERS[name].generate_keypair()
            claims = claim_set("oidc")
            with self.subTest(algorithm=name):
                token = padded_token(name, claims, 5, private_key, public_key)
                self.assertEqual(ADAPTERS[name].verify_token(token, public_key,
                                                             audience=claims["aud"]),
                                 padded_claims(claims, 5))
                with self.assertRaisesRegex(RuntimeError, "did not verify"):
                    padded_token(name, claims, 5, private_key, other_public_key)

    def test_pad_for_target(self):
        for name in ADAPTERS:
            claims = claim_set("minimal")
            smallest = token_bytes(name, claims)
            first_padded = token_bytes(name, padded_claims(claims, 1))
            with self.subTest(algorithm=name):
                self.assertIsNone(pad_for_target(name, claims, smallest - 1))
                self.assertEqual(pad_for_target(name, claims, smallest), 0)
                self.assertEqual(pad_for_target(name, claims, first_padded - 1), 0)
                for target in range(first_padded, first_padded + 8):
                    pad = pad_for_target(name, claims, target)
                    size = token_bytes(name, padded_claims(claims, pad))
                    # base64url skips one length in four, so a target is met within one byte.
                    self.assertLessEqual(size, target)
                    self.assertGreaterEqual(size, target - 1)
                    self.assertGreater(token_bytes(name, padded_claims(claims, pad + 1)), target)

    def test_oidc_ml_dsa_token_exceeds_chromium_cookie_limit(self):
        # The headline S2-04 number: realistic claims alone put ML-DSA-44 past 4,096 bytes of
        # cookie name + value ("jwt" + token).
        self.assertEqual(token_bytes("ML-DSA-44", claim_set("oidc")), 4095)
        self.assertGreater(len("jwt") + token_bytes("ML-DSA-44", claim_set("oidc")), 4096)

    def test_audience_is_enforced_for_oidc_tokens(self):
        claims = claim_set("oidc")
        for name, (private_key, public_key) in self.keys.items():
            token = padded_token(name, claims, 0, private_key)
            with self.subTest(algorithm=name), self.assertRaises(jwt.InvalidAudienceError):
                ADAPTERS[name].verify_token(token, public_key)


if __name__ == "__main__":
    unittest.main()
