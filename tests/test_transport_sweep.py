"""Check the sized issue endpoint, the proxy buffer option, Secure cookies over loopback HTTP,
and short cookie sweeps against a real stack; no timing thresholds."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.token_sizing import claim_set, padded_claims, token_bytes
from scripts.transport_stack import (BROWSER_CHANNEL, http_get, load_manifest,
                                     proxy_buffer_directives, start_stack)
from scripts.transport_sweep import probe, run_cookie_sweep, summary_lines, write_results


PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")  # nginx's default proxy_buffer_size.
COOKIE_LIMIT = 4096  # Chromium's name + value limit.


class StackCase(unittest.TestCase):
    proxy_buffers = None

    @classmethod
    def setUpClass(cls):
        cls.directory = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.stack = cls.enterClassContext(start_stack(run_dir=Path(cls.directory) / "run",
                                                      proxy_buffers=cls.proxy_buffers))
        cls.layers = {layer["role"]: layer for layer in load_manifest()["layers"]}

    def get_json(self, url: str, headers: dict | None = None) -> tuple[int, dict, dict]:
        status, response_headers, body = http_get(url, headers=headers)
        return status, response_headers, json.loads(body)


class IssueParameterTests(StackCase):
    def test_defaults_are_the_unpadded_minimal_fixture(self):
        status, _, body = self.get_json(f"{self.stack.app_url}/api/token/issue?alg=ES256"
                                        "&delivery=body")
        self.assertEqual((status, body["token_bytes"]), (200, 208))
        self.assertNotIn("pad", body)  # Default responses are unchanged from S2-02.
        status, _, body = self.get_json(f"{self.stack.app_url}/api/token/issue?alg=ES256"
                                        "&delivery=body&pad=0&claims=minimal")
        self.assertEqual((body["claims"], body["pad"], body["token_bytes"]), ("minimal", 0, 208))

    def test_padded_oidc_token_with_full_attributes_verifies(self):
        url = (f"{self.stack.app_url}/api/token/issue?alg=ML-DSA-44&claims=oidc&pad=10"
               "&attrs=full")
        status, headers, body = self.get_json(url)
        self.assertEqual(status, 200)
        expected_bytes = token_bytes("ML-DSA-44", padded_claims(claim_set("oidc"), 10))
        self.assertEqual(body["token_bytes"], expected_bytes)
        set_cookie = headers["set-cookie"]
        self.assertEqual(len(set_cookie), body["set_cookie_bytes"])
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=3600"):
            self.assertIn(attribute, set_cookie)
        cookie = set_cookie.split(";", 1)[0]
        status, _, verified = self.get_json(f"{self.stack.app_url}/api/token/verify",
                                            {"Cookie": cookie})
        self.assertEqual((status, verified["verified"], verified["token_bytes"]),
                         (200, True, expected_bytes))

    def test_wrong_audience_is_rejected(self):
        # A minimal-claims token gets no audience; an oidc token must carry APP_AUDIENCE.
        _, _, body = self.get_json(f"{self.stack.app_url}/api/token/issue?alg=EdDSA"
                                   "&delivery=body&claims=oidc")
        header, payload, signature = body["token"].split(".")
        self.assertEqual(self.get_json(f"{self.stack.app_url}/api/token/verify",
                                       {"Authorization": f"Bearer {body['token']}"})[0], 200)
        # A tampered aud breaks the signature, so this checks only that the app reaches
        # verification with an audience; the adapter tests cover aud rules themselves.
        status, _, refused = self.get_json(f"{self.stack.app_url}/api/token/verify",
                                           {"Authorization": f"Bearer {header}.{payload}x."
                                                             f"{signature}"})
        self.assertEqual((status, refused["verified"]), (401, False))

    def test_invalid_parameters_are_rejected(self):
        for query in ("claims=large", "pad=-1", "pad=abc", "pad=1000001", "attrs=none"):
            with self.subTest(query=query):
                status, _, body = self.get_json(f"{self.stack.app_url}/api/token/issue"
                                                f"?alg=ES256&{query}")
                self.assertEqual(status, 400)
                self.assertEqual(body["layer"], "application")


class SecureCookieTests(StackCase):
    def test_chromium_stores_and_sends_secure_cookie_over_loopback_http(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.goto(f"{self.stack.proxy_url}/")
                issued = page.evaluate("async (url) => (await fetch(url)).status",
                                       "/api/token/issue?alg=EdDSA&attrs=full")
                jar = {cookie["name"]: cookie for cookie in context.cookies()}
                verified = page.evaluate("async () => (await fetch('/api/token/verify')).json()")
            finally:
                browser.close()
        self.assertEqual(issued, 200)
        self.assertTrue(jar["jwt"]["secure"])
        self.assertTrue(jar["jwt"]["httpOnly"])
        self.assertEqual(jar["jwt"]["sameSite"], "Strict")
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["source"], "cookie")


class ProxyBufferOptionTests(unittest.TestCase):
    def test_directives(self):
        self.assertEqual(proxy_buffer_directives("16k"),
                         ["proxy_buffer_size 16k;", "proxy_buffers 8 16k;"])
        for bad in ("16K", "0k", "16 k", "16k;", "", None, 16):
            with self.subTest(size=bad), self.assertRaises(ValueError):
                proxy_buffer_directives(bad)

    def test_rendered_config_only_changes_when_asked(self):
        with tempfile.TemporaryDirectory() as directory:
            for buffers in (None, "16k"):
                run_dir = Path(directory) / str(buffers)
                with start_stack(run_dir=run_dir, proxy_buffers=buffers):
                    conf = (run_dir / "nginx" / "nginx.conf").read_text(encoding="utf-8")
                active = [line.strip() for line in conf.splitlines()
                          if line.strip().startswith("proxy_buffer")]
                with self.subTest(buffers=buffers):
                    self.assertEqual(active, [] if buffers is None else
                                     ["proxy_buffer_size 16k;", "proxy_buffers 8 16k;"])


def assert_cookie_boundary(test, result: dict, buffer_bytes: int) -> None:
    """The first rejection is whichever of nginx's buffer and Chromium's limit comes first."""
    entry = result["results"][0]
    boundary = entry["boundaries"][0]
    last, first = boundary["last"], boundary["first"]
    test.assertEqual(last["outcome"], "verified")
    test.assertEqual(first["outcome"], "rejected")
    test.assertTrue(last["verified_directly"] and first["verified_directly"])
    test.assertEqual(entry["largest_verified_token_bytes"], last["token_bytes"])
    if first["rejected_by"] == "proxy":
        # Rejected once the application's response header block fills the buffer.
        test.assertLess(last["bytes"]["upstream_response_headers"], buffer_bytes)
        test.assertGreaterEqual(first["bytes"]["upstream_response_headers"], buffer_bytes)
    else:
        test.assertEqual(first["rejected_by"], "browser")
        test.assertFalse(first["cookie_stored"])
        test.assertLessEqual(last["bytes"]["cookie_name_value"], COOKIE_LIMIT)
        test.assertGreater(first["bytes"]["cookie_name_value"], COOKIE_LIMIT)
    test.assertEqual(first["pad"] - last["pad"], 1)


class DefaultBufferSweepTests(StackCase):
    def test_es256_boundary_and_saved_evidence(self):
        result = run_cookie_sweep(self.stack, ["ES256"], step=2048, max_bytes=6144)
        assert_cookie_boundary(self, result, PAGE_SIZE)
        expected = "proxy" if PAGE_SIZE < COOKIE_LIMIT + 200 else "browser"
        self.assertEqual(result["results"][0]["first_rejection"]["rejected_by"], expected)
        self.assertIn("ES256", summary_lines(result)[0])
        with tempfile.TemporaryDirectory() as directory:
            saved = write_results(result, Path(directory) / "out")
            data = json.loads((saved / "sweep.json").read_text(encoding="utf-8"))
            self.assertEqual(data["settings"]["proxy_buffers"], None)
            self.assertTrue((saved / "nginx.conf").is_file())
            access = (saved / "logs" / "proxy-access.log").read_text(encoding="utf-8")
            boundary = data["results"][0]["boundaries"][0]
            self.assertIn(boundary["first"]["issue_nonce"], access)


class PinnedBufferSweepTests(StackCase):
    proxy_buffers = "16k"

    def test_es256_reaches_chromium_cookie_limit(self):
        result = run_cookie_sweep(self.stack, ["ES256"], step=2048, max_bytes=6144,
                                  proxy_buffers="16k")
        assert_cookie_boundary(self, result, 16384)
        self.assertEqual(result["results"][0]["first_rejection"]["rejected_by"], "browser")

    def test_probe_byte_accounting(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True)
            try:
                entry = probe(browser, self.stack, self.layers, "RS256",
                              {"claims": "minimal", "pad": 0, "attrs": "default"}, 60)
            finally:
                browser.close()
        counted = entry["bytes"]
        self.assertEqual(entry["outcome"], "verified")
        self.assertEqual(counted["cookie_name_value"], 3 + 464)
        self.assertEqual(counted["cookie_line"], len("Cookie: jwt=\r\n") + 464)
        self.assertEqual(counted["set_cookie_line"], len("Set-Cookie: \r\n")
                         + counted["set_cookie_value"])
        self.assertGreater(counted["upstream_response_headers"], counted["set_cookie_line"])
        self.assertGreater(counted["browser_request_headers"], counted["cookie_line"])
        self.assertGreater(counted["app_received_headers"], counted["cookie_line"])


if __name__ == "__main__":
    unittest.main()
