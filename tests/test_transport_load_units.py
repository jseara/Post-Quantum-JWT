"""Check the load command's network model, argument checks, and saved settings without a stack;
no timing thresholds."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.transport_load import (default_settings, modeled_transfer_ms, read_saved_settings,
                                    run_load)


class UnreachableStack:
    """A stack whose URLs nothing listens on, so any request sent to it would fail loudly."""

    proxy_url = app_url = "http://127.0.0.1:9"
    run_dir = Path(tempfile.gettempdir()) / "unused-load-run"


class ModeledTransferTests(unittest.TestCase):
    def test_one_flight_up_to_the_initial_window(self):
        self.assertAlmostEqual(modeled_transfer_ms(14_600, 10, 50), 11.68)
        self.assertAlmostEqual(modeled_transfer_ms(14_601, 10, 50), 11.6808 + 50)

    def test_each_later_flight_doubles(self):
        for size, flights in ((43_800, 2), (43_801, 3), (102_200, 3), (102_201, 4)):
            with self.subTest(size=size):
                expected = size * 8 / 100e6 * 1000 + (flights - 1) * 10
                self.assertAlmostEqual(modeled_transfer_ms(size, 100, 10), expected)

    def test_invalid_arguments(self):
        for arguments in ((0, 10, 50), (True, 10, 50), (1.5, 10, 50), (100, 0, 50),
                          (100, float("inf"), 50), (100, 10, -1), (100, 10, float("nan")),
                          (100, True, 50)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                modeled_transfer_ms(*arguments)


class RunLoadArgumentTests(unittest.TestCase):
    def test_invalid_arguments_raise_before_any_request(self):
        cases = [{"algorithms": "ES256"}, {"algorithms": []}, {"algorithms": ["ES256", "ES256"]},
                 {"transport": "query"}, {"clients": ["curl"]}, {"clients": []},
                 {"concurrency": [0]}, {"concurrency": [65]}, {"concurrency": [True]},
                 {"concurrency": [1, 1]}, {"duration": 0}, {"duration": float("nan")},
                 {"warmup": -1}, {"warmup": False}, {"claims": "huge"}, {"reference": "HS256"},
                 {"size_controls": 1}, {"timeout": 0}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                run_load(UnreachableStack(), **case)

    def test_defaults_are_the_documented_workload(self):
        self.assertEqual(default_settings(), {
            "algorithms": None, "transport": "bearer", "clients": None, "concurrency": (1, 4),
            "duration": 5.0, "warmup": 1.0, "claims": "minimal", "reference": "ES256",
            "size_controls": True, "timeout": 60.0, "proxy_buffers": None,
            "header_buffers": None, "upstream_keepalive": None})


class SavedSettingsTests(unittest.TestCase):
    def write(self, directory: str, text: str) -> Path:
        path = Path(directory) / "load.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_reads_the_settings_object(self):
        with tempfile.TemporaryDirectory() as directory:
            saved = {"duration": 2.0, "header_buffers": "32k"}
            path = self.write(directory, json.dumps({"settings": saved}))
            self.assertEqual(read_saved_settings(path), saved)

    def test_rejects_unusable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            for text in ("not json", "[]", '{"results": []}', '{"settings": {"bogus": 1}}',
                         '{"settings": {"header_buffers": "lots"}}'):
                with self.subTest(text=text), self.assertRaises(ValueError):
                    read_saved_settings(self.write(directory, text))
            with self.assertRaises(ValueError):
                read_saved_settings(Path(directory) / "missing.json")


if __name__ == "__main__":
    unittest.main()
