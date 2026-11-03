"""Check the benchmark runner's output files and settings reuse; no timing thresholds."""

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.algorithms import ADAPTERS
from scripts.benchmark import RAW_FIELDS, run


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark.py"


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        settings = {"algorithms": list(ADAPTERS), "iterations": 2, "warmup": 1,
                    "iterations_per_algorithm": {"RS256": 3}, "claims_file": "fixtures/claims.json"}
        cls.output = run(settings, Path(cls.directory.name) / "run")
        cls.run_info = json.loads((cls.output / "run.json").read_text(encoding="utf-8"))
        cls.summary = json.loads((cls.output / "summary.json").read_text(encoding="utf-8"))
        with (cls.output / "raw.csv").open(newline="", encoding="utf-8") as file:
            cls.rows = list(csv.DictReader(file))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_run_metadata(self):
        settings = self.run_info["settings"]
        self.assertEqual(settings["claims_file"], "fixtures/claims.json")
        self.assertEqual(len(settings["claims_sha256"]), 64)
        self.assertEqual(self.summary["run_id"], self.run_info["run_id"])
        for key in ("python", "platform", "cryptography", "pyjwt", "pqcrypto", "openssl"):
            self.assertIn(key, self.run_info["environment"])

    def test_summary_for_every_algorithm(self):
        rows = {row["algorithm"]: row for row in self.summary["algorithms"]}
        self.assertEqual(list(rows), list(ADAPTERS))
        for name, row in rows.items():
            with self.subTest(algorithm=name):
                expected_n = 3 if name == "RS256" else 2
                self.assertTrue(row["verified"])
                self.assertEqual(row["iterations"], expected_n)
                self.assertEqual(row["sizes_bytes"]["signature"],
                                 ADAPTERS[name].expected_signature_bytes)
                self.assertEqual(row["sizes_bytes"]["jwt"], len(row["token"].encode("ascii")))
                for operation in ("sign", "verify"):
                    self.assertEqual(row[operation]["n"], expected_n)
                    self.assertLessEqual(row[operation]["median_ms"], row[operation]["p95_ms"])

    def test_raw_rows_exclude_warmup(self):
        self.assertEqual(tuple(self.rows[0]), RAW_FIELDS)
        self.assertEqual(len(self.rows), 2 * (3 + 2 * (len(ADAPTERS) - 1)))
        for row in self.rows:
            self.assertEqual(row["run_id"], self.run_info["run_id"])
            self.assertGreater(int(row["duration_ns"]), 0)
        rsa_sign = [int(row["iteration"]) for row in self.rows
                    if row["algorithm"] == "RS256" and row["operation"] == "sign"]
        self.assertEqual(rsa_sign, [1, 2, 3])

    def test_cli_reuses_saved_settings_with_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            subprocess.run([sys.executable, str(SCRIPT), "--algorithms", "EdDSA", "ES256",
                            "--iterations", "2", "--warmup", "0", "--output-dir", str(first)],
                           cwd=directory, capture_output=True, text=True, check=True)
            second = Path(directory) / "second"
            result = subprocess.run([sys.executable, str(SCRIPT), "--settings",
                                     str(first / "run.json"), "--iterations", "1",
                                     "--output-dir", str(second)],
                                    cwd=directory, capture_output=True, text=True, check=True)
            self.assertIn("EdDSA", result.stdout)
            saved = json.loads((second / "run.json").read_text(encoding="utf-8"))["settings"]
            self.assertEqual(saved["algorithms"], ["EdDSA", "ES256"])
            self.assertEqual((saved["iterations"], saved["warmup"]), (1, 0))

    def test_cli_rejects_invalid_settings(self):
        for arguments in (["--iterations", "0"], ["--warmup", "-1"],
                          ["--iterations-per-algorithm", "RS999=2"]):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, str(SCRIPT), "--algorithms", "EdDSA",
                                         *arguments, "--output-dir", directory],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(directory) / "raw.csv").exists())


if __name__ == "__main__":
    unittest.main()
