"""Check S3-02's smaller claim sets without a stack or a browser: the essential fixture, the claim
set names, token_sizes, the Sprint 2 boundaries derived from the committed sweeps, run_claims's
argument checks, summary_lines, and the load settings that accept the essential claims; no
timing thresholds."""

import inspect
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts import token_sizing, transport_load
from scripts.algorithms import ADAPTER_LIST, ADAPTERS
from scripts.token_sizing import (CLAIM_SETS, claim_set, pad_for_target, padded_claims,
                                  padded_token, payload_bytes, token_bytes)
from scripts.transport_stack import load_manifest, manifest_layers

try:
    from scripts import transport_claims
    CLAIMS_IMPORT_ERROR = None
except Exception as error:  # Before S3-02 is built: the tests that need it fail, not vanish.
    transport_claims, CLAIMS_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
# The commit S3-02 builds on (S3-01); unchanged fixtures are compared with it.
BASE_COMMIT = "455828d0f63f8a138590a0fac32f1a83ea51c07f"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
CLAIM_SET_NAMES = ("minimal", "oidc", "essential")
FIXTURE_FILES = {"minimal": "fixtures/claims.json", "oidc": "fixtures/claims_oidc.json",
                 "essential": "fixtures/claims_essential.json"}
COMPARED = ("oidc", "essential")
TRANSPORTS = ("cookie", "bearer")
ESSENTIAL_CLAIMS = ["iss", "sub", "aud", "exp", "iat"]
APP_AUDIENCE = "cis628-transport-client"
PAYLOAD_BYTES = {"minimal": 63, "oidc": 618, "essential": 137}
# R6's expected token sizes, fixed bytes, and raw signature sizes.
TOKEN_BYTES = {
    "RS256": {"minimal": 464, "oidc": 1204, "essential": 563},
    "ES256": {"minimal": 208, "oidc": 948, "essential": 307},
    "EdDSA": {"minimal": 208, "oidc": 948, "essential": 307},
    "ML-DSA-44": {"minimal": 3355, "oidc": 4095, "essential": 3454},
    "SLH-DSA-SHA2-128s": {"minimal": 10613, "oidc": 11353, "essential": 10712},
    "SLH-DSA-SHA2-128f": {"minimal": 22922, "oidc": 23662, "essential": 23021},
}
FIXED_BYTES = {"RS256": 380, "ES256": 124, "EdDSA": 124, "ML-DSA-44": 3271,
               "SLH-DSA-SHA2-128s": 10529, "SLH-DSA-SHA2-128f": 22838}
SIGNATURE_BYTES = {"RS256": 256, "ES256": 64, "EdDSA": 64, "ML-DSA-44": 2420,
                   "SLH-DSA-SHA2-128s": 7856, "SLH-DSA-SHA2-128f": 17088}
SHRINK_BYTES = 641
SHRINK_PERCENT_ONE_DECIMAL = {"RS256": "53.2", "ES256": "67.6", "EdDSA": "67.6",
                              "ML-DSA-44": "15.7", "SLH-DSA-SHA2-128s": "5.6",
                              "SLH-DSA-SHA2-128f": "2.7"}
SPRINT2_RUN = "results/transport/20261113T074114Z-wsl2"
BOUNDARY_NAMES = ("cookie-default", "cookie-16k", "bearer-default")
BOUNDARY_TRANSPORTS = {"cookie-default": "cookie", "cookie-16k": "cookie",
                       "bearer-default": "bearer"}
BOUNDARY_BYTES = {"cookie-default": 3915, "cookie-16k": 4093, "bearer-default": 8168}
SIZE_ROW_KEYS = {"algorithm", "signature_bytes", "fixed_bytes", "token_bytes", "shrink_bytes",
                 "shrink_percent"}
BOUNDARY_KEYS = {"name", "transport", "source", "largest_verified_token_bytes", "rows"}
BOUNDARY_ROW_KEYS = {"algorithm", "fits", "headroom_bytes", "moved"}
RUN_CLAIMS_DEFAULTS = {"algorithms": None, "clients": None, "concurrency": [1, 4],
                       "duration": 5.0, "warmup": 1.0, "timeout": 60.0, "header_buffers": None,
                       "upstream_keepalive": None, "run_dir": None}
LOAD_DEFAULTS = {"algorithms": None, "transport": "bearer", "clients": None,
                 "concurrency": (1, 4), "duration": 5.0, "warmup": 1.0, "claims": "minimal",
                 "reference": "ES256", "size_controls": True, "timeout": 60.0,
                 "proxy_buffers": None, "header_buffers": None, "upstream_keepalive": None}
FULL_ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
COMPONENTS = ("total", "transfer", "other_handling", "verification")

IMPORT_CHECK = """\
import json
import os
import subprocess
import sys
import threading
sys.path.insert(0, sys.argv[1])
import scripts.transport_claims
listing = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True)
output, _ = listing.communicate()
children = [fields[0] for fields in (line.split() for line in output.splitlines())
            if len(fields) == 2 and fields[1] == str(os.getpid())
            and fields[0] != str(listing.pid)]
print(json.dumps({"children": len(children), "threads": threading.active_count()}))
"""
STACK_IMPORT_CHECK = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
import scripts.transport_stack
print(json.dumps(sorted(name for name in ("scripts.transport_load", "scripts.transport_claims",
                                          "scripts.token_sizing", "scripts.algorithms",
                                          "cryptography", "playwright")
                        if name in sys.modules)))
"""
BOUNDARIES_CHECK = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
from scripts.transport_claims import sprint2_boundaries
try:
    entries = sprint2_boundaries(json.loads(sys.argv[2]))
except RuntimeError:
    print(json.dumps("RuntimeError"))
else:
    print(json.dumps([entry["name"] for entry in entries]))
"""
BOUNDARIES_DUMP = """\
import json
import sys
sys.path.insert(0, sys.argv[1])
from scripts.transport_claims import sprint2_boundaries
print(json.dumps(sprint2_boundaries(json.loads(sys.argv[2]))))
"""


# ---- the module under test ---------------------------------------------------------------

def module():
    """Return scripts.transport_claims, failing the calling test when it cannot be imported."""
    if transport_claims is None:
        raise AssertionError(f"scripts/transport_claims.py cannot be imported: "
                             f"{CLAIMS_IMPORT_ERROR!r}")
    return transport_claims


def claim_set_names():
    """token_sizing.CLAIM_SET_NAMES, failing the calling test when it is missing."""
    names = getattr(token_sizing, "CLAIM_SET_NAMES", None)
    if names is None:
        raise AssertionError("scripts/token_sizing.py has no CLAIM_SET_NAMES")
    return names


# ---- helpers -----------------------------------------------------------------------------

def read_fixture(name: str):
    """A fixture file parsed as (key, value) pairs, so key order and duplicates are visible."""
    return json.loads((REPO / FIXTURE_FILES[name]).read_text(encoding="utf-8"),
                      object_pairs_hook=list)


def git_show(path: str) -> str | None:
    """Return a file as committed at BASE_COMMIT, or None when git or the commit is missing."""
    try:
        return subprocess.run(["git", "-C", str(REPO), "show", f"{BASE_COMMIT}:{path}"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def run_python(code: str, *arguments: str, cwd: Path = REPO) -> subprocess.CompletedProcess:
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, "-c", code, *arguments], cwd=cwd, env=environment,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def expected_size_rows(names) -> list[dict]:
    """R6's rows for these configurations, from the spec's numbers."""
    rows = []
    for name in names:
        sizes = TOKEN_BYTES[name]
        shrink = sizes["oidc"] - sizes["essential"]
        rows.append({"algorithm": name, "signature_bytes": SIGNATURE_BYTES[name],
                     "fixed_bytes": FIXED_BYTES[name], "token_bytes": dict(sizes),
                     "shrink_bytes": shrink, "shrink_percent": 100 * shrink / sizes["oidc"]})
    return rows


def sweep_largest(name: str) -> int:
    """The largest verified token of a committed Sprint 2 sweep, read from its sweep.json."""
    data = json.loads((REPO / SPRINT2_RUN / name / "sweep.json").read_text(encoding="utf-8"))
    return max(entry["largest_verified_token_bytes"] for entry in data["results"]
               if entry["largest_verified_token_bytes"] is not None)


def sprint2_copy(root: Path) -> Path:
    """Copy the code, fixtures, stack files, and Sprint 2 sweep.json files under root."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for name in ("scripts", "fixtures", "transport"):
        shutil.copytree(REPO / name, root / name, ignore=ignore)
    for name in BOUNDARY_NAMES:
        target = root / SPRINT2_RUN / name / "sweep.json"
        target.parent.mkdir(parents=True)
        shutil.copy2(REPO / SPRINT2_RUN / name / "sweep.json", target)
    return root


def expected_boundaries(sizes: list[dict], largest_bytes: dict | None = None) -> list[dict]:
    """R7's entries for these size rows, derived independently from the committed sweeps (or
    from the given largest verified sizes)."""
    entries = []
    for name in BOUNDARY_NAMES:
        largest = largest_bytes[name] if largest_bytes else sweep_largest(name)
        rows = []
        for row in sizes:
            fits = {claims: row["token_bytes"][claims] <= largest for claims in COMPARED}
            rows.append({"algorithm": row["algorithm"], "fits": fits,
                         "headroom_bytes": {claims: largest - row["token_bytes"][claims]
                                            for claims in COMPARED},
                         "moved": fits["oidc"] != fits["essential"]})
        entries.append({"name": name, "transport": BOUNDARY_TRANSPORTS[name],
                        "source": f"{SPRINT2_RUN}/{name}/sweep.json",
                        "largest_verified_token_bytes": largest, "rows": rows})
    return entries


def expected_limit(algorithm: str, transport: str, claims: str) -> tuple[str, str | None]:
    """R8's expected outcome and rejecting layer on a 16 KiB-page Mac at the default limits."""
    if algorithm in ("RS256", "ES256", "EdDSA"):
        return "verified", None
    if algorithm == "ML-DSA-44":
        rejected = transport == "cookie" and claims == "oidc"
        return ("rejected", "browser") if rejected else ("verified", None)
    if transport == "bearer":
        return "rejected", "proxy"
    return "rejected", "browser" if algorithm == "SLH-DSA-SHA2-128s" else "proxy"


def synthetic_result(names=("ES256", "ML-DSA-44")) -> dict:
    """A claims.json-shaped result with every R11 key, as summary_lines would read it back."""
    sizes = expected_size_rows(names)
    limit_results, moved = [], []
    nonce = 0
    for name in names:
        for transport in TRANSPORTS:
            outcomes = {}
            for claims in COMPARED:
                outcome, layer = expected_limit(name, transport, claims)
                outcomes[claims] = outcome
                nonce += 2
                limit_results.append({
                    "algorithm": name, "transport": transport, "claims": claims,
                    "token_bytes": TOKEN_BYTES[name][claims], "outcome": outcome,
                    "rejected_by": layer, "verified_directly": True,
                    "cookie_stored": outcome == "verified" if transport == "cookie" else None,
                    "issue_nonce": f"{nonce:032x}", "verify_nonce": f"{nonce + 1:032x}",
                    "evidence": f"{outcome}: a synthetic pair"})
            moved.append({"algorithm": name, "transport": transport, **outcomes,
                          "moved": outcomes["oidc"] != outcomes["essential"]})
    rows = []
    for client in ("direct", "browser"):
        for index, name in enumerate(names):
            means = {claims: {component: 0.1 + 0.01 * index + (0.002 if claims == "oidc" else 0)
                              for component in COMPONENTS} for claims in COMPARED}
            rows.append({
                "client": client, "concurrency": 1, "algorithm": name,
                "token_bytes": {claims: TOKEN_BYTES[name][claims] for claims in COMPARED},
                "verified": {"oidc": 900, "essential": 910}, "failed": {"oidc": 0, "essential": 0},
                "throughput_rps": {"oidc": 4500.5, "essential": 4550.25},
                "median_ms": {"oidc": 0.201, "essential": 0.199},
                "p95_ms": {"oidc": 0.251, "essential": 0.249},
                "mean_ms": means,
                "difference_ms": {component: means["essential"][component]
                                  - means["oidc"][component] for component in COMPONENTS}})
    network = []
    for name in names:
        request = {claims: 120 + TOKEN_BYTES[name][claims] for claims in COMPARED}
        network.append({"algorithm": name, "request_bytes": request,
                        "saved_bytes": request["oidc"] - request["essential"],
                        "modeled": [{**profile, "saved_ms": SHRINK_BYTES * 8 / 1000
                                     / profile["uplink_mbps"]}
                                    for profile in transport_load.NETWORK_PROFILES]})
    settings = {"algorithms": list(names), "clients": ["direct", "browser"], "concurrency": [1],
                "duration": 0.2, "warmup": 0.0, "timeout": 60.0, "header_buffers": "32k",
                "upstream_keepalive": 8}
    claim_names = {name: [key for key, _ in read_fixture(name)] for name in ("minimal", "oidc")}
    claim_names["essential"] = list(ESSENTIAL_CLAIMS)
    claim_sets = [{"name": name, "file": FIXTURE_FILES[name], "claims": claim_names[name],
                   "payload_bytes": PAYLOAD_BYTES[name]} for name in CLAIM_SET_NAMES]
    return {
        "schema_version": 1,
        "started_utc": "2026-11-17T05:00:00+00:00",
        "finished_utc": "2026-11-17T05:01:00+00:00",
        "recorded_utc": "2026-11-17T05:01:01+00:00",
        "settings": settings,
        "environment": {"python": "3.15.2", "platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                        "page_size_bytes": 16384, "waitress_threads": 4,
                        "git_commit": "0" * 40, "git_dirty_scripts_or_fixtures": False},
        "layers": manifest_layers(load_manifest()),
        "browser": {"version": "156.0.8078.4", "user_agent": "Mozilla/5.0 HeadlessChrome"},
        "experiment_keys": True,
        "claim_sets": claim_sets,
        "sizes": sizes,
        "boundaries": expected_boundaries(sizes),
        "limits": {"cookie_attributes": FULL_ATTRIBUTES, "results": limit_results,
                   "moved": moved},
        "latency": {"transport": "bearer", "reference": "ES256", "size_controls": False,
                    "runs": {"oidc": "latency-oidc/load.json",
                             "essential": "latency-essential/load.json"},
                    "rows": rows, "network_model": network},
        "evidence": {"limits": {"logs": {name: f"limits/logs/{name}.gz"
                                         for name in ("app.log", "browser.log",
                                                      "proxy-access.log", "proxy-error.log")},
                                "nginx_conf": "limits/nginx.conf"},
                     "latency": {"oidc": "latency-oidc/load.json",
                                 "essential": "latency-essential/load.json"}},
    }


class JsonCase(unittest.TestCase):
    def assertJsonClose(self, actual, expected, where: str = "result") -> None:
        """Compare JSON-like values exactly, except floats, which may differ by rounding."""
        if isinstance(expected, dict):
            self.assertIsInstance(actual, dict, where)
            self.assertEqual(set(actual), set(expected), where)
            for key in expected:
                self.assertJsonClose(actual[key], expected[key], f"{where}.{key}")
        elif isinstance(expected, list):
            self.assertIsInstance(actual, list, where)
            self.assertEqual(len(actual), len(expected), where)
            for index, (got, wanted) in enumerate(zip(actual, expected)):
                self.assertJsonClose(got, wanted, f"{where}[{index}]")
        elif isinstance(expected, bool) or expected is None:
            self.assertIs(actual, expected, where)
        elif isinstance(expected, int):
            self.assertIs(type(actual), int, f"{where}: {actual!r}")
            self.assertEqual(actual, expected, where)
        elif isinstance(expected, float):
            self.assertTrue(isinstance(actual, (int, float)) and not isinstance(actual, bool),
                            f"{where}: {actual!r}")
            self.assertTrue(math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-12),
                            f"{where}: {actual!r} != {expected!r}")
        else:
            self.assertEqual(actual, expected, where)


# ---- R1: the essential fixture -----------------------------------------------------------

class EssentialFixtureTests(unittest.TestCase):
    def test_keys_in_order_with_the_oidc_values(self):
        pairs = read_fixture("essential")
        self.assertIsInstance(pairs, list, "the fixture must be a JSON object")
        self.assertEqual([key for key, _ in pairs], ESSENTIAL_CLAIMS)
        oidc = dict(read_fixture("oidc"))
        for key, value in pairs:
            with self.subTest(claim=key):
                self.assertEqual(value, oidc[key])
                self.assertIs(type(value), type(oidc[key]))

    def test_payload_bytes(self):
        for name, expected in PAYLOAD_BYTES.items():
            with self.subTest(claims=name):
                claims = dict(read_fixture(name))
                compact = json.dumps(claims, separators=(",", ":")).encode("utf-8")
                self.assertEqual(len(compact), expected)
                self.assertEqual(payload_bytes(claims), expected)

    def test_other_fixtures_unchanged(self):
        for name in ("minimal", "oidc"):
            with self.subTest(claims=name):
                before = git_show(FIXTURE_FILES[name])
                if before is None:
                    self.skipTest("BASE_COMMIT is not available in this checkout")
                text = (REPO / FIXTURE_FILES[name]).read_text(encoding="utf-8")
                self.assertEqual(text, before)


# ---- R2: claim set names and token_sizing -------------------------------------------------

class ClaimSetNameTests(unittest.TestCase):
    def test_claim_sets_keeps_only_minimal_and_oidc(self):
        self.assertEqual(list(CLAIM_SETS), ["minimal", "oidc"])
        self.assertEqual(Path(CLAIM_SETS["minimal"]).resolve(),
                         (REPO / FIXTURE_FILES["minimal"]).resolve())
        self.assertEqual(Path(CLAIM_SETS["oidc"]).resolve(),
                         (REPO / FIXTURE_FILES["oidc"]).resolve())

    def test_claim_set_names(self):
        names = claim_set_names()
        self.assertIsInstance(names, tuple)
        self.assertEqual(names, CLAIM_SET_NAMES)

    def test_claim_set_reads_every_fixture(self):
        claim_set_names()
        for name in CLAIM_SET_NAMES:
            with self.subTest(claims=name):
                expected = json.loads((REPO / FIXTURE_FILES[name]).read_text(encoding="utf-8"))
                self.assertEqual(claim_set(name), expected)
        self.assertEqual(list(claim_set("essential")), ESSENTIAL_CLAIMS)

    def test_unknown_names_raise_naming_all_three(self):
        for name in ("large", "huge", "", "Essential", "ESSENTIAL", "essential ", "essentials"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as raised:
                    claim_set(name)
                for known in CLAIM_SET_NAMES:
                    self.assertIn(known, str(raised.exception))

    def test_sizing_functions_work_with_essential_claims(self):
        essential = claim_set("essential")
        for name in NAMES:
            private_key, public_key = ADAPTERS[name].generate_keypair()
            with self.subTest(algorithm=name):
                token = padded_token(name, essential, 0, private_key, public_key)
                self.assertEqual(len(token), token_bytes(name, essential))
                self.assertEqual(len(token), TOKEN_BYTES[name]["essential"])
                verified = ADAPTERS[name].verify_token(token, public_key, audience=APP_AUDIENCE)
                self.assertEqual(verified, essential)
                padded = padded_token(name, essential, 9, private_key, public_key)
                self.assertEqual(len(padded), token_bytes(name, padded_claims(essential, 9)))
                self.assertEqual(ADAPTERS[name].verify_token(padded, public_key,
                                                             audience=APP_AUDIENCE),
                                 padded_claims(essential, 9))
                smallest = token_bytes(name, essential)
                self.assertEqual(pad_for_target(name, essential, smallest), 0)
                self.assertIsNone(pad_for_target(name, essential, smallest - 1))


# ---- R6: token_sizes -----------------------------------------------------------------------

class TokenSizesTests(JsonCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.error = None, None
        if transport_claims is not None:
            try:
                cls.rows = transport_claims.token_sizes()
            except Exception as error:  # Reported by every test instead of failing setUpClass.
                cls.error = error

    def require_rows(self) -> list[dict]:
        module()
        self.assertIsNone(self.error, f"token_sizes() raised {self.error!r}")
        return self.rows

    def test_one_row_per_configuration_in_adapter_order(self):
        rows = self.require_rows()
        self.assertIsInstance(rows, list)
        self.assertEqual([row["algorithm"] for row in rows], NAMES)
        for row in rows:
            with self.subTest(algorithm=row["algorithm"]):
                self.assertEqual(set(row), SIZE_ROW_KEYS)
                self.assertEqual(set(row["token_bytes"]), set(CLAIM_SET_NAMES))

    def test_sizes_match_the_spec(self):
        self.assertJsonClose(self.require_rows(), expected_size_rows(NAMES), "sizes")

    def test_values_are_consistent(self):
        for row in self.require_rows():
            name = row["algorithm"]
            with self.subTest(algorithm=name):
                self.assertEqual(row["signature_bytes"], ADAPTERS[name].expected_signature_bytes)
                for claims in CLAIM_SET_NAMES:
                    self.assertEqual(row["token_bytes"][claims],
                                     token_bytes(name, claim_set(claims)))
                    payload_segment = (4 * PAYLOAD_BYTES[claims] + 2) // 3
                    self.assertEqual(row["fixed_bytes"],
                                     row["token_bytes"][claims] - payload_segment)
                self.assertEqual(row["shrink_bytes"], SHRINK_BYTES)
                self.assertEqual(row["shrink_bytes"],
                                 row["token_bytes"]["oidc"] - row["token_bytes"]["essential"])

    def test_shrink_percent_is_unrounded(self):
        for row in self.require_rows():
            name = row["algorithm"]
            with self.subTest(algorithm=name):
                self.assertIs(type(row["shrink_percent"]), float)
                exact = 100 * SHRINK_BYTES / TOKEN_BYTES[name]["oidc"]
                self.assertTrue(math.isclose(row["shrink_percent"], exact, rel_tol=1e-12))
                self.assertEqual(f"{row['shrink_percent']:.1f}", SHRINK_PERCENT_ONE_DECIMAL[name])
        rs256 = self.require_rows()[0]
        self.assertNotEqual(rs256["shrink_percent"], round(rs256["shrink_percent"], 1))

    def test_selection_follows_adapter_order_without_a_reference(self):
        sizes = module().token_sizes
        self.assertJsonClose(sizes(["ML-DSA-44"]), expected_size_rows(["ML-DSA-44"]))
        self.assertJsonClose(sizes(["SLH-DSA-SHA2-128f", "EdDSA"]),
                             expected_size_rows(["EdDSA", "SLH-DSA-SHA2-128f"]))
        self.assertJsonClose(sizes(None), expected_size_rows(NAMES))

    def test_invalid_selections_raise(self):
        sizes = module().token_sizes
        for algorithms in ([], ["HS256"], ["ES256", "ES256"], ["ES256", None], "ES256"):
            with self.subTest(algorithms=algorithms), self.assertRaises(ValueError):
                sizes(algorithms)


# ---- R7: Sprint 2 boundaries, derived ---------------------------------------------------

class Sprint2BoundaryTests(JsonCase):
    def test_the_committed_sweeps_give_the_spec_boundaries(self):
        self.assertEqual({name: sweep_largest(name) for name in BOUNDARY_NAMES}, BOUNDARY_BYTES)

    def test_entries_for_all_six(self):
        sizes = expected_size_rows(NAMES)
        entries = module().sprint2_boundaries(sizes)
        self.assertIsInstance(entries, list)
        self.assertEqual([entry["name"] for entry in entries], list(BOUNDARY_NAMES))
        for entry in entries:
            with self.subTest(boundary=entry["name"]):
                self.assertEqual(set(entry), BOUNDARY_KEYS)
                self.assertEqual(entry["source"],
                                 f"{SPRINT2_RUN}/{entry['name']}/sweep.json")
                self.assertTrue((REPO / entry["source"]).is_file())
                self.assertEqual(entry["largest_verified_token_bytes"],
                                 BOUNDARY_BYTES[entry["name"]])
                for row in entry["rows"]:
                    self.assertEqual(set(row), BOUNDARY_ROW_KEYS)
                    self.assertEqual(set(row["fits"]), set(COMPARED))
                    self.assertEqual(set(row["headroom_bytes"]), set(COMPARED))
        self.assertJsonClose(entries, expected_boundaries(sizes), "boundaries")

    def test_only_ml_dsa_44_moves_at_the_cookie_boundaries(self):
        entries = module().sprint2_boundaries(expected_size_rows(NAMES))
        moved = [(entry["name"], row["algorithm"]) for entry in entries
                 for row in entry["rows"] if row["moved"]]
        self.assertEqual(moved, [("cookie-default", "ML-DSA-44"), ("cookie-16k", "ML-DSA-44")])
        bearer = entries[2]["rows"]
        self.assertEqual([row["algorithm"] for row in bearer if row["fits"]["essential"]],
                         ["RS256", "ES256", "EdDSA", "ML-DSA-44"])
        for entry in entries:
            for row in entry["rows"]:
                if row["algorithm"].startswith("SLH-DSA"):
                    self.assertEqual(row["fits"], {"oidc": False, "essential": False})
                    self.assertLess(row["headroom_bytes"]["essential"], 0)

    def test_rows_follow_the_given_sizes(self):
        # Sizes on either side of a boundary: a token that equals it fits, one byte more does not.
        boundary = BOUNDARY_BYTES["cookie-16k"]
        made_up = {"algorithm": "ES256", "signature_bytes": 64, "fixed_bytes": 124,
                   "token_bytes": {"minimal": 100, "oidc": boundary + 1, "essential": boundary},
                   "shrink_bytes": 1, "shrink_percent": 100 / (boundary + 1)}
        sizes = [expected_size_rows(["ML-DSA-44"])[0], made_up]
        entries = module().sprint2_boundaries(sizes)
        self.assertJsonClose(entries, expected_boundaries(sizes), "boundaries")
        row = entries[1]["rows"][1]
        self.assertEqual(row["fits"], {"oidc": False, "essential": True})
        self.assertEqual(row["headroom_bytes"], {"oidc": -1, "essential": 0})
        self.assertIs(row["moved"], True)
        self.assertEqual([len(entry["rows"]) for entry in entries], [2, 2, 2])

    def test_boundaries_are_read_from_the_sweep_files(self):
        # R7: the boundaries come from sweep.json, not hard-coded: change two copies and the
        # derived entries follow (the largest value over all results, not the first one).
        module()
        sizes = expected_size_rows(NAMES)
        changed = {"cookie-default": 3500, "cookie-16k": BOUNDARY_BYTES["cookie-16k"],
                   "bearer-default": 9000}
        with tempfile.TemporaryDirectory() as directory:
            root = sprint2_copy(Path(directory))
            for name in ("cookie-default", "bearer-default"):
                path = root / SPRINT2_RUN / name / "sweep.json"
                data = json.loads(path.read_text(encoding="utf-8"))
                verified = [entry for entry in data["results"]
                            if entry["largest_verified_token_bytes"] is not None]
                for index, entry in enumerate(verified):  # Ascending: the last is the largest.
                    entry["largest_verified_token_bytes"] = (changed[name]
                                                             - 7 * (len(verified) - 1 - index))
                path.write_text(json.dumps(data), encoding="utf-8")
            result = run_python(BOUNDARIES_DUMP, str(root), json.dumps(sizes), cwd=root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertJsonClose(json.loads(result.stdout), expected_boundaries(sizes, changed),
                             "boundaries")

    def test_missing_sweep_raises_runtime_error(self):
        module()
        sizes = json.dumps(expected_size_rows(["ES256", "ML-DSA-44"]))
        with tempfile.TemporaryDirectory() as directory:
            root = sprint2_copy(Path(directory))
            result = run_python(BOUNDARIES_CHECK, str(root), sizes, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), list(BOUNDARY_NAMES))
            for name in BOUNDARY_NAMES:
                with self.subTest(missing=name):
                    path = root / SPRINT2_RUN / name / "sweep.json"
                    saved = path.read_bytes()
                    path.unlink()
                    try:
                        result = run_python(BOUNDARIES_CHECK, str(root), sizes, cwd=root)
                    finally:
                        path.write_bytes(saved)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout), "RuntimeError")


# ---- R5: the module, its interface, and run_claims's argument checks ----------------------

class InterfaceTests(unittest.TestCase):
    def test_run_claims_signature_and_defaults(self):
        parameters = inspect.signature(module().run_claims).parameters
        self.assertEqual(list(parameters), ["output_dir", *RUN_CLAIMS_DEFAULTS])
        self.assertIs(parameters["output_dir"].default, inspect.Parameter.empty)
        for name, default in RUN_CLAIMS_DEFAULTS.items():
            with self.subTest(parameter=name):
                value = parameters[name].default
                if name == "concurrency":
                    self.assertEqual(list(value), default)
                elif default is None:
                    self.assertIsNone(value)
                else:
                    self.assertEqual(value, default)

    def test_other_public_functions(self):
        claims = module()
        for function, names in ((claims.token_sizes, ["algorithms"]),
                                (claims.sprint2_boundaries, ["sizes"]),
                                (claims.summary_lines, ["result"])):
            with self.subTest(function=function.__name__):
                self.assertEqual(list(inspect.signature(function).parameters), names)
        self.assertIsNone(inspect.signature(claims.token_sizes).parameters["algorithms"].default)

    def test_module_docstring_describes_phases_outputs_and_keys(self):
        text = module().__doc__ or ""
        self.assertGreater(len(text.strip()), 200)
        lowered = text.lower()
        for term in ("claims.json", "latency", "limit", "ephemeral", "experiment",
                     "production"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_import_starts_no_process_or_thread(self):
        module()
        result = run_python(IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"children": 0, "threads": 1})

    def test_stack_module_still_imports_nothing_heavy(self):
        result = run_python(STACK_IMPORT_CHECK, str(REPO))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])


class RunClaimsArgumentTests(unittest.TestCase):
    INVALID = [
        {"algorithms": "ES256"}, {"algorithms": []}, {"algorithms": ["HS256"]},
        {"algorithms": ["ES256", "ES256"]}, {"algorithms": ["ES256", None]},
        {"clients": "direct"}, {"clients": []}, {"clients": ["curl"]},
        {"clients": ["direct", "direct"]},
        {"concurrency": 1}, {"concurrency": []}, {"concurrency": [0]}, {"concurrency": [65]},
        {"concurrency": [True]}, {"concurrency": [1, 1]}, {"concurrency": [2.0]},
        {"duration": 0}, {"duration": -1}, {"duration": float("nan")},
        {"duration": float("inf")}, {"duration": True}, {"duration": "5"},
        {"warmup": -0.5}, {"warmup": float("nan")}, {"warmup": float("inf")},
        {"warmup": False}, {"warmup": "1"},
        {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")}, {"timeout": float("inf")},
        {"timeout": True},
        {"header_buffers": "big"}, {"header_buffers": "32 k"}, {"header_buffers": ""},
        {"header_buffers": 32},
        {"upstream_keepalive": 0}, {"upstream_keepalive": 1025}, {"upstream_keepalive": True},
        {"upstream_keepalive": "8"}, {"upstream_keepalive": 8.0},
    ]
    # Valid values for everything else, so each case has exactly one invalid argument.
    VALID = {"algorithms": ["ES256"], "clients": ["direct"], "concurrency": [1],
             "duration": 0.1, "warmup": 0.0, "timeout": 30.0, "header_buffers": "32k",
             "upstream_keepalive": 8}

    def test_invalid_arguments_raise_before_anything_starts(self):
        run_claims = module().run_claims
        with tempfile.TemporaryDirectory() as directory:
            for index, case in enumerate(self.INVALID):
                output = Path(directory) / f"out-{index}" / "nested"
                run_dir = Path(directory) / f"run-{index}"
                with self.subTest(case=case):
                    with self.assertRaises(ValueError):
                        run_claims(output, **{**self.VALID, **case, "run_dir": run_dir})
                    self.assertFalse(output.exists(), "the output directory was created")
                    self.assertFalse(output.parent.exists(), "the output directory was created")
                    self.assertFalse(run_dir.exists(), "a stack was started")

    def test_output_dir_must_be_new_or_empty(self):
        run_claims = module().run_claims
        with tempfile.TemporaryDirectory() as directory:
            occupied = Path(directory) / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("keep", encoding="utf-8")
            a_file = Path(directory) / "a-file"
            a_file.write_text("file", encoding="utf-8")
            for index, output in enumerate((occupied, a_file)):
                run_dir = Path(directory) / f"run-{index}"
                with self.subTest(output=output.name):
                    with self.assertRaises(ValueError):
                        run_claims(output, run_dir=run_dir, **self.VALID)
                    self.assertFalse(run_dir.exists(), "a stack was started")
            self.assertEqual(sorted(path.name for path in occupied.iterdir()), ["keep.txt"])
            self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "keep")
            self.assertEqual(a_file.read_text(encoding="utf-8"), "file")


# ---- R12: summary_lines ----------------------------------------------------------------

class SummaryLinesTests(unittest.TestCase):
    def check_lines(self, result: dict) -> None:
        lines = module().summary_lines(result)
        self.assertIsInstance(lines, list)
        names = [row["algorithm"] for row in result["sizes"]]
        for line in lines:
            with self.subTest(line=line):
                self.assertIsInstance(line, str)
                self.assertTrue(any(name in line for name in names),
                                "each line names its configuration")
        for name in names:
            with self.subTest(algorithm=name):
                needed = (1 + sum(entry["algorithm"] == name
                                  for entry in result["limits"]["moved"])
                          + sum(row["algorithm"] == name for row in result["latency"]["rows"]))
                naming = [line for line in lines if name in line]
                self.assertGreaterEqual(len(naming), needed, lines)
        self.assertGreaterEqual(len(lines), len(result["sizes"]) + len(result["limits"]["moved"])
                                + len(result["latency"]["rows"]))

    def test_lines_for_every_size_moved_entry_and_latency_row(self):
        self.check_lines(synthetic_result())

    def test_every_configuration(self):
        self.check_lines(synthetic_result(tuple(NAMES)))

    def test_reads_only_the_saved_json(self):
        result = synthetic_result()
        text = json.dumps(result)
        lines = module().summary_lines(json.loads(text))
        self.assertEqual(json.dumps(result), text, "summary_lines changed its argument")
        self.assertEqual(module().summary_lines(json.loads(text)), lines)


# ---- R4: the load workload accepts the essential claims -----------------------------------

class UnreachableStack:
    """A stack whose URLs nothing listens on, so every request sent to it fails at once."""

    def __init__(self, run_dir: Path):
        self.proxy_url = self.app_url = "http://127.0.0.1:9"
        self.run_dir = run_dir


class LoadAcceptsEssentialTests(unittest.TestCase):
    def checked(self, **given) -> dict:
        return transport_load.checked_settings(**{**LOAD_DEFAULTS, **given})

    def test_checked_settings_accepts_every_claim_set(self):
        for name in CLAIM_SET_NAMES:
            with self.subTest(claims=name):
                settings = self.checked(claims=name)
                self.assertEqual(settings["claims"], name)
                self.assertEqual(settings["algorithms"], NAMES)

    def test_other_claim_names_still_raise(self):
        for name in ("huge", "large", "Essential", "", None):
            with self.subTest(claims=name), self.assertRaises(ValueError):
                self.checked(claims=name)
            with tempfile.TemporaryDirectory() as directory:
                with self.subTest(claims=name, function="run_load"), \
                        self.assertRaises(ValueError):
                    transport_load.run_load(UnreachableStack(Path(directory) / "run"),
                                            claims=name)

    def test_run_load_plans_essential_cells(self):
        with tempfile.TemporaryDirectory() as directory:
            result = transport_load.run_load(
                UnreachableStack(Path(directory) / "run"), algorithms=["EdDSA"],
                clients=["direct"], concurrency=[1], duration=0.1, warmup=0.0,
                claims="essential", timeout=5.0)
        self.assertEqual(result["settings"]["claims"], "essential")
        self.assertEqual(result["settings"]["algorithms"], ["ES256", "EdDSA"])
        self.assertTrue(result["results"])
        for cell in result["results"]:
            with self.subTest(algorithm=cell["algorithm"], variant=cell["variant"]):
                self.assertEqual(cell["claims"], "essential")
                self.assertEqual(cell["token_bytes"], TOKEN_BYTES[cell["algorithm"]]["essential"])
                self.assertFalse(cell["issue"]["delivered"])  # Nothing listens at the stack.
        rows = {row["algorithm"]: row for row in result["network_model"]["rows"]}
        self.assertEqual(rows["EdDSA"]["request_bytes"], rows["ES256"]["request_bytes"])

    def test_default_settings_unchanged(self):
        self.assertEqual(transport_load.default_settings(), LOAD_DEFAULTS)

    def test_saved_settings_with_essential_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "load.json"
            saved = {**self.checked(claims="essential", concurrency=[1], duration=2.0,
                                    header_buffers="32k", upstream_keepalive=64)}
            path.write_text(json.dumps({"settings": saved}), encoding="utf-8")
            read = transport_load.read_saved_settings(path)
            self.assertEqual(read, saved)
            self.assertEqual(self.checked(**read), saved)


if __name__ == "__main__":
    unittest.main()
