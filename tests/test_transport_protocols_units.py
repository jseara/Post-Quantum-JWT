"""Check S3-04's helpers without nginx or a browser: generate_certificate's per-run certificate
and experiment key, certificate_details, client_context and http_get against local TLS servers,
compare_sweeps on small synthetic sweep results and on Sprint 2's WSL2 runs, summary_lines, the
protocols module's constants, and the TLS interface of scripts/transport_stack.py; no timing
thresholds."""

import ast
import copy
import dataclasses
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

from scripts import transport_stack
from scripts.algorithms import ADAPTER_LIST

try:
    from scripts import transport_tls
    TLS_IMPORT_ERROR = None
except Exception as error:  # Before S3-04's TLS helpers are built: tests fail, not vanish.
    transport_tls, TLS_IMPORT_ERROR = None, error

try:
    from scripts import transport_protocols
    PROTOCOLS_IMPORT_ERROR = None
except Exception as error:  # Before S3-04's protocols command is built.
    transport_protocols, PROTOCOLS_IMPORT_ERROR = None, error


REPO = Path(__file__).resolve().parents[1]
BASELINE = REPO / "results" / "transport" / "20261113T074114Z-wsl2"
HOST = "127.0.0.1"
NAMES = [adapter.name for adapter in ADAPTER_LIST]
PROTOCOL_ORDER = ("http", "https", "h2")
SWEEP_NAMES = ("cookie-default", "cookie-16k", "bearer-default", "bearer-512k")
# R11: each sweep of `make sweep`, as SWEEPS must define it.
SWEEP_SETTINGS = {
    "cookie-default": {"transport": "cookie", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24576},
    "cookie-16k": {"transport": "cookie", "proxy_buffers": "16k", "header_buffers": None,
                   "step": 512, "max_bytes": 24576},
    "bearer-default": {"transport": "bearer", "proxy_buffers": None, "header_buffers": None,
                       "step": 512, "max_bytes": 24576},
    "bearer-512k": {"transport": "bearer", "proxy_buffers": None, "header_buffers": "512k",
                    "step": 16384, "max_bytes": 327680},
}
TRANSPORT_OF = {name: settings["transport"] for name, settings in SWEEP_SETTINGS.items()}
DETAILS_KEYS = {"subject", "issuer", "subject_alt_names", "not_before", "not_after",
                "public_key", "sha256_fingerprint"}
ROW_KEYS = {"sweep", "algorithm", "client", "baseline", "measured", "moved", "difference_bytes",
            "moved_by_http2"}
FINGERPRINT = re.compile(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}")
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
MAX_VALIDITY = timedelta(days=31)


# ---- the modules under test ----------------------------------------------------------------

def tls():
    """Return scripts.transport_tls, failing the calling test when it cannot be imported."""
    if transport_tls is None:
        raise AssertionError(f"scripts/transport_tls.py cannot be imported: {TLS_IMPORT_ERROR!r}")
    return transport_tls


def protocols():
    """Return scripts.transport_protocols, failing the calling test when it cannot be imported."""
    if transport_protocols is None:
        raise AssertionError(f"scripts/transport_protocols.py cannot be imported: "
                             f"{PROTOCOLS_IMPORT_ERROR!r}")
    return transport_protocols


def api(module, name: str):
    """An attribute S3-04 adds to a module, failing the test when it is missing."""
    if not hasattr(module, name):
        raise AssertionError(f"{module.__name__} has no {name}")
    return getattr(module, name)


def generate_certificate(directory) -> tuple[Path, Path]:
    return api(tls(), "generate_certificate")(directory)


def certificate_details(certificate) -> dict:
    return api(tls(), "certificate_details")(certificate)


def client_context(certificate) -> ssl.SSLContext:
    return api(tls(), "client_context")(certificate)


def compare_sweeps(sweep: str, baseline, measured) -> list[dict]:
    return api(protocols(), "compare_sweeps")(sweep, baseline, measured)


def definition_value(definition, key: str):
    """A SWEEPS entry's value, whether the entry is a mapping or an object with attributes."""
    if isinstance(definition, dict):
        return definition[key]
    return getattr(definition, key)


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def colon_fingerprint(certificate: x509.Certificate) -> str:
    return ":".join(f"{byte:02X}" for byte in certificate.fingerprint(hashes.SHA256()))


def parse_utc(text) -> datetime:
    """An ISO 8601 time; raises ValueError unless it is UTC."""
    value = datetime.fromisoformat(text)
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{text!r} is not UTC")
    return value


def contains_number(text: str, number: int) -> bool:
    """True when text shows number, with or without thousands separators."""
    return re.search(rf"(?<![\d,.])(?:{number}|{number:,})(?!,?\d)", text) is not None


def run_python(code: str, *arguments: str) -> subprocess.CompletedProcess:
    """Run code in a fresh interpreter of this environment."""
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", code, *arguments], capture_output=True,
                          text=True, timeout=120, env=environment, cwd=REPO)


# ---- local TLS servers ---------------------------------------------------------------------

class HandshakeServer:
    """A one-connection TLS server on 127.0.0.1 in a thread, with the given ALPN protocols."""

    def __init__(self, certificate: Path, key: Path, alpn: list[str]):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(key))
        context.set_alpn_protocols(alpn)
        self.listener = socket.socket()
        self.listener.bind((HOST, 0))
        self.listener.listen(1)
        self.listener.settimeout(30)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, args=(context,), daemon=True)
        self.thread.start()

    def serve(self, context: ssl.SSLContext) -> None:
        try:
            connection, _ = self.listener.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(30)
            try:
                with context.wrap_socket(connection, server_side=True) as secured:
                    secured.sendall(b"ok")
            except OSError:  # The client refused the certificate or closed first.
                pass

    def close(self) -> None:
        self.listener.close()
        self.thread.join(30)


def handshake(context: ssl.SSLContext, port: int, hostname: str) -> str | None:
    """Complete a TLS handshake with the server; return the ALPN protocol it selected."""
    with socket.create_connection((HOST, port), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as secured:
            return secured.selected_alpn_protocol()


class EchoHandler(BaseHTTPRequestHandler):
    """Answer every GET with its path, HTTP version, and the TLS connection's ALPN protocol."""

    def do_GET(self) -> None:
        alpn = (self.connection.selected_alpn_protocol()
                if isinstance(self.connection, ssl.SSLSocket) else None)
        body = json.dumps({"path": self.path, "version": self.request_version,
                           "alpn": alpn}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args) -> None:  # Keep the test output quiet.
        pass


class EchoServer:
    """An HTTP or (with a certificate) HTTPS echo server on 127.0.0.1 in a thread."""

    def __init__(self, certificate: Path | None = None, key: Path | None = None):
        self.server = ThreadingHTTPServer((HOST, 0), EchoHandler)
        self.server.daemon_threads = True
        if certificate is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(certificate), str(key))
            context.set_alpn_protocols(["h2", "http/1.1"])
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(30)


# ---- synthetic sweep results -------------------------------------------------------------

def synthetic_probe(token_bytes: int, outcome: str, rejected_by: str | None,
                    client: str = "browser") -> dict:
    """A probe as run_sweep records it, with fields a summary must leave out."""
    return {"client": client, "pad": token_bytes - 200, "token_bytes": token_bytes,
            "outcome": outcome, "rejected_by": rejected_by, "verified_directly": True,
            "verify_status": 200 if outcome == "verified" else 400,
            "evidence": f"{rejected_by or 'verified'}: synthetic probe of {token_bytes:,} bytes",
            "verify_nonce": "0" * 32}


def entry(algorithm: str, client: str | None = "browser", largest: int | None = None,
          first: tuple | None = None, boundaries=(), smallest: int = 208) -> dict:
    """One configuration's sweep entry; client None leaves the key out, as Sprint 2's cookie
    sweeps did."""
    probe_client = client or "browser"
    data = {
        "algorithm": algorithm,
        "smallest_token_bytes": smallest,
        "largest_verified_token_bytes": largest,
        "first_rejection": (None if first is None else
                            {"token_bytes": first[0], "rejected_by": first[1],
                             "evidence": f"{first[1]}: first rejection at {first[0]:,} bytes"}),
        "boundaries": [{"last": synthetic_probe(size - 1, "verified", None, probe_client),
                        "first": synthetic_probe(size, outcome, layer, probe_client)}
                       for size, outcome, layer in boundaries],
        "probes": [],
    }
    return data if client is None else {"client": client, **data}


def sweep_result(transport: str, *entries: dict) -> dict:
    """A run_sweep result with the given entries."""
    return {"transport": transport,
            "settings": {"algorithms": sorted({item["algorithm"] for item in entries}),
                         "claims": "minimal", "step": 512, "max_bytes": 24576},
            "proxy_url": "https://127.0.0.1:1", "app_url": "http://127.0.0.1:2",
            "run_dir": "/tmp/run", "results": list(entries)}


def summary(largest: int | None, first: tuple | None = None, boundaries=()) -> dict:
    """The summary compare_sweeps gives an entry (R13)."""
    return {"largest_verified_token_bytes": largest,
            "first_rejection": (None if first is None else
                                {"token_bytes": first[0], "rejected_by": first[1]}),
            "boundaries": [{"token_bytes": size, "outcome": outcome, "rejected_by": layer}
                           for size, outcome, layer in boundaries]}


BEARER_LIMIT = {"largest": 8168, "first": (8170, "proxy"),
                "boundaries": [(8170, "rejected", "proxy")]}
BEARER_SUMMARY = summary(8168, (8170, "proxy"), [(8170, "rejected", "proxy")])


def load_baseline(sweep: str) -> dict:
    return json.loads((BASELINE / sweep / "sweep.json").read_text(encoding="utf-8"))


# ---- R1, R2, R5, R12: the interface ------------------------------------------------------

class InterfaceTests(unittest.TestCase):
    def test_start_stack_and_stack_keep_their_shape(self):
        parameters = inspect.signature(transport_stack.start_stack).parameters
        self.assertEqual(list(parameters), ["proxy_port", "app_port", "run_dir", "timeout",
                                            "proxy_buffers", "header_buffers",
                                            "upstream_keepalive", "ref_store"])
        names = [field.name for field in dataclasses.fields(transport_stack.Stack)]
        self.assertEqual(names, ["proxy_url", "app_url", "run_dir", "upstream_keepalive",
                                 "ref_store", "store_url"])

    def test_tls_protocols(self):
        self.assertEqual(api(transport_stack, "TLS_PROTOCOLS"), ("https", "h2"))

    def test_tls_stack_dataclass(self):
        tls_stack = api(transport_stack, "TlsStack")
        self.assertTrue(dataclasses.is_dataclass(tls_stack))
        self.assertTrue(issubclass(tls_stack, transport_stack.Stack))
        self.assertTrue(tls_stack.__dataclass_params__.frozen)
        fields = dataclasses.fields(tls_stack)
        base = [field.name for field in dataclasses.fields(transport_stack.Stack)]
        self.assertEqual([field.name for field in fields], [*base, "protocol", "certificate"])
        defaults = {field.name: field.default for field in fields}
        self.assertEqual(defaults["protocol"], "https")
        self.assertIsNone(defaults["certificate"])
        stack = tls_stack(proxy_url="https://127.0.0.1:1", app_url="http://127.0.0.1:2",
                          run_dir=Path("/tmp/run"))
        self.assertEqual((stack.protocol, stack.certificate), ("https", None))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            stack.protocol = "h2"

    def test_start_tls_stack_signature(self):
        parameters = inspect.signature(api(transport_stack, "start_tls_stack")).parameters
        self.assertEqual(list(parameters), ["protocol", "proxy_port", "app_port", "run_dir",
                                            "timeout", "proxy_buffers", "header_buffers"])
        self.assertEqual({name: parameter.default for name, parameter in parameters.items()},
                         {"protocol": "https", "proxy_port": None, "app_port": None,
                          "run_dir": None, "timeout": 60.0, "proxy_buffers": None,
                          "header_buffers": None})

    def test_http_get_signature(self):
        parameters = inspect.signature(transport_stack.http_get).parameters
        self.assertEqual(list(parameters), ["url", "headers", "timeout", "certificate"])
        self.assertEqual([parameter.default for parameter in parameters.values()][1:],
                         [None, 10.0, None])

    def test_run_protocols_signature(self):
        parameters = inspect.signature(api(protocols(), "run_protocols")).parameters
        self.assertEqual(list(parameters), ["output_dir", "protocols", "sweeps", "algorithms",
                                            "baseline", "step", "max_bytes", "timeout",
                                            "run_dir"])
        defaults = {name: parameter.default for name, parameter in parameters.items()}
        self.assertIs(defaults["output_dir"], inspect.Parameter.empty)
        self.assertEqual(tuple(defaults["protocols"]), ("https", "h2"))
        for name in ("sweeps", "algorithms", "baseline", "step", "max_bytes", "run_dir"):
            with self.subTest(parameter=name):
                self.assertIsNone(defaults[name])
        self.assertEqual(defaults["timeout"], 60.0)

    def test_compare_sweeps_and_summary_lines(self):
        parameters = inspect.signature(api(protocols(), "compare_sweeps")).parameters
        self.assertEqual(list(parameters), ["sweep", "baseline", "measured"])
        self.assertTrue(callable(api(protocols(), "summary_lines")))

    def test_modules_start_with_a_docstring(self):
        for name in ("transport_tls", "transport_protocols"):
            with self.subTest(module=name):
                path = REPO / "scripts" / f"{name}.py"
                self.assertTrue(path.is_file(), f"scripts/{name}.py is missing")
                tree = ast.parse(path.read_text(encoding="utf-8"))
                self.assertTrue((ast.get_docstring(tree) or "").strip(), name)

    def test_tls_module_uses_only_cryptography_and_the_standard_library(self):
        path = REPO / "scripts" / "transport_tls.py"
        self.assertTrue(path.is_file(), "scripts/transport_tls.py is missing")
        allowed = set(sys.stdlib_module_names) | {"cryptography", "scripts", "__future__"}
        roots = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                roots |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        self.assertLessEqual(roots, allowed, sorted(roots - allowed))

    def test_imports_stay_lazy(self):
        # transport_stack must not load the TLS or protocols modules, cryptography, or
        # Playwright on import; transport_protocols starts no process, thread, or browser.
        stack_check = (
            "import json, sys\n"
            "import scripts.transport_stack\n"
            "print(json.dumps(sorted(name for name in ('scripts.transport_tls',"
            " 'scripts.transport_protocols', 'cryptography', 'playwright')"
            " if name in sys.modules)))\n")
        result = run_python(stack_check)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])
        protocols()  # Fails here, not below, without the module.
        module_check = (
            "import json, os, subprocess, sys, threading\n"
            "import scripts.transport_protocols\n"
            "listing = subprocess.Popen(['ps', '-A', '-o', 'pid=,ppid='],"
            " stdout=subprocess.PIPE, text=True)\n"
            "output, _ = listing.communicate()\n"
            "children = [fields[0] for fields in (line.split() for line in output.splitlines())"
            " if len(fields) == 2 and fields[1] == str(os.getpid())"
            " and fields[0] != str(listing.pid)]\n"
            "print(json.dumps({'playwright': any(name == 'playwright' or"
            " name.startswith('playwright.') for name in sys.modules),"
            " 'threads': threading.active_count(), 'children': len(children)}))\n")
        result = run_python(module_check)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {"playwright": False, "threads": 1, "children": 0})


# ---- R11: the protocols module's constants -----------------------------------------------

class ConstantsTests(unittest.TestCase):
    def test_protocols(self):
        self.assertEqual(tuple(api(protocols(), "PROTOCOLS")), PROTOCOL_ORDER)

    def test_default_baseline(self):
        default = Path(api(protocols(), "DEFAULT_BASELINE"))
        self.assertTrue(default.is_absolute(), default)
        self.assertEqual(default.resolve(), BASELINE.resolve())

    def test_sweeps_mirror_make_sweep(self):
        sweeps = api(protocols(), "SWEEPS")
        self.assertEqual(list(sweeps), list(SWEEP_NAMES))
        for name, expected in SWEEP_SETTINGS.items():
            for key, value in expected.items():
                with self.subTest(sweep=name, key=key):
                    self.assertEqual(definition_value(sweeps[name], key), value)


# ---- R3: generate_certificate --------------------------------------------------------------

class GenerateCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.target = cls.directory / "run" / "nested" / "tls"
        cls.paths, cls.error = None, None
        cls.before = datetime.now(timezone.utc)
        try:
            cls.paths = generate_certificate(cls.target)
        except Exception as error:  # Reported by every test.
            cls.error = error
        cls.after = datetime.now(timezone.utc)

    def setUp(self):
        tls()
        self.assertIsNone(self.error, f"generate_certificate raised {self.error!r}")
        self.certificate_path, self.key_path = self.paths
        self.certificate = load_certificate(self.certificate_path)

    def test_creates_the_directory_and_returns_absolute_paths(self):
        self.assertIsInstance(self.paths, tuple)
        self.assertEqual(len(self.paths), 2)
        for path, name in zip(self.paths, ("certificate.pem", "experiment-key.pem")):
            with self.subTest(name=name):
                self.assertIsInstance(path, Path)
                self.assertTrue(path.is_absolute(), path)
                self.assertEqual(path.name, name)
                self.assertEqual(path.parent.resolve(), self.target.resolve())
                self.assertTrue(path.is_file())
        self.assertEqual(sorted(path.name for path in self.target.iterdir()),
                         ["certificate.pem", "experiment-key.pem"])

    def test_relative_directory_gives_absolute_paths(self):
        target = self.directory / "relative" / "tls"
        relative = Path(os.path.relpath(target))
        self.assertFalse(relative.is_absolute())
        certificate, key = generate_certificate(relative)
        for path in (certificate, key):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_absolute(), path)
                self.assertEqual(path.parent.resolve(), target.resolve())

    def test_self_signed_v3_ec_p256_with_ecdsa_sha256(self):
        certificate = self.certificate
        self.assertEqual(certificate.version, x509.Version.v3)
        public_key = certificate.public_key()
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)
        self.assertIsInstance(public_key.curve, ec.SECP256R1)
        self.assertEqual(certificate.signature_algorithm_oid,
                         SignatureAlgorithmOID.ECDSA_WITH_SHA256)
        self.assertIsInstance(certificate.signature_hash_algorithm, hashes.SHA256)
        self.assertEqual(certificate.subject, certificate.issuer)
        certificate.verify_directly_issued_by(certificate)  # Signed by its own key.

    def test_subject_names_localhost_and_says_not_a_production_credential(self):
        subject = self.certificate.subject
        self.assertEqual([attribute.value for attribute
                          in subject.get_attributes_for_oid(NameOID.COMMON_NAME)], ["localhost"])
        organizations = [attribute.value for attribute
                         in subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
        self.assertEqual(len(organizations), 1, organizations)
        self.assertIn("not a production credential", organizations[0].lower())

    def test_extensions(self):
        extensions = self.certificate.extensions
        names = extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(len(list(names)), 2)
        self.assertEqual(names.get_values_for_type(x509.DNSName), ["localhost"])
        self.assertEqual(names.get_values_for_type(x509.IPAddress),
                         [ipaddress.ip_address("127.0.0.1")])
        constraints = extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(constraints.ca)
        usage = extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertEqual(list(usage), [ExtendedKeyUsageOID.SERVER_AUTH])

    def test_validity_covers_generation_and_is_at_most_31_days(self):
        not_before = self.certificate.not_valid_before_utc
        not_after = self.certificate.not_valid_after_utc
        self.assertLessEqual(not_before, self.after)
        self.assertGreaterEqual(not_after, self.before)
        self.assertLessEqual(not_after - not_before, MAX_VALIDITY)

    def test_key_file_is_unencrypted_pkcs8_with_mode_0600(self):
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        data = self.key_path.read_bytes()
        self.assertTrue(data.startswith(b"-----BEGIN PRIVATE KEY-----"), data[:40])
        key = serialization.load_pem_private_key(data, password=None)
        self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(key.curve, ec.SECP256R1)
        self.assertEqual(key.public_key().public_numbers(),
                         self.certificate.public_key().public_numbers())
        self.assertNotIn(b"PRIVATE KEY", self.certificate_path.read_bytes())

    def test_key_mode_does_not_depend_on_the_umask(self):
        for mask in (0, 0o022):
            with self.subTest(umask=oct(mask)):
                previous = os.umask(mask)
                try:
                    _, key = generate_certificate(self.directory / f"umask-{mask:o}")
                finally:
                    os.umask(previous)
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)

    def test_each_call_makes_a_new_key(self):
        certificate, key = generate_certificate(self.directory / "second")
        other = load_certificate(certificate)
        self.assertNotEqual(colon_fingerprint(other), colon_fingerprint(self.certificate))
        self.assertNotEqual(other.public_key().public_numbers(),
                            self.certificate.public_key().public_numbers())
        self.assertNotEqual(key.read_bytes(), self.key_path.read_bytes())


# ---- R4: certificate_details ---------------------------------------------------------------

class CertificateDetailsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.paths, cls.error = None, None
        try:
            cls.paths = generate_certificate(cls.directory / "tls")
        except Exception as error:  # Reported by every test.
            cls.error = error

    def setUp(self):
        tls()
        self.assertIsNone(self.error, f"generate_certificate raised {self.error!r}")
        self.certificate_path = self.paths[0]
        self.certificate = load_certificate(self.certificate_path)
        self.details = certificate_details(self.certificate_path)

    def test_exact_keys_and_values(self):
        details = self.details
        self.assertEqual(set(details), DETAILS_KEYS)
        self.assertEqual(details["subject"], self.certificate.subject.rfc4514_string())
        self.assertIn("CN=localhost", details["subject"])
        self.assertEqual(details["issuer"], details["subject"])
        self.assertEqual(details["subject_alt_names"], ["DNS:localhost", "IP:127.0.0.1"])
        self.assertEqual(details["public_key"], "EC P-256")
        self.assertEqual(details["sha256_fingerprint"], colon_fingerprint(self.certificate))
        self.assertRegex(details["sha256_fingerprint"], f"^{FINGERPRINT.pattern}$")

    def test_validity_as_utc_iso_8601(self):
        self.assertEqual(parse_utc(self.details["not_before"]),
                         self.certificate.not_valid_before_utc)
        self.assertEqual(parse_utc(self.details["not_after"]),
                         self.certificate.not_valid_after_utc)

    def test_json_without_pem_or_token_like_runs(self):
        text = json.dumps(self.details)
        self.assertEqual(json.loads(text), self.details)
        self.assertNotIn("-----BEGIN", text)
        self.assertEqual(TOKEN_LIKE.findall(text), [])

    def test_differs_between_certificates(self):
        other, _ = generate_certificate(self.directory / "other")
        details = certificate_details(other)
        self.assertNotEqual(details["sha256_fingerprint"], self.details["sha256_fingerprint"])
        self.assertEqual(details["subject_alt_names"], self.details["subject_alt_names"])


# ---- R4, R5: client_context and http_get ---------------------------------------------------

class ClientContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.paths, cls.other, cls.error = None, None, None
        try:
            cls.paths = generate_certificate(cls.directory / "tls")
            cls.other = generate_certificate(cls.directory / "other")
        except Exception as error:  # Reported by every test.
            cls.error = error

    def setUp(self):
        tls()
        self.assertIsNone(self.error, f"generate_certificate raised {self.error!r}")
        self.certificate, self.key = self.paths

    def server(self, alpn: list[str], paths: tuple[Path, Path] | None = None) -> HandshakeServer:
        certificate, key = paths or self.paths
        server = HandshakeServer(certificate, key, alpn)
        self.addCleanup(server.close)
        return server

    def test_requires_verification_and_trusts_only_the_certificate(self):
        context = client_context(self.certificate)
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        # One certificate in the store: no system CA was loaded.
        self.assertEqual(context.cert_store_stats()["x509"], 1)

    def test_offers_http11_only(self):
        # The server prefers h2, so a client that offered h2 would get it.
        for hostname in ("127.0.0.1", "localhost"):
            with self.subTest(hostname=hostname):
                server = self.server(["h2", "http/1.1"])
                self.assertEqual(handshake(client_context(self.certificate), server.port,
                                           hostname), "http/1.1")
        control = ssl.create_default_context(cafile=str(self.certificate))
        control.set_alpn_protocols(["h2", "http/1.1"])
        server = self.server(["h2", "http/1.1"])
        self.assertEqual(handshake(control, server.port, "127.0.0.1"), "h2")

    def test_never_negotiates_h2(self):
        server = self.server(["h2"])
        try:
            selected = handshake(client_context(self.certificate), server.port, "127.0.0.1")
        except ssl.SSLError as error:  # A server may also refuse a client without h2.
            selected = repr(error)
        self.assertNotEqual(selected, "h2")

    def test_rejects_another_certificate(self):
        server = self.server(["http/1.1"], self.other)
        with self.assertRaises(ssl.SSLError):
            handshake(client_context(self.certificate), server.port, "127.0.0.1")

    def test_checks_the_host_name(self):
        server = self.server(["http/1.1"])
        with self.assertRaises(ssl.SSLError):
            handshake(client_context(self.certificate), server.port, "example.com")

    def test_http_get_verifies_https_with_the_certificate(self):
        server = EchoServer(self.certificate, self.key)
        self.addCleanup(server.close)
        url = f"https://{HOST}:{server.port}/api/echo?nonce=abc"
        status, headers, body = transport_stack.http_get(url, certificate=self.certificate)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        echoed = json.loads(body)
        self.assertEqual(echoed, {"path": "/api/echo?nonce=abc", "version": "HTTP/1.1",
                                  "alpn": "http/1.1"})
        with self.assertRaises(OSError):  # Python's default verification refuses it.
            transport_stack.http_get(url)
        with self.assertRaises(OSError):
            transport_stack.http_get(url, certificate=self.other[0])

    def test_http_get_ignores_the_certificate_for_http(self):
        server = EchoServer()
        self.addCleanup(server.close)
        url = f"http://{HOST}:{server.port}/api/echo"
        for certificate in (None, self.certificate, self.directory / "missing.pem"):
            with self.subTest(certificate=certificate):
                status, _, body = transport_stack.http_get(url, certificate=certificate)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["alpn"], None)


# ---- R13: compare_sweeps -------------------------------------------------------------------

class CompareSweepsTests(unittest.TestCase):
    def setUp(self):
        api(protocols(), "compare_sweeps")

    def row(self, rows: list[dict], algorithm: str, client: str) -> dict:
        found = [row for row in rows if (row["algorithm"], row["client"]) == (algorithm, client)]
        self.assertEqual(len(found), 1, rows)
        return found[0]

    def test_row_shape_and_summaries(self):
        baseline = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT),
                                entry("ES256", "direct", **BEARER_LIMIT))
        measured = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT),
                                entry("ES256", "direct", **BEARER_LIMIT))
        rows = compare_sweeps("bearer-default", baseline, {"https": measured})
        self.assertEqual(rows, [
            {"sweep": "bearer-default", "algorithm": "ES256", "client": client,
             "baseline": BEARER_SUMMARY, "measured": {"https": BEARER_SUMMARY},
             "moved": {"https": False}, "difference_bytes": {"https": 0},
             "moved_by_http2": None}
            for client in ("browser", "direct")])
        for row in rows:
            self.assertEqual(set(row), ROW_KEYS)

    def test_rows_follow_adapter_list_then_browser_before_direct(self):
        scrambled = [("SLH-DSA-SHA2-128f", "direct"), ("RS256", "direct"),
                     ("ML-DSA-44", "browser"), ("RS256", "browser"),
                     ("SLH-DSA-SHA2-128f", "browser"), ("ES256", "direct")]
        measured = sweep_result("bearer", *(entry(name, client, **BEARER_LIMIT)
                                            for name, client in scrambled))
        rows = compare_sweeps("bearer-default", None, {"h2": measured})
        expected = sorted(scrambled, key=lambda pair: (NAMES.index(pair[0]),
                                                       ("browser", "direct").index(pair[1])))
        self.assertEqual([(row["algorithm"], row["client"]) for row in rows], expected)
        self.assertEqual([row["sweep"] for row in rows], ["bearer-default"] * len(scrambled))

    def test_rows_are_the_union_of_measured_entries(self):
        baseline = sweep_result("bearer", entry("RS256", "browser", **BEARER_LIMIT),
                                entry("ES256", "browser", **BEARER_LIMIT))
        https = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT))
        h2 = sweep_result("bearer", entry("EdDSA", "direct", **BEARER_LIMIT),
                          entry("ES256", "browser", **BEARER_LIMIT))
        rows = compare_sweeps("bearer-default", baseline, {"https": https, "h2": h2})
        self.assertEqual([(row["algorithm"], row["client"]) for row in rows],
                         [("ES256", "browser"), ("EdDSA", "direct")])
        eddsa = self.row(rows, "EdDSA", "direct")
        self.assertIsNone(eddsa["baseline"])
        self.assertEqual(eddsa["measured"], {"https": None, "h2": BEARER_SUMMARY})
        self.assertEqual(eddsa["moved"], {"https": None, "h2": None})
        self.assertEqual(eddsa["difference_bytes"], {"https": None, "h2": None})
        self.assertIsNone(eddsa["moved_by_http2"])
        es256 = self.row(rows, "ES256", "browser")
        self.assertEqual(es256["moved"], {"https": False, "h2": False})
        self.assertIs(es256["moved_by_http2"], False)

    def test_entry_without_client_counts_as_browser(self):
        cookie = {"largest": 4092, "first": (4094, "browser"),
                  "boundaries": [(4094, "rejected", "browser")]}
        baseline = sweep_result("cookie", entry("ES256", None, **cookie))
        https = sweep_result("cookie", entry("ES256", "browser", **cookie))
        h2 = sweep_result("cookie", entry("ES256", None, **cookie))
        rows = compare_sweeps("cookie-16k", baseline, {"https": https, "h2": h2})
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["client"], "browser")
        expected = summary(4092, (4094, "browser"), [(4094, "rejected", "browser")])
        self.assertEqual(row["baseline"], expected)
        self.assertEqual(row["measured"], {"https": expected, "h2": expected})
        self.assertEqual(row["moved"], {"https": False, "h2": False})

    def test_moved_when_the_largest_verified_token_differs(self):
        baseline = sweep_result("cookie", entry("RS256", None, 3915, (3916, "proxy"),
                                                [(3916, "rejected", "proxy")]))
        https = sweep_result("cookie", entry("RS256", "browser", 4092, (4094, "browser"),
                                             [(4094, "rejected", "browser")]))
        h2 = sweep_result("cookie", entry("RS256", "browser", 3800, (3802, "proxy"),
                                          [(3802, "rejected", "proxy")]))
        row = compare_sweeps("cookie-default", baseline, {"https": https, "h2": h2})[0]
        self.assertEqual(row["moved"], {"https": True, "h2": True})
        self.assertEqual(row["difference_bytes"], {"https": 177, "h2": -115})
        self.assertIs(row["moved_by_http2"], True)

    def test_moved_when_only_the_boundaries_differ(self):
        base_boundaries = [(4094, "rejected", "browser"), (16204, "rejected", "proxy")]
        baseline = sweep_result("cookie", entry("ES256", "browser", 4092, (4094, "browser"),
                                                base_boundaries))
        variants = {
            "missing boundary": [(4094, "rejected", "browser")],
            "other layer": [(4094, "rejected", "proxy"), (16204, "rejected", "proxy")],
            "other outcome": [(4094, "verified", None), (16204, "rejected", "proxy")],
            "other size": [(4094, "rejected", "browser"), (16205, "rejected", "proxy")],
            "extra boundary": [*base_boundaries, (20000, "rejected", "app_server")],
        }
        for name, boundaries in variants.items():
            with self.subTest(name):
                measured = sweep_result("cookie", entry("ES256", "browser", 4092,
                                                        (4094, "browser"), boundaries))
                same = sweep_result("cookie", entry("ES256", "browser", 4092,
                                                    (4094, "browser"), base_boundaries))
                row = compare_sweeps("cookie-16k", baseline,
                                     {"https": same, "h2": measured})[0]
                self.assertEqual(row["moved"], {"https": False, "h2": True})
                self.assertEqual(row["difference_bytes"], {"https": 0, "h2": 0})
                self.assertIs(row["moved_by_http2"], True)

    def test_not_moved_when_only_other_fields_differ(self):
        baseline = sweep_result("bearer", entry("ML-DSA-44", "direct", **BEARER_LIMIT))
        changed = entry("ML-DSA-44", "direct", smallest=3355, **BEARER_LIMIT)
        changed["first_rejection"]["evidence"] = "proxy: different words"
        changed["boundaries"][0]["first"]["evidence"] = "proxy: other evidence"
        changed["boundaries"][0]["first"]["pad"] = 1
        changed["boundaries"][0]["first"]["verify_status"] = None
        changed["boundaries"][0]["last"] = synthetic_probe(5000, "verified", None, "direct")
        changed["probes"] = [synthetic_probe(208, "verified", None, "direct")]
        measured = {**sweep_result("bearer", changed), "recorded_utc": "2026-11-19T00:00:00+00:00",
                    "evidence": {"logs": {}, "nginx_conf": "nginx.conf"},
                    "negotiated": {"direct": {"HTTP/1.1": 30}}}
        row = compare_sweeps("bearer-default", baseline, {"https": measured, "h2": measured})[0]
        self.assertEqual(row["measured"], {"https": BEARER_SUMMARY, "h2": BEARER_SUMMARY})
        self.assertEqual(row["moved"], {"https": False, "h2": False})
        self.assertEqual(row["difference_bytes"], {"https": 0, "h2": 0})
        self.assertIs(row["moved_by_http2"], False)

    def test_first_rejection_alone_does_not_count_as_moved(self):
        baseline = sweep_result("cookie", entry("SLH-DSA-SHA2-128f", None, None,
                                                (22922, "proxy")))
        measured = sweep_result("cookie", entry("SLH-DSA-SHA2-128f", "browser", None,
                                                (22922, "browser")))
        row = compare_sweeps("cookie-default", baseline, {"h2": measured})[0]
        self.assertEqual(row["measured"]["h2"], summary(None, (22922, "browser")))
        self.assertEqual(row["baseline"], summary(None, (22922, "proxy")))
        self.assertEqual(row["moved"], {"h2": False})
        self.assertEqual(row["difference_bytes"], {"h2": None})

    def test_difference_bytes_needs_two_ints(self):
        baseline = sweep_result("bearer", entry("SLH-DSA-SHA2-128s", "browser", None,
                                                (10613, "proxy")),
                                entry("ES256", "browser", **BEARER_LIMIT))
        https = sweep_result("bearer", entry("SLH-DSA-SHA2-128s", "browser", 261519,
                                             (261520, "app_server"),
                                             [(261520, "rejected", "app_server")]),
                             entry("ES256", "browser", None, (208, "proxy")))
        rows = compare_sweeps("bearer-default", baseline, {"https": https})
        slh = self.row(rows, "SLH-DSA-SHA2-128s", "browser")
        self.assertEqual((slh["moved"], slh["difference_bytes"]), ({"https": True},
                                                                   {"https": None}))
        es256 = self.row(rows, "ES256", "browser")
        self.assertEqual((es256["moved"], es256["difference_bytes"]), ({"https": True},
                                                                       {"https": None}))

    def test_without_a_baseline(self):
        https = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT))
        h2 = sweep_result("bearer", entry("ES256", "browser", 12000, (12002, "proxy"),
                                          [(12002, "rejected", "proxy")]))
        row = compare_sweeps("bearer-default", None, {"https": https, "h2": h2})[0]
        self.assertIsNone(row["baseline"])
        self.assertEqual(row["moved"], {"https": None, "h2": None})
        self.assertEqual(row["difference_bytes"], {"https": None, "h2": None})
        self.assertIs(row["moved_by_http2"], True)

    def test_baseline_without_the_entry(self):
        baseline = sweep_result("bearer", entry("ES256", "direct", **BEARER_LIMIT))
        https = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT))
        row = compare_sweeps("bearer-default", baseline, {"https": https})[0]
        self.assertEqual((row["algorithm"], row["client"]), ("ES256", "browser"))
        self.assertIsNone(row["baseline"])
        self.assertEqual(row["moved"], {"https": None})
        self.assertEqual(row["difference_bytes"], {"https": None})

    def test_moved_by_http2(self):
        same = entry("EdDSA", "browser", **BEARER_LIMIT)
        larger = entry("EdDSA", "browser", 9000, (9002, "proxy"), [(9002, "rejected", "proxy")])
        other_layer = entry("EdDSA", "browser", 8168, (8170, "browser"),
                            [(8170, "rejected", "browser")])
        baseline = sweep_result("bearer", same)
        cases = (
            ("identical", {"https": same, "h2": same}, False),
            ("largest differs", {"https": same, "h2": larger}, True),
            ("boundaries differ", {"https": same, "h2": other_layer}, True),
            ("h2 only", {"h2": larger}, None),
            ("https only", {"https": same}, None),
            ("http and https", {"http": same, "https": larger}, None),
        )
        for name, measured, expected in cases:
            with self.subTest(name):
                row = compare_sweeps("bearer-default", baseline,
                                     {protocol: sweep_result("bearer", item)
                                      for protocol, item in measured.items()})[0]
                self.assertIs(row["moved_by_http2"], expected)
        h2_missing = compare_sweeps("bearer-default", baseline,
                                    {"https": sweep_result("bearer", same),
                                     "h2": sweep_result("bearer",
                                                        entry("EdDSA", "direct",
                                                              **BEARER_LIMIT))})
        self.assertIsNone(self.row(h2_missing, "EdDSA", "browser")["moved_by_http2"])
        self.assertIsNone(self.row(h2_missing, "EdDSA", "direct")["moved_by_http2"])

    def test_protocol_keys_follow_protocols_order(self):
        result = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT))
        rows = compare_sweeps("bearer-default", result,
                              {"h2": result, "http": result, "https": result})
        for key in ("measured", "moved", "difference_bytes"):
            with self.subTest(key=key):
                self.assertEqual(list(rows[0][key]), list(PROTOCOL_ORDER))
        rows = compare_sweeps("bearer-default", result, {"h2": result, "https": result})
        self.assertEqual(list(rows[0]["moved"]), ["https", "h2"])

    def test_invalid_arguments_raise_value_error(self):
        bearer = sweep_result("bearer", entry("ES256", "browser", **BEARER_LIMIT))
        cookie = sweep_result("cookie", entry("ES256", "browser", **BEARER_LIMIT))
        cases = {
            "unknown sweep": ("cookie-32k", None, {"https": cookie}),
            "sweep name case": ("Cookie-Default", None, {"https": cookie}),
            "empty sweep": ("", None, {"https": cookie}),
            "oidc sweep": ("mldsa-oidc-default", None, {"https": cookie}),
            "unknown protocol": ("bearer-default", None, {"h3": bearer}),
            "protocol case": ("bearer-default", None, {"HTTPS": bearer}),
            "http2 name": ("bearer-default", None, {"http2": bearer}),
            "baseline transport": ("bearer-default", cookie, {"https": bearer}),
            "measured transport": ("cookie-default", cookie, {"https": cookie, "h2": bearer}),
            "only measured transport": ("bearer-512k", None, {"h2": cookie}),
        }
        for name, arguments in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                compare_sweeps(*arguments)

    def test_does_not_change_its_arguments(self):
        baseline = load_baseline("cookie-default")
        measured = {"https": load_baseline("cookie-default"), "h2": load_baseline("cookie-16k")}
        before = copy.deepcopy((baseline, measured))
        compare_sweeps("cookie-default", baseline, measured)
        self.assertEqual((baseline, measured), before)

    def test_sprint_2_runs_compared_with_themselves(self):
        for sweep in SWEEP_NAMES:
            with self.subTest(sweep=sweep):
                baseline = load_baseline(sweep)
                rows = compare_sweeps(sweep, baseline, {"https": baseline, "h2": baseline})
                clients = ("browser",) if TRANSPORT_OF[sweep] == "cookie" else ("browser",
                                                                               "direct")
                self.assertEqual([(row["algorithm"], row["client"]) for row in rows],
                                 [(name, client) for name in NAMES for client in clients])
                for row in rows:
                    self.assertEqual(row["sweep"], sweep)
                    self.assertEqual(row["moved"], {"https": False, "h2": False})
                    self.assertIs(row["moved_by_http2"], False)
                    largest = row["baseline"]["largest_verified_token_bytes"]
                    expected = None if largest is None else 0
                    self.assertEqual(row["difference_bytes"], {"https": expected, "h2": expected})

    def test_sprint_2_cookie_default_against_cookie_16k(self):
        # Sprint 2's pinned run stands in for a run whose boundaries moved.
        default, pinned = load_baseline("cookie-default"), load_baseline("cookie-16k")
        rows = compare_sweeps("cookie-default", default, {"https": default, "h2": pinned})
        by_name = {row["algorithm"]: row for row in rows}
        self.assertEqual(list(by_name), NAMES)
        for name, difference in (("RS256", 177), ("ES256", 177), ("EdDSA", 177),
                                 ("ML-DSA-44", 178)):
            with self.subTest(algorithm=name):
                row = by_name[name]
                self.assertEqual(row["baseline"]["largest_verified_token_bytes"], 3915)
                self.assertEqual(row["measured"]["h2"]["largest_verified_token_bytes"],
                                 3915 + difference)
                self.assertEqual(row["moved"], {"https": False, "h2": True})
                self.assertEqual(row["difference_bytes"], {"https": 0, "h2": difference})
                self.assertIs(row["moved_by_http2"], True)
        small = by_name["SLH-DSA-SHA2-128s"]  # No verified token; a 16,204-byte boundary added.
        self.assertEqual(small["moved"], {"https": False, "h2": True})
        self.assertEqual(small["difference_bytes"], {"https": None, "h2": None})
        self.assertEqual(small["measured"]["h2"]["boundaries"],
                         [{"token_bytes": 16204, "outcome": "rejected", "rejected_by": "proxy"}])
        fast = by_name["SLH-DSA-SHA2-128f"]  # Rejected by nginx at every size in both runs.
        self.assertEqual(fast["moved"], {"https": False, "h2": False})
        self.assertIs(fast["moved_by_http2"], False)
        self.assertEqual(fast["measured"]["h2"],
                         summary(None, (22922, "proxy")))


# ---- R14: summary_lines --------------------------------------------------------------------

def synthetic_protocols_result() -> dict:
    """A protocols.json object with two runs and three comparison rows."""
    certificate = {"subject": "O=Transport experiment key\\, not a production credential,"
                              "CN=localhost",
                   "issuer": "O=Transport experiment key\\, not a production credential,"
                             "CN=localhost",
                   "subject_alt_names": ["DNS:localhost", "IP:127.0.0.1"],
                   "not_before": "2026-11-19T00:00:00+00:00",
                   "not_after": "2026-11-20T00:00:00+00:00", "public_key": "EC P-256",
                   "sha256_fingerprint": ":".join(["AB"] * 32)}
    rows = [
        {"sweep": "bearer-default", "algorithm": "ES256", "client": "browser",
         "baseline": BEARER_SUMMARY,
         "measured": {"https": BEARER_SUMMARY,
                      "h2": summary(12345, (12347, "proxy"), [(12347, "rejected", "proxy")])},
         "moved": {"https": False, "h2": True}, "difference_bytes": {"https": 0, "h2": 4177},
         "moved_by_http2": True},
        {"sweep": "bearer-default", "algorithm": "ES256", "client": "direct", "baseline": None,
         "measured": {"https": BEARER_SUMMARY, "h2": BEARER_SUMMARY},
         "moved": {"https": None, "h2": None}, "difference_bytes": {"https": None, "h2": None},
         "moved_by_http2": False},
        {"sweep": "cookie-16k", "algorithm": "SLH-DSA-SHA2-128s", "client": "browser",
         "baseline": summary(None, (10613, "browser"), [(16204, "rejected", "proxy")]),
         "measured": {"https": summary(None, (10613, "browser"), [(16204, "rejected", "proxy")]),
                      "h2": summary(261519, (261520, "app_server"),
                                    [(261520, "rejected", "app_server")])},
         "moved": {"https": False, "h2": True}, "difference_bytes": {"https": None, "h2": None},
         "moved_by_http2": True},
    ]
    runs = [
        {"protocol": "https", "sweep": "bearer-default", "directory": "https-bearer-default",
         "check": {"page_status": 200, "negotiated_protocol": "HTTP/1.1"},
         "negotiated": {"browser": {"HTTP/1.1": 34}, "direct": {"HTTP/1.1": 17}},
         "certificate": certificate},
        {"protocol": "h2", "sweep": "bearer-default", "directory": "h2-bearer-default",
         "check": {"page_status": 200, "negotiated_protocol": "HTTP/2.0"},
         "negotiated": {"browser": {"HTTP/2.0": 1234, "unlogged": 3},
                        "direct": {"HTTP/1.1": 19}},
         "certificate": certificate},
    ]
    definition = {"transport": "bearer", "clients": ["browser", "direct"], "claims": "minimal",
                  "attrs": "default", "proxy_buffers": None, "header_buffers": None,
                  "step": 512, "max_bytes": 24576}
    logs = ("app.log", "browser.log", "proxy-access.log", "proxy-error.log")
    return {
        "schema_version": 1,
        "started_utc": "2026-11-19T00:00:00+00:00",
        "finished_utc": "2026-11-19T00:10:00+00:00",
        "recorded_utc": "2026-11-19T00:10:01+00:00",
        "settings": {"protocols": ["https", "h2"], "sweeps": ["bearer-default", "cookie-16k"],
                     "algorithms": ["ES256", "SLH-DSA-SHA2-128s"],
                     "baseline": "results/transport/20261113T074114Z-wsl2", "step": None,
                     "max_bytes": None, "timeout": 60.0},
        "sweep_definitions": {"bearer-default": definition,
                              "cookie-16k": {**definition, "transport": "cookie",
                                             "clients": ["browser"], "proxy_buffers": "16k"}},
        "environment": {"platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                        "git_commit": "0" * 40, "page_size_bytes": 16384},
        "layers": [],
        "browser": {"version": "156.0.8078.4", "user_agent": "Mozilla/5.0 HeadlessChrome"},
        "experiment_keys": True,
        "runs": runs,
        "comparison": rows,
        "evidence": {run["directory"]: {"sweep": f"{run['directory']}/sweep.json",
                                        "logs": {name: f"{run['directory']}/logs/{name}.gz"
                                                 for name in logs},
                                        "nginx_conf": f"{run['directory']}/nginx.conf"}
                     for run in runs},
    }


class SummaryLinesTests(unittest.TestCase):
    def setUp(self):
        self.result = synthetic_protocols_result()
        self.lines = api(protocols(), "summary_lines")(copy.deepcopy(self.result))

    def test_one_line_per_run_and_per_row(self):
        self.assertEqual(len(self.lines), len(self.result["runs"]) + len(self.result["comparison"]))
        for line in self.lines:
            self.assertIsInstance(line, str)
            self.assertNotIn("\n", line)

    def test_run_lines(self):
        for run in self.result["runs"]:
            with self.subTest(run=run["directory"]):
                found = [line for line in self.lines
                         if run["sweep"] in line and run["protocol"] in line.lower()
                         and not any(name in line for name in NAMES)]
                self.assertEqual(len(found), 1, self.lines)
                for counts in run["negotiated"].values():
                    for count in counts.values():
                        self.assertTrue(contains_number(found[0], count), (found[0], count))

    def test_row_lines(self):
        expected_words = {True: "moved", False: "unchanged", None: "no baseline"}
        for row in self.result["comparison"]:
            with self.subTest(row=(row["sweep"], row["algorithm"], row["client"])):
                found = [line for line in self.lines
                         if row["sweep"] in line and row["algorithm"] in line
                         and re.search(rf"\b{row['client']}\b", line)]
                self.assertEqual(len(found), 1, self.lines)
                line = found[0]
                summaries = [row["baseline"], *row["measured"].values()]
                for item in summaries:
                    if item is None:
                        continue
                    largest = item["largest_verified_token_bytes"]
                    self.assertIn("none" if largest is None else f"{largest:,}", line)
                for moved in row["moved"].values():
                    word = expected_words[moved]
                    self.assertRegex(line, rf"\b{word}\b")


if __name__ == "__main__":
    unittest.main()
