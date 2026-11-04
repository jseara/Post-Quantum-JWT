"""Check the transport manifest, docs, and setup script statically; no timing thresholds."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit


REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "transport" / "stack.json"
DOC = REPO / "TRANSPORT.md"
README = REPO / "README.md"
SETUP = REPO / "transport" / "setup.sh"
BASH = shutil.which("bash") or "/bin/bash"

REQUIRED_ROLES = ("automation", "browser", "proxy", "app_server")
LABELS = {"automation": "Browser automation", "browser": "Browser engine",
          "proxy": "Reverse proxy", "app_server": "Application server",
          "app_framework": "Application framework"}
LIMIT_KEYS = ("cookie", "single_header", "total_headers")
LIMIT_FIELDS = {"bytes", "setting", "note", "sources"}
HEADINGS = ("Stack", "Versions and documented limits", "Setup", "Run the check",
            "Support for Sprint 2 tasks", "Limitations")
TABLE_HEADER = ["Layer", "Component", "Version", "Cookie size", "Single header size",
                "Total request header size", "Sources"]

VERSION = re.compile(r"\d+(\.\d+)+[0-9A-Za-z.+-]*")
COMMIT = re.compile(r"[0-9a-f]{40}")
BRANCH_NAMES = ("main", "master", "HEAD", "trunk", "develop", "default", "tip", "latest",
                "mozilla-central")
SOURCE_HOSTS = {"github.com", "raw.githubusercontent.com", "gitlab.com", "codeberg.org",
                "bitbucket.org", "source.chromium.org", "hg.mozilla.org", "searchfox.org",
                "hg.nginx.org"}
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(https://[^)\s]+\)")
# conda reads `name=1.2.3` without a build string as the prefix match 1.2.3.*, so only `==`,
# `name=version=build`, `name version [build]`, and explicit package URLs are exact.
EXACT_PIN = re.compile(r"[A-Za-z0-9_.:\[\],-]+\s*===?\s*(?P<pinned>[^\s=;\[]+).*"
                       r"|[A-Za-z0-9_.:-]+=(?P<with_build>[^\s=]+)=\S+"
                       r"|[A-Za-z0-9_.:-]+\s+(?P<spaced>[^\s=]+)(?:\s+\S+)?"
                       r"|(?:[A-Za-z0-9_.\[\],-]+\s*@\s*)?https://\S+|@EXPLICIT")


def is_exact_version(value) -> bool:
    """Apply the R3 rule: digits with dot-separated numeric parts and no range syntax."""
    return (isinstance(value, str) and VERSION.fullmatch(value) is not None
            and not any(part in ("x", "X") for part in value.split("."))
            and not any(character in value for character in "*<>=~^,")
            and not any(character.isspace() for character in value)
            and "latest" not in value.lower())


def is_exact_pin(requirement: str) -> bool:
    """Accept a pip or conda requirement only when it selects exactly one version."""
    match = EXACT_PIN.fullmatch(requirement)
    if match is None:
        return False
    version = match["pinned"] or match["with_build"] or match["spaced"] or ""
    return (not any(character in version for character in "*<>!~^,|")
            and not any(part in ("x", "X") for part in version.split(".")))


def pin_requirements() -> list[tuple[str, str]]:
    """Return (file name, requirement) for each pin in transport/*.txt and conda YAML files."""
    found = []
    for path in sorted((REPO / "transport").iterdir()):
        if path.suffix not in (".txt", ".yml", ".yaml") or not path.is_file():
            continue
        key = None
        for line in path.read_text(encoding="utf-8").splitlines():
            content = re.split(r"\s#", line)[0].rstrip()
            if not content.strip() or content.lstrip().startswith("#"):
                continue
            if path.suffix == ".txt":
                if not content.lstrip().startswith("-"):
                    found.append((path.name, content.strip()))
            elif not line[0].isspace():
                key = content.split(":")[0].strip()
            else:
                item = re.match(r"\s*-\s+(.+)", content)
                if key == "dependencies" and item and not item[1].endswith(":"):
                    found.append((path.name, item[1].strip().strip("'\"")))
    return found


def source_problem(url: str, versions: list[str]) -> str | None:
    """Return why a source URL breaks the R4/R5 pinning rules, or None when it is acceptable."""
    if not isinstance(url, str):
        return "not a string"
    parts = urlsplit(url)
    if parts.scheme != "https" or not url.startswith("https://") or not parts.hostname:
        return "not an https URL"
    if "/refs/heads/" in url:
        return "points at a branch ref"
    for segment in parts.path.split("/"):
        if any(segment == name or segment.startswith(f"{name}:") for name in BRANCH_NAMES):
            return f"path segment {segment!r} names a moving branch"
    host = parts.hostname.lower()
    if host in SOURCE_HOSTS or host.endswith("googlesource.com"):
        if not any(version and version in url for version in versions) and not COMMIT.search(url):
            return "source code link contains neither a declared version nor a commit id"
    return None


def headings(lines: list[str]) -> list[tuple[int, str, int]]:
    """Return (level, text, line index) for Markdown headings outside fenced code blocks."""
    found, fenced = [], False
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced:
            match = re.match(r"(#{1,6}) (.*?)\s*$", line)
            if match:
                found.append((len(match[1]), match[2], index))
    return found


def section(text: str, title: str, level: int = 2) -> str | None:
    """Return the body below a heading up to the next heading of the same or higher level."""
    lines = text.splitlines()
    marks = headings(lines)
    for position, (depth, name, index) in enumerate(marks):
        if depth == level and name == title:
            end = next((line for depth_after, _, line in marks[position + 1:]
                        if depth_after <= level), len(lines))
            return "\n".join(lines[index + 1:end])
    return None


def code_blocks(text: str) -> list[str]:
    blocks, current = [], None
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            if current is None:
                current = []
            else:
                blocks.append("\n".join(current))
                current = None
        elif current is not None:
            current.append(line)
    return blocks


def cells(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", body)]


def limits_table(text: str) -> list[list[str]] | None:
    """Return the data rows of the table whose header matches TABLE_HEADER, or None."""
    lines = [line.strip() for line in text.splitlines()]
    for index, line in enumerate(lines):
        if line.startswith("|") and cells(line) == TABLE_HEADER:
            separator = lines[index + 1] if index + 1 < len(lines) else ""
            if not all(re.fullmatch(r":?-+:?", cell) for cell in cells(separator)):
                return None
            rows = []
            for row in lines[index + 2:]:
                if not row.startswith("|"):
                    break
                rows.append(cells(row))
            return rows
    return None


def contains_number(text: str, number: int) -> bool:
    return re.search(rf"(?<![\d,])(?:{number}|{number:,})(?!,?\d)", text) is not None


def pin_files_text() -> str:
    """Concatenate setup.sh and every committed pin or config file under transport/."""
    texts = []
    for path in sorted((REPO / "transport").rglob("*")):
        if (path.is_file() and path != MANIFEST and "__pycache__" not in path.parts
                and path.stat().st_size <= 1024 * 1024):
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(texts)


def tracked_files() -> list[str] | None:
    try:
        result = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True,
                                text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return [path for path in result.stdout.split("\0") if path]


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.layers = cls.manifest["layers"]
        cls.doc = DOC.read_text(encoding="utf-8") if DOC.exists() else ""

    def test_schema_and_request_path_order(self):
        self.assertIsInstance(self.manifest, dict)
        self.assertIs(type(self.manifest["schema_version"]), int)
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertIsInstance(self.layers, list)
        roles = [layer.get("role") for layer in self.layers]
        self.assertIn(roles, [list(REQUIRED_ROLES), [*REQUIRED_ROLES, "app_framework"]])
        self.assertEqual(len(roles), len(set(roles)))

    def test_layer_fields(self):
        for layer in self.layers:
            with self.subTest(role=layer.get("role")):
                self.assertIsInstance(layer, dict)
                self.assertIsInstance(layer["component"], str)
                self.assertTrue(layer["component"].strip())
                self.assertIsInstance(layer["version"], str)
                self.assertIsInstance(layer["install"], str)
                self.assertTrue(layer["install"].strip())
                dependencies = layer.get("dependencies", {})
                self.assertIsInstance(dependencies, dict)
                for name, value in dependencies.items():
                    self.assertTrue(isinstance(name, str) and name.strip())
                    self.assertIsInstance(value, str)

    def test_versions_are_exact(self):
        for layer in self.layers:
            versions = [("version", layer["version"]),
                        *layer.get("dependencies", {}).items()]
            for name, value in versions:
                with self.subTest(role=layer["role"], field=name, value=value):
                    self.assertTrue(is_exact_version(value))

    def test_version_rule_rejects_ranges_and_wildcards(self):
        for value in ("1.29.1", "141.0.7390.37", "3.15.2", "0.35.0", "26.0", "2.0.0rc1",
                      "1.2.3+build.5", "1.2.3-1"):
            with self.subTest(value=value):
                self.assertTrue(is_exact_version(value))
        for value in ("", "1", "v1.2.3", "1.x", "1.2.x", "1.2.X", "1.2.*", "^1.2.3", "~1.2",
                      ">=1.2", "<2.0", "==1.2.3", "1.2,1.3", "1.2 3", "1.2.3 ", "latest",
                      "1.2.3-latest", 1.2, None, True):
            with self.subTest(value=value):
                self.assertFalse(is_exact_version(value))

    def test_limits_shape(self):
        for layer in self.layers:
            limits = layer["limits"]
            self.assertIsInstance(limits, dict)
            self.assertEqual(set(limits), set(LIMIT_KEYS))
            for key in LIMIT_KEYS:
                limit = limits[key]
                with self.subTest(role=layer["role"], limit=key):
                    self.assertIsInstance(limit, dict)
                    self.assertEqual(set(limit), LIMIT_FIELDS)
                    size = limit["bytes"]
                    self.assertTrue(size is None or (type(size) is int and size > 0), size)
                    setting = limit["setting"]
                    self.assertTrue(setting is None or (isinstance(setting, str)
                                                        and setting.strip()), setting)
                    self.assertIsInstance(limit["note"], str)
                    self.assertTrue(limit["note"].strip())
                    self.assertIsInstance(limit["sources"], list)
                    self.assertTrue(limit["sources"])
                    for url in limit["sources"]:
                        self.assertIsInstance(url, str)
                        self.assertTrue(url.startswith("https://"), url)
                        self.assertTrue(urlsplit(url).hostname, url)

    def test_sources_are_pinned(self):
        for layer in self.layers:
            versions = [layer["version"], *layer.get("dependencies", {}).values()]
            for key in LIMIT_KEYS:
                for url in layer["limits"][key]["sources"]:
                    with self.subTest(role=layer["role"], limit=key, url=url):
                        self.assertIsNone(source_problem(url, versions))

    def test_source_rule_rejects_moving_links(self):
        commit = "0123456789abcdef0123456789abcdef01234567"
        accepted = [
            ("https://nginx.org/en/docs/http/ngx_http_core_module.html", ["1.29.1"]),
            ("https://www.rfc-editor.org/rfc/rfc6265#section-6.1", ["1.0.0"]),
            ("https://github.com/example/server/blob/0.35.0/server/config.py", ["0.35.0"]),
            ("https://github.com/example/server/blob/release-1.29.1/src/a.c", ["1.29.1"]),
            (f"https://github.com/example/server/blob/{commit}/src/a.c", ["9.9.9"]),
            ("https://chromium.googlesource.com/chromium/src/+/refs/tags/141.0.7390.37/a.cc",
             ["141.0.7390.37"]),
            ("https://github.com/example/parser/blob/v0.16.0/parser/_abnf.py",
             ["1.0.0", "0.16.0"]),
        ]
        rejected = [
            ("http://nginx.org/en/docs/http/ngx_http_core_module.html", ["1.29.1"]),
            ("https://github.com/example/server/blob/master/src/a.c", ["1.29.1"]),
            ("https://github.com/example/server/blob/main/src/a.c", ["1.29.1"]),
            ("https://github.com/example/server/blob/HEAD/src/a.c", ["1.29.1"]),
            ("https://raw.githubusercontent.com/example/server/refs/heads/release/a.c",
             ["1.29.1"]),
            ("https://github.com/example/server/blob/1.28.0/src/a.c", ["1.29.1"]),
            ("https://gitlab.com/example/server/-/blob/develop/a.c", ["1.29.1"]),
            ("https://source.chromium.org/chromium/chromium/src/+/main:net/http/a.cc",
             ["141.0.7390.37"]),
            ("https://hg.nginx.org/nginx/file/tip/src/http/ngx_http_request.c", ["1.29.1"]),
            ("https://searchfox.org/mozilla-central/source/netwerk/a.cpp", ["142.0"]),
            ("https://docs.example.org/en/latest/settings.html", ["23.0.0"]),
            ("https://codeberg.org/example/server/src/branch/trunk/a.c", ["1.29.1"]),
        ]
        for url, versions in accepted:
            with self.subTest(url=url):
                self.assertIsNone(source_problem(url, versions))
        for url, versions in rejected:
            with self.subTest(url=url):
                self.assertIsNotNone(source_problem(url, versions))

    def test_sources_cited_in_transport_doc(self):
        self.assertTrue(DOC.is_file())
        for layer in self.layers:
            for key in LIMIT_KEYS:
                for url in layer["limits"][key]["sources"]:
                    with self.subTest(role=layer["role"], limit=key, url=url):
                        self.assertIn(url, self.doc)


class TransportDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")
        cls.layers = json.loads(MANIFEST.read_text(encoding="utf-8"))["layers"]

    def section(self, title: str) -> str:
        body = section(self.text, title)
        self.assertIsNotNone(body, f"missing heading: ## {title}")
        return body

    def test_required_headings_in_order(self):
        found = [name for depth, name, _ in headings(self.text.splitlines())
                 if depth == 2 and name in HEADINGS]
        self.assertEqual(found, list(HEADINGS))

    def test_stack_section_names_every_component(self):
        body = self.section("Stack")
        for layer in self.layers:
            with self.subTest(role=layer["role"]):
                self.assertIn(layer["component"], body)
        lowered = body.lower()
        self.assertTrue(any(word in lowered for word in ("alternative", "considered", "instead")))

    def test_limits_table_matches_manifest(self):
        body = self.section("Versions and documented limits")
        rows = limits_table(body)
        self.assertIsNotNone(rows, "no limits table with the required header")
        self.assertEqual(len(rows), len(self.layers))
        for row, layer in zip(rows, self.layers):
            with self.subTest(role=layer["role"]):
                self.assertEqual(len(row), len(TABLE_HEADER), row)
                self.assertEqual(row[0], LABELS[layer["role"]])
                self.assertIn(layer["component"], row[1])
                self.assertIn(layer["version"], row[2])
                for key, cell in zip(LIMIT_KEYS, row[3:6]):
                    self.assertTrue(cell, f"empty {key} cell")
                    size = layer["limits"][key]["bytes"]
                    if size is not None:
                        self.assertTrue(contains_number(cell, size), f"{size} not in {cell!r}")
                self.assertRegex(row[6], MARKDOWN_LINK)

    def test_number_matching_accepts_separators_only(self):
        self.assertTrue(contains_number("8192 bytes", 8192))
        self.assertTrue(contains_number("8,192 bytes (`large_client_header_buffers`)", 8192))
        self.assertTrue(contains_number("4,096, set by a flag", 4096))
        self.assertFalse(contains_number("81920 bytes", 8192))
        self.assertFalse(contains_number("18,192 bytes", 8192))
        self.assertFalse(contains_number("not enforced", 8192))

    def test_limits_section_explains_defaults_and_settings(self):
        lowered = self.section("Versions and documented limits").lower()
        self.assertIn("default", lowered)
        self.assertIn("measur", lowered)
        for layer in self.layers:
            for key in LIMIT_KEYS:
                setting = layer["limits"][key]["setting"]
                if setting is None:
                    continue
                with self.subTest(role=layer["role"], limit=key, setting=setting):
                    name = setting.split()[0].strip("`'\",;()") if setting.split() else ""
                    self.assertTrue(setting in self.text or (name and name in self.text))

    def test_setup_section_per_platform(self):
        body = self.section("Setup")
        for title in ("macOS (Apple Silicon)", "WSL2 (x86_64 Linux)"):
            with self.subTest(platform=title):
                subsection = section(body, title, level=3)
                self.assertIsNotNone(subsection, f"missing heading: ### {title}")
                commands = "\n".join(code_blocks(subsection))
                setup_at = commands.find("transport/setup.sh")
                check = re.search(r"transport_stack\.py[\"']?\s+check\b", commands)
                self.assertGreaterEqual(setup_at, 0)
                self.assertIsNotNone(check)
                self.assertGreater(check.start(), setup_at)

    def test_run_the_check_section(self):
        body = self.section("Run the check")
        commands = "\n".join(code_blocks(body))
        for subcommand in ("check", "serve", "versions"):
            with self.subTest(subcommand=subcommand):
                self.assertRegex(commands, rf"transport_stack\.py[\"']?\s+{subcommand}\b")
        self.assertRegex(commands, r"-m unittest\b")
        self.assertRegex(body, r'"ok"\s*:\s*true')

    def test_sprint_2_support_section(self):
        body = self.section("Support for Sprint 2 tasks")
        for task in ("S2-02", "S2-03", "S2-04", "S2-05"):
            with self.subTest(task=task):
                self.assertIn(task, body)
        lowered = body.lower()
        for term in ("set-cookie", "bearer", "fetch", "log"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_limitations_section(self):
        body = self.section("Limitations")
        for term in ("macOS", "WSL2", "HTTP/1.1", "127.0.0.1", "Secure", "HTTP/2"):
            with self.subTest(term=term):
                self.assertIn(term, body)
        self.assertRegex(body, r"3\.15")
        self.assertTrue(any(term in body for term in ("arm64", "aarch64", "Apple Silicon",
                                                      "x86_64")))

    def test_readme_links_transport_doc(self):
        self.assertIn("](TRANSPORT.md", README.read_text(encoding="utf-8"))


class SetupScriptTests(unittest.TestCase):
    def test_bash_syntax(self):
        self.assertTrue(SETUP.is_file())
        result = subprocess.run([BASH, "-n", str(SETUP)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_argument_count_prints_usage_and_creates_nothing(self):
        for names in ([], ["first prefix", "second prefix"], ["one", "two", "three"]):
            with self.subTest(arguments=len(names)), \
                    tempfile.TemporaryDirectory(prefix="setup usage ") as directory:
                root = Path(directory)
                fake_bin = root / "fake bin"
                fake_bin.mkdir()
                marker = root / "conda was called"
                conda = fake_bin / "conda"
                conda.write_text(f'#!/bin/sh\necho "$@" >> "{marker}"\nexit 1\n', encoding="utf-8")
                conda.chmod(0o755)
                work = root / "work"
                work.mkdir()
                environment = {**os.environ, "CONDA_EXE": str(conda),
                               "PATH": os.pathsep.join([str(fake_bin), "/usr/bin", "/bin"])}
                result = subprocess.run([BASH, str(SETUP), *(str(work / name) for name in names)],
                                        cwd=work, env=environment, capture_output=True,
                                        text=True, timeout=60)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage", result.stderr.lower())
                self.assertFalse(marker.exists())
                self.assertEqual(list(work.iterdir()), [])

    def test_conda_forge_only_and_final_versions_check(self):
        code = "\n".join(line for line in SETUP.read_text(encoding="utf-8").splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertIn("CONDA_EXE", code)
        self.assertIn("--override-channels", code)
        self.assertIn("conda-forge", code)
        self.assertRegex(code, r"transport_stack\.py[\"']?\s+versions\b")

    def test_exact_pins_in_committed_files(self):
        text = pin_files_text()
        self.assertRegex(text, r"\bpython\s*(?:==|=|\s)\s*3\.15\.\d+")
        layers = json.loads(MANIFEST.read_text(encoding="utf-8"))["layers"]
        for layer in layers:
            if layer["role"] != "browser":
                with self.subTest(role=layer["role"]):
                    self.assertIn(layer["version"], text)
        requirements = [line.strip() for line in
                        (REPO / "requirements.txt").read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]
        self.assertTrue("requirements.txt" in text
                        or all(requirement in text for requirement in requirements))
        for name, requirement in pin_requirements():
            with self.subTest(file=name, requirement=requirement):
                self.assertTrue(is_exact_pin(requirement))

    def test_pin_rule_accepts_exact_forms_only(self):
        for requirement in ("waitress==3.0.2", "nginx==1.31.8", "python==3.15.2=*_cp315",
                            "python=3.15.2=*_cp315", "python==3.15.2[build=*_cp315]",
                            "nginx 1.31.8", "nginx 1.31.8 h1234_0", "uvicorn[standard]==0.35.0",
                            "conda-forge::nginx==1.31.8", 'tomli==2.2.1; python_version < "3.11"',
                            "https://conda.anaconda.org/conda-forge/noarch/a-1.0-pyh0_0.conda#ab",
                            "@EXPLICIT"):
            with self.subTest(requirement=requirement):
                self.assertTrue(is_exact_pin(requirement))
        for requirement in ("nginx=1.31.8", "pip=26.2.2", "python=3.15", "nginx", "nginx>=1.31",
                            "nginx>=1.31,<1.32", "waitress~=3.0", "waitress==3.*", "nginx 1.31.*",
                            "nginx 1.31.8|1.31.9", "nginx==1.x"):
            with self.subTest(requirement=requirement):
                self.assertFalse(is_exact_pin(requirement))


class CommittedFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tracked = tracked_files()

    def setUp(self):
        if self.tracked is None:
            self.skipTest("not a git checkout")

    def test_no_large_files_or_runtime_directories_under_transport(self):
        transport = [path for path in self.tracked if path.startswith("transport/")]
        self.assertIn("transport/stack.json", transport)
        self.assertIn("transport/setup.sh", transport)
        for path in transport:
            with self.subTest(path=path):
                parts = Path(path).parts
                self.assertNotIn("logs", parts[:-1])
                self.assertNotIn("run", parts[:-1])
                file = REPO / path
                if file.exists():
                    self.assertLessEqual(file.stat().st_size, 1024 * 1024)

    def test_no_environment_cache_or_log_committed(self):
        for path in self.tracked:
            with self.subTest(path=path):
                parts = Path(path).parts
                self.assertNotIn("__pycache__", parts)
                self.assertNotIn("conda-meta", parts)
                self.assertFalse(path.endswith((".log", ".pyc", ".pid")))


if __name__ == "__main__":
    unittest.main()
