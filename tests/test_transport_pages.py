"""Check the test page's read-only mode: scripts/transport_pages.py's embedded block, its command
line, the replays it builds from the committed sweeps, the GitHub Pages workflow, and the page
itself in headless Chromium (read-only off this machine, unchanged on loopback); no timing
thresholds."""

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import threading
import unittest

from scripts import transport_pages, transport_report
from scripts.transport_stack import BROWSER_CHANNEL

try:
    import playwright.sync_api  # noqa: F401
    HAVE_PLAYWRIGHT = True
except ImportError:
    HAVE_PLAYWRIGHT = False


REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "transport" / "static" / "index.html"
WORKFLOW = REPO / ".github" / "workflows" / "pages.yml"
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{40,}")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
NAMES = ["RS256", "ES256", "EdDSA", "ML-DSA-44", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"]


def page_text() -> str:
    return PAGE.read_text(encoding="utf-8")


def embedded_block(text: str) -> str:
    _, block, _ = transport_pages.split_page(text, "index.html")
    return block


def embedded_data(text: str) -> dict:
    block = embedded_block(text)
    match = re.fullmatch(r'<script type="application/json" id="recorded">\n(.*)\n</script>\n',
                         block, flags=re.DOTALL)
    assert match, "the generated block is not one JSON script element"
    return json.loads(match[1])


def run_main(*arguments: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = transport_pages.main(list(arguments))
    return code, out.getvalue(), err.getvalue()


def sweep(name: str) -> dict:
    return json.loads((REPO / name).read_text(encoding="utf-8"))


class GeneratedBlockTests(unittest.TestCase):
    def test_committed_page_is_up_to_date(self):
        code, _, err = run_main("--check")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(embedded_block(page_text()), transport_pages.page_block())

    def test_printing_the_block_matches_the_page(self):
        code, out, _ = run_main()
        self.assertEqual(code, 0)
        self.assertEqual(out, embedded_block(page_text()))

    def test_block_is_inert_json(self):
        block = embedded_block(page_text())
        body = block.split("\n", 1)[1].rsplit("</script>", 1)[0]
        self.assertNotIn("<", body, "a '<' inside the JSON could end the script element")
        data = embedded_data(page_text())
        self.assertEqual(data["generated_by"], "scripts/transport_pages.py")
        self.assertEqual(data["runs"]["cookie"], transport_report.COOKIE_DEFAULT)
        self.assertEqual(data["runs"]["bearer"], transport_report.BEARER_DEFAULT)

    def test_algorithms_match_the_page_constants(self):
        text = page_text()
        constants = re.findall(r'\{name: "([^"]+)", label: "[^"]+", bytes: (\d+), pq: \w+\}',
                               text)
        data = embedded_data(text)
        self.assertEqual([name for name, _ in constants], NAMES)
        self.assertEqual([(row["name"], row["token_bytes"]) for row in data["algorithms"]],
                         [(name, int(size)) for name, size in constants])

    def test_replays_are_the_unpadded_chromium_probes(self):
        data = embedded_data(page_text())
        for carrier, path in (("cookie", transport_report.COOKIE_DEFAULT),
                              ("bearer", transport_report.BEARER_DEFAULT)):
            results = {result["algorithm"]: result for result in sweep(path)["results"]
                       if result.get("client", "browser") == "browser"}
            for row in data["algorithms"]:
                with self.subTest(carrier=carrier, algorithm=row["name"]):
                    probe = next(probe for probe in results[row["name"]]["probes"]
                                 if probe["pad"] == 0
                                 and probe.get("client", "browser") == "browser")
                    replay = row[carrier]
                    self.assertEqual(replay["run"], path)
                    self.assertEqual(replay["outcome"], probe["outcome"])
                    self.assertEqual(replay["token_bytes"], probe["token_bytes"])
                    self.assertEqual(replay["issue_status"], probe["issue_status"])
                    self.assertEqual(replay["verify_status"], probe["verify_status"])
                    self.assertEqual(replay["evidence"], probe["evidence"])

    def test_replays_show_the_known_verdicts(self):
        rows = {row["name"]: row for row in embedded_data(page_text())["algorithms"]}
        for name in ["RS256", "ES256", "EdDSA", "ML-DSA-44"]:
            with self.subTest(name=name):
                self.assertEqual(rows[name]["cookie"]["outcome"], "verified")
                self.assertEqual(rows[name]["bearer"]["outcome"], "verified")
        for name in ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"]:
            with self.subTest(name=name):
                cookie, bearer = rows[name]["cookie"], rows[name]["bearer"]
                self.assertEqual((cookie["outcome"], cookie["rejected_by"],
                                  cookie["issue_status"]), ("rejected", "nginx", 502))
                self.assertEqual((bearer["outcome"], bearer["rejected_by"],
                                  bearer["issue_status"], bearer["verify_status"]),
                                 ("rejected", "nginx", 200, 400))

    def test_limits_by_protocol_come_from_s3_04(self):
        protocols = sweep(transport_pages.PROTOCOLS)
        compared = {(entry["sweep"], entry["algorithm"], entry["client"]): entry
                    for entry in protocols["comparison"]}
        for row in embedded_data(page_text())["algorithms"]:
            for carrier, name in (("cookie", "cookie-default"), ("bearer", "bearer-default")):
                entry = compared[(name, row["name"], "browser")]
                with self.subTest(algorithm=row["name"], carrier=carrier):
                    limits = row["limits"][carrier]
                    self.assertEqual(limits["http1"]["largest_verified"],
                                     entry["baseline"]["largest_verified_token_bytes"])
                    for key in ("https", "h2"):
                        self.assertEqual(limits[key]["largest_verified"],
                                         entry["measured"][key]["largest_verified_token_bytes"])

    def test_sections_are_the_recommendations_tables_plus_protocols(self):
        sections = embedded_data(page_text())["sections"]
        report = transport_report.report_markdown(REPO)
        headings = re.findall(r"^### (.+)$", report, flags=re.MULTILINE)
        self.assertEqual([section["heading"] for section in sections[:-1]], headings)
        self.assertEqual(sections[-1]["heading"], "Size limits by protocol (S3-04)")
        self.assertEqual(len(sections[-1]["rows"]), 2 * len(NAMES))
        for section, chunk in zip(sections, report.split("### ")[1:]):
            with self.subTest(section=section["heading"]):
                table_lines = [line for line in chunk.splitlines() if line.startswith("| ")]
                self.assertEqual(len(section["rows"]), len(table_lines) - 2)
                for row in section["rows"]:
                    self.assertEqual(len(row), len(section["columns"]))

    def test_block_holds_no_token_or_key(self):
        block = embedded_block(page_text())
        leaks = [match for match in TOKEN_LIKE.findall(block) if not HEX_COMMIT.fullmatch(match)]
        self.assertEqual(leaks, [])
        # nginx's error log quotes the Authorization header; the sweeps keep only a redacted
        # prefix of each token segment, like eyJhbGciOiJT[...].
        for match in re.finditer(r"eyJ[A-Za-z0-9_-]*", block):
            with self.subTest(at=match.start()):
                self.assertLessEqual(len(match[0]), 12)
                self.assertEqual(block[match.end():match.end() + 5], "[...]")
        self.assertNotIn("PRIVATE KEY", block)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="pages-test-"))
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.page = self.directory / "index.html"
        self.page.write_bytes(PAGE.read_bytes())

    def stale(self) -> str:
        text = self.page.read_text(encoding="utf-8")
        head, _, tail = transport_pages.split_page(text, "copy")
        stale = head + '<script type="application/json" id="recorded">\n{}\n</script>\n' + tail
        self.page.write_text(stale, encoding="utf-8")
        return stale

    def test_check_reports_a_stale_block(self):
        self.stale()
        code, _, err = run_main("--check", "--page", str(self.page))
        self.assertEqual(code, 1)
        self.assertIn("is out of date", err)
        self.assertIn("scripts/transport_pages.py --write", err)

    def test_write_replaces_only_the_block(self):
        stale = self.stale()
        code, _, _ = run_main("--write", "--page", str(self.page))
        self.assertEqual(code, 0)
        written = self.page.read_bytes()
        self.assertEqual(written, PAGE.read_bytes())
        head, _, tail = transport_pages.split_page(stale, "stale")
        self.assertTrue(written.decode("utf-8").startswith(head))
        self.assertTrue(written.decode("utf-8").endswith(tail))
        self.assertEqual(run_main("--write", "--page", str(self.page))[0], 0)
        self.assertEqual(self.page.read_bytes(), written)

    def test_markers_are_required(self):
        text = PAGE.read_text(encoding="utf-8").replace(transport_pages.END_MARKER, "")
        self.page.write_text(text, encoding="utf-8")
        code, _, err = run_main("--check", "--page", str(self.page))
        self.assertEqual(code, 1)
        self.assertIn("needs exactly one line", err)

    def test_check_and_write_are_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            transport_pages.main(["--check", "--write"])
        self.assertEqual(caught.exception.code, 2)

    def test_reads_only_the_committed_sources(self):
        root = self.directory / "root"
        for name in {*transport_pages.SOURCES, *transport_report.SOURCES}:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, root / name)
        self.assertEqual(transport_pages.recorded_data(root), transport_pages.recorded_data(REPO))
        (root / transport_pages.PROTOCOLS).unlink()
        with self.assertRaisesRegex(ValueError, re.escape(transport_pages.PROTOCOLS)):
            transport_pages.recorded_data(root)


class WorkflowTests(unittest.TestCase):
    def test_pages_publishes_the_test_page_after_checking_it(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("path: transport/static\n", text)
        self.assertIn("python3 scripts/transport_pages.py --check", text)
        self.assertLess(text.index("transport_pages.py --check"),
                        text.index("actions/upload-pages-artifact"))
        for permission in ("pages: write", "id-token: write", "contents: read"):
            self.assertIn(permission, text)

    def test_deploy_runs_in_its_own_job_after_the_upload(self):
        # Uploading and deploying in one job can miss the artifact (actions/deploy-pages#451).
        text = WORKFLOW.read_text(encoding="utf-8")
        build, deploy = text.index("\n  build:\n"), text.index("\n  deploy:\n")
        self.assertLess(build, text.index("actions/upload-pages-artifact@v5"), deploy)
        self.assertLess(deploy, text.index("actions/deploy-pages@v5"))
        self.assertIn("    needs: build\n", text[deploy:])


class DocumentLinkTests(unittest.TestCase):
    """README.md stays at the root; every other document lives in results/."""

    def test_only_readme_and_agents_at_the_root(self):
        self.assertEqual(sorted(path.name for path in REPO.glob("*.md")),
                         ["AGENTS.md", "README.md"])

    def test_relative_links_resolve_from_each_document(self):
        documents = [REPO / "README.md", *sorted((REPO / "results").glob("*.md"))]
        self.assertIn(REPO / "results" / "HISTORY.md", documents)
        for document in documents:
            fenced = False
            for line in document.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("```"):
                    fenced = not fenced
                if fenced:
                    continue
                for target in re.findall(r"\]\(([^)\s]+)\)", line):
                    path = target.split("#", 1)[0]
                    if not path or re.match(r"(?:[a-z][a-z0-9+.-]*:|/)", path, re.IGNORECASE):
                        continue
                    with self.subTest(document=document.name, link=target):
                        self.assertTrue((document.parent / path).exists(), target)

    def test_readme_points_at_the_moved_documents(self):
        text = (REPO / "README.md").read_text(encoding="utf-8")
        for target in ("results/TRANSPORT.md", "results/HISTORY.md",
                       "results/RECOMMENDATIONS.md", "transport/setup.sh"):
            with self.subTest(target=target):
                self.assertIn(target, text)


class OnlyThePage(BaseHTTPRequestHandler):
    """Serve the test page at / on loopback, like the stack, and 404 everything else."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's name.
        if self.path.split("?", 1)[0] != "/":
            self.send_error(404)
            return
        data = PAGE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *arguments):
        pass


@unittest.skipUnless(HAVE_PLAYWRIGHT, "Playwright is not installed")
class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(channel=BROWSER_CHANNEL, headless=True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OnlyThePage)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.loopback = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.browser.close()
        cls.playwright.stop()

    def open(self, url: str, route_pages: bool = False):
        context = self.browser.new_context()
        self.addCleanup(context.close)
        if route_pages:  # Stand in for GitHub Pages: fulfil the page, abort anything else.
            context.route("**/*", lambda route: route.fulfill(
                status=200, content_type="text/html; charset=utf-8", body=PAGE.read_bytes())
                if route.request.url == url else route.abort())
        page = context.new_page()
        errors, requests = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))
        page.goto(url)
        return page, errors, requests

    def click(self, page, algorithm: str, action: str):
        page.click(f'button[data-action="{action}"][data-i="{NAMES.index(algorithm)}"]')

    def entries(self, page) -> list[dict]:
        return page.eval_on_selector_all("#log .entry", """entries => entries.map(e => ({
            tone: e.className.replace("entry ", ""),
            status: e.querySelector(".pill").textContent,
            who: e.querySelector(".top .sub").textContent,
            why: e.querySelector(".why")?.textContent || ""}))""")

    def test_opened_from_disk_it_replays_and_sends_nothing(self):
        url = PAGE.as_uri()
        page, errors, requests = self.open(url)
        self.assertTrue(page.is_visible("#notice"))
        self.assertEqual(page.eval_on_selector("#readme", "a => a.href"),
                         (REPO / "README.md").as_uri())
        self.assertTrue(page.is_visible("#recorded-results"))
        self.assertEqual(page.locator("#tables table").count(), 9)
        self.assertTrue(page.is_disabled("#which"))
        self.assertTrue(page.is_disabled("#echo"))
        self.click(page, "ML-DSA-44", "cookie")
        self.click(page, "SLH-DSA-SHA2-128s", "cookie")
        self.click(page, "SLH-DSA-SHA2-128s", "verify-cookie")
        self.click(page, "SLH-DSA-SHA2-128f", "bearer")
        self.click(page, "EdDSA", "body")
        entries = self.entries(page)[::-1]  # Newest first on the page.
        self.assertEqual([(entry["tone"], entry["status"]) for entry in entries],
                         [("ok", "200"), ("bad", "502"), ("warn", "401"), ("bad", "400"),
                          ("ok", "200")])
        self.assertIn("rejected by nginx", entries[1]["who"])
        self.assertIn("upstream sent too big header", entries[1]["why"])
        self.assertIn("client sent too long header line", entries[3]["why"])
        self.assertIn("Signing took", entries[4]["why"])
        self.assertEqual(page.locator("#log .pill.rec").count(), 5)
        self.assertEqual(errors, [])
        self.assertEqual(requests, [url])

    def test_on_github_pages_it_links_the_committed_runs(self):
        url = "https://example-owner.github.io/CIS628Project/"
        page, errors, requests = self.open(url, route_pages=True)
        self.assertTrue(page.is_visible("#notice"))
        self.assertEqual(page.get_attribute("#readme", "href"),
                         "https://github.com/example-owner/CIS628Project#readme")
        self.click(page, "ML-DSA-44", "bearer")
        link = page.get_attribute("#log .entry .req a", "href")
        self.assertEqual(link, "https://github.com/example-owner/CIS628Project/blob/main/"
                               + transport_report.BEARER_DEFAULT)
        hrefs = page.eval_on_selector_all("#tables a", "links => links.map(a => a.href)")
        self.assertTrue(hrefs)
        for href in hrefs:
            self.assertTrue(href.startswith(
                "https://github.com/example-owner/CIS628Project/"), href)
        self.assertEqual(errors, [])
        self.assertEqual(requests, [url])

    def test_on_loopback_it_stays_live_and_fetches_nothing_on_load(self):
        page, errors, requests = self.open(self.loopback)
        self.assertFalse(page.is_visible("#notice"))
        self.assertEqual(page.get_attribute("#readme", "href"),
                         "https://github.com/jseara/Post-Quantum-JWT#readme")
        self.assertFalse(page.is_visible("#recorded-results"))
        self.assertFalse(page.is_disabled("#which"))
        self.assertIn("Every button sends a real request", page.text_content("#intro"))
        self.assertEqual(errors, [])
        self.assertEqual(requests, [self.loopback])
        # A live click sends a real request; this server has no API, so it gets a 404.
        self.click(page, "ES256", "body")
        page.wait_for_selector("#log .entry")
        self.assertEqual(self.entries(page)[0]["status"], "404")
        self.assertEqual(page.locator("#log .pill.rec").count(), 0)

    def test_recorded_forces_read_only_on_loopback(self):
        url = self.loopback + "?recorded"
        page, errors, requests = self.open(url)
        self.assertTrue(page.is_visible("#notice"))
        self.click(page, "RS256", "cookie")
        self.assertEqual(self.entries(page)[0]["tone"], "ok")
        self.assertEqual(errors, [])
        self.assertEqual(requests, [url])


if __name__ == "__main__":
    unittest.main()
