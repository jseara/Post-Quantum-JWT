"""The Markdown documents that moved from the repository root into results/.

The documents' relative links were rewritten for their new folder. The checks written while they
were at the root read them through DocPath, which turns each relative link back into the target
it had at the root, so those checks keep comparing like with like. repo_file resolves such a
root-style target to the file as it is now.
"""

from pathlib import Path
import posixpath
import re
import subprocess

REPO = Path(__file__).resolve().parents[1]
FOLDER = "results"
# The documents that moved; the old README is kept as results/HISTORY.md.
MOVED = ("PROGRESS.md", "RESULTS.md", "TRANSPORT.md", "TRANSPORT_RESULTS.md",
         "END_TO_END_RESULTS.md", "MITIGATION_RESULTS.md", "RECOMMENDATIONS.md")
HISTORY = REPO / FOLDER / "HISTORY.md"
LINK = re.compile(r"(\]\()([^)\s]+)(\))")
NOT_A_PATH = re.compile(r"(?:[a-z][a-z0-9+.-]*:|#|/)", re.IGNORECASE)


def as_at_root(text: str) -> str:
    """text from a document in results/, with its relative links as they were at the root."""
    lines, fenced = [], False
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced or line.lstrip().startswith("```"):
            lines.append(line)
            continue

        def at_root(match: re.Match) -> str:
            target = match[2]
            if NOT_A_PATH.match(target):
                return match[0]
            path, hash_, anchor = target.partition("#")
            if not path:
                return match[0]
            trailing = "/" if path.endswith("/") else ""
            moved = posixpath.normpath(posixpath.join(FOLDER, path))
            if posixpath.dirname(moved) == FOLDER and posixpath.basename(moved) in MOVED:
                moved = posixpath.basename(moved)
            return f"{match[1]}{moved}{trailing}{hash_}{anchor}{match[3]}"

        lines.append(LINK.sub(at_root, line))
    return "".join(lines)


class DocPath(type(Path())):
    """A moved document's path whose read_text gives the text with root-style links."""

    def read_text(self, *args, **kwargs) -> str:
        return as_at_root(super().read_text(*args, **kwargs))


def moved(name: str) -> DocPath:
    """A moved document, read with root-style links."""
    return DocPath(REPO / FOLDER / name)


def repo_file(target: str) -> Path:
    """The file a root-style repository-relative path names now."""
    path = posixpath.normpath(target)
    return REPO / FOLDER / path if path in MOVED else REPO / path


# The test files edited when the documents moved; the earlier tests' freezes skip them.
MOVE_EDITED_TESTS = {f"tests/test_transport_{name}.py" for name in
                     ("claims", "cookies", "docs", "load", "protocols", "refs", "report",
                      "tokens")}


def split_moved(paths: list[str]) -> tuple[list[str], list[str]]:
    """paths without the moved documents (and README.md), and those documents."""
    documents = [path for path in paths if path in MOVED or path == "README.md"]
    return [path for path in paths if path not in documents], documents


def changed_moved(commit: str, names: list[str]) -> list[str]:
    """The moved documents among names whose root-style text differs from commit's copy;
    README.md is compared through HISTORY.md, the old README kept as it was."""
    changed = []
    for name in names:
        source = HISTORY if name == "README.md" else REPO / FOLDER / name
        before = subprocess.run(["git", "-C", str(REPO), "show", f"{commit}:{name}"],
                                capture_output=True, text=True, encoding="utf-8")
        if (before.returncode != 0 or not source.is_file()
                or as_at_root(source.read_text(encoding="utf-8")) != before.stdout):
            changed.append(name)
    return changed
