#!/usr/bin/env bash
# Create or update the pinned transport environment at PREFIX, then check its versions.
# Usage: bash transport/setup.sh PREFIX   (see TRANSPORT.md)
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "usage: bash transport/setup.sh PREFIX" >&2
    exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$1"
case "$PREFIX" in
    /*) ;;
    *) PREFIX="$PWD/$PREFIX" ;;
esac
CONDA="${CONDA_EXE:-conda}"
if ! command -v "$CONDA" > /dev/null 2>&1; then
    echo "Error: conda not found; set CONDA_EXE or put conda on PATH" >&2
    exit 1
fi

# Only conda-forge, and only the environment at PREFIX.
if [ -d "$PREFIX/conda-meta" ]; then
    "$CONDA" install --yes --prefix "$PREFIX" --override-channels -c conda-forge \
        --file "$REPO/transport/conda-requirements.txt"
else
    "$CONDA" create --yes --prefix "$PREFIX" --override-channels -c conda-forge \
        --file "$REPO/transport/conda-requirements.txt"
fi

# pip from PREFIX only; user site-packages and user installs are disabled.
export PYTHONNOUSERSITE=1
PIP_USER=0 "$PREFIX/bin/python" -m pip install --no-input --disable-pip-version-check \
    -r "$REPO/requirements.txt" -r "$REPO/transport/requirements.txt"

# The Playwright release pins the browser build; it goes to Playwright's default cache.
# --no-shell: the check uses full Chromium in new headless mode, not the headless shell.
# --no-remove: leave browser builds that other Playwright installations use in the cache.
"$PREFIX/bin/python" -m playwright install --no-shell --no-remove chromium

"$PREFIX/bin/python" "$REPO/scripts/transport_stack.py" versions
