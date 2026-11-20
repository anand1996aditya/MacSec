#!/usr/bin/env bash
# Install macsec into an isolated virtual environment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${MHC_VENV:-$ROOT/.venv}"
PYTHON="${PYTHON:-python3}"

usage() {
  cat <<'USAGE'
Usage: ./install.sh [--venv PATH] [--help]

Creates an isolated virtual environment, installs the package and prints the
command to run. No sudo access is required.

Environment:
  PYTHON       Python 3.10+ interpreter (default: python3)
  MHC_VENV     virtual-environment path (default: <repo>/.venv)
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --venv)
      [ "$#" -ge 2 ] || { echo "install.sh: --venv needs a path" >&2; exit 2; }
      VENV="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "install.sh: macOS is required." >&2
  exit 2
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "install.sh: '$PYTHON' was not found. Install Python 3.10 or newer." >&2
  exit 2
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "install.sh: Python 3.10 or newer is required." >&2
  echo "Install it with: brew install python@3.13" >&2
  exit 2
fi

if [ ! -f "$ROOT/pyproject.toml" ]; then
  echo "install.sh: run this from the repository root." >&2
  exit 2
fi

echo "Creating virtual environment: $VENV"
"$PYTHON" -m venv "$VENV"

echo "Installing package"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet "$ROOT"

echo
echo "Installed successfully."
echo "Run it with:"
echo "  $VENV/bin/macsec"
echo
echo "Or add it to your PATH for this shell:"
echo "  export PATH=\"$VENV/bin:\$PATH\""
