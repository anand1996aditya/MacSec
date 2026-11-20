#!/usr/bin/env bash
# Run macsec from this checkout, using .venv when present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${MHC_VENV:-$ROOT/.venv}"

if [ -x "$VENV/bin/macsec" ]; then
  exec "$VENV/bin/macsec" "$@"
fi
if command -v macsec >/dev/null 2>&1; then
  exec macsec "$@"
fi
exec env PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m macsec "$@"
