#!/usr/bin/env bash
# Verify the repository without installing anything system-wide.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo "1/6 compile"
"$PYTHON" -m compileall -q src tests

echo "2/6 bash syntax"
bash -n install.sh run.sh verify.sh

echo "3/6 unit tests"
"$PYTHON" -m unittest discover -s tests

echo "4/6 check registry"
"$PYTHON" -m macsec --list-checks >/tmp/mhc-checks.txt
test "$(wc -l < /tmp/mhc-checks.txt | tr -d ' ')" -ge 20

echo "5/6 JSON smoke test"
"$PYTHON" -m macsec --json >/tmp/mhc-a.json
"$PYTHON" -m macsec --json >/tmp/mhc-b.json
cmp /tmp/mhc-a.json /tmp/mhc-b.json

echo "6/6 JSON schema"
"$PYTHON" - <<'PY'
import json
p = json.load(open('/tmp/mhc-a.json'))
assert p['schema_version'] == '1.0'
assert p['tool']['name'] == 'macsec'
assert p['summary']['total'] >= 20
assert len(p['checks']) == p['summary']['total']
print('schema ok:', p['summary'])
PY

echo "All checks passed."
