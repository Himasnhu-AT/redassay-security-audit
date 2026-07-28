#!/usr/bin/env bash
# Run both suites. Neither needs anything installed.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

echo "== python =="
if python3 -m unittest discover -s tests/python -t . -p "test_*.py" "$@"; then
  echo "python: ok"
else
  echo "python: FAILED"
  fail=1
fi

echo
echo "== javascript =="
if node --test tests/js/*.test.js; then
  echo "javascript: ok"
else
  echo "javascript: FAILED"
  fail=1
fi

exit "$fail"
