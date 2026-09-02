#!/usr/bin/env bash
# Everything CI runs, locally, in the order that fails fastest.
#
#   bash scripts/check.sh          # the lot
#   bash scripts/check.sh --quick  # skip the demo and the fixture scans
set -uo pipefail
cd "$(dirname "$0")/.."

quick=false
[ "${1:-}" = "--quick" ] && quick=true

failed=0
step() {
  local name="$1"; shift
  printf '\033[2m%-34s\033[0m' "$name"
  local output
  if output=$("$@" 2>&1); then
    printf '\033[32mok\033[0m\n'
  else
    printf '\033[31mFAILED\033[0m\n'
    printf '%s\n' "$output" | sed 's/^/    /'
    failed=1
  fi
}

step "engine is stdlib only"        python3 tools/check_stdlib_only.py
step "plugin structure"             python3 tools/validate_plugin.py
step "rule catalogue is current"    python3 tools/generate_rule_docs.py --check
step "rules match their examples"   python3 -m unittest tests.python.test_rule_examples
step "python tests"                 python3 -m unittest discover -s tests/python -t . -p 'test_*.py'
step "javascript tests"             bash -c 'node --test tests/js/*.test.js'
step "redassay scans itself clean"  python3 engine/redassay_cli.py scan --quiet --fail-on info

if [ "$quick" = false ]; then
  step "demo walks the whole loop"  bash scripts/demo.sh
  for fixture in vuln-flask vuln-node vuln-polyglot; do
    step "detection: $fixture" bash -c "
      count=\$(python3 engine/redassay_cli.py --root fixtures/$fixture scan --quiet --json \
              | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"scan\"][\"total\"])')
      rm -rf fixtures/$fixture/.redassay
      [ \"\$count\" -ge 15 ]"
  done
  step "control fixture stays quiet" bash -c '
    loud=$(python3 engine/redassay_cli.py --root fixtures/clean-app scan --quiet --json \
           | python3 -c "import json,sys; print(sum(1 for f in json.load(sys.stdin)[\"findings\"] if f[\"confidence\"] == \"high\"))")
    rm -rf fixtures/clean-app/.redassay
    [ "$loud" -eq 0 ]'
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "everything passes"
else
  echo "something failed - see above"
fi
exit "$failed"
