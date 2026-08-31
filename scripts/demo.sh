#!/usr/bin/env bash
# Walk the whole loop against a throwaway copy of the vulnerable fixture, with
# the model's part played by sed. Nothing here touches the repository you are in.
#
#   bash scripts/demo.sh          # run it
#   bash scripts/demo.sh --serve  # leave the board running at the end
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
CLI="python3 $REPO/engine/redassay_cli.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

cp -R fixtures/vuln-flask/. "$WORK/"
rm -rf "$WORK/.redassay"
cd "$WORK"

say "1. Scan"
$CLI scan --quiet --limit 4 --no-color

say "2. Triage: approve two fixes, dismiss one"
sql=$($CLI list --json --rule py.sql-dynamic      | python3 -c 'import json,sys; print(json.load(sys.stdin)["findings"][0]["id"])')
shell=$($CLI list --json --rule py.shell-dynamic  | python3 -c 'import json,sys; print(json.load(sys.stdin)["findings"][0]["id"])')
noto=$($CLI list --json --rule py.request-no-timeout | python3 -c 'import json,sys; print(json.load(sys.stdin)["findings"][0]["id"])')

$CLI comment "$sql" "Confirmed reachable from the public /user endpoint."
$CLI queue push fix --id "$sql"   --payload '{"note":"Keep returning a dict with a rows key"}'
$CLI queue push fix --id "$shell" --payload '{"note":"Keep the single-packet behaviour"}'
$CLI dismiss "$noto" --reason "Internal service with its own deadline."

say "3. The agent claims the work"
$CLI queue pull | python3 -c '
import json, sys
for action in json.load(sys.stdin)["claimed"]:
    f = action["findings"][0]
    where = f["location"]["path"] + ":" + str(f["location"]["line"])
    print("  #{0}  {1}  {2}".format(action["seq"], f["rule_id"], where))
    print("        note: " + action["payload"]["note"])
'

say "4. The agent fixes the code"
python3 - <<'PY'
import re
path = "app/views.py"
source = open(path).read()
source = source.replace(
    '    query = f"SELECT id, email FROM users WHERE name = \'{name}\'"\n'
    "    cursor = db().cursor()\n"
    "    cursor.execute(query)\n",
    "    cursor = db().cursor()\n"
    '    cursor.execute("SELECT id, email FROM users WHERE name = ?", (name,))\n',
)
source = source.replace(
    '    output = subprocess.check_output("ping -c 1 " + host, shell=True)\n',
    '    output = subprocess.check_output(["ping", "-c", "1", host], timeout=10)\n',
)
open(path, "w").write(source)
print("  patched app/views.py")
PY

# Record what changed, not just that something did. Without a diff, a finding
# marked fixed is hard to tell from one somebody quietly marked done.
diff -u app/views.py.orig app/views.py > "$WORK/change.diff" 2>/dev/null || true
$CLI resolve "$sql"   --summary "Bound the name as a query parameter instead of interpolating it" \
  --diff-file "$WORK/change.diff"
$CLI resolve "$shell" --summary "Passed an argument list with a timeout so no shell parses the host" \
  --diff-file "$WORK/change.diff"
$CLI queue complete 1 --result fixed
$CLI queue complete 2 --result fixed

rm -f app/views.py.orig

say "5. Rescan verifies"
$CLI scan --quiet --limit 0 --no-color 2>&1 | grep -E "^(store|[0-9]+ findings)" || true

$CLI list --all --json | python3 -c '
import json, sys
for finding in json.load(sys.stdin)["findings"]:
    if finding["status"] == "open":
        continue
    where = finding["location"]["path"] + ":" + str(finding["location"]["line"])
    print("  {0:<9} {1:<22} {2}".format(finding["status"], finding["rule_id"], where))
    if finding["fix"]["summary"]:
        print("            fix:  " + finding["fix"]["summary"])
    for comment in finding["comments"]:
        print("            note: [" + comment["author"] + "] " + comment["body"][:66])
'

say "Done"
echo "  Two approved fixes applied and verified by rescan."
echo "  The dismissal and the review note survived it."

if [ "${1:-}" = "--serve" ]; then
  trap - EXIT
  echo
  echo "  Board:  http://127.0.0.1:7717   (repo copy left at $WORK)"
  $CLI serve --no-browser
fi
