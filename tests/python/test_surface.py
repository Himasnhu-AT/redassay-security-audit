"""The entry-point inventory.

This is the artifact an audit starts from, so its failure modes matter in a
specific direction: a missed entry point is a gap in the review, and a route
wrongly marked "guarded" is worse than one wrongly marked "none-found" - the
first hides work, the second only creates some.
"""

import unittest

from .helpers import TempRepo
from redassay import surface, tech
from redassay.surface import _arguments_after_path
from redassay.walker import WalkOptions, collect

EXPRESS = """
const app = require("express")();

app.get("/", home);
app.get("/login", showLogin);
app.post("/login", handleLogin);
app.get("/dashboard", isLoggedIn, showDashboard);
app.post("/profile", isLoggedIn, updateProfile);
app.post("/admin/wipe", (req, res) => { db.drop(); });
app.delete("/account", requireAuth, deleteAccount);
"""

FLASK = """
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route("/public")
def public():
    return "hi"

@app.route("/settings", methods=["POST"])
@login_required
def settings():
    return "ok"
"""


class ArgumentScannerTest(unittest.TestCase):
    """Counting commas naively marks every plain route as protected."""

    def test_a_plain_arrow_handler_is_one_argument(self):
        self.assertEqual(_arguments_after_path(", (req, res) => { res.send(1); })"), 1)

    def test_one_middleware_is_two(self):
        self.assertEqual(_arguments_after_path(", isLoggedIn, handler)"), 2)

    def test_two_middleware_is_three(self):
        self.assertEqual(_arguments_after_path(", a, b, handler)"), 3)

    def test_commas_inside_strings_do_not_count(self):
        self.assertEqual(_arguments_after_path(', function (req, res) { q("a,b,c"); })'), 1)

    def test_commas_inside_objects_do_not_count(self):
        self.assertEqual(_arguments_after_path(", { a: 1, b: 2 }, handler)"), 2)

    def test_it_stops_at_the_end_of_the_call(self):
        self.assertEqual(_arguments_after_path(", handler)\napp.get('/x', a, b, c)"), 1)

    def test_escaped_quotes_do_not_unbalance_it(self):
        self.assertEqual(_arguments_after_path(r', "a\\"b,c", handler)'), 2)


class ExpressInventoryTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.write("package.json", '{"dependencies": {"express": "^4.18.0"}}')
        self.write("routes.js", EXPRESS)
        files = collect(self.root, WalkOptions())
        self.entries = surface.inventory(files, tech.detect(files))
        self.by_label = {e.label: e for e in self.entries}

    def test_every_route_is_found(self):
        self.assertEqual(len(self.entries), 7)

    def test_methods_and_paths_are_captured(self):
        self.assertIn("POST /login", self.by_label)
        self.assertIn("DELETE /account", self.by_label)

    def test_a_route_with_middleware_reads_as_guarded(self):
        self.assertEqual(self.by_label["GET /dashboard"].auth, "guarded")
        self.assertEqual(self.by_label["POST /profile"].auth, "guarded")

    def test_a_route_without_middleware_reads_as_unprotected(self):
        self.assertEqual(self.by_label["POST /admin/wipe"].auth, "none-found")

    def test_an_adjacent_guarded_route_does_not_leak_onto_a_bare_one(self):
        """Call-style registrations are authoritative; neighbours are noise."""
        self.assertEqual(self.by_label["POST /login"].auth, "none-found")
        self.assertEqual(self.by_label["GET /login"].auth, "none-found")

    def test_middleware_registration_is_not_a_route(self):
        self.assertFalse(any(e.method == "USE" for e in self.entries))

    def test_mutating_routes_are_identified(self):
        self.assertTrue(self.by_label["POST /admin/wipe"].is_mutating)
        self.assertFalse(self.by_label["GET /"].is_mutating)

    def test_needs_review_leads_with_the_unprotected_mutation(self):
        first = surface.needs_review(self.entries)[0]
        self.assertEqual(first.label, "POST /admin/wipe")


class FlaskInventoryTest(TempRepo):
    def setUp(self):
        super().setUp()
        self.write("requirements.txt", "flask\n")
        self.write("app.py", FLASK)
        files = collect(self.root, WalkOptions())
        self.entries = surface.inventory(files, tech.detect(files))
        self.by_name = {e.name: e for e in self.entries}

    def test_decorated_routes_are_found(self):
        self.assertEqual(set(self.by_name), {"/public", "/settings"})

    def test_the_methods_list_is_read(self):
        self.assertEqual(self.by_name["/settings"].method, "POST")

    def test_a_decorator_on_the_next_line_counts_as_a_guard(self):
        """Decorator-style frameworks put the guard on its own line, so unlike
        call-style registrations the surrounding window is the only signal."""
        self.assertEqual(self.by_name["/settings"].auth, "guarded")

    def test_an_undecorated_route_reads_as_unprotected(self):
        self.assertEqual(self.by_name["/public"].auth, "none-found")


class SummaryTest(TempRepo):
    def test_summary_counts(self):
        self.write("package.json", '{"dependencies": {"express": "^4"}}')
        self.write("routes.js", EXPRESS)
        files = collect(self.root, WalkOptions())
        entries = surface.inventory(files, tech.detect(files))
        stats = surface.summarize(entries)
        self.assertEqual(stats["total"], 7)
        self.assertEqual(stats["externally_reachable"], 7)
        self.assertEqual(stats["by_framework"], {"Express": 7})
        self.assertGreaterEqual(stats["unprotected"], 1)

    def test_empty_repository(self):
        stats = surface.summarize([])
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["unprotected"], 0)

    def test_entries_serialize(self):
        import json
        self.write("package.json", '{"dependencies": {"express": "^4"}}')
        self.write("routes.js", EXPRESS)
        files = collect(self.root, WalkOptions())
        for entry in surface.inventory(files, tech.detect(files)):
            json.dumps(entry.to_dict())


class OtherSurfacesTest(TempRepo):
    def test_a_next_server_action_is_an_entry_point(self):
        self.write("package.json", '{"dependencies": {"next": "14.0.0"}}')
        self.write("app/actions.ts",
                   '"use server";\n\nexport async function deleteAccount(id: string) {\n  return db.delete(id);\n}\n')
        files = collect(self.root, WalkOptions())
        entries = surface.inventory(files, tech.detect(files))
        actions = [e for e in entries if e.kind == surface.SERVER_ACTION]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].name, "deleteAccount")
        self.assertEqual(actions[0].method, "POST")

    def test_a_next_route_handler_is_found_by_its_path(self):
        self.write("package.json", '{"dependencies": {"next": "14.0.0"}}')
        self.write("app/api/users/route.ts", "export async function GET() {}\n")
        files = collect(self.root, WalkOptions())
        entries = surface.inventory(files, tech.detect(files))
        self.assertIn("/api/users", [e.name for e in entries])

    def test_a_celery_task_is_a_queue_entry_point(self):
        self.write("requirements.txt", "celery\n")
        self.write("tasks.py", "from celery import shared_task\n\n@shared_task\ndef process(payload):\n    return payload\n")
        files = collect(self.root, WalkOptions())
        entries = surface.inventory(files, tech.detect(files))
        queues = [e for e in entries if e.kind == surface.QUEUE]
        self.assertEqual([e.name for e in queues], ["process"])

    def test_a_socket_handler_is_an_entry_point(self):
        self.write("package.json", '{"dependencies": {"socket.io": "^4"}}')
        self.write("io.js", 'socket.on("transfer", (data) => move(data));\n')
        files = collect(self.root, WalkOptions())
        entries = surface.inventory(files, tech.detect(files))
        self.assertIn("transfer", [e.name for e in entries if e.kind == surface.SOCKET])


if __name__ == "__main__":
    unittest.main()
