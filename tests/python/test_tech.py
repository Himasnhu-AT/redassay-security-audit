"""Framework detection.

`languages.py` says what a file is written in. This says what the application is
built with, which is the difference between "there is Python here" and "the
routes are in urls.py, the auth decorator is called login_required, and the
three mistakes this community makes are X, Y and Z".
"""

import json
import unittest

from .helpers import TempRepo
from redassay import tech
from redassay.walker import WalkOptions, collect


class DetectionTest(TempRepo):
    def detect(self):
        return tech.detect(collect(self.root, WalkOptions()))

    def test_nothing_in_an_empty_repo(self):
        self.assertEqual(self.detect().tags, set())
        self.assertEqual(tech.summarize(self.detect()), "no frameworks detected")

    def test_django_from_its_sentinel_file(self):
        self.write("manage.py", "import django\n")
        self.assertIn("django", self.detect().tags)

    def test_django_from_requirements(self):
        self.write("requirements.txt", "Django==4.2\npsycopg2\n")
        self.assertIn("django", self.detect().tags)

    def test_flask_and_fastapi_from_requirements(self):
        self.write("requirements.txt", "flask==3.0\nfastapi\n")
        tags = self.detect().tags
        self.assertIn("flask", tags)
        self.assertIn("fastapi", tags)

    def test_express_from_package_json(self):
        self.write("package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
        self.assertIn("express", self.detect().tags)

    def test_dev_dependencies_count(self):
        self.write("package.json", json.dumps({"devDependencies": {"next": "14.0.0"}}))
        self.assertIn("nextjs", self.detect().tags)

    def test_one_dependency_can_imply_two_tags(self):
        self.write("requirements.txt", "djangorestframework\n")
        tags = self.detect().tags
        self.assertIn("django", tags)
        self.assertIn("drf", tags)

    def test_go_modules(self):
        self.write("go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
        self.assertIn("gin", self.detect().tags)

    def test_rails_from_its_routes_file(self):
        self.write("config/routes.rb", "Rails.application.routes.draw do\nend\n")
        self.assertIn("rails", self.detect().tags)

    def test_laravel_from_artisan(self):
        self.write("artisan", "#!/usr/bin/env php\n")
        self.assertIn("laravel", self.detect().tags)

    def test_infrastructure_tags(self):
        self.write("Dockerfile", "FROM alpine\n")
        self.write("docker-compose.yml", "services: {}\n")
        self.write(".github/workflows/ci.yml", "name: ci\n")
        tags = self.detect().tags
        for expected in ("docker", "compose", "github-actions"):
            self.assertIn(expected, tags)

    def test_a_malformed_manifest_does_not_raise(self):
        self.write("package.json", "{not json")
        self.assertEqual(self.detect().tags, set())

    def test_evidence_records_why(self):
        self.write("package.json", json.dumps({"dependencies": {"express": "^4"}}))
        detection = self.detect()
        self.assertIn("express", detection.evidence)
        self.assertTrue(any("package.json" in why for why in detection.evidence["express"]))

    def test_a_similarly_named_package_is_not_a_match(self):
        self.write("package.json", json.dumps({"dependencies": {"express-rate-limit": "^7"}}))
        self.assertNotIn("express", self.detect().tags)


class CatalogueTest(unittest.TestCase):
    def test_every_emitted_tag_is_declared_somewhere(self):
        """A tag with no catalogue entry and no INFORMATIONAL_TAGS entry is a
        typo in a marker table, not a decision."""
        emitted = set()
        for table in (tech.DEPENDENCY_MARKERS, tech.FILE_MARKERS, tech.PATH_MARKERS):
            for tags in table.values():
                emitted.update(tags)
        undeclared = sorted(emitted - set(tech.CATALOGUE) - tech.INFORMATIONAL_TAGS)
        self.assertEqual(undeclared, [], f"tags emitted but never declared: {undeclared}")

    def test_informational_tags_do_not_also_claim_guidance(self):
        overlap = sorted(tech.INFORMATIONAL_TAGS & set(tech.CATALOGUE))
        self.assertEqual(overlap, [], f"declared both ways: {overlap}")

    def test_catalogue_entries_are_well_formed(self):
        for tag, entry in tech.CATALOGUE.items():
            self.assertEqual(tag, entry.tag)
            self.assertTrue(entry.label)
            self.assertTrue(entry.language)

    def test_notes_are_specific_not_tutorials(self):
        for tag, entry in tech.CATALOGUE.items():
            for note in entry.notes:
                self.assertGreater(len(note), 40, f"{tag}: note too vague")
                self.assertLess(len(note), 260, f"{tag}: note is a tutorial, not a warning")

    def test_notes_render_with_the_framework_name(self):
        detection = tech.Detection()
        detection.add("flask", "requirements.txt")
        notes = detection.notes()
        self.assertTrue(notes)
        self.assertTrue(all(note.startswith("Flask: ") for note in notes))

    def test_to_dict_is_serializable(self):
        detection = tech.Detection()
        detection.add("django", "manage.py")
        json.dumps(detection.to_dict())


if __name__ == "__main__":
    unittest.main()
