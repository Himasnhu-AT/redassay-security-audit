# tools

Maintenance scripts. None of them are needed to *use* redassay - they exist to
keep it honest.

| Script | What it does | Run by CI |
| --- | --- | --- |
| `check_stdlib_only.py` | Fails if the engine imports anything outside the standard library. The zero-dependency property is easy to break by accident and invisible until someone runs it on a clean machine. | yes |
| `validate_plugin.py` | Checks the manifests, the command frontmatter, that each skill's frontmatter name matches its directory, and that every JSON example parses. A skill whose name is wrong simply never triggers, silently. | yes |
| `generate_rule_docs.py` | Regenerates `docs/rules.md` from the packs. `--check` fails if it is stale. A hand-maintained rule catalogue is wrong within a week. | yes |
| `benchmark.py` | Measures scan throughput and the prefilter's contribution, with every A/B half running back to back in one process. Wall-clock numbers taken minutes apart differ by 2x on the same machine. | no |
| `evaluate.py` | Scans real repositories and prints the shape of the result: counts, rule frequency, hotspots. Used to produce `docs/evaluation.md`. | no |

## The two you will actually use

**Adding a rule?** `generate_rule_docs.py` after, `evaluate.py` against a real
repository to see what it does to a codebase you know.

**Changing something hot?** `benchmark.py`, never `time`.
