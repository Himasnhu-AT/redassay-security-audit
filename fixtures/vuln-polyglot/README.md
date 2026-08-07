# Polyglot fixture

One small file per ecosystem, each carrying the defects the corresponding rule
pack is meant to catch. These exist so a rule pack cannot quietly stop working:
`tests/python/test_rule_packs_fire.py` asserts each labelled defect is still
detected.

Nothing here runs. The files are syntactically plausible, not complete programs.
