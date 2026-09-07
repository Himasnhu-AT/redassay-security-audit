# Documentation

Start with the root [README](../README.md); this is the map of everything else.

## Using it

- [**cli.md**](cli.md) - every command and flag, with the CI recipes.
- [**loop.md**](loop.md) - what happens when you run `/redassay-security audit`,
  step by step, and where you fit into it.
- [**ci.md**](ci.md) - running it as a gate: diff scoping, baselines, SARIF
  upload, and how to pick a threshold that will not get switched off.

## Extending it

- [**writing-rules.md**](writing-rules.md) - the rule format, the three guards
  that make regex SAST usable, and how to test a rule properly.
- [**rules.md**](rules.md) - the full catalogue. Generated from the packs by
  `tools/generate_rule_docs.py`; do not edit by hand.

## Understanding it

- [**design.md**](design.md) - the original notes, kept because they explain why
  the pieces are separate.
- [**architecture.md**](architecture.md) - the scan pipeline, finding identity,
  the scope of the taint tracker, and how the board is hardened.
- [**evaluation.md**](evaluation.md) - measured results on real codebases,
  including the false positives real repositories produced and what was
  changed in response.
- [**performance.md**](performance.md) - where the time goes, the optimization
  that worked, and the two that looked obvious and measured slower.

## Contributing

- [**../CONTRIBUTING.md**](../CONTRIBUTING.md) - the rules the project holds
  itself to.
- [**../SECURITY.md**](../SECURITY.md) - the board's threat model and the
  known limits.
- [**../tools/README.md**](../tools/README.md) - what each maintenance script is
  for.
