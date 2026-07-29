# Fixtures

Deliberately vulnerable applications used by the test suite. Each file carries a
`VULN:` comment naming the rule it is meant to trigger, so a test can assert on
coverage rather than on a count that drifts every time a rule is added.

`clean-app/` is the control: idiomatic, safe code that must produce **zero**
findings. It is the more valuable half of the fixture set - a scanner that finds
everything is easy, and useless.

Nothing here is real. The credentials are fake, the endpoints do not exist.
