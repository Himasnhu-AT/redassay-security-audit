"""Put the engine on sys.path for every test module.

Tests run with `python3 -m unittest discover` from the repo root, so there is no
installed package to import.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENGINE = os.path.join(ROOT, "engine")
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)

FIXTURES = os.path.join(ROOT, "fixtures")
