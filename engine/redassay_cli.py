#!/usr/bin/env python3
"""Entry point that works without installing anything.

The plugin invokes `python3 <plugin>/engine/redassay_cli.py`, so this file's job
is to put its own directory on sys.path and hand off. Keeping it separate from
the package means `python3 -m redassay` still works for anyone who does install.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from redassay.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
