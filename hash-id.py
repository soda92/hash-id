#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backwards-compatible launcher for running hash-id straight from a checkout.

Prefer the installed ``hash-id`` command or ``python -m hashid``.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if SRC.is_dir():
    sys.path.insert(0, str(SRC))

from hashid.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
