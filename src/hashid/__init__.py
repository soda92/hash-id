# SPDX-License-Identifier: AGPL-3.0-or-later
# Modernized rewrite of hash-id, originally by Zion3R (www.Blackploit.com).
"""hashid — identify hashes used to hash data, especially passwords.

A data-driven Python 3 rewrite of the original hash-id 1.2. Detection rules
are preserved verbatim; two long-standing bugs were fixed (identifiers
106260/106360 were shadowed by duplicate function definitions, and "1094202"
was a typo for 109420).
"""

from __future__ import annotations

from .core import identify_hash, matches, split_results
from .data import SIGNATURES, CharClass, Signature

__version__ = "2.0.0"

__all__ = [
    "__version__",
    "identify_hash",
    "matches",
    "split_results",
    "SIGNATURES",
    "Signature",
    "CharClass",
]
