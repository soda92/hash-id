# SPDX-License-Identifier: AGPL-3.0-or-later
# Modernized rewrite of hash-id, originally by Zion3R (www.Blackploit.com).
"""Core identification logic: match a candidate hash against the signature table."""

from __future__ import annotations

from .data import SIGNATURES, CharClass, Signature

__all__ = ["identify_hash", "matches", "split_results", "Signature"]


def _char_class_matches(value: str, char_class: CharClass) -> bool:
    """Replicate the exact str.isdigit/isalpha/isalnum predicates of the original."""
    is_digit = value.isdigit()
    is_alpha = value.isalpha()
    is_alnum = value.isalnum()
    if char_class is CharClass.DIGIT:
        return is_digit and not is_alpha
    if char_class is CharClass.MIXED:
        return is_alnum and not is_alpha and not is_digit
    if char_class is CharClass.ALNUM:
        return is_alnum and not is_alpha
    if char_class is CharClass.NON_ALNUM:
        return not is_alpha and not is_digit
    if char_class is CharClass.PUNCT:
        return not is_alnum and not is_alpha and not is_digit
    raise ValueError(f"unknown character class: {char_class!r}")


def matches(value: str, signature: Signature) -> bool:
    """Return True when *value* satisfies every constraint in *signature*."""
    if len(value) != signature.length:
        return False
    if not _char_class_matches(value, signature.char_class):
        return False
    if signature.prefix is not None and not value.startswith(signature.prefix):
        return False
    if (
        signature.colon_at is not None
        and value[signature.colon_at : signature.colon_at + 1] != ":"
    ):
        return False
    if signature.require_not_lower and value.islower():
        return False
    return True


def identify_hash(value: str) -> tuple[Signature, ...]:
    """Identify *value*, returning matching signatures ordered like the original.

    Ordering is by the upstream numeric identifier, which keeps the
    "most likely first" grouping stable.
    """
    return tuple(
        sorted(
            (signature for signature in SIGNATURES if matches(value, signature)),
            key=lambda signature: signature.identifier,
        )
    )


def split_results(
    matches: tuple[Signature, ...],
) -> tuple[tuple[Signature, ...], tuple[Signature, ...]]:
    """Split matches into the two "possible" and remaining "least possible" groups."""
    return matches[:2], matches[2:]
