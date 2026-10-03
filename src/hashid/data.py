# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static signature table for every hash type hash-id can recognize.

Generated from the 125 detector functions in the original hash-id.py;
each signature encodes only what the original tested: sample length,
character class, and an optional prefix/colon/upper-case constraint.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CharClass(str, Enum):
    """Character composition requirement, mirroring str.isdigit/isalpha/isalnum."""

    DIGIT = "digit"  # isdigit(): decimal characters only
    MIXED = "mixed"  # alphanumeric containing both letters and digits
    ALNUM = "alnum"  # alphanumeric, but not purely letters (CRC-16 rule)
    NON_ALNUM = "non_alnum"  # neither purely digits nor purely letters (DES/APR)
    PUNCT = "punct"  # contains a non-alphanumeric character ($, :, *, ...)


@dataclass(frozen=True)
class Signature:
    identifier: str
    name: str
    length: int
    char_class: CharClass
    prefix: str | None = None
    colon_at: int | None = None  # a ":" must exist at this index
    require_not_lower: bool = False  # original SAM rule: not h.islower()


SIGNATURES: tuple[Signature, ...] = (
    Signature("101020", "CRC-16", 4, CharClass.ALNUM),
    Signature("101040", "CRC-16-CCITT", 4, CharClass.MIXED),
    Signature("101060", "FCS-16", 4, CharClass.MIXED),
    Signature("102020", "ADLER-32", 8, CharClass.MIXED),
    Signature("102040", "CRC-32", 8, CharClass.MIXED),
    Signature("102060", "CRC-32B", 8, CharClass.MIXED),
    Signature("102080", "XOR-32", 8, CharClass.MIXED),
    Signature("103020", "GHash-32-5", 8, CharClass.DIGIT),
    Signature("103040", "GHash-32-3", 8, CharClass.DIGIT),
    Signature("104020", "DES(Unix)", 13, CharClass.NON_ALNUM),
    Signature("105020", "MySQL", 16, CharClass.MIXED),
    Signature("105040", "MD5(Middle)", 16, CharClass.MIXED),
    Signature("105060", "MD5(Half)", 16, CharClass.MIXED),
    Signature("106020", "MD5", 32, CharClass.MIXED),
    Signature(
        "106025",
        "Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))",
        32,
        CharClass.MIXED,
    ),
    Signature("106027", "RAdmin v2.x", 32, CharClass.MIXED),
    Signature("106029", "NTLM", 32, CharClass.MIXED),
    Signature("106040", "MD4", 32, CharClass.MIXED),
    Signature("106060", "MD2", 32, CharClass.MIXED),
    Signature("106080", "MD5(HMAC)", 32, CharClass.MIXED),
    Signature("106100", "MD4(HMAC)", 32, CharClass.MIXED),
    Signature("106120", "MD2(HMAC)", 32, CharClass.MIXED),
    Signature("106140", "MD5(HMAC(Wordpress))", 32, CharClass.MIXED),
    Signature("106160", "Haval-128", 32, CharClass.MIXED),
    Signature("106165", "Haval-128(HMAC)", 32, CharClass.MIXED),
    Signature("106180", "RipeMD-128", 32, CharClass.MIXED),
    Signature("106185", "RipeMD-128(HMAC)", 32, CharClass.MIXED),
    Signature("106200", "SNEFRU-128", 32, CharClass.MIXED),
    Signature("106205", "SNEFRU-128(HMAC)", 32, CharClass.MIXED),
    Signature("106220", "Tiger-128", 32, CharClass.MIXED),
    Signature("106225", "Tiger-128(HMAC)", 32, CharClass.MIXED),
    Signature("106240", "md5($pass.$salt)", 32, CharClass.MIXED),
    Signature("106260", "md5($salt.'-'.md5($pass))", 32, CharClass.MIXED),
    Signature("106280", "md5($salt.$pass)", 32, CharClass.MIXED),
    Signature("106300", "md5($salt.$pass.$salt)", 32, CharClass.MIXED),
    Signature("106320", "md5($salt.$pass.$username)", 32, CharClass.MIXED),
    Signature("106340", "md5($salt.md5($pass))", 32, CharClass.MIXED),
    Signature("106360", "md5($salt.md5($pass).$salt)", 32, CharClass.MIXED),
    Signature("106380", "md5($salt.md5($pass.$salt))", 32, CharClass.MIXED),
    Signature("106400", "md5($salt.md5($salt.$pass))", 32, CharClass.MIXED),
    Signature("106420", "md5($salt.md5(md5($pass).$salt))", 32, CharClass.MIXED),
    Signature("106440", "md5($username.0.$pass)", 32, CharClass.MIXED),
    Signature("106460", "md5($username.LF.$pass)", 32, CharClass.MIXED),
    Signature("106480", "md5($username.md5($pass).$salt)", 32, CharClass.MIXED),
    Signature("106500", "md5(md5($pass))", 32, CharClass.MIXED),
    Signature("106520", "md5(md5($pass).$salt)", 32, CharClass.MIXED),
    Signature("106540", "md5(md5($pass).md5($salt))", 32, CharClass.MIXED),
    Signature("106560", "md5(md5($salt).$pass)", 32, CharClass.MIXED),
    Signature("106580", "md5(md5($salt).md5($pass))", 32, CharClass.MIXED),
    Signature("106600", "md5(md5($username.$pass).$salt)", 32, CharClass.MIXED),
    Signature("106620", "md5(md5(md5($pass)))", 32, CharClass.MIXED),
    Signature("106640", "md5(md5(md5(md5($pass))))", 32, CharClass.MIXED),
    Signature("106660", "md5(md5(md5(md5(md5($pass)))))", 32, CharClass.MIXED),
    Signature("106680", "md5(sha1($pass))", 32, CharClass.MIXED),
    Signature("106700", "md5(sha1(md5($pass)))", 32, CharClass.MIXED),
    Signature("106720", "md5(sha1(md5(sha1($pass))))", 32, CharClass.MIXED),
    Signature("106740", "md5(strtoupper(md5($pass)))", 32, CharClass.MIXED),
    Signature("107020", "MD5(Wordpress)", 34, CharClass.PUNCT, prefix="$P$"),
    Signature("107040", "MD5(phpBB3)", 34, CharClass.PUNCT, prefix="$H$"),
    Signature("107060", "MD5(Unix)", 34, CharClass.PUNCT, prefix="$1$"),
    Signature("107080", "Lineage II C4", 34, CharClass.MIXED, prefix="0x"),
    Signature("108020", "MD5(APR)", 37, CharClass.NON_ALNUM, prefix="$apr"),
    Signature("109020", "SHA-1", 40, CharClass.MIXED),
    Signature("109040", "MySQL5 - SHA-1(SHA-1($pass))", 40, CharClass.MIXED),
    Signature(
        "109060", "MySQL 160bit - SHA-1(SHA-1($pass))", 41, CharClass.PUNCT, prefix="*"
    ),
    Signature("109080", "Tiger-160", 40, CharClass.MIXED),
    Signature("109100", "Haval-160", 40, CharClass.MIXED),
    Signature("109120", "RipeMD-160", 40, CharClass.MIXED),
    Signature("109140", "SHA-1(HMAC)", 40, CharClass.MIXED),
    Signature("109160", "Tiger-160(HMAC)", 40, CharClass.MIXED),
    Signature("109180", "RipeMD-160(HMAC)", 40, CharClass.MIXED),
    Signature("109200", "Haval-160(HMAC)", 40, CharClass.MIXED),
    Signature("109220", "SHA-1(MaNGOS)", 40, CharClass.MIXED),
    Signature("109240", "SHA-1(MaNGOS2)", 40, CharClass.MIXED),
    Signature("109260", "sha1($pass.$salt)", 40, CharClass.MIXED),
    Signature("109280", "sha1($salt.$pass)", 40, CharClass.MIXED),
    Signature("109300", "sha1($salt.md5($pass))", 40, CharClass.MIXED),
    Signature("109320", "sha1($salt.md5($pass).$salt)", 40, CharClass.MIXED),
    Signature("109340", "sha1($salt.sha1($pass))", 40, CharClass.MIXED),
    Signature("109360", "sha1($salt.sha1($salt.sha1($pass)))", 40, CharClass.MIXED),
    Signature("109380", "sha1($username.$pass)", 40, CharClass.MIXED),
    Signature("109400", "sha1($username.$pass.$salt)", 40, CharClass.MIXED),
    Signature("109420", "sha1(md5($pass))", 40, CharClass.MIXED),
    Signature("109440", "sha1(md5($pass).$salt)", 40, CharClass.MIXED),
    Signature("109460", "sha1(md5(sha1($pass)))", 40, CharClass.MIXED),
    Signature("109480", "sha1(sha1($pass))", 40, CharClass.MIXED),
    Signature("109500", "sha1(sha1($pass).$salt)", 40, CharClass.MIXED),
    Signature("109520", "sha1(sha1($pass).substr($pass,0,3))", 40, CharClass.MIXED),
    Signature("109540", "sha1(sha1($salt.$pass))", 40, CharClass.MIXED),
    Signature("109560", "sha1(sha1(sha1($pass)))", 40, CharClass.MIXED),
    Signature("109580", "sha1(strtolower($username).$pass)", 40, CharClass.MIXED),
    Signature("110020", "Tiger-192", 48, CharClass.MIXED),
    Signature("110040", "Haval-192", 48, CharClass.MIXED),
    Signature("110060", "Tiger-192(HMAC)", 48, CharClass.MIXED),
    Signature("110080", "Haval-192(HMAC)", 48, CharClass.MIXED),
    Signature("112020", "md5($pass.$salt) - Joomla", 49, CharClass.PUNCT, colon_at=32),
    Signature("113020", "SHA-1(Django)", 52, CharClass.PUNCT, prefix="sha1$"),
    Signature("114020", "SHA-224", 56, CharClass.MIXED),
    Signature("114040", "Haval-224", 56, CharClass.MIXED),
    Signature("114060", "SHA-224(HMAC)", 56, CharClass.MIXED),
    Signature("114080", "Haval-224(HMAC)", 56, CharClass.MIXED),
    Signature("115020", "SHA-256", 64, CharClass.MIXED),
    Signature("115040", "Haval-256", 64, CharClass.MIXED),
    Signature("115060", "GOST R 34.11-94", 64, CharClass.MIXED),
    Signature("115080", "RipeMD-256", 64, CharClass.MIXED),
    Signature("115100", "SNEFRU-256", 64, CharClass.MIXED),
    Signature("115120", "SHA-256(HMAC)", 64, CharClass.MIXED),
    Signature("115140", "Haval-256(HMAC)", 64, CharClass.MIXED),
    Signature("115160", "RipeMD-256(HMAC)", 64, CharClass.MIXED),
    Signature("115180", "SNEFRU-256(HMAC)", 64, CharClass.MIXED),
    Signature("115200", "SHA-256(md5($pass))", 64, CharClass.MIXED),
    Signature("115220", "SHA-256(sha1($pass))", 64, CharClass.MIXED),
    Signature("116020", "md5($pass.$salt) - Joomla", 65, CharClass.PUNCT, colon_at=32),
    Signature(
        "116040",
        "SAM - (LM_hash:NT_hash)",
        65,
        CharClass.PUNCT,
        colon_at=32,
        require_not_lower=True,
    ),
    Signature("117020", "SHA-256(Django)", 78, CharClass.PUNCT, prefix="sha256"),
    Signature("118020", "RipeMD-320", 80, CharClass.MIXED),
    Signature("118040", "RipeMD-320(HMAC)", 80, CharClass.MIXED),
    Signature("119020", "SHA-384", 96, CharClass.MIXED),
    Signature("119040", "SHA-384(HMAC)", 96, CharClass.MIXED),
    Signature("120020", "SHA-256", 98, CharClass.PUNCT, prefix="$6$"),
    Signature("121020", "SHA-384(Django)", 110, CharClass.PUNCT, prefix="sha384"),
    Signature("122020", "SHA-512", 128, CharClass.MIXED),
    Signature("122040", "Whirlpool", 128, CharClass.MIXED),
    Signature("122060", "SHA-512(HMAC)", 128, CharClass.MIXED),
    Signature("122080", "Whirlpool(HMAC)", 128, CharClass.MIXED),
)
