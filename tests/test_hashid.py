# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the modernized hashid package.

The original hash-id.py 1.2 script is kept under tests/fixtures and used as an
oracle: detection results must match it exactly, apart from the two bugs that
were intentionally fixed in the rewrite.
"""

from __future__ import annotations

import ast
import io
import json
import sys
import warnings
from pathlib import Path

import pytest

from hashid import __version__, identify_hash
from hashid.banner import logo
from hashid.cli import format_json, format_result, main
from hashid.core import split_results
from hashid.data import SIGNATURES

FIXTURE = Path(__file__).parent / "fixtures" / "hash_id_original_1_2.py"
ORIGINAL_SRC = FIXTURE.read_text()
with warnings.catch_warnings():
    # The 2010-era fixture source contains invalid string escape sequences.
    warnings.simplefilter("ignore", SyntaxWarning)
    ORIGINAL_TREE = ast.parse(ORIGINAL_SRC)


# --- Oracle: emulate the runtime of the original 1.2 script -----------------


def _original_names():
    algorithms = {}
    for node in ORIGINAL_TREE.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "algorithms":
                    algorithms = ast.literal_eval(node.value)
    return algorithms


ORIGINAL_ALGORITHMS = _original_names()


def _original_samples():
    """Return (sample_hash, appended_identifier) for every original function."""
    samples = []
    for node in ORIGINAL_TREE.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        sample = None
        appended = None
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Assign)
                and isinstance(sub.targets[0], ast.Name)
                and sub.targets[0].id == "hs"
            ):
                sample = ast.literal_eval(sub.value)
            if (
                isinstance(sub, ast.Expr)
                and isinstance(sub.value, ast.Call)
                and isinstance(sub.value.func, ast.Attribute)
                and sub.value.func.attr == "append"
            ):
                appended = ast.literal_eval(sub.value.args[0])
        samples.append((sample, appended))
    return samples


ORIGINAL_SAMPLES = _original_samples()

# The original defines two function names twice; the later definition silently
# shadows the earlier one, so identifiers 106260 and 106360 were unreachable.
SHADOWED_IDENTIFIERS = {"106260", "106360"}
# The original dictionary has typo key "1094202" for sha1(md5($pass)).
TYPO_IDENTIFIERS = {"1094202": "109420"}


def _emulate_original(value: str) -> list[str]:
    """Run the original detector functions in their original call order."""
    namespace = {"jerar": [], "algorithms": ORIGINAL_ALGORITHMS}
    for node in ORIGINAL_TREE.body:
        if isinstance(node, ast.FunctionDef):
            exec(
                compile(ast.Module(body=[node], type_ignores=[]), str(FIXTURE), "exec"),
                namespace,
            )

    while_node = next(n for n in ORIGINAL_TREE.body if isinstance(n, ast.While))
    try_node = next(s for s in while_node.body if isinstance(s, ast.Try))
    function_names = {
        n.name for n in ORIGINAL_TREE.body if isinstance(n, ast.FunctionDef)
    }
    for stmt in try_node.body:
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and stmt.value.func.id in function_names
        ):
            namespace[stmt.value.func.id](value)
    return namespace["jerar"]


def _names(matches) -> list[str]:
    return [m.name for m in matches]


# --- Table integrity --------------------------------------------------------


def test_table_completeness():
    assert len(SIGNATURES) == 125
    identifiers = [s.identifier for s in SIGNATURES]
    assert len(set(identifiers)) == 125
    assert set(identifiers) == {
        TYPO_IDENTIFIERS.get(key, key) for key in ORIGINAL_ALGORITHMS
    }
    for signature in SIGNATURES:
        assert signature.length > 0
        assert signature.name


# --- Fidelity against the original 1.2 script ------------------------------


@pytest.mark.parametrize("sample,identifier", ORIGINAL_SAMPLES)
def test_every_original_detector_fires_on_its_sample(sample, identifier):
    names = _names(identify_hash(sample))
    assert ORIGINAL_ALGORITHMS[identifier] in names


def test_identifies_md5_like_the_original():
    value = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
    matches = identify_hash(value)
    possible, least = split_results(matches)

    assert _names(possible) == [
        "MD5",
        "Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))",
    ]
    # Shadowed detectors are reachable again.
    least_names = _names(least)
    assert "md5($salt.'-'.md5($pass))" in least_names
    assert "md5($salt.md5($pass).$salt)" in least_names
    # Results are de-duplicated (the original listed 106340/106380 twice).
    all_names = _names(matches)
    assert len(all_names) == len(set(all_names))


@pytest.mark.parametrize(
    "value,expected",
    [
        ("4607", ["CRC-16"]),  # digits only: CCITT/FCS need letters too
        ("3d08", ["CRC-16", "CRC-16-CCITT", "FCS-16"]),
        ("80000000", ["GHash-32-5", "GHash-32-3"]),
        ("85318985", ["GHash-32-5", "GHash-32-3"]),
    ],
)
def test_short_checksums(value, expected):
    assert _names(identify_hash(value)) == expected


@pytest.mark.parametrize("value", ["0" * 32, "a" * 32, "0" * 40, "F" * 64])
def test_pure_digit_or_pure_alpha_hashes_are_rejected(value):
    assert identify_hash(value) == ()


@pytest.mark.parametrize(
    "value,expected_name",
    [
        ("ZiY8YtDKXJwYQ", "DES(Unix)"),
        ("$1$cTuJH0Ju$1J8rI.mJReeMvpKUZbSlY/", "MD5(Unix)"),
        ("$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1", "MD5(phpBB3)"),
        ("$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh.", "MD5(Wordpress)"),
        ("$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1", "MD5(APR)"),
        ("0x49a57f66bd3d5ba6abda5579c264a0e4", "Lineage II C4"),
        (
            "*2470c0c06dee42fd1618bb99005adca2ec9d1e19",
            "MySQL 160bit - SHA-1(SHA-1($pass))",
        ),
        (
            "35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX",
            "md5($pass.$salt) - Joomla",
        ),
        (
            "4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5",
            "SAM - (LM_hash:NT_hash)",
        ),
        ("sha1$Zion3R$299c3d65a0dcab1fc38421783d64d0ecf4113448", "SHA-1(Django)"),
        (
            "sha256$Zion3R$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3",
            "SHA-256(Django)",
        ),
        (
            "sha384$Zion3R$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba",
            "SHA-384(Django)",
        ),
        (
            "$6$g4TpUQzk$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g.",
            "SHA-256",
        ),
    ],
)
def test_structured_hash_formats(value, expected_name):
    assert expected_name in _names(identify_hash(value))


def test_sam_hash_also_matches_joomla_like_the_original():
    # The original Joomla2 detector never required lowercase, so an uppercase
    # LM:NT pair matched both rules.
    sam = "4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5"
    names = _names(identify_hash(sam))
    assert "SAM - (LM_hash:NT_hash)" in names
    assert "md5($pass.$salt) - Joomla" in names


def test_unknown_hash():
    assert identify_hash("not-a-hash") == ()


def test_oracle_fidelity_on_all_original_samples():
    probes = {sample for sample, _ in ORIGINAL_SAMPLES}
    probes.update(["", "a", "0" * 32, "a" * 32, "F" * 64, "é" * 32])
    for value in probes:
        original = {
            TYPO_IDENTIFIERS.get(identifier, identifier)
            for identifier in _emulate_original(value)
        }
        rewritten = {s.identifier for s in identify_hash(value)}
        # Same identifiers, plus the two detectors that used to be shadowed.
        assert rewritten - original <= SHADOWED_IDENTIFIERS, value
        assert original - rewritten == set(), value


# --- Formatting and CLI -----------------------------------------------------


def test_format_not_found():
    assert format_result(()) == "\n Not Found."


def test_format_groups():
    matches = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    text = format_result(matches)
    assert text.startswith("\nPossible Hashs:\n[+] MD5")
    assert "\nLeast Possible Hashs:\n" in text


def test_cli_positional(capsys):
    assert main(["5f4dcc3b5aa765d61d8327deb882cf99"]) == 0
    output = capsys.readouterr().out
    assert "HASH: 5f4dcc3b5aa765d61d8327deb882cf99" in output
    assert "[+] MD5" in output


def test_cli_not_found(capsys):
    main(["definitely-not-a-hash"])
    assert "Not Found." in capsys.readouterr().out


def test_cli_json(capsys):
    main(["--json", "5f4dcc3b5aa765d61d8327deb882cf99"])
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert "MD5" in payload[0]["possible"]
    assert isinstance(payload[0]["least_possible"], list)


def test_cli_reads_piped_stdin(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("5f4dcc3b5aa765d61d8327deb882cf99\n"))
    assert main([]) == 0
    assert "[+] MD5" in capsys.readouterr().out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_json_formatting_roundtrip():
    matches = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    decoded = json.loads(format_json([("sample", matches)]))
    assert decoded[0]["possible"][0] == "MD5"


def test_banner_frame_is_aligned():
    lines = logo().splitlines()
    assert len({len(line) for line in lines}) == 1
    assert f"v{__version__}" in logo()
