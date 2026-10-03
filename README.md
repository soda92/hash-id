# hash-id

Identify the different types of hashes used to hash data and especially passwords.

This is a modernized Python 3 fork of the original [hash-id 1.2][upstream] by
Zion3R (www.Blackploit.com). Detection is data-driven instead of using 125
copy-pasted functions, but the rules — and therefore the results — are
identical, with two long-standing bugs fixed (see [Changes from upstream](#changes-from-upstream)).

[upstream]: https://www.blackploit.com

## Features

- 125 hash/signature recognitions (CRC, MD5 family, SHA family, NTLM, DES
  crypt, Joomla, Django, SAM, `$6$`, …)
- Interactive prompt, positional arguments, `-f/--file`, or piped standard input
- Machine-readable JSON output
- Zero runtime dependencies — standard library only
- Usable as a library: `from hashid import identify_hash`

## Installation

### Arch Linux (pacman / AUR)

Use your favorite AUR helper against the [`hash-id-git`][aur] VCS package, or
manually:

```sh
git clone https://aur.archlinux.org/hash-id-git.git
cd hash-id-git
makepkg -si
```

[aur]: https://aur.archlinux.org/packages/hash-id-git

### From source

```sh
uv tool install .
# or
python -m pip install .
```

## Usage

```sh
# interactive session (the original banner and prompt)
hash-id

# one or more hashes
hash-id 5f4dcc3b5aa765d61d8327deb882cf99
hash-id --json 5f4dcc3b5aa765d61d8327deb882cf99

# read hashes from a file (one hash per line, blank lines ignored); repeat -f
hash-id -f hashes.txt
hash-id -f wordlists/a.txt -f wordlists/b.txt --json

# positional hashes and files combine
hash-id -f hashes.txt 4607

# or pipe a list of hashes on standard input
cat hashes.txt | hash-id
```

```
--------------------------------------------------
 HASH: 5f4dcc3b5aa765d61d8327deb882cf99

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] NTLM
...
```

As a library:

```python
from hashid import identify_hash

for match in identify_hash("5f4dcc3b5aa765d61d8327deb882cf99"):
    print(match.identifier, match.name)
```

## Changes from upstream

- Rewritten as an installable Python package (`pyproject.toml`, console
  script, `python -m hashid`), standard-library only.
- The 125 detector functions became a single declarative signature table;
  the global result list and all duplicated code are gone.
- `argparse`-based CLI with standard input and `--json` support.
- Bug fixes, verified against the original 1.2 script by an oracle test
  (`tests/fixtures/hash_id_original_1_2.py`):
  - two detector functions were defined twice, shadowing identifiers
    `106260` (`md5($salt.'-'.md5($pass))`) and `106360`
    (`md5($salt.md5($pass).$salt)`) — both are reachable again;
  - dictionary key typo `1094202` normalized to `109420`
    (`sha1(md5($pass))`);
  - duplicate result rows are removed.
- Typed public API, test suite (160 tests), ruff configuration.

## Development

```sh
uv run pytest          # run the test suite
uv run ruff check      # lint
uv build --wheel       # build a wheel
```

## License

GNU Affero General Public License v3.0 or later — see [LICENSE](LICENSE).
Original code by Zion3R / Blackploit.com.
