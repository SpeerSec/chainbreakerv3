# Chainbreaker - @Speersec Fork

```
   _____ _           _       ____                 _
  / ____| |         (_)     |  _ \               | |
 | |    | |__   __ _ _ _ __ | |_) |_ __ ___  __ _| | _____ _ __
 | |    | '_ \ / _` | | '_ \|  _ <| '__/ _ \/ _` | |/ / _ \ '__|
 | |____| | | | (_| | | | | | |_) | | |  __/ (_| |   <  __/ |
  \_____|_| |_|\__,_|_|_| |_|____/|_|  \___|\_,_|_|\_\___|_|
                                                  @Speersec fork
```

A Python 3.12+ rewrite of [chainbreaker](https://github.com/Just1uke/chainbreaker) (originally by n0fate, refactored by Luke Gaddie). Extracts credentials, keys, certificates, and crackable password hashes from macOS Keychain files (`.keychain` and `.keychain-db`).

## Updates in this Fork

This is a complete rewrite from Python 2 to modern Python 3.12+. Every file has been rebuilt.

### Removed Files

| File        | Why Removed                                                                                                                                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pbkdf2.py` | Replaced by `hashlib.pbkdf2_hmac()` from the Python standard library. The original was a custom PBKDF2 implementation with Python 2 string maths that broke under Python 3 bytes semantics.                              |
| `pyDes.py`  | Replaced by `cryptography` library's TripleDES implementation. The original was a pure-Python DES/3DES engine with Python 2 `chr()`/`ord()` throughout. Slow, fragile, and unnecessary when `cryptography` is available. |

### Key Changes

**Bytes/String Separation** -- The single biggest class of bug. Python 2 let you freely mix `str` and `bytes`. Python 3 does not. Every buffer operation, struct unpack, slice comparison, and crypto call has been audited:
- `kc_buffer` is now `bytes` (was `str`)
- `KEYCHAIN_SIGNATURE` is `b'kych'` (was `"kych"`)
- `SECURE_STORAGE_GROUP` is `b'ssgp'` (was `'ssgp'`)
- `PROTOCOL_TYPE` and `AUTH_TYPE` dict keys are `bytes` (struct.unpack `>4s` returns `bytes` in Python 3)
- `_KEYCHAIN_TIME`, `_LV`, `_FOUR_CHAR_CODE` all decode from bytes to str explicitly
- `hexlify()` and `base64.b64encode()` results are `.decode('ascii')` where needed for string output

**Removed Python 2 Constructs:**
- `xrange()` replaced with `range()`
- `except OSError, e:` replaced with `except OSError as e:`
- `__len__()` calls replaced with `len()`
- Integer division `/` replaced with `//` where needed (e.g. `_get_lv` alignment calculation)
- `hmac.new()` with string args replaced by `hashlib.pbkdf2_hmac()`
- String concatenation loops for byte reversal replaced with slice `[::-1]`

**Cryptography:**
- 3DES-CBC via `cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES` (with fallback to the old import path for `cryptography` < 43.0)
- PBKDF2-HMAC-SHA1 via `hashlib.pbkdf2_hmac()` (stdlib, no external dependency needed)

**Bug Fixes:**
- `hashlib.md5(args.keychain)` was hashing the *filename string*, not the file contents. Now reads and hashes the actual file data.
- Dead `return record` after an earlier `return` in `_get_generic_password_record` removed.
- `_get_lv` integer division was producing `float` in Python 3 -- now uses `//`.
- `_kcdecrypt` padding validation used `ord()` on bytes elements (Python 3 bytes indexing already returns `int`).
- Malformed/truncated keychain files now produce clear error messages instead of unhandled `struct.error` crashes.

**Hardening:**
- `_read_keychain_to_buffer` catches `struct.error`, `KeyError`, and `IndexError` for corrupt files.
- `_is_valid_keychain` handles empty buffers.
- `dump_keychain_password_hash` returns `None` if the DB blob was never parsed.
- CLI output loop filters `None` records.
- `write_to_disk` handles both `bytes` and `str` export content.

## Requirements

- Python 3.12+
- `cryptography` (pip install cryptography)

That is the only external dependency. Everything else is stdlib.

## Supported macOS Versions

Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra, Mojave, Catalina. Maybe Sequoia and Tahoe? 

## Extractable Data

- Keychain password hash (hashcat mode 23100 / John the Ripper `$keychain$` format)
- Generic passwords (application passwords, secure notes)
- Internet passwords (Safari, mail, etc.)
- AppleShare passwords (legacy)
- Private keys
- Public keys
- X509 certificates

## Usage

```bash
# Dump everything with a known password
python3 chainbreaker.py --password=KeychainPassword -a /path/to/login.keychain

# Just extract the crackable hash (no password needed)
python3 chainbreaker.py --dump-keychain-password-hash /path/to/login.keychain

# Unlock with a master key from memory (volafox/volatility)
python3 chainbreaker.py --key 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9 -a /path/to/login.keychain

# Unlock with SystemKey file (for System.keychain)
python3 chainbreaker.py --unlock-file /var/db/SystemKey -a /Library/Keychains/System.keychain

# Export everything to a directory
python3 chainbreaker.py --password=KeychainPassword -e -o ./output /path/to/login.keychain

# Prompt for password securely (no shell history)
python3 chainbreaker.py -p -a /path/to/login.keychain
```

### Common Keychain Locations

| Keychain   | Path                                                                        |
| ---------- | --------------------------------------------------------------------------- |
| User login | `/Users/<username>/Library/Keychains/login.keychain` or `login.keychain-db` |
| System     | `/Library/Keychains/System.keychain` (unlock file: `/var/db/SystemKey`)     |
|            |                                                                             |

### Cracking the Hash

```bash
# Extract
python3 chainbreaker.py --dump-keychain-password-hash ./login.keychain

# Crack with hashcat (mode 23100)
hashcat -m 23100 --keep-guessing hashes.txt wordlist.txt
```

Note: hash collisions are common with keychain hashes. Use `--keep-guessing` and validate each candidate against the keychain with `--check-unlock-options`.

## File Structure

```
chainbreaker/
  chainbreaker.py   # Main tool (CLI + Chainbreaker class)
  schema.py         # Binary format structs and constant definitions
  LICENSE           # GPL-3.0
  README.md         # This file
```

## License

GNU GPL v3 -- see LICENSE file.
