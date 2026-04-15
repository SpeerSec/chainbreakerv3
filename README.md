# ChainBreaker v3 - @SpeerSec

```
   _____ _           _       ____                 _
  / ____| |         (_)     |  _ \               | |
 | |    | |__   __ _ _ _ __ | |_) |_ __ ___  __ _| | _____ _ __
 | |    | '_ \ / _` | | '_ \|  _ <| '__/ _ \/ _` | |/ / _ \ '__|
 | |____| | | | (_| | | | | | |_) | | |  __/ (_| |   <  __/ |
  \_____|_| |_|\__,_|_|_| |_|____/|_|  \___|\_,_|_|\_\___|_|
                                                  v3 - @SpeerSec
```


## Repository Structure

```
chainbreakerv3/
|
|-- legacy/                    # Offline keychain file parsing
|   |-- chainbreaker.py        # Main parser (legacy .keychain format)
|   |-- schema.py              # Binary format structs and constants
|
|-- live/                      # Live system extraction tools
|   |-- kc_recon.py            # Recon and hash extraction (run first)
|   |-- kc_dump.py             # Credential dumper (dual-API)
|
|-- LICENSE                    # GPL-2.0
|-- requirements.txt           # Python dependencies
|-- README.md                  # This file
```

## Coverage Matrix

| Tool | Target | Needs Password | Needs Root | Needs GUI Session | macOS Versions |
|------|--------|:-:|:-:|:-:|---|
| `chainbreaker.py` | Legacy `.keychain` files (offline) | Yes (or master key) | No | No | Snow Leopard - Mojave (reliable), Catalina - Monterey (upgraded machines) |
| `kc_recon.py` | All keychain files (recon + hash extraction) | No | Yes (recommended) | No | All versions |
| `kc_dump.py --system` | System keychain (live) | No | Yes | No | Catalina - Sonoma |
| `kc_dump.py --password` | Login keychain (live, legacy API) | Yes | No | Yes | Catalina - Sonoma |
| `kc_dump.py --modern-only` | Data Protection keychain (live, SecItem API) | No | No | Yes | Catalina - Sonoma (diminishing on Sequoia+) |

## Quick Start

### Step 1: Recon (always run first)

```bash
# As root on the target. No password needed. Tells you what you're dealing with.
sudo python3 live/kc_recon.py
```

This enumerates all keychain files, identifies their format (legacy binary vs SQLite), extracts crackable hashes from legacy keychains, pulls cleartext metadata from SQLite keychains, and attempts SystemKey extraction. The output tells you which tools will work against this target.

### Step 2a: System Keychain (as root, no password)

```bash
# The System keychain is unlocked at boot by the OS.
# Contains WiFi PSKs, VPN creds, certificates, 802.1X identities.
sudo python3 live/kc_dump.py --system
```

### Step 2b: Login Keychain (needs user password)

```bash
# If you have the user's login password (keylogged, cracked, reused)
python3 live/kc_dump.py --password TheUserPassword

# Or prompt interactively
python3 live/kc_dump.py --prompt

# Non-interactive JSON output for C2 exfil
python3 live/kc_dump.py --password TheUserPassword --quiet
```

### Step 2c: Modern Keychain (no password, session-authenticated)

```bash
# If the user is logged in, the Data Protection keychain may already
# be unlocked. Try this first before attempting password-based unlock.
python3 live/kc_dump.py --modern-only
```

### Step 3: Offline Cracking (if no live access)

```bash
# Extract hash from a legacy keychain file (no password needed)
python3 legacy/chainbreaker.py --dump-keychain-password-hash /path/to/login.keychain

# Crack with hashcat (mode 23100, collisions are common, use --keep-guessing)
hashcat -m 23100 --keep-guessing hashes.txt wordlist.txt

# Once cracked, dump everything
python3 legacy/chainbreaker.py --password CrackedPassword -a /path/to/login.keychain

# Or use a memory-extracted master key (from volatility/volafox)
python3 legacy/chainbreaker.py --key 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9 -a /path/to/login.keychain
```

## Tool Details

### `live/kc_recon.py` - Reconnaissance and Hash Extraction

- Enumerates all `.keychain` and `.keychain-db` files on the system
- Identifies format (legacy binary vs SQLite) by reading file headers
- Extracts hashcat-compatible hashes (mode 23100) from legacy keychains
- Extracts unencrypted metadata (account names, services, servers) from SQLite keychains
- Attempts `/var/db/SystemKey` extraction with format identification
- Checks SIP status, logged-in users, and `securityd` process state
- Outputs full JSON to `/tmp/.kc_recon.json`

### `live/kc_dump.py` - Live Credential Extraction

Dual-API keychain dumper using Security.framework via ctypes. Covers both the legacy file-based keychain and the modern Data Protection keychain (SQLite-backed, SEP-encrypted).

**Legacy API** (`SecKeychainOpen` / `SecKeychainUnlock` / `SecKeychainItemCopyContent`):
- Targets `.keychain` and `.keychain-db` files directly
- Handles 3DES-CBC (legacy) and AES-GCM (modern) transparently via Apple's framework
- Requires user password for login keychain
- System keychain accessed without password (OS keeps it unlocked)

**Modern API** (`SecItemCopyMatching`):
- Targets the Data Protection keychain (where Safari passwords, WiFi PSKs, and app tokens live)
- Handles SEP-wrapped class keys transparently via `securityd`
- May work without password if the user session is already authenticated

**Key flags:**
- `--system` - Target System keychain as root (no password needed)
- `--password` - Provide user password for login keychain
- `--modern-only` - Skip legacy API, use SecItemCopyMatching only
- `--quiet` - JSON-only output for C2 piping
- `--output` - Write JSON to file

**Tahoe 26.x caveat:** The script must be the direct process in a GUI session, not a subprocess of bash. SecurityAgent session attachment is not inherited by child processes on Tahoe.

### `legacy/chainbreaker.py` - Offline Keychain Parser

Complete Python 3.12+ rewrite of the original chainbreaker tool. Parses legacy binary `.keychain` files offline without needing macOS or the Security framework.

- Extracts: generic passwords, internet passwords, AppleShare passwords, private keys, public keys, X509 certificates, crackable password hashes
- Unlock methods: password, hex master key, SystemKey file
- Removed: `pyDes.py` (replaced by `cryptography` TripleDES), `pbkdf2.py` (replaced by `hashlib.pbkdf2_hmac`)

This is the script for forensic disk image analysis and offline work. It does not require macOS to run.

## Common Keychain Locations

| Keychain | Path | Unlock Method |
|----------|------|---------------|
| User login | `~/Library/Keychains/login.keychain` or `login.keychain-db` | User's login password |
| System | `/Library/Keychains/System.keychain` | `/var/db/SystemKey` (or auto-unlocked at boot) |
| Local Items | `~/Library/Keychains/<UUID>/` | Derived from user password + SEP |

## Requirements

- Python 3.12+
- `cryptography` >= 43.0 (for `legacy/chainbreaker.py` only)
- Live tools (`live/`) use only stdlib + macOS frameworks (no pip dependencies)

```bash
pip install -r requirements.txt
```

## Credits

- Original [chainbreaker](https://github.com/n0fate/chainbreaker) by [n0fate](https://twitter.com/n0fate)
- v2 refactor by [Luke Gaddie](https://github.com/Just1uke/chainbreaker)
