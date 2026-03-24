#!/usr/bin/env python3
#
# Chainbreaker - macOS Keychain Forensic Tool
# @Speersec fork - Python 3.12+ rewrite
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#

import struct
import hashlib
import logging
import base64
import string
import uuid
import os
import sys

from binascii import unhexlify, hexlify

from cryptography.hazmat.primitives.ciphers import Cipher, modes

# cryptography >= 43.0 moved TripleDES into the 'decrepit' namespace
# because 3DES is considered legacy. We need it for keychain decryption
# so import from the new location first, falling back to the old one.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from schema import (
    CSSM_DL_DB_RECORD_GENERIC_PASSWORD,
    CSSM_DL_DB_RECORD_INTERNET_PASSWORD,
    CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD,
    CSSM_DL_DB_RECORD_X509_CERTIFICATE,
    CSSM_DL_DB_RECORD_PUBLIC_KEY,
    CSSM_DL_DB_RECORD_PRIVATE_KEY,
    CSSM_DL_DB_RECORD_SYMMETRIC_KEY,
    CSSM_DL_DB_RECORD_METADATA,
    CSSM_ALGORITHMS,
    KEY_TYPE,
    STD_APPLE_ADDIN_MODULE,
    SECURE_STORAGE_GROUP,
    PROTOCOL_TYPE,
    AUTH_TYPE,
    _APPL_DB_HEADER,
    _APPL_DB_SCHEMA,
    _TABLE_HEADER,
    _DB_BLOB,
    _GENERIC_PW_HEADER,
    _KEY_BLOB_REC_HEADER,
    _KEY_BLOB,
    _SSGP,
    _INTERNET_PW_HEADER,
    _APPLE_SHARE_HEADER,
    _X509_CERT_HEADER,
    _SECKEY_HEADER,
    _UNLOCK_BLOB,
    _KEYCHAIN_TIME,
    _INT,
    _FOUR_CHAR_CODE,
    _LV,
    _TABLE_ID,
    _RECORD_OFFSET,
)

BANNER = """
   _____ _           _       ____                 _
  / ____| |         (_)     |  _ \\               | |
 | |    | |__   __ _ _ _ __ | |_) |_ __ ___  __ _| | _____ _ __
 | |    | '_ \\ / _` | | '_ \\|  _ <| '__/ _ \\/ _` | |/ / _ \\ '__|
 | |____| | | | (_| | | | | | |_) | | |  __/ (_| |   <  __/ |
  \\_____|_| |_|\\__,_|_|_| |_|____/|_|  \\___|\\__,_|_|\\_\\___|_|
                                                  @Speersec fork
"""


class Chainbreaker:
    ATOM_SIZE = 4
    KEYCHAIN_SIGNATURE = b'kych'
    BLOCKSIZE = 8
    KEYLEN = 24
    MAGIC_CMS_IV = unhexlify('4adda22c79e82105')
    KEYCHAIN_LOCKED_SIGNATURE = '[Invalid Password / Keychain Locked]'

    def __init__(
        self,
        filepath: str,
        unlock_password: str | None = None,
        unlock_key: str | None = None,
        unlock_file: str | None = None,
    ):
        self._filepath: str | None = None
        self._unlock_password: str | None = None
        self._unlock_key: str | None = None
        self._unlock_file: str | None = None
        self._db_key: bytes | None = None

        # Raw buffer of keychain file contents (bytes)
        self.kc_buffer: bytes = b''

        self.header = None
        self.schema_info = None
        self.table_list: list | None = None
        self.table_metadata = None
        self.record_list: list | None = None
        self.table_count: int | None = None
        self.table_enum: dict | None = None
        self.symmetric_key_list = None
        self.symmetric_key_offset = None
        self.base_addr: int = 0
        self.dbblob = None
        self.locked: bool = True

        self.logger = logging.getLogger('Chainbreaker')
        self.key_list: dict[bytes, bytes] = {}
        self.db_key = None

        self.filepath = filepath

        if not self._is_valid_keychain():
            self.logger.warning(
                'Keychain signature does not match. Are you sure this is a valid keychain file?'
            )
            return

        if self.dbblob is None:
            self.logger.warning(
                'Failed to parse keychain structure. Cannot proceed with unlock.'
            )
            return

        self.unlock_password = unlock_password
        self.unlock_key = unlock_key
        self.unlock_file = unlock_file

    # ──────────────────────────────────────────────────────────────────
    # Public dump methods - each returns a list of record objects
    # ──────────────────────────────────────────────────────────────────

    def dump_generic_passwords(self) -> list:
        entries = []
        try:
            _meta, generic_pw_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_GENERIC_PASSWORD
            )
            for record_id in generic_pw_list:
                entries.append(self._get_generic_password_record(record_id))
        except KeyError:
            self.logger.warning('[!] Generic Password Table is not available')
        return entries

    def dump_internet_passwords(self) -> list:
        entries = []
        try:
            _meta, internet_pw_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_INTERNET_PASSWORD
            )
            for record_id in internet_pw_list:
                entries.append(self._get_internet_password_record(record_id))
        except KeyError:
            self.logger.warning('[!] Internet Password Table is not available')
        return entries

    def dump_appleshare_passwords(self) -> list:
        entries = []
        try:
            _meta, appleshare_pw_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD
            )
            for offset in appleshare_pw_list:
                entries.append(self._get_appleshare_record(offset))
        except KeyError:
            self.logger.warning('[!] Appleshare Records Table is not available')
        return entries

    def dump_x509_certificates(self) -> list:
        entries = []
        try:
            _meta, x509_cert_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_X509_CERTIFICATE
            )
            for offset in x509_cert_list:
                entries.append(self._get_x_509_record(offset))
        except KeyError:
            self.logger.warning('[!] Certificate Table is not available')
        return entries

    def dump_public_keys(self) -> list:
        entries = []
        try:
            _meta, public_key_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_PUBLIC_KEY
            )
            for offset in public_key_list:
                entries.append(self._get_public_key_record(offset))
        except KeyError:
            self.logger.warning('[!] Public Key Table is not available')
        return entries

    def dump_private_keys(self) -> list:
        entries = []
        try:
            _meta, private_key_list = self._get_table_from_type(
                CSSM_DL_DB_RECORD_PRIVATE_KEY
            )
            for offset in private_key_list:
                entries.append(self._get_private_key_record(offset))
        except KeyError:
            self.logger.warning('[!] Private Key Table is not available')
        return entries

    def dump_keychain_password_hash(self):
        """Extract the ciphertext, IV, and salt for offline cracking (hashcat mode 23100)."""
        if self.dbblob is None:
            self.logger.warning('[!] Cannot extract password hash: keychain not parsed.')
            return None

        cyphertext = hexlify(
            self.kc_buffer[
                self.base_addr + self.dbblob.StartCryptoBlob
                : self.base_addr + self.dbblob.TotalLength
            ]
        ).decode('ascii')

        iv = hexlify(self.dbblob.IV).decode('ascii')
        salt = hexlify(self.dbblob.Salt).decode('ascii')

        return self.KeychainPasswordHash(salt, iv, cyphertext)

    # ──────────────────────────────────────────────────────────────────
    # Internal: file reading and validation
    # ──────────────────────────────────────────────────────────────────

    def _read_keychain_to_buffer(self) -> None:
        try:
            with open(self.filepath, 'rb') as fp:
                self.kc_buffer = fp.read()

            if self.kc_buffer:
                self.header = _APPL_DB_HEADER(
                    self.kc_buffer[: _APPL_DB_HEADER.STRUCT.size]
                )
                self.schema_info, self.table_list = self._get_schema_info(
                    self.header.SchemaOffset
                )
                self.table_metadata, self.record_list = self._get_table(
                    self.table_list[0]
                )
                self.table_count, self.table_enum = self._get_table_name_to_list(
                    self.record_list, self.table_list
                )
                self.symmetric_key_offset = self.table_list[
                    self.table_enum[CSSM_DL_DB_RECORD_METADATA]
                ]
                self.base_addr = (
                    _APPL_DB_HEADER.STRUCT.size + self.symmetric_key_offset + 0x38
                )
                self.dbblob = _DB_BLOB(
                    self.kc_buffer[self.base_addr : self.base_addr + _DB_BLOB.STRUCT.size]
                )
        except OSError as e:
            self.logger.critical("Unable to read keychain: %s", e)
        except (struct.error, KeyError, IndexError) as e:
            self.logger.critical(
                "Keychain file appears malformed or truncated: %s", e
            )

    def _is_valid_keychain(self) -> bool:
        if len(self.kc_buffer) < 4:
            return False
        return self.kc_buffer[0:4] == Chainbreaker.KEYCHAIN_SIGNATURE

    # ──────────────────────────────────────────────────────────────────
    # Internal: key list generation after successful unlock
    # ──────────────────────────────────────────────────────────────────

    def _generate_key_list(self) -> int:
        _meta, symmetric_key_list = self._get_table_from_type(
            CSSM_DL_DB_RECORD_SYMMETRIC_KEY
        )
        for symmetric_key_record in symmetric_key_list:
            keyblob, ciphertext, iv, return_value = self._get_keyblob_record(
                symmetric_key_record
            )
            if return_value == 0:
                password = Chainbreaker.keyblob_decryption(ciphertext, iv, self.db_key)
                if password != b'':
                    self.key_list[keyblob] = password
        return len(self.key_list)

    # ──────────────────────────────────────────────────────────────────
    # Internal: schema / table parsing
    # ──────────────────────────────────────────────────────────────────

    def _get_schema_info(self, offset: int):
        table_list = []
        schema_info = _APPL_DB_SCHEMA(
            self.kc_buffer[offset : offset + _APPL_DB_SCHEMA.STRUCT.size]
        )
        for i in range(schema_info.TableCount):
            base_addr = _APPL_DB_HEADER.STRUCT.size + _APPL_DB_SCHEMA.STRUCT.size
            start = base_addr + (Chainbreaker.ATOM_SIZE * i)
            end = start + Chainbreaker.ATOM_SIZE
            table_list.append(_TABLE_ID(self.kc_buffer[start:end]).Value)
        return schema_info, table_list

    def _get_table_offset(self, table_name):
        return self.table_list[self.table_enum[table_name]]

    def _get_table_from_type(self, table_type):
        return self._get_table(self._get_table_offset(table_type))

    def _get_table(self, offset: int):
        record_list = []
        base_addr = _APPL_DB_HEADER.STRUCT.size + offset
        table_metadata = _TABLE_HEADER(
            self.kc_buffer[base_addr : base_addr + _TABLE_HEADER.STRUCT.size]
        )
        record_offset_base = base_addr + _TABLE_HEADER.STRUCT.size

        record_count = 0
        idx = 0
        while table_metadata.RecordCount != record_count:
            start = record_offset_base + (Chainbreaker.ATOM_SIZE * idx)
            end = start + Chainbreaker.ATOM_SIZE
            record_offset = _RECORD_OFFSET(self.kc_buffer[start:end]).Value

            if (record_offset != 0x00) and (record_offset % 4 == 0):
                record_list.append(record_offset)
                record_count += 1
            idx += 1

        return table_metadata, record_list

    def _get_table_name_to_list(self, record_list, table_list):
        table_dict = {}
        for count in range(len(record_list)):
            table_metadata, _generic_list = self._get_table(table_list[count])
            table_dict[table_metadata.TableId] = count
        return len(record_list), table_dict

    # ──────────────────────────────────────────────────────────────────
    # Internal: keyblob record parsing
    # ──────────────────────────────────────────────────────────────────

    def _get_keyblob_record(self, record_offset: int):
        base_addr = self._get_base_address(
            CSSM_DL_DB_RECORD_SYMMETRIC_KEY, record_offset
        )
        key_blob_record_header = _KEY_BLOB_REC_HEADER(
            self.kc_buffer[base_addr : base_addr + _KEY_BLOB_REC_HEADER.STRUCT.size]
        )
        record = self.kc_buffer[
            base_addr + _KEY_BLOB_REC_HEADER.STRUCT.size
            : base_addr + key_blob_record_header.RecordSize
        ]
        key_blob_record = _KEY_BLOB(record[: _KEY_BLOB.STRUCT.size])

        ssg_marker = record[
            key_blob_record.TotalLength + 8 : key_blob_record.TotalLength + 8 + 4
        ]
        if SECURE_STORAGE_GROUP != ssg_marker:
            return b'', b'', b'', 1

        cipher_len = key_blob_record.TotalLength - key_blob_record.StartCryptoBlob
        if cipher_len % Chainbreaker.BLOCKSIZE != 0:
            self.logger.debug("Bad ciphertext length.")
            return b'', b'', b'', 1

        cipher_text = record[
            key_blob_record.StartCryptoBlob : key_blob_record.TotalLength
        ]

        match_data = record[
            key_blob_record.TotalLength + 8 : key_blob_record.TotalLength + 8 + 20
        ]
        return match_data, cipher_text, key_blob_record.IV, 0

    # ──────────────────────────────────────────────────────────────────
    # Internal: field extraction helpers
    # ──────────────────────────────────────────────────────────────────

    def _get_keychain_time(self, base_addr: int, pcol: int):
        if pcol <= 0:
            return ''
        return _KEYCHAIN_TIME(
            self.kc_buffer[base_addr + pcol : base_addr + pcol + _KEYCHAIN_TIME.STRUCT.size]
        ).Time

    def _get_int(self, base_addr: int, pcol: int) -> int:
        if pcol <= 0:
            return 0
        return _INT(self.kc_buffer[base_addr + pcol : base_addr + pcol + 4]).Value

    def _get_four_char_code(self, base_addr: int, pcol: int) -> bytes:
        """Returns raw bytes (4-char code) for use as dict lookup key."""
        if pcol <= 0:
            return b''
        return _FOUR_CHAR_CODE(
            self.kc_buffer[base_addr + pcol : base_addr + pcol + 4]
        ).Value

    def _get_lv(self, base_addr: int, pcol: int) -> str:
        """Returns a decoded string from a length-value structure."""
        if pcol <= 0:
            return ''

        str_length = _INT(
            self.kc_buffer[base_addr + pcol : base_addr + pcol + 4]
        ).Value

        # 4-byte alignment
        if (str_length % 4) == 0:
            real_str_len = str_length
        else:
            real_str_len = ((str_length // 4) + 1) * 4

        try:
            data = _LV(
                self.kc_buffer[
                    base_addr + pcol + 4 : base_addr + pcol + 4 + real_str_len
                ],
                real_str_len,
            ).Value
        except struct.error:
            self.logger.debug('LV string length is too long.')
            return ''
        return data

    # ──────────────────────────────────────────────────────────────────
    # Internal: cryptographic operations
    # ──────────────────────────────────────────────────────────────────

    def _private_key_decryption(self, encryptedblob: bytes, iv: bytes):
        plain = Chainbreaker._kcdecrypt(
            self.db_key, Chainbreaker.MAGIC_CMS_IV, encryptedblob
        )
        if len(plain) == 0:
            return b'', b''

        # Unwrap: reverse the plaintext bytes
        revplain = plain[::-1]

        # Decrypt the reversed blob with the record IV
        plain = Chainbreaker._kcdecrypt(self.db_key, iv, revplain)

        keyname = plain[:12]
        keyblob = plain[12:]
        return keyname, keyblob

    def _generate_master_key(self, pw: str) -> bytes:
        """Derive master key from password using PBKDF2-HMAC-SHA1."""
        password_bytes = pw.encode('utf-8') if isinstance(pw, str) else pw
        salt = bytes(self.dbblob.Salt)
        return hashlib.pbkdf2_hmac(
            'sha1', password_bytes, salt, 1000, dklen=Chainbreaker.KEYLEN
        )

    def _find_wrapping_key(self, master: bytes) -> bytes:
        """Decrypt the DB blob to extract the wrapping key."""
        ciphertext = self.kc_buffer[
            self.base_addr + self.dbblob.StartCryptoBlob
            : self.base_addr + self.dbblob.TotalLength
        ]
        plain = Chainbreaker._kcdecrypt(master, self.dbblob.IV, ciphertext)

        if len(plain) < Chainbreaker.KEYLEN:
            return b''

        return plain[: Chainbreaker.KEYLEN]

    @staticmethod
    def _kcdecrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """3DES-CBC decryption with manual PKCS5 padding removal."""
        logger = logging.getLogger('Chainbreaker')

        if len(data) == 0:
            logger.debug("Encrypted data is 0.")
            return b''

        if len(data) % Chainbreaker.BLOCKSIZE != 0:
            return b''

        cipher = Cipher(TripleDES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plain = decryptor.update(data) + decryptor.finalize()

        # Validate and strip PKCS5 padding
        pad = plain[-1]
        if pad > 8:
            logger.debug("Bad padding byte. Keychain password might be incorrect.")
            return b''

        for byte_val in plain[-pad:]:
            if byte_val != pad:
                logger.debug("Bad padding byte. Keychain password might be incorrect.")
                return b''

        return plain[:-pad]

    @staticmethod
    def _get_encrypted_data_in_blob(blob_buffer: bytes):
        key_blob = _KEY_BLOB(blob_buffer[: _KEY_BLOB.STRUCT.size])

        if key_blob.CommonBlob.Magic != _KEY_BLOB.COMMON_BLOB_MAGIC:
            return b'', b''

        key_data = blob_buffer[key_blob.StartCryptoBlob : key_blob.TotalLength]
        return key_blob.IV, key_data

    @staticmethod
    def keyblob_decryption(encryptedblob: bytes, iv: bytes, dbkey: bytes) -> bytes:
        logger = logging.getLogger('Chainbreaker')

        plain = Chainbreaker._kcdecrypt(
            dbkey, Chainbreaker.MAGIC_CMS_IV, encryptedblob
        )
        if len(plain) == 0:
            return b''

        # Unwrap: reverse the first 32 bytes
        revplain = plain[:32][::-1]

        plain = Chainbreaker._kcdecrypt(dbkey, iv, revplain)
        keyblob = plain[4:]

        if len(keyblob) != Chainbreaker.KEYLEN:
            logger.debug("Decrypted key length is not valid")
            return b''

        return keyblob

    # ──────────────────────────────────────────────────────────────────
    # Internal: record extraction
    # ──────────────────────────────────────────────────────────────────

    def _get_appleshare_record(self, record_offset: int):
        base_addr = self._get_base_address(
            CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD, record_offset
        )
        record_meta = _APPLE_SHARE_HEADER(
            self.kc_buffer[base_addr : base_addr + _APPLE_SHARE_HEADER.STRUCT.size]
        )
        buffer = self.kc_buffer[
            base_addr + _APPLE_SHARE_HEADER.STRUCT.size : base_addr + record_meta.RecordSize
        ]
        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.AppleshareRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            comment=self._get_lv(base_addr, record_meta.Comment & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            protected=self._get_lv(base_addr, record_meta.Protected & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            volume=self._get_lv(base_addr, record_meta.Volume & 0xFFFFFFFE),
            server=self._get_lv(base_addr, record_meta.Server & 0xFFFFFFFE),
            protocol_type=self._get_four_char_code(base_addr, record_meta.Protocol & 0xFFFFFFFE),
            address=self._get_lv(base_addr, record_meta.Address & 0xFFFFFFFE),
            signature=self._get_lv(base_addr, record_meta.Signature & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey,
        )

    def _get_private_key_record(self, record_offset: int):
        record = self._get_key_record(
            self._get_table_offset(CSSM_DL_DB_RECORD_PRIVATE_KEY), record_offset
        )
        if not self.db_key:
            keyname = privatekey = Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE
        else:
            keyname, privatekey = self._private_key_decryption(record[10], record[9])

        return self.PrivateKeyRecord(
            print_name=record[0],
            label=record[1],
            key_class=KEY_TYPE[record[2]],
            private=record[3],
            key_type=record[4],
            key_size=record[5],
            effective_key_size=record[6],
            extracted=record[7],
            cssm_type=record[8],
            iv=record[9],
            key=record[10],
            key_name=keyname,
            private_key=privatekey,
        )

    def _get_public_key_record(self, record_offset: int):
        record = self._get_key_record(
            self._get_table_offset(CSSM_DL_DB_RECORD_PUBLIC_KEY), record_offset
        )
        return self.PublicKeyRecord(
            print_name=record[0],
            label=record[1],
            key_class=KEY_TYPE[record[2]],
            private=record[3],
            key_type=record[4],
            key_size=record[5],
            effective_key_size=record[6],
            extracted=record[7],
            cssm_type=record[8],
            iv=record[9],
            public_key=record[10],
        )

    def _get_key_record(self, table_name, record_offset: int) -> list:
        base_addr = self._get_base_address(table_name, record_offset)
        record_meta = _SECKEY_HEADER(
            self.kc_buffer[base_addr : base_addr + _SECKEY_HEADER.STRUCT.size]
        )
        key_blob = self.kc_buffer[
            base_addr + _SECKEY_HEADER.STRUCT.size
            : base_addr + _SECKEY_HEADER.STRUCT.size + record_meta.BlobSize
        ]
        iv, key = Chainbreaker._get_encrypted_data_in_blob(key_blob)

        # Resolve the KeyCreator GUID to a human-readable name
        key_creator_raw = self._get_lv(base_addr, record_meta.KeyCreator & 0xFFFFFFFE)
        key_creator_guid = key_creator_raw.split('\x00')[0]
        cssm_type = STD_APPLE_ADDIN_MODULE.get(key_creator_guid, key_creator_guid)

        return [
            self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            self._get_lv(base_addr, record_meta.Label & 0xFFFFFFFE),
            self._get_int(base_addr, record_meta.KeyClass & 0xFFFFFFFE),
            self._get_int(base_addr, record_meta.Private & 0xFFFFFFFE),
            CSSM_ALGORITHMS.get(
                self._get_int(base_addr, record_meta.KeyType & 0xFFFFFFFE), 'UNKNOWN'
            ),
            self._get_int(base_addr, record_meta.KeySizeInBits & 0xFFFFFFFE),
            self._get_int(base_addr, record_meta.EffectiveKeySize & 0xFFFFFFFE),
            self._get_int(base_addr, record_meta.Extractable & 0xFFFFFFFE),
            cssm_type,
            iv,
            key,
        ]

    def _get_x_509_record(self, record_offset: int):
        base_addr = self._get_base_address(
            CSSM_DL_DB_RECORD_X509_CERTIFICATE, record_offset
        )
        record_meta = _X509_CERT_HEADER(
            self.kc_buffer[base_addr : base_addr + _X509_CERT_HEADER.STRUCT.size]
        )
        return self.X509CertificateRecord(
            type=self._get_int(base_addr, record_meta.CertType & 0xFFFFFFFE),
            encoding=self._get_int(base_addr, record_meta.CertEncoding & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            subject=self._get_lv(base_addr, record_meta.Subject & 0xFFFFFFFE),
            issuer=self._get_lv(base_addr, record_meta.Issuer & 0xFFFFFFFE),
            serial_number=self._get_lv(base_addr, record_meta.SerialNumber & 0xFFFFFFFE),
            subject_key_identifier=self._get_lv(
                base_addr, record_meta.SubjectKeyIdentifier & 0xFFFFFFFE
            ),
            public_key_hash=self._get_lv(
                base_addr, record_meta.PublicKeyHash & 0xFFFFFFFE
            ),
            certificate=self.kc_buffer[
                base_addr + _X509_CERT_HEADER.STRUCT.size
                : base_addr + _X509_CERT_HEADER.STRUCT.size + record_meta.CertSize
            ],
        )

    def _extract_ssgp_and_dbkey(self, record_meta, buffer: bytes):
        ssgp = None
        dbkey = None
        if record_meta.SSGPArea != 0:
            ssgp = _SSGP(buffer[: record_meta.SSGPArea])
            dbkey_index = ssgp.Magic + ssgp.Label
            if dbkey_index in self.key_list:
                dbkey = self.key_list[dbkey_index]
        return ssgp, dbkey

    def _get_internet_password_record(self, record_offset: int):
        base_addr = self._get_base_address(
            CSSM_DL_DB_RECORD_INTERNET_PASSWORD, record_offset
        )
        record_meta = _INTERNET_PW_HEADER(
            self.kc_buffer[base_addr : base_addr + _INTERNET_PW_HEADER.STRUCT.size]
        )
        buffer = self.kc_buffer[
            base_addr + _INTERNET_PW_HEADER.STRUCT.size : base_addr + record_meta.RecordSize
        ]
        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.InternetPasswordRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            comment=self._get_lv(base_addr, record_meta.Comment & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            protected=self._get_lv(base_addr, record_meta.Protected & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            security_domain=self._get_lv(base_addr, record_meta.SecurityDomain & 0xFFFFFFFE),
            server=self._get_lv(base_addr, record_meta.Server & 0xFFFFFFFE),
            protocol_type=self._get_four_char_code(base_addr, record_meta.Protocol & 0xFFFFFFFE),
            auth_type=self._get_four_char_code(base_addr, record_meta.AuthType & 0xFFFFFFFE),
            port=self._get_int(base_addr, record_meta.Port & 0xFFFFFFFE),
            path=self._get_lv(base_addr, record_meta.Path & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey,
        )

    def _get_generic_password_record(self, record_offset: int):
        base_addr = self._get_base_address(
            CSSM_DL_DB_RECORD_GENERIC_PASSWORD, record_offset
        )
        record_meta = _GENERIC_PW_HEADER(
            self.kc_buffer[base_addr : base_addr + _GENERIC_PW_HEADER.STRUCT.size]
        )
        buffer = self.kc_buffer[
            base_addr + _GENERIC_PW_HEADER.STRUCT.size : base_addr + record_meta.RecordSize
        ]
        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.GenericPasswordRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            service=self._get_lv(base_addr, record_meta.Service & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey,
        )

    def _get_base_address(self, table_name, offset: int | None = None) -> int:
        base_address = _APPL_DB_HEADER.STRUCT.size + self._get_table_offset(table_name)
        if offset:
            base_address += offset
        return base_address

    # ──────────────────────────────────────────────────────────────────
    # Properties with unlock logic
    # ──────────────────────────────────────────────────────────────────

    @property
    def filepath(self) -> str | None:
        return self._filepath

    @filepath.setter
    def filepath(self, value: str | None) -> None:
        self._filepath = value
        if self._filepath:
            self._read_keychain_to_buffer()

    @property
    def unlock_password(self) -> str | None:
        return self._unlock_password

    @unlock_password.setter
    def unlock_password(self, unlock_password: str | None) -> None:
        self._unlock_password = unlock_password
        if self._unlock_password:
            master_key = self._generate_master_key(self._unlock_password)
            self.db_key = self._find_wrapping_key(master_key)

    @property
    def unlock_key(self) -> str | None:
        return self._unlock_key

    @unlock_key.setter
    def unlock_key(self, unlock_key: str | None) -> None:
        self._unlock_key = unlock_key
        if self._unlock_key:
            self.db_key = self._find_wrapping_key(unhexlify(self._unlock_key))

    @property
    def unlock_file(self) -> str | None:
        return self._unlock_file

    @unlock_file.setter
    def unlock_file(self, filepath: str | None) -> None:
        self._unlock_file = filepath
        if self._unlock_file:
            try:
                with open(self._unlock_file, mode='rb') as uf:
                    file_content = uf.read()
                unlock_key_blob = _UNLOCK_BLOB(file_content)
                self.db_key = self._find_wrapping_key(unlock_key_blob.MasterKey)
            except OSError:
                self.logger.warning("Unable to read unlock file: %s", self._unlock_file)

    @property
    def db_key(self) -> bytes | None:
        return self._db_key

    @db_key.setter
    def db_key(self, key: bytes | None) -> None:
        self._db_key = key
        if self._db_key:
            if self._generate_key_list() > 0:
                self.locked = False

    # ──────────────────────────────────────────────────────────────────
    # Inner record classes
    # ──────────────────────────────────────────────────────────────────

    class KeychainRecord:
        def __init__(self):
            self.logger = logging.getLogger('Chainbreaker')

        def write_to_disk(self, output_directory: str) -> bool:
            try:
                export_content = self.exportable
            except NotImplementedError:
                self.logger.warning('Attempted to export a non-exportable record.')
                return False

            if not os.path.exists(output_directory):
                try:
                    os.makedirs(output_directory)
                except OSError:
                    self.logger.critical(
                        'Unable to create export directory: %s', output_directory
                    )
                    return False

            file_name = self.FileName + self.FileExt
            iteration = 1
            while os.path.exists(os.path.join(output_directory, file_name)):
                file_name = f"{self.FileName}.{iteration}{self.FileExt}"
                iteration += 1

            file_path = os.path.join(output_directory, file_name)

            try:
                # Write bytes or encode str for binary mode
                write_data = export_content
                if isinstance(write_data, str):
                    write_data = write_data.encode('utf-8')

                with open(file_path, 'wb') as fp:
                    self.logger.info('\t [-] Exported: %s', file_path)
                    fp.write(write_data)
                    return True
            except OSError as e:
                self.logger.critical(
                    'Exception while attempting to export %s: %s', file_path, e
                )
                return False

        @property
        def FileName(self) -> str:
            return str(uuid.uuid4())

        @property
        def FileExt(self) -> str:
            return '.txt'

    class KeychainPasswordHash(KeychainRecord):
        KEYCHAIN_PASSWORD_HASH_FORMAT = "$keychain$*%s*%s*%s"

        def __init__(self, salt: str, iv: str, cyphertext: str):
            self.salt = salt
            self.iv = iv
            self.cypher_text = cyphertext
            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self) -> str:
            return Chainbreaker.KeychainPasswordHash.KEYCHAIN_PASSWORD_HASH_FORMAT % (
                self.salt,
                self.iv,
                self.cypher_text,
            )

        @property
        def exportable(self):
            return str(self)

        @property
        def FileName(self) -> str:
            return "keychain_password_hash"

    class PublicKeyRecord(KeychainRecord):
        def __init__(self, print_name=None, label=None, key_class=None,
                     private=None, key_type=None, key_size=None,
                     effective_key_size=None, extracted=None, cssm_type=None,
                     public_key=None, iv=None, key=None):
            self.PrintName = print_name or ''
            self.Label = label
            self.KeyClass = key_class
            self.Private = private
            self.KeyType = key_type
            self.KeySize = key_size
            self.EffectiveKeySize = effective_key_size
            self.Extracted = extracted
            self.CSSMType = cssm_type
            self.PublicKey = public_key or b''
            self.IV = iv
            self.Key = key
            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] Public Key\n'
            output += ' [-] Print Name: %s\n' % self.PrintName
            output += ' [-] Key Class: %s\n' % self.KeyClass
            output += ' [-] Private: %s\n' % self.Private
            output += ' [-] Key Type: %s\n' % self.KeyType
            output += ' [-] Key Size: %s\n' % self.KeySize
            output += ' [-] Effective Key Size: %s\n' % self.EffectiveKeySize
            output += ' [-] Extracted: %s\n' % self.Extracted
            output += ' [-] CSSM Type: %s\n' % self.CSSMType
            output += ' [-] Base64 Encoded Public Key: %s\n' % base64.b64encode(
                self.PublicKey
            ).decode('ascii')
            return output

        @property
        def exportable(self):
            return self.PublicKey

        @property
        def FileName(self) -> str:
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self) -> str:
            return '.pub'

    class PrivateKeyRecord(KeychainRecord):
        def __init__(self, print_name=None, label=None, key_class=None,
                     private=None, key_type=None, key_size=None,
                     effective_key_size=None, extracted=None, cssm_type=None,
                     key_name=None, private_key=None, iv=None, key=None):
            self.PrintName = print_name or ''
            self.Label = label
            self.KeyClass = key_class
            self.Private = private
            self.KeyType = key_type
            self.KeySize = key_size
            self.EffectiveKeySize = effective_key_size
            self.Extracted = extracted
            self.CSSMType = cssm_type
            self.KeyName = key_name
            self.PrivateKey = private_key
            self.IV = iv
            self.Key = key
            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] Private Key\n'
            output += ' [-] Print Name: %s\n' % self.PrintName
            output += ' [-] Key Class: %s\n' % self.KeyClass
            output += ' [-] Key Type: %s\n' % self.KeyType
            output += ' [-] Key Size: %s\n' % self.KeySize
            output += ' [-] Effective Key Size: %s\n' % self.EffectiveKeySize
            output += ' [-] CSSM Type: %s\n' % self.CSSMType
            output += ' [-] Base64 Encoded PrivateKey: '
            if self.PrivateKey == Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE:
                output += "%s\n" % Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE
            elif isinstance(self.PrivateKey, bytes):
                output += "%s\n" % base64.b64encode(self.PrivateKey).decode('ascii')
            else:
                output += "%s\n" % self.PrivateKey
            return output

        @property
        def exportable(self):
            return self.PrivateKey

        @property
        def FileName(self) -> str:
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self) -> str:
            return '.key'

    class X509CertificateRecord(KeychainRecord):
        def __init__(self, type=None, encoding=None, print_name=None,
                     alias=None, subject=None, issuer=None,
                     serial_number=None, subject_key_identifier=None,
                     public_key_hash=None, certificate=None):
            self.Type = type
            self.Encoding = encoding
            self.PrintName = print_name or ''
            self.Alias = alias
            self.Subject = subject
            self.Issuer = issuer
            self.Serial_Number = serial_number
            self.Subject_Key_Identifier = subject_key_identifier
            self.Public_Key_Hash = public_key_hash
            self.Certificate = certificate or b''
            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] X509 Certificate\n'
            output += " [-] Print Name: %s\n" % self.PrintName
            output += " [-] Certificate: %s\n" % base64.b64encode(
                self.Certificate
            ).decode('ascii')
            return output

        @property
        def exportable(self):
            return self.Certificate

        @property
        def FileName(self) -> str:
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self) -> str:
            return '.crt'

    class SSGBEncryptedRecord(KeychainRecord):
        def __init__(self):
            self._password: str | None = None
            self.locked: bool = True
            self.password_b64_encoded: bool = False
            Chainbreaker.KeychainRecord.__init__(self)

        def decrypt_password(self) -> str | None:
            try:
                if self.SSGP and self.DBKey:
                    raw_password: bytes = Chainbreaker._kcdecrypt(
                        self.DBKey, self.SSGP.IV, self.SSGP.EncryptedPassword
                    )
                    # Try to decode as printable text
                    try:
                        decoded = raw_password.decode('utf-8')
                        if all(c in string.printable for c in decoded):
                            self._password = decoded
                        else:
                            self._password = base64.b64encode(raw_password).decode('ascii')
                            self.password_b64_encoded = True
                    except (UnicodeDecodeError, AttributeError):
                        self._password = base64.b64encode(raw_password).decode('ascii')
                        self.password_b64_encoded = True

                    self.locked = False
            except KeyError:
                if not self._password:
                    self.locked = True
                    self._password = None
            return self._password

        def get_password_output_str(self) -> str:
            password = self.Password
            if self.password_b64_encoded:
                return ' [-] Base64 Encoded Password: %s\n' % password
            else:
                return ' [-] Password: %s\n' % password

        @property
        def Password(self) -> str:
            if not self._password:
                self.decrypt_password()
                if self.locked:
                    self._password = Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE
            return self._password

        @property
        def exportable(self):
            return str(self)

        @property
        def FileName(self) -> str:
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self) -> str:
            return '.txt'

    class GenericPasswordRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None,
                     creator=None, type=None, print_name=None, alias=None,
                     account=None, service=None, key=None, ssgp=None, dbkey=None):
            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name or ''
            self.Alias = alias
            self.Account = account
            self.Service = service
            self.Key = key
            self.SSGP = ssgp
            self.DBKey = dbkey
            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] Generic Password Record\n'
            output += ' [-] Create DateTime: %s\n' % self.Created
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Creator: %s\n' % _safe_four_char(self.Creator)
            output += ' [-] Type: %s\n' % _safe_four_char(self.Type)
            output += ' [-] Print Name: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] Service: %s\n' % self.Service
            output += self.get_password_output_str()
            return output

    class InternetPasswordRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None,
                     comment=None, creator=None, type=None, print_name=None,
                     alias=None, protected=None, account=None,
                     security_domain=None, server=None, protocol_type=None,
                     auth_type=None, port=None, path=None, ssgp=None, dbkey=None):
            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Comment = comment
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name or ''
            self.Alias = alias
            self.Protected = protected
            self.Account = account
            self.SecurityDomain = security_domain
            self.Server = server
            self.ProtocolType = protocol_type
            self.AuthType = auth_type
            self.Port = port or 0
            self.Path = path
            self.SSGP = ssgp
            self.DBKey = dbkey
            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] Internet Record\n'
            output += ' [-] Create DateTime: %s\n' % self.Created
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Comment: %s\n' % self.Comment
            output += ' [-] Creator: %s\n' % _safe_four_char(self.Creator)
            output += ' [-] Type: %s\n' % _safe_four_char(self.Type)
            output += ' [-] PrintName: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Protected: %s\n' % self.Protected
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] SecurityDomain: %s\n' % self.SecurityDomain
            output += ' [-] Server: %s\n' % self.Server

            try:
                output += ' [-] Protocol Type: %s\n' % PROTOCOL_TYPE[self.ProtocolType]
            except KeyError:
                output += ' [-] Protocol Type: %s\n' % _safe_four_char(self.ProtocolType)

            try:
                output += ' [-] Auth Type: %s\n' % AUTH_TYPE[self.AuthType]
            except KeyError:
                output += ' [-] Auth Type: %s\n' % _safe_four_char(self.AuthType)

            output += ' [-] Port: %d\n' % self.Port
            output += ' [-] Path: %s\n' % self.Path
            output += self.get_password_output_str()
            return output

    class AppleshareRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None,
                     comment=None, creator=None, type=None, print_name=None,
                     alias=None, protected=None, account=None, volume=None,
                     server=None, protocol_type=None, address=None,
                     signature=None, dbkey=None, ssgp=None):
            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Comment = comment
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name or ''
            self.Alias = alias
            self.Protected = protected
            self.Account = account
            self.Volume = volume
            self.Server = server
            self.Protocol_Type = protocol_type
            self.Address = address or ''
            self.Signature = signature
            self.SSGP = ssgp
            self.DBKey = dbkey
            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self) -> str:
            output = '[+] AppleShare Record (no longer used in OS X)\n'
            output += ' [-] Create DateTime: %s\n' % self.Created
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Comment: %s\n' % self.Comment
            output += ' [-] Creator: %s\n' % _safe_four_char(self.Creator)
            output += ' [-] Type: %s\n' % _safe_four_char(self.Type)
            output += ' [-] PrintName: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Protected: %s\n' % self.Protected
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] Volume: %s\n' % self.Volume
            output += ' [-] Server: %s\n' % self.Server

            try:
                output += ' [-] Protocol Type: %s\n' % PROTOCOL_TYPE[self.Protocol_Type]
            except KeyError:
                output += ' [-] Protocol Type: %s\n' % _safe_four_char(self.Protocol_Type)

            output += ' [-] Address: %s\n' % self.Address
            output += ' [-] Signature: %s\n' % self.Signature
            output += self.get_password_output_str()
            return output


def _safe_four_char(value) -> str:
    """Safely convert a 4-char code (bytes or str) to a printable string."""
    if isinstance(value, bytes):
        return value.decode('ascii', errors='replace').strip('\x00')
    if value is None:
        return ''
    return str(value)


# ======================================================================
# CLI entry point
# ======================================================================

if __name__ == "__main__":
    import argparse
    import getpass
    import datetime

    print(BANNER)

    arguments = argparse.ArgumentParser(
        description='Dump items stored in a macOS Keychain'
    )

    arguments.add_argument(
        'keychain', help='Location of the keychain file to parse'
    )

    dump_actions = arguments.add_argument_group('Dump Actions')
    dump_actions.add_argument(
        '--dump-all', '-a',
        help='Dump records to the console window.',
        action='store_true', dest='dump_all',
    )
    dump_actions.add_argument(
        '--dump-keychain-password-hash',
        help='Dump the keychain password hash (hashcat mode 23100 / JtR)',
        action='store_true', dest='dump_keychain_password_hash',
    )
    dump_actions.add_argument(
        '--dump-generic-passwords',
        help='Dump all generic passwords',
        action='store_true', dest='dump_generic_passwords',
    )
    dump_actions.add_argument(
        '--dump-internet-passwords',
        help='Dump all internet passwords',
        action='store_true', dest='dump_internet_passwords',
    )
    dump_actions.add_argument(
        '--dump-appleshare-passwords',
        help='Dump all appleshare passwords',
        action='store_true', dest='dump_appleshare_passwords',
    )
    dump_actions.add_argument(
        '--dump-private-keys',
        help='Dump all private keys',
        action='store_true', dest='dump_private_keys',
    )
    dump_actions.add_argument(
        '--dump-public-keys',
        help='Dump all public keys',
        action='store_true', dest='dump_public_keys',
    )
    dump_actions.add_argument(
        '--dump-x509-certificates',
        help='Dump all X509 certificates',
        action='store_true', dest='dump_x509_certificates',
    )

    export_actions = arguments.add_argument_group(
        'Export Actions',
        description='Export records to files. Save location is CWD, '
                    'overridable with --output / -o',
    )
    export_actions.add_argument(
        '--export-keychain-password-hash',
        help='Save the keychain password hash to disk',
        action='store_true', dest='export_keychain_password_hash',
    )
    export_actions.add_argument(
        '--export-generic-passwords',
        help='Save all generic passwords to disk',
        action='store_true', dest='export_generic_passwords',
    )
    export_actions.add_argument(
        '--export-internet-passwords',
        help='Save all internet passwords to disk',
        action='store_true', dest='export_internet_passwords',
    )
    export_actions.add_argument(
        '--export-appleshare-passwords',
        help='Save all appleshare passwords to disk',
        action='store_true', dest='export_appleshare_passwords',
    )
    export_actions.add_argument(
        '--export-private-keys',
        help='Save private keys to disk',
        action='store_true', dest='export_private_keys',
    )
    export_actions.add_argument(
        '--export-public-keys',
        help='Save public keys to disk',
        action='store_true', dest='export_public_keys',
    )
    export_actions.add_argument(
        '--export-x509-certificates',
        help='Save X509 certificates to disk',
        action='store_true', dest='export_x509_certificates',
    )
    export_actions.add_argument(
        '--export-all', '-e',
        help='Save records to disk',
        action='store_true', dest='export_all',
    )

    misc_actions = arguments.add_argument_group('Misc. Actions')
    misc_actions.add_argument(
        '--check-unlock-options', '-c',
        help='Only check if the provided unlock options work. '
             'Exits 0 on success, 1 on failure.',
        action='store_true', dest='check_unlock',
    )

    unlock_args = arguments.add_argument_group('Unlock Options')
    unlock_args.add_argument(
        '--password-prompt', '-p',
        help='Prompt for a password to use in unlocking the keychain',
        action='store_true', dest='password_prompt',
    )
    unlock_args.add_argument(
        '--password',
        help='Unlock the keychain with a password, provided on the terminal. '
             'Caution: This is insecure and you should likely use --password-prompt instead',
    )
    unlock_args.add_argument(
        '--key-prompt', '-k',
        help='Prompt for a key to use in unlocking the keychain',
        action='store_true', dest='key_prompt',
    )
    unlock_args.add_argument(
        '--key',
        help='Unlock the keychain with a key, provided via argument. '
             'Caution: This is insecure and you should likely use --key-prompt instead',
    )
    unlock_args.add_argument(
        '--unlock-file',
        help='Unlock the keychain with a key file (e.g. SystemKey)',
    )

    output_args = arguments.add_argument_group('Output Options')
    output_args.add_argument(
        '--output', '-o',
        help='Directory to output exported records to.',
    )
    output_args.add_argument(
        '-d', '--debug',
        help="Print debug information",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.INFO,
    )

    args = arguments.parse_args()

    if args.password_prompt:
        args.password = getpass.getpass('Unlock Password: ')

    if args.key_prompt:
        args.key = getpass.getpass('Unlock Key: ')

    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=args.loglevel,
        stream=sys.stdout,
    )
    logger = logging.getLogger('Chainbreaker')

    if args.output:
        if not os.path.exists(args.output):
            try:
                os.makedirs(args.output)
            except OSError:
                logger.critical("Unable to create output directory: %s", args.output)
                sys.exit(1)
        logger.addHandler(
            logging.FileHandler(os.path.join(args.output, 'output.log'), mode='w')
        )
    else:
        args.output = os.getcwd()

    if args.dump_all:
        args.dump_keychain_password_hash = True
        args.dump_generic_passwords = True
        args.dump_internet_passwords = True
        args.dump_appleshare_passwords = True
        args.dump_public_keys = True
        args.dump_private_keys = True
        args.dump_x509_certificates = True

    if args.export_all:
        args.export_keychain_password_hash = True
        args.export_generic_passwords = True
        args.export_internet_passwords = True
        args.export_appleshare_passwords = True
        args.export_public_keys = True
        args.export_private_keys = True
        args.export_x509_certificates = True

    any_action = any([
        args.dump_keychain_password_hash, args.dump_generic_passwords,
        args.dump_internet_passwords, args.dump_appleshare_passwords,
        args.dump_public_keys, args.dump_private_keys,
        args.dump_x509_certificates, args.export_keychain_password_hash,
        args.export_generic_passwords, args.export_internet_passwords,
        args.export_appleshare_passwords, args.export_private_keys,
        args.export_public_keys, args.export_x509_certificates,
        args.check_unlock,
    ])

    if not any_action:
        logger.critical("No action specified.")
        sys.exit(1)

    # Hash the keychain FILE CONTENTS (not the filename)
    try:
        with open(args.keychain, 'rb') as kc_fp:
            kc_file_data = kc_fp.read()
        keychain_md5 = hashlib.md5(kc_file_data).hexdigest()
        keychain_sha256 = hashlib.sha256(kc_file_data).hexdigest()
    except OSError as e:
        logger.critical("Unable to read keychain file for hashing: %s", e)
        sys.exit(1)

    summary_output = [
        "\nChainBreaker - @Speersec fork\n",
        "Runtime Command: %s" % ' '.join(sys.argv),
        "Keychain: %s" % args.keychain,
        "Keychain MD5: %s" % keychain_md5,
        "Keychain SHA256: %s" % keychain_sha256,
        "Dump Start: %s" % datetime.datetime.now(),
    ]

    for line in summary_output:
        logger.info(line)

    summary_output.append("Dump Summary:")

    keychain = Chainbreaker(
        args.keychain,
        unlock_password=args.password,
        unlock_key=args.key,
        unlock_file=args.unlock_file,
    )

    if args.check_unlock:
        if keychain.locked:
            logger.info("Invalid Unlock Options")
            sys.exit(1)
        else:
            logger.info("Keychain Unlock Successful.")
            sys.exit(0)

    output = []

    if args.dump_keychain_password_hash or args.export_keychain_password_hash:
        output.append({
            'header': 'Keychain Password Hash',
            'records': [keychain.dump_keychain_password_hash()],
            'write_to_console': args.dump_keychain_password_hash,
            'write_to_disk': args.export_keychain_password_hash,
            'write_directory': args.output,
        })

    if args.dump_generic_passwords or args.export_generic_passwords:
        output.append({
            'header': 'Generic Passwords',
            'records': keychain.dump_generic_passwords(),
            'write_to_console': args.dump_generic_passwords,
            'write_to_disk': args.export_generic_passwords,
            'write_directory': os.path.join(args.output, 'passwords', 'generic'),
        })

    if args.dump_internet_passwords or args.export_internet_passwords:
        output.append({
            'header': 'Internet Passwords',
            'records': keychain.dump_internet_passwords(),
            'write_to_console': args.dump_internet_passwords,
            'write_to_disk': args.export_internet_passwords,
            'write_directory': os.path.join(args.output, 'passwords', 'internet'),
        })

    if args.dump_appleshare_passwords or args.export_appleshare_passwords:
        output.append({
            'header': 'Appleshare Passwords',
            'records': keychain.dump_appleshare_passwords(),
            'write_to_console': args.dump_appleshare_passwords,
            'write_to_disk': args.export_appleshare_passwords,
            'write_directory': os.path.join(args.output, 'passwords', 'appleshare'),
        })

    if args.dump_private_keys or args.export_private_keys:
        output.append({
            'header': 'Private Keys',
            'records': keychain.dump_private_keys(),
            'write_to_console': args.dump_private_keys,
            'write_to_disk': args.export_private_keys,
            'write_directory': os.path.join(args.output, 'keys', 'private'),
        })

    if args.dump_public_keys or args.export_public_keys:
        output.append({
            'header': 'Public Keys',
            'records': keychain.dump_public_keys(),
            'write_to_console': args.dump_public_keys,
            'write_to_disk': args.export_public_keys,
            'write_directory': os.path.join(args.output, 'keys', 'public'),
        })

    if args.dump_x509_certificates or args.export_x509_certificates:
        output.append({
            'header': 'x509 Certificates',
            'records': keychain.dump_x509_certificates(),
            'write_to_console': args.dump_x509_certificates,
            'write_to_disk': args.export_x509_certificates,
            'write_directory': os.path.join(args.output, 'certificates'),
        })

    try:
        for record_collection in output:
            if 'records' in record_collection:
                # Filter out None records (e.g. from unparseable keychains)
                records = [r for r in record_collection['records'] if r is not None]
                collection_summary = "%s %s" % (
                    len(records),
                    record_collection['header'],
                )
                logger.info(collection_summary)
                summary_output.append("\t%s" % collection_summary)

                for record in records:
                    if record_collection.get('write_to_console', False):
                        for line in str(record).split('\n'):
                            logger.info("\t%s", line)
                    if record_collection.get('write_to_disk', False):
                        record.write_to_disk(
                            record_collection.get('write_directory', args.output)
                        )
                    logger.info("")

        summary_output.append("Dump End: %s" % datetime.datetime.now())

        if any(x.get('write_to_disk', False) for x in output):
            with open(os.path.join(args.output, "summary.txt"), 'w') as summary_fp:
                for line in summary_output:
                    summary_fp.write("%s\n" % line)
                    logger.info(line)
        else:
            for line in summary_output:
                logger.info(line)

    except KeyboardInterrupt:
        sys.exit(0)

    sys.exit(0)
