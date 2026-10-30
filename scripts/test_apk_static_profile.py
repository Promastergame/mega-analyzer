"""Offline tests for the inventory utility (not tests of the Go planner)."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import warnings
import zipfile
import zlib

from apk_static_profile import Dex, profile


def sealed(data):
    data = bytearray(data)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def empty_dex():
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<III', data, 32, 112, 112, 0x12345678)
    return sealed(data)


class StaticProfileTests(unittest.TestCase):
    def test_empty_valid_dex(self):
        self.assertEqual(Dex(empty_dex()).inventory()['counts']['classes'], 0)

    def test_truncated_header(self):
        with self.assertRaises(ValueError):
            Dex(b'dex\n035\0')

    def test_bad_checksum(self):
        data = bytearray(empty_dex())
        data[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'Adler'):
            Dex(data)

    def test_bad_signature_even_with_valid_checksum(self):
        data = bytearray(empty_dex())
        data[12] ^= 1
        struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'SHA-1'):
            Dex(data)

    def test_out_of_bounds_table(self):
        data = bytearray(empty_dex())
        struct.pack_into('<II', data, 56, 10, 112)
        with self.assertRaises(ValueError):
            Dex(sealed(data))

    def test_uleb_bounds_and_overflow(self):
        dex = Dex(empty_dex())
        with self.assertRaises(ValueError):
            dex.uleb(len(dex.data))
        dex.data = bytes([255] * 5)
        with self.assertRaises(ValueError):
            dex.uleb(0)

    def test_zip_with_dex(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as z:
                z.writestr('classes.dex', empty_dex())
            result = profile(apk)
            self.assertTrue(result['zip_crc_valid'])
            self.assertEqual(len(result['dex']), 1)
            self.assertEqual(result['dex'][0]['counts']['native_methods'], 0)

    def test_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / 'duplicate.apk'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(apk, 'w') as z:
                    z.writestr('classes.dex', empty_dex())
                    z.writestr('classes.dex', empty_dex())
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                profile(apk)


if __name__ == '__main__':
    unittest.main()
