#!/usr/bin/env python3
"""Read-only APK/DEX inventory, Python stdlib only; NOT an ART or ML test."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
import zlib

MAX_ENTRY = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


class Dex:
    def __init__(self, data):
        self.data = data
        self.require(0, 112)
        if data[:4] != b'dex\n' or data[7] != 0:
            raise ValueError('not a standard DEX')
        if data[4:7] not in (b'035', b'037', b'038', b'039', b'040'):
            raise ValueError('unsupported DEX version (no compact/container DEX support)')
        if self.u32(32) != len(data) or self.u32(36) != 112 or self.u32(40) != 0x12345678:
            raise ValueError('unsupported or inconsistent DEX header')
        if self.u32(8) != zlib.adler32(data[12:]) & 0xffffffff:
            raise ValueError('DEX Adler-32 mismatch')
        if data[12:32] != hashlib.sha1(data[32:]).digest():
            raise ValueError('DEX SHA-1 mismatch')
        self.strings = []
        for p in self.table(56, 4):
            off = self.u32(p)
            _, off = self.uleb(off)
            end = data.find(b'\0', off)
            if end < 0:
                raise ValueError('unterminated DEX string')
            # Names/descriptors in this inventory are normally ASCII. MUTF-8
            # non-ASCII edge cases are replaced for display, not interpreted.
            self.strings.append(data[off:end].decode('utf-8', errors='replace'))
        self.types = [self.at(self.strings, self.u32(p)) for p in self.table(64, 4)]
        self.methods = []
        for p in self.table(88, 8):
            self.methods.append((self.at(self.types, self.u16(p)),
                                 self.at(self.strings, self.u32(p + 4))))

    @staticmethod
    def at(items, index):
        if index >= len(items):
            raise ValueError('DEX index outside table')
        return items[index]

    def require(self, off, size):
        if off < 0 or size < 0 or off + size > len(self.data):
            raise ValueError('DEX offset outside file')

    def u16(self, off):
        self.require(off, 2)
        return struct.unpack_from('<H', self.data, off)[0]

    def u32(self, off):
        self.require(off, 4)
        return struct.unpack_from('<I', self.data, off)[0]

    def table(self, header_off, stride):
        count, off = self.u32(header_off), self.u32(header_off + 4)
        self.require(off, count * stride)
        return range(off, off + count * stride, stride)

    def uleb(self, off):
        value = 0
        for i in range(5):
            self.require(off, 1)
            byte = self.data[off]
            off += 1
            if i == 4 and byte > 15:
                raise ValueError('ULEB128 overflow')
            value |= (byte & 127) << (7 * i)
            if byte < 128:
                return value, off
        raise ValueError('unterminated ULEB128')

    def inventory(self):
        counts = collections.Counter()
        natives = []
        class_prefixes = collections.Counter()
        for p in self.table(96, 32):
            cls = self.at(self.types, self.u32(p))
            class_prefixes['/'.join(cls.split('/')[:3])] += 1
            counts['classes'] += 1
            off = self.u32(p + 24)
            if off == 0:
                continue
            ns, off = self.uleb(off)
            ni, off = self.uleb(off)
            nd, off = self.uleb(off)
            nv, off = self.uleb(off)
            if ns + ni + nd + nv > len(self.data):
                raise ValueError('implausible class data size')
            for _ in range(ns + ni):
                _, off = self.uleb(off)
                _, off = self.uleb(off)
            for length in (nd, nv):
                index = 0
                for _ in range(length):
                    delta, off = self.uleb(off)
                    flags, off = self.uleb(off)
                    code_off, off = self.uleb(off)
                    index += delta
                    owner, name = self.at(self.methods, index)
                    if owner != cls:
                        raise ValueError('encoded method belongs to another class')
                    counts['defined_methods'] += 1
                    if flags & 0x100:
                        counts['native_methods'] += 1
                        natives.append({'class': cls, 'name': name, 'method_index': index, 'code_off': code_off})
                    if flags & 0x400:
                        counts['abstract_methods'] += 1
                    if code_off:
                        self.require(code_off, 16)
                        units = self.u32(code_off + 12)
                        self.require(code_off + 16, units * 2)
                        counts['methods_with_code'] += 1
                        counts['code_units'] += units
                    else:
                        counts['methods_without_code'] += 1
                    if bool(code_off) == bool(flags & (0x100 | 0x400)):
                        counts['inconsistent_code_flags'] += 1
        for key in ('classes', 'defined_methods', 'native_methods', 'abstract_methods',
                    'methods_with_code', 'methods_without_code', 'inconsistent_code_flags'):
            counts.setdefault(key, 0)
        return {'counts': dict(counts), 'native_methods': natives,
                'top_class_prefixes': class_prefixes.most_common(12)}


def profile(path):
    result = {'schema': 'apk-static-profile/v1', 'analysis': 'read_only_inventory',
              'apk_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'apk_bytes': path.stat().st_size, 'dex': [], 'native_libraries': [],
              'limitations': ['No APK execution, rebuild, signature authentication or ART verification.',
                              'No ML planner execution, accuracy measurement or model training.',
                              'DEX inventory is not a proof of Smali patch applicability.',
                              'Method display names are not complete overload descriptors.']}
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        if len(entries) > 100000 or sum(i.file_size for i in entries) > MAX_TOTAL:
            raise ValueError('APK exceeds inventory size limit')
        names = [i.filename for i in entries]
        if len(names) != len(set(names)):
            raise ValueError('duplicate ZIP entry names')
        if any(i.file_size > MAX_ENTRY or i.flag_bits & 1 for i in entries):
            raise ValueError('oversized or encrypted ZIP entry')
        bad = z.testzip()
        if bad is not None:
            raise ValueError('ZIP CRC failure: ' + bad)
        result['zip_entries'] = len(entries)
        result['zip_crc_valid'] = True
        for name in sorted(names):
            if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name):
                data = z.read(name)
                result['dex'].append({'name': name, 'bytes': len(data),
                                      'sha256': hashlib.sha256(data).hexdigest(),
                                      **Dex(data).inventory()})
            elif name.startswith('lib/') and name.endswith('.so'):
                data = z.read(name)
                elf = len(data) >= 20 and data[:4] == b'\x7fELF'
                result['native_libraries'].append({'name': name, 'bytes': len(data),
                    'sha256': hashlib.sha256(data).hexdigest(), 'elf_magic': elf})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = profile(args.apk)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    for dex in report['dex']:
        print(dex['name'], json.dumps(dex['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
