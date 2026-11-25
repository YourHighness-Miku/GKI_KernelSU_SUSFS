"""Synthetic container/archive fixtures; real public input is checked separately."""
from pathlib import Path
import stat
import struct
import tempfile
import unittest

import lz4.block

from vendor_ramdisk import align, cpio, decode, extract, fragments


def archive(entries, crc=False):
    result = bytearray()
    for i, (name, payload, mode, nlink) in enumerate(entries + [('TRAILER!!!', b'', 0, 1)]):
        raw = name.encode() + b'\0'
        fields = (i + 1, mode, 0, 0, nlink, 0, len(payload), 0, 0, 0, 0, len(raw), sum(payload) if crc else 0)
        result.extend((b'070702' if crc else b'070701') + ''.join(f'{x:08x}' for x in fields).encode())
        result.extend(raw)
        result.extend(bytes(align(len(result), 4) - len(result)))
        result.extend(payload)
        result.extend(bytes(align(len(result), 4) - len(result)))
    return bytes(result)


def legacy(data):
    block = lz4.block.compress(data, store_size=False)
    return b'\x02\x21\x4c\x18' + struct.pack('<I', len(block)) + block


def image(parts):
    raw = b''.join(blob for _, blob in parts)
    table = 4096 + align(len(raw))
    data = bytearray(table + align(len(parts) * 108))
    data[:8] = b'VNDRBOOT'
    struct.pack_into('<II', data, 8, 4, 4096)
    struct.pack_into('<I', data, 24, len(raw))
    struct.pack_into('<II', data, 2096, 2128, 0)
    struct.pack_into('<4I', data, 2112, len(parts) * 108, len(parts), 108, 0)
    data[4096:4096 + len(raw)] = raw
    offset = 0
    for i, (kind, blob) in enumerate(parts):
        struct.pack_into('<III', data, table + i * 108, len(blob), offset, kind)
        data[table + i * 108 + 12:table + i * 108 + 14] = b'x\0'
        offset += len(blob)
    return bytes(data)


class VendorRamdiskTests(unittest.TestCase):
    def test_actual_parser_raw_and_legacy_streams(self):
        for crc in (False, True):
            raw = archive([('lib/modules/a.ko', b'ELF fixture', stat.S_IFREG | 0o644, 1),
                           ('lib/modules/modules.load', b'a.ko\n', stat.S_IFREG | 0o644, 1)], crc)
            self.assertEqual(decode(legacy(raw)), raw)
            for blob in (raw, legacy(raw)):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / 'out'
                    report = extract(image([(1, blob), (2, b'not selected recovery data')]), out)
                    self.assertEqual(len(report['modules']), 1)
                    self.assertEqual((out / '0/lib/modules/a.ko').read_bytes(), b'ELF fixture')
                    self.assertFalse((out / '1').exists())
                    self.assertEqual(len(report['metadata']), 1)
                    self.assertIn('unknown', report['scope'])

    def test_archive_safety_and_truncation(self):
        for name in ('../a.ko', '/a.ko', 'x/../../a.ko'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                list(cpio(archive([(name, b'x', stat.S_IFREG, 1)])))
        raw = archive([('x', b'x', stat.S_IFREG, 1)])
        for data in (raw[:-1], raw + b'extra', raw + raw,
                     archive([('x', b'a', stat.S_IFREG, 1), ('x', b'b', stat.S_IFREG, 1)])):
            with self.assertRaises(ValueError):
                list(cpio(data))
        bad = bytearray(raw)
        bad[6:14] = b'-0000001'
        with self.assertRaises(ValueError):
            list(cpio(bytes(bad)))

    def test_selected_link_never_materializes(self):
        for mode, links in ((stat.S_IFLNK, 1), (stat.S_IFREG, 2), (stat.S_IFIFO, 1)):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'out'
                with self.assertRaises(ValueError):
                    extract(image([(3, archive([('lib/a.ko', b'target', mode, links)]))]), out)
                self.assertFalse((out / '0/lib/a.ko').exists())

    def test_bad_tables_and_unsupported_compression(self):
        raw = archive([('a.ko', b'x', stat.S_IFREG, 1)])
        data = image([(1, raw), (3, raw)])
        table = 4096 + align(2 * len(raw))
        for offset, value in ((8, 3), (12, 8192), (2116, 257), (2120, 109), (table + 108 + 4, 0)):
            changed = bytearray(data)
            struct.pack_into('<I', changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                fragments(bytes(changed))
        for bad in (b'', b'gzip', legacy(raw)[:-1], legacy(raw) + b'x', b'\x02\x21\x4c\x18\x00\x00\x00\x00junk'):
            with self.assertRaises((ValueError, RuntimeError)):
                decode(bad)

    def test_newc_crc_and_missing_module_evidence_fail_closed(self):
        raw = bytearray(archive([('a.ko', b'x', stat.S_IFREG, 1)], True))
        raw[102:110] = b'00000000'
        with self.assertRaises(ValueError):
            list(cpio(bytes(raw)))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                extract(image([(1, archive([]))]), Path(tmp) / 'out')

    def test_lz4_block_count_and_canonical_archive_aliases(self):
        tiny = legacy(b'x')[4:]
        self.assertEqual(decode(b'\x02\x21\x4c\x18' + tiny * 1024), b'x' * 1024)
        with self.assertRaises(ValueError):
            decode(b'\x02\x21\x4c\x18' + tiny * 1025)
        with self.assertRaises(ValueError):
            list(cpio(archive([('a', b'x', stat.S_IFREG, 1), ('./a', b'y', stat.S_IFREG, 1)])))



if __name__ == '__main__':
    unittest.main()
