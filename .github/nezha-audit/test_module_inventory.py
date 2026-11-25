"""All ELF bytes in these tests are synthetic structural fixtures, not OTA evidence."""
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import module_inventory as audit


def synthetic_elf(*, fmt='extended', required=((b'kernel_symbol', 123),), undefined=None,
                  export=None, crc_kind='abs', signed=False, extra=()):
    sections = [(b'', 0, b'', 0, 0, 0)]

    def add(name, typ, data, link=0, info=0, ent=0):
        sections.append((name, typ, data, link, info, ent))
        return len(sections) - 1

    add(b'.modinfo', 1, b'license=GPL\0vermagic=synthetic ARM64\0')
    if fmt == 'basic':
        add(b'__versions', 1, b''.join(struct.pack('<Q56s', v, k) for k, v in required))
    if fmt == 'extended':
        add(b'__version_ext_names', 1, b''.join(k + b'\0' for k, _ in required))
        add(b'__version_ext_crcs', 1, b''.join(struct.pack('<I', v) for _, v in required))
    for name, payload in extra:
        add(name, 1, payload)
    strings = bytearray(b'\0')
    symbols = bytearray(24)

    def symbol(name, idx, size=0, val=0):
        symbols.extend(struct.pack('<IBBHQQ', len(strings), 0x10, 0, idx, val, size))
        strings.extend(name + b'\0')

    for name in (undefined if undefined is not None else (k for k, _ in required)):
        symbol(name, 0)
    if export:
        name, crc = export
        ktab = add(b'__ksymtab_gpl', 1, bytes(12))
        symbol(b'__ksymtab_' + name, ktab)
        if crc_kind == 'abs':
            symbol(b'__crc_' + name, 0xfff1, val=crc)
        elif crc_kind in ('literal', 'relocated'):
            tab = add(b'__kcrctab_gpl', 1, struct.pack('<I', crc))
            symbol(b'__crc_' + name, tab, size=4)
            if crc_kind == 'relocated':
                add(b'.rela__kcrctab_gpl', 4, bytes(24), info=tab, ent=24)
    strtab = add(b'.strtab', 3, strings)
    add(b'.symtab', 2, symbols, link=strtab, info=1, ent=24)
    shstr = add(b'.shstrtab', 3, b'')
    names = b''.join(s[0] + b'\0' for s in sections)
    buf = bytearray(64)
    headers = bytearray(64)
    for idx, (name, typ, data, link, info, ent) in enumerate(sections[1:], 1):
        if idx == shstr:
            data = names
        headers.extend(struct.pack('<IIQQQQIIQQ', names.index(name + b'\0'), typ, 2 if typ == 1 else 0,
                                   0, len(buf), len(data), link, info, 1, ent))
        buf.extend(data)
    buf[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\2\1\1', 1, 183, 1, 0, 0,
                           len(buf), 0, 64, 0, 0, 64, len(sections), shstr)
    buf.extend(headers)
    if signed:
        buf.extend(b'FAKE' + struct.pack('>5B3sI', 0, 0, 2, 0, 0, bytes(3), 4) + audit.MARKER)
    return bytes(buf)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.tree = self.base / 'modules'
        self.tree.mkdir()
        self.sym = self.base / 'Module.symvers'
        self.sym.write_bytes(b'0x0000007b\tkernel_symbol\tvmlinux\tEXPORT_SYMBOL_GPL\t\n'
                             b'0x8\text\tdrivers/external\tEXPORT_SYMBOL\t\n')

    def cli(self, *roots, expect=1):
        report = self.base / 'report.json'
        cmd = [sys.executable, '-B', audit.__file__, '--symvers', str(self.sym), '--report', str(report)]
        for root in roots or (self.tree,):
            cmd.extend(['--module-root', str(root)])
        run = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(run.returncode, expect, run.stderr)
        result = json.loads(report.read_bytes())
        self.assertEqual(json.loads(run.stdout)['status'], result['status'])
        return result

    def test_repeated_roots_gzip_xz_digests_and_signature_presence(self):
        blob = synthetic_elf(signed=True)
        inputs = {'same.ko': blob, 'same.ko.gz': gzip.compress(blob), 'same.ko.xz': lzma.compress(blob)}
        for name, data in inputs.items():
            (self.tree / name).write_bytes(data)
        r = self.cli(self.tree, self.tree, expect=0)
        self.assertEqual(r['module_rows'], 6)
        self.assertEqual(r['counts'], dict(matched=6, missing_or_external=0, wrong_crc=0, unsupported=0))
        for row in r['modules']:
            self.assertEqual(row['file_sha256'], hashlib.sha256(inputs[row['path']]).hexdigest())
            self.assertEqual(row['expanded_sha256'], hashlib.sha256(blob).hexdigest())
            self.assertEqual(row['signature_presence'], 'trailer_present')
            self.assertEqual(row['vermagic'], 'synthetic ARM64')

    def test_basic_contradiction_and_unversioned_import(self):
        (self.tree / 'basic.ko').write_bytes(synthetic_elf(fmt='basic', required=((b'kernel_symbol', 124),),
                                                           undefined=[b'kernel_symbol', b'other']))
        r = self.cli()
        self.assertEqual(r['status'], 'CRC_CONTRADICTION')
        row, = r['modules']
        self.assertEqual(row['counts']['unsupported'], 1)
        self.assertEqual(row['imports']['kernel_symbol']['observed_crc'], 123)
        self.assertEqual(row['counts']['wrong_crc'], 1)
        self.assertEqual(row['signature_presence'], 'no_marker')

    def test_oem_evidence_not_guessed_from_symvers_or_consumers(self):
        (self.tree / 'consumer.ko').write_bytes(synthetic_elf(required=((b'ext', 8),)))
        provider = self.tree / 'oem.ko'
        for kind, crc, matched in [('abs', 8, True), ('literal', 8, True), ('relocated', 8, False),
                                   ('none', 8, False), ('abs', 9, False)]:
            with self.subTest(kind=kind, crc=crc):
                provider.write_bytes(synthetic_elf(export=(b'ext', crc), crc_kind=kind))
                r = self.cli(expect=0 if matched else 1)
                self.assertEqual(r['counts']['wrong_crc'], 0)
                self.assertEqual(r['counts']['missing_or_external'], int(not matched))
                self.assertEqual(r['status'], 'OBSERVED_CRCS_MATCH' if matched else 'UNKNOWN')

    def test_aliases_cannot_turn_self_exports_into_provider_evidence(self):
        nested = self.tree / 'nested'
        nested.mkdir()
        blob = synthetic_elf(required=((b'ext', 8),), export=(b'ext', 8))
        (nested / 'self.ko').write_bytes(blob)
        for roots in ((self.tree,), (self.tree, self.tree), (self.tree, nested)):
            with self.subTest(roots=roots):
                result = self.cli(*roots)
                self.assertEqual(result['status'], 'UNKNOWN')
                self.assertEqual(result['counts']['matched'], 0)
                self.assertEqual(result['counts']['missing_or_external'], result['module_rows'])
        (nested / 'copy.ko.gz').write_bytes(gzip.compress(blob))
        result = self.cli()
        self.assertEqual(result['module_rows'], 2)
        self.assertEqual(result['counts']['missing_or_external'], 2)


    def test_observed_contradiction_survives_unavailable_symtab(self):
        data = bytearray(synthetic_elf(required=((b'kernel_symbol', 124),)))
        shoff, = struct.unpack_from('<Q', data, 40)
        for at in range(shoff, len(data), 64):
            if struct.unpack_from('<I', data, at + 4)[0] == 2:
                struct.pack_into('<I', data, at + 4, 1)
        (self.tree / 'stripped.ko').write_bytes(data)
        r = self.cli()
        self.assertEqual(r['status'], 'CRC_CONTRADICTION')
        self.assertEqual(r['counts']['wrong_crc'], 1)
        self.assertEqual(r['counts']['unsupported'], 1)

    def test_bounds_and_trailing_compression(self):
        for suffix, compressor in [('gz', gzip.compress), ('xz', lzma.compress)]:
            raw = compressor(b'x' * 4096)
            for limit, blob in [(4095, raw), (4096, raw[:-1]), (4096, raw + raw)]:
                with self.assertRaises(ValueError):
                    audit.expand('a.ko.' + suffix, blob, limit)
            self.assertEqual(len(audit.expand('a.ko.' + suffix, raw, 4096)), 4096)

    def test_missing_symvers_empty_root_and_absent_versions(self):
        self.sym.unlink()
        empty = self.cli()
        self.assertEqual(empty['module_rows'], 0)
        self.assertIn('error', empty['symvers'])
        (self.tree / 'none.ko').write_bytes(synthetic_elf(fmt='none'))
        r = self.cli()
        self.assertEqual(r['status'], 'UNKNOWN')
        self.assertEqual(r['modules'][0]['version_format'], 'absent')

    def test_refuses_symlink_escapes_and_nonregular_modules(self):
        (self.base / 'outside').write_bytes(synthetic_elf())
        (self.tree / 'a.ko').symlink_to(self.base / 'outside')
        (self.tree / 'subdir').symlink_to(self.base, target_is_directory=True)
        alias = self.base / 'alias'
        alias.symlink_to(self.tree, target_is_directory=True)
        audit.os.mkfifo(self.tree / 'pipe.ko')
        r = self.cli(self.tree, alias)
        self.assertEqual(r['module_rows'], 2)
        self.assertEqual(r['counts']['unsupported'], 2)
        self.assertGreaterEqual(len(r['inventory_errors']), 2)
        self.assertTrue(all('file_sha256' not in row for row in r['modules']))

    def test_invalid_metadata_and_unknown_encoding_remain_unknown(self):
        valid = synthetic_elf()
        blobs = {'truncated.ko': valid[:-1], 'wrongarch.ko': valid[:18] + bytes(2) + valid[20:],
                 'unsupported.ko.zst': valid, 'partial.ko': synthetic_elf(fmt='none', extra=[(b'__version_ext_names', b'x\0')]),
                 'duplicate.ko': synthetic_elf(required=((b'ext', 12), (b'ext', 13))),
                 'invalid.ko': synthetic_elf(fmt='none', extra=[(b'__versions', bytes(65))]),
                 'trailer.ko': valid + bytes(12) + audit.MARKER}
        for name, data in blobs.items():
            (self.tree / name).write_bytes(data)
        r = self.cli()
        self.assertEqual(r['module_rows'], len(blobs))
        self.assertEqual(r['status'], 'UNKNOWN')
        self.assertGreaterEqual(r['counts']['unsupported'], len(blobs))
        self.assertTrue(all('error' in row for row in r['modules']))


if __name__ == '__main__':
    unittest.main()
