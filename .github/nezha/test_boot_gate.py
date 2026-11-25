import bz2
import lzma
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from boot_gate import assess, boot_layout, decode_operation, digest, place, run_tool, signing_metadata


class PayloadTests(unittest.TestCase):
    def test_replace_and_compressed_operations(self):
        data = b'public-reference' * 512
        for kind, encoded in ((0, data), (1, bz2.compress(data)), (8, lzma.compress(data))):
            with self.subTest(kind=kind):
                self.assertEqual(decode_operation(kind, encoded, len(data)), data)

    def test_zero_and_discard(self):
        for kind in (6, 7):
            self.assertEqual(decode_operation(kind, b'', 4096), bytes(4096))
            with self.assertRaises(ValueError):
                decode_operation(kind, b'nonempty', 4096)

    def test_bad_or_oversized_compressed_operations(self):
        for kind, encoded in ((1, bz2.compress(b'abc')), (8, lzma.compress(b'abc'))):
            for data, size in ((encoded, 2), (encoded, 4), (encoded[:-1], 3), (encoded + b'x', 3)):
                with self.subTest(kind=kind, size=size), self.assertRaises((ValueError, EOFError)):
                    decode_operation(kind, data, size)

    def test_invalid_operation_types_and_lengths(self):
        for args in ((0, b'x', 2), (5, b'x', 1), (0, b'', 0), (0, b'', 100663297)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                decode_operation(*args)

    def test_extent_scatter_and_coverage(self):
        image, seen = bytearray(8), set()
        place(image, seen, [(1, 1), (0, 1)], b'abc12345', 4)
        self.assertEqual(image, b'2345abc1')
        self.assertEqual(seen, {0, 1})

    def test_extent_overlap_bounds_and_unused_data(self):
        for extents, data in (([(0, 1), (0, 1)], bytes(8)), ([(2, 1)], bytes(4)),
                              ([(-1, 1)], bytes(4)), ([(0, 0)], b''),
                              ([(0, 1)], bytes(3)), ([(0, 1)], bytes(5))):
            with self.subTest(extents=extents), self.assertRaises(ValueError):
                place(bytearray(8), set(), extents, data, 4)


class BootTests(unittest.TestCase):
    def boot(self, kernel=b'kernel', ramdisk=b'', signature=b'signed-region'):
        data = bytearray(16384)
        data[:8] = b'ANDROID!'
        struct.pack_into('<II', data, 8, len(kernel), len(ramdisk))
        struct.pack_into('<I', data, 20, 1584)
        struct.pack_into('<I', data, 40, 4)
        struct.pack_into('<I', data, 1580, len(signature))
        data[4096:4096 + len(kernel)] = kernel
        ramdisk_at = 4096 + (len(kernel) + 4095) // 4096 * 4096
        data[ramdisk_at:ramdisk_at + len(ramdisk)] = ramdisk
        signature_at = ramdisk_at + (len(ramdisk) + 4095) // 4096 * 4096
        data[signature_at:signature_at + len(signature)] = signature
        return data

    def test_v4_components_and_metadata(self):
        result = boot_layout(self.boot())
        self.assertEqual(result['kernel_sha256'], digest(b'kernel'))
        self.assertEqual(result['ramdisk_bytes'], 0)
        self.assertEqual(result['signature_sha256'], digest(b'signed-region'))
        changed = boot_layout(self.boot(kernel=b'new kernel'))
        self.assertEqual(result['header_metadata_sha256'], changed['header_metadata_sha256'])
        self.assertNotEqual(result['kernel_sha256'], changed['kernel_sha256'])

    def test_ramdisk_offsets(self):
        result = boot_layout(self.boot(ramdisk=b'ramdisk'))
        self.assertEqual(result['ramdisk_sha256'], digest(b'ramdisk'))
        self.assertEqual(result['signature_sha256'], digest(b'signed-region'))

    def test_corrupt_or_overflowing_headers(self):
        for field, value in ((8, 0), (8, 16384), (20, 100), (40, 3), (1580, 16384)):
            data = self.boot()
            struct.pack_into('<I', data, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                boot_layout(data)
        for data in (b'', bytes(4096), self.boot()[:100]):
            with self.assertRaises(ValueError):
                boot_layout(data)

    def test_avb_metadata_is_complete_and_exact(self):
        text = 'Public key (sha1): abc\nAlgorithm: SHA256_RSA4096\nFlags: 0\nRollback Index: 1\nRollback Index Location: 2\n'
        self.assertEqual(signing_metadata(text)['Rollback Index Location'], '2')
        for line in text.splitlines(keepends=True):
            with self.subTest(line=line), self.assertRaises(ValueError):
                signing_metadata(text.replace(line, ''))


class FailureReportTests(unittest.TestCase):
    def test_invalid_tool_identity_persists_blocked_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = assess(root, root / 'absent-image', root, root / 'reports')
            saved = json.loads((root / 'reports/boot-result.json').read_text())
            self.assertEqual(saved, result)
            self.assertEqual(saved['delivery_state'], 'BLOCKED')
            self.assertFalse(saved['offline_gate_passed'])
            self.assertEqual(saved['error']['stage'], 'input-identity')
            self.assertEqual(saved['scope']['unlocked_device_acceptance'], 'UNKNOWN')

    def test_real_failing_tool_output_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {'checks': {}}
            result = run_tool('failure', [sys.executable, '-c', 'print("actual tool failure"); raise SystemExit(7)'], root, root, report)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(report['checks']['failure']['returncode'], 7)
            self.assertIn('actual tool failure', (root / 'failure.txt').read_text())

    def test_timeout_partial_output_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {'checks': {}}
            with self.assertRaises(subprocess.TimeoutExpired):
                run_tool('timeout', [sys.executable, '-c', 'import time; print("started", flush=True); time.sleep(10)'],
                         root, root, report, timeout=0.2)
            self.assertTrue(report['checks']['timeout']['timed_out'])
            self.assertIn('started', (root / 'timeout.txt').read_text())

    def test_missing_executable_output_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {'checks': {}}
            with self.assertRaises(OSError):
                run_tool('missing', [str(root / 'nonexistent-command')], root, root, report)
            self.assertEqual(report['checks']['missing']['error_type'], 'FileNotFoundError')
            self.assertTrue((root / 'missing.txt').is_file())


@unittest.skipUnless(os.environ.get('BOOT_GATE_REFERENCE_BOOT') and os.environ.get('BOOT_GATE_AVBTOOL'),
                     'Real public-reference AVB integration runs only in CI after fetch')
class OfficialAVBTests(unittest.TestCase):
    def test_named_boot_descriptor_verifies_changed_file_not_stock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = Path(os.environ['BOOT_GATE_AVBTOOL']).resolve()
            boot = root / 'boot.img'
            shutil.copyfile(Path(os.environ['BOOT_GATE_REFERENCE_BOOT']).resolve(), boot)
            report = {'checks': {}}
            command = [sys.executable, str(tool), 'verify_image', '--image', str(boot)]
            self.assertEqual(run_tool('original', command, root, root, report).returncode, 0)
            with boot.open('r+b') as image:
                image.seek(4096)
                byte = image.read(1)
                image.seek(4096)
                image.write(bytes([byte[0] ^ 1]))
            self.assertNotEqual(run_tool('modified', command, root, root, report).returncode, 0)


if __name__ == '__main__':
    unittest.main()
