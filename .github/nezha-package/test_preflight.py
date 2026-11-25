import hashlib
import os
import re
import subprocess
from pathlib import Path
import struct
import tempfile
import unittest

import preflight

from preflight import ASSETS, IMAGE_SHA, TEMPLATE_SHA, arm64_header, assess, read_regular, template_policy

TEMPLATE = Path(__file__).with_name('anykernel.sh')


class PreflightTests(unittest.TestCase):
    def test_reviewed_template_identity_and_explicit_policy(self):
        data = TEMPLATE.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), TEMPLATE_SHA)
        result = template_policy(data.decode())
        self.assertEqual(result['patch_vbmeta_flag'], '0')
        self.assertEqual(result['slot_select'], 'active')
        self.assertEqual(result['expected_image'], IMAGE_SHA)

    def test_unsafe_or_ambiguous_policy_is_refused(self):
        original = TEMPLATE.read_text()
        for before, after in (
            ('do.devicecheck=1', 'do.devicecheck=0'),
            ('patch_vbmeta_flag=0', 'patch_vbmeta_flag=auto'),
            ('export PATCHVBMETAFLAG=false', 'export PATCHVBMETAFLAG=true'),
            ('slot_select=active', 'slot_select=inactive'),
            ('is_slot_device=1', 'is_slot_device=auto'),
            ('device.name2=', 'device.name2=other'),
            ('flash_boot', 'write_boot'),
        ):
            with self.subTest(setting=before), self.assertRaises(ValueError):
                template_policy(original.replace(before, after))
        with self.assertRaises(ValueError):
            template_policy(original + '\npatch_vbmeta_flag=1\n')

    def test_critical_settings_must_precede_core_import(self):
        text = TEMPLATE.read_text().replace('export NO_VBMETA_PARTITION_PATCH=1\n', '')
        with self.assertRaises(ValueError):
            template_policy(text + '\nexport NO_VBMETA_PARTITION_PATCH=1\n')

    def test_arm64_runtime_extent_is_not_file_length(self):
        data = bytearray(64)
        data[56:60] = b'ARMd'
        struct.pack_into('<QQQ', data, 8, 0, 47775744, 10)
        self.assertEqual(arm64_header(data)['runtime_image_bytes'], 47775744)
        for flags, runtime in ((12, 47775744), (10, 0)):
            struct.pack_into('<QQQ', data, 8, 0, runtime, flags)
            with self.assertRaises(ValueError):
                arm64_header(data)

    def test_regular_read_rejects_symlink_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = root / 'plain'
            plain.write_bytes(b'public input')
            self.assertEqual(read_regular(plain, 64), b'public input')
            (root / 'link').symlink_to(plain)
            os.mkfifo(root / 'fifo')
            for name, limit in (('link', 64), ('fifo', 64), ('plain', 2)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    read_regular(root / name, limit)

    def test_whitelist_contains_no_signer_or_extra_partition(self):
        self.assertEqual(set(ASSETS), {
            'LICENSE', 'META-INF/com/google/android/update-binary',
            'META-INF/com/google/android/updater-script', 'tools/ak3-core.sh',
            'tools/busybox', 'tools/magiskboot',
        })


    def test_vendor_patch_guard_rejects_absent_and_malformed_values(self):
        text = TEMPLATE.read_text()
        function = re.search(r'^vendor_patch_allowed\(\) \{\n.*?^\}', text, re.M | re.S)
        self.assertIsNotNone(function, 'Fail-closed vendor patch predicate missing')
        for value, expected in (('', False), ('2026-10', False), ('2026-10-00', False),
                                ('2026-09-01', False), ('2026-11-01', False),
                                ('2026-10-01\n2026-10-02', False),
                                ('2026-10-32', False), ('2026-10-01', True), ('2026-10-31', True)):
            script = function[0] + '\nvendor_patch_allowed "$1"\n'
            result = subprocess.run(['sh', '-c', script, 'guard', value], capture_output=True, timeout=5)
            self.assertEqual(result.returncode == 0, expected, value)

    def test_vendor_property_record_count_survives_shell_newline_trimming(self):
        function = re.search(r'^read_vendor_patch\(\) \{\n.*?^\}', TEMPLATE.read_text(), re.M | re.S)
        self.assertIsNotNone(function, 'Exact vendor property record count missing')
        key = 'ro.vendor.build.security_patch='
        rows = [(key + '2026-10-01\n', True),
                (key + '2026-10-01\n' + key + '\n', False),
                (key + '2026-10-01\n' + key + '2026-10-01\n', False),
                (key + '\n' + key + '2026-10-01\n', False), ('', False)]
        with tempfile.TemporaryDirectory() as tmp:
            prop = Path(tmp) / 'build.prop'
            for data, expected in rows:
                prop.write_text(data)
                result = subprocess.run(['sh', '-c', function[0] + '\nread_vendor_patch "$1"',
                                         'guard', str(prop)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, expected, data)



@unittest.skipUnless(os.environ.get('NEZHA_PASSED_IMAGE') and os.environ.get('NEZHA_AK3_ASSETS'),
                     'Exact passed Image and pinned public AK3 assets required')
class RealPayloadTests(unittest.TestCase):
    def test_exact_payload_validation_never_authorizes_release(self):
        result = assess(Path(os.environ['NEZHA_PASSED_IMAGE']), Path(os.environ['NEZHA_AK3_ASSETS']), TEMPLATE)
        self.assertEqual(result['status'], 'PAYLOAD_PREFLIGHT_ONLY')
        self.assertEqual(result['arm64']['runtime_image_bytes'], 47775744)
        self.assertFalse(result['release_authorized'])
        self.assertFalse(result['flashable_archive_created'])
        self.assertFalse(result['installer_executed'])

    def test_prepared_backend_never_archives_boot_or_recovery_logs(self):
        data = (Path(os.environ['NEZHA_AK3_ASSETS']) / 'META-INF/com/google/android/update-binary').read_bytes()
        result = preflight.prepare_backend(data)
        self.assertIn(b'debugging() { :; }', result)
        self.assertNotIn(b'tar -czf', result)
        begin, end = data.index(b'debugging() {\n'), data.index(b'cleanup() {\n')
        self.assertEqual(result, data[:begin] + b'debugging() { :; }\n' + data[end:])
        self.assertIn(b'restore_env', result)
        self.assertIn(b'do_devicecheck;', result)
        self.assertEqual(subprocess.run(['sh', '-n'], input=result, capture_output=True).returncode, 0)
        with self.assertRaises(ValueError):
            preflight.prepare_backend(data + b'\n')

    def test_altered_template_rejected_with_real_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp) / 'anykernel.sh'
            changed.write_text(TEMPLATE.read_text() + '\necho unexpected\n')
            with self.assertRaisesRegex(ValueError, 'Unreviewed installer'):
                assess(Path(os.environ['NEZHA_PASSED_IMAGE']), Path(os.environ['NEZHA_AK3_ASSETS']), changed)


if __name__ == '__main__':
    unittest.main()
