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

    def test_only_consistent_explicit_unlocked_values_are_accepted(self):
        function = re.search(r'^unlocked_values_allowed\(\) \{\n.*?^\}', TEMPLATE.read_text(), re.M | re.S)
        self.assertIsNotNone(function)
        for values, expected in ((('0', 'unlocked', '0', 'unlocked'), True),
                                 (('1', 'locked', '1', 'locked'), False),
                                 (('0', 'unlocked', '1', 'locked'), False),
                                 (('0', 'unlocked', '', ''), False),
                                 (('0', 'orange', '0', 'unlocked'), False)):
            run = subprocess.run(['sh', '-c', function[0] + '\nunlocked_values_allowed "$@"',
                                  'guard', *values], capture_output=True, timeout=5)
            self.assertEqual(run.returncode == 0, expected, values)

    def test_real_boot_record_files_reject_duplicate_and_malformed_values(self):
        function = re.search(r'^boot_record\(\) \{\n.*?^\}', TEMPLATE.read_text(), re.M | re.S)
        self.assertIsNotNone(function)
        cases = [('config', 'androidboot.flash.locked = "0"\n', True, b'0\n'),
                 ('config', 'androidboot.flash.locked = "0"\nandroidboot.flash.locked = ""\n', False, b''),
                 ('config', 'androidboot.flash.locked = "0" extra\n', False, b''),
                 ('config', 'androidboot.flash.locked = ""\n', False, b''),
                 ('cmdline', 'androidboot.flash.locked=\n', False, b''),
                 ('cmdline', 'x=y androidboot.flash.locked=0\n', True, b'0\n'),
                 ('cmdline', 'androidboot.flash.locked=0 androidboot.flash.locked=0\n', False, b'')]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'boot-record'
            for kind, text, success, output in cases:
                path.write_text(text)
                run = subprocess.run(['sh', '-c', function[0] + '\nboot_record "$@"', 'guard',
                                      str(path), 'androidboot.flash.locked', kind],
                                     capture_output=True, timeout=5)
                self.assertEqual(run.returncode == 0, success, text)
                if success:
                    self.assertEqual(run.stdout, output)

    def test_kernel_partition_labels_are_exact_single_records(self):
        function = re.search(r'^partition_label\(\) \{\n.*?^\}', TEMPLATE.read_text(), re.M | re.S)
        self.assertIsNotNone(function)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'uevent'
            for text, success in (('MAJOR=8\nPARTNAME=boot_a\n', True),
                                  ('PARTNAME=boot_a\nPARTNAME=boot_b\n', False),
                                  ('PARTNAME=boot_a=other\n', False), ('PARTNAME=\n', False)):
                path.write_text(text)
                run = subprocess.run(['sh', '-c', function[0] + '\npartition_label "$1"',
                                      'guard', str(path)], capture_output=True, timeout=5)
                self.assertEqual(run.returncode == 0, success, text)
                if success:
                    self.assertEqual(run.stdout, b'boot_a\n')

    def test_active_slot_sources_must_agree(self):
        function = re.search(r'^slots_agree\(\) \{\n.*?^\}', TEMPLATE.read_text(), re.M | re.S)
        self.assertIsNotNone(function)
        for values, expected in ((('_a', '_a', 'a'), True), (('_b', '_b', ''), True),
                                 (('_a', '_b', 'b'), False), (('_a', '_a', 'b'), False),
                                 (('', '_a', 'a'), False), (('a', 'a', 'a'), False)):
            run = subprocess.run(['sh', '-c', function[0] + '\nslots_agree "$@"',
                                  'guard', *values], capture_output=True, timeout=5)
            self.assertEqual(run.returncode == 0, expected, values)

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
        self.assertEqual(result, TEMPLATE.with_name('update-binary').read_bytes())
        for forbidden in (b'tar -czf', b'setup_env', b'mount_all', b'restore_env', b'setprop'):
            self.assertNotIn(forbidden, result)
        self.assertEqual(result.count(b'@PAYLOAD_PINS@'), 1)
        self.assertEqual(result.count(b'@REPACKED_BOOT_SHA@'), 1)
        self.assertIn(b'env -i AKHOME=', result)
        self.assertEqual(subprocess.run(['sh', '-n'], input=result, capture_output=True).returncode, 0)
        with self.assertRaises(ValueError):
            preflight.prepare_backend(data + b'\n')

    def test_backend_rendering_requires_exact_payload_set_and_golden_digest(self):
        assets = Path(os.environ['NEZHA_AK3_ASSETS'])
        raw = (assets / 'META-INF/com/google/android/update-binary').read_bytes()
        pins = {name: (size, digest) for name, (digest, size) in ASSETS.items()
                if name != 'META-INF/com/google/android/update-binary'}
        core = preflight.prepare_core((assets / 'tools/ak3-core.sh').read_bytes())
        pins['tools/ak3-core.sh'] = (len(core), hashlib.sha256(core).hexdigest())
        pins['Image'] = (44603904, IMAGE_SHA)
        pins['anykernel.sh'] = (TEMPLATE.stat().st_size, TEMPLATE_SHA)
        rendered = preflight.prepare_backend(raw, pins, 'a' * 64)
        self.assertNotIn(b'@PAYLOAD_PINS@', rendered)
        self.assertNotIn(b'@REPACKED_BOOT_SHA@', rendered)
        self.assertIn(b"EXPECTED_REPACKED_SHA256='" + b'a' * 64 + b"'", rendered)
        for digest in (None, '', 'g' * 64):
            with self.assertRaises(ValueError):
                preflight.prepare_backend(raw, pins, digest)
        with self.assertRaises(ValueError):
            preflight.prepare_backend(raw, dict(pins, unwanted=(1, 'b' * 64)), 'a' * 64)

    def test_core_derivation_changes_only_writer_and_private_temp_path(self):
        data = (Path(os.environ['NEZHA_AK3_ASSETS']) / 'tools/ak3-core.sh').read_bytes()
        result = preflight.prepare_core(data)
        begin = data.index(b'  blockdev --setrw $BLOCK 2>/dev/null;\n')
        end = data.index(b'\n}\n\n# flash_generic')
        restored_temp = result.replace(b'    tmpfile="$AKHOME/ak3decomp"\n',
                                       b'    tmpfile="${target}_ak3decomp"\n')
        self.assertEqual(restored_temp, data[:begin] +
                         b'  nezha_write_verified || abort "Verified write failed.";\n' + data[end:])
        flash = result.split(b'flash_boot() {', 1)[1].split(b'# flash_generic', 1)[0]
        self.assertNotIn(b'dd if=/dev/zero', flash)
        self.assertNotIn(b'blockdev --setrw', flash)
        self.assertEqual(subprocess.run(['sh', '-n'], input=result, capture_output=True).returncode, 0)
        with self.assertRaises(ValueError):
            preflight.prepare_core(data + b'\n')

    def test_altered_template_rejected_with_real_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp) / 'anykernel.sh'
            changed.write_text(TEMPLATE.read_text() + '\necho unexpected\n')
            with self.assertRaisesRegex(ValueError, 'Unreviewed installer'):
                assess(Path(os.environ['NEZHA_PASSED_IMAGE']), Path(os.environ['NEZHA_AK3_ASSETS']), changed)


if __name__ == '__main__':
    unittest.main()
