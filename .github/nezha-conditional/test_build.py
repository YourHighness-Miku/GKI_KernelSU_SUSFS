import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

from build import SELF, verify_archive


class ArchiveVerificationTests(unittest.TestCase):
    def test_real_assembly_refuses_a_non_actions_process_before_io(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('build.py')),
                                 '--image', '/nonexistent', '--assets', '/nonexistent',
                                 '--evidence', '/nonexistent', '--runs', '/nonexistent', '--output', '/nonexistent'],
                                env={'PATH': os.environ['PATH']}, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'GitHub Actions only', result.stderr)

    def test_real_nonexecutable_zip_fixtures_use_production_inventory_helpers(self):
        names = ('Image', 'anykernel.sh', 'LICENSE', 'tools/ak3-core.sh', 'tools/busybox',
                 'tools/magiskboot', 'META-INF/com/google/android/updater-script')
        payloads = {name: ('harmless fixture ' + name).encode() for name in names}
        pins = '\n'.join(f'{name} {len(data)} {hashlib.sha256(data).hexdigest()}'
                         for name, data in payloads.items())
        source = Path(__file__).resolve().parents[1] / 'nezha-package/update-binary'
        payloads[SELF] = source.read_bytes().replace(b'@PAYLOAD_PINS@', pins.encode()).replace(
            b'@REPACKED_BOOT_SHA@', b'a' * 64)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.zip'
            with zipfile.ZipFile(path, 'w', allowZip64=False) as archive:
                for name, data in payloads.items():
                    item = zipfile.ZipInfo(name)
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(item, data)
            result = verify_archive(path, payloads)
            self.assertFalse(result['installer_executed'])
            self.assertTrue(result['archive_helpers_validated_without_payload_execution'])
            self.assertEqual(set(result['members']), set(payloads))
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr('unwanted', b'x')
            with self.assertRaises(ValueError):
                verify_archive(path, payloads)


if __name__ == '__main__':
    unittest.main()
