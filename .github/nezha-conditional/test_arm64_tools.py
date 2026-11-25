"""Offline capability tests; only the authenticated BusyBox is run under QEMU."""

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parents[1] / 'nezha-package'
# Raw tools/ entries from nezha-package/preflight.py:ASSETS.
TOOLS = {
    'busybox': (1498688, 'c629fce4b0dd3ba9775f851d0941e74582115f423258d3a79800f2bd11d30f5c'),
    'magiskboot': (1015160, '4c480c9ffc51b4b9d8c3760bb188fd1eb73972a90983963ef791bca6faa65d6c'),
}


class TestArm64Tools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qemu = shutil.which('qemu-aarch64')
        assets = os.environ.get('NEZHA_AK3_ASSETS')
        if not cls.qemu or not assets:
            reason = 'requires qemu-aarch64 and NEZHA_AK3_ASSETS'
            if os.environ.get('CI') == 'true':
                raise RuntimeError(reason)
            raise unittest.SkipTest(reason)

        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.bb = Path(temp.name) / 'busybox'
        for name, (size, digest) in TOOLS.items():
            data = (Path(assets) / 'tools' / name).read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise AssertionError(f'{name}: raw asset size or digest mismatch')
            if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183:
                raise AssertionError(f'{name}: expected ELF64 LE AArch64')
            if name == 'busybox':
                cls.bb.write_bytes(data)
                cls.bb.chmod(0o500)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name).resolve()

    def run_bb(self, app, *args, input=None, status=0):
        result = subprocess.run([self.qemu, self.bb, app, *args], cwd=self.work,
                                env={'PATH': str(self.work / 'no-host-tools'), 'LC_ALL': 'C'},
                                input=b'' if input is None else input, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, status, (app, result.stderr))
        return result.stdout

    def helper(self, name, source='anykernel.sh'):
        definitions = (PACKAGE / source).read_text().split('\n# entrypoint\n', 1)[0]
        matches = re.findall(rf'^{name}\(\) \{{\n.*?^\}}$', definitions, re.M | re.S)
        self.assertEqual(len(matches), 1, name)
        return matches[0]

    def test_shell_syntax_and_pipefail(self):
        for script in ('anykernel.sh', 'update-binary'):
            with self.subTest(script=script):
                self.run_bb('sh', '-n', input=(PACKAGE / script).read_bytes())
        self.run_bb('ash', '-c', 'set -o pipefail || exit 2; false | true', status=1)

    def test_link_resolution_and_stat(self):
        target = self.work / 'ordinary file'
        target.touch()
        link = self.work / 'alias'
        link.symlink_to(target.name)
        self.assertEqual(self.run_bb('readlink', '-f', link), os.fsencode(target) + b'\n')
        self.assertEqual(self.run_bb('stat', '-L', '-c', '%t:%T', link), b'0:0\n')

    def test_partition_and_boot_record_awk(self):
        # Pass the production awk programs directly as argv, not via ash's PATH.
        label = self.helper('partition_label')
        record = self.helper('boot_record')
        key = 'androidboot.slot_suffix'
        programs = {}
        for mode, source, prefix, flags in (
                ('label', label, 'awk -F=', ['-F=']),
                ('config', record, 'config)\n      awk -v key="$2"', ['-v', f'key={key}']),
                ('cmdline', record, 'cmdline)\n      awk -v key="$2"', ['-v', f'key={key}'])):
            match = re.search(re.escape(prefix) + r''' '([^']+)' "\$1"''', source)
            self.assertIsNotNone(match, mode)
            programs[mode] = [*flags, match[1]]

        fixture = self.work / 'input records'
        for mode, text, expected, status in (
                ('label', 'MAJOR=1\nPARTNAME=boot_b', b'boot_b\n', 0),
                ('label', 'PARTNAME=boot_a\nPARTNAME=boot_b', b'', 1),
                ('config', f'{key} = "_a"', b'_a\n', 0),
                ('config', f'{key} = "_a"\n{key} = "_a"', b'', 1),
                ('cmdline', f'other=1 {key}=_b', b'_b\n', 0),
                ('cmdline', f'other=1 {key}=', b'', 1)):
            with self.subTest(mode=mode, text=text):
                fixture.write_text(text + '\n')
                self.assertEqual(self.run_bb('awk', *programs[mode], fixture, status=status), expected)

    def test_builtin_slot_and_unlock_checks(self):
        for name, args, status in (
                ('slots_agree', ('_a', '_a', ''), 0),
                ('slots_agree', ('_b', '_b', 'b'), 0),
                ('slots_agree', ('_a', '_b', ''), 1),
                ('slots_agree', ('_b', '_b', 'a'), 1),
                ('unlocked_values_allowed', ('0', 'unlocked', '0', 'unlocked'), 0),
                ('unlocked_values_allowed', ('0', 'unlocked', '1', 'locked'), 1)):
            with self.subTest(name=name, args=args):
                body = self.helper(name) + f'\n{name} "$@"'
                self.run_bb('ash', '-c', body, 'test', *args, status=status)

    def test_normal_and_recovery_shell_selection(self):
        normal = self.work / 'normal-sh'
        recovery = self.work / 'recovery-sh'
        for path in (normal, recovery):
            path.write_text('never executed')
            path.chmod(0o500)
        body = self.helper('select_entry_shell', 'update-binary') + '\nselect_entry_shell "$@"'
        self.assertEqual(self.run_bb('ash', '-c', body, 'test', normal, recovery), os.fsencode(normal) + b'\n')
        normal.chmod(0o400)
        self.assertEqual(self.run_bb('ash', '-c', body, 'test', normal, recovery), os.fsencode(recovery) + b'\n')
        recovery.unlink()
        self.run_bb('ash', '-c', body, 'test', normal, recovery, status=1)

    def test_regular_file_copy_hash_and_count(self):
        data = bytes(range(256)) * 4096 + b'partial final block'
        (self.work / 'input').write_bytes(data)
        self.run_bb('dd', 'if=input', 'of=copy', 'bs=1048576', 'conv=fsync')
        copied = (self.work / 'copy').read_bytes()
        self.assertEqual(copied, data)
        digest = hashlib.sha256(data).hexdigest().encode()
        self.assertEqual(self.run_bb('sha256sum', 'copy'), digest + b'  copy\n')
        self.assertEqual(self.run_bb('wc', '-c', input=copied).strip(), str(len(data)).encode())

    def test_read_only_prefixes(self):
        data = b'A' * 4096 + b'B' * 4096 + b'ignored suffix'
        source = self.work / 'input'
        source.write_bytes(data)
        source.chmod(0o400)
        prefix = self.run_bb('dd', 'if=input', 'bs=4096', 'count=2')
        self.assertEqual(prefix, data[:8192])
        digest = hashlib.sha256(prefix).hexdigest().encode()
        self.assertEqual(self.run_bb('sha256sum', input=prefix), digest + b'  -\n')
        self.assertEqual(self.run_bb('head', '-c', '4097', source), data[:4097])
        self.assertEqual(source.read_bytes(), data)

    def test_gate_exclusion_and_shell_cleanup(self):
        self.run_bb('mkdir', 'gate')
        self.run_bb('mkdir', 'gate', status=1)
        self.assertTrue((self.work / 'gate').is_dir())
        body = '''trap 'printf "reaped:%s\\n" "$?"' 0
                  (exit 7) & child=$!
                  wait "$child"'''
        self.assertEqual(self.run_bb('ash', '-c', body, status=7), b'reaped:7\n')


if __name__ == '__main__':
    unittest.main()
