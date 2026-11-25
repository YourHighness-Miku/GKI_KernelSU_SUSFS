import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
import warnings
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


BACKEND = Path(__file__).with_name('update-binary').resolve()
SELF = 'META-INF/com/google/android/update-binary'
FILES = {name: ('fixture ' + name).encode() for name in (
    'Image', 'anykernel.sh', 'LICENSE', 'tools/ak3-core.sh', 'tools/busybox',
    'tools/magiskboot', 'META-INF/com/google/android/updater-script')}
PINS = [f'{k} {len(v)} {hashlib.sha256(v).hexdigest()}' for k, v in FILES.items()]
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


class TestBackend(unittest.TestCase):
    shell = '/bin/sh'

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / '- fixture [0].zip'
        self.entries = [(SELF, b'not executable'), *reversed(FILES.items())]
        self.work = self.root / 'private'
        self.work.mkdir(mode=0o700)
        template = BACKEND.read_text()
        self.assertEqual(template.count('\n# entrypoint\n'), 1)
        self.helpers = template.split('\n# entrypoint\n')[0]
        self.assertEqual(self.helpers.count('\n@PAYLOAD_PINS@\n'), 1)

    def pack(self, entries):
        with warnings.catch_warnings(), ZipFile(self.archive, 'w', ZIP_DEFLATED) as output:
            warnings.filterwarnings('ignore', message='Duplicate name:')
            for name, content in entries:
                output.writestr(name, content)

    def run_helper(self, body, pins=PINS, cwd=None, boot_pin=None):
        defs = self.helpers.replace('@PAYLOAD_PINS@', '\n'.join(pins))
        if boot_pin is not None:
            defs = defs.replace('@REPACKED_BOOT_SHA@', boot_pin)
        return subprocess.run([self.shell, '-c', defs + '\nset -f\numask 077\n' + body,
                               'test', str(self.archive)], cwd=cwd or self.work, env=ENV,
                              capture_output=True, timeout=10)

    def verify(self):
        return self.run_helper('verify_payload "$1"')

    def test_valid_only_regular_nonexecutable_payload_files_remain(self):
        self.pack(self.entries)
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        extracted = {file.relative_to(self.work).as_posix(): file for file in self.work.rglob('*')
                     if file.is_file()}
        self.assertEqual(extracted.keys(), FILES.keys())
        for name, file in extracted.items():
            self.assertEqual(file.read_bytes(), FILES[name])
            self.assertFalse(file.is_symlink() or os.access(file, os.X_OK))


    def test_payload_verification_does_not_require_host_awk(self):
        self.pack(self.entries)
        system = self.root / 'system-tools'
        system.mkdir()
        for tool in ('cat', 'sort', 'cmp', 'stat', 'head', 'tail', 'od', 'mkdir', 'unzip', 'sha256sum', 'rm', 'printf'):
            (system / tool).symlink_to(shutil.which(tool))
        run = self.run_helper(f'PATH="{system}"; command -v awk >/dev/null && exit 9; verify_payload "$1"')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_encryption_and_invalid_directory_ranges_fail_before_extraction(self):
        for field in ('encrypted', 'wrong_signature', 'bad_span'):
            self.pack(self.entries)
            data = bytearray(self.archive.read_bytes())
            with ZipFile(self.archive) as archive:
                central = archive.start_dir
            if field == 'encrypted':
                data[central + 8] |= 1
            elif field == 'wrong_signature':
                data[central] = 0
            else:
                data[-10] ^= 1
            self.archive.write_bytes(data)
            destination = self.work / field
            destination.mkdir()
            run = self.run_helper('verify_payload "$1"', cwd=destination)
            self.assertNotEqual(run.returncode, 0, field)
            self.assertFalse((destination / 'tools').exists())

    def test_reentry_shell_selection_uses_available_regular_executables(self):
        normal = self.root / 'normal-sh'
        recovery = self.root / 'recovery-sh'
        for path in (normal, recovery):
            path.write_text('not executed')
            path.chmod(0o700)
        body = 'select_entry_shell "$1/normal-sh" "$1/recovery-sh"'
        run = self.run_helper(body.replace('$1', str(self.root)))
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout, str(normal).encode() + b'\n')
        normal.chmod(0o600)
        run = self.run_helper(body.replace('$1', str(self.root)))
        self.assertEqual(run.stdout, str(recovery).encode() + b'\n')
        recovery.unlink()
        self.assertNotEqual(self.run_helper(body.replace('$1', str(self.root))).returncode, 0)

    def test_bad_inventory_refused_before_payload_paths(self):
        for label, entries in {
            'duplicate': [('Image', b'duplicate'), *self.entries[1:]],
            'traversal': [('../escaped', b'escaped'), *self.entries[1:]],
            'extra': [*self.entries, ('unwanted', b'')],
            'directory': [('tools/', b''), *self.entries[1:]],
            'missing': self.entries[1:],
            'many': self.entries + [(str(i), b'') for i in range(300)],
            'long': [('A' * 6000, b''), *self.entries[1:]],
        }.items():
            with self.subTest(label=label):
                work = self.work / label
                work.mkdir()
                self.pack(entries)
                self.assertNotEqual(self.run_helper('verify_payload "$1"', cwd=work).returncode, 0)
                self.assertFalse((work / 'tools').exists())
                self.assertFalse((self.work / 'escaped').exists())

    def test_directory_or_link_attributes_without_trailing_slash(self):
        for i, attrs in enumerate([0x10, 0o040755 << 16, 0o120777 << 16]):
            with self.subTest(attrs=attrs):
                info = ZipInfo(SELF)
                info.create_system = 3
                info.external_attr = attrs
                self.pack([(info, b'not executable'), *self.entries[1:]])
                work = self.work / str(i)
                work.mkdir()
                self.assertNotEqual(self.run_helper('verify_payload "$1"', cwd=work).returncode, 0)
                self.assertFalse((work / 'tools').exists())

    def test_literal_inventory_not_zipinfo_display(self):
        self.pack([(SELF + 'XX', b'not executable'), *self.entries[1:]])
        self.archive.write_bytes(self.archive.read_bytes().replace(
            SELF.encode() + b'XX', SELF.encode() + b'\x00X'))
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertFalse((self.work / 'Image').exists())

    def test_hash_and_short_content(self):
        for i, value in enumerate([b'Z' * len(FILES['Image']), FILES['Image'][:-1]]):
            with self.subTest(value=value):
                work = self.work / str(i)
                work.mkdir()
                self.pack([(n, value if n == 'Image' else v) for n, v in self.entries])
                self.assertNotEqual(self.run_helper('verify_payload "$1"', cwd=work).returncode, 0)
                self.assertEqual((work / 'Image').read_bytes(), value)
                self.assertFalse((work / 'anykernel.sh').exists())

    def test_expansion_bounded_even_with_correct_prefix(self):
        image = FILES['Image'] + b'X' * (4 * 1024**2)
        self.pack([(n, image if n == 'Image' else v) for n, v in self.entries])
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertEqual((self.work / 'Image').stat().st_size, len(FILES['Image']) + 1)
        self.assertFalse((self.work / 'anykernel.sh').exists())

    def test_reject_unzip_error_after_valid_data(self):
        self.pack(self.entries)
        data = bytearray(self.archive.read_bytes())
        # Info-ZIP emits valid bytes but returns a warning for mismatched names.
        with ZipFile(self.archive) as source:
            off = source.getinfo('Image').header_offset + 30
        self.assertEqual(data[off:off + 5], b'Image')
        data[off:off + 5] = b'imAge'
        self.archive.write_bytes(data)
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertEqual((self.work / 'Image').read_bytes(), FILES['Image'])
        self.assertFalse((self.work / 'anykernel.sh').exists())

    def test_strict_pin_rows(self):
        for i, rows in enumerate([
            PINS[:-1], PINS + PINS[:1], [PINS[1], *PINS[1:]],
            *[[row, *PINS[1:]] for row in (
                ' ' + PINS[0], PINS[0] + ' ', PINS[0].replace(' ', '\t'),
                PINS[0].replace('Image', '../Image'), PINS[0].replace('13', '013', 1),
                PINS[0].replace('13', '0', 1), PINS[0][:-1], PINS[0].upper(),
                PINS[0].replace('13', '44603905', 1), PINS[0] + ' ignored',
                '$(touch BAD) 1 ' + 'f' * 64)],
            [PINS[0], 'anykernel.sh 2097152 ' + '0' * 64, *PINS[2:]],
        ]):
            with self.subTest(rows=rows):
                work = self.work / str(i)
                work.mkdir()
                result = self.run_helper('mkdir .check && payload_pins > .check/pins && validate_pins',
                                         rows, work)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((work / 'BAD').exists())

    def test_boot_pin_must_be_rendered(self):
        self.assertEqual(self.helpers.count('@REPACKED_BOOT_SHA@'), 1)
        for pin in [None, '', 'a' * 63, 'a' * 65, 'A' * 64, 'f' * 63 + 'g']:
            with self.subTest(pin=pin):
                self.assertNotEqual(self.run_helper('load_boot_pin', boot_pin=pin).returncode, 0)
        digest = hashlib.sha256(b'expected repack fixture').hexdigest()
        result = self.run_helper('load_boot_pin && printf %s "$EXPECTED_REPACKED_SHA256"',
                                 boot_pin=digest)
        self.assertEqual((result.returncode, result.stdout), (0, digest.encode()))

    def test_cleanup_preserves_exit_and_removes_only_private_tree(self):
        for action, status in [('exit 37', 37), ('kill -TERM $$', 143), ('kill -HUP $$', 129),
                               ('kill -INT $$', 130)]:
            with self.subTest(action=action):
                keep = self.work / 'keep'
                keep.touch()
                result = self.run_helper('AKHOME=$PWD; enter_workdir "$PWD" || exit 3; '
                                         'mkdir bin && : > bin/private || exit 4; ' + action)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(list(self.work.iterdir()), [keep])

    def test_owned_child_status_without_cancellation(self):
        for rc in [0, 37, 143]:
            with self.subTest(rc=rc):
                result = self.run_helper(f'enter_workdir "$PWD" && run_owned /bin/sh -c "exit {rc}"')
                self.assertEqual(result.returncode, rc, result.stderr)
                self.assertEqual(list(self.work.iterdir()), [])

    def exercise_gate(self, child_first, first_signal):
        child = """
            if [ "$2" = committed ]; then mkdir write-gate || exit 11; fi
            : > "$1/ready"
            while [ ! -f "$1/release" ]; do sleep 0.01; done
            [ -f cancel-requested ] && [ -d write-gate ] || exit 12
            if [ "$2" = committed ] || mkdir write-gate 2>/dev/null; then
                outcome=committed
            else
                outcome=blocked
            fi
            printf '%s' "$outcome" > "$1/result"
            exit 23
        """
        expected = 'committed' if child_first else 'blocked'
        control = self.root / f'{expected}-{first_signal}'
        control.mkdir()
        body = 'umask 077; enter_workdir "$PWD" && run_owned /bin/sh -c "$1" child "$2" "$3"'
        with subprocess.Popen([self.shell, '-c', self.helpers + '\n' + body, 'parent', child,
                               control, expected], env=ENV, cwd=self.work) as parent:
            def await_file(path):
                deadline = time.monotonic() + 5
                while not path.is_file():
                    self.assertIsNone(parent.poll(), f'parent exited before {path.name}')
                    self.assertLess(time.monotonic(), deadline, f'timed out waiting for {path.name}')
                    time.sleep(0.01)

            try:
                await_file(control / 'ready')
                home, = self.work.iterdir()
                self.assertEqual((home / 'write-gate').exists(), child_first)
                parent.send_signal(first_signal)
                await_file(home / 'cancel-requested')
                self.assertTrue((home / 'write-gate').is_dir())
                for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
                    parent.send_signal(sig)
                with self.assertRaises(subprocess.TimeoutExpired):
                    parent.wait(timeout=0.1)
                self.assertTrue(home.is_dir())
            finally:
                (control / 'release').touch()
                parent.wait(timeout=5)
        self.assertEqual(parent.returncode, 128 + first_signal)
        self.assertEqual((control / 'result').read_text(), expected)
        self.assertFalse(home.exists())

    def test_parent_cancellation_wins_gate(self):
        for sig in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
            with self.subTest(sig=sig):
                self.exercise_gate(False, sig)

    def test_parent_cancellation_waits_out_committed_child(self):
        self.exercise_gate(True, signal.SIGTERM)

    def test_replaced_workdir_not_removed(self):
        result = self.run_helper('enter_workdir "$PWD" && mv "$AKHOME" "$AKHOME.old" && '
                                 'mkdir "$AKHOME" && : > "$AKHOME/keep"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list(self.work.glob('nezha.*/keep'))), 1)

    def test_size_and_type_gate(self):
        with self.archive.open('wb') as stream:
            stream.truncate(64 * 1024**2)
        self.assertEqual(self.run_helper('zip_size "$1"').returncode, 0)
        with self.archive.open('ab') as stream:
            stream.write(b'X')
        self.assertNotEqual(self.run_helper('zip_size "$1"').returncode, 0)
        self.archive.unlink()
        self.archive.symlink_to(BACKEND)
        self.assertNotEqual(self.run_helper('zip_size "$1"').returncode, 0)

    @unittest.skipIf(os.uname().machine == 'aarch64', 'only probe failure on a non-target host')
    def test_non_target_fails_closed(self):
        self.pack(self.entries)
        self.assertNotEqual(self.run_helper('check_platform').returncode, 0)
        env = {**ENV, 'AKHOME': str(self.work)}
        sentinel = self.work / 'keep'
        sentinel.touch()
        result = subprocess.run([self.shell, BACKEND, '3', '1', self.archive],
                                env=env, cwd=self.work, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.work.iterdir()), [sentinel])


if __name__ == '__main__':
    unittest.main()
