import os
from pathlib import Path
import subprocess
import tempfile
import unittest


BACKEND = Path(__file__).with_name('update-binary')


class InvocationTests(unittest.TestCase):
    def run_parse(self, args):
        definitions = BACKEND.read_text().split('\n# entrypoint\n')[0]
        body = definitions + '\nparse_invocation "$@" || exit $?\nprintf "%s\\n" "$OUTFD" "$ZIPFILE" "$REQUESTED_SLOT"\n'
        return subprocess.run(['/bin/sh', '-c', body, 'nova-call', *args],
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=5)

    def test_standard_and_nova_slot_arguments_reach_the_same_protocol(self):
        for suffix, expected in (((), b''), (('a',), b'_a'), (('b',), b'_b')):
            run = self.run_parse(('3', '1', '/private test/kernel.zip', *suffix))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.splitlines(), [b'1', b'/private test/kernel.zip', expected])

    def test_invalid_arity_protocol_descriptor_and_slot_are_visible(self):
        cases = [(), ('3', '1'), ('2', '1', '/kernel.zip'), ('3', 'x', '/kernel.zip'),
                 ('3', '0', '/kernel.zip'), ('3', '001', '/kernel.zip'), ('3', '256', '/kernel.zip'),
                 ('3', '1', ''), ('3', '1', '/kernel.zip', ''), ('3', '1', '/kernel.zip', '_a'),
                 ('3', '1', '/kernel.zip', 'auto'), ('3', '1', '/kernel.zip', 'a', 'ignored')]
        for args in cases:
            with self.subTest(args=args):
                run = self.run_parse(args)
                self.assertNotEqual(run.returncode, 0)
                visible = [line for line in run.stderr.splitlines() if line.startswith(b'ui_print')]
                self.assertTrue(visible, run.stderr)
                self.assertNotIn(b'/kernel.zip', run.stderr)

    def test_relative_path_is_preserved_without_shell_evaluation(self):
        name = 'a $(touch MUST_NOT_EXIST).zip'
        with tempfile.TemporaryDirectory() as tmp:
            definitions = BACKEND.read_text().split('\n# entrypoint\n')[0]
            result = subprocess.run(['/bin/sh', '-c', definitions + '\nparse_invocation "$@" || exit $?\nprintf "%s" "$ZIPFILE"',
                                     'nova-call', '3', '1', name], cwd=tmp,
                                    env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, os.fsencode(str(Path(tmp) / name)))
            self.assertFalse((Path(tmp) / 'MUST_NOT_EXIST').exists())


    def test_actual_clean_reentry_preserves_nova_arguments_and_removes_inheritance(self):
        definitions = BACKEND.read_text().split('\n# entrypoint\n')[0]
        with tempfile.TemporaryDirectory() as tmp:
            entry = Path(tmp) / 'harmless entry.sh'
            entry.write_text(definitions + '\nparse_invocation "$@" || exit $?\n'
                             'printf "%s\\n" "$0" "$REQUESTED_SLOT" "${INHERITED_SENTINEL:-absent}" "${POSTINSTALL:-absent}"\n')
            command = definitions + '\nclean_reentry /usr/bin/env /bin/sh "$1" 3 1 "$2" b'
            run = subprocess.run(['/bin/sh', '-c', command, 'nova', str(entry), '/a path/kernel.zip'],
                                 env={'PATH': '/usr/bin:/bin', 'INHERITED_SENTINEL': 'must disappear',
                                      'POSTINSTALL': '/untrusted/inherited'}, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.splitlines(), [b'nezha-clean/', b'_b', b'absent', b'absent'])

    def test_requested_slot_never_overrides_the_raw_boot_slot(self):
        source = BACKEND.with_name('anykernel.sh').read_text().split('\n# entrypoint\n')[0]
        for requested, raw, accepted in (('', '_a', True), ('_a', '_a', True), ('_b', '_b', True),
                                         ('_b', '_a', False), ('_a', '_b', False), ('bad', '_a', False),
                                         ('', '', False)):
            run = subprocess.run(['/bin/sh', '-c', source + '\nrequested_slot_allowed "$@"',
                                  'slot', requested, raw], capture_output=True, timeout=5)
            self.assertEqual(run.returncode == 0, accepted, (requested, raw, run.stderr))


if __name__ == '__main__':
    unittest.main()
