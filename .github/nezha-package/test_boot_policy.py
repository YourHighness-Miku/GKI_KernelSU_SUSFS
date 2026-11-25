from pathlib import Path
import subprocess
import unittest


SOURCE = Path(__file__).with_name('anykernel.sh')


class BootPolicyTests(unittest.TestCase):
    def call(self, name, values):
        definitions = SOURCE.read_text().split('\n# entrypoint\n')[0]
        return subprocess.run(['/bin/sh', '-c', definitions + '\n' + name + ' "$@"',
                               'observations', *values], env={'PATH': '/usr/bin:/bin'},
                              capture_output=True, timeout=5)

    def test_observations_are_classified_without_claiming_hardware_lock_state(self):
        for values, expected in (
            (('0', 'unlocked', '0', 'unlocked'), b'reported_unlocked_consistent'),
            (('1', 'locked', '', 'locked'), b'reported_locked_or_masked'),
            (('1', 'locked', '1', 'locked'), b'reported_locked_or_masked'),
            (('0', 'unlocked', '', 'unlocked'), b'unverified_or_conflicting'),
            (('0', 'unlocked', '1', 'locked'), b'unverified_or_conflicting'),
        ):
            with self.subTest(values=values):
                result = self.call('boot_policy_class', values)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_user_reported_masked_tuple_is_not_device_or_slot_failure(self):
        result = self.call('require_supported_policy_values', ('1', 'locked', '', 'locked'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'ui_print Nezha[E_BOOT_POLICY_UNVERIFIED]', result.stderr)
        self.assertNotIn(b'E_BOOT_STATE', result.stderr)
        self.assertNotIn(b'E_SLOT', result.stderr)

    def test_unknown_profile_is_not_implicitly_authorized_by_root_or_locked(self):
        for values in (('1', 'locked', '', 'locked'), ('', '', '', ''),
                       ('PRIVATE_VALUE', 'locked', '', 'locked')):
            result = self.call('require_supported_policy_values', values)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'PRIVATE_VALUE', result.stdout + result.stderr)
        result = self.call('require_supported_policy_values', ('0', 'unlocked', '0', 'unlocked'))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
