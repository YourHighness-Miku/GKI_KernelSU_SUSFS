import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from delivery import HOLD, delivery_status, require_delivery_approval


class DeliveryBoundaryTests(unittest.TestCase):
    def test_reviewed_stock_evidence_cannot_authorize_an_unknown_modified_chain(self):
        status = delivery_status()
        self.assertEqual(status['status'], HOLD)
        for key in ('candidate_delivery_allowed', 'hardware_boot_verified',
                    'bootchain_profile_verified', 'original_content_authentication_passed'):
            self.assertIs(status[key], False)
        with self.assertRaisesRegex(ValueError, HOLD):
            require_delivery_approval()

    def test_direct_actions_builder_refuses_before_input_or_output_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = [sys.executable, str(Path(__file__).with_name('build.py'))]
            for flag in ('image', 'assets', 'evidence', 'runs', 'output'):
                command.extend(['--' + flag, str(root / flag)])
            env = {**os.environ, 'GITHUB_ACTIONS': 'true',
                   'GITHUB_REPOSITORY': 'YourHighness-Miku/GKI_KernelSU_SUSFS',
                   'GITHUB_REF': 'refs/heads/fix/nezha-r74-binder-baseline'}
            result = subprocess.run(command, env=env, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(HOLD.encode(), result.stderr)
            self.assertEqual(list(root.iterdir()), [])

    def test_hold_report_is_not_an_installable_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'report.json'
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('delivery.py')),
                                     '--output', str(output)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text()), delivery_status())
            self.assertEqual(list(Path(tmp).iterdir()), [output])


if __name__ == '__main__':
    unittest.main()
