import json
import os
from pathlib import Path
import tempfile
import unittest

from abl_policy import ABL_SHA, PE_SHA, conditional_continuation, fixed_efi, inspect, publish, sha


class PublicABLPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = Path(os.environ['ABL_REFERENCE']).read_bytes()

    def test_real_public_container_and_executable_identity(self):
        self.assertEqual(sha(self.data), ABL_SHA)
        self.assertEqual(sha(fixed_efi(self.data)), PE_SHA)

    def test_real_instruction_and_enum_evidence(self):
        report = inspect(self.data)
        self.assertEqual(report['conditional_unlocked_nonfatal_results'],
                         ['OK', 'ERROR_VERIFICATION', 'ERROR_ROLLBACK_INDEX', 'ERROR_PUBLIC_KEY_REJECTED'])
        self.assertEqual(report['conditional_locked_nonfatal_results'], ['OK'])
        self.assertFalse(report['installable_package_authorized'])
        self.assertEqual(report['hardware_boot'], 'UNKNOWN')

    def test_modified_and_truncated_public_input_rejected(self):
        for data in (b'', self.data[:-1], self.data[:50] + bytes([self.data[50] ^ 1]) + self.data[51:]):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                inspect(data)

    def test_result_table_inference_keeps_nonverification_errors_fatal(self):
        for unlocked in (False, True):
            for result in range(-1, 11):
                for loaded in (False, True):
                    with self.subTest(unlocked=unlocked, result=result, loaded=loaded):
                        expected = loaded and result in ((0, 3, 4, 5) if unlocked else (0,))
                        self.assertEqual(conditional_continuation(unlocked, result, loaded), expected)

    def test_report_publishes_once_without_stale_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'policy.json'
            publish({'artifact_sha256': ABL_SHA}, output)
            before = output.read_bytes()
            self.assertEqual(json.loads(before)['artifact_sha256'], ABL_SHA)
            with self.assertRaises(ValueError):
                publish({'different': True}, output)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_report_refuses_dangling_symlink_without_writing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'policy.json'
            target = Path(directory) / 'absent.json'
            output.symlink_to(target)
            with self.assertRaises(FileExistsError):
                publish({}, output)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [output])



if __name__ == '__main__':
    unittest.main()
