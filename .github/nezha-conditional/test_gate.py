import copy
import json
from pathlib import Path
import tempfile
import unittest

from gate import FIXTURE_SHA, PRODUCERS, evaluate, load_bound, validate_runs

FIXTURES = Path(__file__).with_name('fixtures')


class ConditionalGateTests(unittest.TestCase):
    def setUp(self):
        self.evidence = load_bound(FIXTURES)

    def test_real_reviewed_reports_only_authorize_conditional_packaging(self):
        result = evaluate(self.evidence)
        self.assertTrue(result['conditional_zip_eligible'])
        for key in ('original_content_authentication_passed', 'original_boot_report_rewritten',
                    'raw_global_module_audit_passed', 'hardware_boot_verified'):
            self.assertIs(result[key], False)
        self.assertEqual(result['required_window_bytes'], 76816384)
        self.assertEqual(result['provider_margin_bytes'], 191619072)
        self.assertFalse(self.evidence['boot-result.json']['offline_gate_passed'])

    def test_any_other_tool_error_timeout_or_unknown_check_is_rejected(self):
        for kind in ('io', 'timeout', 'extra', 'missing', 'code', 'error'):
            evidence = copy.deepcopy(self.evidence)
            boot = evidence['boot-result.json']
            if kind == 'io':
                boot['checks']['unpack']['returncode'] = 1
            elif kind == 'timeout':
                boot['checks']['repacked-boot-verify'] = {'returncode': None, 'timed_out': True}
            elif kind == 'extra':
                boot['checks']['unexpected'] = {'returncode': 0}
            elif kind == 'missing':
                del boot['checks']['stock-boot-verify']
            elif kind == 'code':
                boot['checks']['repacked-boot-verify']['returncode'] = 2
            else:
                boot['error'] = {'message': 'Cannot read image'}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                evaluate(evidence)

    def test_verifier_text_is_not_a_broad_error_waiver(self):
        original = self.evidence['repacked-boot-verify.txt']
        for text in (original + 'I/O error\n', original.replace('Successfully verified', 'Failed to verify'),
                     original.replace('digest in descriptor', 'public key'), original[:150]):
            evidence = copy.deepcopy(self.evidence)
            evidence['repacked-boot-verify.txt'] = text
            with self.assertRaises(ValueError):
                evaluate(evidence)

    def test_blob_layout_golden_and_raw_dispositions_cannot_be_relaxed(self):
        changes = [('boot-result.json', ('repacked_image_sha256',), '0' * 64),
                   ('boot-result.json', ('signed_vbmeta_blob_unchanged',), False),
                   ('boot-result.json', ('offline_gate_passed',), True),
                   ('boot-result.json', ('repacked_boot_layout', 'signature_bytes'), 4096),
                   ('boot-result.json', ('repacked_boot_layout', 'header_metadata_sha256'), '0' * 64),
                   ('conditional-policy.json', ('raw_global_audit_passed',), True),
                   ('conditional-policy.json', ('conditional_counts_replayed', 'wrong_crc'), 1),
                   ('conditional-policy.json', ('runtime_provider_observed',), True),
                   ('payload-preflight.json', ('generic_mount_backend_removed',), False),
                   ('capacity.json', ('page_rounded_R',), 0),
                   ('provider-evidence.json', ('conditional_values', 'size'), 67108864),
                   ('abl-policy.json', ('locked_verification_failure_rejected',), False)]
        for name, keys, value in changes:
            evidence = copy.deepcopy(self.evidence)
            row = evidence[name]
            for key in keys[:-1]:
                row = row[key]
            row[keys[-1]] = value
            with self.subTest(name=name, keys=keys), self.assertRaises(ValueError):
                evaluate(evidence)

    def test_bound_source_bytes_reject_modified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in FIXTURE_SHA:
                (directory / name).write_bytes((FIXTURES / name).read_bytes())
            path = directory / 'boot-result.json'
            path.write_text(path.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'Unreviewed evidence'):
                load_bound(directory)

    def test_producer_identity_and_completion_are_required(self):
        runs = {}
        for name, (rid, sha, workflow, conclusion, aid, digest) in PRODUCERS.items():
            runs[name] = {'id': rid, 'head_sha': sha, 'head_branch': 'fix/nezha-r74-binder-baseline',
                          'path': '.github/workflows/' + workflow, 'status': 'completed',
                          'conclusion': conclusion, 'artifact_id': aid, 'artifact_zip_sha256': digest}
        validate_runs(runs)
        for name, field, value in (('boot', 'status', 'in_progress'), ('guard', 'conclusion', 'failure'),
                                   ('candidate', 'head_sha', '0' * 40), ('scope', 'artifact_id', 1)):
            changed = copy.deepcopy(runs)
            changed[name][field] = value
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                validate_runs(changed)


if __name__ == '__main__':
    unittest.main()
