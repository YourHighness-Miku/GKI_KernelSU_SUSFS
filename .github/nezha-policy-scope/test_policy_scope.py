import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from policy_scope import BLOCKLIST_SHA, evaluate, pinned


@unittest.skipUnless(os.environ.get('NEZHA_SCOPE_ROOT') and os.environ.get('NEZHA_SCOPE_SYMVERS'),
                     'Exact retained cloud snapshot and candidate exports required')
class RealPolicyScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ['NEZHA_SCOPE_ROOT'])
        cls.audit = json.loads(pinned(root / 'module-audit.json', 'module-audit.json'))
        cls.metadata = json.loads(pinned(root / 'module-load-metadata.json', 'module-load-metadata.json'))
        cls.symvers = pinned(Path(os.environ['NEZHA_SCOPE_SYMVERS']), 'Module.symvers')

    def test_replays_real_raw_and_conditional_graph_without_modifying_inputs(self):
        before = json.dumps(self.audit, sort_keys=True)
        result = evaluate(self.audit, self.metadata, self.symvers)
        self.assertEqual(result['raw_counts_replayed'],
                         {'matched': 59283, 'missing_or_external': 6, 'wrong_crc': 0, 'unsupported': 0})
        self.assertEqual(result['conditional_counts_replayed'],
                         {'matched': 58829, 'missing_or_external': 0, 'wrong_crc': 0, 'unsupported': 0})
        self.assertEqual((result['raw_occurrences'], result['conditional_occurrences']), (1081, 1077))
        self.assertEqual(len(result['six_issue_dispositions']), 6)
        self.assertEqual(json.dumps(self.audit, sort_keys=True), before)
        self.assertFalse(result['raw_global_audit_passed'])
        self.assertFalse(result['runtime_provider_observed'])
        self.assertFalse(result['boot_verified'])
        self.assertFalse(result['release_authorized'])

    def test_filtered_provider_ids_still_reference_original_content(self):
        result = evaluate(self.audit, self.metadata, self.symvers)
        retained = [r for r in result['six_issue_dispositions'] if 'provider' in r]
        self.assertEqual(len(retained), 4)
        for issue in retained:
            provider = issue['provider']
            original = self.audit['modules'][provider['original_id']]
            self.assertEqual(provider['path'], original['path'])
            self.assertEqual(provider['expanded_sha256'], original['expanded_sha256'])
            consumer = self.audit['modules'][issue['original_id']]
            self.assertNotEqual(consumer['expanded_sha256'], original['expanded_sha256'])
            self.assertEqual(original['observed_exports'][issue['symbol']], issue['required_crc'])
            self.assertEqual(issue['conditional_disposition'], 'matched')

    def test_missing_duplicate_or_altered_original_blocklist_is_not_guessed(self):
        for mode in ('missing', 'duplicate', 'content'):
            data = copy.deepcopy(self.metadata)
            entry, = [f for f in data['files'] if f['sha256'] == BLOCKLIST_SHA]
            if mode == 'missing':
                data['files'].remove(entry)
            elif mode == 'duplicate':
                data['files'].append(copy.deepcopy(entry))
            else:
                entry['text'] = 'blocklist unrelated\n'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                evaluate(self.audit, data, self.symvers)

    def test_changed_gki_content_or_missing_occurrence_is_not_filtered(self):
        for mode in ('content', 'missing'):
            data = copy.deepcopy(self.audit)
            if mode == 'content':
                data['modules'][7]['expanded_sha256'] = '0' * 64
            else:
                data['modules'].pop()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                evaluate(data, self.metadata, self.symvers)

    def test_incomplete_source_or_stale_counts_fail_closed(self):
        for mode in ('errors', 'counts', 'exports'):
            data = copy.deepcopy(self.audit)
            if mode == 'errors':
                data['inventory_errors'].append({'error': 'incomplete'})
            elif mode == 'counts':
                data['counts']['matched'] += 1
            else:
                data['symvers']['sha256'] = '0' * 64
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                evaluate(data, self.metadata, self.symvers)

    def test_real_snapshot_byte_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'module-audit.json'
            path.write_text(json.dumps(self.audit) + '\n')
            with self.assertRaises(ValueError):
                pinned(path, 'module-audit.json')


if __name__ == '__main__':
    unittest.main()
