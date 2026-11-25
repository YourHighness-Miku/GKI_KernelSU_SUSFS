import hashlib
from pathlib import Path
import tempfile
import unittest

from module_metadata import collect


class ModuleMetadataTests(unittest.TestCase):
    def test_preserves_original_declarations_without_reading_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'lib/modules').mkdir(parents=True)
            text = b'# original declaration\na.ko\n'
            (root / 'lib/modules/modules.load').write_bytes(text)
            (root / 'lib/modules/a.ko').write_bytes(b'not read as text')
            result = collect([root])
            item, = result['files']
            self.assertEqual(item['path'], 'lib/modules/modules.load')
            self.assertEqual(item['text'], text.decode())
            self.assertEqual(item['sha256'], hashlib.sha256(text).hexdigest())
            self.assertIn('no runtime', result['scope'])

    def test_selected_symlink_and_binary_declaration_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / 'not_selected'
            outside.write_bytes(b'not followed')
            path = root / 'modules.dep'
            path.symlink_to(outside)
            with self.assertRaises(ValueError):
                collect([root])
            path.unlink()
            path.write_bytes(b'binary\0declaration')
            with self.assertRaises(ValueError):
                collect([root])

    def test_invalid_root_counts_fail(self):
        with self.assertRaises(ValueError):
            collect([])
        with self.assertRaises(ValueError):
            collect([Path('.')] * 65)


if __name__ == '__main__':
    unittest.main()
