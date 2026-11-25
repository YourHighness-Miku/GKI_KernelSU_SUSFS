import io
import unittest
import warnings
import zipfile

from fetch import select


class EvidenceSelectionTests(unittest.TestCase):
    def archive(self, rows):
        stream = io.BytesIO()
        with warnings.catch_warnings(), zipfile.ZipFile(stream, 'w') as archive:
            warnings.filterwarnings('ignore', message='Duplicate name:')
            for name, data in rows:
                archive.writestr(name, data)
        return stream.getvalue()

    def test_exact_member_selection_uses_real_zip_bytes_without_extraction(self):
        archive = self.archive([('Image', b'actual bytes'), ('unselected', b'other')])
        self.assertEqual(select(archive, 'Image', 64), b'actual bytes')
        for name, limit in (('missing', 64), ('Image', 2)):
            with self.assertRaises(ValueError):
                select(archive, name, limit)

    def test_duplicate_and_empty_evidence_are_rejected(self):
        for rows in ([('Image', b'a'), ('Image', b'b')], [('Image', b'')]):
            with self.assertRaises(ValueError):
                select(self.archive(rows), 'Image', 64)


if __name__ == '__main__':
    unittest.main()
