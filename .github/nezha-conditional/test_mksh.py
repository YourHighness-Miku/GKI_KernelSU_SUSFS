import os
from pathlib import Path
import shutil
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'nezha-package'))
import test_backend


class TestMkshBackend(test_backend.TestBackend):
    @classmethod
    def setUpClass(cls):
        cls.shell = shutil.which('mksh')
        if not cls.shell:
            if os.environ.get('CI') == 'true':
                raise RuntimeError('The conditional CI must install mksh')
            raise unittest.SkipTest('mksh capability validation is required in CI')


if __name__ == '__main__':
    unittest.main()
