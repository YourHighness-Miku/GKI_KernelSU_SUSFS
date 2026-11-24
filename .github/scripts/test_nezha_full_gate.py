import tempfile
import unittest
from pathlib import Path

from bbg_integrate_pinned import integrate
from nezha_full_gate import CASES, REQUIRED, check_config, check_kunit


class CombinedGateTests(unittest.TestCase):
    def config(self):
        return '\n'.join(f'CONFIG_{key}=y' for key in REQUIRED) + '\nCONFIG_LSM="selinux,baseband_guard"\n'

    def test_complete_config(self):
        self.assertEqual(check_config(self.config())['lsms'], ['selinux', 'baseband_guard'])

    def test_each_feature_required(self):
        for key in REQUIRED:
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_config(self.config().replace(f'CONFIG_{key}=y', f'# CONFIG_{key} is not set'))

    def test_lsm_missing_or_forced_loading_rejected(self):
        for text in (self.config().replace(',baseband_guard', ''),
                     self.config().replace('selinux,', ''),
                     self.config() + 'CONFIG_MODULE_FORCE_LOAD=y\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_config(text)

    def test_duplicate_config_rejected(self):
        with self.assertRaises(ValueError):
            check_config(self.config() + 'CONFIG_KSU=y\n')

    def test_formatted_and_tap_passes(self):
        for lines in ([f'[02:03:04] \x1b[32m[PASSED] {c}\x1b[0m' for c in CASES],
                      [f'ok {i} - {c}' for i, c in enumerate(CASES, 1)]):
            self.assertEqual(len(check_kunit('\n'.join(lines))['cases']), 4)

    def test_missing_duplicate_and_failed_cases_rejected(self):
        valid = '\n'.join(f'[PASSED] {c}' for c in CASES)
        for text in ('', valid.replace(f'[PASSED] {CASES[0]}', ''),
                     valid + f'\n[PASSED] {CASES[0]}', valid + '\nnot ok 5 failure',
                     valid + '\n[SKIPPED] extra', valid + '\n# TODO missing'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_kunit(text)


class BBGIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('common/security', 'common/include/linux', 'Baseband-guard'):
            (self.root / name).mkdir(parents=True)
        self.makefile = self.root / 'common/security/Makefile'
        self.kconfig = self.root / 'common/security/Kconfig'
        self.header = self.root / 'common/include/linux/lsm_hooks.h'
        self.makefile.write_text('obj-y += selinux/\n')
        self.kconfig.write_text('menu "Security"\nconfig LSM\n default "selinux"\nendmenu\n')
        self.header.write_text('#define DEFINE_LSM(lsm) static struct lsm_info lsm\n')
        for name in ('Kconfig', 'Makefile', 'kernel_compat.h', 'blkdev_helper.c'):
            (self.root / 'Baseband-guard' / name).write_text('fixture\n')

    def test_installs_relative_link_and_preserves_security_entries(self):
        integrate(self.root)
        link = self.root / 'common/security/baseband-guard'
        self.assertTrue(link.is_symlink())
        self.assertFalse(Path(link.readlink()).is_absolute())
        self.assertEqual(link.resolve(), self.root / 'Baseband-guard')
        self.assertIn('obj-y += selinux/', self.makefile.read_text())
        self.assertIn('obj-$(CONFIG_BBG) += baseband-guard/', self.makefile.read_text())
        self.assertIn('source "security/baseband-guard/Kconfig"\nendmenu', self.kconfig.read_text())

    def test_second_install_rejected_without_changes(self):
        integrate(self.root)
        before = self.makefile.read_bytes(), self.kconfig.read_bytes()
        with self.assertRaises(ValueError):
            integrate(self.root)
        self.assertEqual(before, (self.makefile.read_bytes(), self.kconfig.read_bytes()))

    def test_legacy_conflicting_and_incomplete_trees_fail_before_writes(self):
        for mode in ('legacy', 'conflict', 'no-menu', 'incomplete'):
            with self.subTest(mode=mode):
                old_header, old_make, old_config = (self.header.read_text(), self.makefile.read_text(), self.kconfig.read_text())
                if mode == 'legacy':
                    self.header.write_text('/* legacy API */\n')
                elif mode == 'conflict':
                    self.makefile.write_text('obj-y += baseband-guard/\n')
                elif mode == 'no-menu':
                    self.kconfig.write_text('config LSM\n')
                else:
                    (self.root / 'Baseband-guard/Makefile').unlink()
                before = self.makefile.read_bytes(), self.kconfig.read_bytes()
                with self.assertRaises(ValueError):
                    integrate(self.root)
                self.assertEqual(before, (self.makefile.read_bytes(), self.kconfig.read_bytes()))
                self.assertFalse((self.root / 'common/security/baseband-guard').exists())
                self.header.write_text(old_header)
                self.makefile.write_text(old_make)
                self.kconfig.write_text(old_config)


if __name__ == '__main__':
    unittest.main()
