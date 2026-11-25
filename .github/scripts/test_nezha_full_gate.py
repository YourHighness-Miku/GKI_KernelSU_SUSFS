import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from bbg_integrate_pinned import integrate
from nezha_full_gate import CASES, REQUIRED, check_config, check_kunit
from sukisu_builtin_compat import adapt_lsm


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

    def prepare_static_lsm(self):
        include = self.root / 'common/include/linux'
        fixtures = Path(__file__).with_name('testdata')
        for name in ('lsm_count.h', 'args.h'):
            shutil.copyfile(fixtures / name, include / name)
        self.header.write_text(self.header.read_text() + '\nstruct lsm_static_call;\n'
            'extern void security_add_hooks(struct security_hook_list *hooks, int count, const struct lsm_id *lsmid);\n')
        nova = self.root / 'KernelSU'
        (nova / 'kernel/hook').mkdir(parents=True)
        (nova / 'kernel/hook/lsm_hook.c').write_text(
            'void __init ksu_lsm_hook_init(void) {\n'
            'security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");\n}\n')
        return nova

    def real_lsm_count(self, bbg, ksu):
        source = ('#define IS_ENABLED(x) ((x) == 1)\n'
                  '#define IS_BUILTIN(x) ((x) == 1)\n'
                  '#define CONFIG_SECURITY 1\n#define CONFIG_SECURITY_SELINUX 1\n'
                  f'#define CONFIG_BBG {bbg}\n#define CONFIG_KSU {ksu}\n'
                  '#include <linux/lsm_count.h>\nMAX_LSM_COUNT\n')
        result = subprocess.run(['gcc', '-E', '-P', '-x', 'c', '-I', str(self.root / 'common/include'), '-'],
                                input=source, text=True, check=True, capture_output=True)
        return int(result.stdout.strip())

    def test_actual_pinned_header_counts_bbg_only_when_builtin(self):
        self.prepare_static_lsm()
        integrate(self.root)
        for enabled, expected in ((0, 2), (1, 3), (2, 2)):
            with self.subTest(bbg=enabled):
                self.assertEqual(self.real_lsm_count(enabled, 0), expected)

    def combined_capacity(self, nova_first):
        nova = self.prepare_static_lsm()
        if nova_first:
            adapt_lsm(self.root / 'common', nova)
        integrate(self.root)
        if not nova_first:
            adapt_lsm(self.root / 'common', nova)
        for bbg, ksu, expected in ((0, 0, 2), (1, 0, 3), (0, 1, 3), (1, 1, 4)):
            with self.subTest(bbg=bbg, ksu=ksu):
                self.assertEqual(self.real_lsm_count(bbg, ksu), expected)
        self.assertEqual((self.root / 'common/include/linux/lsm_count.h').read_text().count('#define BBG_ENABLED 1,'), 1)

    def test_bbg_capacity_before_nova(self):
        self.combined_capacity(False)

    def test_bbg_capacity_after_nova(self):
        self.combined_capacity(True)

    def test_unknown_or_missing_static_count_rejected_before_mutations(self):
        self.prepare_static_lsm()
        count = self.root / 'common/include/linux/lsm_count.h'
        for missing in (False, True):
            if missing:
                count.unlink()
            else:
                count.write_text('/* unsupported static LSM counter */\n')
            before = self.makefile.read_bytes(), self.kconfig.read_bytes()
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                integrate(self.root)
            self.assertEqual(before, (self.makefile.read_bytes(), self.kconfig.read_bytes()))
            self.assertFalse((self.root / 'common/security/baseband-guard').is_symlink())


if __name__ == '__main__':
    unittest.main()
