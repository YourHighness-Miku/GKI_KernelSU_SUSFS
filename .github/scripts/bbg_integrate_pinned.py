#!/usr/bin/env python3
"""Integrate an already verified BBG checkout into a modern GKI tree offline."""
import argparse
import os
from pathlib import Path
import re


def reserve_lsm_slot(common, header):
    path = common / 'include/linux/lsm_count.h'
    if not path.exists():
        if 'lsm_static_call' in header:
            raise ValueError('Static-call LSM header without lsm_count.h')
        return None
    text = path.read_text()
    anchor = '#define __COUNT_LSMS(skipped_arg, args...) COUNT_ARGS(args...)'
    if text.count(anchor) != 1 or re.search(r'\bBBG_ENABLED\b', text):
        raise ValueError('Unknown or conflicting BBG LSM capacity accounting')
    slot = ('#if IS_BUILTIN(CONFIG_BBG)\n#define BBG_ENABLED 1,\n'
            '#else\n#define BBG_ENABLED\n#endif\n\n')
    text = text.replace(anchor, slot + anchor, 1)
    text, changed = re.subn(r'(^[ \t]+CAPABILITIES_ENABLED[^\n]*\\\n)([ \t]*)',
                            r'\1\2BBG_ENABLED \\\n\2', text, flags=re.M)
    if changed != 1:
        raise ValueError('Cannot reserve the builtin BBG LSM static-call slot')
    return path, text


def integrate(kernel):
    kernel = kernel.resolve()
    common = kernel / 'common'
    checkout = kernel / 'Baseband-guard'
    security = common / 'security'
    target = security / 'baseband-guard'
    for name in ('Kconfig', 'Makefile', 'kernel_compat.h', 'blkdev_helper.c'):
        if not (checkout / name).is_file():
            raise ValueError(f'Incomplete BBG checkout: {name}')
    if target.exists() or target.is_symlink():
        raise ValueError('Refusing an existing BBG integration')
    header = (common / 'include/linux/lsm_hooks.h').read_text()
    if not re.search(r'^#define\s+DEFINE_LSM\(lsm\)', header, re.M):
        raise ValueError('Only modern GKI LSM integration is supported')
    makefile = security / 'Makefile'
    kconfig = security / 'Kconfig'
    before_make, before_config = makefile.read_text(), kconfig.read_text()
    if 'baseband-guard/' in before_make or 'security/baseband-guard/Kconfig' in before_config:
        raise ValueError('Conflicting BBG build entries')
    ends = list(re.finditer(r'^endmenu[ \t]*$', before_config, re.M))
    if not ends:
        raise ValueError('Missing security Kconfig endmenu')
    at = ends[-1].start()
    after_config = (before_config[:at] + 'source "security/baseband-guard/Kconfig"\n'
                    + before_config[at:])
    count = reserve_lsm_slot(common, header)
    if count is not None:
        count[0].write_text(count[1])
    makefile.write_text(before_make + '\nobj-$(CONFIG_BBG) += baseband-guard/\n')
    kconfig.write_text(after_config)
    target.symlink_to(os.path.relpath(checkout, security), target_is_directory=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    integrate(parser.parse_args().kernel)
