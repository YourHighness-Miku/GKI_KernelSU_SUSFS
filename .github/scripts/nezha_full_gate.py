#!/usr/bin/env python3
"""Check the actual combined build configuration or its SysV KUnit evidence."""
import argparse
import collections
import json
from pathlib import Path
import re

CASES = ('state_race_test', 'semundo_share_test', 'shm_lifecycle_test',
         'semundo_alloc_failure_test')
REQUIRED = ('ARM64_4K_PAGES', 'MODVERSIONS', 'KSU', 'KSU_SUSFS', 'BBG',
            'SYSVIPC', 'IPC_NS', 'POSIX_MQUEUE', 'USER_NS', 'PID_NS',
            'OVERLAY_FS', 'NETFILTER', 'TCP_CONG_BBR', 'WIREGUARD')


def check_config(text):
    config = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            name, value = line.split('=', 1)
            if name in config:
                raise ValueError(f'Duplicate actual config: {name}')
            config[name] = value
    missing = [f'CONFIG_{name}=y' for name in REQUIRED
               if config.get(f'CONFIG_{name}') != 'y']
    if missing:
        raise ValueError(f'Missing combined build features: {missing}')
    if config.get('CONFIG_MODULE_FORCE_LOAD') not in (None, 'n'):
        raise ValueError('Forced module loading is forbidden')
    lsms = config.get('CONFIG_LSM', '').strip('"').split(',')
    if 'selinux' not in lsms or 'baseband_guard' not in lsms:
        raise ValueError('Actual LSM list must retain SELinux and BBG')
    return {'required_enabled': list(REQUIRED), 'lsms': lsms,
            'scope': 'Actual build .config only, not runtime functionality'}


def check_kunit(text):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    counts = collections.Counter()
    for line in text.splitlines():
        line = re.sub(r'^\s*\[(?:\d\d:\d\d:\d\d(?:\.\d+)?|\s*\d+\.\d+)\]\s*',
                      '', line).strip()
        if re.search(r'\[(?:FAIL(?:ED|URE)?|SKIP(?:PED)?|ERROR|CRASHED|TIMEOUT)\]|'
                     r'^not ok\b|^Bail out!|#\s*(?:SKIP|TODO)\b|'
                     r'\b(?:failed|skipped|errors?|crashed):\s*[1-9]', line, re.I):
            raise ValueError('KUnit failure, skip, or incomplete execution')
        match = re.fullmatch(r'(?:\[PASSED\]\s+|ok\s+\d+\s+(?:-\s+)?)([A-Za-z0-9_]+)', line)
        if match:
            counts[match[1]] += 1
    if counts != collections.Counter(CASES):
        raise ValueError(f'Expected each of four cases exactly once, got {dict(counts)}')
    return {'cases': {case: 'PASS' for case in CASES},
            'scope': 'ARM64 QEMU SysV tests, not nezha hardware boot'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('config', 'kunit'))
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    check = check_config if args.mode == 'config' else check_kunit
    report = check(args.input.read_text())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
