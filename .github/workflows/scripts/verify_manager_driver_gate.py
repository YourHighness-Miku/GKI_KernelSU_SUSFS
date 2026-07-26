#!/usr/bin/env python3
"""Hard gate: manager baseline versionCode must match driver expected_ksu_version_code."""
import json
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from config import EXPECTED_KSU_VERSION_CODE, SUKISU_MAIN_COMMIT_COUNT
except Exception:  # pragma: no cover
    EXPECTED_KSU_VERSION_CODE = 40856
    SUKISU_MAIN_COMMIT_COUNT = 3671


def main() -> int:
    want = int(os.environ.get('WANT_VC') or EXPECTED_KSU_VERSION_CODE)
    paths = glob.glob('/tmp/gki-build/**/source-manifest.txt', recursive=True)
    if not paths:
        print('::error::source-manifest.txt not found under /tmp/gki-build')
        return 1
    mpath = paths[0]
    with open(mpath, 'r', encoding='utf-8') as f:
        m = json.load(f)
    got = int(m.get('expected_ksu_version_code') or -1)
    print(f'manifest={mpath}')
    print(f'expected_ksu_version_code={got} want={want}')
    print(f"sukisu_main_commit_count={m.get('sukisu_main_commit_count')}")
    print(f"manager_commit={m.get('sukisu_manager_pin_commit')}")
    print(f"builtin_commit={m.get('sukisu_resolved_commit') or m.get('sukisu_pin_commit')}")
    if got != want:
        print(f'::error::driver versionCode {got} != manager baseline {want}')
        return 1
    if got == 37973:
        print('::error::legacy failed driver 37973 (FAILED / DO NOT FLASH)')
        return 1
    if m.get('sukisu_main_commit_count') not in (
        SUKISU_MAIN_COMMIT_COUNT, str(SUKISU_MAIN_COMMIT_COUNT)
    ):
        print(
            f"::error::main commit count not {SUKISU_MAIN_COMMIT_COUNT}: "
            f"{m.get('sukisu_main_commit_count')}"
        )
        return 1
    mgr_txt = os.environ.get('MANAGER_COMMIT_TXT', '')
    if mgr_txt and os.path.isfile(mgr_txt):
        text = open(mgr_txt, encoding='utf-8').read()
        print(text)
        for line in text.splitlines():
            if line.startswith('expected_version_code='):
                mvc = int(line.split('=', 1)[1])
                if mvc != want:
                    print(f'::error::manager-commit.txt versionCode {mvc} != {want}')
                    return 1
    else:
        print('::error::manager-commit.txt missing — manager build must succeed')
        return 1
    print(f'HARD GATE PASS: versionCode {got}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
