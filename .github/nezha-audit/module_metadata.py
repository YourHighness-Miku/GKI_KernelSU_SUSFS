"""Retain bounded original module-load declarations; never execute init/modprobe."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from module_inventory import DIR, directory, read_file

NAMES = {
    'modules.dep', 'modules.alias', 'modules.softdep', 'modules.blocklist',
    'modules.options', 'system_dlkm.modules.blocklist',
    'modules.audio.ar.blocklist', 'modules.audio.legacy.blocklist',
}


def collect(roots):
    files, total, entries = [], 0, 0

    def walk(fd, index, prefix='', depth=0):
        nonlocal total, entries
        if depth > 40:
            raise ValueError('metadata depth limit')
        with os.scandir(fd) as iterator:
            for entry in iterator:
                entries += 1
                if entries > 200000:
                    raise ValueError('metadata entry limit')
                name = entry.name
                path = prefix + name
                if entry.is_dir(follow_symlinks=False):
                    child = os.open(name, DIR, dir_fd=fd)
                    try:
                        walk(child, index, path + '/', depth + 1)
                    finally:
                        os.close(child)
                elif name in NAMES or name.startswith('modules.load') or name.endswith('.rc') or name.startswith('fstab.'):
                    data = read_file(fd, name, 4 * 1024**2)
                    total += len(data)
                    if total > 16 * 1024**2 or len(files) >= 4096 or b'\0' in data:
                        raise ValueError('metadata representation limit or non-text declaration')
                    files.append({'root_index': index, 'path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'bytes': len(data), 'text': data.decode('utf-8')})

    if not 0 < len(roots) <= 64:
        raise ValueError('metadata root count')
    for i, root in enumerate(roots):
        with directory(root) as fd:
            walk(fd, i)
    return {'scope': 'Observed original text declarations; no runtime ordering, conditions or provider selection asserted',
            'roots': list(map(str, roots)), 'files': files}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, action='append', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    args.report.write_text(json.dumps(collect(args.root), indent=2) + '\n')
