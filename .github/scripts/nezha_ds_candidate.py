"""Prepare and qualify a diagnostic 6.12 DS candidate; never package it."""
import argparse
import json
import re
import struct
from pathlib import Path


def apply(path):
    source = path.read_text()
    for index, (typ, field) in enumerate((('sysv_sem', 'sysvsem'), ('sysv_shm', 'sysvshm'))):
        block = (rf'(?m)^(\s*?)union\s*\{{\s*char __kabi_ignored_{index};\s*'
                 rf'struct {typ}\s+{field};\s*\}}\s*__attribute__\(\(packed\)\);')
        source, count = re.subn(block, rf'\g<1>struct {typ} {field};', source)
        if count != 1:
            raise ValueError(f'Unexpected pinned DS layout for {field}: {count} matches')
    path.write_text(source)


def task_layout(path):
    image = path.read_bytes()
    for m in re.finditer(b'\x9f\xeb\x01\x00\x18\x00\x00\x00', image):
        off, size, stroff, strlen = struct.unpack_from('<4I', image, m.end())
        base = m.start()+24
        if size < 100000 or base+stroff+strlen > len(image) or stroff < off+size:
            continue
        strings = image[base+stroff:base+stroff+strlen]
        if not strings.startswith(b'\0'):
            continue
        def name(i):
            return strings[i:strings.index(0, i)].decode()
        pos, end = base+off, base+off+size
        while pos < end:
            n, info, length = struct.unpack_from('<III', image, pos)
            pos += 12
            kind, count = (info >> 24) & 31, info & 65535
            if kind == 4 and n and name(n) == 'task_struct':
                fields = {}
                for member, _, offset in struct.iter_unpack('<III', image[pos:pos+12*count]):
                    if member:
                        fields[name(member)] = offset
                return length, fields
            pos += {1:4, 2:0, 3:12, 4:12*count, 5:12*count, 6:8*count, 7:0,
                    8:0, 9:0, 10:0, 11:0, 12:0, 13:8*count, 14:4, 15:12*count,
                    16:0, 17:4, 18:0, 19:12*count}[kind]
    raise ValueError('No usable task_struct BTF')


def exports(path):
    return {p[1]: int(p[0], 16) for line in path.read_text().splitlines()
            if len(p := line.split()) >= 3 and p[2] == 'vmlinux'}


def compare(reference, candidate):
    a, b = [exports(p/'Module.symvers') for p in (reference, candidate)]
    if len(a) < 9000 or len(b) < 9000:
        raise ValueError('Incomplete vmlinux export inventory')
    sa, ma = task_layout(reference/'Image')
    sb, mb = task_layout(candidate/'Image')
    changes = {n: [a[n], b.get(n)] for n in a if a[n] != b.get(n)}
    moved = {n: [v, mb.get(n)] for n, v in ma.items() if mb.get(n) != v}
    config = set((candidate/'built.config').read_text().splitlines())
    required = set(re.findall(r'^(CONFIG_\w+=y)$', (candidate/'requested.fragment').read_text(), re.M))
    required.update({'CONFIG_SYSVIPC=y','CONFIG_IPC_NS=y','CONFIG_POSIX_MQUEUE=y','CONFIG_USER_NS=y'})
    absent = sorted(required-config)
    report = dict(baseline_exports=len(a), changed_or_missing=changes, task_bytes=[sa,sb],
                  changed_named_task_members=moved, missing_requested_config=absent)
    (candidate/'ds-abi-result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Changed or missing exports:', len(changes), 'changed named offsets:', len(moved), 'task sizes:', sa, sb, 'missing configs:', absent)
    if changes or moved or sa != sb or absent:
        raise SystemExit('Candidate rejected: do not package')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest='mode', required=True)
    modes.add_parser('apply').add_argument('header', type=Path)
    check = modes.add_parser('compare')
    check.add_argument('reference', type=Path)
    check.add_argument('candidate', type=Path)
    args = parser.parse_args()
    if args.mode == 'apply':
        apply(args.header)
    else:
        compare(args.reference, args.candidate)
