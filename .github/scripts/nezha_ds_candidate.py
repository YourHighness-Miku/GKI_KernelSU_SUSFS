"""Prepare and qualify a diagnostic 6.12 DS candidate; never package it."""
import argparse
import json
import re
import struct
from pathlib import Path


def apply(root):
    path = root / "include/linux/sched.h"
    source = path.read_text()
    definitions = []
    for index, (typ, field, short) in enumerate((('sysv_sem', 'sysvsem', 'sem'), ('sysv_shm', 'sysvshm', 'shm'))):
        tag = f"nezha_sysv_{short}_state"
        block = (rf'(?m)^(\s*?)union\s*\{{\s*char __kabi_ignored_{index};\s*'
                 rf'struct {typ}\s+{field};\s*\}}\s*__attribute__\(\(packed\)\);')
        source, count = re.subn(block, rf'\g<1>union {tag} {field};', source)
        if count != 1:
            raise ValueError(f'Unexpected pinned DS layout for {field}: {count} matches')
        definitions.append(f"union {tag} {{ char __kabi_ignored_{index}; struct {typ} state; }};")
    anchor = "struct task_struct {"
    if source.count(anchor) != 1:
        raise ValueError("Ambiguous task definition")
    source = source.replace(anchor, "#ifdef CONFIG_SYSVIPC\n" + "\n".join(definitions) + "\n#endif\n\n" + anchor)
    path.write_text(source)
    for rel in ('ipc/sem.c', 'ipc/shm.c', 'include/linux/shm.h', 'kernel/kcmp.c'):
        path = root / rel
        text = path.read_text()
        text, n = re.subn(r'(->sysvsem|->sysvshm)(\s*\.)', r'\1.state\2', text)
        if n == 0:
            raise ValueError(f'No SysV references updated in {rel}')
        path.write_text(text)
    path = root / 'rust/Makefile'
    text = path.read_text()
    anchor = '--use-core --with-derive-default --ctypes-prefix ffi --no-layout-tests'
    if text.count(anchor) != 1:
        raise ValueError('Ambiguous pinned bindgen invocation')
    text = text.replace(anchor, anchor + " --no-default '(nezha_sysv_(sem|shm)_state|sysv_(sem|shm))'")
    path.write_text(text)


def instrument(root):
    path = root / 'rust/Makefile'
    with path.open('a') as out:
        out.write('\n$(obj)/bindings.o $(obj)/kernel.o: private KBUILD_SYMTYPES := 1\n')
    path = root / 'BUILD.bazel'
    text = path.read_text()
    anchor = 'name = "kernel_aarch64",\n    outs = DEFAULT_GKI_OUTS,'
    if text.count(anchor) != 1:
        raise ValueError('Ambiguous kernel outputs')
    text = text.replace(anchor, anchor[:-1] + ' + ["rust/bindings/bindings_generated.rs", "rust/kernel.symtypes", "rust/bindings.symtypes"],')
    path.write_text(text)


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
    bindings = (candidate/'bindings_generated.rs').read_text()
    for tag in ('nezha_sysv_sem_state', 'nezha_sysv_shm_state'):
        if not re.search(r'pub union ' + tag + r'\s*\{', bindings):
            raise ValueError(f'Real Rust union layout missing for {tag}')
        if re.search(r'impl\s+(?:[a-zA-Z_:]*::)?Default\s+for\s+' + tag + r'\b', bindings):
            raise ValueError(f'Unexpected new Default implementation for {tag}')
    report = dict(baseline_exports=len(a), changed_or_missing=changes, task_bytes=[sa,sb],
                  changed_named_task_members=moved, missing_requested_config=absent)
    (candidate/'ds-abi-result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Changed or missing exports:', len(changes), 'changed named offsets:', len(moved), 'task sizes:', sa, sb, 'missing configs:', absent)
    if changes or moved or sa != sb or absent:
        raise SystemExit('Candidate rejected: do not package')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest='mode', required=True)
    modes.add_parser('apply').add_argument('root', type=Path)
    modes.add_parser('instrument').add_argument('root', type=Path)
    check = modes.add_parser('compare')
    check.add_argument('reference', type=Path)
    check.add_argument('candidate', type=Path)
    args = parser.parse_args()
    if args.mode == 'apply':
        apply(args.root)
    elif args.mode == 'instrument':
        instrument(args.root)
    else:
        compare(args.reference, args.candidate)
