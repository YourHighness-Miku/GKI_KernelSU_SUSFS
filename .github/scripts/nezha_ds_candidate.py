"""Prepare and qualify a diagnostic 6.12 DS candidate; never package it."""
import argparse
import json
import re
import struct
from pathlib import Path


def replace_once(path, old, new):
    source = path.read_text()
    if source.count(old) != 1:
        raise ValueError(f'Expected one source anchor in {path}: {old[:80]!r}')
    path.write_text(source.replace(old, new, 1))


def apply(root):
    path = root / 'include/linux/sched.h'
    source = path.read_text()
    for index, (typ, field) in enumerate((('sysv_sem', 'sysvsem'), ('sysv_shm', 'sysvshm'))):
        pattern = (rf'(?m)^\s*union\s*\{{\s*char __kabi_ignored_{index};\s*'
                   rf'struct {typ}\s+{field};\s*\}}\s*__attribute__\(\(packed\)\);')
        source, n = re.subn(pattern, '', source)
        if n != 1:
            raise ValueError(f'Unexpected original DS field: {field}')
    path.write_text(source)
    flags = '--use-core --with-derive-default --ctypes-prefix ffi --no-layout-tests'
    replace_once(root/'rust/Makefile', flags, flags + " --no-default 'sysv_(sem|shm)'")
    source_dir = Path(__file__).parent
    for filename, destination in (
            ('nezha_sysv_task.h', 'include/linux/nezha_sysv_task.h'),
            ('nezha_sysv_state.c', 'ipc/nezha_sysv_state.c'),
            ('nezha_sysv_state_test.c', 'ipc/nezha_sysv_state_test.c')):
        target = root / destination
        if target.exists():
            raise ValueError(f'Refuse to overwrite {target}')
        target.write_text((source_dir/filename).read_text())
    for rel, anchor in (
            ('ipc/sem.c', '#include <linux/ipc_namespace.h>'),
            ('ipc/shm.c', '#include <linux/ipc_namespace.h>'),
            ('kernel/fork.c', '#include <linux/sched/task.h>'),
            ('kernel/kcmp.c', '#include <linux/ptrace.h>')):
        replace_once(root/rel, anchor, anchor+'\n#include <linux/nezha_sysv_task.h>')
    path = root / 'ipc/sem.c'
    replace_once(path,
        'static inline int get_undo_list(struct sem_undo_list **undo_listp)\n{\n'
        '\tstruct sem_undo_list *undo_list;\n\n'
        '\tundo_list = current->sysvsem.undo_list;',
        'static inline int get_undo_list(struct sem_undo_list **undo_listp)\n{\n'
        '\tstruct nezha_sysv_state *state;\n'
        '\tstruct sem_undo_list *undo_list;\n\n'
        '\tstate = nezha_sysv_get(current, true);\n'
        '\tif (!state)\n\t\treturn -ENOMEM;\n'
        '\tundo_list = READ_ONCE(state->undo_list);')
    replace_once(path, '\t\tcurrent->sysvsem.undo_list = undo_list;',
                 '\t\tWRITE_ONCE(state->undo_list, undo_list);')
    replace_once(path,
        '\tstruct sem_undo_list *undo_list;\n\tint error;\n\n'
        '\tif (clone_flags & CLONE_SYSVSEM) {\n'
        '\t\terror = get_undo_list(&undo_list);',
        '\tstruct sem_undo_list *undo_list;\n'
        '\tstruct nezha_sysv_state *state;\n\tint error;\n\n'
        '\tif (clone_flags & CLONE_SYSVSEM) {\n'
        '\t\tstate = nezha_sysv_get(tsk, true);\n'
        '\t\tif (!state)\n\t\t\treturn -ENOMEM;\n'
        '\t\terror = get_undo_list(&undo_list);')
    replace_once(path,
        '\t\ttsk->sysvsem.undo_list = undo_list;\n'
        '\t} else\n\t\ttsk->sysvsem.undo_list = NULL;',
        '\t\tWRITE_ONCE(state->undo_list, undo_list);\n\t}')
    replace_once(path,
        'void exit_sem(struct task_struct *tsk)\n{\n'
        '\tstruct sem_undo_list *ulp;\n\n'
        '\tulp = tsk->sysvsem.undo_list;\n\tif (!ulp)\n\t\treturn;\n'
        '\ttsk->sysvsem.undo_list = NULL;',
        'void exit_sem(struct task_struct *tsk)\n{\n'
        '\tstruct nezha_sysv_state *state;\n\tstruct sem_undo_list *ulp;\n\n'
        '\tstate = nezha_sysv_get(tsk, false);\n'
        '\tif (!state)\n\t\treturn;\n'
        '\tulp = READ_ONCE(state->undo_list);\n\tif (!ulp)\n\t\treturn;\n'
        '\tWRITE_ONCE(state->undo_list, NULL);')
    path = root / 'ipc/shm.c'
    replace_once(path,
        '\t\tstruct ipc_namespace *ns;\n\n\t\ttask_lock(task);\n\n'
        '\t\tif (list_empty(&task->sysvshm.shm_clist)) {',
        '\t\tstruct ipc_namespace *ns;\n'
        '\t\tstruct nezha_sysv_state *state;\n\n\t\ttask_lock(task);\n\n'
        '\t\tstate = nezha_sysv_get(task, false);\n'
        '\t\tif (!state || list_empty(&state->shm_clist)) {')
    replace_once(path, '&task->sysvshm.shm_clist, struct shmid_kernel,',
                 '&state->shm_clist, struct shmid_kernel,')
    replace_once(path,
        '\tstruct shmid_kernel *shp;\n\tsize_t numpages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;',
        '\tstruct shmid_kernel *shp;\n\tstruct nezha_sysv_state *state;\n'
        '\tsize_t numpages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;')
    replace_once(path,
        '\tshp = kmalloc(sizeof(*shp), GFP_KERNEL_ACCOUNT);',
        '\tstate = nezha_sysv_get(current, true);\n'
        '\tif (!state)\n\t\treturn -ENOMEM;\n\n'
        '\tshp = kmalloc(sizeof(*shp), GFP_KERNEL_ACCOUNT);')
    replace_once(path, '&current->sysvshm.shm_clist);', '&state->shm_clist);')
    replace_once(root/'include/linux/shm.h',
        '#define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)',
        '#define shm_init_task(task) do { } while (0)')
    for task in ('task1', 'task2'):
        replace_once(root/'kernel/kcmp.c', f'{task}->sysvsem.undo_list',
                     f'nezha_sysv_undo({task})')
    replace_once(root/'kernel/fork.c',
        '\tcpufreq_task_times_exit(tsk);',
        '\tcpufreq_task_times_exit(tsk);\n\tnezha_sysv_free(tsk);')
    with (root/'ipc/shm.c').open('a') as output:
        output.write('\n#if IS_ENABLED(CONFIG_NEZHA_SYSV_STATE_KUNIT_TEST)\n'
                     'long nezha_sysv_test_remove_shm(int shmid)\n{\n'
                     '\treturn ksys_shmctl(shmid, IPC_RMID, NULL, IPC_64);\n}\n#endif\n')
    # Permit task-scoped failslab on sleepable allocations only in the test kernel.
    replace_once(root/'mm/failslab.c', '.ignore_gfp_reclaim = true,',
                 '.ignore_gfp_reclaim = !IS_ENABLED(CONFIG_NEZHA_SYSV_STATE_KUNIT_TEST),')
    with (root/'ipc/Makefile').open('a') as output:
        output.write('\nobj-$(CONFIG_SYSVIPC) += nezha_sysv_state.o\n'
                     'obj-$(CONFIG_NEZHA_SYSV_STATE_KUNIT_TEST) += nezha_sysv_state_test.o\n')
    with (root/'init/Kconfig').open('a') as output:
        output.write('\nconfig NEZHA_SYSV_STATE_KUNIT_TEST\n'
                     '\tbool "Nezha external SysV state lifecycle tests"\n'
                     '\tdepends on KUNIT=y && SYSVIPC && FAILSLAB\n\tdefault n\n')


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
    after = (candidate/'bindings_generated.rs').read_text()
    for filename in ('kernel.symtypes', 'bindings.symtypes'):
        def records(directory):
            return dict(line.split(' ', 1) for line in (directory/filename).read_text().splitlines())
        old, new = records(candidate/'clean'), records(candidate)
        different = [name for name in old.keys() & new.keys() if old[name] != new[name]]
        if different:
            raise ValueError(f'Original Rust type records changed: {different[:10]}')
    if 'nezha_sysv_state' in after:
        raise ValueError('Private SysV state leaked into Rust ABI bindings')
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
