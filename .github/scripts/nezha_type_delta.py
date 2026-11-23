"""Summarize compiler-produced type deltas; do not modify any input."""
import difflib
import re
from pathlib import Path

root = Path('reports')
for filename in ('kernel.symtypes', 'bindings.symtypes'):
    def records(directory):
        return dict(line.split(' ', 1) for line in (directory/filename).read_text().splitlines())

    before, after = records(root/'clean'), records(root)
    changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
    print(filename, 'changed common type records:', len(changed))
    for key in changed[:100]:
        left, right = before[key].split(), after[key].split()
        edits = [(left[a:b][:20], right[c:d][:20]) for op, a, b, c, d in
                 difflib.SequenceMatcher(None, left, right, autojunk=False).get_opcodes() if op != 'equal']
        print('TYPE_DELTA', key, str(edits)[:1600])
    print('lost/gained rb Default names:', [n for n in sorted(before.keys() ^ after.keys()) if '7default' in n and '7rb_' in n])
texts = [(p/'bindings_generated.rs').read_text() for p in (root/'clean', root)]
diff = list(difflib.unified_diff(*(s.splitlines(True) for s in texts), n=2))
(root/'generated.diff').write_text(''.join(diff))
for line in diff:
    if line.startswith(('+', '-')) and re.search(r'\b(impl|union|struct|sysvsem|sysvshm|__bindgen_padding_\w+)\b',line):
        print('BINDING_DELTA', line[:200].rstrip())
