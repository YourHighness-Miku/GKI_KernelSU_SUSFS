"""Bounded static ARM64 module-version inventory (Linux, standard library only)."""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zlib


MiB = 1 << 20
FILE_LIMIT = 64 * MiB
TREE_BYTES = 4 * 1024 * MiB
MAX_RECORDS = 65536
MARKER = b'~Module signature appended~\n'
SYMBOL = re.compile(rb'[A-Za-z0-9_.$]{1,512}\Z')
HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
SECTION = struct.Struct('<IIQQQQIIQQ')
SYM = struct.Struct('<IBBHQQ')
NOFOLLOW = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
DIR = NOFOLLOW | os.O_DIRECTORY
KEYS = ('matched', 'wrong_crc', 'missing_or_external', 'unsupported')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def symbol(raw):
    require(SYMBOL.fullmatch(raw), 'unsupported symbol name')
    return raw.decode('ascii')


def string_at(data, offset):
    end = data.find(b'\0', offset, offset + 513)
    require(end >= offset, 'unterminated or overlong ELF name')
    return data[offset:end]


def signature(data):
    if not data.endswith(MARKER):
        return 'no_marker', len(data)
    at = len(data) - len(MARKER) - 12
    require(at >= 0, 'truncated signature trailer')
    _, _, _, signer, key, pad, size = struct.unpack_from('>5B3sI', data, at)
    start = at - signer - key - size
    require(size and start >= HEADER.size and pad == bytes(3), 'invalid signature trailer')
    return 'trailer_present', start


class Elf:
    def __init__(self, data, end):
        require(end >= HEADER.size, 'truncated ELF header')
        ident, kind, arch, ver, _, phoff, off, _, eh, _, phnum, ent, n, strings = HEADER.unpack_from(data)
        require(ident[:7] == b'\x7fELF\x02\x01\x01' and (kind, arch, ver) == (1, 183, 1),
                'expected ELF64 little-endian ARM64 ET_REL')
        require(not phoff and not phnum and eh == HEADER.size and ent == SECTION.size and
                0 < strings < n <= 32768 and eh <= off <= end - n * ent, 'unsupported section table')
        self.data = data
        self.headers = [SECTION.unpack_from(data, off + i * ent) for i in range(n)]
        require(not any(self.headers[0]), 'unsupported extended ELF numbering')
        for _, typ, _, _, pos, size, _, _, _, _ in self.headers:
            require(typ == 8 or pos + size <= end, 'section outside ELF')
        names = self.content(strings, 3)
        self.names = [string_at(names, h[0]) for h in self.headers]
        self.relocated = {h[7] for h in self.headers if h[1] in (4, 9) and h[5]}

    def content(self, index, typ):
        require(0 <= index < len(self.headers), 'bad section index')
        _, actual, flags, _, pos, size, *_ = self.headers[index]
        require(actual == typ and not flags & 0x800, 'unsupported section type/compression')
        return self.data[pos:pos + size]

    def named(self, name):
        indices = [i for i, n in enumerate(self.names) if n == name]
        require(len(indices) <= 1, 'duplicate metadata section')
        if indices:
            require(indices[0] not in self.relocated, 'relocated metadata not supported')
            return self.content(indices[0], 1)
        return None

    def versions(self):
        basic, names, crcs = map(self.named, (b'__versions', b'__version_ext_names', b'__version_ext_crcs'))
        result = {}
        if names is not None or crcs is not None:
            require(not basic and names is not None and crcs is not None and len(crcs) % 4 == 0
                    and len(crcs) // 4 <= MAX_RECORDS, 'invalid extended version sections')
            pos = 0
            for crc, in struct.iter_unpack('<I', crcs):
                raw = string_at(names, pos)
                pos += len(raw) + 1
                name = symbol(raw)
                require(name not in result, 'duplicate version requirement')
                result[name] = crc
            require(not names[pos:].strip(b'\0'), 'excess extended version names')
            fmt = 'extended'
        elif basic is not None:
            require(len(basic) % 64 == 0 and len(basic) // 64 <= MAX_RECORDS, 'invalid __versions size')
            for crc, field in struct.iter_unpack('<Q56s', basic):
                name = symbol(string_at(field, 0))
                require(crc <= 0xffffffff and name not in result, 'invalid basic version record')
                result[name] = crc
            fmt = 'basic'
        else:
            fmt = 'absent'
        return fmt, result

    def symbols(self):
        tables = [i for i, h in enumerate(self.headers) if h[1] == 2]
        require(len(tables) == 1, 'missing or ambiguous ELF symbol table')
        i, = tables
        h = self.headers[i]
        require(h[9] == SYM.size and h[5] % SYM.size == 0 and
                0 < h[5] // SYM.size <= 500000, 'invalid or excessive symbol table')
        strings = self.content(h[6], 3)
        imports, crcs, exports = {}, {}, set()
        for off, info, _, idx, val, size in SYM.iter_unpack(self.content(i, 2)):
            require(idx < len(self.headers) or idx == 0xfff1, 'unsupported symbol section index')
            bind = info >> 4
            if idx == 0 and bind:
                require(bind in (1, 2), 'unknown undefined symbol binding')
                imports[symbol(string_at(strings, off))] = 'weak' if bind == 2 else 'global'
                continue
            if not idx or not strings.startswith((b'__crc_', b'__ksymtab_'), off):
                continue
            raw = string_at(strings, off)
            sh = None if idx == 0xfff1 else self.headers[idx]
            section = self.names[idx] if sh else b''
            if raw.startswith(b'__ksymtab_'):
                name = raw[10:]
                if (table_section(section, b'ksymtab', name) and sh[1] == 1 and sh[2] & 2
                        and not sh[2] & 0x800 and val + 12 <= sh[5]):
                    exports.add(symbol(name))
                continue
            name = raw[6:]
            if idx == 0xfff1 and val <= 0xffffffff:
                value = val
            elif (table_section(section, b'kcrctab', name) and idx not in self.relocated and sh[1] == 1
                  and sh[2] & 2 and not sh[2] & 0x800 and size in (0, 4) and val % 4 == 0 and val + 4 <= sh[5]):
                value, = struct.unpack_from('<I', self.data, sh[4] + val)
            else:
                continue  # Never reinterpret a relocation, address or undefined symbol as a CRC.
            name = symbol(name)
            require(name not in crcs, 'duplicate provider CRC')
            crcs[name] = value
        require(len(imports) + len(exports) <= MAX_RECORDS, 'excessive imports/exports')
        return imports, {name: crcs.get(name) for name in exports}

    def vermagic(self):
        data = self.named(b'.modinfo')
        if data is None:
            return None
        require(len(data) <= MiB and data.endswith(b'\0'), 'invalid .modinfo')
        values = [item[9:].decode('ascii') for item in data.split(b'\0') if item.startswith(b'vermagic=')]
        require(len(values) <= 1 and all(0 < len(v) <= 1024 for v in values), 'invalid vermagic')
        return values[0] if values else None


def table_section(section, kind, name):
    return any(section in (b'__' + kind + lic, b'___' + kind + lic + b'+' + name)
               for lic in (b'', b'_gpl', b'_unused', b'_unused_gpl', b'_gpl_future'))


@contextmanager
def directory(path):
    path = Path(path)
    require('..' not in path.parts, 'parent traversal not supported')
    fd = os.open(path.anchor or '.', DIR)
    try:
        for part in path.parts[int(path.is_absolute()):]:
            nxt = os.open(part, DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def read_file(fd, name, limit):
    require(stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode), 'not a regular file')
    with os.fdopen(os.open(name, NOFOLLOW, dir_fd=fd), 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and 0 <= st.st_size <= limit, 'not regular or file byte limit')
        data = stream.read(st.st_size + 1)
        require(len(data) == st.st_size, 'file changed while reading')
        return data


def kernel_exports(raw):
    result = {}
    require(raw.count(b'\n') <= 200000, 'symvers row limit')
    for line in raw.split(b'\n'):
        if not line.strip():
            continue
        require(len(line) <= 4096, 'overlong symvers line')
        parts = line.split()
        require(4 <= len(parts) <= 5 and re.fullmatch(rb'0x[0-9a-fA-F]{1,8}', parts[0])
                and parts[3].startswith(b'EXPORT_SYMBOL'), 'malformed Module.symvers row')
        if parts[2] == b'vmlinux':  # A separately built .ko need not be installed unchanged.
            name = symbol(parts[1])
            require(name not in result, 'duplicate vmlinux export')
            result[name] = int(parts[0], 16)
    require(result, 'no vmlinux exports in Module.symvers')
    return result


def expand(name, raw, limit):
    if name.endswith('.ko'):
        require(len(raw) <= limit, 'expanded byte limit')
        return raw
    if name.endswith('.ko.gz'):
        decoder = zlib.decompressobj(31)
    elif name.endswith('.ko.xz'):
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=96 * MiB)
    else:
        raise ValueError('unsupported module compression')
    data = decoder.decompress(raw, max_length=limit + 1)
    require(len(data) <= limit and decoder.eof and not decoder.unused_data,
            'over-limit, incomplete or trailing compressed stream')
    return data


def is_module(name):
    return name.endswith('.ko') or '.ko.' in name


class TreeLimit(ValueError):
    pass


class Inventory:
    def __init__(self):
        self.entries = self.disk = self.expanded = self.records = 0
        self.rows, self.errors = [], []
        self.providers = defaultdict(dict)

    def inspect(self, fd, name, row):
        raw = read_file(fd, name, min(FILE_LIMIT, TREE_BYTES - self.disk))
        self.disk += len(raw)
        row['file_sha256'] = hashlib.sha256(raw).hexdigest()
        limit = min(FILE_LIMIT, TREE_BYTES - self.expanded)
        try:
            data = expand(name, raw, limit)
        except (ValueError, zlib.error, lzma.LZMAError):
            if name.endswith(('.ko.xz', '.ko.gz')):
                self.expanded += limit  # Charge failed decodes for their possible output, too.
            raise
        self.expanded += len(data)
        row['expanded_sha256'] = hashlib.sha256(data).hexdigest()
        row['signature_presence'], end = signature(data)
        elf = Elf(data, end)
        issues = []
        try:
            row['vermagic'] = elf.vermagic()
            require(row['vermagic'], 'vermagic absent')
        except ValueError as exc:
            issues.append(str(exc))
        try:
            fmt, versions = elf.versions()
            if not versions:
                issues.append('no imported version evidence')
        except ValueError as exc:
            issues.append(str(exc))
            fmt, versions = 'unsupported', {}
        try:
            imports, providers = elf.symbols()
        except ValueError as exc:
            # A missing symbol table does not invalidate independently readable version records.
            issues.append(str(exc))
            imports, providers = {}, {}
        self.records += len(versions) + len(imports) + len(providers)
        require(self.records <= 1000000, 'tree record limit')
        row['version_format'] = fmt
        if issues:
            row['error'] = '; '.join(issues)
        row['imports'] = {k: {'required_crc': versions.get(k), 'undefined_binding': imports.get(k)}
                          for k in sorted(versions.keys() | imports.keys())}
        row['observed_exports'] = dict(sorted(providers.items()))
        for name, crc in providers.items():
            self.providers[name][row['expanded_sha256']] = (crc, row['id'])

    def walk(self, fd, root, prefix='', depth=0):
        require(depth <= 40 and len(prefix) <= 4096, 'tree depth/path limit')
        with os.scandir(fd) as entries:
            for entry in entries:
                self.entries += 1
                if self.entries > 200000:
                    raise TreeLimit('tree entry limit')
                name = entry.name
                path = prefix + name
                try:
                    if entry.is_dir(follow_symlinks=False):
                        child = os.open(name, DIR, dir_fd=fd)
                        try:
                            self.walk(child, root, path + '/', depth + 1)
                        finally:
                            os.close(child)
                    elif is_module(name):
                        if len(self.rows) >= 8192:
                            raise TreeLimit('module occurrence limit')
                        row = {'root_index': root, 'path': path, 'id': len(self.rows)}
                        self.rows.append(row)
                        try:
                            self.inspect(fd, name, row)
                        except (OSError, ValueError, zlib.error, lzma.LZMAError) as exc:
                            row['error'] = str(exc)
                    elif entry.is_symlink():
                        raise ValueError('not following symlink; inventory may be incomplete')
                except TreeLimit:
                    raise
                except (OSError, ValueError) as exc:
                    if len(self.errors) >= 1024:
                        raise TreeLimit('inventory error limit')
                    self.errors.append({'root_index': root, 'path': path, 'error': str(exc)})

    def compare(self, kernel):
        # Distinct paths or compression wrappers cannot witness their own module content.
        witnesses = {}
        for name, candidates in self.providers.items():
            if len({crc for crc, _ in candidates.values()}) == 1:
                value, first = next(iter(candidates.values()))
                _, last = candidates[next(reversed(candidates))]
                witnesses[name] = value, first, last
        totals = Counter(dict.fromkeys(KEYS, 0))
        for row in self.rows:
            counts = Counter(dict.fromkeys(KEYS, 0))
            counts['unsupported'] += int('error' in row)
            for name, rec in row.get('imports', {}).items():
                crc = rec['required_crc']
                if crc is None or kernel is None:
                    status = 'unsupported'
                elif name in kernel:
                    rec.update(source='vmlinux', observed_crc=kernel[name])
                    status = 'matched' if crc == kernel[name] else 'wrong_crc'
                else:
                    value, first, last = witnesses.get(name, (None, None, None))
                    own = row['expanded_sha256']
                    witness = last if first is not None and self.rows[first]['expanded_sha256'] == own else first
                    if value == crc and witness is not None and self.rows[witness]['expanded_sha256'] != own:
                        rec.update(source='observed_oem_export', provider_id=witness, observed_crc=crc)
                        status = 'matched'
                    else:
                        status = 'missing_or_external'
                counts[status] += 1
                rec['comparison'] = status
            row['counts'] = dict(counts)
            row['status'] = verdict(counts, False)
            totals.update(counts)
        return dict(totals)


def verdict(counts, incomplete):
    if counts['wrong_crc']:
        return 'CRC_CONTRADICTION'
    if incomplete or counts['unsupported'] or counts['missing_or_external']:
        return 'UNKNOWN'
    return 'OBSERVED_CRCS_MATCH'


def audit(symvers, roots):
    inv = Inventory()
    source = {'path': str(symvers)}
    kernel = None
    try:
        p = Path(symvers)
        with directory(p.parent) as fd:
            raw = read_file(fd, p.name, 16 * MiB)
        source['sha256'] = hashlib.sha256(raw).hexdigest()
        kernel = kernel_exports(raw)
        source['vmlinux_exports'] = len(kernel)
    except (OSError, ValueError) as exc:
        source['error'] = str(exc)
    for index, root in enumerate(roots):
        before = len(inv.rows)
        try:
            if index >= 64:
                raise TreeLimit('module root limit')
            with directory(root) as fd:
                inv.walk(fd, index)
            require(len(inv.rows) > before, 'no module occurrences in root')
        except (OSError, ValueError) as exc:
            inv.errors.append({'root_index': index, 'error': str(exc)})
            if isinstance(exc, TreeLimit):
                break
    counts = inv.compare(kernel)
    return {'status': verdict(counts, inv.errors or kernel is None or not inv.rows),
            'scope': 'Static CRC evidence only. An OEM match witnesses a supplied export, not provider selection. '
                     'No assertion of tree provenance/completeness, signature trust, loadability or boot.',
            'symvers': source, 'module_roots': list(map(str, roots)), 'inventory_errors': inv.errors,
            'module_rows': len(inv.rows), 'counts': counts, 'modules': inv.rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--symvers', type=Path, required=True)
    parser.add_argument('--module-root', type=Path, action='append', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.report
    if output.is_symlink() or is_module(output.name) or os.path.realpath(output) == os.path.realpath(args.symvers):
        parser.error('unsafe report destination')
    report = audit(args.symvers, args.module_root)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=output.parent, delete=False) as tmp:
        try:
            json.dump(report, tmp, separators=(',', ':'), sort_keys=True)
            tmp.write('\n')
            tmp.close()
            os.replace(tmp.name, output)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
    print(json.dumps({k: report[k] for k in ('module_rows', 'counts', 'status')}))
    return int(report['status'] != 'OBSERVED_CRCS_MATCH')


if __name__ == '__main__':
    raise SystemExit(main())
