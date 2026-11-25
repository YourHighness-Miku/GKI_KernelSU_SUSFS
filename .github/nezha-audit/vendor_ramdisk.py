"""Read-only bounded vendor-boot-v4 module extraction; never run archive members."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import struct

import lz4.block

from public_audit_refs import PARTITIONS

LIMIT = 256 * 1024**2
BLOCK = 8 * 1024**2


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(n, page=4096):
    return (n + page - 1) // page * page


def fragments(data):
    require(len(data) >= 2128 and data[:8] == b'VNDRBOOT', 'not vendor boot')
    version, page = struct.unpack_from('<II', data, 8)
    require((version, page) == (4, 4096), 'unsupported vendor boot version/page')
    ramdisk, = struct.unpack_from('<I', data, 24)
    header, dtb = struct.unpack_from('<II', data, 2096)
    table_size, count, entry_size, bootconfig = struct.unpack_from('<4I', data, 2112)
    require(header == 2128 and 0 < ramdisk <= LIMIT and 0 < count <= 256 and
            entry_size == 108 and table_size == count * entry_size, 'unsupported vendor table')
    start = align(header)
    table = start + align(ramdisk) + align(dtb)
    require(table + align(table_size) + bootconfig <= len(data), 'vendor sections exceed image')
    result, intervals = [], []
    for i in range(count):
        at = table + i * entry_size
        size, offset, kind = struct.unpack_from('<III', data, at)
        name = data[at + 12:at + 44]
        require(0 < size and offset + size <= ramdisk and kind in (0, 1, 2, 3) and b'\0' in name,
                'invalid ramdisk fragment')
        end = offset + size
        require(not any(offset < b and a < end for a, b in intervals), 'overlapping ramdisks')
        intervals.append((offset, end))
        result.append({'index': i, 'type': kind, 'name': name.split(b'\0', 1)[0].decode('ascii'),
                       'board_id': list(struct.unpack_from('<16I', data, at + 44)),
                       'data': data[start + offset:start + end]})
    require(sum(b - a for a, b in intervals) == ramdisk, 'unaccounted vendor ramdisk bytes')
    return result


def decode(data):
    if data.startswith((b'070701', b'070702')):
        require(len(data) <= LIMIT, 'cpio byte limit')
        return data
    require(data[:4] == b'\x02\x21\x4c\x18', 'unsupported ramdisk compression')
    chunks, total, pos = [], 0, 4
    while pos < len(data):
        require(pos + 4 <= len(data), 'truncated legacy LZ4 length')
        size, = struct.unpack_from('<I', data, pos)
        pos += 4
        if size == 0:
            require(not any(data[pos:]), 'trailing legacy LZ4 data')
            break
        require(len(chunks) < 1024, 'legacy LZ4 block count limit')
        require(size <= BLOCK + BLOCK // 255 + 16 and pos + size <= len(data), 'invalid legacy LZ4 block')
        chunk = lz4.block.decompress(data[pos:pos + size], uncompressed_size=BLOCK)
        require(chunk and len(chunk) <= BLOCK, 'invalid legacy LZ4 output')
        total += len(chunk)
        require(total <= LIMIT, 'expanded ramdisk byte limit')
        chunks.append(chunk)
        pos += size
    require(chunks, 'empty legacy LZ4 stream')
    return b''.join(chunks)


def cpio(data):
    require(len(data) <= LIMIT, 'cpio byte limit')
    pos, seen = 0, set()
    for _ in range(100000):
        require(pos + 110 <= len(data) and data[pos:pos + 6] in (b'070701', b'070702'), 'invalid newc header')
        magic = data[pos:pos + 6]
        require(all(c in b'0123456789abcdefABCDEF' for c in data[pos + 6:pos + 110]), 'invalid cpio integer')
        fields = [int(data[at:at + 8], 16) for at in range(pos + 6, pos + 110, 8)]
        mode, nlink, size, namesize, check = fields[1], fields[4], fields[6], fields[11], fields[12]
        pos += 110
        require(1 <= namesize <= 4096 and pos + namesize <= len(data), 'invalid cpio name length')
        raw = data[pos:pos + namesize]
        require(raw[-1:] == b'\0' and b'\0' not in raw[:-1], 'invalid cpio name')
        name = raw[:-1].decode('utf-8')
        pos = align(pos + namesize, 4)
        require(pos + size <= len(data), 'cpio payload out of bounds')
        payload = data[pos:pos + size]
        pos = align(pos + size, 4)
        require((sum(payload) & 0xffffffff) == check if magic == b'070702' else check == 0,
                'invalid cpio checksum')
        if name == 'TRAILER!!!':
            require(size == 0 and not any(data[pos:]), 'trailing cpio content')
            return
        path = PurePosixPath(name)
        canonical = path.as_posix()
        require(name and not path.is_absolute() and '..' not in path.parts and canonical not in seen,
                'unsafe or duplicate cpio name')
        seen.add(canonical)
        require(len(seen) <= 100000, 'cpio entry limit')
        yield path, mode, nlink, payload
    raise ValueError('cpio entry limit or missing trailer')


def extract(data, output):
    require(not output.exists(), 'ramdisk output already exists')
    rows = fragments(data)
    output.mkdir(mode=0o700)
    report = {'vendor_boot_sha256': sha(data), 'fragments': [], 'modules': [], 'metadata': [],
              'scope': 'Static non-recovery fragments; board selection, runtime loading and signature trust unknown'}
    total_decoded = 0
    for row in rows:
        compressed = row.pop('data')
        row.update(compressed_sha256=sha(compressed), compressed_bytes=len(compressed))
        report['fragments'].append(row)
        if row['type'] == 2:
            row['selection'] = 'recovery excluded from normal-boot candidate inventory'
            continue
        decoded = decode(compressed)
        total_decoded += len(decoded)
        require(total_decoded <= LIMIT, 'total expanded ramdisk byte limit')
        row.update(decoded_bytes=len(decoded), decoded_sha256=sha(decoded), selection='normal-boot candidate, board-dependent')
        root = output / str(row['index'])
        root.mkdir(mode=0o700)
        for path, mode, nlink, payload in cpio(decoded):
            module = path.name.endswith(('.ko', '.ko.gz', '.ko.xz', '.ko.zst'))
            metadata = path.name.startswith('modules.') or path.name.endswith('.rc') or path.name.startswith('fstab.')
            if not module and not metadata:
                continue
            require(stat.S_ISREG(mode) and nlink == 1 and len(payload) <= 64 * 1024**2,
                    'selected cpio member is nonregular, hardlinked or oversized')
            target = root.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.exists(), 'duplicate extracted destination')
            target.write_bytes(payload)
            record = {'fragment': row['index'], 'path': path.as_posix(), 'bytes': len(payload), 'sha256': sha(payload)}
            report['modules' if module else 'metadata'].append(record)
    require(report['modules'], 'no normal vendor ramdisk module evidence')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    size, expected = PARTITIONS['vendor_boot']
    require(args.image.stat().st_size == size, 'unexpected public vendor_boot size')
    data = args.image.read_bytes()
    require(sha(data) == expected, 'unexpected public vendor_boot digest')
    report = extract(data, args.output)
    args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
