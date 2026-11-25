"""Fetch only fixed public ABL/module references; no private input or boot edits."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path[0:0] = [str(Path(__file__).resolve().parents[1] / name) for name in ('scripts', 'nezha')]
from boot_gate import MANIFEST_SHA, decode_operation, digest, place
from nezha_baseline import URL, fields, read_range

PARTITIONS = {
    'abl': (335872, '9f6a3bd6ec3c2785b2fab8101c779990cb85fc7c3de7bead2798f015b8c2da50'),
    'system_dlkm': (17281024, 'b4177b860c3c99ccacf8e1fefb8584032ba214f61fe47e9f9cd78c4d3820d0d9'),
    'vendor_dlkm': (59228160, '094b779c61c8b1736025230e545838001b0d4037ff2473dcbc413af128738cb4'),
}


def fetch(output):
    if output.exists():
        raise ValueError('Reference output already exists')
    first = read_range(0, 524288)
    pos = first.index(b'CrAU\0\0\0\0\0\0\0\x02')
    version, length, siglen = struct.unpack_from('>QQI', first, pos + 4)
    if version != 2 or not 0 < length <= 8 * 1024**2:
        raise ValueError('Unsupported public payload header')
    raw = read_range(pos + 24, length)
    if digest(raw) != MANIFEST_SHA:
        raise ValueError('Pinned public manifest changed')
    manifest = fields(raw)
    if manifest.get(3, [4096])[0] != 4096:
        raise ValueError('Unexpected payload block size')
    start = pos + 24 + length + siglen
    parts = [fields(p) for p in manifest[13]]
    report = {'public_url': URL, 'manifest_sha256': MANIFEST_SHA, 'partitions': {},
              'scope': 'Exact public bytes only; no runtime or authenticity assertion beyond the stated pins'}
    output.mkdir()
    for name, (size, expected) in PARTITIONS.items():
        part, = [p for p in parts if p[1][0] == name.encode()]
        info = fields(part[7][0])
        if (info[1][0], info[2][0].hex()) != (size, expected):
            raise ValueError(f'Public identity changed: {name}')
        image, occupied = bytearray(size), set()
        for index, op in enumerate(map(fields, part[8])):
            n = op.get(3, [0])[0]
            if not 0 <= n <= size:
                raise ValueError('Oversized public operation')
            data = b''.join(read_range(start + op[2][0] + at, min(n - at, 524288))
                            for at in range(0, n, 524288))
            if 8 in op and hashlib.sha256(data).digest() != op[8][0]:
                raise ValueError('Operation compressed digest mismatch')
            extents = [(e[1][0], e[2][0]) for e in map(fields, op[6])]
            decoded = decode_operation(op[1][0], data, sum(b * 4096 for _, b in extents))
            place(image, occupied, extents, decoded, 4096)
            print(name, 'verified operation', index, flush=True)
        if len(occupied) * 4096 != size or digest(image) != expected:
            raise ValueError(f'Incomplete or changed public {name}')
        (output / f'{name}.img').write_bytes(image)
        report['partitions'][name] = {'bytes': size, 'sha256': expected}
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    result = fetch(args.output)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
