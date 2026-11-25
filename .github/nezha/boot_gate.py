"""Report-only public-OTA boot assessment; never create an installable archive."""
import argparse
import bz2
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

MANIFEST_SHA = '9e888cc69b2b94c36d793b9f8cc1400d0294e0a218224bab640f083c9c03701d'
PARTITIONS = {
    'boot': (100663296, '1f7a147e34b6ca82621a194b3b6fa54735ae2236e34c65c42df41ec05422e832'),
    'init_boot': (8388608, '1f5105d5fba35d5a6ef14a429de595a7149044dcac2b90e74a18ac413b9933f2'),
    'vendor_boot': (100663296, '68a80b12e8210e0683fb0f275e0df2134db591113c9d6d91acbd34f54f4409cf'),
    'vbmeta': (12288, 'dcb74c3deca0b406b04b6892035f91c2c59475b69dc42857c3d9439a512bed78'),
    'vbmeta_system': (4096, 'ada7f6370b2821c02f4b2832cba224472ca66decdcc9c1f9a1c35d32d6e515a7'),
}
TOOL_SHA = {
    'avbtool.py': 'e5a664a38db623da00f080219bc0ee60a640a9dc4a872803616fae4938ac749b',
    'magiskboot': '4c480c9ffc51b4b9d8c3760bb188fd1eb73972a90983963ef791bca6faa65d6c',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode_operation(kind, data, count):
    if count <= 0 or count > 100663296:
        raise ValueError('Invalid operation output size')
    if kind == 1:
        decoder = bz2.BZ2Decompressor()
        result = decoder.decompress(data, max_length=count + 1)
    elif kind == 8:
        decoder = lzma.LZMADecompressor(memlimit=256 * 1024**2)
        result = decoder.decompress(data, max_length=count + 1)
    elif kind == 0:
        if len(data) != count:
            raise ValueError('Incorrect REPLACE length')
        return data
    elif kind in (6, 7):
        if data:
            raise ValueError('ZERO/DISCARD unexpectedly contains bytes')
        return bytes(count)
    else:
        raise ValueError(f'Unsupported payload operation {kind}')
    if len(result) != count or not decoder.eof or decoder.unused_data:
        raise ValueError('Invalid, trailing, or oversized compressed operation')
    return result


def place(image, occupied, extents, data, block):
    offset = 0
    for start, blocks in extents:
        if start < 0 or blocks <= 0 or (start + blocks) * block > len(image):
            raise ValueError('Invalid destination extent')
        slots = set(range(start, start + blocks))
        if occupied.intersection(slots):
            raise ValueError('Overlapping payload extents')
        size = blocks * block
        if offset + size > len(data):
            raise ValueError('Extent exceeds decoded operation')
        image[start * block:(start + blocks) * block] = data[offset:offset + size]
        occupied.update(slots)
        offset += size
    if offset != len(data):
        raise ValueError('Unused operation bytes')


def fetch(output):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    from nezha_baseline import URL, fields, read_range

    if output.exists():
        raise ValueError('Reference directory already exists')
    first = read_range(0, 524288)
    pos = first.index(b'CrAU\0\0\0\0\0\0\0\x02')
    version, length, signature_length = struct.unpack_from('>QQI', first, pos + 4)
    if version != 2 or length > 8 * 1024**2:
        raise ValueError('Unsupported payload header')
    raw = read_range(pos + 24, length)
    if digest(raw) != MANIFEST_SHA:
        raise ValueError('Public payload manifest changed')
    manifest = fields(raw)
    block = manifest.get(3, [4096])[0]
    if block != 4096:
        raise ValueError('Unexpected payload block size')
    parts = [fields(p) for p in manifest[13]]
    start = pos + 24 + length + signature_length
    report = {'public_url': URL, 'manifest_sha256': MANIFEST_SHA, 'partitions': {},
              'declared_names': [p[1][0].decode() for p in parts],
              'scope': 'Pinned public OTA bytes; no device state or OEM private keys'}
    output.mkdir()
    for name, (expected_size, expected_sha) in PARTITIONS.items():
        part, = [p for p in parts if p[1][0] == name.encode()]
        info = fields(part[7][0])
        if (info[1][0], info[2][0].hex()) != (expected_size, expected_sha):
            raise ValueError(f'Public partition identity changed: {name}')
        image = bytearray(expected_size)
        occupied = set()
        for index, operation in enumerate(map(fields, part[8])):
            size = operation.get(3, [0])[0]
            if size < 0 or size > expected_size:
                raise ValueError('Oversized operation input')
            data = b''.join(read_range(start + operation[2][0] + at, min(size - at, 524288))
                            for at in range(0, size, 524288))
            if 8 in operation and hashlib.sha256(data).digest() != operation[8][0]:
                raise ValueError('Operation compressed-data digest mismatch')
            extents = [(e[1][0], e[2][0]) for e in map(fields, operation[6])]
            data = decode_operation(operation[1][0], data, sum(n * block for _, n in extents))
            place(image, occupied, extents, data, block)
            print(name, 'verified operation', index, flush=True)
        if len(occupied) * block != expected_size or digest(image) != expected_sha:
            raise ValueError(f'Incomplete or corrupt reference {name}')
        (output / f'{name}.img').write_bytes(image)
        report['partitions'][name] = {'bytes': expected_size, 'sha256': expected_sha}
    return report


def boot_layout(data):
    if len(data) < 4096 or data[:8] != b'ANDROID!':
        raise ValueError('Not an Android boot image')
    kernel, ramdisk = struct.unpack_from('<II', data, 8)
    header, version = struct.unpack_from('<I', data, 20)[0], struct.unpack_from('<I', data, 40)[0]
    if version != 4 or not 1584 <= header <= 4096:
        raise ValueError('Expected nezha boot-v4 header')
    signature = struct.unpack_from('<I', data, 1580)[0]
    align = lambda n: (n + 4095) // 4096 * 4096
    ramdisk_offset = 4096 + align(kernel)
    signature_offset = ramdisk_offset + align(ramdisk)
    if not kernel or signature_offset + signature > len(data):
        raise ValueError('Boot components exceed partition')
    return {'header_version': version, 'header_bytes': header, 'partition_bytes': len(data),
            'kernel_bytes': kernel, 'ramdisk_bytes': ramdisk, 'signature_bytes': signature,
            'kernel_sha256': digest(data[4096:4096 + kernel]),
            'ramdisk_sha256': digest(data[ramdisk_offset:ramdisk_offset + ramdisk]),
            'signature_sha256': digest(data[signature_offset:signature_offset + signature]),
            'header_metadata_sha256': digest(data[:8] + data[12:4096])}


def signing_metadata(text):
    keys = (r'Public key \(sha1\)', 'Algorithm', 'Flags', 'Rollback Index', 'Rollback Index Location')
    result = {}
    for key in keys:
        match = re.search(rf'^{key}:\s*(.+)$', text, re.M)
        if not match:
            raise ValueError(f'Missing AVB metadata: {key}')
        result[key] = match[1].strip()
    return result


def _assess(reference, candidate, tools, reports, report):
    report['stage'] = 'input-identity'
    for name, sha in TOOL_SHA.items():
        if digest((tools / name).read_bytes()) != sha:
            raise ValueError(f'Unreviewed tool: {name}')
    for name, (size, sha) in PARTITIONS.items():
        data = (reference / f'{name}.img').read_bytes()
        if len(data) != size or digest(data) != sha:
            raise ValueError(f'Reference changed: {name}')
    image = candidate.read_bytes()
    if len(image) < 64 or image[56:60] != b'ARMd' or (struct.unpack_from('<Q', image, 24)[0] >> 1) & 3 != 1:
        raise ValueError('Candidate is not an ARM64 4K Image')
    report['candidate_image_sha256'] = digest(image)

    def run(name, command, cwd):
        return run_tool(name, command, cwd, reports, report)

    avb = [sys.executable, str(tools / 'avbtool.py')]
    stock_info = None
    for name in ('boot', 'vbmeta', 'vbmeta_system'):
        info = run(f'{name}-info', avb + ['info_image', '--image', str(reference / f'{name}.img')], reference)
        if name == 'boot':
            stock_info = info.stdout
        if name == 'boot':
            run('stock-boot-verify', avb + ['verify_image', '--image', str(reference / 'boot.img')], reference)
    report['reference_boot_layout'] = boot_layout((reference / 'boot.img').read_bytes())
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        boot = reference / 'boot.img'
        packer = ['qemu-aarch64', str(tools / 'magiskboot')]
        for name, command in [('unpack', packer + ['unpack', '-h', str(boot)])]:
            if run(name, command, work).returncode:
                raise ValueError(f'Boot tool failed: {name}')
        (work / 'kernel').write_bytes(image)
        if run('repack', packer + ['repack', str(boot), str(work / 'boot.img')], work).returncode:
            raise ValueError('Repack failed')
        new_boot = work / 'boot.img'
        layout = boot_layout(new_boot.read_bytes())
        report['repacked_boot_layout'] = layout
        old = report['reference_boot_layout']
        report['structural_roundtrip_passed'] = (layout['kernel_sha256'] == digest(image) and
            all(layout[k] == old[k] for k in ('partition_bytes', 'ramdisk_sha256', 'header_metadata_sha256')))
        info = run('repacked-boot-info', avb + ['info_image', '--image', str(new_boot)], work)
        run('repacked-boot-verify', avb + ['verify_image', '--image', str(new_boot)], work)
        report['signing_metadata_unchanged'] = signing_metadata(stock_info) == signing_metadata(info.stdout)
    report['offline_gate_passed'] = (report['structural_roundtrip_passed'] and report['signing_metadata_unchanged']
        and all(v['returncode'] == 0 for v in report['checks'].values()))
    report['delivery_state'] = 'OFFLINE_CHECKS_ONLY' if report['offline_gate_passed'] else 'BLOCKED'
    return report


def run_tool(name, command, cwd, reports, report, timeout=180):
    report['stage'] = name
    env = {'PATH': os.environ['PATH'], 'PATCHVBMETAFLAG': 'false'}
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        (reports / f'{name}.txt').write_text(text(error.stdout) + text(error.stderr))
        report['checks'][name] = {'returncode': None, 'timed_out': True}
        raise
    except OSError as error:
        (reports / f'{name}.txt').write_text(str(error) + '\n')
        report['checks'][name] = {'returncode': None, 'error_type': type(error).__name__}
        raise
    (reports / f'{name}.txt').write_text(result.stdout + result.stderr)
    report['checks'][name] = {'returncode': result.returncode}
    return result


def assess(reference, candidate, tools, reports):
    reports.mkdir(exist_ok=True)
    report = {
        'checks': {}, 'offline_gate_passed': False, 'delivery_state': 'BLOCKED',
        'scope': {
            'whole_boot_footer_avb': 'Checks listed separately below',
            'boot_v4_signature_region': 'Hashed only; not independently signature-verified',
            'outer_vbmeta_chain': 'Metadata recorded only; complete descriptor chain NOT verified',
            'oem_bootloader_trust': 'UNKNOWN', 'unlocked_device_acceptance': 'UNKNOWN',
        },
        'limitations': ['No device execution or installable archive',
                        'No verification flags changed, signatures created, or replacement bootchain published',
                        'Even a standalone offline pass does not establish full boot-chain validity or hardware bootability'],
    }
    try:
        _assess(reference, candidate, tools, reports, report)
    except (ValueError, OSError, subprocess.SubprocessError, struct.error) as error:
        report['offline_gate_passed'] = False
        report['delivery_state'] = 'BLOCKED'
        report['error'] = {'stage': report.get('stage', 'input'), 'type': type(error).__name__, 'message': str(error)}
    (reports / 'boot-result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    fetch_parser = sub.add_parser('fetch')
    fetch_parser.add_argument('output', type=Path)
    fetch_parser.add_argument('report', type=Path)
    check = sub.add_parser('assess')
    for name in ('reference', 'candidate', 'tools', 'reports'):
        check.add_argument(name, type=Path)
    args = parser.parse_args()
    if args.mode == 'fetch':
        try:
            result = fetch(args.output.resolve())
        except (AssertionError, ValueError, OSError, KeyError, struct.error, lzma.LZMAError, EOFError) as error:
            args.report.write_text(json.dumps({'delivery_state': 'BLOCKED', 'stage': 'public-reference-fetch',
                'error_type': type(error).__name__, 'error': str(error)}, indent=2) + '\n')
            raise SystemExit('Public reference acquisition failed; no flashable output created')
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    else:
        result = assess(*(getattr(args, name).resolve() for name in ('reference', 'candidate', 'tools', 'reports')))
        (args.reports / 'boot-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        if not result['offline_gate_passed']:
            raise SystemExit('Offline boot gate blocked publication; no flashable output created')
