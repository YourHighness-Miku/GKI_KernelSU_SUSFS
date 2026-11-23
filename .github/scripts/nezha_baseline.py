"""Check original public-OTA Binder requirements without changing a module."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import time
import urllib.request
import bz2
import lzma

URL = 'https://bigota.d.miui.com/OS4.0.7.0.XPACNXM/nezha-ota_full-OS4.0.7.0.XPACNXM-user-17.0-5d0985edfa.zip'
SYSTEM_DLKM_SHA = 'b4177b860c3c99ccacf8e1fefb8584032ba214f61fe47e9f9cd78c4d3820d0d9'


def read_range(offset, length):
    for attempt in range(4):
        try:
            req = urllib.request.Request(URL, headers={'Range': f'bytes={offset}-{offset+length-1}', 'Accept-Encoding': 'identity'})
            with urllib.request.urlopen(req, timeout=60) as response:
                assert response.status == 206
                assert response.headers['Content-Range'].startswith(f'bytes {offset}-{offset+length-1}/')
                data = response.read(length+1)
                assert len(data) == length
                return data
        except Exception:
            if attempt == 3:
                raise
            time.sleep(3*(attempt+1))


def fields(data):
    at = 0

    def varint():
        nonlocal at
        value = 0
        for i in range(10):
            byte = data[at]
            at += 1
            value |= (byte & 127) << (7*i)
            if byte < 128:
                return value
        raise ValueError('Invalid varint')

    result = {}
    while at < len(data):
        key = varint()
        if key & 7 == 0:
            value = varint()
        elif key & 7 == 2:
            size = varint()
            assert size <= len(data)-at
            value = data[at:at+size]
            at += size
        else:
            raise ValueError('Unsupported protobuf wire type')
        result.setdefault(key >> 3, []).append(value)
    return result


def fetch(output):
    first = read_range(0, 524288)
    pos = first.index(b'CrAU\0\0\0\0\0\0\0\x02')
    version, length, signature_length = struct.unpack_from('>QQI', first, pos+4)
    assert version == 2 and length < 8*1024**2
    manifest = fields(read_range(pos+24, length))
    start = pos+24+length+signature_length
    block = manifest.get(3, [4096])[0]
    part, = [fields(raw) for raw in manifest[13] if fields(raw)[1][0] == b'system_dlkm']
    info = fields(part[7][0])
    assert info[2][0].hex() == SYSTEM_DLKM_SHA and info[1][0] <= 64*1024**2
    image = bytearray(info[1][0])
    for number, op in enumerate(map(fields, part[8])):
        kind = op[1][0]
        size = op.get(3, [0])[0]
        raw = b''
        for offset in range(0, size, 512*1024):
            raw += read_range(start+op[2][0]+offset, min(size-offset, 512*1024))
        extents = [fields(e) for e in op[6]]
        count = sum(e[2][0]*block for e in extents)
        if kind == 1:
            raw = bz2.decompress(raw)
        elif kind == 8:
            raw = lzma.decompress(raw)
        elif kind in (6, 7):
            raw = bytes(count)
        else:
            assert kind == 0, kind
        assert len(raw) == count
        idx = 0
        for extent in extents:
            off, n = extent[1][0]*block, extent[2][0]*block
            assert off+n <= len(image)
            image[off:off+n] = raw[idx:idx+n]
            idx += n
        print('Verified operation', number, flush=True)
    assert hashlib.sha256(image).hexdigest() == SYSTEM_DLKM_SHA
    output.write_bytes(image)
    print('Public OTA system_dlkm SHA-256 verified', flush=True)


def requirements(ko):
    assert ko[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', ko, 18)[0] == 183
    table_offset = struct.unpack_from('<Q', ko, 40)[0]
    entry_size, count, strings = struct.unpack_from('<HHH', ko, 58)

    def section(index):
        at = table_offset+index*entry_size
        name = struct.unpack_from('<I', ko, at)[0]
        offset, size = struct.unpack_from('<QQ', ko, at+24)
        assert offset+size <= len(ko)
        return name, ko[offset:offset+size]

    names = section(strings)[1]
    sections = {names[name:].split(b'\0', 1)[0]: data for name, data in map(section, range(count))}
    symbols = sections[b'__version_ext_names'].rstrip(b'\0').split(b'\0')
    crcs = (crc for crc, in struct.iter_unpack('<I', sections[b'__version_ext_crcs']))
    return {name.decode(): crc for name, crc in zip(symbols, crcs, strict=True)}


def verify(module, symvers, output):
    ko = module.read_bytes()
    expected = requirements(ko)
    assert len(expected) == 240, 'Unexpected original module requirements'
    actual = {}
    for line in symvers.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            crc, name = int(parts[0], 16), parts[1]
            assert name not in actual or actual[name] == crc, name
            actual[name] = crc
    missing = sorted(set(expected)-set(actual))
    wrong = {name: {'required': hex(crc), 'built': hex(actual[name])}
             for name, crc in expected.items() if name in actual and actual[name] != crc}
    report = {'module_sha256': hashlib.sha256(ko).hexdigest(), 'public_system_dlkm_sha256': SYSTEM_DLKM_SHA,
              'required': len(expected), 'matched': len(expected)-len(missing)-len(wrong),
              'missing': missing, 'wrong_crc': wrong,
              'scope': 'Static symbol/CRC only; not module signature, all OEM modules, AVB trust or hardware boot'}
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2), flush=True)
    assert not missing and not wrong, 'Original Binder imports are incompatible'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['fetch', 'verify'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--module', type=Path)
    parser.add_argument('--symvers', type=Path)
    args = parser.parse_args()
    if args.mode == 'fetch':
        fetch(args.output)
    else:
        verify(args.module, args.symvers, args.output)
