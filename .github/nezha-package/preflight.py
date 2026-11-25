"""Validate a fixed prospective AK3 payload; never create a ZIP or execute it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

AK3_COMMIT = 'e1e9dce98430c5c6f231f7094a8c7f4ecaf50948'
TEMPLATE_SHA = '74aedf1e09955d34754f2f6ef4f8d6f60c2ec1af44cde8229345aba9f1be29e3'
IMAGE_SHA = '278e05748f16841f4cc86cd33954e065acef0e34038a949385dd196c1219a47c'
ASSETS = {
    'LICENSE': ('df6f65da47d459fdf2a2ef0eadb34f37d838befc91352b64a84f35507bea95cd', 11630),
    'META-INF/com/google/android/update-binary': ('18bfaca89bdf67115447895e28b65a6127a8ddab6ff2561b214e70cef35f76f9', 19948),
    'META-INF/com/google/android/updater-script': ('ef91e7d8a9b3dc2076be6412932d82657751d0f21471b1d09f2ca8855bcbb899', 115),
    'tools/ak3-core.sh': ('715d7bde56eed0c02d56956f2ffa3a41a181a6b2523b5e356f79f127f46d7b38', 39792),
    'tools/busybox': ('c629fce4b0dd3ba9775f851d0941e74582115f423258d3a79800f2bd11d30f5c', 1498688),
    'tools/magiskboot': ('4c480c9ffc51b4b9d8c3760bb188fd1eb73972a90983963ef791bca6faa65d6c', 1015160),
}
REQUIRED = {
    'do.devicecheck': '1', 'device.name1': 'nezha', 'do.check_boot_version': '1',
    'do.modules': '0', 'do.systemless': '0', 'block': 'boot', 'is_slot_device': '1',
    'slot_select': 'active', 'patch_vbmeta_flag': '0', 'PATCHVBMETAFLAG': 'false',
    'NO_VBMETA_PARTITION_PATCH': '1', 'expected_image': IMAGE_SHA,
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def prepare_backend(data):
    expected, length = ASSETS['META-INF/com/google/android/update-binary']
    require(len(data) == length and hashlib.sha256(data).hexdigest() == expected,
            'Unreviewed AK3 backend')
    require(data.count(b'debugging() {\n') == data.count(b'cleanup() {\n') == 1,
            'Ambiguous debug archive function')
    begin, end = data.index(b'debugging() {\n'), data.index(b'cleanup() {\n')
    require(begin < end, 'Unexpected backend function order')
    return data[:begin] + b'debugging() { :; }\n' + data[end:]


def read_regular(path, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError('Missing or linked input: ' + str(path)) from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'Invalid input type/size')
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(1048576, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, 'Input grew beyond bound')
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == before.st_size,
                'Input changed while reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def template_policy(text):
    for name, expected in REQUIRED.items():
        values = re.findall(r'^(?:export\s+)?' + re.escape(name) + r'=(.*)$', text, re.M)
        require(values == [expected], 'Unsafe or ambiguous template setting: ' + name)
    for index in range(2, 6):
        require(re.findall(r'^device\.name' + str(index) + r'=(.*)$', text, re.M) == [''],
                'Unexpected device alias')
    anchor = '. tools/ak3-core.sh'
    require(text.count(anchor) == 1, 'Ambiguous core import')
    prefix = text.split(anchor)[0]
    for name in ('PATCHVBMETAFLAG', 'NO_VBMETA_PARTITION_PATCH', 'patch_vbmeta_flag', 'slot_select'):
        require(re.search(r'^(?:export\s+)?' + name + '=', prefix, re.M), 'Setting applied after core import')
    require('vendor_patch_allowed "$vendor_patch" || exit 1' in prefix, 'Missing strict vendor patch guard')
    require('sha256sum "$AKHOME/Image"' in prefix and '[ "$actual_image" = "$expected_image" ] || exit 1' in prefix,
            'Missing pre-import payload integrity check')
    require('flash_boot' in text and 'write_boot' not in text and 'flash_generic' not in text and 'reset_ak' not in text,
            'Unexpected multi-partition install path')
    return dict(REQUIRED)


def arm64_header(data):
    require(len(data) >= 64 and data[56:60] == b'ARMd', 'Not an ARM64 Image')
    text_offset, runtime_size, flags = struct.unpack_from('<QQQ', data, 8)
    require((flags >> 1) & 3 == 1, 'Not the tested 4K page configuration')
    require(runtime_size > 0, 'Unknown runtime image extent')
    return {'text_offset': text_offset, 'runtime_image_bytes': runtime_size, 'flags': flags}


def assess(image, assets, template):
    image_data = read_regular(image, 64 * 1024**2)
    require(hashlib.sha256(image_data).hexdigest() == IMAGE_SHA and len(image_data) == 44603904,
            'Not the exact previously passed candidate')
    template_data = read_regular(template, 16384)
    require(hashlib.sha256(template_data).hexdigest() == TEMPLATE_SHA, 'Unreviewed installer template')
    policy = template_policy(template_data.decode())
    observed, prepared = {}, {}
    for name, (expected, length) in ASSETS.items():
        data = read_regular(assets / name, 3 * 1024**2)
        require(len(data) == length and hashlib.sha256(data).hexdigest() == expected, 'Fixed AK3 asset mismatch: ' + name)
        observed[name] = {'bytes': length, 'sha256': expected}
        output = prepare_backend(data) if name == 'META-INF/com/google/android/update-binary' else data
        prepared[name] = {'bytes': len(output), 'sha256': hashlib.sha256(output).hexdigest()}
    return {
        'status': 'PAYLOAD_PREFLIGHT_ONLY', 'source_run': 45524716598, 'image_sha256': IMAGE_SHA,
        'image_file_bytes': len(image_data), 'arm64': arm64_header(image_data),
        'ak3_commit': AK3_COMMIT, 'template_sha256': TEMPLATE_SHA, 'fixed_assets': observed, 'prepared_assets': prepared, 'template_policy': policy,
        'debug_archive_export_disabled': True,
        'prospective_archive_allowlist': sorted([*ASSETS, 'Image', 'anykernel.sh']),
        'installer_executed': False, 'flashable_archive_created': False, 'release_authorized': False,
        'remaining': ['Original signed boot-content descriptor mismatch', 'Actual runtime provider and device boot unproven'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = assess(args.image, args.assets, args.template)
    with args.report.open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
