"""Read-only, revision-specific ABL policy evidence; never change a boot image."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, __version__ as CAPSTONE_VERSION


ABL_SIZE = 335872
ABL_SHA = '9f6a3bd6ec3c2785b2fab8101c779990cb85fc7c3de7bead2798f015b8c2da50'
DECODED_SHA = '576dc6430ee021e7f7e2596bcc0e90faab378733921a7a59ea33a167b502880f'
PE_SHA = '56ec352c42637ec1ce81bca0673e2a5f93dfb0081a8b2fe212ff9c8c2bd0d5b0'
RESULT_NAMES = ('OK', 'ERROR_OOM', 'ERROR_IO', 'ERROR_VERIFICATION',
                'ERROR_ROLLBACK_INDEX', 'ERROR_PUBLIC_KEY_REJECTED',
                'ERROR_INVALID_METADATA', 'ERROR_UNSUPPORTED_VERSION',
                'ERROR_INVALID_ARGUMENT')
EXPECTED = {
    0x222EC: ('ldrb', 'w27, [x8, #0xddd]'),
    0x2230C: ('cmp', 'w27, #0'),
    0x22318: ('cset', 'w25, ne'),
    0x22860: ('orr', 'w10, w25, #2'),
    0x2286C: ('cmp', 'w9, #0'),
    0x22870: ('csel', 'w24, w25, w10, ne'),
    0x22C08: ('mov', 'w3, w24'),
    0x22C0C: ('bl', '#0x286a0'),
    0x22C14: ('mov', 'w25, w0'),
    0x22C18: ('cbz', 'x8, #0x22e30'),
    0x22C28: ('b', '#0x22e30'),
    0x22E30: ('ldr', 'x8, [sp, #0xa8]'),
    0x22E34: ('cbz', 'x8, #0x22e78'),
    0x22E38: ('cbz', 'w27, #0x22e8c'),
    0x22E44: ('cmp', 'w25, #5'),
    0x22E48: ('b.hi', '#0x22e98'),
    0x22E4C: ('bl', '#0x64850'),
    0x22E50: ('b.eq', '#0x22e98'),
    0x22E5C: ('bl', '#0x2d440'),
    0x22E64: ('adrp', 'x1, #0x76000'),
    0x22E68: ('add', 'x1, x1, #0xf2c'),
    0x22E74: ('b', '#0x22ee0'),
    0x22E8C: ('cbz', 'w25, #0x22ecc'),
    0x22EC8: ('b', '#0x2255c'),
    0x22EE0: ('mov', 'x21, xzr'),
    0x22F20: ('ldr', 'x9, [x8, #0x20]'),
    0x22F28: ('b.hs', '#0x22fd8'),
    0x27C64: ('adrp', 'x8, #0xd5000'),
    0x27C6C: ('ldrb', 'w8, [x8, #0xddd]'),
    0x27C70: ('strb', 'w8, [x1]'),
    0x28538: ('adrp', 'x9, #0x27000'),
    0x2853C: ('add', 'x9, x9, #0xc4c'),
    0x28540: ('stp', 'x8, x9, [x19, #0x40]'),
    0x286D0: ('ldr', 'x8, [x0, #0x48]'),
    0x64854: ('mov', 'w8, #1'),
    0x64858: ('mov', 'w9, #0x39'),
    0x6485C: ('lsl', 'w8, w8, w25'),
    0x64860: ('tst', 'w8, w9'),
    0x64864: ('ret', ''),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixed_efi(data):
    if len(data) != ABL_SIZE or sha(data) != ABL_SHA:
        raise ValueError('Not the pinned public nezha ABL')
    raw = data[4216:4216 + 270478]
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 * 1024**2)
    decoded = decoder.decompress(raw, max_length=1089737)
    if not decoder.eof or decoder.unused_data or sha(decoded) != DECODED_SHA:
        raise ValueError('Public ABL container no longer matches reviewed extraction')
    pe = decoded[184:184 + 1089536]
    if sha(pe) != PE_SHA or pe[:2] != b'MZ':
        raise ValueError('Unexpected public ABL executable')
    return pe


def conditional_continuation(unlocked, result, loaded_data):
    if not loaded_data:
        return False
    return result == 0 or (unlocked and 0 <= result <= 5 and bool((1 << result) & 0x39))


def inspect(data):
    if CAPSTONE_VERSION != '5.0.6':
        raise ValueError('Unreviewed disassembler version')
    pe = fixed_efi(data)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for address, expected in EXPECTED.items():
        instructions = list(md.disasm(pe[address:address + 4], address))
        if len(instructions) != 1 or (instructions[0].mnemonic, instructions[0].op_str) != expected:
            raise ValueError(f'Reviewed instruction differs at RVA {address:#x}')
    enum = {}
    for code, expected in enumerate(RESULT_NAMES):
        address = struct.unpack_from('<Q', pe, 0xBB658 + code * 8)[0]
        end = pe.find(b'\0', address, address + 128)
        if end < 0 or pe[address:end].decode() != expected:
            raise ValueError('Embedded AVB result-name mapping differs')
        enum[code] = expected
    log = b'State: Unlocked, AvbSlotVerify returned %a, continue boot\n\0'
    if pe[0x76F2C:0x76F2C + len(log)] != log:
        raise ValueError('Reviewed continuation log differs')
    ranges = ((0x222B0, 0x22410), (0x22838, 0x228D8), (0x22BF8, 0x22C2C),
              (0x22E30, 0x23090), (0x27C4C, 0x27CA4), (0x284D8, 0x285A0),
              (0x286A0, 0x286DC), (0x28900, 0x28A84), (0x2D440, 0x2D4C0),
              (0x64850, 0x64868))
    assembly = [[{'rva': x.address, 'mnemonic': x.mnemonic, 'operands': x.op_str}
                 for x in md.disasm(pe[lo:hi], lo)] for lo, hi in ranges]
    return {
        'artifact_sha256': ABL_SHA, 'decoded_sha256': DECODED_SHA, 'efi_sha256': PE_SHA,
        'coordinates': 'Preferred PE base 0 RVAs, not observed runtime addresses',
        'authority': 'Pinned public bytes and decoded instructions; reviewed conditional static inference, not automated whole-program proof',
        'disassembler_version': CAPSTONE_VERSION,
        'analyzer_sha256': sha(Path(__file__).read_bytes()),
        'producer_revision': os.environ.get('GITHUB_SHA'),
        'producer_run': os.environ.get('GITHUB_RUN_ID'),
        'read_is_device_unlocked_callback_rva': 0x27C4C,
        'shared_state_byte_rva': 0xD5DDD,
        'normal_avb_call_rva': 0x22C0C,
        'normal_result_branch_rva': 0x22E30,
        'conditional_unlocked_nonfatal_results': [enum[i] for i in (0, 3, 4, 5)],
        'conditional_locked_nonfatal_results': [enum[0]],
        'precondition': 'The reviewed normal AVB result branch is reached and loaded slot data is non-null',
        'locked_verification_failure_rejected': True,
        'unlocked_verification_failure_continues_at_reviewed_branch': True,
        'descriptor_consistency': 'Not evaluated by this ABL analysis; it does not alter cryptographic verification results',
        'assumptions': ['Reviewed register continuity and the compiled call conventions across intervening calls',
                        'The shared byte supplies both this branch and the observed libavb unlock callback'],
        'device_unlocked_state': 'UNKNOWN; no device consulted',
        'hardware_boot': 'UNKNOWN', 'installable_package_authorized': False,
        'limitations': ['Static result handling is not execution or complete boot-chain proof',
                        'Other partition, I/O, parsing, firmware and hardware failures remain possible',
                        'No bootloader, image, verification flag, signature or key was modified'],
        'assembly': assembly,
    }


def publish(report, output):
    if output.exists():
        raise ValueError('Refusing an existing policy report')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(report, indent=2) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('abl', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    if args.abl.stat().st_size != ABL_SIZE:
        raise ValueError('Unexpected ABL size')
    report = inspect(args.abl.read_bytes())
    publish(report, args.report)


if __name__ == '__main__':
    main()
