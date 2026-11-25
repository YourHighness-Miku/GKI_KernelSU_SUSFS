"""Assemble one conditional AK3 only inside the authorized GitHub Actions job."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import zipfile

from gate import REPACKED_SHA, evaluate, load_bound, validate_runs
from preflight import ASSETS, IMAGE_SHA, assess, prepare_backend, prepare_core, read_regular, require

ARCHIVE_NAME = 'Nezha-r74-Nova-SUSFS-DroidSpaces-Networking-BBG-conditional.zip'
SELF = 'META-INF/com/google/android/update-binary'


def identity(data):
    return len(data), hashlib.sha256(data).hexdigest()


def verify_archive(path, payloads):
    require(path.stat().st_size < 64 * 1024**2, 'Archive exceeds installer admission')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) == len(payloads) == 8 and {i.filename for i in infos} == set(payloads)
                and not archive.comment, 'Archive inventory differs')
        for item in infos:
            require(not item.is_dir() and not item.extra and not item.comment
                    and not item.flag_bits & 1 and item.extract_version <= 20
                    and stat.S_ISREG(item.external_attr >> 16), 'Unexpected ZIP member type/encoding')
            require(item.file_size == len(payloads[item.filename])
                    and archive.read(item) == payloads[item.filename], 'Archive payload differs')
        require(archive.testzip() is None, 'Archive CRC failed')
    definitions = payloads[SELF].decode().split('\n# entrypoint\n')
    require(len(definitions) == 2, 'Ambiguous restricted bootstrap')
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(['/bin/sh', '-c', definitions[0] + '\nset -f\numask 077\nverify_payload "$1"',
                                 'verify-only', str(path.resolve())], cwd=tmp,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=120)
        require(result.returncode == 0, 'Actual archive rejected by nonexecuting bootstrap helpers: '
                + result.stderr.decode(errors='replace')[:1000])
        observed = {p.relative_to(tmp).as_posix(): p for p in Path(tmp).rglob('*') if p.is_file()}
        require(set(observed) == set(payloads) - {SELF}, 'Verified extraction inventory differs')
        require(all(observed[name].read_bytes() == payloads[name] for name in observed),
                'Verified extraction bytes differ')
    return {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'members': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        for name, data in sorted(payloads.items())},
            'installer_executed': False, 'archive_helpers_validated_without_payload_execution': True}


def build(image, assets, evidence_directory, runs_path, output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == 'YourHighness-Miku/GKI_KernelSU_SUSFS'
            and os.environ.get('GITHUB_REF') == 'refs/heads/fix/nezha-r74-binder-baseline',
            'Real package assembly is GitHub Actions only on the authorized branch')
    validate_runs(json.loads(read_regular(runs_path, 1048576)))
    evidence = load_bound(evidence_directory)
    decision = evaluate(evidence)
    require(not output.exists() and output.parent.is_dir(), 'Output directory must be absent')
    template = Path(__file__).resolve().parents[1] / 'nezha-package/anykernel.sh'
    fresh = assess(image, assets, template)
    baseline = evidence['payload-preflight.json']
    for field in ('fixed_assets', 'template_sha256', 'image_sha256', 'image_file_bytes', 'template_policy', 'arm64'):
        require(fresh[field] == baseline[field], 'Current payload differs from reviewed baseline: ' + field)
    require(fresh['prepared_assets']['tools/ak3-core.sh'] == baseline['prepared_assets']['tools/ak3-core.sh'],
            'Derived transformation core differs')
    payloads = {'Image': read_regular(image, 64 * 1024**2), 'anykernel.sh': read_regular(template, 16384)}
    require(identity(payloads['Image']) == (44603904, IMAGE_SHA), 'Exact passed Image missing')
    original_backend = None
    for name, (digest, size) in ASSETS.items():
        data = read_regular(assets / name, 3 * 1024**2)
        require(identity(data) == (size, digest), 'Unreviewed source asset: ' + name)
        if name == SELF:
            original_backend = data
        else:
            payloads[name] = prepare_core(data) if name == 'tools/ak3-core.sh' else data
    pins = {name: identity(data) for name, data in payloads.items()}
    payloads[SELF] = prepare_backend(original_backend, pins, REPACKED_SHA)
    require(b'@PAYLOAD_PINS@' not in payloads[SELF] and b'@REPACKED_BOOT_SHA@' not in payloads[SELF],
            'Unrendered installer parameters')
    for name in ('anykernel.sh', SELF, 'tools/ak3-core.sh'):
        result = subprocess.run(['sh', '-n'], input=payloads[name], capture_output=True, timeout=10)
        require(result.returncode == 0, 'Invalid shell syntax: ' + name)
    output.mkdir(mode=0o700)
    temporary = output / 'assembling.zip'
    try:
        with zipfile.ZipFile(temporary, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                             allowZip64=False) as archive:
            for name, data in sorted(payloads.items()):
                member = zipfile.ZipInfo(name, date_time=(2026, 11, 25, 0, 0, 0))
                member.create_system = 3
                mode = 0o755 if name == SELF or name.startswith('tools/') else 0o644
                member.external_attr = (stat.S_IFREG | mode) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, data, compresslevel=6)
        details = verify_archive(temporary, payloads)
        final = output / ARCHIVE_NAME
        temporary.rename(final)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    decision.update(archive_created=True, archive=ARCHIVE_NAME, archive_identity=details,
                    actual_guard_preflight=fresh, prepared_bootstrap_sha256=identity(payloads[SELF])[1])
    with (output / 'conditional-package.json').open('x') as handle:
        json.dump(decision, handle, indent=2)
        handle.write('\n')
    return decision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'assets', 'evidence', 'runs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = build(args.image, args.assets, args.evidence, args.runs, args.output)
    print(result['status'], result['archive_identity']['sha256'])


if __name__ == '__main__':
    main()
