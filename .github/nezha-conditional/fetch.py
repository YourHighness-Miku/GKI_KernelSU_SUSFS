"""Acquire only exact prior Actions evidence and hash-pinned public utility assets."""
import hashlib
import io
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from gate import FIXTURE_SHA, PRODUCERS, validate_runs
from preflight import AK3_COMMIT, ASSETS, IMAGE_SHA, require

API_ROOT = 'https://api.github.com/repos/'
REPOSITORY = 'YourHighness-Miku/GKI_KernelSU_SUSFS'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = build_opener(NoRedirect())


def api(path, binary=False, repository=REPOSITORY):
    require(repository in (REPOSITORY, 'WildKernels/AnyKernel3') and path.startswith('/'),
            'Unexpected source repository')
    token = os.environ['GH_TOKEN']
    request = Request(API_ROOT + repository + path, headers={'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github.raw+json' if binary else 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'})
    for attempt in range(3):
        try:
            with OPENER.open(request, timeout=60) as response:
                data = response.read((64 if binary else 2) * 1024**2 + 1)
            require(len(data) <= (64 if binary else 2) * 1024**2, 'API reply exceeds bound')
            return data if binary else json.loads(data)
        except HTTPError as error:
            if error.code in (502, 503, 504) and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            if binary and error.code == 302:
                location = error.headers['Location']
                parsed = urlparse(location)
                host = parsed.hostname or ''
                require(parsed.scheme == 'https' and not parsed.username and not parsed.password
                        and (host.endswith('.blob.core.windows.net') or host.endswith('.amazonaws.com')),
                        'Unexpected artifact storage origin')
                # No GitHub Authorization header is sent to artifact storage.
                with OPENER.open(Request(location), timeout=120) as response:
                    data = response.read(64 * 1024**2 + 1)
                require(len(data) <= 64 * 1024**2, 'Artifact exceeds bound')
                return data
            raise
    raise ValueError('API acquisition did not complete')


def select(data, name, maximum):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        matches = [i for i in archive.infolist() if i.filename == name]
        require(len(matches) == 1 and 0 < matches[0].file_size <= maximum,
                'Missing, duplicate or oversized evidence member: ' + name)
        return archive.read(matches[0])


def main():
    root = Path('inputs')
    require(not root.exists(), 'Inputs must be fresh')
    root.mkdir()
    evidence = root / 'evidence'
    evidence.mkdir()
    fixture_root = Path(__file__).with_name('fixtures')
    for name, digest in FIXTURE_SHA.items():
        data = (fixture_root / name).read_bytes()
        require(hashlib.sha256(data).hexdigest() == digest, 'Reviewed native fixture differs')
        (evidence / name).write_bytes(data)
    runs = {}
    for name, (rid, sha, workflow, conclusion, aid, digest) in PRODUCERS.items():
        run = api(f'/actions/runs/{rid}')
        artifact = api(f'/actions/artifacts/{aid}')
        require(artifact['workflow_run']['id'] == rid and artifact['workflow_run']['head_sha'] == sha
                and artifact['digest'] == 'sha256:' + digest and not artifact['expired'],
                'Artifact producer/identity differs: ' + name)
        run.update(artifact_id=aid, artifact_zip_sha256=digest)
        runs[name] = run
        expected = {'id': rid, 'head_sha': sha, 'head_branch': 'fix/nezha-r74-binder-baseline',
                    'path': '.github/workflows/' + workflow, 'status': 'completed', 'conclusion': conclusion}
        require(all(run.get(k) == v for k, v in expected.items()), 'Run differs: ' + name)
        data = api(f'/actions/artifacts/{aid}/zip', binary=True)
        require(len(data) == artifact['size_in_bytes'] and hashlib.sha256(data).hexdigest() == digest,
                'Artifact bytes differ: ' + name)
        if name == 'candidate':
            image = select(data, 'Image', 44603904)
            require(len(image) == 44603904 and hashlib.sha256(image).hexdigest() == IMAGE_SHA,
                    'Candidate Image differs')
            (root / 'Image').write_bytes(image)
        else:
            members = {'boot': ('boot-result.json', 'repacked-boot-verify.txt'),
                       'scope': ('conditional-policy.json',), 'guard': ('payload-preflight.json',)}[name]
            for member in members:
                value = select(data, member, 200000)
                require(hashlib.sha256(value).hexdigest() == FIXTURE_SHA[member],
                        'Live evidence differs from reviewed actual report: ' + member)
                (evidence / member).write_bytes(value)
        print('Verified source', name, rid, aid, digest)
    validate_runs(runs)
    (root / 'runs.json').write_text(json.dumps(runs, indent=2) + '\n')
    for name, (digest, size) in ASSETS.items():
        data = api(f'/contents/{name}?ref={AK3_COMMIT}', binary=True, repository='WildKernels/AnyKernel3')
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
                'Pinned public utility differs: ' + name)
        target = root / 'assets' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


if __name__ == '__main__':
    main()
