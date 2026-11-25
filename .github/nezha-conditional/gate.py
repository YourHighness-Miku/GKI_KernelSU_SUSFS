"""A finite conditional packaging criterion; never rewrite OEM authentication results."""
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'nezha-package'))
from preflight import IMAGE_SHA, TEMPLATE_SHA, read_regular, require

REPACKED_SHA = '2a49d69e6c0ab4d89364f6d598c5b30983fe2fba0a618f9fcfa1cea4ece7c5bf'
FIXTURE_SHA = {
    'boot-result.json': 'e2727d4bd66f9072a583a62505ef923a7ec975cb7ce1dc9544d1555896a07817',
    'repacked-boot-verify.txt': 'dba3a9e0fb9e06898ee30ed4c14e14b8cf1c7be39539d6420409f246bea04852',
    'conditional-policy.json': 'cdd767683d6f7868fb628b70052b000f2dfac64251540b88056a75dbc1c787f8',
    'payload-preflight.json': 'c07f7cbb9e71826e88f23729c23f49878b969ba4c298937788f0aade102d9c7a',
    'abl-policy.json': '1b93381d5d90e9dcfeebfc68979f321a4fba2c492da380bcd8672fcab04b62af',
    'abl-load-evidence.json': '2b5663c984bd115d2518b5b91595b8b99522bdf36264841bd695166367afb33d',
    'provider-evidence.json': '71a3fb62ea438bbd9dc22b0e8ee9f571110f265335207f0a3c57b70f43fa7eff',
    'capacity.json': 'd05b166d580efa57b86bec57715ce3c7889baea7d3c215ea49fb75fd1df48840',
}
PRODUCERS = {
    'candidate': (45524716598, '4c7d5e68abe115d3411dce40fb004912c17f3253', 'nezha-baseline.yml', 'success', 14983219658,
                  '960427ec7dc0aeb253c59b7be64070d949e219178e428fdd47e20c6df02e97de'),
    'boot': (45615505728, '26f4546c2a5217179d65156683c421b37cfbcdfc', 'nezha-boot-check.yml', 'failure', 15022842324,
             'f6a95c2e7f1bb3383c8327cc75a25d58ef0739639e7eb03334a6cc2f9b74d9f4'),
    'guard': (45615505980, '26f4546c2a5217179d65156683c421b37cfbcdfc', 'nezha-package-preflight.yml', 'success', 15021708729,
              '8e34f80dd26921216927fdca595c295041a1e80ff9eadccd8458a325a6a27e65'),
    'scope': (45593336776, '1f041509ef642cbc0420f2a7447046ba1949cff9', 'nezha-policy-scope.yml', 'success', 15011457957,
              '17e5a32376c82d3610cd2a9a20ddeeeb9805c58f14a267f6771f3a3de894528d'),
}


def load_bound(directory):
    result = {}
    for name, expected in FIXTURE_SHA.items():
        data = read_regular(directory / name, 200000)
        require(hashlib.sha256(data).hexdigest() == expected, 'Unreviewed evidence: ' + name)
        result[name] = json.loads(data) if name.endswith('.json') else data.decode('utf-8')
    return result


def validate_runs(runs):
    require(set(runs) == set(PRODUCERS), 'Missing or extra source runs')
    for name, (rid, sha, workflow, conclusion, aid, digest) in PRODUCERS.items():
        run = runs[name]
        expected = {'id': rid, 'head_sha': sha, 'head_branch': 'fix/nezha-r74-binder-baseline',
                    'path': '.github/workflows/' + workflow, 'status': 'completed', 'conclusion': conclusion}
        require(all(run.get(k) == v for k, v in expected.items()), 'Producer identity/state differs: ' + name)
        require(run.get('artifact_id') == aid and run.get('artifact_zip_sha256') == digest,
                'Producer artifact identity differs: ' + name)


def evaluate(evidence):
    boot = evidence['boot-result.json']
    expected = {name: {'returncode': 0} for name in ('boot-info', 'stock-boot-verify', 'vbmeta-info',
                'vbmeta_system-info', 'unpack', 'repack', 'repacked-boot-info')}
    expected['repacked-boot-verify'] = {'returncode': 1}
    require(boot['checks'] == expected and 'error' not in boot and boot['stage'] == 'repacked-boot-verify',
            'Not solely the reviewed content-digest mismatch')
    require(boot['offline_gate_passed'] is False and boot['delivery_state'] == 'BLOCKED',
            'Original authentication disposition was altered')
    require(boot['candidate_image_sha256'] == IMAGE_SHA and boot['repacked_image_sha256'] == REPACKED_SHA,
            'Candidate or golden transformation differs')
    for field in ('structural_roundtrip_passed', 'signed_vbmeta_blob_unchanged', 'signing_metadata_unchanged'):
        require(boot[field] is True, 'Repack preservation check failed: ' + field)
    blob = {'bytes': 2432, 'sha256': 'd10d34c8d68f880a554c14b4b65340efe9a68983997dc59493c83a11e5fd678e'}
    require(boot['reference_vbmeta_blob'] == boot['repacked_vbmeta_blob'] == blob, 'Signed vbmeta differs')
    stock, new = boot['reference_boot_layout'], boot['repacked_boot_layout']
    for key, value in {'header_version': 4, 'header_bytes': 1584, 'partition_bytes': 100663296,
                       'ramdisk_bytes': 0, 'signature_bytes': 0,
                       'header_metadata_sha256': '3c88019de260099905c584c0a2803b38d337757b228e187cd8be14b66705c7c9'}.items():
        require(stock[key] == new[key] == value, 'Boot layout differs: ' + key)
    empty = hashlib.sha256(b'').hexdigest()
    require(stock['kernel_bytes'] == 41511424 and new['kernel_bytes'] == 44603904
            and new['kernel_sha256'] == IMAGE_SHA, 'Kernel extent or identity differs')
    require(all(layout[k] == empty for layout in (stock, new) for k in ('ramdisk_sha256', 'signature_sha256')),
            'Unexpected ramdisk/signature region')
    text = evidence['repacked-boot-verify.txt']
    pattern = (r'Verifying image (?P<image>/tmp/[^\s]+/boot\.img) using embedded public key\n'
               r'vbmeta: Successfully verified footer and SHA256_RSA4096 vbmeta struct in (?P=image)\n'
               r'sha256 digest of (?P=image) does not match digest in descriptor\n'
               r'/home/runner/work/GKI_KernelSU_SUSFS/GKI_KernelSU_SUSFS/tools/avbtool\.py: Error verifying descriptor\.\n')
    require(re.fullmatch(pattern, text) is not None, 'Unexpected verifier diagnostic')
    scope = evidence['conditional-policy.json']
    require(scope['status'] == 'CONDITIONAL_SELECTED_CRCS_MATCH' and scope['source_candidate_run'] == 45524716598
            and scope['source_audit_run'] == 45579562778, 'Conditional module source differs')
    require(scope['conditional_counts_replayed'] == {'matched': 58829, 'wrong_crc': 0,
            'missing_or_external': 0, 'unsupported': 0} and scope['conditional_occurrences'] == 1077,
            'Conditional CRC graph failed')
    require(scope['raw_status_unchanged'] == 'UNKNOWN' and scope['raw_global_audit_passed'] is False
            and scope['runtime_provider_observed'] is False
            and scope['raw_counts_replayed'] == {'matched': 59283, 'wrong_crc': 0,
            'missing_or_external': 6, 'unsupported': 0}, 'Raw unknowns were hidden')
    guard = evidence['payload-preflight.json']
    require(guard['status'] == 'PAYLOAD_PREFLIGHT_ONLY' and guard['source_run'] == 45524716598
            and guard['image_sha256'] == IMAGE_SHA and guard['template_sha256'] == TEMPLATE_SHA,
            'Guard source differs')
    require(guard['generic_mount_backend_removed'] is True and guard['core_writer_replaced_with_guarded_single_write'] is True
            and guard['golden_repacked_identity_required'] is True, 'Restricted installer checks missing')
    policy = evidence['abl-policy.json']
    require(policy['artifact_sha256'] == '9f6a3bd6ec3c2785b2fab8101c779990cb85fc7c3de7bead2798f015b8c2da50'
            and policy['locked_verification_failure_rejected'] is True
            and policy['unlocked_verification_failure_continues_at_reviewed_branch'] is True
            and policy['conditional_locked_nonfatal_results'] == ['OK']
            and 'ERROR_VERIFICATION' in policy['conditional_unlocked_nonfatal_results'], 'OEM conditional policy differs')
    source = evidence['abl-load-evidence.json']
    require(source['inputs']['candidate_Image_sha256'] == IMAGE_SHA
            and source['inputs']['partition_bytes'] == 100663296
            and source['source_fit_bytes']['kernel_end_exclusive'] == 44608000
            and source['source_fit_bytes']['page_rounded_end'] < 100663296, 'Source buffer proof differs')
    provider, cap = evidence['provider-evidence.json'], evidence['capacity.json']
    require(provider['conditional_values']['size'] == 268435456
            and provider['ABL_fit']['reference_sha256']['passed-candidate/Image'] == IMAGE_SHA,
            'Provider proof differs')
    quantities = ('page_rounded_R', 'vendor_page_P', 'vendor_ramdisk_V', 'auxiliary_E', 'candidate_runtime_H',
                  'given_stock_published_window_S', 'fallback_min_span')
    require(all(type(cap[k]) is int and 0 <= cap[k] < 2**64 for k in quantities), 'Invalid capacity quantities')
    r, p, v, e, h, size, fallback = (cap[k] for k in quantities)
    require((r, p, v, e, h, size, fallback) == (2588672, 4096, 22246717, 0, 47775744, 268435456, 60612608),
            'Unreviewed capacity inputs')
    reserved = ((v + r + e + p - 1) // p) * p + 2 * p + 0x400000
    require(reserved == cap['reserved_D'] and size >= h + reserved == cap['required_window']
            and fallback >= h, 'Destination capacity check failed')
    return {
        'status': 'CONDITIONAL_PACKAGE_ELIGIBLE_NOT_BOOT_VERIFIED', 'conditional_zip_eligible': True,
        'scope': 'Already officially unlocked nezha; exact pinned public OTA references; unchanged OEM normal policy',
        'original_content_authentication_passed': False, 'original_boot_report_rewritten': False,
        'original_verifier_disposition': 'BLOCKED: RSA structure valid; modified content digest mismatch',
        'raw_global_module_audit_passed': False, 'raw_module_status': scope['raw_status_unchanged'],
        'raw_module_counts': dict(scope['raw_counts_replayed']),
        'conditional_module_counts': dict(scope['conditional_counts_replayed']),
        'hardware_boot_verified': False,
        'image_sha256': IMAGE_SHA, 'golden_repacked_sha256': REPACKED_SHA,
        'required_window_bytes': h + reserved, 'provider_margin_bytes': size - h - reserved,
        'unproven_conditions': [policy['precondition'], *policy['assumptions'],
                               provider['conditional_values']['predicate'], *scope['assumptions_not_established_by_this_check']],
        'limitations': ['Conditional static acceptance, not device execution or guaranteed boot',
                        'Trusted supported shell/tools and isolated installer context are prerequisites',
                        'Firmware prefix checks do not authenticate unexamined physical partition tails',
                        'Flashing is not power-loss or SIGKILL atomic'],
    }
