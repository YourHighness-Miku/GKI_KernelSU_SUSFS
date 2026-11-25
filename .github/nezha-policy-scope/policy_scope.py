"""Recalculate a given stock-filter hypothesis, not actual module selection or boot."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'nezha-audit'))
from module_inventory import Inventory, directory, kernel_exports, read_file, require

INPUT_SHA = {
    'module-audit.json': 'd09adf6f2e1ab2ac6611861e20a1a03d8e42918995c450ae84909c0ef954e903',
    'module-load-metadata.json': '4d37818e6da8b6bdea973a02c499355bdbd70132ad3d988b195040e195f8e1ce',
    'Module.symvers': '3c4cec4c93217ba5ba406fbf771447d57ad953b440c31a9dfd4cb9c8b8f129ea',
}
BLOCKLIST_SHA = '370cb88e7e8915f34e94bd6b93616f263be8a3523adc15fb554a712dc016a03f'
EXCLUDED = {
    'flatten/lib/modules/zsmalloc.ko': 'b54598bea0a162cd2578f9d1490095fef148014de0c7dbaf012036b6adcbc465',
    'flatten/lib/modules/zram.ko': '7a440b89b62385d1affc0dca25af32c75f6e03af1a884e3d2ae8e4e75402b3c3',
    'lib/modules/6.12.69-android16-6-g43b5ab7e247d-abogki561813157-4k/kernel/mm/zsmalloc.ko':
        'b54598bea0a162cd2578f9d1490095fef148014de0c7dbaf012036b6adcbc465',
    'lib/modules/6.12.69-android16-6-g43b5ab7e247d-abogki561813157-4k/kernel/drivers/block/zram/zram.ko':
        '7a440b89b62385d1affc0dca25af32c75f6e03af1a884e3d2ae8e4e75402b3c3',
}


def declaration(metadata, root, path):
    selected = [f for f in metadata['files'] if f['root_index'] == root and f['path'] == path]
    require(len(selected) == 1, 'Missing or ambiguous original declaration: ' + path)
    row, = selected
    data = row['text'].encode()
    require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
            'Declaration content/hash mismatch')
    return row


def recalculate(rows, kernel):
    inv = Inventory()
    for index, original in enumerate(rows):
        row = copy.deepcopy(original)
        row.update(id=index, original_id=original['id'])
        row['imports'] = {name: {'required_crc': rec['required_crc'], 'undefined_binding': rec['undefined_binding']}
                          for name, rec in row['imports'].items()}
        inv.rows.append(row)
        for name, crc in row['observed_exports'].items():
            inv.providers[name][row['expanded_sha256']] = (crc, index)
    counts = inv.compare(kernel)
    return inv.rows, counts


def evaluate(audit, metadata, symvers):
    require(not audit['inventory_errors'] and audit['module_rows'] == len(audit['modules']) > 0,
            'Incomplete source inventory')
    rows = audit['modules']
    require([r['id'] for r in rows] == list(range(len(rows))), 'Source occurrence identities differ')
    kernel = kernel_exports(symvers)
    require(hashlib.sha256(symvers).hexdigest() == audit['symvers']['sha256'], 'Candidate export identity differs')
    raw_rows, raw_counts = recalculate(rows, kernel)
    require(raw_counts == audit['counts'], 'Source counts do not replay')
    blocklist = declaration(metadata, 1, 'lib/modules/system_dlkm.modules.blocklist')
    require(blocklist['sha256'] == BLOCKLIST_SHA, 'Unreviewed stock filter')
    removed = [r for r in rows if r['root_index'] == 0 and r['path'] in EXCLUDED]
    require(len(removed) == len(EXCLUDED) and {r['path'] for r in removed} == set(EXCLUDED),
            'Original filtered occurrence coverage differs')
    require(all(r['expanded_sha256'] == EXCLUDED[r['path']] for r in removed), 'Filtered content differs')
    removed_ids = {r['id'] for r in removed}
    selected, counts = recalculate([r for r in rows if r['id'] not in removed_ids], kernel)
    selected_by_original = {r['original_id']: r for r in selected}
    resolutions = []
    for raw in raw_rows:
        for name, rec in raw['imports'].items():
            if rec['comparison'] == 'matched':
                continue
            item = {'original_id': raw['original_id'], 'root_index': raw['root_index'], 'path': raw['path'],
                    'symbol': name, 'required_crc': rec['required_crc'], 'raw_comparison': rec['comparison']}
            if raw['original_id'] in removed_ids:
                item['conditional_disposition'] = 'EXCLUDED_BY_GIVEN_STOCK_FILTER'
            else:
                current = selected_by_original[raw['original_id']]['imports'][name]
                item['conditional_disposition'] = current['comparison']
                if current.get('source') == 'observed_oem_export':
                    provider = selected[current['provider_id']]
                    item['provider'] = {k: provider[k] for k in ('original_id', 'root_index', 'path', 'expanded_sha256')}
                    item['observed_crc'] = current['observed_crc']
            resolutions.append(item)
    for root, path, prefix in ((1, 'lib/modules/modules.dep', '/vendor/lib/modules/'),
                               (2, '0/lib/modules/modules.dep', '/lib/modules/')):
        dep = declaration(metadata, root, path)
        lines = set(dep['text'].splitlines())
        for consumer in ('zram', 'node_cache'):
            require(prefix + consumer + '.ko: ' + prefix + 'zsmalloc.ko' in lines,
                    'Original consumer dependency differs')
    passed = not any(counts[k] for k in ('wrong_crc', 'missing_or_external', 'unsupported'))
    return {
        'status': 'CONDITIONAL_SELECTED_CRCS_MATCH' if passed else 'CONDITIONAL_GRAPH_UNRESOLVED',
        'source_audit_run': 45579562778, 'source_candidate_run': 45524716598,
        'raw_status_unchanged': audit['status'], 'raw_counts_replayed': raw_counts,
        'raw_occurrences': len(rows), 'excluded_original_ids': sorted(removed_ids),
        'conditional_occurrences': len(selected), 'conditional_counts_replayed': counts,
        'six_issue_dispositions': resolutions,
        'assumptions_not_established_by_this_check': [
            'The original normal system-script filter is the effective request policy',
            'No other requester or preloaded module defeats that filter',
            'Effective init properties, mounts and services follow the retained original route',
        ],
        'scope': 'Replayed static CRC graph under the given immutable stock-filter hypothesis only',
        'runtime_provider_observed': False, 'raw_global_audit_passed': False,
        'boot_verified': False, 'release_authorized': False,
    }


def pinned(path, name):
    with directory(path.parent) as fd:
        data = read_file(fd, path.name, 16 * 1024**2)
    require(hashlib.sha256(data).hexdigest() == INPUT_SHA[name], 'Source snapshot changed: ' + name)
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--symvers', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(json.loads(pinned(args.audit, 'module-audit.json')),
                      json.loads(pinned(args.metadata, 'module-load-metadata.json')),
                      pinned(args.symvers, 'Module.symvers'))
    with args.report.open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    print(result['status'], result['conditional_counts_replayed'])
    raise SystemExit(result['status'] != 'CONDITIONAL_SELECTED_CRCS_MATCH')
