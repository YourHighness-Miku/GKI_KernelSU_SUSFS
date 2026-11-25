"""Keep source validation separate from delivery to an unverified boot chain."""
import argparse
import json
from pathlib import Path


HOLD = 'WITHHELD_MODIFIED_BOOTCHAIN_UNVERIFIED'


def delivery_status():
    return {
        'status': HOLD,
        'candidate_delivery_allowed': False,
        'bootchain_profile_verified': False,
        'hardware_boot_verified': False,
        'original_content_authentication_passed': False,
        'target_scope': 'User-reported partition-level fake relock; exact installed implementation/version unverified',
        'required_next_evidence': 'Exact public tool identity/version and reviewed applicability; no private images or repeat flashing',
        'preserved': ['existing fake-relock installation', 'SukiSU/Nova', 'SUSFS and existing hiding',
                      'DroidSpaces', 'Networking', 'BBG', 'original Image and golden transformation',
                      'slot, target, capacity, archive authentication and write/readback safeguards'],
        'source_validation_is_not_candidate_acceptance': True,
    }


def require_delivery_approval():
    raise ValueError(HOLD + ': no reviewed applicability profile for the modified boot chain')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        json.dump(delivery_status(), handle, indent=2)
        handle.write('\n')
    print(HOLD + ': source checks only; no candidate archive will be assembled or uploaded')


if __name__ == '__main__':
    main()
