# fix-report.md — CI40838 version match (no full re-audit)

## Scope
Directional fix only: manager 40838 / ci_3653 ↔ driver versionCode.
Preserved: ACK 6.1.138, SUSFS v2.2.0, Inline Hook path, KPM, LZ4KD, BBR default, BBG off, OP8E off, Telegram off, aurora AK3 packaging.

## Root cause (definitive)
builtin rev-list 788 locked into LOCAL_COUNT → driver **37973**; manager APK **40838**.

## Code changes
- `config.py`: CI mode pins, EXPECTED_KSU_VERSION_CODE=40838, main count 3653
- `kb_mix1.py`: pin builtin source; force LOCAL_COUNT=3653; forbid 788/37973
- `kb_mix4.py`: Image must contain 40838; reject 37973
- `kb_mix6.py`: manifest records manager/builtin/count; hard gate before/after pack
- `build_manager_apk.py`: build from main manager commit (not builtin); fail hard
- `verify_manager_driver_gate.py` + `kernel-build.yml`: remove continue-on-error; new inputs; new release tag CI40838

## Expected new driver
versionCode **40838** with kernel source still builtin@b1d534bc (SUSFS), LOCAL_COUNT=3653.

## User manager
Keep existing official CI APK. Do not reinstall locally-built APK if signature differs.

## Phone operations
None (ADB/fastboot/flash forbidden).
