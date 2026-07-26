# Root cause: driver 37973 (FAILED / DO NOT FLASH)

## Exact mechanism
1. Workflow chose SukiSU **builtin** source for SUSFS (`b1d534bc...`).
2. `add_kernelsu()` then ran `git branch -f main HEAD`, pointing local `main` at the builtin commit.
3. It set `LOCAL_COUNT := $(git rev-list --count HEAD)` → **788**.
4. Driver versionCode = 40000 + 788 - 2815 = **37973**.
5. Release notes still said "v4.1.3" from name/tag string, not from versionCode.
6. Manager APK build targeted the same builtin pin (incomplete manager tree / wrong count) and was `continue-on-error`, so AK3 still published.

## Why manager showed red mismatch
`showVersionMismatchWarning = (ksuVersion != managerVersionCode)` → 37973 != 40838.

## Fix
- Keep builtin for **source/SUSFS only**
- Force `LOCAL_COUNT := 3653` (main count at manager pin)
- Never `git branch -f main HEAD` onto builtin
- Manager builds from main `f1e24b66`
- Hard gate blocks 37973 and requires 40838 before artifacts/release

## Classification
`android14-6.1.138-2026-02-AnyKernel3.zip` and prior aurora release with driver 37973:
**FAILED / DO NOT FLASH / manager-driver mismatch**
