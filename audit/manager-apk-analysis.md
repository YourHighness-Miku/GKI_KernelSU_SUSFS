# manager-apk-analysis.md

## Summary
User-provided APK is a complete, valid official SukiSU Ultra **main CI test** build:

| Field | Value |
|---|---|
| File | `SukiSU_v4.1.3_40838-release.apk` |
| Size | 12348880 bytes (~11.78 MB) |
| ZIP integrity | OK |
| packageName | `com.sukisu.ultra` |
| versionName | `v4.1.3` |
| versionCode | **40838** |
| minSdk / targetSdk | 26 / 37 |
| Build type | Android `release` (filename `release` ≠ stable channel) |
| Signer | shirkneko official (SHA-256 `947ae944...`) |
| CI label | **ci_3653** = `git rev-list --count main` at tip |
| Manager commit | `f1e24b66057d774888f80ea95fab4cfebb9612fe` |
| Subject | feat: manager: Add in-app language switcher (#916) |

## Version formula (official)
```
versionCode = 40000 + rev-list --count HEAD - 2815
# main tip count = 3653 → 40000 + 3653 - 2815 = 40838
```

## Manager vs driver compatibility (official UI rule)
`HomeUiState.showVersionMismatchWarning`:
```
ksuVersion != null && ksuVersion.toLong() != currentManagerVersionCode
```
Exact equality required. Manager 40838 demands driver **40838**.

UAPI: `KERNEL_SU_UAPI_VERSION = 2` on both manager and builtin kernel.

## Must not
- Downgrade user manager to stable tag manager
- Re-sign or modify this APK
- Treat versionName `v4.1.3` as proof of tag `v4.1.3` (tag count=3611 → versionCode 40796)
