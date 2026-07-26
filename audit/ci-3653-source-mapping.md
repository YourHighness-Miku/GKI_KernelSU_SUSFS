# ci-3653-source-mapping.md

## What "ci_3653" means
It is **not** GitHub Actions `run_number` on `SukiSU-Ultra/SukiSU-Ultra` (recent main runs are ~262x).
It is the **git commit count on `main`**:

```
git rev-list --count origin/main  # = 3653 at tip f1e24b66
versionCode = 40000 + 3653 - 2815 = 40838
```

This matches the APK filename / versionCode and Telegram note for #916.

## Exact pins for this rebuild

| Role | Ref | Commit | Count → versionCode |
|---|---|---|---|
| Manager baseline (user APK) | main | `f1e24b66057d774888f80ea95fab4cfebb9612fe` | 3653 → **40838** |
| Kernel source (SUSFS) | builtin | `b1d534bc41941b2c818d7a1a1dac341e4aabfc2d` | 788 (source only) |
| Driver versionCode lock | LOCAL_COUNT | **forced 3653** | **40838** |

## Why kernel source stays on builtin
- `main` / tag `v4.1.3` **do not** ship `KSU_SUSFS` Kconfig / `susfs_init`
- `builtin` does (inline SUSFS + SUSFS Inline Hook path)
- Official Makefile always numbers driver with **main** commit count (`REPO_BRANCH := main`), not builtin ancestry

## vs formal v4.1.3 tag
- tag `v4.1.3` = `0ca744a88835144c58d8256ebb32c279edabfcde`, count 3611
- main tip is **42 commits** after tag (includes #916 language switcher and SUSFS manager UI work)

## Mapping rule used by this repo (mode B / CI)
1. Manager pin = main commit for 40838
2. Kernel source pin = builtin with SUSFS
3. LOCAL_COUNT locked to main count 3653 (never builtin rev-list)
4. Hard gate fails if driver is 37973 or not 40838
