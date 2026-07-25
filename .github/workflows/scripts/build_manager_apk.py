#!/usr/bin/env python3
"""构建 SukiSU-Ultra 管理器 APK（从 main manager pin，不是 builtin）。

用法:
    python3 build_manager_apk.py <output_dir>

行为:
- 克隆 SukiSU-Ultra 并 checkout 到 SUKISU_MANAGER_PIN_COMMIT（main/ci_3653 / 40838）。
- 用 Gradle 构建 manager 的 release/debug APK。
- 写出 manager-commit.txt；versionCode 必须为 40838。
- 注意：官方签名私钥不可用时，本地 APK 签名会与用户现网官方 CI APK 不同。
  因此用户应继续使用已提供的官方 CI APK 作为管理器基准；本脚本产物仅作对照。
- 构建失败必须非 0 退出（workflow 不得 continue-on-error）。
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import (
    KSU_REPO_CONFIG,
    SUKISU_MANAGER_PIN_COMMIT,
    SUKISU_MANAGER_PIN_REF,
    SUKISU_MANAGER_CI_LABEL,
    SUKISU_MAIN_COMMIT_COUNT,
    EXPECTED_KSU_VERSION_CODE,
    SUKISU_VERSION_BASE,
    SUKISU_VERSION_OFFSET,
    SUKISU_PIN_COMMIT,
    SUKISU_PIN_REF,
)


def run(cmd, cwd=None, check=True):
    print(f"[manager] $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=cwd, check=check)


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: build_manager_apk.py <output_dir>")
        return 1
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    work = Path(os.environ.get("GKI_WORKSPACE", "/tmp/gki-build")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    src = work / "SukiSU-Manager"

    manager_commit = os.environ.get("SUKISU_MANAGER_COMMIT", SUKISU_MANAGER_PIN_COMMIT)
    want_vc = int(os.environ.get("SUKISU_MANAGER_VERSION_CODE", EXPECTED_KSU_VERSION_CODE))

    run(f"rm -rf {src}")
    run(f"git clone {KSU_REPO_CONFIG['repo_url']} {src}")
    run("git fetch --all --tags --prune", cwd=src)
    # 管理器必须从 main 对应 commit 构建，禁止 checkout builtin（无完整 manager 工程）。
    run(f"git checkout --force {manager_commit}", cwd=src)

    head = subprocess.run(
        "git rev-parse HEAD", shell=True, cwd=src, capture_output=True, text=True
    ).stdout.strip()
    if head != manager_commit and not manager_commit.startswith(head[:12]):
        print(f"[manager] 固定失败: HEAD {head} != {manager_commit}")
        return 2

    local_count = subprocess.run(
        "git rev-list --count HEAD", shell=True, cwd=src, capture_output=True, text=True
    ).stdout.strip()
    try:
        expected_version_code = SUKISU_VERSION_BASE + int(local_count) - SUKISU_VERSION_OFFSET
    except ValueError:
        print(f"[manager] 无法解析 commit count: {local_count}")
        return 2

    print(
        f"[manager] ref={SUKISU_MANAGER_PIN_REF} commit={head} "
        f"ci={SUKISU_MANAGER_CI_LABEL} count={local_count} "
        f"versionCode={expected_version_code} (want {want_vc})"
    )
    if int(local_count) != SUKISU_MAIN_COMMIT_COUNT and want_vc == EXPECTED_KSU_VERSION_CODE:
        print(
            f"[manager] 警告: local_count={local_count} != pinned main count "
            f"{SUKISU_MAIN_COMMIT_COUNT}"
        )
    if expected_version_code != want_vc:
        print(
            f"[manager] 错误: 计算出的 versionCode {expected_version_code} != 期望 {want_vc}"
        )
        return 5
    if expected_version_code == 37973:
        print("[manager] 错误: 拒绝 37973（builtin 误用路径）")
        return 5

    manager_dir = None
    for cand in ["manager", "app", "."]:
        gradlew = src / cand / "gradlew"
        if gradlew.exists():
            manager_dir = src / cand
            break
    if manager_dir is None and (src / "gradlew").exists():
        manager_dir = src
    if manager_dir is None:
        print("[manager] 未找到 gradlew，无法构建管理器 APK（禁止 continue-on-error）")
        return 3

    run("chmod +x gradlew", cwd=manager_dir, check=False)
    rc = run(
        "./gradlew :manager:assembleRelease || ./gradlew assembleRelease || "
        "./gradlew :manager:assembleDebug || ./gradlew assembleDebug",
        cwd=manager_dir,
        check=False,
    ).returncode

    apks = [p for p in src.rglob("*.apk") if "intermediates" not in str(p)]
    if not apks:
        print(f"[manager] 构建后未找到 APK（gradle rc={rc}）——工作流必须失败")
        return 4

    copied = []
    for apk in apks:
        dest = out_dir / apk.name
        run(f"cp {apk} {dest}")
        copied.append(dest.name)

    (out_dir / "manager-commit.txt").write_text(
        f"sukisu_mode=ci\n"
        f"sukisu_manager_ref={SUKISU_MANAGER_PIN_REF}\n"
        f"sukisu_manager_commit={head}\n"
        f"sukisu_manager_ci={SUKISU_MANAGER_CI_LABEL}\n"
        f"sukisu_kernel_builtin_ref={SUKISU_PIN_REF}\n"
        f"sukisu_kernel_builtin_commit={SUKISU_PIN_COMMIT}\n"
        f"commit_count={local_count}\n"
        f"expected_version_code={expected_version_code}\n"
        f"manager_version_code_baseline={want_vc}\n"
        f"note=local_apk_signature_may_differ_from_official_ci_apk\n"
        f"official_user_apk_required=true\n"
        f"apks={copied}\n"
    )
    print(
        f"[manager] 完成 APK={copied} commit={head} versionCode={expected_version_code} "
        f"(官方用户 APK 签名可能不同，勿覆盖安装用户现网 APK)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
