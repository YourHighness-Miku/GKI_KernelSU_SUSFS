#!/usr/bin/env python3
"""构建 SukiSU-Ultra 管理器 APK，并强制与内核驱动同源（同一 pin commit）。

用法:
    python3 build_manager_apk.py <output_dir>

行为:
- 克隆 SukiSU-Ultra 并 checkout 到 config.SUKISU_PIN_COMMIT（与内核驱动同一 commit）。
- 用 Gradle 构建 manager 的 release/debug APK。
- 把 APK 复制到 output_dir，并写出 manager-commit.txt 记录解析 SHA，供
  “manager == driver 同源” 门禁核对。
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import KSU_REPO_CONFIG, SUKISU_PIN_COMMIT, SUKISU_PIN_REF


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

    run(f"rm -rf {src}")
    run(f"git clone {KSU_REPO_CONFIG['repo_url']} {src}")
    run("git fetch --all --tags --prune", cwd=src)
    run(f"git checkout --force {SUKISU_PIN_COMMIT}", cwd=src)

    head = subprocess.run("git rev-parse HEAD", shell=True, cwd=src,
                          capture_output=True, text=True).stdout.strip()
    if head != SUKISU_PIN_COMMIT and not SUKISU_PIN_COMMIT.startswith(head[:12]):
        print(f"[manager] 固定失败: HEAD {head} != {SUKISU_PIN_COMMIT}")
        return 2

    # manager 工程目录（SukiSU-Ultra 仓库里的 Android app 模块）。
    manager_dir = None
    for cand in ["manager", "app", "."]:
        gradlew = src / cand / "gradlew"
        if gradlew.exists():
            manager_dir = src / cand
            break
    if manager_dir is None:
        # 顶层 gradlew
        if (src / "gradlew").exists():
            manager_dir = src
    if manager_dir is None:
        print("[manager] 未找到 gradlew，无法构建管理器 APK")
        return 3

    run("chmod +x gradlew", cwd=manager_dir, check=False)
    # 优先 release，失败回退 debug（无签名 key 时）。
    rc = run("./gradlew :manager:assembleRelease || ./gradlew assembleRelease || "
             "./gradlew :manager:assembleDebug || ./gradlew assembleDebug",
             cwd=manager_dir, check=False).returncode

    apks = list(src.rglob("*.apk"))
    apks = [p for p in apks if "intermediates" not in str(p)]
    if not apks:
        print(f"[manager] 构建后未找到 APK（gradle rc={rc}）")
        return 4

    copied = []
    for apk in apks:
        dest = out_dir / apk.name
        run(f"cp {apk} {dest}")
        copied.append(dest.name)

    (out_dir / "manager-commit.txt").write_text(
        f"sukisu_ref={SUKISU_PIN_REF}\nsukisu_commit={head}\napks={copied}\n"
    )
    print(f"[manager] 完成，APK: {copied}, commit={head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
