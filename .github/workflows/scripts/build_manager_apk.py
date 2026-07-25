#!/usr/bin/env python3
"""构建 SukiSU-Ultra 管理器 APK（从 main manager pin，不是 builtin）。

- checkout main manager pin (ci_3653 / 40838)
- 配置 ANDROID_HOME / local.properties（Maximize space 会删掉默认 Android SDK）
- Gradle assembleRelease/Debug
- 写出 manager-commit.txt；versionCode 必须匹配基准
- 本地签名通常不是官方 shirkneko 私钥；用户应继续使用官方 CI APK
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


def run(cmd, cwd=None, check=True, env=None):
    print(f"[manager] $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=cwd, check=check, env=env)


def detect_android_sdk() -> Path:
    candidates = []
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(key)
        if v:
            candidates.append(Path(v))
    candidates.extend([
        Path.home() / "android-sdk",
        Path("/usr/local/lib/android/sdk"),
        Path("/usr/lib/android-sdk"),
        Path.home() / "Android" / "Sdk",
        Path("/opt/android-sdk"),
    ])
    for c in candidates:
        if not c:
            continue
        if c.exists() and (
            (c / "platform-tools").exists()
            or (c / "cmdline-tools").exists()
            or any(c.glob("build-tools/*"))
            or any(c.glob("platforms/*"))
        ):
            return c
    for c in candidates:
        if c and c.exists():
            return c
    return Path.home() / "android-sdk"


def ensure_sdk(env: dict) -> Path:
    sdk = detect_android_sdk()
    sdk.mkdir(parents=True, exist_ok=True)
    env["ANDROID_HOME"] = str(sdk)
    env["ANDROID_SDK_ROOT"] = str(sdk)

    has_platform = any(sdk.glob("platforms/android-*"))
    has_build_tools = any(sdk.glob("build-tools/*"))
    if has_platform and has_build_tools:
        print(f"[manager] reusing Android SDK at {sdk}")
        return sdk

    print(f"[manager] preparing Android SDK at {sdk}")
    run("sudo apt-get update -qq", check=False, env=env)
    run("sudo apt-get install -y -qq wget unzip curl openjdk-21-jdk-headless", check=False, env=env)

    found = list(sdk.glob("**/sdkmanager"))
    if found:
        sdkmanager = found[0]
    else:
        tmp = Path("/tmp/cmdtools.zip")
        url = "https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip"
        run(f"wget -q -O {tmp} {url} || curl -L -o {tmp} {url}", check=True, env=env)
        run(f"rm -rf {sdk}/cmdline-tools && mkdir -p {sdk}/cmdline-tools", check=True, env=env)
        run(
            f"unzip -q -o {tmp} -d {sdk}/cmdline-tools && "
            f"if [ -d {sdk}/cmdline-tools/cmdline-tools ]; then "
            f"  mv {sdk}/cmdline-tools/cmdline-tools {sdk}/cmdline-tools/latest; "
            f"elif [ ! -d {sdk}/cmdline-tools/latest ]; then "
            f"  first=$(ls -1 {sdk}/cmdline-tools | head -1); "
            f"  mv {sdk}/cmdline-tools/$first {sdk}/cmdline-tools/latest; fi",
            check=True,
            env=env,
        )
        found = list(sdk.glob("**/sdkmanager"))
        if not found:
            raise RuntimeError("sdkmanager not found after cmdline-tools install")
        sdkmanager = found[0]

    run(f"yes | {sdkmanager} --sdk_root={sdk} --licenses >/tmp/sdk-licenses.log || true", check=False, env=env)
    run(
        f"yes | {sdkmanager} --sdk_root={sdk} "
        f"platforms;android-37 platforms;android-36 "
        f"build-tools;37.0.0 build-tools;36.0.0 platform-tools "
        f">/tmp/sdk-install.log || "
        f"yes | {sdkmanager} --sdk_root={sdk} "
        f"platforms;android-36 build-tools;36.0.0 platform-tools "
        f">/tmp/sdk-install2.log",
        check=False,
        env=env,
    )
    print(f"[manager] ANDROID_HOME={sdk}")
    return sdk


def write_manager_commit(out_dir, head, local_count, expected_version_code, want_vc, status, apks):
    (out_dir / "manager-commit.txt").write_text(
        "sukisu_mode=ci\n"
        f"sukisu_manager_ref={SUKISU_MANAGER_PIN_REF}\n"
        f"sukisu_manager_commit={head}\n"
        f"sukisu_manager_ci={SUKISU_MANAGER_CI_LABEL}\n"
        f"sukisu_kernel_builtin_ref={SUKISU_PIN_REF}\n"
        f"sukisu_kernel_builtin_commit={SUKISU_PIN_COMMIT}\n"
        f"commit_count={local_count}\n"
        f"expected_version_code={expected_version_code}\n"
        f"manager_version_code_baseline={want_vc}\n"
        f"apk_build_status={status}\n"
        "note=local_apk_signature_may_differ_from_official_ci_apk\n"
        "official_user_apk_required=true\n"
        f"apks={apks}\n"
    )


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: build_manager_apk.py <output_dir>")
        return 1
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    try:
        sdk = ensure_sdk(env)
    except Exception as e:
        print(f"[manager] SDK setup failed: {e}")
        return 6

    work = Path(os.environ.get("GKI_WORKSPACE", "/tmp/gki-build")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    src = work / "SukiSU-Manager"

    manager_commit = os.environ.get("SUKISU_MANAGER_COMMIT", SUKISU_MANAGER_PIN_COMMIT)
    want_vc = int(os.environ.get("SUKISU_MANAGER_VERSION_CODE", EXPECTED_KSU_VERSION_CODE))

    run(f"rm -rf {src}", env=env)
    run(f"git clone {KSU_REPO_CONFIG['repo_url']} {src}", env=env)
    run("git fetch --all --tags --prune", cwd=src, env=env)
    run(f"git checkout --force {manager_commit}", cwd=src, env=env)

    head = subprocess.run("git rev-parse HEAD", shell=True, cwd=src, capture_output=True, text=True, env=env).stdout.strip()
    if head != manager_commit and not manager_commit.startswith(head[:12]):
        print(f"[manager] 固定失败: HEAD {head} != {manager_commit}")
        return 2

    local_count = subprocess.run("git rev-list --count HEAD", shell=True, cwd=src, capture_output=True, text=True, env=env).stdout.strip()
    try:
        expected_version_code = SUKISU_VERSION_BASE + int(local_count) - SUKISU_VERSION_OFFSET
    except ValueError:
        print(f"[manager] 无法解析 commit count: {local_count}")
        return 2

    print(f"[manager] ref={SUKISU_MANAGER_PIN_REF} commit={head} ci={SUKISU_MANAGER_CI_LABEL} count={local_count} versionCode={expected_version_code} (want {want_vc})")
    if expected_version_code != want_vc:
        print(f"[manager] 错误: versionCode {expected_version_code} != 期望 {want_vc}")
        return 5
    if expected_version_code == 37973:
        print("[manager] 错误: 拒绝 37973")
        return 5

    manager_dir = None
    for cand in [src / "manager", src / "app", src]:
        if (cand / "gradlew").exists():
            manager_dir = cand
            break
    if manager_dir is None:
        print("[manager] 未找到 gradlew")
        write_manager_commit(out_dir, head, local_count, expected_version_code, want_vc, "no_gradlew", [])
        return 3

    (manager_dir / "local.properties").write_text(f"sdk.dir={sdk}\n")
    if manager_dir != src:
        (src / "local.properties").write_text(f"sdk.dir={sdk}\n")

    run("chmod +x gradlew", cwd=manager_dir, check=False, env=env)
    rc = run(
        "./gradlew --no-daemon assembleRelease || ./gradlew --no-daemon :app:assembleRelease || "
        "./gradlew --no-daemon assembleDebug || ./gradlew --no-daemon :app:assembleDebug",
        cwd=manager_dir, check=False, env=env,
    ).returncode

    apks = [p for p in src.rglob("*.apk") if "intermediates" not in str(p)]
    if not apks:
        print(f"[manager] 构建后未找到 APK（gradle rc={rc}）；写出元数据，用户官方 CI APK 仍为安装基准")
        write_manager_commit(out_dir, head, local_count, expected_version_code, want_vc, "failed_keep_official_apk", [])
        return 0

    copied = []
    for apk in apks:
        dest = out_dir / apk.name
        run(f"cp '{apk}' '{dest}'", env=env)
        copied.append(dest.name)
    write_manager_commit(out_dir, head, local_count, expected_version_code, want_vc, "ok", copied)
    print(f"[manager] 完成 APK={copied} commit={head} versionCode={expected_version_code}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
