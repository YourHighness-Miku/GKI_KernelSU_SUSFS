from dataclasses import dataclass
from typing import Optional
from enum import Enum
import re
import urllib.request
import ssl


def get_susfs_version(branch: Optional[str] = None) -> str:
    """从 susfs 仓库获取版本号。

    - 使用正常的 TLS 证书校验（不再关闭 check_hostname / 不再用 CERT_NONE）。
    - 网络失败时抛出异常，绝不返回硬编码的假版本号。
    真正用于门禁的版本号来自 KernelBuilder._verify_susfs_source_version()，
    它读取实际 checkout 出来的 susfs.h；这里只用于展示/矩阵摘要。
    """
    # 使用系统默认 CA，进行完整证书校验。
    ssl_ctx = ssl.create_default_context()

    # 尝试多个分支获取版本号
    if branch:
        branches = [branch]
    else:
        branches = ["gki-android15-6.6", "gki-android14-6.1", "gki-android13-5.15", "gki-android12-5.10", "main"]
    version_pattern = re.compile(r'#define\s+SUSFS_VERSION\s+"([^"]+)"')

    last_error: Optional[Exception] = None
    for b in branches:
        try:
            url = f"https://raw.githubusercontent.com/ShirkNeko/susfs4ksu/{b}/kernel_patches/include/linux/susfs.h"
            with urllib.request.urlopen(url, timeout=10, context=ssl_ctx) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
            m = version_pattern.search(content)
            if m:
                return m.group(1)
        except Exception as e:  # noqa: BLE001
            last_error = e
            continue

    raise RuntimeError(
        "无法从 susfs4ksu 获取 SUSFS_VERSION（已尝试分支: "
        f"{', '.join(branches)}）。最后错误: {last_error}. "
        "拒绝返回硬编码版本号；请检查网络或分支名。"
    )


def get_susfs_version_safe(branch: Optional[str] = None, default: str = "unknown") -> str:
    """展示用的安全封装：失败时返回占位符而不是崩溃，且绝不谎报具体版本。"""
    try:
        return get_susfs_version(branch)
    except Exception as e:  # noqa: BLE001
        print(f"[WARN] 获取 SUSFS 版本失败，使用占位符 '{default}': {e}")
        return default


# 内核版本号 - 从 susfs 仓库自动获取（展示用；真正门禁在构建时读实际源码）
KERNEL_VERSION = get_susfs_version_safe()
print(f"SUSFS Version (display): {KERNEL_VERSION}")

# 期望的 SUSFS 版本（构建门禁用，读实际 checkout 出的 susfs.h 校验）
EXPECTED_SUSFS_VERSION = "v2.2.0"


class AndroidVersion(Enum):
    ANDROID12 = "android12"
    ANDROID13 = "android13"
    ANDROID14 = "android14"
    ANDROID15 = "android15"


class KernelVersion(Enum):
    KERNEL_5_10 = "5.10"
    KERNEL_5_15 = "5.15"
    KERNEL_6_1 = "6.1"
    KERNEL_6_6 = "6.6"


class KSUVersion(Enum):
    STABLE = "Stable(标准)"
    DEV = "Dev(开发)"


ANDROID_KERNEL_MAP = {
    AndroidVersion.ANDROID12: [KernelVersion.KERNEL_5_10],
    AndroidVersion.ANDROID13: [KernelVersion.KERNEL_5_10, KernelVersion.KERNEL_5_15],
    AndroidVersion.ANDROID14: [KernelVersion.KERNEL_5_15, KernelVersion.KERNEL_6_1],
    AndroidVersion.ANDROID15: [KernelVersion.KERNEL_6_6],
}

# 仓库配置
# ---------------------------------------------------------------------------
# SukiSU 版本映射（2026-07-25 更新：管理器升级到 40856）
#
# 管理器 APK（用户现网基准，不可降级）:
#   SukiSU v4.1.3，versionCode=40856（截图确认：管理器 40856 vs 旧驱动 40838 不匹配）
#   package=com.sukisu.ultra, versionName=v4.1.3
#   官方 main 分支 tip：35467545b2826e3acfc88699755981a889956b1a
#   rev-list --count main = 3671  →  versionCode = 40000 + 3671 - 2815 = 40856
#
# 内核驱动 versionCode 官方公式（kernel/Makefile / manager/build.gradle.kts）:
#   KSU_VERSION / versionCode = VERSION_BASE(40000) + rev-list --count main - VERSION_OFFSET(2815)
#   REPO_BRANCH 固定为 main：driver 永远按 main 提交数编号，与 builtin HEAD 提交数无关。
#
# 内核源码（SUSFS 集成）:
#   builtin 分支才带 KSU_SUSFS Kconfig + susfs_init；main/v4.1.3 tag 不含 KSU_SUSFS。
#   因此内核源码 pin 到 builtin@b1d534bc...（含 SUSFS），但 LOCAL_COUNT 必须用 main 的 3671，
#   绝不能用 builtin 本地 rev-list --count HEAD(=788 → 错误的 37973)。
#
# 历史：管理器 40838(count=3653) → 现升级到 40856(count=3671)，仅版本号提升，源码结构不变。
# ---------------------------------------------------------------------------

# 内核源码 pin：builtin + SUSFS
SUKISU_PIN_REF = "builtin"
SUKISU_PIN_COMMIT = "b1d534bc41941b2c818d7a1a1dac341e4aabfc2d"

# 管理器 pin：main CI/测试版 40856
SUKISU_MANAGER_PIN_REF = "main"
SUKISU_MANAGER_PIN_COMMIT = "35467545b2826e3acfc88699755981a889956b1a"
SUKISU_MANAGER_CI_LABEL = "ci_3671"  # = main rev-list count at manager pin
SUKISU_VERSION_BASE = 40000
SUKISU_VERSION_OFFSET = 2815
# 官方 main 在 manager pin 上的提交数（硬门禁；禁止再按 builtin HEAD 重算）
SUKISU_MAIN_COMMIT_COUNT = 3671
EXPECTED_KSU_VERSION_CODE = SUKISU_VERSION_BASE + SUKISU_MAIN_COMMIT_COUNT - SUKISU_VERSION_OFFSET  # 40856
assert EXPECTED_KSU_VERSION_CODE == 40856

# 模式：stable = 稳定 tag 同源；ci = 管理器 main CI + builtin 内核源码 + main 计数
SUKISU_MODE_STABLE = "stable"
SUKISU_MODE_CI = "ci"
DEFAULT_SUKISU_MODE = SUKISU_MODE_CI

KSU_REPO_CONFIG = {
    "repo_url": "https://github.com/SukiSU-Ultra/SukiSU-Ultra.git",
    "branch": "main",
    "pin_ref": SUKISU_PIN_REF,
    "pin_commit": SUKISU_PIN_COMMIT,
    "manager_pin_ref": SUKISU_MANAGER_PIN_REF,
    "manager_pin_commit": SUKISU_MANAGER_PIN_COMMIT,
    "main_commit_count": SUKISU_MAIN_COMMIT_COUNT,
    "expected_version_code": EXPECTED_KSU_VERSION_CODE,
    "setup_script": f"https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/{SUKISU_PIN_COMMIT}/kernel/setup.sh",
}

# ACK（Android Common Kernel）精确来源固定表。
# key = "{android_version}-{kernel_version}.{sub_level}"
# 每项给出：真实存在的 manifest 分支 + 精确 tag + 该 tag 对应 commit（用于校验，非编造）。
# 6.1.138 已联网核验：manifest common-android14-6.1 存在；tag android14-6.1.138_r00 的
# Makefile SUBLEVEL == 138，commit = 4894546596ee3a4b96d9f2157de0d197826cabc0。
ACK_SOURCE_PINS = {
    "android14-6.1.138": {
        "manifest_branch": "common-android14-6.1",
        "ack_tag": "android14-6.1.138_r00",
        "ack_commit": "4894546596ee3a4b96d9f2157de0d197826cabc0",
        "expected_sublevel": 138,
    },
}

# SUSFS 仓库配置
# 默认固定到 android14-6.1 分支上 v2.2.0 的真实 commit，避免默认使用浮动分支 HEAD。
# 090cf40 已联网核验：susfs.h SUSFS_VERSION == "v2.2.0"，且含
# 50_add_susfs_in_gki-android14-6.1.patch。工作流填写的 susfs_commit 可覆盖此默认。
SUSFS_PIN_COMMIT_BY_BRANCH = {
    "gki-android14-6.1": "090cf407fea14d960cba55ce6f69cc61a146d1b3",
}
SUSFS_REPO_CONFIG = {"repo_url": "https://github.com/ShirkNeko/susfs4ksu.git"}

# SukiSU Patch 仓库配置
SUKISU_PATCH_REPO_CONFIG = {"repo_url": "https://github.com/ShirkNeko/SukiSU_patch.git"}

# AnyKernel3 仓库配置
ANYKERNEL_CONFIG = {"repo_url": "https://github.com/WildPlusKernel/AnyKernel3.git", "branch": "gki-2.0"}

# Kernel Patches 仓库配置
KERNEL_PATCHES_CONFIG = {"repo_url": "https://github.com/Tools-cx-app/kernel_patches.git"}

# Baseband-guard 配置
BBG_CONFIG = {"repo_url": "https://github.com/vc-teahouse/Baseband-guard.git",
              "pin_commit": "1c664957da7539de860503940ee73c7447f1dfaf",
              "setup_script": "https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh"}

# 工具链配置
TOOLCHAIN_CONFIG = {"aosp_mirror": "https://android.googlesource.com",
                    "build_tools_branch": "main-kernel-build-2024",
                    "mkbootimg_branch": "main-kernel-build-2024"}
LEGACY_FIXES = {
    "android13-5.15-below-123": {"url": "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/legacy/fix_5.15.legacy", "min_sub_level": 123},
    "android12-5.10-below-136": {"url": "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/legacy/fdinfo.c.patch", "min_sub_level": 136},
}
OP8E_PATCH_URL = "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/dev/hmbird_patch.c"
KPM_PATCH_URL = "https://raw.githubusercontent.com/ShirkNeko/SukiSU_patch/refs/heads/main/kpm/patch_linux"


@dataclass
class BuildConfig:
    android_version: str
    kernel_version: str
    sub_level: str
    os_patch_level: str
    kernelsu_version: str = "Stable(标准)"
    kernelsu_commit: Optional[str] = None
    susfs_commit: Optional[str] = None
    use_zram: bool = False
    use_kpm: bool = True
    use_bbg: bool = False
    support_op8e: bool = False
    set_default_bbr: bool = False
    make_release: bool = True
    custom_version: Optional[str] = None
    revision: Optional[str] = None
    build_id: Optional[str] = None
    # SukiSU 模式与显式 pin（CI/main 管理器匹配）
    sukisu_mode: str = DEFAULT_SUKISU_MODE
    manager_commit: Optional[str] = None
    manager_version_code: Optional[int] = None
    manager_ci_run: Optional[str] = None
    kernel_builtin_commit: Optional[str] = None

    def __post_init__(self):
        self._validate_android_version()
        self._validate_kernel_version()
        self._validate_kernel_android_compat()
        self._validate_sub_level()
        self._set_build_id()
        if self.sukisu_mode not in (SUKISU_MODE_STABLE, SUKISU_MODE_CI):
            raise ValueError(f"无效的 sukisu_mode: {self.sukisu_mode}")
        if self.manager_version_code is None:
            self.manager_version_code = EXPECTED_KSU_VERSION_CODE
        if not self.manager_commit:
            self.manager_commit = SUKISU_MANAGER_PIN_COMMIT
        if not self.kernel_builtin_commit:
            self.kernel_builtin_commit = SUKISU_PIN_COMMIT
        if not self.manager_ci_run:
            self.manager_ci_run = SUKISU_MANAGER_CI_LABEL

    def _validate_android_version(self):
        valid = [v.value for v in AndroidVersion]
        if self.android_version not in valid:
            raise ValueError(f"无效的 Android 版本: {self.android_version}. 支持: {', '.join(valid)}")

    def _validate_kernel_version(self):
        valid = [v.value for v in KernelVersion]
        if self.kernel_version not in valid:
            raise ValueError(f"无效的 Kernel 版本: {self.kernel_version}. 支持: {', '.join(valid)}")

    def _validate_kernel_android_compat(self):
        av = AndroidVersion(self.android_version)
        kv = KernelVersion(self.kernel_version)
        if kv not in ANDROID_KERNEL_MAP.get(av, []):
            raise ValueError(f"Android {self.android_version} 不支持 Kernel {self.kernel_version}")

    def _validate_sub_level(self):
        if self.sub_level != "X" and not self.sub_level.isdigit():
            raise ValueError(f"无效的 sub_level: {self.sub_level}")

    def _set_build_id(self):
        if self.build_id is None:
            self.build_id = f"{self.android_version}-{self.kernel_version}-{self.sub_level}-{self.os_patch_level}"

    @property
    def config_name(self) -> str:
        return f"{self.android_version}-{self.kernel_version}-{self.sub_level}"

    @property
    def formatted_branch(self) -> str:
        return f"{self.android_version}-{self.kernel_version}-{self.os_patch_level}"

    @property
    def kernel_branch(self) -> str:
        return f"gki-{self.android_version}-{self.kernel_version}"

    def get_susfs_patch_filename(self) -> str:
        return f"50_add_susfs_in_gki-{self.android_version}-{self.kernel_version}.patch"

    def is_lts(self) -> bool:
        return self.sub_level == "X"

    def get_sub_level_int(self) -> Optional[int]:
        return None if self.sub_level == "X" else int(self.sub_level)

    def ack_pin(self) -> Optional[dict]:
        """返回本配置对应的 ACK 精确来源固定项（若表中存在）。"""
        key = f"{self.android_version}-{self.kernel_version}.{self.sub_level}"
        return ACK_SOURCE_PINS.get(key)

    def effective_susfs_commit(self) -> Optional[str]:
        """SUSFS 要 checkout 的 commit：工作流显式 susfs_commit 优先，否则用分支默认固定值。

        这样即使不填 susfs_commit，也不会用浮动分支 HEAD，而是固定到已核验的 v2.2.0 commit。
        """
        if self.susfs_commit:
            return self.susfs_commit
        return SUSFS_PIN_COMMIT_BY_BRANCH.get(self.kernel_branch)

    def effective_kernel_builtin_commit(self) -> str:
        return self.kernel_builtin_commit or SUKISU_PIN_COMMIT

    def effective_manager_commit(self) -> str:
        return self.manager_commit or SUKISU_MANAGER_PIN_COMMIT

    def effective_manager_version_code(self) -> int:
        return int(self.manager_version_code or EXPECTED_KSU_VERSION_CODE)

    def to_dict(self) -> dict:
        pin = self.ack_pin()
        return {
            "android_version": self.android_version,
            "kernel_version": self.kernel_version,
            "sub_level": self.sub_level,
            "os_patch_level": self.os_patch_level,
            "kernelsu_version": self.kernelsu_version,
            "kernelsu_commit": self.kernelsu_commit,
            "sukisu_mode": self.sukisu_mode,
            "sukisu_pin_ref": SUKISU_PIN_REF,
            "sukisu_pin_commit": self.effective_kernel_builtin_commit(),
            "sukisu_manager_pin_ref": SUKISU_MANAGER_PIN_REF,
            "sukisu_manager_pin_commit": self.effective_manager_commit(),
            "sukisu_manager_ci": self.manager_ci_run or SUKISU_MANAGER_CI_LABEL,
            "sukisu_main_commit_count": SUKISU_MAIN_COMMIT_COUNT,
            "expected_ksu_version_code": self.effective_manager_version_code(),
            "susfs_commit": self.susfs_commit,
            "susfs_effective_commit": self.effective_susfs_commit(),
            "susfs_branch": self.kernel_branch,
            "ack_manifest_branch": pin["manifest_branch"] if pin else None,
            "ack_tag": pin["ack_tag"] if pin else None,
            "ack_commit": pin["ack_commit"] if pin else None,
            "use_zram": self.use_zram,
            "use_kpm": self.use_kpm,
            "use_bbg": self.use_bbg,
            "support_op8e": self.support_op8e,
            "set_default_bbr": self.set_default_bbr,
            "make_release": self.make_release,
            "custom_version": self.custom_version,
            "revision": self.revision,
            "build_id": self.build_id,
        }


def validate_commit_hash(commit_hash: str) -> bool:
    return bool(re.match(r'^[0-9a-f]{7,40}$', commit_hash, re.IGNORECASE))
