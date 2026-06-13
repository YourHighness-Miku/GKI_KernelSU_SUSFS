import os
import subprocess
import logging
import re
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field

from config import (BuildConfig, KSU_REPO_CONFIG, SUSFS_REPO_CONFIG, SUKISU_PATCH_REPO_CONFIG,
                   ANYKERNEL_CONFIG, KERNEL_PATCHES_CONFIG, BBG_CONFIG, TOOLCHAIN_CONFIG,
                   LEGACY_FIXES, OP8E_PATCH_URL, KPM_PATCH_URL)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class BuildResult:
    success: bool
    config: BuildConfig
    message: str = ""
    artifacts: list = field(default_factory=list)
    build_time: Optional[float] = None


class ShellCommand:
    def __init__(self, cwd: Optional[str] = None, env: Optional[dict] = None):
        self.cwd = cwd
        self.env = env or os.environ.copy()

    def run(self, cmd: str, check: bool = True, capture_output: bool = False,
            shell: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        logger.info(f"执行命令: {cmd}")
        try:
            return subprocess.run(cmd, shell=shell, cwd=self.cwd, env=self.env,
                                capture_output=capture_output, text=True, timeout=timeout, check=check)
        except subprocess.CalledProcessError as e:
            logger.error(f"命令执行失败: {e.stderr or str(e)}")
            raise
        except subprocess.TimeoutExpired:
            logger.error(f"命令执行超时: {cmd}")
            raise

    def run_with_callback(self, cmd: str, callback: Optional[Callable] = None) -> str:
        logger.info(f"执行命令: {cmd}")
        process = subprocess.Popen(cmd, shell=True, cwd=self.cwd, env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        output_lines = []
        for line in process.stdout:
            line = line.rstrip()
            output_lines.append(line)
            if callback:
                callback(line)
        process.wait()
        if process.returncode != 0:
            raise RuntimeError(f"命令执行失败")
        return "\n".join(output_lines)


class KernelBuilder:
    KERNEL_CONFIG_TEMPLATE = """
# === KernelSU Config ===
CONFIG_KSU=y
CONFIG_KPM=y
CONFIG_KSU_SUSFS_SUS_SU=n

# === TMPFS Config ===
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_POSIX_ACL=y

# === Network Config ===
CONFIG_IP_NF_TARGET_TTL=y
CONFIG_IP6_NF_TARGET_HL=y
CONFIG_IP6_NF_MATCH_HL=y

# === BBR Config ===
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BBR=y
CONFIG_NET_SCH_FQ=y
CONFIG_TCP_CONG_BIC=n
CONFIG_TCP_CONG_WESTWOOD=n
CONFIG_TCP_CONG_HTCP=n

# === SUSFS Config ===
CONFIG_KSU_SUSFS=y
CONFIG_KSU_SUSFS_SUS_MAP=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_TRY_UMOUNT=y
CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
"""

    ZRAM_CONFIG_5_10 = "CONFIG_ZSMALLOC=y\nCONFIG_ZRAM=y\nCONFIG_MODULE_SIG=n\nCONFIG_CRYPTO_LZO=y\nCONFIG_ZRAM_DEF_COMP_LZ4KD=y\n"
    ZRAM_CONFIG_COMMON = "CONFIG_CRYPTO_LZ4HC=y\nCONFIG_CRYPTO_LZ4K=y\nCONFIG_CRYPTO_LZ4KD=y\nCONFIG_CRYPTO_842=y\nCONFIG_CRYPTO_LZ4K_OPLUS=y\nCONFIG_ZRAM_WRITEBACK=y\n"

    def __init__(self, config: BuildConfig, workspace: str):
        self.config = config
        self.workspace = Path(workspace)
        self.shell = ShellCommand(cwd=workspace)
        self.env = os.environ.copy()
        self.work_dir = self.workspace / config.config_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.susfs_dir = self.workspace / "susfs4ksu"
        self.sukisu_patch_dir = self.workspace / "SukiSU_patch"
        self.anykernel_dir = self.workspace / "AnyKernel3"
        self.kernel_patches_dir = self.workspace / "kernel_patches"
        self.toolchain_dir = self.workspace / "toolchain"
        self.mkbootimg_dir = self.workspace / "mkbootimg"
        self._setup_env()

    def _setup_env(self):
        self.env["CONFIG"] = self.config.config_name
        self.env["CCACHE_COMPILERCHECK"] = "%compiler% -dumpmachine; %compiler% -dumpversion"
        self.env["CCACHE_NOHASHDIR"] = "true"
        self.env["CCACHE_HARDLINK"] = "true"
        self.shell.env = self.env

    def _run_cmd(self, cmd: str, **kwargs) -> subprocess.CompletedProcess:
        return self.shell.run(cmd, **kwargs)

    def _chdir(self, path: Path):
        os.chdir(path)
        self.shell.cwd = str(path)

    def _apply_susfs_commit(self):
        if not self.config.susfs_commit or not self.susfs_dir.exists():
            return

        logger.info(f"=== 切换 SUSFS commit/tag: {self.config.susfs_commit} ===")
        self._chdir(self.susfs_dir)

        self._run_cmd("git fetch --all --tags --prune", check=True)

        if self.config.susfs_commit.startswith("HEAD~"):
            self._run_cmd(f"git reset --hard {self.config.susfs_commit}", check=True)
        else:
            self._run_cmd(f"git checkout --force {self.config.susfs_commit}", check=True)

        self._run_cmd("git rev-parse --short HEAD", check=True)
        self._chdir(self.workspace)

    def clone_repositories(self):
        logger.info("=== 开始克隆/更新仓库 ===")

        repos = [
            ("SUSFS", self.susfs_dir, SUSFS_REPO_CONFIG['repo_url'], self.config.kernel_branch),
            ("SukiSU Patch", self.sukisu_patch_dir, SUKISU_PATCH_REPO_CONFIG['repo_url'], None),
            ("AnyKernel3", self.anykernel_dir, ANYKERNEL_CONFIG['repo_url'], ANYKERNEL_CONFIG['branch']),
            ("Kernel Patches", self.kernel_patches_dir, KERNEL_PATCHES_CONFIG['repo_url'], None),
        ]

        for name, repo_dir, url, branch in repos:
            if not repo_dir.exists():
                cmd = f"git clone {url} {repo_dir}"
                if branch:
                    cmd += f" -b {branch}"
                logger.info(f"克隆 {name}: {url} {branch or ''}")
                self._run_cmd(cmd, check=True)
            else:
                logger.info(f"{name} 已存在，强制更新到目标分支/最新提交")
                self._chdir(repo_dir)
                self._run_cmd("git fetch --all --tags --prune", check=True)

                if branch:
                    self._run_cmd(f"git checkout --force {branch}", check=True)
                    self._run_cmd(f"git reset --hard origin/{branch}", check=True)
                else:
                    self._run_cmd("git reset --hard HEAD", check=True)

                self._chdir(self.workspace)

        self._apply_susfs_commit()
        self._verify_susfs_source_version()
        logger.info("=== 仓库克隆/更新完成 ===")

    def _verify_susfs_source_version(self):
        logger.info("=== 检查 SUSFS 源码版本 ===")

        susfs_header = self.susfs_dir / "kernel_patches/include/linux/susfs.h"
        if not susfs_header.exists():
            raise RuntimeError(f"SUSFS 版本头文件不存在: {susfs_header}")

        with open(susfs_header, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        match = re.search(r'#define\s+SUSFS_VERSION\s+"([^"]+)"', content)
        if not match:
            raise RuntimeError("无法从 susfs.h 读取 SUSFS_VERSION")

        version = match.group(1)
        logger.info(f"SUSFS source version: {version}")

        if version != "v2.1.0":
            raise RuntimeError(
                f"SUSFS 源码版本错误：当前是 {version}，目标必须是 v2.1.0。"
                f"请检查 susfs4ksu 的 {self.config.kernel_branch} 分支，或在工作流 SUSFS commit hash 中填写真正的 v2.1.0 commit/tag。"
            )

    def clone_toolchain(self):
        logger.info("=== 克隆工具链 ===")
        if not self.toolchain_dir.exists():
            self._run_cmd(f"git clone {TOOLCHAIN_CONFIG['aosp_mirror']}/kernel/prebuilts/build-tools "
                         f"-b {TOOLCHAIN_CONFIG['build_tools_branch']} --depth 1 {self.toolchain_dir}", check=False)
        if not self.mkbootimg_dir.exists():
            self._run_cmd(f"git clone {TOOLCHAIN_CONFIG['aosp_mirror']}/platform/system/tools/mkbootimg "
                         f"-b {TOOLCHAIN_CONFIG['mkbootimg_branch']} --depth 1 {self.mkbootimg_dir}", check=False)
        self.env["AVBTOOL"] = str(self.toolchain_dir / "linux-x86/bin/avbtool")
        self.env["MKBOOTIMG"] = str(self.mkbootimg_dir / "mkbootimg.py")
        self.env["UNPACK_BOOTIMG"] = str(self.mkbootimg_dir / "unpack_bootimg.py")
        if "BOOT_SIGN_KEY_PATH" in os.environ:
            self.env["BOOT_SIGN_KEY_PATH"] = os.environ["BOOT_SIGN_KEY_PATH"]
        self.shell.env = self.env
        logger.info("=== 工具链准备完成 ===")

    def setup_repo_tool(self):
        logger.info("=== 安装 repo 工具 ===")
        repo_dir = self.workspace / "git-repo"
        repo_dir.mkdir(exist_ok=True)
        repo_path = repo_dir / "repo"
        if not repo_path.exists():
            self._run_cmd(f"curl https://storage.googleapis.com/git-repo-downloads/repo > {repo_path}", check=False)
            self._run_cmd(f"chmod a+rx {repo_path}", check=False)
        self.env["REPO"] = str(repo_path)
        self.shell.env = self.env

    def init_and_sync_kernel(self):
        logger.info("=== 初始化和同步内核源代码 ===")
        self._chdir(self.work_dir)
        formatted_branch = self.config.formatted_branch

        self._run_cmd(f"$REPO init --depth=1 --u https://android.googlesource.com/kernel/manifest "
                     f"-b common-{formatted_branch} --repo-rev=v2.16", check=False)

        remote = subprocess.run(f"git ls-remote https://android.googlesource.com/kernel/common {formatted_branch}",
                               shell=True, capture_output=True, text=True).stdout.strip()
        if "deprecated" in remote:
            manifest_path = self.work_dir / ".repo/manifests/default.xml"
            with open(manifest_path, "r") as f:
                content = f.read()
            content = content.replace(f'"{formatted_branch}"', f'"deprecated/{formatted_branch}"')
            with open(manifest_path, "w") as f:
                f.write(content)

        self.env["REMOTE_BRANCH"] = remote
        logger.info("同步内核源代码...")
        self._run_cmd("$REPO --trace sync -c -j$(nproc --all) --no-tags --fail-fast", check=False)

        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            raise RuntimeError("repo sync 失败，common 目录不存在")
        self._apply_legacy_fixes(remote)
        logger.info("=== 内核源代码同步完成 ===")

    def _apply_legacy_fixes(self, remote_branch: str = ""):
        av, kv = self.config.android_version, self.config.kernel_version
        sub = self.config.get_sub_level_int()
        is_deprecated = "deprecated" in remote_branch

        if is_deprecated and av == "android13" and kv == "5.15" and sub and sub < 123:
            common_dir = self.work_dir / "common"
            self._chdir(common_dir)
            self._run_cmd(f"curl -LSs {LEGACY_FIXES['android13-5.15-below-123']['url']} -o fix.patch && patch -p1 < fix.patch", check=False)
            self._chdir(self.work_dir)

        if av == "android12" and kv == "5.10" and sub and sub < 136:
            common_dir = self.work_dir / "common"
            self._chdir(common_dir)
            self._run_cmd(f"curl -LSs {LEGACY_FIXES['android12-5.10-below-136']['url']} | patch -p1", check=False)
            self._chdir(self.work_dir)

    def add_kernel_supatch(self):
        if not self.config.support_op8e:
            return
        logger.info("=== 添加 OnePlus 8E 支持补丁 ===")
        drivers_dir = self.work_dir / "common/drivers"
        if not drivers_dir.exists():
            return
        self._chdir(drivers_dir)
        self._run_cmd(f"curl -LSs {OP8E_PATCH_URL} -o hmbird_patch.c", check=False)
        if (drivers_dir / "hmbird_patch.c").exists():
            with open(drivers_dir / "Makefile", "a") as f:
                f.write("obj-y += hmbird_patch.o\n")

    def add_kernelsu(self):
        logger.info("=== 添加 KernelSU ===")
        self._chdir(self.work_dir)
        setup_url = (f"https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/{self.config.kernelsu_commit}/kernel/setup.sh"
                    if self.config.kernelsu_commit else KSU_REPO_CONFIG["setup_script"])
        self._run_cmd(f"curl -LSs {setup_url} | bash -s builtin", check=False)
        if self.config.kernelsu_commit:
            ksu_dir = self.work_dir / "KernelSU"
            if ksu_dir.exists():
                self._chdir(ksu_dir)
                self._run_cmd(f"git checkout {self.config.kernelsu_commit}", check=False)
                self._chdir(self.work_dir)

    def add_bbg(self):
        if not self.config.use_bbg:
            return
        logger.info("=== 添加 Baseband-guard ===")
        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            return
        self._chdir(common_dir)
        self._run_cmd(f"wget -O- {BBG_CONFIG['setup_script']} | bash", check=False)
        config_file = common_dir / "arch/arm64/configs/gki_defconfig"
        if config_file.exists():
            with open(config_file, "a") as f:
                f.write("CONFIG_BBG=y\n")
        kconfig_file = common_dir / "security/Kconfig"
        if kconfig_file.exists():
            with open(kconfig_file, "r") as f:
                content = f.read()
            content = re.sub(r'(config LSM.*?)(default .*)(\n.*?help)',
                           lambda m: m.group(1) + ('lockdown,baseband_guard' if 'lockdown' in m.group(2) and 'baseband_guard' not in m.group(2) else m.group(2)) + m.group(3),
                           content, flags=re.DOTALL)
            with open(kconfig_file, "w") as f:
                f.write(content)

    def apply_susfs_patches(self):
        logger.info("=== 应用 SUSFS 补丁 - strict v2.1.0 + KernelSU integration ===")

        self._verify_susfs_source_version()

        self._chdir(self.work_dir)
        common_dir = self.work_dir / "common"
        ksu_dir = self.work_dir / "KernelSU"

        if not common_dir.exists():
            raise RuntimeError(f"common 目录不存在: {common_dir}")

        if not ksu_dir.exists():
            raise RuntimeError(f"KernelSU 目录不存在: {ksu_dir}")

        susfs_patch = self.susfs_dir / "kernel_patches" / self.config.get_susfs_patch_filename()
        if not susfs_patch.exists():
            raise RuntimeError(f"SUSFS 主补丁不存在: {susfs_patch}")

        # 1. 复制 SUSFS 核心源码到 common。
        copy_jobs = [
            (self.susfs_dir / "kernel_patches/fs", common_dir / "fs"),
            (self.susfs_dir / "kernel_patches/include/linux", common_dir / "include/linux"),
        ]

        for src, dst in copy_jobs:
            if not src.exists():
                raise RuntimeError(f"SUSFS 源码目录不存在: {src}")
            self._run_cmd(f"mkdir -p {dst} && cp -r {src}/* {dst}/", check=True)

        # 2. 应用 GKI/common 侧 SUSFS 主补丁。
        patch_file = common_dir / self.config.get_susfs_patch_filename()
        self._run_cmd(f"cp {susfs_patch} {patch_file}", check=True)

        self._chdir(common_dir)
        self._run_cmd(f"patch -p1 --fuzz=3 < {patch_file}", check=True)

        reject_files = list(common_dir.rglob("*.rej"))
        if reject_files:
            reject_list = "\n".join(str(p) for p in reject_files[:50])
            raise RuntimeError(f"SUSFS GKI 主补丁存在失败片段 .rej，禁止继续构建:\n{reject_list}")

        patched_header = common_dir / "include/linux/susfs.h"
        if not patched_header.exists():
            raise RuntimeError(f"补丁后 common/include/linux/susfs.h 不存在: {patched_header}")

        with open(patched_header, "r", encoding="utf-8", errors="ignore") as f:
            patched_content = f.read()

        match = re.search(r'#define\s+SUSFS_VERSION\s+"([^"]+)"', patched_content)
        if not match:
            raise RuntimeError("补丁后的 common/include/linux/susfs.h 里找不到 SUSFS_VERSION")

        patched_version = match.group(1)
        logger.info(f"Patched kernel SUSFS_VERSION: {patched_version}")

        if patched_version != "v2.1.0":
            raise RuntimeError(f"补丁后的 SUSFS_VERSION 错误：{patched_version}，目标必须是 v2.1.0")

        # 3. 关键修复：应用 KernelSU/SukiSU 侧 SUSFS 启用补丁。
        #    如果漏掉这里，最终刷入后 ksu_susfs 仍可能检测成 v1.5.2。
        ksu_patch_dir = self.susfs_dir / "kernel_patches/KernelSU"
        if not ksu_patch_dir.exists():
            raise RuntimeError(f"SUSFS KernelSU 补丁目录不存在: {ksu_patch_dir}")

        ksu_patches = sorted(ksu_patch_dir.glob("*.patch"))
        if not ksu_patches:
            raise RuntimeError(f"SUSFS KernelSU 补丁目录里没有 patch: {ksu_patch_dir}")

        self._chdir(ksu_dir)

        for p in ksu_patches:
            logger.info(f"应用 KernelSU SUSFS 补丁: {p.name}")
            self._run_cmd(f"patch -p1 --fuzz=3 < {p}", check=True)

        ksu_reject_files = list(ksu_dir.rglob("*.rej"))
        if ksu_reject_files:
            reject_list = "\n".join(str(p) for p in ksu_reject_files[:50])
            raise RuntimeError(f"SUSFS KernelSU 补丁存在失败片段 .rej，禁止继续构建:\n{reject_list}")

        # 4. 强制检查 KernelSU/SukiSU 侧是否真的接入 SUSFS。
        ksu_kconfig_candidates = [
            ksu_dir / "kernel/Kconfig",
            ksu_dir / "kernel/Kconfig.legacy",
        ]

        ksu_init_candidates = [
            ksu_dir / "kernel/core/init.c",
            ksu_dir / "kernel/core_hook.c",
            ksu_dir / "kernel/kernel.c",
        ]

        ksu_kconfig = next((p for p in ksu_kconfig_candidates if p.exists()), None)
        if not ksu_kconfig:
            raise RuntimeError(
                "找不到 KernelSU Kconfig，已检查:\n"
                + "\n".join(str(p) for p in ksu_kconfig_candidates)
            )

        with open(ksu_kconfig, "r", encoding="utf-8", errors="ignore") as f:
            kconfig_content = f.read()

        if "config KSU_SUSFS" not in kconfig_content and "KSU_SUSFS" not in kconfig_content:
            raise RuntimeError(f"{ksu_kconfig} 里没有 KSU_SUSFS，KernelSU SUSFS 补丁没有真正生效")

        init_hit = False
        init_hit_file = None

        for candidate in ksu_init_candidates:
            if not candidate.exists():
                continue

            with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                init_content = f.read()

            if "susfs_init" in init_content:
                init_hit = True
                init_hit_file = candidate
                break

        if not init_hit:
            raise RuntimeError(
                "没有在 KernelSU/SukiSU 初始化源码里找到 susfs_init，SUSFS 初始化没有真正接入。已检查:\n"
                + "\n".join(str(p) for p in ksu_init_candidates)
            )

        logger.info(f"KernelSU SUSFS Kconfig check passed: {ksu_kconfig}")
        logger.info(f"KernelSU SUSFS init check passed: {init_hit_file}")
        logger.info("=== KernelSU SUSFS integration check passed ===")

        self._chdir(self.work_dir)
        logger.info("=== SUSFS v2.1.0 + KernelSU integration 补丁应用完成 ===")

    def apply_sukisu_patches(self):
        logger.info("=== 应用 SukiSU 补丁 ===")

        # android14-6.1.138 下，SukiSU_patch 的 69_hide_stuff.patch
        # 会在 fs/proc/task_mmu.c 里留下未使用的 dentry 变量和 bypass 标签：
        #   error: unused variable 'dentry'
        #   error: unused label 'bypass'
        # 这会被 -Werror 当成编译失败。
        #
        # 这个补丁只改 proc maps 隐藏相关逻辑，不是下列核心目标的必要补丁：
        # SUSFS v2.1.0 / Manual Syscall Hooks / Magic Mount / BBR / KPM / LZ4KD。
        # 所以在 android14-6.1.138 上跳过它，避免破坏编译。
        if (
            self.config.android_version == "android14"
            and self.config.kernel_version == "6.1"
            and self.config.get_sub_level_int() == 138
        ):
            logger.info("跳过 69_hide_stuff.patch：android14-6.1.138 会触发 task_mmu.c unused dentry/bypass 编译失败")
            return

        self._chdir(self.work_dir / "common")
        hooks_patch = self.sukisu_patch_dir / "69_hide_stuff.patch"
        if hooks_patch.exists():
            self._run_cmd(f"cp {hooks_patch} . && patch -p1 -F 3 < 69_hide_stuff.patch", check=True)

    def apply_zram_patches(self):
        if not self.config.use_zram:
            return

        logger.info("=== 应用 ZRAM (LZ4KD) 补丁 - final safe fix ===")

        common_dir = self.work_dir / "common"
        zram_root = self.sukisu_patch_dir / "other/zram"
        self._chdir(common_dir)

        # 关键原则：
        # 1. 不能把 other/zram/lz4k/lib/* 整个摊平复制到 common/lib/
        #    否则会覆盖 AOSP 原始 lib/Kconfig 和 lib/Makefile。
        # 2. 但必须完整复制 LZ4K/LZ4KD 真正需要的源码：
        #    crypto/lz4k.c、crypto/lz4kd.c、lib/lz4k/、lib/lz4kd/。

        safe_copy_jobs = [
            # headers
            (zram_root / "lz4k/include/linux", common_dir / "include/linux"),

            # lib codec directories
            (zram_root / "lz4k/lib/lz4k",  common_dir / "lib/lz4k"),
            (zram_root / "lz4k/lib/lz4kd", common_dir / "lib/lz4kd"),

            # crypto api source files
            (zram_root / "lz4k/crypto/lz4k.c",  common_dir / "crypto/lz4k.c"),
            (zram_root / "lz4k/crypto/lz4kd.c", common_dir / "crypto/lz4kd.c"),
        ]

        for src, dst in safe_copy_jobs:
            if not src.exists():
                raise RuntimeError(f"缺少 ZRAM/LZ4KD 必需源码: {src}")

            if src.is_dir():
                self._run_cmd(f"mkdir -p {dst} && cp -r {src}/* {dst}/", check=True)
            else:
                self._run_cmd(f"mkdir -p {dst.parent} && cp {src} {dst}", check=True)

        # OPlus LZ4KD 源码作为独立目录复制到 lib/ 下，
        # 不能把里面的内容摊平到 common/lib/，避免覆盖 lib/Kconfig / lib/Makefile。
        oplus_src = zram_root / "lz4k_oplus"
        if oplus_src.exists():
            self._run_cmd(f"cp -r {oplus_src} {common_dir}/lib/", check=True)
        else:
            logger.warning(f"ZRAM OPlus source missing, skip: {oplus_src}")

        # 提前检查关键源码是否真的存在，避免跑到 Bazel 编译阶段才炸。
        required_sources = [
            common_dir / "crypto/lz4k.c",
            common_dir / "crypto/lz4kd.c",
            common_dir / "lib/lz4k/Makefile",
            common_dir / "lib/lz4kd/Makefile",
        ]

        for required in required_sources:
            if not required.exists():
                raise RuntimeError(f"LZ4KD 源码复制不完整，缺少: {required}")

        # 应用 LZ4KD 接入补丁。
        # 必须 check=True，补丁失败就立刻停止，不能带着坏源码继续编译。
        zram_patch_dir = zram_root / f"zram_patch/{self.config.kernel_version}"

        for patch_name in ["lz4kd.patch", "lz4k_oplus.patch"]:
            patch_file = zram_patch_dir / patch_name
            if not patch_file.exists():
                raise RuntimeError(f"缺少 ZRAM/LZ4KD 补丁: {patch_file}")

            self._run_cmd(f"patch -p1 -F 3 < {patch_file}", check=True)

    def apply_task_mmu_fixes(self):
        logger.info("=== 应用 task_mmu.c 修复 ===")
        self._chdir(self.work_dir / "common")
        task_mmu = Path("fs/proc/task_mmu.c")
        if not task_mmu.exists():
            return

        fb = f"{self.config.android_version}-{self.config.kernel_version}"
        with open(task_mmu, "r") as f:
            content = f.read()

        if fb == "android15-6.6" and "unsigned int nr_subpages" not in content:
            self._fix_base_c_header()
        elif fb == "android14-6.1" and "if (!vma_pages(vma))" not in content:
            self._fix_base_c_header()
            if "goto show_pad;" in content:
                content = content.replace("goto show_pad;", "return 0;")
                with open(task_mmu, "w") as f:
                    f.write(content)
        elif fb in ["android12-5.10", "android13-5.10", "android13-5.15"] and "if (!vma_pages(vma))" not in content:
            if "goto show_pad;" in content:
                content = content.replace("goto show_pad;", "return 0;")
                with open(task_mmu, "w") as f:
                    f.write(content)

    def _fix_base_c_header(self):
        base_c = self.work_dir / "common/fs/proc/base.c"
        if not base_c.exists():
            return
        with open(base_c, "r") as f:
            content = f.read()
        if "#include <linux/dma-buf.h>" not in content:
            content = content.replace("#include <linux/cpufreq_times.h>",
                                    "#include <linux/cpufreq_times.h>\n#include <linux/dma-buf.h>")
            with open(base_c, "w") as f:
                f.write(content)

    def configure_kernel(self):
        logger.info("=== 配置内核 ===")
        self._chdir(self.work_dir)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        if not config_file.exists():
            logger.warning(f"配置文件不存在: {config_file}")
            return

        with open(config_file, "a") as f:
            f.write(self.KERNEL_CONFIG_TEMPLATE)
            if self.config.kernel_version != "6.6":
                f.write("CONFIG_KSU_SUSFS_SUS_PATH=y\n")
            else:
                f.write("CONFIG_KSU_SUSFS_SUS_PATH=n\n")

        if self.config.use_zram:
            self._configure_zram()
            self._configure_bazel()

        if self.config.set_default_bbr:
            with open(config_file, "a") as f:
                f.write("CONFIG_DEFAULT_BBR=y\n")

        build_config = self.work_dir / "common/build.config.gki"
        if build_config.exists():
            with open(build_config, "r") as f:
                content = f.read()
            content = content.replace("check_defconfig", "")
            with open(build_config, "w") as f:
                f.write(content)

    def _configure_zram(self):
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        with open(config_file, "r") as f:
            content = f.read()
        kv = self.config.kernel_version
        if kv == "5.10":
            with open(config_file, "a") as f:
                f.write(self.ZRAM_CONFIG_5_10)
        else:
            content = content.replace("CONFIG_ZRAM=m", "CONFIG_ZRAM=y")
            with open(config_file, "w") as f:
                f.write(content)
            with open(config_file, "a") as f:
                f.write("CONFIG_ZSMALLOC=y\n")
        with open(config_file, "a") as f:
            f.write(self.ZRAM_CONFIG_COMMON)

    def _configure_bazel(self):
        modules_bzl = self.work_dir / "common/modules.bzl"
        if modules_bzl.exists():
            with open(modules_bzl, "r") as f:
                content = f.read()
            modified = False
            for old in ['"drivers/block/zram/zram.ko",\n', '"drivers/block/zram/zram.ko",',
                       '"mm/zsmalloc.ko",\n', '"mm/zsmalloc.ko",']:
                if old in content:
                    content = content.replace(old, '')
                    modified = True
            if modified:
                with open(modules_bzl, "w") as f:
                    f.write(content)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        with open(config_file, "a") as f:
            f.write("CONFIG_MODULE_SIG_FORCE=n\n")

    def configure_kernel_name(self):
        logger.info("=== 配置内核名称 ===")
        self._chdir(self.work_dir)
        MAX_CUSTOM_LEN = 48
        safe_custom_version = ""
        if self.config.custom_version:
            safe_custom_version = self.config.custom_version.rstrip('-')[:MAX_CUSTOM_LEN]

        setlocalversion = self.work_dir / "common/scripts/setlocalversion"
        if setlocalversion.exists():
            with open(setlocalversion, "r") as f:
                content = f.read()
            if safe_custom_version:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'echo "$res"' in line and not line.strip().startswith('#'):
                        lines[i] = f'\techo "{safe_custom_version}$res"'
                        break
                with open(setlocalversion, "w") as f:
                    f.write('\n'.join(lines))
            if "-dirty" in content:
                content = content.replace("-dirty", "")
                with open(setlocalversion, "w") as f:
                    f.write(content)

        import datetime
        current_time = datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        mkcompile_h = self.work_dir / "common/scripts/mkcompile_h"
        if mkcompile_h.exists():
            with open(mkcompile_h, "r") as f:
                content = f.read()
            content = content.replace('UTS_VERSION="$(echo $UTS_VERSION $CONFIG_FLAGS $TIMESTAMP | cut -b -$UTS_LEN)"',
                                    f'UTS_VERSION="#1 SMP PREEMPT {current_time}"')
            with open(mkcompile_h, "w") as f:
                f.write(content)

        if self.config.kernel_version in ["6.1", "6.6"]:
            init_makefile = self.work_dir / "common/init/Makefile"
            if init_makefile.exists():
                with open(init_makefile, "r") as f:
                    content = f.read()
                content = content.replace('$(preempt-flag-y) "$(build-timestamp)"', f'$(preempt-flag-y) "{current_time}"')
                with open(init_makefile, "w") as f:
                    f.write(content)

        if not (self.work_dir / "build/build.sh").exists():
            bazel_build = self.work_dir / "common/BUILD.bazel"
            if bazel_build.exists():
                with open(bazel_build, "r") as f:
                    content = f.read()
                lines = [l for l in content.split('\n') if '"protected_exports_list"' not in l or 'android/abi_gki_protected_exports_aarch64' not in l]
                with open(bazel_build, "w") as f:
                    f.write('\n'.join(lines))

            abi_path = self.work_dir / "common/android/abi_gki_protected_exports_aarch64"
            if abi_path.exists():
                import shutil
                try:
                    if abi_path.is_dir():
                        shutil.rmtree(abi_path)
                    else:
                        abi_path.unlink()
                except Exception:
                    pass

            stamp_bzl = self.work_dir / "build/kernel/kleaf/impl/stamp.bzl"
            if stamp_bzl.exists():
                with open(stamp_bzl, "r") as f:
                    content = f.read()
                content = content.replace("-maybe-dirty", "")
                with open(stamp_bzl, "w") as f:
                    f.write(content)

            if self.config.custom_version:
                config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
                if config_file.exists():
                    with open(config_file, "r") as f:
                        content = f.read()
                    content = re.sub(r'^CONFIG_LOCALVERSION=".*"$', f'CONFIG_LOCALVERSION="{self.config.custom_version}"', content, flags=re.MULTILINE)
                    with open(config_file, "w") as f:
                        f.write(content)
                else:
                    logger.warning(f"配置文件不存在，跳过 custom_version 设置: {config_file}")

    def show_kernel_config(self):
        logger.info("=== 显示内核配置列表 ===")
        self._chdir(self.work_dir)
        config_file = self.work_dir / "common/arch/arm64/configs/gki_defconfig"

        if not config_file.exists():
            logger.warning(f"配置文件不存在: {config_file}")
            return

        with open(config_file, "r") as f:
            lines = f.readlines()

        config_lines = [line.strip() for line in lines if line.strip().startswith("CONFIG_")]

        key_configs = {
            "CONFIG_KSU": "KernelSU",
            "CONFIG_KPM": "KPM",
            "CONFIG_KSU_SUSFS": "SUSFS",
            "CONFIG_BBG": "Baseband-guard",
            "CONFIG_TCP_CONG_BBR": "BBR",
            "CONFIG_ZRAM": "ZRAM",
        }

        logger.info("关键配置状态:")
        for prefix, name in key_configs.items():
            found = [c for c in config_lines if c.startswith(prefix)]
            if found:
                status = "已启用"
            else:
                status = "未配置"
            logger.info(f"  [{status}] {name}")
            if found:
                for f in sorted(found):
                    logger.info(f"      -> {f}")

        if self.config.use_zram:
            zram_configs = [c for c in config_lines if any(x in c for x in ["ZRAM", "ZSMALLOC", "LZ4", "LZ4KD", "CRYPTO_LZ4", "MODULE_SIG"])]
            if zram_configs:
                logger.info("ZRAM 相关配置:")
                for zc in sorted(zram_configs):
                    logger.info(f"  -> {zc}")

        logger.info("-" * 60)

    def build_kernel(self) -> bool:
        logger.info("=== 开始编译内核 ===")
        self._chdir(self.work_dir)

        build_config = self.work_dir / "common/build.config.gki.aarch64"
        if build_config.exists():
            with open(build_config, "r") as f:
                content = f.read()
            content = content.replace("BUILD_SYSTEM_DLKM=1", "BUILD_SYSTEM_DLKM=0")
            lines = [l for l in content.split('\n') if 'MODULES_ORDER=android/gki_aarch64_modules' not in l and 'KMI_SYMBOL_LIST_STRICT_MODE' not in l]
            with open(build_config, "w") as f:
                f.write('\n'.join(lines))

        try:
            if (self.work_dir / "build/build.sh").exists():
                logger.info("使用旧版构建方式...")
                result = self._run_cmd("LTO=thin BUILD_CONFIG=common/build.config.gki.aarch64 build/build.sh CC=\"/usr/bin/ccache clang\"", check=False)
            else:
                logger.info("使用 Bazel 构建方式...")
                result = self._run_cmd("tools/bazel build --disk_cache=/home/runner/.cache/bazel --config=fast --lto=thin //common:kernel_aarch64_dist", check=False)

            if result.returncode == 0:
                logger.info("=== 内核编译成功 ===")
                return True
            logger.error(f"内核编译失败: {result.stderr if result.stderr else 'Unknown error'}")
            return False
        except Exception as e:
            logger.error(f"编译过程出错: {e}")
            return False

    def patch_kpm_image(self):
        if not self.config.use_kpm or self.config.kernel_version == "6.6":
            return
        logger.info("=== 修补 Image 文件 (KPM) ===")
        self._chdir(self.work_dir)

        if self.config.android_version in ["android12", "android13"]:
            image_dir = self.work_dir / f"out/{self.config.android_version}-{self.config.kernel_version}/dist"
        else:
            image_dir = self.work_dir / "bazel-bin/common/kernel_aarch64"

        if not image_dir.exists():
            return
        self._chdir(image_dir)
        self._run_cmd(f"curl -LSs {KPM_PATCH_URL} -o patch && chmod 777 patch && ./patch", check=False)
        if (image_dir / "oImage").exists():
            self._run_cmd("mv oImage Image", check=False)

    def prepare_boot_images(self) -> list:
        logger.info("=== 准备启动镜像 ===")
        self._chdir(self.work_dir)
        bootimgs_dir = self.work_dir / "bootimgs"
        bootimgs_dir.mkdir(exist_ok=True)
        artifacts = []

        if self.config.android_version in ["android12", "android13"]:
            image_source = self.work_dir / f"out/{self.config.android_version}-{self.config.kernel_version}/dist"
        else:
            image_source = self.work_dir / "bazel-bin/common/kernel_aarch64"

        for image_name in ["Image", "Image.lz4"]:
            src = image_source / image_name
            if src.exists():
                self._run_cmd(f"cp {src} {bootimgs_dir}/ && cp {src} {self.work_dir}/", check=False)

        if (self.work_dir / "Image").exists():
            self._run_cmd("gzip -n -k -f -9 Image", check=False)

        if self.config.android_version == "android12":
            self._prepare_android12_boot_images(bootimgs_dir, artifacts)
        else:
            self._prepare_boot_images_generic(bootimgs_dir, artifacts)
        return artifacts

    def _prepare_android12_boot_images(self, bootimgs_dir: Path, artifacts: list):
        self._chdir(bootimgs_dir)
        gki_url = f"https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-{self.config.os_patch_level}_{self.config.revision}.zip"
        fallback_url = "https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-2023-01_r1.zip"
        result = subprocess.run(f"curl -sL -w '%{{http_code}}' {gki_url} -o /dev/null", shell=True, capture_output=True, text=True)
        url = gki_url if "200" in result.stdout else fallback_url
        self._run_cmd(f"curl -Lo gki-kernel.zip {url} && unzip -o gki-kernel.zip && rm gki-kernel.zip", check=False)
        boot_img_path = bootimgs_dir / "boot-5.10.img"
        if boot_img_path.exists():
            self._run_cmd(f"$UNPACK_BOOTIMG --boot_img={boot_img_path}", check=False)
        self._create_boot_image_variants(bootimgs_dir, artifacts, has_ramdisk=True)

    def _prepare_boot_images_generic(self, bootimgs_dir: Path, artifacts: list):
        self._chdir(bootimgs_dir)
        self._create_boot_image_variants(bootimgs_dir, artifacts, has_ramdisk=False)

    def _create_boot_image_variants(self, bootimgs_dir: Path, artifacts: list, has_ramdisk: bool = False):
        self._chdir(bootimgs_dir)
        if (bootimgs_dir / "Image").exists():
            self._run_cmd("gzip -n -k -f -9 Image", check=False)

        for kernel_file, output_file in [("Image", "boot.img"), ("Image.gz", "boot-gz.img"), ("Image.lz4", "boot-lz4.img")]: