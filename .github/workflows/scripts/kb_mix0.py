import os
import subprocess
import re
import logging
import datetime
import shutil
import json
from pathlib import Path

from config import (KSU_REPO_CONFIG, SUSFS_REPO_CONFIG, SUKISU_PATCH_REPO_CONFIG,
                   ANYKERNEL_CONFIG, KERNEL_PATCHES_CONFIG, BBG_CONFIG, TOOLCHAIN_CONFIG,
                   LEGACY_FIXES, OP8E_PATCH_URL, KPM_PATCH_URL,
                   SUKISU_PIN_REF, SUKISU_PIN_COMMIT, EXPECTED_SUSFS_VERSION)
from kb_types import BuildResult

logger = logging.getLogger(__name__)


class BuilderMix0:
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

        if version != "v2.2.0":
            raise RuntimeError(
                f"SUSFS 源码版本错误：当前是 {version}，目标必须是 v2.2.0。"
                f"请检查 susfs4ksu 的 {self.config.kernel_branch} 分支，或在工作流 SUSFS commit hash 中填写真正的 v2.2.0 commit/tag。"
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

        pin = self.config.ack_pin()

        if pin:
            # 有精确 ACK 固定项：用真实存在的 manifest 分支初始化，同步后再把 common
            # 切到精确 tag，并用 Makefile SUBLEVEL 做门禁（修复 六 / 八.5）。
            manifest_branch = pin["manifest_branch"]
            logger.info(f"使用固定 ACK 来源: manifest={manifest_branch} tag={pin['ack_tag']} commit={pin['ack_commit']}")
            self._run_cmd(
                f"$REPO init --depth=1 -u https://android.googlesource.com/kernel/manifest "
                f"-b {manifest_branch} --repo-rev=v2.16",
                check=True,
            )
            logger.info("同步内核源代码...")
            self._run_cmd("$REPO --trace sync -c -j$(nproc --all) --no-tags --fail-fast", check=True)

            common_dir = self.work_dir / "common"
            if not common_dir.exists():
                raise RuntimeError("repo sync 失败，common 目录不存在")

            self._checkout_ack_pin(common_dir, pin)
            self._apply_legacy_fixes("")
            logger.info("=== 内核源代码同步完成（已固定到 ACK tag）===")
            return

        # 无精确固定项：退回原有按 os_patch 月份分支的逻辑（保持兼容其它设备/矩阵）。
        formatted_branch = self.config.formatted_branch
        self._run_cmd(f"$REPO init --depth=1 -u https://android.googlesource.com/kernel/manifest "
                     f"-b common-{formatted_branch} --repo-rev=v2.16", check=True)

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
        self._run_cmd("$REPO --trace sync -c -j$(nproc --all) --no-tags --fail-fast", check=True)

        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            raise RuntimeError("repo sync 失败，common 目录不存在")
        self._apply_legacy_fixes(remote)
        logger.info("=== 内核源代码同步完成 ===")
