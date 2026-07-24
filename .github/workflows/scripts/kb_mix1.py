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


class BuilderMix1:
    def _checkout_ack_pin(self, common_dir: Path, pin: dict):
        """把 common/ 精确切到 ACK tag，并用 Makefile SUBLEVEL 做硬门禁。"""
        self._chdir(common_dir)
        tag = pin["ack_tag"]
        # repo sync 使用 --no-tags，且 remote 名通常是 aosp（不是 origin）。
        # 直接 fetch refs/tags/<tag> 的 peeled object，兼容 aosp/origin 与 annotated tag。
        remotes = subprocess.run(
            "git remote",
            shell=True,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        remote = "aosp" if "aosp" in remotes else ("origin" if "origin" in remotes else (remotes[0] if remotes else ""))
        if not remote:
            raise RuntimeError("common 仓库没有可用 git remote，无法拉取 ACK tag")

        fetch_specs = [
            f"+refs/tags/{tag}^{{}}:refs/tags/{tag}",
            f"+refs/tags/{tag}:refs/tags/{tag}",
        ]
        last_err = None
        for spec in fetch_specs:
            try:
                self._run_cmd(f"git fetch --depth 1 {remote} {spec}", check=True)
                last_err = None
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
        if last_err is not None:
            raise RuntimeError(
                f"拉取 ACK tag 失败: remote={remote} tag={tag}; last_error={last_err}"
            ) from last_err

        self._run_cmd(f"git checkout -q refs/tags/{tag}", check=True)

        head = subprocess.run("git rev-parse HEAD", shell=True, capture_output=True, text=True).stdout.strip()
        logger.info(f"common HEAD = {head} (期望 tag {tag} -> {pin['ack_commit']})")
        if pin.get("ack_commit") and not head.startswith(pin["ack_commit"][:12]) and head != pin["ack_commit"]:
            # tag 的 peeled commit 应与固定 commit 一致；不一致则拒绝继续。
            raise RuntimeError(
                f"ACK tag {tag} 解析到的 commit {head} 与固定值 {pin['ack_commit']} 不一致，拒绝继续。"
            )

        makefile = common_dir / "Makefile"
        text = makefile.read_text(errors="ignore")
        sub = re.search(r'^SUBLEVEL\s*=\s*(\d+)', text, re.MULTILINE)
        patch = re.search(r'^PATCHLEVEL\s*=\s*(\d+)', text, re.MULTILINE)
        ver = re.search(r'^VERSION\s*=\s*(\d+)', text, re.MULTILINE)
        got = (int(ver.group(1)) if ver else None, int(patch.group(1)) if patch else None, int(sub.group(1)) if sub else None)
        # kernel_version 形如 "6.1" -> (6,1)
        want = (6, int(self.config.kernel_version.split(".")[1]), pin["expected_sublevel"])
        if got != want:
            raise RuntimeError(
                f"ACK 源码版本不符：Makefile 得到 {got}，期望 {want}（tag {tag}）。拒绝继续。"
            )
        logger.info(f"ACK 源码版本校验通过：VERSION.PATCHLEVEL.SUBLEVEL = {got[0]}.{got[1]}.{got[2]}")
        self._chdir(self.work_dir)

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
        logger.info(f"=== 添加 SukiSU Ultra KernelSU (builtin, 固定 {SUKISU_PIN_REF}) ===")
        self._chdir(self.work_dir)

        # 使用 SukiSU Ultra 官方 builtin，并固定到稳定 commit（修复 八.1 / 十九.15）。
        # setup.sh 从固定 commit 拉取，避免浮动 main 造成 manager/driver 漂移。
        setup_url = KSU_REPO_CONFIG["setup_script"]  # 已指向 SUKISU_PIN_COMMIT

        # 清理旧 KernelSU，避免上一次失败构建残留污染。
        self._run_cmd("rm -rf KernelSU", check=True)

        self._run_cmd(f"curl -LSs {setup_url} | bash -s builtin", check=True)

        ksu_dir = self.work_dir / "KernelSU"
        if not ksu_dir.exists():
            raise RuntimeError(f"SukiSU builtin 安装后 KernelSU 目录不存在: {ksu_dir}")

        self._chdir(ksu_dir)

        # 把 KernelSU 精确固定到 SUKISU_PIN_COMMIT，并记录解析出的 SHA。
        self._run_cmd("git fetch --all --tags --prune", check=True)
        self._run_cmd(f"git checkout --force {SUKISU_PIN_COMMIT}", check=True)
        head = subprocess.run("git rev-parse HEAD", shell=True, capture_output=True, text=True).stdout.strip()
        logger.info(f"SukiSU KernelSU pinned HEAD = {head} (期望 {SUKISU_PIN_COMMIT})")
        if head != SUKISU_PIN_COMMIT and not SUKISU_PIN_COMMIT.startswith(head[:12]):
            raise RuntimeError(
                f"SukiSU 固定失败：KernelSU HEAD {head} != 期望 {SUKISU_PIN_COMMIT}。拒绝继续。"
            )
        self.resolved_sukisu_commit = head

        # === 版本号确定性修复（消除 manager/driver 版本号不一致，如 40838 vs 40837）===
        # 根因：KernelSU 的 kernel/Kbuild 用「实时 GitHub API 统计 main 的提交数」来算 KSU_VERSION，
        # 即使已 checkout 到固定 commit，构建时仍会 curl 到当前 main 的最新提交数，
        # 从而与「管理器 APK 用本地 git rev-list --count HEAD」得到的数不一致。
        # 修复：把本地 main 指到固定 commit，并把 Kbuild 的提交数来源改成本地 rev-list，
        # 关闭实时 GitHub API 统计。这样 driver 与 manager 都基于同一个固定 commit 的本地提交数。
        self._run_cmd("git branch -f main HEAD", check=True)
        local_count = subprocess.run("git rev-list --count HEAD", shell=True,
                                     capture_output=True, text=True).stdout.strip()
        logger.info(f"KernelSU 固定提交数 (rev-list --count HEAD) = {local_count}")

        kbuild = ksu_dir / "kernel" / "Kbuild"
        if kbuild.exists():
            text = kbuild.read_text(errors="ignore")
            # 强制 LOCAL_COUNT 使用本地提交数，屏蔽 GITHUB_COMMITS 实时统计。
            if "LOCAL_COUNT" in text and "GITHUB_COMMITS" in text:
                text = re.sub(
                    r"LOCAL_COUNT\s*:=.*",
                    f"LOCAL_COUNT     := {local_count}",
                    text, count=1,
                )
                kbuild.write_text(text)
                logger.info(f"已锁定 KernelSU Kbuild LOCAL_COUNT = {local_count}（关闭实时 GitHub 统计）")
            else:
                logger.warning("KernelSU Kbuild 未找到预期的 LOCAL_COUNT/GITHUB_COMMITS，跳过锁定（请核对上游是否改版）")
        else:
            logger.warning(f"未找到 KernelSU kernel/Kbuild，跳过版本号锁定: {kbuild}")

        # 计算期望的版本号（VERSION_BASE=40000, VERSION_OFFSET=2815，与管理器 build.gradle.kts 一致）。
        try:
            self.expected_ksu_version_code = 40000 + int(local_count) - 2815
            logger.info(f"期望 KSU/管理器 versionCode = {self.expected_ksu_version_code}")
        except ValueError:
            self.expected_ksu_version_code = None

        # 立刻检查 KSU_SUSFS，防止跑到后面才失败。
        kconfig_files = list(ksu_dir.rglob("Kconfig*"))
        if not kconfig_files:
            raise RuntimeError(f"SukiSU builtin 检查失败：KernelSU 目录里没有 Kconfig 文件: {ksu_dir}")

        kconfig_hit = False
        kconfig_hit_file = None

        for candidate in kconfig_files:
            with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "KSU_SUSFS" in content:
                kconfig_hit = True
                kconfig_hit_file = candidate
                break

        if not kconfig_hit:
            raise RuntimeError(
                "SukiSU builtin 检查失败：KernelSU Kconfig 里没有 KSU_SUSFS。"
                "说明 builtin 分支也没有拉到带 SUSFS 的 KernelSU，禁止继续生成包。"
            )

        logger.info(f"SukiSU builtin KSU_SUSFS check passed: {kconfig_hit_file}")

        self._chdir(self.work_dir)

        if self.config.kernelsu_commit:
            logger.warning(
                f"已忽略工作流填写的 KernelSU commit（{self.config.kernelsu_commit}）："
                f"本仓库将 SukiSU 固定到 {SUKISU_PIN_REF} ({SUKISU_PIN_COMMIT})，"
                "以保证内核驱动与管理器 APK 同源。"
            )

    def add_bbg(self):
        if not self.config.use_bbg:
            return
        logger.info("=== 添加 Baseband-guard（固定 commit + 本地 setup，不再 wget|bash）===")
        common_dir = self.work_dir / "common"
        if not common_dir.exists():
            raise RuntimeError("添加 BBG 失败：common 目录不存在")

        # 修复 十一.4：不再把远程脚本直接管道进 bash。改为克隆到固定 commit 后运行本地 setup.sh。
        bbg_dir = self.work_dir / "Baseband-guard"
        self._run_cmd("rm -rf Baseband-guard", check=True)
        self._run_cmd(f"git clone --depth 1 {BBG_CONFIG['repo_url']} {bbg_dir}", check=True)
        bbg_commit = BBG_CONFIG.get("pin_commit")
        if bbg_commit:
            self._chdir(bbg_dir)
            self._run_cmd("git fetch --depth 1 origin " + bbg_commit, check=True)
            self._run_cmd(f"git checkout --force {bbg_commit}", check=True)
            self._chdir(self.work_dir)
        setup = bbg_dir / "setup.sh"
        if not setup.exists():
            raise RuntimeError(f"BBG setup.sh 不存在: {setup}")
        self._chdir(common_dir)
        # 本地脚本、明确失败即停。
        self._run_cmd(f"bash {setup}", check=True)

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
        self._chdir(self.work_dir)
