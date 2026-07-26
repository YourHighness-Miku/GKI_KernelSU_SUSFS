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
                   SUKISU_PIN_REF, SUKISU_PIN_COMMIT, EXPECTED_SUSFS_VERSION,
                   SUKISU_MANAGER_PIN_COMMIT, SUKISU_MANAGER_PIN_REF,
                   SUKISU_MAIN_COMMIT_COUNT, EXPECTED_KSU_VERSION_CODE,
                   SUKISU_VERSION_BASE, SUKISU_VERSION_OFFSET,
                   SUKISU_MANAGER_CI_LABEL)
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

        # git fetch 不接受 peels 语法作为 refspec 源；直接抓 tag 即可（annotated tag 会解析到 peeled commit）。
        fetch_specs = [
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
        """安装 SukiSU：内核源码 pin 到 builtin(SUSFS)，versionCode 按 main 计数锁定。

        关键兼容规则（官方）:
          versionCode = 40000 + rev-list --count main - 2815
        管理器 40856 对应 main tip 35467545（count=3671 / ci_3671）。
        内核源码必须用 builtin（含 KSU_SUSFS），但 LOCAL_COUNT 必须是 main 的 3671，
        绝不能 `git branch -f main HEAD` 后对 builtin 做 rev-list（那会得到 788→37973）。
        """
        pin_commit = self.config.effective_kernel_builtin_commit()
        want_vc = self.config.effective_manager_version_code()
        main_count = SUKISU_MAIN_COMMIT_COUNT
        manager_commit = self.config.effective_manager_commit()

        logger.info(
            f"=== 添加 SukiSU Ultra KernelSU "
            f"(源码 {SUKISU_PIN_REF}@{pin_commit[:12]}, "
            f"versionCount main={main_count} → versionCode={want_vc}, "
            f"manager {SUKISU_MANAGER_PIN_REF}@{manager_commit[:12]} / {SUKISU_MANAGER_CI_LABEL}) ==="
        )
        self._chdir(self.work_dir)

        # setup.sh 从固定 builtin commit 拉取，避免浮动 HEAD。
        setup_url = (
            f"https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/"
            f"{pin_commit}/kernel/setup.sh"
        )

        # 清理旧 KernelSU，避免上一次失败构建残留污染。
        self._run_cmd("rm -rf KernelSU", check=True)

        self._run_cmd(f"curl -LSs {setup_url} | bash -s builtin", check=True)

        ksu_dir = self.work_dir / "KernelSU"
        if not ksu_dir.exists():
            raise RuntimeError(f"SukiSU builtin 安装后 KernelSU 目录不存在: {ksu_dir}")

        self._chdir(ksu_dir)

        # 把 KernelSU 源码精确固定到 builtin pin，并记录解析出的 SHA。
        self._run_cmd("git fetch --all --tags --prune", check=True)
        self._run_cmd(f"git checkout --force {pin_commit}", check=True)
        head = subprocess.run(
            "git rev-parse HEAD", shell=True, capture_output=True, text=True
        ).stdout.strip()
        logger.info(f"SukiSU KernelSU 源码 pinned HEAD = {head} (期望 {pin_commit})")
        if head != pin_commit and not pin_commit.startswith(head[:12]):
            raise RuntimeError(
                f"SukiSU 固定失败：KernelSU HEAD {head} != 期望 {pin_commit}。拒绝继续。"
            )
        self.resolved_sukisu_commit = head
        self.resolved_manager_commit = manager_commit
        self.resolved_main_commit_count = main_count

        # === 版本号硬锁定（对齐管理器 versionCode）===
        # 官方 Makefile 用 REPO_BRANCH=main 的提交数算 KSU_VERSION。
        # 禁止：git branch -f main HEAD（会把 main 指到 builtin，count 变成 788）。
        # 正确：LOCAL_COUNT 强制为 main 在 manager pin 上的提交数（见 config）。
        builtin_count = subprocess.run(
            "git rev-list --count HEAD", shell=True, capture_output=True, text=True
        ).stdout.strip()
        logger.info(
            f"builtin HEAD rev-list={builtin_count}（仅供参考，禁止用于 versionCode）；"
            f"强制 LOCAL_COUNT={main_count}（main@{manager_commit[:12]}）"
        )
        if str(builtin_count) == str(main_count):
            logger.warning(
                "builtin rev-list 与 main_count 相同，异常；请人工核对 pin。"
            )

        # 校验公式与期望 versionCode 一致
        computed = SUKISU_VERSION_BASE + int(main_count) - SUKISU_VERSION_OFFSET
        if computed != want_vc:
            raise RuntimeError(
                f"versionCode 公式不一致：40000+{main_count}-2815={computed} != want {want_vc}"
            )
        if computed == 37973 or int(main_count) == 788:
            raise RuntimeError(
                "拒绝错误映射：检测到旧的 37973/788 路径（builtin rev-list 误用）。"
            )
        if want_vc != EXPECTED_KSU_VERSION_CODE and self.config.sukisu_mode == "ci":
            logger.warning(
                f"CI 模式下 manager_version_code={want_vc} 与默认 "
                f"{EXPECTED_KSU_VERSION_CODE} 不同，将按输入覆盖。"
            )

        version_files = [
            ksu_dir / "kernel" / "Makefile",
            ksu_dir / "kernel" / "Kbuild",
            ksu_dir / "Makefile",
            ksu_dir / "Kbuild",
        ]
        locked = False
        for version_file in version_files:
            if not version_file.exists():
                continue
            text = version_file.read_text(errors="ignore")
            if "LOCAL_COUNT" not in text:
                continue
            new_text = re.sub(
                r"LOCAL_COUNT\s*:=.*",
                f"LOCAL_COUNT     := {main_count}",
                text,
                count=1,
            )
            # 同时切断 GitHub API 实时统计（GITHUB_COMMITS），避免覆盖 LOCAL_COUNT。
            new_text = re.sub(
                r"GITHUB_COMMITS\s*:=.*",
                "GITHUB_COMMITS   :=",
                new_text,
                count=1,
            )
            if new_text != text:
                version_file.write_text(new_text)
                logger.info(
                    f"已锁定 KernelSU 版本计数 LOCAL_COUNT = {main_count} "
                    f"(versionCode={computed}) @ {version_file}"
                )
                locked = True
                # 二次确认文件内不是 788
                if re.search(r"LOCAL_COUNT\s*:=\s*788\b", new_text):
                    raise RuntimeError(f"{version_file} 仍含 LOCAL_COUNT:=788，拒绝继续")
                if not re.search(rf"LOCAL_COUNT\s*:=\s*{main_count}\b", new_text):
                    raise RuntimeError(
                        f"{version_file} 未能写入 LOCAL_COUNT:={main_count}，拒绝继续"
                    )
                break
        if not locked:
            raise RuntimeError(
                "未找到可锁定的 LOCAL_COUNT（kernel/Makefile 或 Kbuild）。"
                "禁止继续——否则 versionCode 会漂到错误值。"
            )

        self.expected_ksu_version_code = computed
        logger.info(
            f"期望 KSU/管理器 versionCode = {self.expected_ksu_version_code} "
            f"(manager APK 基准 {want_vc} / {SUKISU_MANAGER_CI_LABEL})"
        )
        if self.expected_ksu_version_code != want_vc:
            raise RuntimeError(
                f"expected_ksu_version_code {self.expected_ksu_version_code} != "
                f"manager_version_code {want_vc}"
            )

        # 立刻检查 KSU_SUSFS，防止跑到后面才失败。
        kconfig_files = list(ksu_dir.rglob("Kconfig*"))
        if not kconfig_files:
            raise RuntimeError(
                f"SukiSU builtin 检查失败：KernelSU 目录里没有 Kconfig 文件: {ksu_dir}"
            )

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

        # susfs_init 接入检查
        init_hit = any(
            "susfs_init" in p.read_text(errors="ignore")
            for p in ksu_dir.rglob("*.c")
        )
        if not init_hit:
            raise RuntimeError(
                "SukiSU builtin 检查失败：源码里没有 susfs_init，禁止继续。"
            )

        logger.info(f"SukiSU builtin KSU_SUSFS check passed: {kconfig_hit_file}")
        logger.info("SukiSU builtin susfs_init check passed")

        self._chdir(self.work_dir)

        if self.config.kernelsu_commit and self.config.kernelsu_commit not in (
            pin_commit,
            head,
            head[:12],
            pin_commit[:12],
        ):
            logger.warning(
                f"工作流填写的 kernelsu_commit={self.config.kernelsu_commit} "
                f"与有效 builtin pin={pin_commit} 不同；已使用 pin。"
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
