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


class BuilderMix2:
    def apply_susfs_patches(self):
        logger.info("=== 应用 SUSFS 补丁 - strict v2.2.0 + SukiSU Ultra builtin integration ===")

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

        if patched_version != "v2.2.0":
            raise RuntimeError(f"补丁后的 SUSFS_VERSION 错误：{patched_version}，目标必须是 v2.2.0")

        # 3. 当前使用 SukiSU Ultra builtin。
        #    不再应用 susfs4ksu/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch。
        #    原因：外部 KernelSU patch 会在当前 SukiSU Ultra 的 init.c / app_profile.c 产生关键 .rej。
        logger.info("=== 跳过外部 KernelSU SUSFS patch，改用 SukiSU Ultra builtin 自带集成检查 ===")

        self._chdir(ksu_dir)

        # 确保没有残留 .rej。
        leftover_rejects = list(ksu_dir.rglob("*.rej"))
        if leftover_rejects:
            reject_list = "\n".join(str(p) for p in leftover_rejects[:50])
            raise RuntimeError(
                "KernelSU 目录存在旧的 .rej 残留，请清理工作区后重新构建，禁止继续：\n"
                + reject_list
            )

        # 4. 强制检查 SukiSU builtin 是否真的带了 SUSFS Kconfig。
        kconfig_files = list(ksu_dir.rglob("Kconfig*"))
        if not kconfig_files:
            raise RuntimeError(f"KernelSU 目录里找不到任何 Kconfig 文件: {ksu_dir}")

        kconfig_hit = False
        ksu_kconfig = None

        for candidate in kconfig_files:
            with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "KSU_SUSFS" in content:
                kconfig_hit = True
                ksu_kconfig = candidate
                break

        if not kconfig_hit:
            raise RuntimeError(
                "SukiSU builtin 检查失败：KernelSU Kconfig 里没有 KSU_SUSFS。"
                "说明没有真正拉到带 SUSFS 的 builtin 分支，禁止继续生成包。"
            )

        # 5. 强制检查是否存在 susfs_init 接入。
        init_hit = False
        init_hit_file = None

        for candidate in ksu_dir.rglob("*.c"):
            with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "susfs_init" in content:
                init_hit = True
                init_hit_file = candidate
                break

        if not init_hit:
            raise RuntimeError(
                "SukiSU builtin 检查失败：KernelSU 源码里没有找到 susfs_init。"
                "说明 SUSFS 初始化没有真正接入，禁止继续生成包。"
            )

        logger.info(f"KernelSU SUSFS Kconfig check passed: {ksu_kconfig}")
        logger.info(f"KernelSU SUSFS init check passed: {init_hit_file}")
        logger.info("=== KernelSU SUSFS integration check passed ===")

        self._chdir(self.work_dir)
        logger.info("=== SUSFS v2.2.0 + SukiSU Ultra builtin integration 补丁应用完成 ===")

    def apply_sukisu_patches(self):
        logger.info("=== 应用 SukiSU 补丁 ===")

        common_dir = self.work_dir / "common"
        self._chdir(common_dir)
        hooks_patch = self.sukisu_patch_dir / "69_hide_stuff.patch"
        if not hooks_patch.exists():
            logger.warning(f"69_hide_stuff.patch 不存在，跳过: {hooks_patch}")
            return

        # 应用补丁（不再对 android14-6.1.138 整块跳过 —— 修复 八.9）。
        self._run_cmd(f"cp {hooks_patch} . && patch -p1 -F 3 < 69_hide_stuff.patch", check=True)

        # 应用后扫描 .rej，任何拒绝块都必须失败，不能静默带病继续。
        rejects = list(common_dir.rglob("*.rej"))
        if rejects:
            raise RuntimeError(
                "69_hide_stuff.patch 存在未应用的拒绝块(.rej):\n"
                + "\n".join(str(p) for p in rejects[:50])
            )

        # android14-6.1.138：该补丁会在 fs/proc/task_mmu.c 留下未使用的 dentry 变量
        # 和 bypass 标签，-Werror 下会失败。这里只做“最小外科修复”，删除真正未使用的
        # 声明/标签，保留补丁的隐藏功能本身（不是整块跳过）。
        if (
            self.config.android_version == "android14"
            and self.config.kernel_version == "6.1"
            and self.config.get_sub_level_int() == 138
        ):
            self._fix_task_mmu_unused_after_hide(common_dir)

    def _fix_task_mmu_unused_after_hide(self, common_dir: Path):
        """修复 69_hide_stuff + SUSFS 在 6.1.138 task_mmu.c 引入的编译错误。

        常见问题：
        1) `struct dentry *dentry;` 在部分分支未赋值就被使用，-Werror 下触发
           -Wsometimes-uninitialized；
        2) 残留未使用的 bypass 标签。
        """
        task_mmu = common_dir / "fs/proc/task_mmu.c"
        if not task_mmu.exists():
            logger.warning(f"task_mmu.c 不存在，跳过外科修复: {task_mmu}")
            return
        src = task_mmu.read_text(errors="ignore")
        orig = src
        changed = []

        # 1) 未使用的 'bypass:' 标签：若函数体内不再有 'goto bypass;'，删除标签定义行。
        if "goto bypass;" not in src:
            new = re.sub(r'\n[ \t]*bypass:[ \t]*\n', '\n', src)
            if new != src:
                src = new
                changed.append("removed unused label 'bypass:'")

        # 2) 把未初始化的 dentry 声明改为 = NULL，消掉 -Wsometimes-uninitialized。
        #    SUSFS 的 spoofed_redirected_name 分支可能跳过 dentry 赋值，但仍会检查 if (dentry)。
        new = re.sub(
            r'(\bstruct dentry \*dentry)\s*;',
            r'\1 = NULL;',
            src,
            count=1,
        )
        if new != src:
            src = new
            changed.append("initialized 'struct dentry *dentry = NULL'")

        # 3) 若声明后完全没有其它 dentry 使用，再删除声明本身。
        decl_pat = re.compile(r'\n[ \t]*struct dentry \*dentry\s*(?:=\s*NULL\s*)?;[ \t]*\n')
        for m in list(decl_pat.finditer(src)):
            uses = len(re.findall(r'\bdentry\b', src))
            if uses <= 1:
                src = src[:m.start()] + "\n" + src[m.end():]
                changed.append("removed unused 'struct dentry *dentry;'")
                break

        if src != orig:
            task_mmu.write_text(src)
            logger.info("task_mmu.c 外科修复: " + "; ".join(changed))
        else:
            logger.info("task_mmu.c 无需外科修复（未发现未使用的 dentry/bypass，或已被使用）")
