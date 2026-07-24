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


class BuilderMix3:
    def apply_zram_patches(self):
        if not self.config.use_zram:
            return

        logger.info("=== 应用 ZRAM (LZ4KD) 补丁 - final safe fix ===")

        common_dir = self.work_dir / "common"
        zram_root = self.sukisu_patch_dir / "other/zram"
        self._chdir(common_dir)

        safe_copy_jobs = [
            (zram_root / "lz4k/include/linux", common_dir / "include/linux"),
            (zram_root / "lz4k/lib/lz4k",  common_dir / "lib/lz4k"),
            (zram_root / "lz4k/lib/lz4kd", common_dir / "lib/lz4kd"),
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

        oplus_src = zram_root / "lz4k_oplus"
        if oplus_src.exists():
            self._run_cmd(f"cp -r {oplus_src} {common_dir}/lib/", check=True)
        else:
            logger.warning(f"ZRAM OPlus source missing, skip: {oplus_src}")

        required_sources = [
            common_dir / "crypto/lz4k.c",
            common_dir / "crypto/lz4kd.c",
            common_dir / "lib/lz4k/Makefile",
            common_dir / "lib/lz4kd/Makefile",
        ]

        for required in required_sources:
            if not required.exists():
                raise RuntimeError(f"LZ4KD 源码复制不完整，缺少: {required}")

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

        # KPM 开关不再硬编码在模板里（修复 八.10）：仅当 use_kpm 时写入，
        # 否则显式关闭，保证工作流上的 use_kpm=false 真正生效。
        with open(config_file, "a") as f:
            if self.config.use_kpm and self.config.kernel_version != "6.6":
                f.write("CONFIG_KPM=y\n")
            else:
                f.write("# CONFIG_KPM is not set\n")

        if self.config.use_zram:
            self._configure_zram()
            self._configure_bazel()

        # BBR：真正设为默认拥塞算法（修复 十）。
        # 编译 BBR，保留 cubic 作为回退，并同时写入 choice 与显式默认字符串。
        if self.config.set_default_bbr:
            with open(config_file, "a") as f:
                f.write(
                    "# === BBR (set as default) ===\n"
                    "CONFIG_TCP_CONG_ADVANCED=y\n"
                    "CONFIG_TCP_CONG_BBR=y\n"
                    "CONFIG_TCP_CONG_CUBIC=y\n"      # 保留回退
                    "CONFIG_NET_SCH_FQ=y\n"          # BBR 推荐 qdisc
                    "CONFIG_DEFAULT_BBR=y\n"
                    'CONFIG_DEFAULT_TCP_CONG="bbr"\n'
                )

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
                # lz4kd.patch(6.1) 已把默认压缩算法 choice 切到 LZ4KD 并新增该符号；
                # 这里显式写入以保证确定性，同时保留 lzo-rle/lz4/zstd 等回退（不删除）。
                f.write("CONFIG_ZRAM_DEF_COMP_LZ4KD=y\n")
                f.write('CONFIG_ZRAM_DEF_COMP="lz4kd"\n')
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
