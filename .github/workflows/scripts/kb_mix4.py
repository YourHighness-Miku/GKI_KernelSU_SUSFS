import os
import subprocess
import re
import logging
import datetime
import shutil
import json
from pathlib import Path
from typing import Optional

from config import (KSU_REPO_CONFIG, SUSFS_REPO_CONFIG, SUKISU_PATCH_REPO_CONFIG,
                   ANYKERNEL_CONFIG, KERNEL_PATCHES_CONFIG, BBG_CONFIG, TOOLCHAIN_CONFIG,
                   LEGACY_FIXES, OP8E_PATCH_URL, KPM_PATCH_URL,
                   SUKISU_PIN_REF, SUKISU_PIN_COMMIT, EXPECTED_SUSFS_VERSION)
from kb_types import BuildResult

logger = logging.getLogger(__name__)


class BuilderMix4:
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

    def _find_image_dir(self) -> Path:
        if self.config.android_version in ["android12", "android13"]:
            return self.work_dir / f"out/{self.config.android_version}-{self.config.kernel_version}/dist"
        return self.work_dir / "bazel-bin/common/kernel_aarch64"

    def verify_kernel_version(self):
        """编译产物版本门禁：Image 里必须包含期望的 x.y.z，以及 KSU versionCode。"""
        image_dir = self._find_image_dir()
        image = image_dir / "Image"
        if not image.exists():
            raise RuntimeError(f"内核 Image 不存在，无法做版本校验: {image}")

        want = f"{self.config.kernel_version}.{self.config.sub_level}"  # e.g. 6.1.138
        out = subprocess.run(f"strings '{image}' | grep -m1 'Linux version' || true",
                             shell=True, capture_output=True, text=True).stdout.strip()
        logger.info(f"Image 版本串: {out or '(未找到 Linux version)'}")
        if self.config.sub_level != "X" and want not in out:
            raise RuntimeError(
                f"内核版本校验失败：Image 中未包含期望版本 {want}。实际: '{out}'。拒绝打包。"
            )
        logger.info(f"内核版本校验通过：包含 {want}")

        # manager/driver 硬门禁：Image 必须含期望 KSU versionCode（如 40838），禁止 37973。
        want_vc = str(self.expected_ksu_version_code or self.config.effective_manager_version_code())
        strings_out = subprocess.run(
            f"strings '{image}'",
            shell=True, capture_output=True, text=True,
        ).stdout
        if "37973" in strings_out and want_vc != "37973":
            raise RuntimeError(
                "Image 含旧 driver versionCode 37973（builtin rev-list 误用产物）。"
                "FAILED / DO NOT FLASH。拒绝打包。"
            )
        # KSU_VERSION 以十进制数字编入；同时核对完整版本串模式
        vc_hits = re.findall(r"\b" + re.escape(want_vc) + r"\b", strings_out)
        full_hits = [
            line for line in strings_out.splitlines()
            if want_vc in line and ("SukiSU" in line or "KernelSU" in line or "v4." in line or "@" in line)
        ]
        logger.info(
            f"Image KSU versionCode 扫描: want={want_vc}, "
            f"numeric_hits={len(vc_hits)}, annotated_hits={len(full_hits)}"
        )
        if not vc_hits and not full_hits:
            # 仍允许仅编译标志；再查 -DKSU_VERSION 写入的数值是否出现在二进制
            # 硬失败：必须能在产物中找到 versionCode
            raise RuntimeError(
                f"Image 中未找到期望 driver versionCode {want_vc}。"
                "manager/driver 兼容门禁失败，拒绝打包。"
            )
        if want_vc != "40838" and self.config.sukisu_mode == "ci":
            logger.warning(
                f"CI 模式期望通常为 40838，当前 want_vc={want_vc}"
            )
        logger.info(f"manager/driver versionCode 门禁通过：{want_vc}")

    def verify_manager_driver_gate(self, artifacts_dir: Optional[Path] = None):
        """打包/Release 前硬门禁：manager versionCode == driver versionCode == 40838（CI 模式）。"""
        want = self.config.effective_manager_version_code()
        got = self.expected_ksu_version_code
        if got is None:
            raise RuntimeError("expected_ksu_version_code 未设置，拒绝发布")
        if int(got) != int(want):
            raise RuntimeError(
                f"manager/driver 不匹配：manager={want} driver={got}。拒绝发布。"
            )
        if int(got) == 37973:
            raise RuntimeError("driver 仍为 37973（旧错误映射）。FAILED / DO NOT FLASH。")
        if self.config.sukisu_mode == "ci" and int(got) != 40838:
            raise RuntimeError(
                f"CI 模式强制 driver versionCode=40838，实际 {got}。拒绝发布。"
            )
        # 源码侧 LOCAL_COUNT 再核对
        ksu_makefile = self.work_dir / "KernelSU" / "kernel" / "Makefile"
        if ksu_makefile.exists():
            text = ksu_makefile.read_text(errors="ignore")
            if re.search(r"LOCAL_COUNT\s*:=\s*788\b", text):
                raise RuntimeError("KernelSU Makefile 仍含 LOCAL_COUNT:=788，拒绝发布")
            if not re.search(r"LOCAL_COUNT\s*:=\s*3653\b", text) and int(got) == 40838:
                raise RuntimeError(
                    "KernelSU Makefile 未锁定 LOCAL_COUNT:=3653，拒绝发布"
                )
        logger.info(
            f"manager/driver 硬门禁通过：versionCode={got}, "
            f"manager_commit={self.resolved_manager_commit}, "
            f"builtin_commit={self.resolved_sukisu_commit}"
        )
