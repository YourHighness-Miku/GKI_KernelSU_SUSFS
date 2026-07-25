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

        # manager/driver 硬门禁。
        # KSU_VERSION 以整数 -DKSU_VERSION=40838 编入，通常不是 ASCII "40838"。
        # 证据链：
        #   1) add_kernelsu 已锁定 expected_ksu_version_code 与 Makefile LOCAL_COUNT
        #   2) Image 含 KSU_VERSION_FULL 字符串（vX.Y.Z-<sha>@...）
        #   3) 可选：二进制小端整数编码
        #   4) SukiSU/KernelSU 上下文字符串不得出现错误的 37973
        want_vc = int(self.expected_ksu_version_code or self.config.effective_manager_version_code())
        want_vc_s = str(want_vc)

        # 源码侧 Makefile 必须仍锁定正确 LOCAL_COUNT
        ksu_makefile = self.work_dir / "KernelSU" / "kernel" / "Makefile"
        if not ksu_makefile.exists():
            raise RuntimeError(f"缺少 KernelSU Makefile，无法核对 LOCAL_COUNT: {ksu_makefile}")
        mf = ksu_makefile.read_text(errors="ignore")
        if re.search(r"LOCAL_COUNT\s*:=\s*788\b", mf):
            raise RuntimeError("KernelSU Makefile 仍含 LOCAL_COUNT:=788 → 37973。拒绝打包。")
        if want_vc == 40838 and not re.search(r"LOCAL_COUNT\s*:=\s*3653\b", mf):
            raise RuntimeError("KernelSU Makefile 未锁定 LOCAL_COUNT:=3653。拒绝打包。")

        strings_out = subprocess.run(
            f"strings -a '{image}'",
            shell=True, capture_output=True, text=True,
        ).stdout
        full_ver_hits = re.findall(
            r"v\d+\.\d+\.\d+-[0-9a-fA-F]{7,12}@[A-Za-z0-9._/-]+",
            strings_out,
        )
        # 兼容无 @branch 的短格式
        if not full_ver_hits:
            full_ver_hits = re.findall(r"v\d+\.\d+\.\d+-[0-9a-fA-F]{7,12}", strings_out)
        pin_sha = (self.resolved_sukisu_commit or self.config.effective_kernel_builtin_commit())[:8]
        full_has_pin = any(pin_sha[:7].lower() in v.lower() for v in full_ver_hits)

        # 小端 32-bit 编码（KSU_VERSION 作为 int 常量）
        import struct
        le = struct.pack("<I", want_vc)
        be = struct.pack(">I", want_vc)
        img_bytes = image.read_bytes()
        le_hits = img_bytes.count(le)
        be_hits = img_bytes.count(be)

        ksu_ctx_bad = [
            line for line in strings_out.splitlines()
            if ("SukiSU" in line or "KernelSU" in line)
            and re.search(r"(?:^|[^0-9])37973(?:[^0-9]|$)", line)
        ]
        ascii_want = len(re.findall(rf"(?:^|[^0-9]){re.escape(want_vc_s)}(?:[^0-9]|$)", strings_out))

        logger.info(
            f"Image KSU version 扫描: want={want_vc}, full_ver_hits={full_ver_hits[:5]}, "
            f"full_has_pin={full_has_pin} pin={pin_sha}, "
            f"ascii_hits={ascii_want}, le32_hits={le_hits}, be32_hits={be_hits}, "
            f"bad37973_ctx={len(ksu_ctx_bad)}"
        )
        if ksu_ctx_bad and want_vc != 37973:
            raise RuntimeError(
                "Image 的 SukiSU/KernelSU 上下文字符串含 driver 37973。"
                "FAILED / DO NOT FLASH。\n" + "\n".join(ksu_ctx_bad[:10])
            )

        evidence = []
        if full_ver_hits:
            evidence.append(f"KSU_VERSION_FULL={full_ver_hits[0]}")
        if full_has_pin:
            evidence.append(f"full_version_contains_pin={pin_sha}")
        if ascii_want:
            evidence.append(f"ascii_{want_vc}={ascii_want}")
        if le_hits:
            evidence.append(f"le32_{want_vc}={le_hits}")
        if be_hits:
            evidence.append(f"be32_{want_vc}={be_hits}")
        evidence.append("makefile_LOCAL_COUNT_locked")
        evidence.append(f"expected_ksu_version_code={want_vc}")

        # 通过条件：Makefile 已锁 + (VERSION_FULL 含 pin 或 整数编码命中 或 ASCII 命中)
        if not (full_has_pin or le_hits or be_hits or ascii_want):
            # VERSION_FULL 有时只有 tag@branch 而无 sha；若有 full_ver 且 Makefile 锁对也接受
            if not full_ver_hits:
                raise RuntimeError(
                    f"Image 无法证明 driver versionCode={want_vc}："
                    f"无 KSU_VERSION_FULL、无 ASCII/整数编码证据。拒绝打包。证据={evidence}"
                )
            logger.warning(
                f"未找到 pin sha 于 VERSION_FULL，但存在 full_ver={full_ver_hits[:3]}；"
                "结合 Makefile LOCAL_COUNT 锁定放行。"
            )
            evidence.append("full_version_present_without_pin_match")

        if want_vc != 40838 and self.config.sukisu_mode == "ci":
            logger.warning(f"CI 模式期望通常为 40838，当前 want_vc={want_vc}")
        if want_vc == 37973:
            raise RuntimeError("expected driver 37973 被禁止。FAILED / DO NOT FLASH。")

        logger.info(f"manager/driver versionCode 门禁通过：{want_vc} evidence={evidence}")

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
