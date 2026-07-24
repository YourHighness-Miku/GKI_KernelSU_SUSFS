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


class BuilderMix5:
    def verify_final_config(self):
        """.config 门禁：核对 KPM / BBR / ZRAM-LZ4KD 与开关一致（修复 十/九/八.10 产物侧）。"""
        # bazel: .config 在 bazel-bin 下不稳定，改用 defconfig + 期望值双向核对。
        defconfig = self.work_dir / "common/arch/arm64/configs/gki_defconfig"
        if not defconfig.exists():
            logger.warning(f"defconfig 不存在，跳过 .config 门禁: {defconfig}")
            return
        text = defconfig.read_text(errors="ignore")

        def has(line): return line in text

        problems = []
        # KPM
        if self.config.use_kpm and self.config.kernel_version != "6.6":
            if not has("CONFIG_KPM=y"):
                problems.append("期望 CONFIG_KPM=y 但缺失")
        else:
            if has("CONFIG_KPM=y"):
                problems.append("期望关闭 KPM 但发现 CONFIG_KPM=y")
        # BBR
        if self.config.set_default_bbr:
            for need in ["CONFIG_TCP_CONG_BBR=y", 'CONFIG_DEFAULT_TCP_CONG="bbr"', "CONFIG_TCP_CONG_CUBIC=y"]:
                if not has(need):
                    problems.append(f"期望 {need} 但缺失")
        # ZRAM / LZ4KD
        if self.config.use_zram:
            for need in ["CONFIG_ZRAM=y", "CONFIG_ZSMALLOC=y", "CONFIG_CRYPTO_LZ4KD=y"]:
                if not has(need):
                    problems.append(f"期望 {need} 但缺失")

        if problems:
            raise RuntimeError("defconfig 门禁失败:\n - " + "\n - ".join(problems))
        logger.info("defconfig 门禁通过（KPM/BBR/ZRAM 与开关一致）")

    def verify_final_config_gki_invariants(self):
        """GKI 兼容性不变量门禁：确认小米 14 Ultra(aurora) 需要的基础能力未被破坏。

        这些多来自 ACK gki_defconfig 默认；此处显式核对，防止我们追加的配置意外覆盖/回归。
        KSU 依赖 KPROBES && EXT4_FS，否则 CONFIG_KSU 会静默失效。
        """
        # 用最终生效的 .config（若存在）优先，回退到 defconfig。
        cfg_candidates = [
            self.work_dir / "out" / f"{self.config.android_version}-{self.config.kernel_version}" / ".config",
            self.work_dir / "common" / ".config",
            self.work_dir / "common/arch/arm64/configs/gki_defconfig",
        ]
        cfg = next((c for c in cfg_candidates if c.exists()), None)
        if cfg is None:
            logger.warning("未找到 .config/defconfig，跳过 GKI 不变量门禁")
            return
        text = cfg.read_text(errors="ignore")

        def on(sym):
            return f"{sym}=y" in text

        # KSU 依赖项 + 设备基础能力。SELINUX/EXT4/KPROBES/4K 缺失即拒绝。
        required_y = [
            "CONFIG_KSU",
            "CONFIG_KPROBES",       # KSU 依赖
            "CONFIG_EXT4_FS",       # KSU 依赖
            "CONFIG_ARM64_4K_PAGES",
            "CONFIG_SECURITY_SELINUX",
            "CONFIG_OVERLAY_FS",
        ]
        missing = [s for s in required_y if not on(s)]
        # ZRAM 开启时 SWAP 也应在（zram 作为 swap backend）。
        if self.config.use_zram and not on("CONFIG_SWAP"):
            missing.append("CONFIG_SWAP")
        if missing:
            raise RuntimeError("GKI 不变量门禁失败，缺少: " + ", ".join(missing) +
                               f"（来源: {cfg}）")
        logger.info(f"GKI 不变量门禁通过（KSU/KPROBES/EXT4/4K/SELINUX/OverlayFS，来源 {cfg.name}）")

    def patch_kpm_image(self):
        if not self.config.use_kpm or self.config.kernel_version == "6.6":
            logger.info("未启用 KPM 或 6.6，跳过 KPM 修补")
            return
        logger.info("=== 修补 Image 文件 (KPM) ===")
        self._chdir(self.work_dir)

        image_dir = self._find_image_dir()
        if not image_dir.exists():
            raise RuntimeError(f"KPM: Image 目录不存在: {image_dir}")

        self._chdir(image_dir)
        if not (image_dir / "Image").exists():
            raise RuntimeError(f"KPM: 期望的 Image 不存在: {image_dir/'Image'}")

        # KPM patch 必须成功（修复 八.10 / 八.6）。
        self._run_cmd(f"curl -LSs {KPM_PATCH_URL} -o patch && chmod 777 patch && ./patch", check=True)
        if not (image_dir / "oImage").exists():
            raise RuntimeError("KPM 修补后未生成 oImage，说明 KPM patch 未真正生效，拒绝继续。")
        self._run_cmd("mv oImage Image", check=True)
        logger.info("KPM 修补完成并已替换 Image")

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
                self._run_cmd(f"cp {src} {bootimgs_dir}/ && cp {src} {self.work_dir}/", check=True)

        if (self.work_dir / "Image").exists():
            self._run_cmd("gzip -n -k -f -9 Image", check=True)

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
            kernel_path = bootimgs_dir / kernel_file
            if not kernel_path.exists():
                continue
            cmd = f"$MKBOOTIMG --header_version 4 --kernel {kernel_file} --output {output_file}"
            if has_ramdisk:
                cmd += f" --ramdisk out/ramdisk --os_version 12.0.0 --os_patch_level {self.config.os_patch_level}"
            self._run_cmd(cmd, check=True)
            if not (bootimgs_dir / output_file).exists():
                raise RuntimeError(f"mkbootimg 未生成 {output_file}")
            # 仅在提供签名 key 时做 AVB 签名；否则跳过（boot.img 为附属产物，AK3 为主）。
            if os.environ.get("BOOT_SIGN_KEY_PATH"):
                self._run_cmd(
                    f"$AVBTOOL add_hash_footer --partition_name boot --partition_size $((64 * 1024 * 1024)) "
                    f"--image {output_file} --algorithm SHA256_RSA2048 --key $BOOT_SIGN_KEY_PATH",
                    check=True,
                )
            else:
                logger.warning("未设置 BOOT_SIGN_KEY_PATH，跳过 boot.img AVB 签名（AK3 为主产物）")
            dest = self.work_dir / f"{self.config.android_version}-{self.config.kernel_version}.{self.config.sub_level}-{self.config.os_patch_level}-{output_file}"
            self._run_cmd(f"cp {output_file} {dest}", check=True)
            artifacts.append(str(dest))
