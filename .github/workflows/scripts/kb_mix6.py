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


class BuilderMix6:
    def create_anykernel_zips(self) -> list:
        logger.info("=== 创建 AnyKernel3 ZIP 文件（隔离打包 + 校验）===")
        self._chdir(self.work_dir)
        artifacts = []

        # 只用未压缩的原始 Image（AK3 gki-2.0 会自行处理）。仅打包本次构建产物。
        image_path = self.work_dir / "Image"
        if not image_path.exists():
            raise RuntimeError(f"AK3: 未找到本次构建的 Image: {image_path}")

        import shutil
        zip_name = (f"{self.config.android_version}-{self.config.kernel_version}."
                    f"{self.config.sub_level}-{self.config.os_patch_level}-AnyKernel3.zip")

        # 每次构建使用全新临时目录，避免上一轮残留污染（修复 八.11 / 十八）。
        stage = self.work_dir / "ak3_stage"
        if stage.exists():
            shutil.rmtree(stage)
        # 从固定的 AK3 模板复制一份干净副本
        shutil.copytree(self.anykernel_dir, stage, symlinks=True,
                        ignore=shutil.ignore_patterns(".git"))

        # 清理模板里任何可能残留的内核镜像 / boot 镜像 / APK / 旧 zip。
        removed = []
        for pat in ["Image", "Image.*", "*.img", "*.apk", "*.zip", "zImage", "oImage"]:
            for p in stage.glob(pat):
                if p.is_file():
                    p.unlink()
                    removed.append(p.name)
        if removed:
            logger.info(f"AK3 模板清理掉的残留文件: {sorted(set(removed))}")

        # 仅放入本次构建的原始 Image。
        shutil.copy2(image_path, stage / "Image")

        # 断言：stage 内 arm64 内核镜像有且仅有一个（就是我们放的 Image）。
        image_like = [p.name for p in stage.iterdir()
                      if p.is_file() and (p.name == "Image" or p.name.startswith("Image.")
                                          or p.name in ("zImage", "oImage") or p.name.endswith(".img"))]
        if image_like != ["Image"]:
            raise RuntimeError(f"AK3 打包前镜像文件不唯一/不正确: {image_like}（应仅为 ['Image']）")

        # 断言：不得混入 APK。
        apks = [p.name for p in stage.rglob("*.apk")]
        if apks:
            raise RuntimeError(f"AK3 包内不应包含 APK: {apks}")

        # 打包（排除 .git），并校验 zip 完整性。
        zip_out = self.work_dir / zip_name
        if zip_out.exists():
            zip_out.unlink()
        self._chdir(stage)
        self._run_cmd(f"zip -r9 '{zip_out}' ./* -x '*.git*'", check=True)
        self._run_cmd(f"zip -T '{zip_out}'", check=True)  # 完整性测试

        # 解包复验：确认 zip 内确有 Image、有 anykernel.sh、无 .img/.apk。
        verify_dir = self.work_dir / "ak3_verify"
        if verify_dir.exists():
            shutil.rmtree(verify_dir)
        verify_dir.mkdir()
        self._chdir(verify_dir)
        self._run_cmd(f"unzip -qq '{zip_out}'", check=True)
        names = [str(p.relative_to(verify_dir)) for p in verify_dir.rglob("*") if p.is_file()]
        if "Image" not in names:
            raise RuntimeError(f"AK3 zip 复验失败：缺少 Image。内容: {names}")
        if not any(n.endswith("anykernel.sh") for n in names):
            raise RuntimeError(f"AK3 zip 复验失败：缺少 anykernel.sh。内容: {names}")
        bad = [n for n in names if n.endswith(".img") or n.endswith(".apk")]
        if bad:
            raise RuntimeError(f"AK3 zip 复验失败：混入了 {bad}")

        # 记录文件清单与 sha256。
        listing = self.work_dir / (zip_name + ".filelist.txt")
        listing.write_text("\n".join(sorted(names)) + "\n")
        sha = subprocess.run(f"sha256sum '{zip_out}'", shell=True, capture_output=True, text=True).stdout.strip()
        (self.work_dir / (zip_name + ".sha256")).write_text(sha + "\n")
        logger.info(f"AK3 打包完成并通过校验: {zip_out}\n{sha}")

        self._chdir(self.work_dir)
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(verify_dir, ignore_errors=True)

        artifacts.append(str(zip_out))
        artifacts.append(str(listing))
        return artifacts

    def write_source_manifest(self) -> list:
        """写出 source-manifest.txt：记录所有固定来源的解析 SHA（修复 八.7 可追溯）。"""
        import json
        pin = self.config.ack_pin() or {}
        manifest = {
            "device": self.config.custom_version or self.config.config_name,
            "android_version": self.config.android_version,
            "kernel_version": f"{self.config.kernel_version}.{self.config.sub_level}",
            "os_patch_level": self.config.os_patch_level,
            "ack_manifest_branch": pin.get("manifest_branch"),
            "ack_tag": pin.get("ack_tag"),
            "ack_commit_expected": pin.get("ack_commit"),
            "sukisu_pin_ref": SUKISU_PIN_REF,
            "sukisu_pin_commit": SUKISU_PIN_COMMIT,
            "sukisu_resolved_commit": self.resolved_sukisu_commit,
            "susfs_commit": self.config.susfs_commit,
            "expected_susfs_version": EXPECTED_SUSFS_VERSION,
            "use_kpm": self.config.use_kpm,
            "use_zram": self.config.use_zram,
            "set_default_bbr": self.config.set_default_bbr,
            "use_bbg": self.config.use_bbg,
        }
        out = self.work_dir / "source-manifest.txt"
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        logger.info("source-manifest.txt:\n" + out.read_text())
        return [str(out)]

    def build(self) -> BuildResult:
        import time
        start_time = time.time()
        logger.info("=" * 50)
        logger.info(f"开始 GKI Kernel 构建 - {self.config.config_name}")
        logger.info("=" * 50)

        try:
            self.clone_repositories()
            self.clone_toolchain()
            self.setup_repo_tool()
            self.init_and_sync_kernel()
            self.add_kernel_supatch()
            self.add_kernelsu()
            self.add_bbg()
            self.apply_susfs_patches()
            self.apply_sukisu_patches()
            self.apply_zram_patches()
            self.apply_task_mmu_fixes()
            self.configure_kernel()
            self.configure_kernel_name()
            self.show_kernel_config()

            # 编译前 defconfig 门禁（KPM/BBR/ZRAM 与开关一致）。
            self.verify_final_config()

            if not self.build_kernel():
                return BuildResult(success=False, config=self.config, message="内核编译失败", build_time=time.time() - start_time)

            # 编译后产物版本门禁（Image 内必须含期望 x.y.z）。
            self.verify_kernel_version()

            self.patch_kpm_image()
            artifacts = []
            artifacts.extend(self.prepare_boot_images())
            artifacts.extend(self.create_anykernel_zips())
            artifacts.extend(self.write_source_manifest())

            build_time = time.time() - start_time
            logger.info(f"构建成功! 耗时: {build_time:.2f} 秒, 生成 {len(artifacts)} 个产物")
            return BuildResult(success=True, config=self.config, message="构建成功", artifacts=artifacts, build_time=build_time)
        except Exception as e:
            logger.error(f"构建过程出错: {e}")
            return BuildResult(success=False, config=self.config, message=str(e), build_time=time.time() - start_time)
