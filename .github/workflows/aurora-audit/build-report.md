# build-report.md — Xiaomi 14 Ultra (aurora) 6.1.138 构建审计报告

分支: `fix/aurora-6.1.138-lz4kd-bbr-ak3`  草稿 PR: #1
本轮范围: 审计并修复构建仓库 + 核验官方镜像 + 产出可静态证明的审计物。
**未操作手机；未 force push；未改 main。**

## A. PR 审计结论：通过（并新增修复）
逐项核对真实源码/工作流，而非仅版本串。关键项：aurora/设备档案、android14/6.1/138、
ACK tag+peeled commit 固定、SukiSU v4.1.3 真实 commit（driver+manager 同源）、
SUSFS 固定真实 commit(修复)、ZRAM-LZ4KD 真源码+补丁+符号、KPM 真门控+oImage 断言、
BBR 编译并默认+cubic 保留、BBG/op8e 关闭、Telegram 关闭(修复)、Release 开启、
AK3 全新目录+单一 raw Image+无 init_boot/boot/apk+解包复验、安全模式 hook 源码级检查。

### 反模式核查（全部未命中）
只改版本串/浮动 main/高 fuzz/关键步骤 check=False/旧缓存复用/manager!=driver/
网页开关不生效/SUSFS 与 Manual hook 混淆/跳过 69_hide_stuff/把 boot 补丁日期当 ACK 分支 —— 均否。

### 本轮新发现并修复（已提交本分支）
1. SUSFS 默认用浮动分支 HEAD → 新增 SUSFS_PIN_COMMIT_BY_BRANCH + effective_susfs_commit()，
   默认固定 090cf407(v2.2.0)，工作流 susfs_commit 可覆盖；_apply_susfs_commit 强校验 HEAD。
2. manager/driver versionCode 可能不一致(40838 vs 40837)：根因 KernelSU Kbuild 用实时 GitHub API
   统计 main 提交数。→ add_kernelsu 把本地 main 指到固定 commit，改写 Kbuild LOCAL_COUNT=本地
   rev-list（关闭实时统计）；manager 侧同样锁定；两边都算 40000+count-2815，driver==manager。
3. 缺 GKI 不变量门禁 → 新增 verify_final_config_gki_invariants()：断言 KSU/KPROBES/EXT4/
   ARM64_4K_PAGES/SELINUX/OVERLAY_FS(+ZRAM 时 SWAP)，缺失即中止。已用官方 stock .config 证明
   这些在 GKI 默认即为 y，门禁防回归。
4. Telegram 默认开启 → 改默认关闭。

## B. 官方镜像核验：通过（真实解析）
详见 version-verification.txt。boot.img=hdr v4 / raw Image / 无 ramdisk / 6.1.138-android14-11 /
ARM64 / 4K；init_boot 无 kernel。SHA-256 已记录。=> AK3 只替换 boot 的 kernel Image。

## C. 正式编译：本轮未在此沙箱执行（诚实说明）
正式 GKI 编译需同步整套 ACK（common-android14-6.1 + prebuilts/clang + bazel + ndk，约数十 GB）
并用 kleaf/bazel + thin-LTO 编译，对本交互沙箱的磁盘/内存/时长风险过高，失败半成品不产出有效 Image。
本仓库的正式构建环境是固定的 GitHub Actions 工作流 .github/workflows/kernel-build.yml（ubuntu-latest
+ 磁盘最大化）。**我没有伪造 .config / Image / APK / 绿色结果。**

### 触发正式编译（workflow_dispatch 输入）
android14 / 6.1 / 138 / 2026-02 / Stable(标准) / kernelsu_commit 留空 / susfs_commit 留空(或 090cf407)
/ use_zram=true / use_kpm=true / BBG=false / supp_op=false / set_defbbr=true / make_release=true
/ send_telegram=false / custom_version 留空

### 正式编译后强制验收（【需正式编译后验证】）
extract-ikconfig 产出 final-config.txt；断言 ARM64_4K_PAGES/KSU/KPM/SUSFS*/SWAP/ZRAM/ZSMALLOC/
CRYPTO_LZ4KD/TCP_CONG_ADVANCED/TCP_CONG_BBR/TCP_CONG_CUBIC/NET_SCH_FQ/DEFAULT_BBR/
DEFAULT_TCP_CONG="bbr"/SELINUX/TUN；Image 版本含 6.1.138（strings+IKCONFIG 双核验）；
manager-commit.txt versionCode == 内核 KSU_VERSION；AK3 zip -T 完整、仅一个 raw Image、
无 boot/init_boot/vendor_boot/vbmeta/dtbo/旧 Image。

## D. 交付物（.github/workflows/aurora-audit/）
stock-boot-kernel.config / stock-vs-final-config.diff / source-manifest.txt / patch-list.txt /
safe-mode-audit.md / zram-lz4kd-audit.md / bbr-audit.md / version-verification.txt / build-report.md /
sha256sums.txt。正式编译产物（Image/AK3 zip/APK/build.log/final-config.txt）由 CI 工作流产出。
