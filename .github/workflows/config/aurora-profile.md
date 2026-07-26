# Aurora (Xiaomi 14 Ultra 国行) 构建参数档案

设备 = aurora / aurorapro / 24031PN0DC，基于官方 boot.img + init_boot.img 解析（见 audit/）。

## 运行 kernel-build.yml 的推荐输入

| 输入 | 值 | 依据 |
|------|----|------|
| android_version | android14 | 指纹 aurora:14 / boot header OS 14 |
| kernel_version | 6.1 | 内核 6.1.138 |
| sub_level | 138 | Makefile SUBLEVEL == 138（ACK tag android14-6.1.138_r00） |
| os_patch_level | 2026-02 | boot header / AVB security_patch 2026-02-01（仅元数据） |
| kernelsu_version | Stable(标准) | — |
| kernelsu_commit | （留空） | 本仓库固定 SukiSU builtin@b1d534bc（含 KSU_SUSFS），忽略此项 |
| susfs_commit | （留空或指定 v2.2.0 commit） | 门禁读 susfs.h 校验 == v2.2.0 |
| custom_version | aurora | 便于产物命名与 manifest |
| use_zram | true | LZ4KD 默认压缩（内置） |
| use_kpm | true | 现在是真开关 |
| BBG | false | 见 baseband-guard-aurora-compatibility.md（会挡 modem/固件 OTA） |
| supp_op | false | 禁止 OnePlus 设备代码 |
| set_defbbr | true | BBR 设为默认（保留 cubic 回退） |
| make_release | true | 出 Release |
| send_telegram | false | 无 secrets 时避免失败 |

## 固定来源（由 config.py 强制）
- ACK: manifest common-android14-6.1 + tag android14-6.1.138_r00 (4894546596ee3a4b96d9f2157de0d197826cabc0)
- SukiSU-Ultra: builtin (b1d534bc41941b2c818d7a1a1dac341e4aabfc2d)  —— 含 KSU_SUSFS；驱动固定 commit（manager APK 可选）
- SUSFS: v2.2.0（读实际 susfs.h 校验）
- BBG: 若开启则固定 1c664957da7539de860503940ee73c7447f1dfaf

## 产物（AK3 主）
- `android14-6.1.138-2026-02-AnyKernel3.zip`（仅替换 boot 分区里的原始 ARM64 Image）
- 附：boot.img 变体、SukiSU 管理器 APK（同源）、source-manifest.txt、SHA256SUMS.txt、构建日志
- init_boot 不修改、不打包，仅作官方回滚备份

## 刷入策略（供用户，本轮不执行）
- 仅刷 AK3（替换 boot 内核）。init_boot 保持官方。
- 保留官方 boot.img/init_boot.img 作回滚。
