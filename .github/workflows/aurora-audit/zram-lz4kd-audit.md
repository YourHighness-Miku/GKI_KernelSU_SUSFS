# zram-lz4kd-audit.md — ZRAM / LZ4KD 真实性审计

目标: 证明 LZ4KD 是真实源码 + 真实 Kconfig 符号，而非仅写开关字符串。

## 1. 补丁与源码来源（真实存在）
仓库 ShirkNeko/SukiSU_patch 确认存在:
- other/zram/zram_patch/6.1/lz4kd.patch
- other/zram/zram_patch/6.1/lz4k_oplus.patch
- 源码: other/zram/lz4k/lib/lz4k/、.../lib/lz4kd/、.../crypto/lz4k.c、.../crypto/lz4kd.c

## 2. 构建器真复制源码并打补丁（失败即中止）
kb_mix3.apply_zram_patches(): 逐一 cp lz4k/lz4kd 的 include/lib/crypto 到 common/，缺失即 raise；
复制后断言 common/crypto/lz4kd.c、common/lib/lz4kd/Makefile 存在；
patch -p1 -F 3 应用 lz4kd.patch 与 lz4k_oplus.patch，check=True，失败即抛错。

## 3. Kconfig 符号真实（由补丁引入）
lz4kd.patch 中出现的 crypto 符号: CONFIG_CRYPTO_842/LZ4/LZ4HC/LZ4K/LZ4KD。
构建器 ZRAM 配置只用这些真实符号 + CONFIG_ZRAM_DEF_COMP_LZ4KD=y、CONFIG_ZRAM_DEF_COMP="lz4kd"。

## 4. 相对官方 stock（数据来自官方 boot 内嵌 IKCONFIG）
| 符号 | stock | 本构建 |
|---|---|---|
| CONFIG_ZRAM | m | y |
| CONFIG_ZSMALLOC | m | y |
| CONFIG_ZRAM_DEF_COMP | "lzo-rle" | "lz4kd" |
| CONFIG_ZRAM_DEF_COMP_LZ4KD | 无 | y |
| CONFIG_CRYPTO_LZ4KD | 无 | y |
| CONFIG_CRYPTO_LZ4K | 无 | y |
| CONFIG_CRYPTO_842 | 未设 | y |
| CONFIG_CRYPTO_LZ4HC | 未设 | y |
| CONFIG_ZRAM_WRITEBACK | 未设 | y |
| CONFIG_SWAP | y | y（保留） |

## 5. 门禁
编译前 verify_final_config(): 断言 CONFIG_ZRAM=y/ZSMALLOC=y/CRYPTO_LZ4KD=y。
编译前 verify_final_config_gki_invariants(): use_zram 时断言 CONFIG_SWAP=y。
编译后 Image 内嵌 IKCONFIG，可复核（需正式编译后验证）。

## 结论
LZ4KD 为真实源码 + 真实 Kconfig 符号 + 真实补丁；运行时以 `cat /sys/block/zram0/comp_algorithm` 为准（真机项）。
