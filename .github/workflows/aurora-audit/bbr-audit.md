# bbr-audit.md — BBR 默认拥塞算法审计

## 1. 官方 stock 现状（来自 boot 内嵌 IKCONFIG）
CONFIG_TCP_CONG_ADVANCED 未设；CONFIG_TCP_CONG_BBR 无；CONFIG_TCP_CONG_CUBIC=y；
CONFIG_DEFAULT_TCP_CONG="cubic"；CONFIG_DEFAULT_BBR 无；CONFIG_NET_SCH_FQ=y。
即官方默认 cubic，未启用 BBR。

## 2. 本构建写入（kb_mix3.configure_kernel，仅当 set_default_bbr=True）
CONFIG_TCP_CONG_ADVANCED=y / CONFIG_TCP_CONG_BBR=y / CONFIG_TCP_CONG_CUBIC=y（保留回退）
CONFIG_NET_SCH_FQ=y / CONFIG_DEFAULT_BBR=y / CONFIG_DEFAULT_TCP_CONG="bbr"。
同时写 choice 选择与显式默认串，保证默认拥塞算法确定为 bbr。

## 3. 门禁（编译前）
verify_final_config(): set_default_bbr 时断言 defconfig 同时含 CONFIG_TCP_CONG_BBR=y、
CONFIG_DEFAULT_TCP_CONG="bbr"、CONFIG_TCP_CONG_CUBIC=y，缺任一即 raise。

## 4. 相对 stock 的差异
| 符号 | stock | 本构建 |
|---|---|---|
| CONFIG_TCP_CONG_ADVANCED | 未设 | y |
| CONFIG_TCP_CONG_BBR | 无 | y |
| CONFIG_TCP_CONG_CUBIC | y | y（保留） |
| CONFIG_NET_SCH_FQ | y | y |
| CONFIG_DEFAULT_BBR | 无 | y |
| CONFIG_DEFAULT_TCP_CONG | "cubic" | "bbr" |

## 结论
BBR 真正编译并设为默认，cubic 保留为回退。运行时以 `sysctl net.ipv4.tcp_congestion_control`=bbr、
`net.core.default_qdisc`=fq 为准（真机项）。【最终 .config 需正式编译后复核】
