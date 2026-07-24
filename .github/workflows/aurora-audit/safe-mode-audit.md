# safe-mode-audit.md — SukiSU-Ultra 安全模式 / Hook 源码审计

对象: SukiSU-Ultra 固定 commit `0ca744a88835144c58d8256ebb32c279edabfcde`（tag v4.1.3）
方法: 检出该 commit 后逐文件静态审计 `kernel/`。这是**内核驱动与管理器 APK 的同一来源 commit**。

## 1. isSafeMode 不是永远 false —— 通过
`ksu_is_safe_mode()`（kernel/runtime/ksud_integration.c）返回值由真实的音量减按键计数
(`volumedown_pressed_count`) 决定，未被硬编码为 false；`is_volumedown_enough()` 达阈值才置真。

## 2. 开机早期音量减救砖保留 —— 通过
输入回调对 `KEY_VOLUMEDOWN` 累加计数，早期启动阶段有效，按满阈值进入安全模式（禁用模块）。

## 3. post-fs-data 后注销安全模式音量监听 —— 通过
`on_post_fs_data()`（kernel/runtime/boot_event.c）调用 `ksu_stop_input_hook_runtime()`，
经 `schedule_work(&stop_input_hook_work)` 异步执行 `do_stop_input_hook()` 注销输入 hook。
另外在音量减达阈值处与 `ksu_is_safe_mode()` 入口也会提前停用。
=> post-fs-data 完成后安全模式的音量监听被注销，不长期占用输入子系统。

## 4. 单一有效 Hook 方案 —— 通过
采用内建 syscall/tracepoint hook（kernel/hook/：tp_marker.c、syscall_hook_manager.c、
setuid_hook.c、lsm_hook.c）。defconfig 设 `CONFIG_KSU_SUSFS_SUS_SU=n`（不启用 SUSFS sus_su）。
只有一套有效内核 hook 在工作，未把 SUSFS Inline Hook 与 KernelSU Manual Hook 混用。

## 5. 未删除 SUSFS Inline Hook —— 通过
SUSFS 由 `50_add_susfs_in_gki-android14-6.1.patch`（v2.2.0）注入，应用后扫描 `.rej`，失败即中止；
defconfig 启用整套 `CONFIG_KSU_SUSFS_*`。未见任何移除/短路 SUSFS hook 的改动。

## 6. 需刷入后真机验证（静态无法完全证明）
- 实际按音量减进入/退出安全模式；
- post-fs-data 之后输入 hook 确已释放（dmesg 观察）；
- 安全模式下模块被禁用、正常模式下 SUSFS 隐藏生效；
- 管理器 APK 与内核驱动握手、版本号一致。

## 总结
固定 commit `0ca744a8`(v4.1.3) 上安全模式与 hook 生命周期设计正确。运行时正确性以上表【需刷入后验证】项为准。
