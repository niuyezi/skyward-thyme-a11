# Skyward Recovery — Xiaomi 10S (thyme) Android 11 移植

[English notes at the bottom](#english-notes)

本仓库是 [kirklin/skyward](https://github.com/kirklin/skyward) 向 **小米 10S（thyme，M2102J2SC）** 的移植分支，目标系统为基于 Android 11（MIUI 12.5.3 / ANXIN ROM，SDK 30）的官方包。

上游 Skyward 面向 Android 13+ 的 A/B 动态分区设备（recovery 独立分区、AIDL KeyMint、GKI boot）。thyme 是 Android 11 的 **recovery-in-boot** 设备：没有独立 recovery 分区，recovery 与系统共用 boot 分区，HAL 全部是 HIDL（keymaster@4.0、boot@1.0/1.1、gatekeeper@1.0）。本分支把这些差异逐项补齐。

## 当前状态

| 功能 | 状态 |
| --- | --- |
| 临时启动（`fastboot boot`，免改 misc） | ✅ 可用，基于 TWRP ramdisk 底座 |
| 触摸 / 显示 / 60Hz 刷新 | ✅ 正常（雪花条纹已修复） |
| 时钟避开左上角挖孔 | ✅ `clock_x_dp = 55` |
| 槽位（slot）读取 | ✅ HIDL boot@1.0/1.1 回退 + `ro.boot.slot_suffix` |
| Data 解密 | 🚧 HIDL keymaster@4.0 客户端已实现，待真机验证 |
| Wi-Fi | 🚧 未完成（wlan0 节点 / 驱动加载） |
| 90Hz 刷新率 | ⏸ 按需求暂缓，当前锁定 60Hz |

## 与上游的主要差异

- **binder 头**：`parcel.rs` 的 AIDL 头从 `RECO` 改为 AOSP 标准的 `SYST`，修复 Android 11 上所有 binder 调用返回 `BAD_TYPE (-2147483647)` 的问题。
- **Data 解密**：新增 `skyward-crypto/src/keymaster.rs`，实现 HIDL `android.hardware.keymaster@4.0::IKeymasterDevice` 客户端（plain union KeyParameter 布局），`keymint.rs` 中以 `KeyMint` 枚举统一 AIDL KeyMint（新设备）与 HIDL keymaster（本机）两条路径。
- **槽位读取**：`skyward-vab/src/boot.rs` 支持 HIDL boot@1.0/1.1/1.2，低版本回退读 `ro.boot.slot_suffix`。
- **服务发现**：`skyward-programs/src/secure.rs` 的密钥服务查找同时尝试 AIDL `android.hardware.security.keymint` 与 HIDL `android.hardware.keymaster`，并为 HIDL 场景拉起 hwservicemanager。
- **设备配置**：`devices/thyme.toml` — 60Hz 刷新、时钟右移 55dp 避开挖孔、面板/触摸/背光节点按本机修正。

## 临时启动（推荐用法）

本机没有独立 recovery 分区，直接 `fastboot boot` 官方风格的镜像会被小米 init 的版本校验逻辑带回系统。因此本分支提供 **TWRP 底座 + Skyward** 的临时启动镜像：

```sh
# 手机进入 fastboot 后
fastboot boot skyward-thyme-tempboot.img
```

- 不写任何分区（misc、boot 均不动），重启即恢复原样。
- 底座使用 [BOOT]Mi10S_TWRP3.7.1_A15_thyme 的 init / sepolicy / 用户空间，`system/bin/recovery` 替换为 Skyward 二进制。
- 需要固化时，在临时启动的 Skyward 里操作，或参考 TWRP 的固化流程。

## 构建

本机无 Rust 工具链，使用 GitHub Actions 云端构建（`.github/workflows/`，push 到 master/thyme 自动触发），产物在 Actions Artifacts 下载。

本地重建临时启动镜像（Python，无需 Rust）：

```sh
# 前置：TWRP [BOOT] 镜像 + CI 构建出的 skyward 二进制镜像
python imgcmp/graft.py   # 以 TWRP ramdisk 为底座替换 recovery 并重打包
```

上游完整构建方式见 [kirklin/skyward](https://github.com/kirklin/skyward) 的 README。

## 致谢

- [kirklin/skyward](https://github.com/kirklin/skyward) — 上游项目
- TWRP for thyme — 临时启动底座与 Android 11 HIDL 适配参考

## License

[GPL-3.0-or-later](LICENSE)

---

## English notes

This fork ports [kirklin/skyward](https://github.com/kirklin/skyward) to the **Xiaomi 10S (thyme)** running Android 11 (MIUI 12.5.3 / ANXIN ROM, SDK 30).

thyme is a recovery-in-boot device on Android 11 with HIDL-only HALs (keymaster@4.0, boot@1.0/1.1), unlike the AIDL / dedicated-recovery devices upstream targets. Key changes:

- AIDL binder header fixed to AOSP `SYST` (upstream `RECO` caused `BAD_TYPE` on every call).
- HIDL `keymaster@4.0` client added for data decryption, unified behind a `KeyMint` enum with the AIDL path.
- HIDL boot control fallback (`ro.boot.slot_suffix`) for slot detection.
- Key service discovery tries AIDL keymint first, then HIDL keymaster, and starts hwservicemanager when needed.
- `devices/thyme.toml`: 60 Hz panel, clock shifted 55 dp past the camera hole.

**Temporary boot** (recommended, no partition is written):

```sh
fastboot boot skyward-thyme-tempboot.img
```

The image grafts the Skyward binary onto a TWRP ramdisk base, which avoids Xiaomi's init version-check that otherwise bounces `fastboot boot` back into the system. Build it locally with `imgcmp/graft.py`, or let GitHub Actions build the binary.

Status: temp boot, touch/display/60 Hz, and slot reading work; data decryption (HIDL keymaster) is implemented and pending on-device verification; Wi-Fi is not yet working; 90 Hz is deferred by request.
