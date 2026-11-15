# 更新日志 (Changelog)

[English](./CHANGELOG.md) | **简体中文**

**`kiss-shot`** 的所有重要版本变更均记录于此文件中。

日志格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本 2.0.0 (SemVer)](https://semver.org/lang/zh-CN/)。

## [1.1.0] - 2026-11-15 — 专属家徽图标、原生系统托盘网桥保活与开始菜单集成

### 新增
- **官方矢量家徽与多尺寸高清图标（`assets/logo.svg` & `assets/app.ico`）**：
  - 绘制与三部曲视觉规格对齐的 `256×256` 黑曜石鎏金绯红矢量标（哥特玫瑰窗 AEAD 密文环 + 鎏金冠冕 + 竖瞳密钥盾芯），并内置 9 档尺寸（`16px`–`256px`）高清透明 `.ico` 图标。
- **零依赖原生 Win32 系统托盘常驻与隧道保活（`kiss_shot/win_tray.py` & `kiss_shot/panel.py`）**：
  - Windows 下点击控制台右上角 `×` 自动转入右下角托盘静默休眠（挂起 UI 轮询实现 `0% CPU` 待机），同时持续保活 `127.0.0.1:18443/v1` 本地 AEAD 加密网桥与剪贴板票据监听，彻底消除误关窗口断连痛点；补齐高分屏 DPI 自适应、单实例前置唤醒、`--minimized` 静默启动与托盘右键快捷菜单（复制端点、拉取阅后即焚信箱、擦除剪贴板、彻底退出）。
- **Windows 开始菜单与任务栏独立身份注册（`kiss-shot shortcut`）**：
  - 绑定显式 `AppUserModelID`（`Trinity.KissShot.Panel`），并基于纯 `ctypes` COM 接口新增 `kiss-shot shortcut [--remove]` 命令，一键注册无黑框 `pythonw.exe` 开始菜单与任务栏可固定快捷方式（`12/12` 安全与脱敏测试全绿）。

## [1.0.0] - 2026-11-15 — 代号：`Kiss-Shot (姬丝秀忒)` · 正式版协议契约冻结

### 正式版晋升与契约锁定
- **晋升 Production/Stable 正式版（`pyproject.toml` & `kiss_shot`）**：
  - 在完成端到端密码学、流式防截断、防压缩炸弹与本地守护进程全量安全验证（`11/11` 自动化测试全绿）后，包成熟度分类正式由 `4 - Beta` 晋升为 `5 - Production/Stable`。
- **AEAD 传输协议与握手契约冻结（Wire Protocol Freeze）**：
  - 正式锁定 `1.x` 周期内的帧封装规范：`PBKDF2-HMAC-SHA256`（`210,000` 次迭代）+ `AES-256-GCM`、四类严格域分离 AAD 上下文（`AAD_PAYLOAD` / `AAD_TICKET` / `AAD_BLOB` / `AAD_ARCHIVE`）、`KISSSHOT_TICKET:...` 握手票据、SSE 流单调递增序号绑定（`kissshot-s2c:<req_id>:<seq>`）及 `EOF:...` 认证结束帧校验。
- **双层 AEAD 阅后即焚密文信箱定型**：
  - 固化面向异步远程 GPU 生图/生视频任务的零压缩 `WZ_AES`（`ZIP_STORED`）+ 外层 `AES-256-GCM`（`AAD_ARCHIVE`）纯内存推理与阅后即焚交付契约。
- **文档与三部曲规范对齐**：
  - 新增中英双语 `CHANGELOG.md` / `CHANGELOG_ZH.md` 并补齐包元数据仓库索引链接，完成 **Kiss-Shot · Acerola-Orion · Heart-Under-Blade** 三位一体安全套件的 `1.x` 正式版体系对齐。

## [0.2.0] - 2026-11-14 — 纵深防御密码学与本地守护进程加固

### 安全加固
- **严格上下文域分离与信封时效校验（`kiss_shot/crypto.py`）**：
  - 强制隔离四类场景的 GCM 附加认证数据（`AAD_PAYLOAD` / `AAD_TICKET` / `AAD_BLOB` / `AAD_ARCHIVE`）并引入 24 小时签发时效（TTL），阻断跨上下文密文替换与陈旧重放。
- **双层 AEAD 归档封装与流式防压缩炸弹（`kiss_shot/crypto.py`）**：
  - 在 `256-bit WinZip AES`（`WZ_AES`、`ZIP_STORED` 无压缩防长度侧信道 + 内层文件名随机混淆）外层再套入 `AES-256-GCM`（`AAD_ARCHIVE`）认证密文信封；解包端强制拒收 `ZIP_DEFLATED` 压缩条目并设 `2 GiB` 熔断上限。
- **远端网关防重放、并发限流与 SSRF 白名单（`kiss_shot/remote_gateway.py`）**：
  - 新增 `±300s` 时钟偏移校验、有界 `ReplayGuard` 请求 ID 去重缓存、`BoundedSemaphore` 并发控制及严格的上游转发路径白名单（`/v1/*`、`/health`）。
- **本地网桥与凭据保险箱加固（`kiss_shot/local_bridge.py`、`kiss_shot/clipboard.py`、`kiss_shot/panel.py`）**：
  - 本地静态凭据采用 Windows `DPAPI`（`CryptProtectData`）或 POSIX `0600` 权限保险箱加密；本地管理接口强制 `X-KissShot-Admin-Token` 鉴权，严格校验 `Host` 与 `Sec-Fetch-Site` 阻断浏览器 DNS Rebinding 与跨站探测，清洗响应头（`X-Content-Type-Options: nosniff`），并为剪贴板口令注入防云同步/防历史记录标记与 90 秒自动擦除机制。

## [0.1.0] - 2026-11-12 — 初始版本发布

### 新增
- **透明兼容 OpenAI `/v1` 的流式 E2EE 网桥（`kiss_shot/local_bridge.py` & `kiss_shot/remote_gateway.py`）**：
  - 提供本地 `127.0.0.1:18443/v1` 环回入口与远端一次性动态随机路由（`/v1/ks-<random>`），对请求载荷与 SSE 流式响应逐帧执行 `AES-256-GCM` 认证加密。
- **纯内存阅后即焚 GPU 推理节点脚本（`notebooks/`）**：
  - 提供开箱即用的远程 GPU 加密 LLM 网关与纯内存（`BytesIO` / `/dev/shm`）生图/生视频密文信箱 Worker Notebook。
- **桌面控制台与自动化安全验证套件（`kiss_shot/panel.py` & `tests/test_e2ee_suite.py`）**：
  - 内置原生 `tkinter` 管理面板、CLI 命令入口与 GitHub Actions CI 端到端测试套件。
