# Changelog

**English** | [简体中文](./CHANGELOG_ZH.md)

All notable changes to **`kiss-shot`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-15 — Crest Artwork, Native System Tray Bridge Keep-Alive & Start Menu Integration

### Added
- **Official Vector Crest & Multi-Size Desktop Icon (`assets/logo.svg` & `assets/app.ico`)**:
  - Designed the official `256×256` Obsidian/Gold/Crimson **Kiss-Shot** crest (`logo.svg`) and bundled a 9-scale (`16px`–`256px`) RGBA `.ico` icon aligned with the Trinity visual family.
- **Zero-Dependency Win32 System Tray Bridge Keep-Alive (`kiss_shot/win_tray.py` & `kiss_shot/panel.py`)**:
  - Closing the desktop GUI (`×`) on Windows now minimizes cleanly into the system tray (`0%` idle UI CPU) while keeping the `127.0.0.1:18443/v1` AEAD bridge and clipboard ticket watcher continuously online; added `--minimized` startup flag, High-DPI scaling, cross-instance foreground wakeup, and right-click tray actions (copy endpoint, pull & burn mailbox, scrub clipboard, exit).
- **Windows Start Menu & Taskbar AppUserModelID Registration (`kiss-shot shortcut`)**:
  - Bound `SetCurrentProcessExplicitAppUserModelID` (`Trinity.KissShot.Panel`) and added pure-`ctypes` COM (`IShellLinkW` + `IPropertyStore` `PKEY_AppUserModel_ID`) `kiss-shot shortcut [--remove]` command for console-free `pythonw.exe` Start Menu & Taskbar pinning (`12/12` automated security & hygiene tests passing).

## [1.0.0] - 2026-11-15 — Codename: `Kiss-Shot (姬丝秀忒)` · Stable Protocol Freeze

### Changed & Promoted
- **Production/Stable Promotion (`pyproject.toml` & `kiss_shot`)**:
  - Promoted package maturity classifier from `4 - Beta` to `5 - Production/Stable` following complete end-to-end cryptographic, streaming truncation, and local daemon security verification (`11/11` automated test scenarios passing).
- **AEAD Wire Protocol & Handshake Contract Freeze**:
  - Frozen the `1.x` wire envelope specification across `PBKDF2-HMAC-SHA256` (`210,000` iterations) + `AES-256-GCM`, strict domain-separated AAD contexts (`AAD_PAYLOAD`, `AAD_TICKET`, `AAD_BLOB`, `AAD_ARCHIVE`), `KISSSHOT_TICKET:...` handshake tokens, monotonic SSE chunk sequence binding (`kissshot-s2c:<req_id>:<seq>`), and authenticated `EOF:...` stream termination tags.
- **Double-AEAD Ephemeral Mailbox Baseline**:
  - Stabilized the zero-compression `WZ_AES` (`ZIP_STORED`) + outer `AES-256-GCM` (`AAD_ARCHIVE`) burn-on-read ciphertext mailbox contract for asynchronous remote GPU media generation.
- **Documentation & Release Metadata**:
  - Added bilingual `CHANGELOG.md` / `CHANGELOG_ZH.md` and canonical repository metadata URLs, aligning release governance across the **Kiss-Shot · Acerola-Orion · Heart-Under-Blade** security suite.

## [0.2.0] - 2026-11-14 — Deep-Defense Cryptographic & Daemon Hardening

### Security & Hardened
- **Strict Context Domain Separation & Envelope TTL (`kiss_shot/crypto.py`)**:
  - Enforced domain-separated Additional Authenticated Data (`AAD_PAYLOAD`, `AAD_TICKET`, `AAD_BLOB`, `AAD_ARCHIVE`) and 24-hour authenticated envelope TTL checks to prevent cross-context ciphertext substitution and stale replay.
- **Double-AEAD Archive Wrapping & Anti-Decompression-Bomb Guard (`kiss_shot/crypto.py`)**:
  - Wrapped `256-bit WinZip AES` (`WZ_AES`, `ZIP_STORED` zero-compression with obfuscated inner entry names) inside an outer `AES-256-GCM` (`AAD_ARCHIVE`) envelope; enforced streaming rejection of `ZIP_DEFLATED` entries and a strict `2 GiB` extraction fuse.
- **Remote Gateway Replay, Concurrency & SSRF Protections (`kiss_shot/remote_gateway.py`)**:
  - Added `±300s` clock-skew validation, bounded `ReplayGuard` request-ID deduplication, `BoundedSemaphore` concurrency throttling, and strict upstream path allowlisting (`/v1/*`, `/health`).
- **Local Bridge & Credential Vault Hardening (`kiss_shot/local_bridge.py`, `kiss_shot/clipboard.py`, `kiss_shot/panel.py`)**:
  - Added at-rest secret protection via Windows `DPAPI` (`CryptProtectData`) and POSIX `0600` vaults, `X-KissShot-Admin-Token` IPC authentication, `Host` / `Sec-Fetch-Site` browser DNS-Rebinding & cross-site request blocking, `X-Content-Type-Options: nosniff` MIME sanitization, and Windows Clipboard cloud-sync/history exclusion flags with 90-second auto-scrubbing.

## [0.1.0] - 2026-11-12 — Initial Release

### Added
- **Streaming OpenAI-Compatible E2EE Bridge (`kiss_shot/local_bridge.py` & `kiss_shot/remote_gateway.py`)**:
  - Local `127.0.0.1:18443/v1` proxy and remote ephemeral route (`/v1/ks-<random>`) sealing HTTP requests and SSE token streams end-to-end with `AES-256-GCM`.
- **In-Memory Burn-After-Reading GPU Media Worker (`notebooks/`)**:
  - Ready-to-run remote GPU notebooks for encrypted LLM gateways and pure-memory (`BytesIO` / `/dev/shm`) Diffusion/Video ciphertext mailbox workers.
- **Desktop Control Panel & Automated Security Test Suite (`kiss_shot/panel.py` & `tests/test_e2ee_suite.py`)**:
  - Native `tkinter` management UI, CLI entrypoints, and GitHub Actions CI verification suite.
