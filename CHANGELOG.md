# Changelog

**English** | [简体中文](./CHANGELOG_ZH.md)

All notable changes to **`kiss-shot`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-21 — Transactional Ciphertext Queue v2, Encrypted Job Ledger & Supply-Chain Hardening

### Added
- **Local Encrypted SQLite WAL Job Ledger & Outbox (`kiss_shot/job_ledger.py`)**:
  - Persists cross-restart job lifecycle states (`jobs`), encrypted ciphertext outbox blobs (`outbox` — never storing plaintext prompts or `hf_token`), structured failure records (`failures`), and delivery/burn receipts (`receipts`) with `0600` POSIX permissions.
- **Transactional Mailbox v2 CAS Delivery & Snapshot Verification (`kiss_shot/mailbox_delivery.py` & `notebooks/remote_media_worker.ipynb`)**:
  - Introduced `_queue/v2/` dispatch with HuggingFace `parent_commit` CAS retry (`commit_with_parent_retry` / `enqueue_job_v2`), remote worker lease claiming & renewal heartbeats (`_claims/<job_id>.json`, `_try_claim_job`, `_ClaimHeartbeat`), atomic completion commits (`_finish_job` committing `_inbox/pkt_*.bin` + `_receipts/<job_id>.json` while cleaning `_queue/`/`_claims/`/`_staging/`), revision-locked `blob_id` (Git Blob SHA-1 / LFS SHA-256) download verification, and conditional burning (`burn_packets_conditional`) with accurate `removed_count` / `skipped_paths` reporting.
- **Optional Runtime Dependency Lock & Engine Integrity Verification (`kiss_shot/runtime_lock.py`, `notebooks/remote_llm_gateway.ipynb` & `notebooks/remote_media_worker.ipynb`)**:
  - Added `snapshot("llm" | "studio")` and `verify_runtime_lock(..., strict=False)` (compatibility-first default with strict-mode enforcement on drift or `manifest_sha256` tampering) plus `verified_engine` SHA-256 binary integrity checks and default `127.0.0.1` loopback binding in the remote LLM gateway notebook.
- **Dynamic LoRA Strength Controls & Idempotent Unpacking (`kiss_shot/crypto.py`, `kiss_shot/panel.py` & `notebooks/remote_media_worker.ipynb`)**:
  - Added deterministic `packet_id` idempotent unpacking in `unpack_encrypted_zip` (reusing identical existing files while refusing to overwrite user-modified files via `FileExistsError`), dynamic LoRA loading/scaling/unloading (`_set_lora_strength`), and recipe restoration helpers (`resolve_recipe_restore_values`, `validate_media_batch`, `strip_queue_job_secrets`, `format_burn_report`).

### Security & Fixed
- **Pinned Model Commits, Approved Custom Code & Executable Stripping (`notebooks/remote_media_worker.ipynb`)**:
  - Pinned all 8 preset HuggingFace model repositories to immutable 40-character commit SHAs (`PINNED_MODEL_REVISIONS`), enforced SHA-256 digest checks via `verified_model_file`, restricted custom MOSS pipeline Python code strictly to `APPROVED_MOSS_SOURCES` (`_approved_moss_source`), and stripped executable/script files from downloaded model directories (`_strip_repo_executables`).
- **Selective IPython History Scrubbing & Single-Profile SillyTavern Binding (`notebooks/*.ipynb` & `kiss_shot/local_bridge.py`)**:
  - Replaced blanket history wiping with selective deletion of only `KISSSHOT_`-related sensitive rows (`_scrub_sqlite_history_file`) so unrelated user notebook history is preserved.
  - Hardened `bind_sillytavern_client` to require an explicit single `profile` when multiple profiles exist (refusing bulk overwrites) and automatically save a one-time `settings.before-kiss-shot.json` backup before patching.
- **Architecture & Queue Hygiene Fixes (`notebooks/remote_media_worker.ipynb` & `kiss_shot/panel.py`)**:
  - Preserved `wan_ti2v_5b` in `_job_arch` (with backward compatibility for `wan_ti2v`), stripped `hf_token` from queued ciphertext jobs (falling back to in-memory daemon credentials), and expanded the automated verification suite to `25/25` passing tests without altering the frozen five-domain `kissshot-*` AAD or `KISSSHOT_TICKET` wire contract.

## [1.2.0] - 2026-11-17 — Bidirectional Ciphertext Queue, Local Visual Studio & Full-VRAM Pipeline Suite

### Added
- **Bidirectional Ephemeral Ciphertext Queue (`AAD_QUEUE` · `kiss_shot/crypto.py`, `kiss_shot/panel.py` & `notebooks/remote_media_worker.ipynb`)**:
  - Introduced domain-separated `AAD_QUEUE` (`kissshot-queue-v2`) with 24-hour authenticated TTL envelopes (`encrypt_queue_job` / `decrypt_queue_job`), enabling one-click atomic job dispatch (`_queue/job_*.bin`), remote 1.5s daemon polling (with 90-minute idle auto-stop), automatic background retrieval (`_inbox/pkt_*.bin`), and single-commit burn-after-reading without manual token copy-pasting.
- **Zero-WebUI Local Offline Visual Studio (`kiss_shot/studio_widgets.py` & `kiss_shot/panel.py`)**:
  - **`MaskPainterDialog`**: Local `tkinter + Pillow` semi-transparent brush canvas for `Inpainting` (brush radius slider, 15-step undo stack, mask inversion, right-click eraser), sealing binary PNG masks end-to-end under `AAD_BLOB` (`_staging/mask_*.bin`).
  - **`MossLayoutDialog`**: Interactive centered-origin (`abs_centralized` `yxyx`) bounding-box visual composer for `OpenMOSS-Team/MOSS-Image-SFT` spatial object & bilingual typography layout JSON compilation.
  - **`GallerySidebar` & Encrypted Recipe Vault (`.kissshot_gallery_vault.json`)**: Local thumbnail/video gallery backed by Windows `DPAPI` / POSIX `0600` at-rest encryption for generation recipes (`seed`, `prompt`, `model`, dimensions), supporting one-click Seed/recipe restoration, `Img2Img` / `Inpainting` staging, `I2V` keyframe handoff, and lossless directory migration (`migrate_output_vault`).
- **Custom HuggingFace Repository Auto-Probing & Expanded Presets (`kiss_shot/crypto.py` & `kiss_shot/panel.py`)**:
  - Added neutral open-source presets (`MOSS-Image-SFT`, `HunyuanVideo-1.5 720P T2V`, `Wan 2.2 I2V A14B MoE`) plus an interactive custom `owner/repo` inspector that automatically detects Diffusers `_class_name` architectures or `.gguf` / `mmproj` weights.
- **TorchAO FP8/8-bit Streaming Residency & Tiled 2x Super-Resolution (`notebooks/remote_media_worker.ipynb`)**:
  - Added hardware-probed `TorchAO` `FP8 TensorCore` / `8-bit` streaming VRAM placement and in-memory tiled `RealESRGAN_x2` (`512px` tiles, `32px` feather overlap, `<0.8 GB` peak extra VRAM).

### Fixed
- **Remote Reference Image (`Img2Img` / `Inpainting` / `I2V`) Execution Pipeline (`notebooks/remote_media_worker.ipynb`)**:
  - Wired decrypted `_staging/ref_*.bin` and `_staging/mask_*.bin` inputs end-to-end into `MOSS` Rectified Flow latent blending, `AutoPipelineForImage2Image` / `AutoPipelineForInpainting` Gaussian-feathered compositing, and `WanImageToVideoPipeline` / `CogVideoXImageToVideoPipeline` aspect-aligned video synthesis.
- **Windowless `pythonw.exe` Null Standard Stream Guard (`kiss_shot/panel.py`)**:
  - Redirected `None` `sys.stdout` / `sys.stderr` handles to `os.devnull` and silenced background progress bars so tray-mode `huggingface_hub` transfers never raise `AttributeError` under `pythonw.exe`.

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
