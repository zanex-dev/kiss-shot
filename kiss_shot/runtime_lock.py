# -*- coding: utf-8 -*-
"""
远端推理运行时依赖锁清单快照与校验模块 (kiss_shot/runtime_lock.py)

职责与兼容策略：
- `snapshot("llm" | "studio")`: 为远端 LLM 网关或 Studio 媒体工作节点生成可复现的运行时依赖版本锁清单及 SHA-256 摘要。
- `verify_runtime_lock(..., strict=False)`: 核验当前运行环境与锁清单是否一致；默认兼容无锁清单直接放行
  (`strict=False` 且未提供清单时返回 ok=True)，开启 `strict=True` 时遇缺清单、摘要篡改或版本漂移立即熔断抛错。
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.metadata as importlib_metadata
import json
from pathlib import Path
import platform
import sys
import time
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

RUNTIME_LOCK_SCHEMA = "kissshot-runtime-lock-v1"

RUNTIME_PROFILES: Dict[str, Tuple[str, ...]] = {
    "llm": (
        "cryptography",
        "huggingface_hub",
    ),
    "studio": (
        "cryptography",
        "pyzipper",
        "huggingface_hub",
        "Pillow",
        "numpy",
        "torch",
        "diffusers",
        "transformers",
        "accelerate",
        "peft",
        "spandrel",
        "imageio",
        "sentencepiece",
        "ftfy",
        "hf_transfer",
        "bitsandbytes",
        "torchao",
    ),
}


def _canonical_digest(schema: str, profile: str, packages: Dict[str, Dict[str, Any]]) -> str:
    payload = {
        "schema": schema,
        "profile": profile,
        "packages": {k: packages[k] for k in sorted(packages.keys())},
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _probe_package_version(pkg_name: str) -> Optional[str]:
    candidates = [pkg_name]
    if "_" in pkg_name:
        candidates.append(pkg_name.replace("_", "-"))
    if "-" in pkg_name:
        candidates.append(pkg_name.replace("-", "_"))
    for name in candidates:
        try:
            return importlib_metadata.version(name)
        except importlib_metadata.PackageNotFoundError:
            continue
    return None


def snapshot(
    profile: Literal["llm", "studio"],
    *,
    extra_packages: Optional[Sequence[str]] = None,
    installed_overrides: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Any]:
    """采集指定运行时配置档 (`llm` 或 `studio`) 的依赖版本快照，生成可校验的锁清单字典。"""
    prof = str(profile).strip().lower()
    if prof not in RUNTIME_PROFILES:
        raise ValueError(f"Unsupported runtime lock profile: {profile!r} (expected 'llm' or 'studio')")

    pkg_names: List[str] = list(RUNTIME_PROFILES[prof])
    for extra in extra_packages or ():
        clean = str(extra).strip()
        if clean and clean not in pkg_names:
            pkg_names.append(clean)

    packages: Dict[str, Dict[str, Any]] = {}
    for name in pkg_names:
        if installed_overrides is not None and name in installed_overrides:
            ver = installed_overrides[name]
        else:
            ver = _probe_package_version(name)
        packages[name] = {
            "version": ver or "",
            "installed": bool(ver),
        }

    manifest: Dict[str, Any] = {
        "schema": RUNTIME_LOCK_SCHEMA,
        "profile": prof,
        "created_at": int(time.time()),
        "python": platform.python_version(),
        "platform": sys.platform,
        "packages": packages,
        "manifest_sha256": _canonical_digest(RUNTIME_LOCK_SCHEMA, prof, packages),
    }
    return manifest


def verify_runtime_lock(
    manifest: Optional[Dict[str, Any]] = None,
    *,
    profile: Optional[str] = None,
    strict: bool = False,
    installed_versions: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Any]:
    """
    校验当前运行时环境与锁清单的一致性。
    - 无锁清单且 `strict=False`：兼容放行（`ok=True, mode='unlocked'`）。
    - 无锁清单且 `strict=True`：抛出 `RuntimeError`。
    - 有锁清单时校验 schema、`manifest_sha256`、`profile` 及已锁定包版本。
    """
    if not manifest:
        if strict:
            raise RuntimeError("Missing runtime lock manifest while strict=True")
        return {
            "ok": True,
            "allowed": True,
            "mode": "unlocked",
            "warnings": ["No runtime lock manifest supplied; proceeding in compatibility mode."],
            "missing": [],
            "mismatches": [],
        }

    if not isinstance(manifest, dict):
        raise ValueError("Runtime lock manifest must be a dictionary")

    warnings: List[str] = []
    missing: List[str] = []
    mismatches: List[Dict[str, str]] = []

    schema = str(manifest.get("schema", ""))
    if schema != RUNTIME_LOCK_SCHEMA:
        warnings.append(f"Unexpected schema: {schema!r}")

    m_profile = str(manifest.get("profile", ""))
    if profile and m_profile and m_profile != profile:
        warnings.append(f"Profile mismatch: expected {profile!r}, got {m_profile!r}")

    packages = manifest.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("Runtime lock manifest 'packages' must be a dictionary")

    declared_digest = str(manifest.get("manifest_sha256", "")).strip().lower()
    if declared_digest:
        expected_digest = _canonical_digest(schema, m_profile, packages)
        if not hmac.compare_digest(declared_digest, expected_digest):
            warnings.append("Runtime lock manifest_sha256 integrity check failed")

    for pkg_name, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        if not entry.get("installed", True):
            continue
        locked_ver = str(entry.get("version", "")).strip()
        if not locked_ver:
            continue
        if installed_versions is not None and pkg_name in installed_versions:
            actual_ver = installed_versions[pkg_name]
        else:
            actual_ver = _probe_package_version(pkg_name)
        if not actual_ver:
            missing.append(pkg_name)
        elif actual_ver != locked_ver:
            mismatches.append({"package": pkg_name, "expected": locked_ver, "actual": actual_ver})

    clean = not warnings and not missing and not mismatches
    if not clean and strict:
        details = []
        if warnings:
            details.append("warnings=" + "; ".join(warnings))
        if missing:
            details.append("missing=" + ",".join(missing))
        if mismatches:
            details.append(
                "mismatches=" + ",".join(f"{m['package']}:{m['actual']}!={m['expected']}" for m in mismatches)
            )
        raise RuntimeError(f"Runtime lock verification failed ({'; '.join(details)})")

    return {
        "ok": clean,
        "allowed": True if (clean or not strict) else False,
        "mode": "verified" if clean else "warn",
        "warnings": warnings,
        "missing": missing,
        "mismatches": mismatches,
    }


def save_runtime_lock(path: str | Path, manifest: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_runtime_lock(path: str | Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        return None
    obj = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Runtime lock file does not contain a JSON object")
    return obj
