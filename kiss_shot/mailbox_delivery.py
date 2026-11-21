# -*- coding: utf-8 -*-
"""
密文信箱 v2 条件提交与快照摘要校验模块 (kiss_shot/mailbox_delivery.py)

职责与一致性保障：
- 统一管理 `_queue/v2/` 队列路径命名、向后兼容 `_queue/job_*.bin` 旧路径识别与 `_claims/` / `_receipts/` 协同路径。
- 基于 HuggingFace Hub `parent_commit` 乐观并发控制 (CAS) 执行条件提交，遇 412 Precondition Failed 时自动刷新基线并重试。
- 拉取 `_inbox/` 加密分片时锁定 `packet_revision` 仓库提交号并逐片校验 `blob_id`（Git Blob SHA-1 或 LFS SHA-256），
  防列举与下载之间的 TOCTOU 掉包，并仅在当前仓库版本中精确删除已验证分片、如实回报移除数量。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import inspect
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from huggingface_hub import CommitOperationAdd, CommitOperationDelete, hf_hub_download

QUEUE_V2_PREFIX = "_queue/v2/"
INBOX_PREFIX = "_inbox/"
CLAIMS_PREFIX = "_claims/"
RECEIPTS_PREFIX = "_receipts/"
STAGING_PREFIX = "_staging/"

SAFE_QUEUE_V2_RE = re.compile(r"^_queue/v2/job_[0-9]{9,13}_[A-Za-z0-9_-]{6,48}\.bin$")
SAFE_QUEUE_LEGACY_RE = re.compile(r"^_queue/job_[0-9]{9,13}_[0-9a-f]{8}\.bin$")
SAFE_INBOX_RE = re.compile(r"^_inbox/pkt_[0-9]{9,13}_[A-Za-z0-9_-]{6,48}\.bin$")
SAFE_STAGING_RE = re.compile(r"^_staging/(?:ref|mask)_[0-9a-f]{12}\.bin$")
SAFE_CLAIM_RE = re.compile(r"^_claims/[A-Za-z0-9_-]{6,64}\.json$")
SAFE_RECEIPT_RE = re.compile(r"^_receipts/[A-Za-z0-9_-]{6,64}\.json$")


@dataclass(frozen=True)
class MailboxPacketInfo:
    path: str
    blob_id: str = ""
    size: int = 0
    revision: Optional[str] = None


def make_queue_v2_path(job_id: str, ts: Optional[int] = None) -> str:
    clean_id = re.sub(r"[^A-Za-z0-9_-]", "", job_id or "")[:48]
    if len(clean_id) < 6:
        raise ValueError(f"Invalid job_id for _queue/v2 path: {job_id!r}")
    stamp = int(time.time()) if ts is None else int(ts)
    rel = f"{QUEUE_V2_PREFIX}job_{stamp}_{clean_id}.bin"
    if not SAFE_QUEUE_V2_RE.fullmatch(rel):
        raise ValueError(f"Generated unsafe queue v2 path: {rel!r}")
    return rel


def is_queue_job_path(path: str) -> bool:
    return bool(SAFE_QUEUE_V2_RE.fullmatch(path) or SAFE_QUEUE_LEGACY_RE.fullmatch(path))


def extract_job_id_from_queue_path(path: str) -> str:
    base = os.path.basename(path)
    if base.startswith("job_") and base.endswith(".bin"):
        parts = base[:-4].split("_", 2)
        if len(parts) == 3 and parts[2]:
            return parts[2]
    return re.sub(r"[^A-Za-z0-9_-]", "", os.path.splitext(base)[0])[:48]


def compute_git_blob_id(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def compute_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_packet_blob_id(data: bytes, expected_blob_id: str) -> bool:
    """校验下载的密文分片字节流是否与仓库树记录的 Git Blob SHA-1 或 LFS SHA-256 一致。"""
    exp = (expected_blob_id or "").strip().lower()
    if not exp:
        return True
    if len(exp) == 64 and all(c in "0123456789abcdef" for c in exp):
        return hmac.compare_digest(compute_sha256_hex(data), exp)
    if len(exp) == 40 and all(c in "0123456789abcdef" for c in exp):
        return hmac.compare_digest(compute_git_blob_id(data), exp)
    return False


def _is_parent_conflict(exc: Exception) -> bool:
    resp = getattr(exc, "response", None)
    status = getattr(resp, "status_code", None)
    if status in (409, 412):
        return True
    msg = str(exc).lower()
    return any(tok in msg for tok in ("412", "precondition failed", "parent_commit", "outdated", "conflict"))


def get_repo_head_sha(api: Any, repo_id: str, repo_type: str = "model") -> Optional[str]:
    if not hasattr(api, "repo_info"):
        return None
    info = api.repo_info(repo_id=repo_id, repo_type=repo_type)
    sha = getattr(info, "sha", None)
    if sha is None and isinstance(info, dict):
        sha = info.get("sha")
    return str(sha).strip() if sha else None


def _call_create_commit(
    api: Any,
    *,
    repo_id: str,
    repo_type: str,
    operations: Sequence[Any],
    commit_message: str,
    parent_commit: Optional[str],
) -> Any:
    kwargs: Dict[str, Any] = {
        "repo_id": repo_id,
        "repo_type": repo_type,
        "operations": list(operations),
        "commit_message": commit_message,
    }
    if parent_commit:
        try:
            sig = inspect.signature(api.create_commit)
            if "parent_commit" in sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            ):
                kwargs["parent_commit"] = parent_commit
        except (TypeError, ValueError):
            kwargs["parent_commit"] = parent_commit
    return api.create_commit(**kwargs)


def commit_with_parent_retry(
    api: Any,
    repo_id: str,
    operations: Sequence[Any],
    commit_message: str,
    *,
    parent_commit: Optional[str] = None,
    max_retries: int = 3,
    repo_type: str = "model",
    on_conflict: Optional[Callable[[int, Optional[str]], Optional[Sequence[Any]]]] = None,
) -> Dict[str, Any]:
    """基于 `parent_commit` 执行条件提交，发生并发版本冲突时自动刷新 HEAD 并重试。"""
    current_ops: List[Any] = list(operations)
    if not current_ops:
        return {"committed": False, "commit_oid": "", "parent_commit": parent_commit or ""}

    head_sha = parent_commit or get_repo_head_sha(api, repo_id, repo_type=repo_type)
    last_exc: Optional[Exception] = None

    for attempt in range(max(1, int(max_retries))):
        try:
            info = _call_create_commit(
                api,
                repo_id=repo_id,
                repo_type=repo_type,
                operations=current_ops,
                commit_message=commit_message,
                parent_commit=head_sha,
            )
            oid = getattr(info, "oid", None)
            if oid is None and isinstance(info, dict):
                oid = info.get("oid", "")
            return {
                "committed": True,
                "commit_oid": str(oid or ""),
                "parent_commit": head_sha or "",
                "attempts": attempt + 1,
            }
        except Exception as exc:
            last_exc = exc
            if not _is_parent_conflict(exc) or attempt + 1 >= max(1, int(max_retries)):
                raise
            head_sha = get_repo_head_sha(api, repo_id, repo_type=repo_type)
            if on_conflict is not None:
                rebuilt = on_conflict(attempt + 1, head_sha)
                if rebuilt is None:
                    return {
                        "committed": False,
                        "commit_oid": "",
                        "parent_commit": head_sha or "",
                        "attempts": attempt + 1,
                    }
                current_ops = list(rebuilt)
                if not current_ops:
                    return {
                        "committed": False,
                        "commit_oid": "",
                        "parent_commit": head_sha or "",
                        "attempts": attempt + 1,
                    }

    if last_exc is not None:
        raise last_exc
    return {"committed": False, "commit_oid": "", "parent_commit": head_sha or ""}


def enqueue_job_v2(
    api: Any,
    repo_id: str,
    job_rel: str,
    job_bytes: bytes,
    staging_ops: Optional[Sequence[Any]] = None,
    *,
    parent_commit: Optional[str] = None,
    max_retries: int = 3,
    repo_type: str = "model",
) -> Dict[str, Any]:
    """原子向 `_queue/v2/` 条件提交加密任务及其加密暂存附件。"""
    if not SAFE_QUEUE_V2_RE.fullmatch(job_rel):
        raise ValueError(f"Queue v2 path failed validation: {job_rel!r}")
    ops: List[Any] = list(staging_ops or ())
    ops.append(CommitOperationAdd(path_in_repo=job_rel, path_or_fileobj=job_bytes))
    res = commit_with_parent_retry(
        api,
        repo_id=repo_id,
        operations=ops,
        commit_message="enqueue kissshot v2 job",
        parent_commit=parent_commit,
        max_retries=max_retries,
        repo_type=repo_type,
    )
    res["job_rel"] = job_rel
    return res


def _extract_entry_blob_id(entry: Any) -> Tuple[str, int]:
    lfs = getattr(entry, "lfs", None)
    if lfs is None and isinstance(entry, dict):
        lfs = entry.get("lfs")
    if lfs:
        sha256 = getattr(lfs, "sha256", None)
        if sha256 is None and isinstance(lfs, dict):
            sha256 = lfs.get("sha256")
        if sha256:
            sz = getattr(lfs, "size", 0) if not isinstance(lfs, dict) else lfs.get("size", 0)
            return str(sha256).strip().lower(), int(sz or 0)
    blob_id = getattr(entry, "blob_id", None)
    if blob_id is None and isinstance(entry, dict):
        blob_id = entry.get("blob_id")
    sz = getattr(entry, "size", 0) if not isinstance(entry, dict) else entry.get("size", 0)
    return str(blob_id or "").strip().lower(), int(sz or 0)


def list_inbox_packets_with_revision(
    api: Any,
    repo_id: str,
    *,
    repo_type: str = "model",
) -> Tuple[Optional[str], List[MailboxPacketInfo]]:
    """锁定当前仓库 `packet_revision` 提交号并列举 `_inbox/*.bin` 及其 `blob_id`。"""
    revision = get_repo_head_sha(api, repo_id, repo_type=repo_type)
    packets: List[MailboxPacketInfo] = []

    if hasattr(api, "list_repo_tree"):
        try:
            tree_kwargs: Dict[str, Any] = {
                "repo_id": repo_id,
                "path_in_repo": "_inbox",
                "repo_type": repo_type,
            }
            if revision:
                tree_kwargs["revision"] = revision
            entries = list(api.list_repo_tree(**tree_kwargs))
            for entry in entries:
                path = getattr(entry, "path", None)
                if path is None and isinstance(entry, dict):
                    path = entry.get("path")
                path_s = str(path or "")
                if path_s.startswith(INBOX_PREFIX) and path_s.endswith(".bin"):
                    blob_id, sz = _extract_entry_blob_id(entry)
                    packets.append(MailboxPacketInfo(path=path_s, blob_id=blob_id, size=sz, revision=revision))
            packets.sort(key=lambda p: p.path)
            return revision, packets
        except Exception as exc:
            msg = str(exc).lower()
            if "404" in msg or "not found" in msg or "does not exist" in msg:
                return revision, []
            # Fallback to list_repo_files if custom mock doesn't support path_in_repo/revision

    if hasattr(api, "list_repo_files"):
        rf_kwargs: Dict[str, Any] = {"repo_id": repo_id, "repo_type": repo_type}
        if revision:
            try:
                sig = inspect.signature(api.list_repo_files)
                if "revision" in sig.parameters:
                    rf_kwargs["revision"] = revision
            except (TypeError, ValueError):
                pass
        files = list(api.list_repo_files(**rf_kwargs))
        for f in sorted(files):
            if f.startswith(INBOX_PREFIX) and f.endswith(".bin"):
                packets.append(MailboxPacketInfo(path=f, blob_id="", size=0, revision=revision))
    return revision, packets


def download_verified_packet(
    repo_id: str,
    packet: MailboxPacketInfo,
    *,
    token: str,
    local_dir: str,
    repo_type: str = "model",
    downloader: Optional[Callable[..., str]] = None,
) -> bytes:
    """按锁定的 `packet_revision` 下载分片并强校验 `blob_id`，防列举与下载之间的内容掉包。"""
    dl = downloader or hf_hub_download
    dl_kwargs: Dict[str, Any] = {
        "repo_id": repo_id,
        "filename": packet.path,
        "repo_type": repo_type,
        "token": token,
        "local_dir": local_dir,
    }
    if packet.revision:
        dl_kwargs["revision"] = packet.revision
    local_path = dl(**dl_kwargs)
    with open(local_path, "rb") as f:
        raw = f.read()
    if packet.blob_id and not verify_packet_blob_id(raw, packet.blob_id):
        raise ValueError(
            f"Packet blob_id verification failed for {packet.path} "
            f"(revision={packet.revision or 'HEAD'}, expected={packet.blob_id[:12]}...)"
        )
    return raw


def burn_packets_conditional(
    api: Any,
    repo_id: str,
    packets: Sequence[MailboxPacketInfo],
    *,
    parent_commit: Optional[str] = None,
    max_retries: int = 3,
    repo_type: str = "model",
) -> Dict[str, Any]:
    """
    以条件提交方式精确销毁当前仓库版本中已验证的密文分片，绝不误删被更新覆盖的新分片；
    返回值如实汇报在当前仓库版本中实际移除的分片数 (`removed_count`)。
    """
    target_map: Dict[str, str] = {p.path: p.blob_id for p in packets}
    if not target_map:
        return {"removed_count": 0, "removed_paths": [], "skipped_paths": [], "commit_oid": ""}

    def _filter_present_ops() -> Tuple[Optional[str], List[str], List[str]]:
        rev, live_packets = list_inbox_packets_with_revision(api, repo_id, repo_type=repo_type)
        live_map = {p.path: p.blob_id for p in live_packets}
        to_delete: List[str] = []
        skipped: List[str] = []
        for path, exp_blob in target_map.items():
            if path not in live_map:
                skipped.append(path)
                continue
            live_blob = live_map[path]
            if exp_blob and live_blob and live_blob != exp_blob:
                skipped.append(path)
                continue
            to_delete.append(path)
        return rev, to_delete, skipped

    active_delete = list(target_map.keys())
    skipped_paths: List[str] = []

    def _on_conflict(_attempt: int, _new_head: Optional[str]) -> Optional[Sequence[Any]]:
        nonlocal active_delete, skipped_paths
        _rev, live_del, live_skip = _filter_present_ops()
        active_delete = live_del
        skipped_paths = live_skip
        if not active_delete:
            return None
        return [CommitOperationDelete(path_in_repo=p) for p in active_delete]

    init_ops = [CommitOperationDelete(path_in_repo=p) for p in active_delete]
    res = commit_with_parent_retry(
        api,
        repo_id=repo_id,
        operations=init_ops,
        commit_message="burn verified kissshot artifacts",
        parent_commit=parent_commit,
        max_retries=max_retries,
        repo_type=repo_type,
        on_conflict=_on_conflict,
    )
    if res.get("committed"):
        return {
            "removed_count": len(active_delete),
            "removed_paths": list(active_delete),
            "skipped_paths": list(skipped_paths),
            "commit_oid": res.get("commit_oid", ""),
        }
    return {
        "removed_count": 0,
        "removed_paths": [],
        "skipped_paths": list(target_map.keys()),
        "commit_oid": "",
    }
