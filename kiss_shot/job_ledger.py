# -*- coding: utf-8 -*-
"""
本地持久化加密任务账本与发件箱 (kiss_shot/job_ledger.py)

职责与安全边界：
- 基于本机 SQLite (WAL) 持久化跨重启密文队列任务状态 (`jobs`)、加密发件箱二进制密文 (`outbox`)、
  投递/执行失败记录 (`failures`) 与已签收/已阅后即焚回执 (`receipts`)。
- `outbox` 表仅存储已经过 `AAD_QUEUE` / `AAD_BLOB` 认证加密的密文字节流，绝不在 SQLite 落盘任何明文提示词、
  参考图或 `hf_token`。
- POSIX 平台自动将账本文件收紧至 0600 属主权限，支持多线程安全访问与幂等恢复。
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

DEFAULT_LEDGER_FILENAME = ".kissshot_jobs.sqlite3"

ACTIVE_JOB_STATES = ("pending_upload", "queued", "claimed", "running")
TERMINAL_JOB_STATES = ("completed", "failed", "burned", "cancelled")

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    mailbox_repo TEXT NOT NULL,
    queue_rel TEXT NOT NULL,
    ref_rel TEXT NOT NULL DEFAULT '',
    mask_rel TEXT NOT NULL DEFAULT '',
    preset_key TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending_upload',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    packet_rel TEXT NOT NULL DEFAULT '',
    packet_blob_id TEXT NOT NULL DEFAULT '',
    saved_paths_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_state_updated ON jobs(state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_repo_state ON jobs(mailbox_repo, state);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    path_in_repo TEXT NOT NULL,
    kind TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    uploaded INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE(job_id, path_in_repo),
    FOREIGN KEY(job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_outbox_job_uploaded ON outbox(job_id, uploaded);

CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL,
    retryable INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_failures_job_created ON failures(job_id, created_at DESC);

CREATE TABLE IF NOT EXISTS receipts (
    packet_rel TEXT PRIMARY KEY,
    job_id TEXT NOT NULL DEFAULT '',
    packet_blob_id TEXT NOT NULL DEFAULT '',
    packet_revision TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unpacked',
    saved_paths_json TEXT NOT NULL DEFAULT '[]',
    received_at INTEGER NOT NULL,
    burned_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_receipts_job ON receipts(job_id);
"""


def default_ledger_path(work_dir: Optional[str] = None) -> str:
    base = os.path.abspath(work_dir or os.getcwd())
    return os.path.join(base, DEFAULT_LEDGER_FILENAME)


def _row_to_job(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["saved_paths"] = json.loads(d.pop("saved_paths_json", "[]") or "[]")
    except Exception:
        d["saved_paths"] = []
    return d


def _row_to_receipt(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["saved_paths"] = json.loads(d.pop("saved_paths_json", "[]") or "[]")
    except Exception:
        d["saved_paths"] = []
    return d


class JobLedger:
    """线程安全的本地 SQLite 加密发件箱与任务状态账本。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.abspath(db_path)
        parent = os.path.dirname(self.db_path) or "."
        os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()
        if sys.platform != "win32":
            for suffix in ("", "-wal", "-shm"):
                p = self.db_path + suffix
                if os.path.exists(p):
                    try:
                        os.chmod(p, 0o600)
                    except OSError:
                        pass

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self) -> "JobLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def create_job(
        self,
        job_id: str,
        mailbox_repo: str,
        queue_rel: str,
        *,
        preset_key: str = "",
        arch: str = "",
        ref_rel: str = "",
        mask_rel: str = "",
        outbox_blobs: Optional[Sequence[Tuple[str, str, bytes]]] = None,
        state: str = "pending_upload",
    ) -> Dict[str, Any]:
        """原子写入任务元数据与加密发件箱载荷（`outbox_blobs`: [(path_in_repo, kind, ciphertext), ...]）。"""
        if not job_id or not job_id.strip():
            raise ValueError("job_id must not be empty")
        now = int(time.time())
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO jobs (
                        job_id, mailbox_repo, queue_rel, ref_rel, mask_rel,
                        preset_key, arch, state, attempts, last_error,
                        packet_rel, packet_blob_id, saved_paths_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', '', '[]', ?, ?)
                    """,
                    (
                        job_id,
                        mailbox_repo,
                        queue_rel,
                        ref_rel,
                        mask_rel,
                        preset_key,
                        arch,
                        state,
                        now,
                        now,
                    ),
                )
                for path_in_repo, kind, ciphertext in outbox_blobs or ():
                    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
                        raise TypeError("outbox ciphertext must be bytes")
                    self._conn.execute(
                        """
                        INSERT OR REPLACE INTO outbox (
                            job_id, path_in_repo, kind, ciphertext, uploaded, created_at, uploaded_at
                        ) VALUES (?, ?, ?, ?, 0, ?, 0)
                        """,
                        (job_id, path_in_repo, kind, sqlite3.Binary(bytes(ciphertext)), now),
                    )
            row = self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            assert row is not None
            return _row_to_job(row)

    def stage_outbox_blob(self, job_id: str, path_in_repo: str, kind: str, ciphertext: bytes) -> None:
        now = int(time.time())
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO outbox (
                        job_id, path_in_repo, kind, ciphertext, uploaded, created_at, uploaded_at
                    ) VALUES (?, ?, ?, ?, 0, ?, 0)
                    """,
                    (job_id, path_in_repo, kind, sqlite3.Binary(bytes(ciphertext)), now),
                )

    def get_outbox_blobs(self, job_id: str, *, include_uploaded: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            if include_uploaded:
                rows = self._conn.execute(
                    "SELECT * FROM outbox WHERE job_id = ? ORDER BY id ASC",
                    (job_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM outbox WHERE job_id = ? AND uploaded = 0 ORDER BY id ASC",
                    (job_id,),
                ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                d["ciphertext"] = bytes(d["ciphertext"])
                out.append(d)
            return out

    def mark_outbox_uploaded(self, job_id: str, paths: Optional[Sequence[str]] = None) -> int:
        now = int(time.time())
        with self._lock:
            with self._conn:
                if paths:
                    placeholders = ",".join("?" for _ in paths)
                    cur = self._conn.execute(
                        f"UPDATE outbox SET uploaded = 1, uploaded_at = ? WHERE job_id = ? AND path_in_repo IN ({placeholders})",
                        (now, job_id, *paths),
                    )
                else:
                    cur = self._conn.execute(
                        "UPDATE outbox SET uploaded = 1, uploaded_at = ? WHERE job_id = ?",
                        (now, job_id),
                    )
                return int(cur.rowcount)

    def purge_outbox_blobs(self, job_id: str) -> int:
        """确认任务成功入队或终结后，从本地账本中清除已不再需要的加密发件箱大块。"""
        with self._lock:
            with self._conn:
                cur = self._conn.execute("DELETE FROM outbox WHERE job_id = ?", (job_id,))
                return int(cur.rowcount)

    def update_job_state(
        self,
        job_id: str,
        state: str,
        *,
        last_error: Optional[str] = None,
        packet_rel: Optional[str] = None,
        packet_blob_id: Optional[str] = None,
        saved_paths: Optional[Sequence[str]] = None,
        increment_attempts: bool = False,
    ) -> None:
        now = int(time.time())
        sets = ["state = ?", "updated_at = ?"]
        params: List[Any] = [state, now]
        if last_error is not None:
            sets.append("last_error = ?")
            params.append(str(last_error)[:512])
        if packet_rel is not None:
            sets.append("packet_rel = ?")
            params.append(packet_rel)
        if packet_blob_id is not None:
            sets.append("packet_blob_id = ?")
            params.append(packet_blob_id)
        if saved_paths is not None:
            sets.append("saved_paths_json = ?")
            params.append(json.dumps(list(saved_paths), ensure_ascii=False))
        if increment_attempts:
            sets.append("attempts = attempts + 1")
        params.append(job_id)
        with self._lock:
            with self._conn:
                self._conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE job_id = ?", params)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return _row_to_job(row) if row is not None else None

    def list_active_jobs(self, mailbox_repo: Optional[str] = None) -> List[Dict[str, Any]]:
        placeholders = ",".join("?" for _ in ACTIVE_JOB_STATES)
        with self._lock:
            if mailbox_repo:
                rows = self._conn.execute(
                    f"SELECT * FROM jobs WHERE mailbox_repo = ? AND state IN ({placeholders}) ORDER BY created_at ASC",
                    (mailbox_repo, *ACTIVE_JOB_STATES),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    f"SELECT * FROM jobs WHERE state IN ({placeholders}) ORDER BY created_at ASC",
                    ACTIVE_JOB_STATES,
                ).fetchall()
            return [_row_to_job(r) for r in rows]

    def list_pending_uploads(self, mailbox_repo: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if mailbox_repo:
                rows = self._conn.execute(
                    "SELECT * FROM jobs WHERE mailbox_repo = ? AND state = 'pending_upload' ORDER BY created_at ASC",
                    (mailbox_repo,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM jobs WHERE state = 'pending_upload' ORDER BY created_at ASC"
                ).fetchall()
            return [_row_to_job(r) for r in rows]

    def list_jobs(self, limit: int = 50, states: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if states:
                placeholders = ",".join("?" for _ in states)
                rows = self._conn.execute(
                    f"SELECT * FROM jobs WHERE state IN ({placeholders}) ORDER BY updated_at DESC LIMIT ?",
                    (*states, int(limit)),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM jobs ORDER BY updated_at DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            return [_row_to_job(r) for r in rows]

    def record_failure(
        self,
        job_id: str,
        stage: str,
        error_message: str,
        *,
        error_code: str = "",
        retryable: bool = True,
    ) -> int:
        now = int(time.time())
        clean_msg = str(error_message)[:1024]
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    """
                    INSERT INTO failures (job_id, stage, error_code, error_message, retryable, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (job_id, stage, error_code[:64], clean_msg, 1 if retryable else 0, now),
                )
                if job_id:
                    self._conn.execute(
                        "UPDATE jobs SET last_error = ?, updated_at = ? WHERE job_id = ?",
                        (clean_msg[:512], now, job_id),
                    )
                return int(cur.lastrowid or 0)

    def list_failures(self, job_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            if job_id:
                rows = self._conn.execute(
                    "SELECT * FROM failures WHERE job_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                    (job_id, int(limit)),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM failures ORDER BY created_at DESC, id DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            return [dict(r) for r in rows]

    def record_receipt(
        self,
        packet_rel: str,
        *,
        job_id: str = "",
        packet_blob_id: str = "",
        packet_revision: str = "",
        status: str = "unpacked",
        saved_paths: Optional[Sequence[str]] = None,
        burned_at: Optional[int] = None,
    ) -> None:
        now = int(time.time())
        saved_json = json.dumps(list(saved_paths or ()), ensure_ascii=False)
        b_ts = int(burned_at) if burned_at is not None else (now if status == "burned" else 0)
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO receipts (
                        packet_rel, job_id, packet_blob_id, packet_revision,
                        status, saved_paths_json, received_at, burned_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(packet_rel) DO UPDATE SET
                        job_id = CASE WHEN excluded.job_id != '' THEN excluded.job_id ELSE receipts.job_id END,
                        packet_blob_id = CASE WHEN excluded.packet_blob_id != '' THEN excluded.packet_blob_id ELSE receipts.packet_blob_id END,
                        packet_revision = CASE WHEN excluded.packet_revision != '' THEN excluded.packet_revision ELSE receipts.packet_revision END,
                        status = excluded.status,
                        saved_paths_json = CASE WHEN excluded.saved_paths_json != '[]' THEN excluded.saved_paths_json ELSE receipts.saved_paths_json END,
                        burned_at = CASE WHEN excluded.burned_at > 0 THEN excluded.burned_at ELSE receipts.burned_at END
                    """,
                    (packet_rel, job_id, packet_blob_id, packet_revision, status, saved_json, now, b_ts),
                )

    def mark_receipt_burned(self, packet_rel: str) -> None:
        now = int(time.time())
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "UPDATE receipts SET status = 'burned', burned_at = ? WHERE packet_rel = ?",
                    (now, packet_rel),
                )

    def get_receipt(self, packet_rel: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM receipts WHERE packet_rel = ?", (packet_rel,)).fetchone()
            return _row_to_receipt(row) if row is not None else None

    def is_packet_processed(self, packet_rel: str, packet_blob_id: str = "") -> bool:
        rec = self.get_receipt(packet_rel)
        if not rec:
            return False
        if packet_blob_id and rec.get("packet_blob_id") and rec["packet_blob_id"] != packet_blob_id:
            return False
        return rec.get("status") in ("unpacked", "burned")

    def list_receipts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM receipts ORDER BY received_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
            return [_row_to_receipt(r) for r in rows]

    def summary(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {
                "active": 0,
                "pending_upload": 0,
                "queued": 0,
                "claimed": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
                "receipts": 0,
                "failures": 0,
            }
            for row in self._conn.execute("SELECT state, COUNT(*) AS cnt FROM jobs GROUP BY state").fetchall():
                st = str(row["state"])
                cnt = int(row["cnt"])
                if st in counts:
                    counts[st] = cnt
                if st in ACTIVE_JOB_STATES:
                    counts["active"] += cnt
            counts["receipts"] = int(self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
            counts["failures"] = int(self._conn.execute("SELECT COUNT(*) FROM failures").fetchone()[0])
            return counts
