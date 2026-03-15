# SPDX-License-Identifier: Apache-2.0
"""SQLite receipt store: append-only, hash-chained event ledger.

Design:
- Events are append-only (no UPDATE/DELETE on events table)
- Hash chain: each event's prev_event_hash links to the previous event
- Blobs are content-addressed by sha256
- Blob lifecycle: LIVE -> EXPIRED_HASH_ONLY -> PURGED
- Optional redaction hook on blob write

Schema is intentionally simple. No ORM, no migrations framework.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from receipt_kernel.envelope import canonical_json, compute_hash, compute_hash_raw, seal_envelope
from receipt_kernel.redact import RedactionReport, redact
from receipt_kernel.types import (
    BlobRef,
    BlobState,
    EvidenceClass,
    EVENT_SCHEMA_VERSION,
)

STORE_SCHEMA_VERSION = 1

_SCHEMA_SQL = """
-- Runs table: one row per governed execution
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    stage_graph_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}'
);

-- Events table: append-only, hash-chained
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    prev_event_hash TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

-- Blobs table: content-addressed evidence storage
CREATE TABLE IF NOT EXISTS blobs (
    sha256 TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    bytes_len INTEGER NOT NULL,
    evidence_class TEXT NOT NULL DEFAULT 'public',
    state TEXT NOT NULL DEFAULT 'live',
    data BLOB,
    created_at TEXT NOT NULL,
    expired_at TEXT,
    redaction_json TEXT
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class SqliteReceiptStore:
    """Append-only receipt store backed by SQLite.

    Thread safety: one writer at a time. Readers are safe concurrent.
    For multi-writer, use per-run leases (not implemented in kernel v0).
    """

    def __init__(
        self,
        db_path: str,
        *,
        redaction_enabled: bool = True,
        custom_redactor: Callable[
            [bytes, str, str, str], tuple[bytes, RedactionReport]
        ] | None = None,
    ):
        self.db_path = db_path
        self.redaction_enabled = redaction_enabled
        self._custom_redactor = custom_redactor
        self._conn: sqlite3.Connection | None = None

    def initialize_schema(self) -> None:
        """Create tables if they don't exist."""
        self._ensure_conn()
        assert self._conn is not None
        self._conn.executescript(_SCHEMA_SQL)
        # Store schema version
        self._conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("store_schema_version", str(STORE_SCHEMA_VERSION)),
        )
        self._conn.commit()

    def _ensure_conn(self) -> None:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -----------------------------------------------------------------
    # Runs
    # -----------------------------------------------------------------

    def ensure_run(
        self,
        run_id: str,
        policy_id: str,
        policy_version: str,
        stage_graph_id: str,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Create a run record if it doesn't exist."""
        self._ensure_conn()
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT OR IGNORE INTO runs
               (run_id, policy_id, policy_version, stage_graph_id, created_at, meta_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (run_id, policy_id, policy_version, stage_graph_id, now,
             json.dumps(meta or {})),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Get run metadata."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT run_id, policy_id, policy_version, stage_graph_id, created_at, meta_json "
            "FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "run_id": row[0],
            "policy_id": row[1],
            "policy_version": row[2],
            "stage_graph_id": row[3],
            "created_at": row[4],
            "meta": json.loads(row[5]),
        }

    # -----------------------------------------------------------------
    # Events (append-only, hash-chained)
    # -----------------------------------------------------------------

    def append_event(self, run_id: str, envelope: dict[str, Any]) -> str:
        """Append an event to the run's ledger.

        Fills in run_id, seq, prev_event_hash, and computes event_hash.
        Returns the event reference string.
        """
        self._ensure_conn()
        assert self._conn is not None

        # Check schema version
        esv = envelope.get("event_schema_version", EVENT_SCHEMA_VERSION)
        if esv > EVENT_SCHEMA_VERSION:
            raise ValueError(
                f"Event schema version {esv} is newer than supported "
                f"({EVENT_SCHEMA_VERSION}). Upgrade receipt_kernel."
            )

        # Get next seq and prev_hash
        row = self._conn.execute(
            "SELECT seq, event_hash FROM events WHERE run_id = ? ORDER BY seq DESC LIMIT 1",
            (run_id,),
        ).fetchone()

        if row is None:
            next_seq = 1
            prev_hash = None
        else:
            next_seq = row[0] + 1
            prev_hash = row[1]

        # Fill in chain fields
        env = dict(envelope)
        env["run_id"] = run_id
        env["seq"] = next_seq
        env["prev_event_hash"] = prev_hash

        # Seal (compute event_hash)
        env = seal_envelope(env)
        event_hash = env["event_hash"]

        now = datetime.now(timezone.utc).isoformat()
        env_json = json.dumps(env, sort_keys=True, ensure_ascii=True)

        self._conn.execute(
            """INSERT INTO events
               (run_id, seq, event_type, envelope_json, event_hash, prev_event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (run_id, next_seq, env["event_type"], env_json, event_hash, prev_hash, now),
        )
        self._conn.commit()

        return f"event://{run_id}/{next_seq}"

    def get_events(
        self,
        run_id: str,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get events for a run, optionally filtered by type."""
        self._ensure_conn()
        assert self._conn is not None

        if event_type:
            rows = self._conn.execute(
                "SELECT envelope_json FROM events WHERE run_id = ? AND event_type = ? ORDER BY seq ASC",
                (run_id, event_type),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT envelope_json FROM events WHERE run_id = ? ORDER BY seq ASC",
                (run_id,),
            ).fetchall()

        return [json.loads(row[0]) for row in rows]

    def get_event_by_ref(self, ref: str) -> dict[str, Any] | None:
        """Get a single event by its reference string (event://run_id/seq)."""
        if not ref.startswith("event://"):
            return None
        parts = ref[len("event://"):].rsplit("/", 1)
        if len(parts) != 2:
            return None
        run_id, seq_str = parts
        try:
            seq = int(seq_str)
        except ValueError:
            return None

        self._ensure_conn()
        assert self._conn is not None

        row = self._conn.execute(
            "SELECT envelope_json FROM events WHERE run_id = ? AND seq = ?",
            (run_id, seq),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def event_count(self, run_id: str) -> int:
        """Count events in a run."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return row[0] if row else 0

    # -----------------------------------------------------------------
    # Blobs (content-addressed, with redaction + retention)
    # -----------------------------------------------------------------

    def put_blob(
        self,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        kind: str = "evidence",
        evidence_class: str = "public",
    ) -> BlobRef:
        """Store a blob, applying redaction if enabled.

        Returns a BlobRef with the content hash (post-redaction).
        Deduplicates by sha256 — same content = same blob.
        """
        self._ensure_conn()
        assert self._conn is not None

        original_hash = compute_hash_raw(data)
        redaction_report: RedactionReport | None = None

        # Apply redaction
        if self.redaction_enabled:
            if self._custom_redactor:
                data, redaction_report = self._custom_redactor(
                    data, content_type, evidence_class, original_hash,
                )
            else:
                data, redaction_report = redact(
                    data, content_type, evidence_class, original_hash,
                )

        sha = compute_hash_raw(data)
        ref = f"blob://sha256:{sha}"

        # Dedup: if blob already exists, just return the ref
        existing = self._conn.execute(
            "SELECT sha256 FROM blobs WHERE sha256 = ?", (sha,)
        ).fetchone()

        if existing is None:
            now = datetime.now(timezone.utc).isoformat()
            redaction_json = (
                json.dumps(redaction_report.to_dict())
                if redaction_report and redaction_report.redacted
                else None
            )
            self._conn.execute(
                """INSERT INTO blobs
                   (sha256, content_type, bytes_len, evidence_class, state, data, created_at, redaction_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (sha, content_type, len(data), evidence_class,
                 BlobState.LIVE.value, data, now, redaction_json),
            )
            self._conn.commit()

        return BlobRef(
            ref=ref,
            sha256=sha,
            content_type=content_type,
            bytes_len=len(data),
            evidence_class=evidence_class,
        )

    def get_blob(self, sha256: str) -> bytes | None:
        """Retrieve blob data by sha256. Returns None if expired or missing."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT data, state FROM blobs WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row is None:
            return None
        data, state = row
        if state != BlobState.LIVE.value or data is None:
            return None
        return data

    def get_blob_meta(self, sha256: str) -> dict[str, Any] | None:
        """Get blob metadata (available even after expiry)."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            """SELECT sha256, content_type, bytes_len, evidence_class, state,
                      created_at, expired_at, redaction_json
               FROM blobs WHERE sha256 = ?""",
            (sha256,),
        ).fetchone()
        if row is None:
            return None
        return {
            "sha256": row[0],
            "content_type": row[1],
            "bytes_len": row[2],
            "evidence_class": row[3],
            "state": row[4],
            "created_at": row[5],
            "expired_at": row[6],
            "redaction_report": json.loads(row[7]) if row[7] else None,
        }

    def has_blob(self, sha256: str) -> bool:
        """Check if blob exists (any state)."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT 1 FROM blobs WHERE sha256 = ?", (sha256,)
        ).fetchone()
        return row is not None

    def blob_is_live(self, sha256: str) -> bool:
        """Check if blob data is still available."""
        self._ensure_conn()
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT state FROM blobs WHERE sha256 = ?", (sha256,)
        ).fetchone()
        return row is not None and row[0] == BlobState.LIVE.value
