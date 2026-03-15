# SPDX-License-Identifier: Apache-2.0
"""Retention policy enforcement for evidence blobs.

Manages blob lifecycle: LIVE -> EXPIRED_HASH_ONLY -> PURGED.
Every transition is receipted via a BLOB_EXPIRE event in the ledger.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from receipt_kernel.envelope import make_envelope
from receipt_kernel.types import BlobState, EvidenceClass, RetentionPolicy

if TYPE_CHECKING:
    from receipt_kernel.store_sqlite import SqliteReceiptStore


def compute_expiry_ts(
    created_at: str,
    evidence_class: EvidenceClass,
    policy: RetentionPolicy,
) -> str | None:
    """Compute the expiry timestamp for a blob.

    Returns None if the blob should be kept forever.
    """
    ttl = policy.ttl_for_class(evidence_class)
    if ttl < 0:
        return None

    created = datetime.fromisoformat(created_at)
    expiry = created.timestamp() + ttl
    return datetime.fromtimestamp(expiry, tz=timezone.utc).isoformat()


def find_expired_blobs(
    store: SqliteReceiptStore,
    policy: RetentionPolicy,
    now: str | None = None,
) -> list[dict[str, Any]]:
    """Find blobs that have exceeded their TTL.

    Returns list of blob metadata dicts for blobs in LIVE state
    whose TTL has expired.
    """
    now_ts = now or datetime.now(timezone.utc).isoformat()

    store._ensure_conn()
    assert store._conn is not None
    rows = store._conn.execute(
        """SELECT sha256, content_type, bytes_len, created_at, evidence_class, state
           FROM blobs WHERE state = ?""",
        (BlobState.LIVE.value,),
    ).fetchall()

    expired = []
    for sha, ct, blen, created, eclass, state in rows:
        ec = EvidenceClass(eclass)
        expiry = compute_expiry_ts(created, ec, policy)
        if expiry is not None and now_ts > expiry:
            expired.append({
                "sha256": sha,
                "content_type": ct,
                "bytes_len": blen,
                "created_at": created,
                "evidence_class": eclass,
                "expires_at": expiry,
            })

    return expired


def purge_expired(
    store: SqliteReceiptStore,
    policy: RetentionPolicy,
    now: str | None = None,
    *,
    dry_run: bool = False,
    maintenance_run_id: str | None = None,
) -> list[dict[str, Any]]:
    """Expire blobs that have exceeded their TTL.

    For each expired blob:
    - Transition state from LIVE to EXPIRED_HASH_ONLY
    - Delete the raw data bytes
    - Keep sha256, content_type, bytes_len, created_at metadata
    - Emit a BLOB_EXPIRE event (if maintenance_run_id provided)

    The BLOB_EXPIRE event receipts the purge action itself, so there's
    never a "we deleted something but can't prove why" situation.

    Returns list of expired blob metadata.
    """
    expired = find_expired_blobs(store, policy, now)

    if dry_run or not expired:
        return expired

    expire_ts = now or datetime.now(timezone.utc).isoformat()

    for blob in expired:
        store._ensure_conn()
        assert store._conn is not None
        store._conn.execute(
            """UPDATE blobs SET state = ?, data = NULL, expired_at = ?
               WHERE sha256 = ? AND state = ?""",
            (
                BlobState.EXPIRED_HASH_ONLY.value,
                expire_ts,
                blob["sha256"],
                BlobState.LIVE.value,
            ),
        )

    store._conn.commit()

    # Emit BLOB_EXPIRE events if we have a maintenance run
    if maintenance_run_id:
        store.ensure_run(
            run_id=maintenance_run_id,
            policy_id="retention",
            policy_version="0.1.0",
            stage_graph_id="v1_minimal",
            meta={"type": "maintenance", "action": "purge_expired"},
        )
        for blob in expired:
            env = make_envelope(
                event_type="BLOB_EXPIRE",
                stage="FINALIZE",
                policy_id="retention",
                policy_version="0.1.0",
                stage_graph_id="v1_minimal",
                actor_kind="system",
                actor_id="retention_policy",
                payload={
                    "sha256": blob["sha256"],
                    "evidence_class": blob["evidence_class"],
                    "bytes_len": blob["bytes_len"],
                    "created_at": blob["created_at"],
                    "expired_at": expire_ts,
                    "new_state": BlobState.EXPIRED_HASH_ONLY.value,
                    "policy": policy.to_dict(),
                },
                blob_refs=[f"blob://sha256:{blob['sha256']}"],
            )
            store.append_event(maintenance_run_id, env)

    return expired
