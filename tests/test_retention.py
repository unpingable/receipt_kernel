# SPDX-License-Identifier: Apache-2.0
"""Tests for retention policy enforcement."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from receipt_kernel.retention import compute_expiry_ts, find_expired_blobs, purge_expired
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import BlobState, EvidenceClass, RetentionPolicy


def _make_store(tmp_path, redaction=False) -> SqliteReceiptStore:
    store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=redaction)
    store.initialize_schema()
    return store


class TestComputeExpiry:
    def test_public_ttl(self):
        policy = RetentionPolicy(public_ttl_seconds=3600)
        expiry = compute_expiry_ts("2026-01-01T00:00:00+00:00", EvidenceClass.PUBLIC, policy)
        assert expiry is not None
        assert "2026-01-01T01:00:00" in expiry

    def test_sealed_ttl(self):
        policy = RetentionPolicy(sealed_ttl_seconds=60)
        expiry = compute_expiry_ts("2026-01-01T00:00:00+00:00", EvidenceClass.SEALED, policy)
        assert expiry is not None
        assert "2026-01-01T00:01:00" in expiry

    def test_forever_returns_none(self):
        policy = RetentionPolicy(public_ttl_seconds=-1)
        expiry = compute_expiry_ts("2026-01-01T00:00:00+00:00", EvidenceClass.PUBLIC, policy)
        assert expiry is None


class TestRetentionPolicy:
    def test_serialization_roundtrip(self):
        policy = RetentionPolicy(
            public_ttl_seconds=86400,
            sealed_ttl_seconds=3600,
            hash_retention_seconds=604800,
        )
        d = policy.to_dict()
        restored = RetentionPolicy.from_dict(d)
        assert restored.public_ttl_seconds == 86400
        assert restored.sealed_ttl_seconds == 3600
        assert restored.hash_retention_seconds == 604800

    def test_defaults(self):
        policy = RetentionPolicy()
        assert policy.public_ttl_seconds == 30 * 24 * 3600
        assert policy.sealed_ttl_seconds == 7 * 24 * 3600
        assert policy.hash_retention_seconds == -1


class TestFindExpiredBlobs:
    def test_finds_expired_public(self, tmp_path):
        store = _make_store(tmp_path)
        # Store a blob with old timestamp
        store.put_blob(b"old data", content_type="text/plain", evidence_class="public")

        # Hack the created_at to be old
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        expired = find_expired_blobs(store, policy)
        assert len(expired) == 1
        store.close()

    def test_ignores_fresh_blobs(self, tmp_path):
        store = _make_store(tmp_path)
        store.put_blob(b"fresh data", content_type="text/plain")

        policy = RetentionPolicy(public_ttl_seconds=86400)
        expired = find_expired_blobs(store, policy)
        assert len(expired) == 0
        store.close()

    def test_ignores_forever_policy(self, tmp_path):
        store = _make_store(tmp_path)
        store.put_blob(b"permanent", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=-1)
        expired = find_expired_blobs(store, policy)
        assert len(expired) == 0
        store.close()

    def test_sealed_shorter_ttl(self, tmp_path):
        store = _make_store(tmp_path)
        store.put_blob(b"sealed data", content_type="text/plain", evidence_class="sealed")
        # Set created_at to 2 hours ago
        two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        store._conn.execute(
            "UPDATE blobs SET created_at = ?", (two_hours_ago,)
        )
        store._conn.commit()

        # Public TTL = 1 day, sealed = 1 hour -> sealed should be expired
        policy = RetentionPolicy(public_ttl_seconds=86400, sealed_ttl_seconds=3600)
        expired = find_expired_blobs(store, policy)
        assert len(expired) == 1
        assert expired[0]["evidence_class"] == "sealed"
        store.close()


class TestPurgeExpired:
    def test_purge_transitions_state(self, tmp_path):
        store = _make_store(tmp_path)
        ref = store.put_blob(b"to expire", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        expired = purge_expired(store, policy)
        assert len(expired) == 1

        # Data should be gone
        assert store.get_blob(ref.sha256) is None

        # Metadata should survive
        meta = store.get_blob_meta(ref.sha256)
        assert meta is not None
        assert meta["state"] == BlobState.EXPIRED_HASH_ONLY.value
        assert meta["expired_at"] is not None
        assert meta["bytes_len"] > 0  # original size preserved
        store.close()

    def test_purge_dry_run(self, tmp_path):
        store = _make_store(tmp_path)
        ref = store.put_blob(b"keep me", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        expired = purge_expired(store, policy, dry_run=True)
        assert len(expired) == 1

        # Data should still be there
        assert store.get_blob(ref.sha256) is not None
        store.close()

    def test_purge_idempotent(self, tmp_path):
        store = _make_store(tmp_path)
        store.put_blob(b"expire me", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        first = purge_expired(store, policy)
        assert len(first) == 1

        # Second purge should find nothing (already expired)
        second = purge_expired(store, policy)
        assert len(second) == 0
        store.close()

    def test_has_blob_after_expiry(self, tmp_path):
        """has_blob returns True even after expiry (hash still exists)."""
        store = _make_store(tmp_path)
        ref = store.put_blob(b"expire me", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        purge_expired(store, policy)

        assert store.has_blob(ref.sha256)  # hash exists
        assert not store.blob_is_live(ref.sha256)  # but not live
        assert store.get_blob(ref.sha256) is None  # can't get data
        store.close()


class TestBlobExpireEvent:
    """BLOB_EXPIRE events must receipt every purge action."""

    def test_purge_emits_blob_expire_events(self, tmp_path):
        """Each purged blob gets a BLOB_EXPIRE event in the maintenance run."""
        store = _make_store(tmp_path)
        ref1 = store.put_blob(b"blob one", content_type="text/plain")
        ref2 = store.put_blob(b"blob two", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        purge_expired(store, policy, maintenance_run_id="maint_001")

        events = store.get_events("maint_001", event_type="BLOB_EXPIRE")
        assert len(events) == 2

        # Events should reference the expired blobs
        shas = {e["payload"]["sha256"] for e in events}
        assert ref1.sha256 in shas
        assert ref2.sha256 in shas

        # Each event should record the new state
        for ev in events:
            assert ev["payload"]["new_state"] == BlobState.EXPIRED_HASH_ONLY.value
            assert ev["payload"]["policy"]["public_ttl_seconds"] == 3600
        store.close()

    def test_purge_without_run_id_skips_events(self, tmp_path):
        """Without maintenance_run_id, purge still works but emits no events."""
        store = _make_store(tmp_path)
        store.put_blob(b"ephemeral", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        expired = purge_expired(store, policy)  # no maintenance_run_id
        assert len(expired) == 1

        # No events emitted (no run to emit into)
        assert store.get_run("maint_001") is None
        store.close()

    def test_blob_expire_event_is_hash_chained(self, tmp_path):
        """BLOB_EXPIRE events participate in the hash chain."""
        from receipt_kernel.invariants.ledger_chain_valid import LedgerChainValidInvariant
        from receipt_kernel.types import Verdict

        store = _make_store(tmp_path)
        store.put_blob(b"chain test", content_type="text/plain")
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()

        policy = RetentionPolicy(public_ttl_seconds=3600)
        purge_expired(store, policy, maintenance_run_id="maint_chain")

        # Chain should be valid
        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "maint_chain"})
        assert result.verdict == Verdict.PASS
        store.close()
