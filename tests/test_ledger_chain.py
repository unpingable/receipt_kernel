# SPDX-License-Identifier: Apache-2.0
"""Tests for ledger chain integrity and the chain validation invariant."""

from __future__ import annotations

import json

import pytest

from receipt_kernel.envelope import make_envelope, seal_envelope, verify_envelope_hash
from receipt_kernel.invariants.ledger_chain_valid import LedgerChainValidInvariant
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import Verdict


def _make_store(tmp_path) -> SqliteReceiptStore:
    store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
    store.initialize_schema()
    return store


def _make_env(**overrides) -> dict:
    defaults = dict(
        event_type="RUN_START",
        stage="START",
        policy_id="test",
        policy_version="0.0.0",
        stage_graph_id="v1_default",
        actor_kind="pytest",
        actor_id="test",
        payload={},
    )
    defaults.update(overrides)
    return make_envelope(**defaults)


class TestEnvelopeHashing:
    def test_seal_and_verify(self):
        env = _make_env()
        env["run_id"] = "run1"
        env["seq"] = 1
        sealed = seal_envelope(env)
        assert sealed["event_hash"] is not None
        assert verify_envelope_hash(sealed)

    def test_tampered_envelope_fails_verify(self):
        env = _make_env()
        env["run_id"] = "run1"
        env["seq"] = 1
        sealed = seal_envelope(env)
        sealed["stage"] = "TAMPERED"
        assert not verify_envelope_hash(sealed)

    def test_missing_hash_fails_verify(self):
        env = _make_env()
        assert not verify_envelope_hash(env)  # event_hash is None


class TestLedgerChain:
    def test_valid_chain_passes(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")

        store.append_event("run1", _make_env())
        store.append_event("run1", _make_env(
            event_type="STAGE_ADVANCE", stage="COLLECT",
            payload={"from_stage": "START", "to_stage": "COLLECT", "reason": "test"},
        ))
        store.append_event("run1", _make_env(
            event_type="RUN_FINALIZE", stage="COLLECT",
            payload={"overall_verdict": "pass", "summary": {}},
        ))

        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.PASS
        assert result.meta["event_count"] == 3
        store.close()

    def test_empty_run_is_unknown(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")

        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.UNKNOWN
        assert result.reasons[0].code == "NO_EVENTS"
        store.close()

    def test_tampered_event_hash_detected(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _make_env())

        # Tamper with the stored hash
        store._conn.execute(
            "UPDATE events SET event_hash = 'sha256:deadbeef' WHERE run_id = 'run1'"
        )
        store._conn.commit()

        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "EVENT_HASH_MISMATCH" for r in result.reasons)
        store.close()

    def test_tampered_prev_hash_detected(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _make_env())
        store.append_event("run1", _make_env(
            event_type="RUN_FINALIZE", stage="FINALIZE",
            payload={"overall_verdict": "pass", "summary": {}},
        ))

        # Tamper with prev_event_hash of second event
        row = store._conn.execute(
            "SELECT envelope_json FROM events WHERE run_id = 'run1' AND seq = 2"
        ).fetchone()
        env = json.loads(row[0])
        env["prev_event_hash"] = "sha256:badfood"
        store._conn.execute(
            "UPDATE events SET envelope_json = ?, prev_event_hash = ? WHERE run_id = 'run1' AND seq = 2",
            (json.dumps(env), "sha256:badfood"),
        )
        store._conn.commit()

        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "PREV_HASH_MISMATCH" for r in result.reasons)
        store.close()

    def test_seq_gap_detected(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _make_env())

        # Insert event with seq=3 (skipping seq=2)
        env = _make_env(event_type="RUN_FINALIZE", stage="FINALIZE",
                        payload={"overall_verdict": "pass", "summary": {}})
        env["run_id"] = "run1"
        env["seq"] = 3
        env["prev_event_hash"] = None
        sealed = seal_envelope(env)
        store._conn.execute(
            """INSERT INTO events (run_id, seq, event_type, envelope_json, event_hash, prev_event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("run1", 3, sealed["event_type"], json.dumps(sealed),
             sealed["event_hash"], None, "2026-01-01T00:00:00Z"),
        )
        store._conn.commit()

        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "SEQ_GAP" for r in result.reasons)
        store.close()

    def test_nonexistent_run(self, tmp_path):
        store = _make_store(tmp_path)
        inv = LedgerChainValidInvariant()
        result = inv.evaluate({"store": store, "run_id": "nope"})
        assert result.verdict == Verdict.UNKNOWN
        store.close()
