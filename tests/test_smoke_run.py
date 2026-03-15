# SPDX-License-Identifier: Apache-2.0
"""End-to-end smoke test: build a complete run and verify all invariants PASS.

This is the proof-of-concept test: if this passes, the kernel works.
"""

from __future__ import annotations

import json

import pytest

from receipt_kernel.envelope import make_envelope, canonical_json, compute_hash
from receipt_kernel.invariants import (
    EvaluationCompletenessInvariant,
    FinalizationCompletenessInvariant,
    LedgerChainValidInvariant,
    ReceiptCompletenessInvariant,
    SingleFinalizeInvariant,
    StageRequiredPathInvariant,
)
from receipt_kernel.retention import purge_expired
from receipt_kernel.stages import DEFAULT_STAGE_GRAPH, StageGraph
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import RetentionPolicy, Verdict


def _env(**kw):
    defaults = dict(
        event_type="RUN_START", stage="START",
        policy_id="smoke", policy_version="0.0.0",
        stage_graph_id="v1_default",
        actor_kind="pytest", actor_id="test_smoke_run",
        payload={},
    )
    defaults.update(kw)
    return make_envelope(**defaults)


class TestSmokeRun:
    """Full lifecycle: START → COLLECT → EVALUATE → DECIDE → FINALIZE."""

    def test_complete_run_all_invariants_pass(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "smoke.db"), redaction_enabled=False)
        store.initialize_schema()

        run_id = "run_smoke_0001"
        store.ensure_run(run_id, "smoke", "0.0.0", "v1_default", meta={"test": "smoke"})

        # RUN_START
        store.append_event(run_id, _env())

        # STAGE_ADVANCE: START → COLLECT
        DEFAULT_STAGE_GRAPH.validate_transition("START", "COLLECT")
        store.append_event(run_id, _env(
            event_type="STAGE_ADVANCE", stage="COLLECT",
            payload={"from_stage": "START", "to_stage": "COLLECT", "reason": "normal"},
        ))

        # EVIDENCE_PUT: model output
        blob_model = store.put_blob(
            b'{"ok": true, "value": 42}',
            content_type="application/json", kind="evidence",
        )
        store.append_event(run_id, _env(
            event_type="EVIDENCE_PUT", stage="COLLECT",
            payload={
                "key": "model_output",
                "evidence": {
                    "ref": blob_model.ref, "sha256": blob_model.sha256,
                    "content_type": blob_model.content_type,
                    "bytes_len": blob_model.bytes_len,
                },
                "meta": {"source": "fake_model"},
            },
            blob_refs=[blob_model.ref],
        ))

        # EVIDENCE_PUT: tool trace
        blob_trace = store.put_blob(
            b'{"calls": [{"tool": "noop", "ok": true}]}',
            content_type="application/json", kind="evidence",
        )
        store.append_event(run_id, _env(
            event_type="EVIDENCE_PUT", stage="COLLECT",
            payload={
                "key": "tool_trace",
                "evidence": {
                    "ref": blob_trace.ref, "sha256": blob_trace.sha256,
                    "content_type": blob_trace.content_type,
                    "bytes_len": blob_trace.bytes_len,
                },
                "meta": {"source": "fake_tools"},
            },
            blob_refs=[blob_trace.ref],
        ))

        # STAGE_ADVANCE: COLLECT → EVALUATE
        DEFAULT_STAGE_GRAPH.validate_transition("COLLECT", "EVALUATE")
        store.append_event(run_id, _env(
            event_type="STAGE_ADVANCE", stage="EVALUATE",
            payload={"from_stage": "COLLECT", "to_stage": "EVALUATE", "reason": "normal"},
        ))

        # Run receipt completeness check
        rc = ReceiptCompletenessInvariant(["model_output", "tool_trace"], verify_blobs=True)
        rc_res = rc.evaluate({"store": store, "run_id": run_id})
        assert rc_res.verdict == Verdict.PASS

        # EVALUATION
        eval_ref = store.append_event(run_id, _env(
            event_type="EVALUATION", stage="EVALUATE",
            payload={
                "results": [{
                    "invariant_id": "receipt.completeness",
                    "verdict": rc_res.verdict.value,
                    "reasons": [r.to_dict() for r in rc_res.reasons],
                    "evidence_refs": list(rc_res.evidence_refs),
                    "meta": rc_res.meta,
                }],
                "overall_verdict": "pass",
                "evidence_complete": True,
            },
        ))

        # STAGE_ADVANCE: EVALUATE → DECIDE
        DEFAULT_STAGE_GRAPH.validate_transition("EVALUATE", "DECIDE")
        store.append_event(run_id, _env(
            event_type="STAGE_ADVANCE", stage="DECIDE",
            payload={"from_stage": "EVALUATE", "to_stage": "DECIDE", "reason": "normal"},
        ))

        # DECISION
        dec_ref = store.append_event(run_id, _env(
            event_type="DECISION", stage="DECIDE",
            payload={
                "decision_id": "dec_0001",
                "basis": {"overall_verdict": "pass", "blocking_invariants": []},
                "action_plan": [],
            },
            event_refs=[eval_ref],
        ))

        # STAGE_ADVANCE: DECIDE → FINALIZE
        DEFAULT_STAGE_GRAPH.validate_transition("DECIDE", "FINALIZE")
        store.append_event(run_id, _env(
            event_type="STAGE_ADVANCE", stage="FINALIZE",
            payload={"from_stage": "DECIDE", "to_stage": "FINALIZE", "reason": "normal"},
        ))

        # RUN_FINALIZE
        store.append_event(run_id, _env(
            event_type="RUN_FINALIZE", stage="FINALIZE",
            payload={"overall_verdict": "pass", "summary": {"failed_invariants": [], "remediations_taken": []}},
            event_refs=[eval_ref, dec_ref],
        ))

        # ---- Verify all 6 invariants ----
        ctx = {"store": store, "run_id": run_id}

        chain = LedgerChainValidInvariant().evaluate(ctx)
        assert chain.verdict == Verdict.PASS, f"chain: {chain.reasons}"

        receipt = ReceiptCompletenessInvariant(
            ["model_output", "tool_trace"], verify_blobs=True
        ).evaluate(ctx)
        assert receipt.verdict == Verdict.PASS, f"receipt: {receipt.reasons}"

        evaluation = EvaluationCompletenessInvariant(
            required_invariants=("receipt.completeness",),
        ).evaluate(ctx)
        assert evaluation.verdict == Verdict.PASS, f"evaluation: {evaluation.reasons}"

        finalization = FinalizationCompletenessInvariant(
            require_decision_ref=True
        ).evaluate(ctx)
        assert finalization.verdict == Verdict.PASS, f"finalization: {finalization.reasons}"

        single_fin = SingleFinalizeInvariant().evaluate(ctx)
        assert single_fin.verdict == Verdict.PASS, f"single_finalize: {single_fin.reasons}"

        stage_path = StageRequiredPathInvariant(
            ["START", "COLLECT", "EVALUATE", "DECIDE", "FINALIZE"]
        ).evaluate(ctx)
        assert stage_path.verdict == Verdict.PASS, f"stage_path: {stage_path.reasons}"

        # Verify event count (START + 4 STAGE_ADVANCE + 2 EVIDENCE_PUT + EVAL + DECISION + FINALIZE = 10)
        assert store.event_count(run_id) == 10

        store.close()


class TestStageGraphEnforcement:
    """StageGraph must hard-fail on illegal transitions."""

    def test_legal_transition_ok(self):
        DEFAULT_STAGE_GRAPH.validate_transition("START", "COLLECT")

    def test_illegal_transition_raises(self):
        with pytest.raises(ValueError, match="Illegal transition"):
            DEFAULT_STAGE_GRAPH.validate_transition("START", "FINALIZE")

    def test_unknown_stage_raises(self):
        with pytest.raises(ValueError, match="Unknown stage"):
            DEFAULT_STAGE_GRAPH.validate_transition("NONEXISTENT", "COLLECT")

    def test_terminal_stage(self):
        assert DEFAULT_STAGE_GRAPH.is_terminal("FINALIZE")
        assert not DEFAULT_STAGE_GRAPH.is_terminal("START")

    def test_remediation_loop(self):
        """DECIDE → REMEDIATE → COLLECT is legal."""
        DEFAULT_STAGE_GRAPH.validate_transition("DECIDE", "REMEDIATE")
        DEFAULT_STAGE_GRAPH.validate_transition("REMEDIATE", "COLLECT")

    def test_graph_serialization(self):
        d = DEFAULT_STAGE_GRAPH.to_dict()
        restored = StageGraph.from_dict(d)
        assert restored.graph_id == DEFAULT_STAGE_GRAPH.graph_id
        assert restored.initial_stage == DEFAULT_STAGE_GRAPH.initial_stage
        assert restored.terminal_stages == DEFAULT_STAGE_GRAPH.terminal_stages

    def test_all_stages(self):
        stages = DEFAULT_STAGE_GRAPH.all_stages()
        assert "START" in stages
        assert "FINALIZE" in stages
        assert "REMEDIATE" in stages


class TestBlobStore:
    """Evidence blob storage basics."""

    def test_put_and_get(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        ref = store.put_blob(b"hello", content_type="text/plain")
        assert store.get_blob(ref.sha256) == b"hello"
        store.close()

    def test_dedup(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        ref1 = store.put_blob(b"same", content_type="text/plain")
        ref2 = store.put_blob(b"same", content_type="text/plain")
        assert ref1.sha256 == ref2.sha256
        store.close()

    def test_blob_ref_format(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        ref = store.put_blob(b"test", content_type="text/plain")
        assert ref.ref.startswith("blob://sha256:")
        store.close()

    def test_missing_blob(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        assert store.get_blob("nonexistent") is None
        assert not store.has_blob("nonexistent")
        store.close()


class TestEventStore:
    """Event append and retrieval."""

    def test_append_and_get(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        store.append_event("r1", _env())
        events = store.get_events("r1")
        assert len(events) == 1
        assert events[0]["event_type"] == "RUN_START"
        assert events[0]["seq"] == 1
        store.close()

    def test_seq_auto_increment(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        store.append_event("r1", _env())
        store.append_event("r1", _env(event_type="RUN_FINALIZE", stage="FINALIZE",
                                       payload={"overall_verdict": "pass", "summary": {}}))
        events = store.get_events("r1")
        assert events[0]["seq"] == 1
        assert events[1]["seq"] == 2
        store.close()

    def test_prev_hash_chain(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        store.append_event("r1", _env())
        store.append_event("r1", _env(event_type="RUN_FINALIZE", stage="FINALIZE",
                                       payload={"overall_verdict": "pass", "summary": {}}))
        events = store.get_events("r1")
        assert events[0]["prev_event_hash"] is None
        assert events[1]["prev_event_hash"] == events[0]["event_hash"]
        store.close()

    def test_filter_by_type(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        store.append_event("r1", _env())
        store.append_event("r1", _env(event_type="EVIDENCE_PUT", stage="COLLECT",
                                       payload={"key": "x", "evidence": {}, "meta": {}}))
        store.append_event("r1", _env(event_type="RUN_FINALIZE", stage="FINALIZE",
                                       payload={"overall_verdict": "pass", "summary": {}}))
        evidence = store.get_events("r1", event_type="EVIDENCE_PUT")
        assert len(evidence) == 1
        store.close()

    def test_get_event_by_ref(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        ref = store.append_event("r1", _env())
        event = store.get_event_by_ref(ref)
        assert event is not None
        assert event["event_type"] == "RUN_START"
        store.close()

    def test_rejects_future_schema(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        env = _env()
        env["event_schema_version"] = 999
        with pytest.raises(ValueError, match="newer than supported"):
            store.append_event("r1", env)
        store.close()

    def test_rejects_unknown_event_type(self):
        with pytest.raises(ValueError, match="Unknown event_type"):
            _env(event_type="BOGUS")


class TestRunMetadata:
    def test_ensure_run_idempotent(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")
        store.ensure_run("r1", "p", "0", "g")  # no error
        run = store.get_run("r1")
        assert run is not None
        assert run["policy_id"] == "p"
        store.close()

    def test_missing_run(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        assert store.get_run("nope") is None
        store.close()


class TestRetentionWithBlobs:
    """Integration test: retention policy + blob lifecycle."""

    def test_expired_blob_warns_on_completeness(self, tmp_path):
        store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
        store.initialize_schema()
        store.ensure_run("r1", "p", "0", "g")

        ref = store.put_blob(b'{"data": 1}', content_type="application/json")
        store.append_event("r1", _env(
            event_type="EVIDENCE_PUT", stage="COLLECT",
            payload={
                "key": "model_output",
                "evidence": {"ref": ref.ref, "sha256": ref.sha256,
                             "content_type": ref.content_type, "bytes_len": ref.bytes_len},
                "meta": {},
            },
        ))

        # Force-expire the blob
        store._conn.execute(
            "UPDATE blobs SET created_at = '2020-01-01T00:00:00+00:00'"
        )
        store._conn.commit()
        policy = RetentionPolicy(public_ttl_seconds=3600)
        purge_expired(store, policy)

        # Receipt completeness should WARN (not FAIL) for expired blobs
        result = ReceiptCompletenessInvariant(
            ["model_output"], verify_blobs=True
        ).evaluate({"store": store, "run_id": "r1"})
        assert result.verdict == Verdict.WARN
        assert any(r.code == "BLOB_EXPIRED" for r in result.reasons)
        store.close()
