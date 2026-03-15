# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for all 6 constitutional invariants."""

from __future__ import annotations

import pytest

from receipt_kernel.envelope import make_envelope
from receipt_kernel.invariants import (
    EvaluationCompletenessInvariant,
    FinalizationCompletenessInvariant,
    LedgerChainValidInvariant,
    ReceiptCompletenessInvariant,
    SingleFinalizeInvariant,
    StageRequiredPathInvariant,
)
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import Verdict


def _make_store(tmp_path) -> SqliteReceiptStore:
    store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
    store.initialize_schema()
    return store


def _env(**kw):
    defaults = dict(
        event_type="RUN_START", stage="START",
        policy_id="test", policy_version="0.0.0",
        stage_graph_id="v1_default",
        actor_kind="pytest", actor_id="test",
        payload={},
    )
    defaults.update(kw)
    return make_envelope(**defaults)


def _build_complete_run(store: SqliteReceiptStore, run_id: str = "run1"):
    """Build a complete, valid run for testing."""
    store.ensure_run(run_id, "test", "0.0.0", "v1_default")

    # RUN_START
    store.append_event(run_id, _env())

    # STAGE_ADVANCE to COLLECT
    store.append_event(run_id, _env(
        event_type="STAGE_ADVANCE", stage="COLLECT",
        payload={"from_stage": "START", "to_stage": "COLLECT", "reason": "normal"},
    ))

    # EVIDENCE_PUT
    blob = store.put_blob(b'{"result": "ok"}', content_type="application/json")
    store.append_event(run_id, _env(
        event_type="EVIDENCE_PUT", stage="COLLECT",
        payload={
            "key": "model_output",
            "evidence": {
                "ref": blob.ref, "sha256": blob.sha256,
                "content_type": blob.content_type, "bytes_len": blob.bytes_len,
            },
            "meta": {},
        },
        blob_refs=[blob.ref],
    ))

    # STAGE_ADVANCE to EVALUATE
    store.append_event(run_id, _env(
        event_type="STAGE_ADVANCE", stage="EVALUATE",
        payload={"from_stage": "COLLECT", "to_stage": "EVALUATE", "reason": "normal"},
    ))

    # EVALUATION
    eval_ref = store.append_event(run_id, _env(
        event_type="EVALUATION", stage="EVALUATE",
        payload={
            "results": [{
                "invariant_id": "receipt.completeness",
                "verdict": "pass",
                "reasons": [],
                "evidence_refs": [],
                "meta": {},
            }],
            "overall_verdict": "pass",
            "evidence_complete": True,
        },
    ))

    # STAGE_ADVANCE to DECIDE
    store.append_event(run_id, _env(
        event_type="STAGE_ADVANCE", stage="DECIDE",
        payload={"from_stage": "EVALUATE", "to_stage": "DECIDE", "reason": "normal"},
    ))

    # DECISION
    dec_ref = store.append_event(run_id, _env(
        event_type="DECISION", stage="DECIDE",
        payload={
            "decision_id": "dec_001",
            "basis": {"overall_verdict": "pass", "blocking_invariants": []},
            "action_plan": [],
        },
        event_refs=[eval_ref],
    ))

    # STAGE_ADVANCE to FINALIZE
    store.append_event(run_id, _env(
        event_type="STAGE_ADVANCE", stage="FINALIZE",
        payload={"from_stage": "DECIDE", "to_stage": "FINALIZE", "reason": "normal"},
    ))

    # RUN_FINALIZE
    store.append_event(run_id, _env(
        event_type="RUN_FINALIZE", stage="FINALIZE",
        payload={"overall_verdict": "pass", "summary": {}},
        event_refs=[eval_ref, dec_ref],
    ))


class TestAllInvariantsOnCompleteRun:
    """All 6 invariants must PASS on a correctly built run."""

    def test_chain_valid(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = LedgerChainValidInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.PASS
        store.close()

    def test_receipt_completeness(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = ReceiptCompletenessInvariant(
            required_keys=["model_output"], verify_blobs=True
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.PASS
        store.close()

    def test_evaluation_completeness(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = EvaluationCompletenessInvariant(
            required_invariants=("receipt.completeness",),
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.PASS
        store.close()

    def test_finalization_completeness(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = FinalizationCompletenessInvariant(
            require_decision_ref=True
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.PASS
        store.close()

    def test_single_finalize(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = SingleFinalizeInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.PASS
        store.close()

    def test_stage_required_path(self, tmp_path):
        store = _make_store(tmp_path)
        _build_complete_run(store)
        result = StageRequiredPathInvariant(
            ["START", "COLLECT", "EVALUATE", "DECIDE", "FINALIZE"]
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.PASS
        store.close()


class TestInvariantFailureCases:
    """Each invariant must correctly FAIL on specific defects."""

    def test_receipt_missing_key(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())
        # No EVIDENCE_PUT for "model_output"
        result = ReceiptCompletenessInvariant(
            required_keys=["model_output"]
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.FAIL
        assert result.reasons[0].code == "MISSING_KEY"
        store.close()

    def test_evaluation_silent_downgrade(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())
        store.append_event("run1", _env(
            event_type="EVALUATION", stage="EVALUATE",
            payload={
                "results": [{"invariant_id": "x", "verdict": "pass"}],
                "overall_verdict": "pass",
                "evidence_complete": False,  # incomplete but claiming pass!
            },
        ))
        result = EvaluationCompletenessInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "SILENT_DOWNGRADE" for r in result.reasons)
        store.close()

    def test_evaluation_verdict_inconsistency(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())
        store.append_event("run1", _env(
            event_type="EVALUATION", stage="EVALUATE",
            payload={
                "results": [{"invariant_id": "x", "verdict": "fail"}],
                "overall_verdict": "pass",  # claiming pass despite fail!
                "evidence_complete": True,
            },
        ))
        result = EvaluationCompletenessInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "VERDICT_INCONSISTENCY" for r in result.reasons)
        store.close()

    def test_finalization_no_finalize(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())
        result = FinalizationCompletenessInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.FAIL
        assert result.reasons[0].code == "NO_FINALIZE"
        store.close()

    def test_double_finalize(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())
        store.append_event("run1", _env(
            event_type="RUN_FINALIZE", stage="FINALIZE",
            payload={"overall_verdict": "pass", "summary": {}},
        ))
        store.append_event("run1", _env(
            event_type="RUN_FINALIZE", stage="FINALIZE",
            payload={"overall_verdict": "pass", "summary": {}},
        ))
        result = SingleFinalizeInvariant().evaluate(
            {"store": store, "run_id": "run1"}
        )
        assert result.verdict == Verdict.FAIL
        assert result.reasons[0].code == "MULTIPLE_FINALIZE"
        store.close()

    def test_missing_stages(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run("run1", "test", "0.0.0", "v1_default")
        store.append_event("run1", _env())  # START only
        store.append_event("run1", _env(
            event_type="RUN_FINALIZE", stage="FINALIZE",
            payload={"overall_verdict": "pass", "summary": {}},
        ))
        result = StageRequiredPathInvariant(
            ["START", "COLLECT", "EVALUATE", "DECIDE", "FINALIZE"]
        ).evaluate({"store": store, "run_id": "run1"})
        assert result.verdict == Verdict.FAIL
        assert result.reasons[0].code == "MISSING_STAGES"
        store.close()


class TestVerdictSemantics:
    """Verify Verdict enum semantics."""

    def test_pass_is_success(self):
        assert Verdict.PASS.is_success()
        assert not Verdict.PASS.is_failure()

    def test_warn_is_success(self):
        assert Verdict.WARN.is_success()
        assert not Verdict.WARN.is_failure()

    def test_fail_is_failure(self):
        assert Verdict.FAIL.is_failure()
        assert not Verdict.FAIL.is_success()

    def test_unknown_is_failure(self):
        """UNKNOWN must be treated as failure — no silent downgrade."""
        assert Verdict.UNKNOWN.is_failure()
        assert not Verdict.UNKNOWN.is_success()
