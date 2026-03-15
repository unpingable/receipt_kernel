# SPDX-License-Identifier: Apache-2.0
"""Tests for hallucination invariants.

These verify structural binding between claims ↔ evidence ↔ tools ↔ output.
No NLP, no heuristics — just accounting.
"""

from __future__ import annotations

import json

import pytest

from receipt_kernel.envelope import make_envelope
from receipt_kernel.invariants.claims_evidence_binding import ClaimsEvidenceBindingInvariant
from receipt_kernel.invariants.confidence_sanity import ConfidenceSanityInvariant
from receipt_kernel.invariants.epistemic_mode_requirements import EpistemicModeRequirementsInvariant
from receipt_kernel.invariants.output_bound_to_claims import OutputBoundToClaimsInvariant
from receipt_kernel.invariants.refs_closed_world import RefsClosedWorldInvariant
from receipt_kernel.invariants.tool_trace_consistency import ToolTraceConsistencyInvariant
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import Verdict


# ---- helpers ----

def _make_store(tmp_path) -> SqliteReceiptStore:
    store = SqliteReceiptStore(str(tmp_path / "test.db"), redaction_enabled=False)
    store.initialize_schema()
    return store


def _start_run(store, run_id, mode="factual"):
    """Create a run with a RUN_START event that sets mode."""
    store.ensure_run(
        run_id=run_id, policy_id="test", policy_version="0.1",
        stage_graph_id="v1_default", meta={"mode": mode},
    )
    env = make_envelope(
        event_type="RUN_START", stage="START",
        policy_id="test", policy_version="0.1",
        stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
        payload={"meta": {"mode": mode}},
    )
    store.append_event(run_id, env)


def _put_evidence(store, run_id, key, data, content_type="application/json",
                   evidence_kind=None):
    """Store a blob and emit EVIDENCE_PUT, returning the blob ref."""
    blob = store.put_blob(data, content_type=content_type)
    meta = {}
    if evidence_kind is not None:
        meta["evidence_kind"] = evidence_kind
    env = make_envelope(
        event_type="EVIDENCE_PUT", stage="COLLECT",
        policy_id="test", policy_version="0.1",
        stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
        payload={"key": key, "evidence": blob.to_dict(), "meta": meta},
        blob_refs=[blob.ref],
    )
    store.append_event(run_id, env)
    return blob


def _put_claims_map(store, run_id, claims, output_sha256=None, output_ref=None):
    """Store a claims_map blob and emit EVIDENCE_PUT."""
    doc = {"schema_version": 1, "claims": claims}
    if output_sha256:
        doc["output_sha256"] = output_sha256
    if output_ref:
        doc["output_ref"] = output_ref
    return _put_evidence(store, run_id, "claims_map", json.dumps(doc).encode())


def _put_tool_trace(store, run_id, calls):
    """Store a tool_trace blob and emit EVIDENCE_PUT."""
    doc = {"schema_version": 1, "calls": calls}
    return _put_evidence(store, run_id, "tool_trace", json.dumps(doc).encode())


def _ctx(store, run_id):
    return {"store": store, "run_id": run_id}


# =============================================================================
# claims.evidence_binding
# =============================================================================

class TestClaimsEvidenceBinding:

    def test_factual_mode_missing_claims_map_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "CLAIMS_MAP_MISSING" for r in result.reasons)
        store.close()

    def test_factual_mode_claim_without_refs_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X happened", "evidence_refs": [], "confidence": "high"},
        ])
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "CLAIM_UNBOUND" for r in result.reasons)
        store.close()

    def test_factual_mode_claim_with_missing_blob_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X happened",
             "evidence_refs": ["blob://sha256:deadbeef0000000000000000000000000000000000000000000000000000dead"],
             "confidence": "high"},
        ])
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "EVIDENCE_REF_MISSING" for r in result.reasons)
        store.close()

    def test_factual_mode_properly_bound_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"data": true}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X happened", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_creative_mode_skips(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta.get("skipped") is True
        store.close()

    def test_missing_mode_fails(self, tmp_path):
        """Mode is mandatory — you don't get to be vague."""
        store = _make_store(tmp_path)
        store.ensure_run(
            run_id="r1", policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default",
        )
        # RUN_START without mode in meta
        env = make_envelope(
            event_type="RUN_START", stage="START",
            policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
            payload={"meta": {}},
        )
        store.append_event("r1", env)
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "RUN_MODE_MISSING" for r in result.reasons)
        store.close()

    def test_no_store_returns_unknown(self):
        result = ClaimsEvidenceBindingInvariant().evaluate({"store": None, "run_id": "x"})
        assert result.verdict == Verdict.UNKNOWN

    def test_malformed_claims_list_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # claims is a string, not a list
        blob = store.put_blob(json.dumps({"schema_version": 1, "claims": "not a list"}).encode())
        env = make_envelope(
            event_type="EVIDENCE_PUT", stage="COLLECT",
            policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
            payload={"key": "claims_map", "evidence": blob.to_dict()},
            blob_refs=[blob.ref],
        )
        store.append_event("r1", env)
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "CLAIMS_MAP_MALFORMED" for r in result.reasons)
        store.close()

    def test_mixed_mode_enforced(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "mixed")
        result = ClaimsEvidenceBindingInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL  # missing claims_map
        store.close()


# =============================================================================
# tools.trace_consistency
# =============================================================================

class TestToolTraceConsistency:

    def test_claims_with_tool_ids_but_no_trace_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"result": 42}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "Tool returned 42",
             "evidence_refs": [blob.ref], "confidence": "high",
             "tool_call_ids": ["t1"]},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "TOOL_TRACE_MISSING" for r in result.reasons)
        store.close()

    def test_tool_ids_present_in_trace_with_outputs_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"result": 42}')
        out1 = _put_evidence(store, "r1", "t1_output", b'{"web": "result"}')
        out2 = _put_evidence(store, "r1", "t2_output", b'{"calc": 42}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "Tool returned 42",
             "evidence_refs": [blob.ref], "confidence": "high",
             "tool_call_ids": ["t1", "t2"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "web.run", "ok": True, "output_ref": out1.ref},
            {"id": "t2", "tool": "calc.eval", "ok": True, "output_ref": out2.ref},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_missing_tool_id_in_trace_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"result": 42}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "Tool returned 42",
             "evidence_refs": [blob.ref], "confidence": "high",
             "tool_call_ids": ["t1", "t2", "t3"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "web.run", "ok": True},
            # t2 and t3 missing
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        missing_reason = [r for r in result.reasons if r.code == "TOOL_CALL_MISSING"]
        assert len(missing_reason) == 1
        assert "t2" in missing_reason[0].msg
        assert "t3" in missing_reason[0].msg
        store.close()

    def test_no_tool_ids_in_claims_passes(self, tmp_path):
        """Claims without tool_call_ids don't need a trace."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"result": 42}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X happened", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_creative_mode_skips(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta.get("skipped") is True
        store.close()

    def test_malformed_trace_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"r": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        # tool_trace with calls as a string, not list
        _put_evidence(store, "r1", "tool_trace",
                       json.dumps({"schema_version": 1, "calls": "not_a_list"}).encode())
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "TOOL_TRACE_MALFORMED" for r in result.reasons)
        store.close()

    # --- Tool output binding tests ---

    def test_output_ref_in_run_passes(self, tmp_path):
        """Tool output_ref pointing to in-run blob passes."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        output_blob = _put_evidence(store, "r1", "tool_result", b'{"result": 42}')
        blob = _put_evidence(store, "r1", "source", b'{"x": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True, "output_ref": output_blob.ref},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_output_ref_not_in_run_fails(self, tmp_path):
        """Tool output_ref pointing to blob NOT from this run → FAIL."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # Put blob directly (not via EVIDENCE_PUT for r1)
        rogue_blob = store.put_blob(b'rogue output', content_type="text/plain")
        blob = _put_evidence(store, "r1", "source", b'{"x": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True, "output_ref": rogue_blob.ref},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "TOOL_OUTPUT_NOT_IN_RUN" for r in result.reasons)
        store.close()

    def test_output_sha256_in_run_passes(self, tmp_path):
        """Tool output_sha256 resolves to in-run blob passes."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        output_blob = _put_evidence(store, "r1", "tool_result", b'{"result": 42}')
        blob = _put_evidence(store, "r1", "source", b'{"x": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True,
             "output_sha256": output_blob.sha256},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_no_output_binding_factual_fails(self, tmp_path):
        """Factual mode: tool call without output binding → FAIL."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"x": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        # Trace entry has no output_ref or output_sha256
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "TOOL_OUTPUT_UNBOUND" for r in result.reasons)
        store.close()

    def test_no_output_binding_mixed_warns(self, tmp_path):
        """Mixed mode: tool call without output binding → WARN (not FAIL)."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "mixed")
        blob = _put_evidence(store, "r1", "source", b'{"x": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "tool_call_ids": ["t1"]},
        ])
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True},
        ])
        result = ToolTraceConsistencyInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.WARN
        assert any(r.code == "TOOL_OUTPUT_UNBOUND_WARN" for r in result.reasons)
        store.close()


# =============================================================================
# epistemic.mode_requirements
# =============================================================================

class TestEpistemicModeRequirements:

    def test_factual_without_claims_map_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        result = EpistemicModeRequirementsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "MODE_REQUIREMENTS_MISSING" for r in result.reasons)
        store.close()

    def test_factual_with_claims_map_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": ["blob://sha256:abc"], "confidence": "high"},
        ])
        result = EpistemicModeRequirementsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_creative_mode_no_requirements(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = EpistemicModeRequirementsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_unknown_mode_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "yolo")
        result = EpistemicModeRequirementsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "RUN_MODE_UNKNOWN" for r in result.reasons)
        store.close()

    def test_unknown_mode_allowed_warns(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "yolo")
        result = EpistemicModeRequirementsInvariant(
            allow_unknown_modes=True,
        ).evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.WARN
        store.close()

    def test_missing_mode_fails(self, tmp_path):
        store = _make_store(tmp_path)
        store.ensure_run(
            run_id="r1", policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default",
        )
        env = make_envelope(
            event_type="RUN_START", stage="START",
            policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
            payload={"meta": {}},
        )
        store.append_event("r1", env)
        result = EpistemicModeRequirementsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "RUN_MODE_MISSING" for r in result.reasons)
        store.close()

    def test_custom_requirements(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        inv = EpistemicModeRequirementsInvariant(
            requirements={"factual": ("claims_map", "tool_trace")},
        )
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert "claims_map" in result.meta["missing"]
        assert "tool_trace" in result.meta["missing"]
        store.close()


# =============================================================================
# refs.closed_world
# =============================================================================

class TestRefsClosedWorld:

    def test_refs_from_run_pass(self, tmp_path):
        """Evidence refs produced by this run's events are valid."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"data": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = RefsClosedWorldInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_ref_outside_run_fails(self, tmp_path):
        """Evidence ref not produced by this run → citation laundering."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # Store a blob directly (not through an EVIDENCE_PUT event for this run)
        rogue_blob = store.put_blob(b'rogue evidence', content_type="text/plain")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [rogue_blob.ref], "confidence": "high"},
        ])
        result = RefsClosedWorldInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "REFS_OUTSIDE_RUN" for r in result.reasons)
        store.close()

    def test_ref_from_other_run_fails(self, tmp_path):
        """Evidence produced by a different run → still citation laundering."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _start_run(store, "r2", "factual")
        blob_r2 = _put_evidence(store, "r2", "source", b'{"data": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob_r2.ref], "confidence": "high"},
        ])
        result = RefsClosedWorldInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        store.close()

    def test_no_blob_refs_passes(self, tmp_path):
        """Claims with event refs (not blob refs) are outside our scope here."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X",
             "evidence_refs": ["event://r1/2"],  # not a blob ref
             "confidence": "high"},
        ])
        result = RefsClosedWorldInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_creative_mode_skips(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = RefsClosedWorldInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()


# =============================================================================
# output.bound_to_claims
# =============================================================================

class TestOutputBoundToClaims:

    def test_output_ref_matches_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        output_blob = _put_evidence(store, "r1", "final_output", b"The answer is 42.")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "answer is 42",
             "evidence_refs": [output_blob.ref], "confidence": "high"},
        ], output_ref=output_blob.ref)
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_output_sha256_matches_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        output_blob = _put_evidence(store, "r1", "final_output", b"The answer is 42.")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "answer is 42",
             "evidence_refs": [output_blob.ref], "confidence": "high"},
        ], output_sha256=output_blob.sha256)
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_missing_final_output_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": ["blob://sha256:abc"], "confidence": "high"},
        ])
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "FINAL_OUTPUT_MISSING" for r in result.reasons)
        store.close()

    def test_output_not_bound_in_claims_map_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_evidence(store, "r1", "final_output", b"The answer is 42.")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": ["blob://sha256:abc"], "confidence": "high"},
        ])
        # claims_map has no output_ref or output_sha256
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "OUTPUT_NOT_BOUND" for r in result.reasons)
        store.close()

    def test_output_mismatch_fails(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_evidence(store, "r1", "final_output", b"The real answer is 42.")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": ["blob://sha256:abc"], "confidence": "high"},
        ], output_sha256="wrong_hash_not_matching")
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "OUTPUT_MISMATCH" for r in result.reasons)
        store.close()

    def test_creative_mode_skips(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = OutputBoundToClaimsInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()


# =============================================================================
# confidence.sanity
# =============================================================================

class TestConfidenceSanity:

    def test_all_low_confidence_warns(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "maybe X", "evidence_refs": ["blob://sha256:a"], "confidence": "low"},
            {"id": "c2", "text": "maybe Y", "evidence_refs": ["blob://sha256:b"], "confidence": "low"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.WARN
        assert any(r.code == "ALL_LOW_CONFIDENCE" for r in result.reasons)
        store.close()

    def test_some_high_confidence_with_strong_evidence_passes(self, tmp_path):
        """High confidence backed by oracle evidence → PASS."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"data": 1}',
                             evidence_kind="oracle:test_log")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
            {"id": "c2", "text": "Y", "evidence_refs": [blob.ref], "confidence": "low"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_high_confidence_weak_evidence_fails(self, tmp_path):
        """Strength derived from evidence_kind on EVIDENCE_PUT, not claim self-report."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # Evidence tagged as model self-report → WEAK
        blob = _put_evidence(store, "r1", "source", b'{"guess": true}',
                             evidence_kind="model:self_report")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "HIGH_CONFIDENCE_WEAK_EVIDENCE" for r in result.reasons)
        store.close()

    def test_high_confidence_strong_evidence_passes(self, tmp_path):
        """Oracle-backed evidence_kind → STRONG → high confidence allowed."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'{"result": 42}',
                             evidence_kind="oracle:test_log")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_high_confidence_no_kind_defaults_weak(self, tmp_path):
        """Evidence without evidence_kind tag defaults to WEAK."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # No evidence_kind on the EVIDENCE_PUT → defaults to WEAK
        blob = _put_evidence(store, "r1", "source", b'{"data": 1}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert any(r.code == "HIGH_CONFIDENCE_WEAK_EVIDENCE" for r in result.reasons)
        store.close()

    def test_high_confidence_medium_evidence_passes(self, tmp_path):
        """User-provided evidence_kind → MEDIUM → high confidence allowed."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        blob = _put_evidence(store, "r1", "source", b'user document',
                             evidence_kind="user:provided")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref], "confidence": "high"},
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_claim_self_report_strength_ignored(self, tmp_path):
        """evidence_strength on the claim is IGNORED — provenance decides."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        # Claim says "strong" but evidence_kind says model:self_report → WEAK
        blob = _put_evidence(store, "r1", "source", b'{"guess": true}',
                             evidence_kind="model:self_report")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": [blob.ref],
             "confidence": "high", "evidence_strength": "strong"},  # self-report, ignored
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL  # provenance wins
        store.close()

    def test_no_claims_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_creative_mode_skips(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "creative")
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        store.close()

    def test_unspecified_confidence_counts_as_low(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "X", "evidence_refs": ["blob://sha256:a"]},
            # no confidence field → counts as unspecified → treated as low
        ])
        result = ConfidenceSanityInvariant().evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.WARN
        assert any(r.code == "ALL_LOW_CONFIDENCE" for r in result.reasons)
        store.close()


# =============================================================================
# Integration: full factual run with all invariants passing
# =============================================================================

class TestFullFactualRun:
    """End-to-end: a properly-formed factual run passes ALL hallucination invariants."""

    def test_complete_factual_run_passes_all(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")

        # Evidence: a source document (oracle-backed → STRONG)
        source_blob = _put_evidence(
            store, "r1", "source_doc", b'{"population": 8000000}',
            evidence_kind="oracle:retrieval_bundle",
        )

        # Evidence: tool trace with output binding
        _put_tool_trace(store, "r1", [
            {"id": "t1", "tool": "db.query", "ok": True,
             "output_ref": source_blob.ref},
        ])

        # Evidence: final output
        output_blob = _put_evidence(store, "r1", "final_output",
                                     b"The population is 8 million.",
                                     evidence_kind="tool:output")

        # Evidence: claims_map binding everything together
        _put_claims_map(store, "r1", [
            {
                "id": "c1",
                "text": "population is 8 million",
                "evidence_refs": [source_blob.ref],
                "confidence": "high",
                "tool_call_ids": ["t1"],
            },
        ], output_ref=output_blob.ref)

        ctx = _ctx(store, "r1")

        # All 6 hallucination invariants
        assert ClaimsEvidenceBindingInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert ToolTraceConsistencyInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert EpistemicModeRequirementsInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert RefsClosedWorldInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert OutputBoundToClaimsInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert ConfidenceSanityInvariant().evaluate(ctx).verdict == Verdict.PASS

        store.close()

    def test_fabricated_claim_fails_multiple_invariants(self, tmp_path):
        """A claim with no evidence binding should fail multiple invariants."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")

        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "I totally checked this",
             "evidence_refs": [], "confidence": "high"},
        ])

        ctx = _ctx(store, "r1")

        # Should fail: claim has no evidence refs
        assert ClaimsEvidenceBindingInvariant().evaluate(ctx).verdict == Verdict.FAIL
        # Should fail: high confidence but no evidence strength
        # (no strength → not flagged, but empty refs → CLAIM_UNBOUND caught above)

        store.close()

    def test_phantom_tool_fails(self, tmp_path):
        """Claiming tool use without a trace is phantom tooling."""
        store = _make_store(tmp_path)
        _start_run(store, "r1", "factual")

        blob = _put_evidence(store, "r1", "source", b'{"data": true}')
        _put_claims_map(store, "r1", [
            {"id": "c1", "text": "Tool confirmed it",
             "evidence_refs": [blob.ref], "confidence": "high",
             "tool_call_ids": ["phantom_tool_1"]},
        ])

        ctx = _ctx(store, "r1")

        # evidence_binding passes (has refs), but trace_consistency fails
        assert ClaimsEvidenceBindingInvariant().evaluate(ctx).verdict == Verdict.PASS
        assert ToolTraceConsistencyInvariant().evaluate(ctx).verdict == Verdict.FAIL

        store.close()
