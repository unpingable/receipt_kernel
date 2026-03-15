# SPDX-License-Identifier: Apache-2.0
"""Tests for oracle.independence_minimum invariant.

Tests:
- Default policy (class 0) passes everything
- Custom policy can fail low-class oracles
- Skips non-oracle evidence (no false positives)
- Skips non-required modes
- Missing context handling (UNKNOWN/FAIL)
- Policy lookup for missing keys defaults to 0
- Multiple oracle refs: max class used
- build_blob_class_map helper
"""

from __future__ import annotations

import json

import pytest

from receipt_kernel.envelope import make_envelope
from receipt_kernel.invariants.oracle_independence import (
    DEFAULT_ORACLE_POLICY,
    OracleIndependenceInvariant,
)
from receipt_kernel.invariants._helpers import build_blob_class_map
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.types import Verdict


# ---------------------------------------------------------------------------
# Helpers (following test_hallucination_invariants pattern)
# ---------------------------------------------------------------------------

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
                   evidence_kind=None, oracle_class=None):
    """Store a blob and emit EVIDENCE_PUT, returning the blob ref."""
    blob = store.put_blob(data, content_type=content_type)
    meta = {}
    if evidence_kind is not None:
        meta["evidence_kind"] = evidence_kind
    if oracle_class is not None:
        meta["oracle_class"] = oracle_class
    env = make_envelope(
        event_type="EVIDENCE_PUT", stage="COLLECT",
        policy_id="test", policy_version="0.1",
        stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
        payload={"key": key, "evidence": blob.to_dict(), "meta": meta},
        blob_refs=[blob.ref],
    )
    store.append_event(run_id, env)
    return blob


def _put_claims_map(store, run_id, claims):
    """Store a claims_map blob and emit EVIDENCE_PUT."""
    doc = {"schema_version": 1, "claims": claims}
    return _put_evidence(store, run_id, "claims_map", json.dumps(doc).encode())


def _ctx(store, run_id):
    return {"store": store, "run_id": run_id}


# ---------------------------------------------------------------------------
# Tests: build_blob_class_map helper
# ---------------------------------------------------------------------------

class TestBuildBlobClassMap:
    def test_extracts_oracle_class(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "test_log", b'{"ok":true}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        m = build_blob_class_map(store, "r1")
        assert m[blob.ref] == 0

    def test_ignores_non_oracle_blobs(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        _put_evidence(store, "r1", "output", b"text",
                      evidence_kind="model:self_report")
        m = build_blob_class_map(store, "r1")
        assert m == {}

    def test_multiple_oracle_classes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        b0 = _put_evidence(store, "r1", "local", b'{"a":1}',
                           evidence_kind="oracle:pytest_log", oracle_class=0)
        b1 = _put_evidence(store, "r1", "ci", b'{"b":2}',
                           evidence_kind="oracle:pytest_log", oracle_class=1)
        m = build_blob_class_map(store, "r1")
        assert m[b0.ref] == 0
        assert m[b1.ref] == 1


# ---------------------------------------------------------------------------
# Tests: Default policy (all class 0 — inert)
# ---------------------------------------------------------------------------

class TestDefaultPolicy:
    def test_all_defaults_are_zero(self):
        for key, val in DEFAULT_ORACLE_POLICY.items():
            assert val == 0, f"Default policy for {key} should be 0, got {val}"

    def test_class0_oracle_passes(self, tmp_path):
        """Class 0 oracle should pass with default policy."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "test_log", b'{"tests":5}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta["claims_with_oracle"] == 1
        assert result.meta["claims_passing"] == 1

    def test_no_claims_passes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        _put_claims_map(store, "r1", [])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta.get("claim_count") == 0

    def test_claims_without_oracle_not_checked(self, tmp_path):
        """Claims with only non-oracle evidence should not be checked."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "output", b"text",
                             evidence_kind="model:self_report")
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta["claims_with_oracle"] == 0


# ---------------------------------------------------------------------------
# Tests: Custom policy (enforce higher classes)
# ---------------------------------------------------------------------------

class TestCustomPolicy:
    def test_class0_fails_when_class1_required(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "test_log", b'{"tests":5}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert len(result.reasons) == 1
        assert result.reasons[0].code == "ORACLE_CLASS_BELOW_MINIMUM"
        assert "class 0 < required 1" in result.reasons[0].msg

    def test_class1_passes_when_class1_required(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "ci_log", b'{"tests":5}',
                             evidence_kind="oracle:pytest_log", oracle_class=1)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS

    def test_class2_passes_when_class1_required(self, tmp_path):
        """Higher class always meets lower requirement."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "ext_ci", b'{"tests":5}',
                             evidence_kind="oracle:pytest_log", oracle_class=2)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS

    def test_max_class_from_multiple_refs(self, tmp_path):
        """If multiple oracle refs, max class is used."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        b0 = _put_evidence(store, "r1", "local", b'{"a":1}',
                           evidence_kind="oracle:pytest_log", oracle_class=0)
        b1 = _put_evidence(store, "r1", "ci", b'{"b":2}',
                           evidence_kind="oracle:pytest_log", oracle_class=1)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [b0.ref, b1.ref],
        }])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS

    def test_multiple_claims_mixed_results(self, tmp_path):
        """One claim passes, one fails — overall FAIL."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        b0 = _put_evidence(store, "r1", "local", b'{"a":1}',
                           evidence_kind="oracle:pytest_log", oracle_class=0)
        b1 = _put_evidence(store, "r1", "ci", b'{"b":2}',
                           evidence_kind="oracle:pytest_log", oracle_class=1)
        _put_claims_map(store, "r1", [
            {"id": "c1", "confidence": "high", "evidence_refs": [b0.ref]},
            {"id": "c2", "confidence": "high", "evidence_refs": [b1.ref]},
        ])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert result.meta["claims_with_oracle"] == 2
        assert result.meta["claims_passing"] == 1
        assert len(result.reasons) == 1
        assert "c1" in result.reasons[0].msg

    def test_medium_confidence_separate_policy(self, tmp_path):
        """Medium claims can have different requirements than high."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "local", b'{"a":1}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "medium", "evidence_refs": [blob.ref],
        }])

        # high requires class 1, medium allows class 0
        policy = {("factual", "high"): 1, ("factual", "medium"): 0}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS


# ---------------------------------------------------------------------------
# Tests: Mode handling
# ---------------------------------------------------------------------------

class TestModeHandling:
    def test_exploratory_mode_skipped_by_default(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", mode="exploratory")
        _put_claims_map(store, "r1", [{"id": "c1", "confidence": "high", "evidence_refs": []}])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        assert result.meta.get("skipped") is True

    def test_custom_modes(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", mode="strict")
        blob = _put_evidence(store, "r1", "t", b'{}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("strict", "high"): 2}
        inv = OracleIndependenceInvariant(
            require_in_modes=("strict",),
            policy=policy,
        )
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL

    def test_mixed_mode_checked(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1", mode="mixed")
        blob = _put_evidence(store, "r1", "t", b'{"x":1}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS


# ---------------------------------------------------------------------------
# Tests: Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_missing_context(self):
        inv = OracleIndependenceInvariant()
        result = inv.evaluate({})
        assert result.verdict == Verdict.UNKNOWN
        assert result.reasons[0].code == "CONTEXT_MISSING"

    def test_missing_run_mode(self, tmp_path):
        store = _make_store(tmp_path)
        # Create run without mode in meta
        store.ensure_run(
            run_id="r1", policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default", meta={},
        )
        env = make_envelope(
            event_type="RUN_START", stage="START",
            policy_id="test", policy_version="0.1",
            stage_graph_id="v1_default", actor_kind="pytest", actor_id="test",
            payload={"meta": {}},
        )
        store.append_event("r1", env)

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert result.reasons[0].code == "RUN_MODE_MISSING"

    def test_missing_claims_map(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.UNKNOWN
        assert result.reasons[0].code == "CLAIMS_MAP_MISSING"


# ---------------------------------------------------------------------------
# Tests: Policy lookup
# ---------------------------------------------------------------------------

class TestPolicyLookup:
    def test_missing_key_defaults_to_zero(self):
        inv = OracleIndependenceInvariant(policy={})
        assert inv.min_class_for("factual", "high") == 0
        assert inv.min_class_for("unknown_mode", "unknown_level") == 0

    def test_explicit_policy_returned(self):
        policy = {("factual", "high"): 3}
        inv = OracleIndependenceInvariant(policy=policy)
        assert inv.min_class_for("factual", "high") == 3
        assert inv.min_class_for("factual", "medium") == 0

    def test_default_policy_covers_standard_combos(self):
        """All standard (mode, level) combos have entries."""
        for mode in ("factual", "mixed", "exploratory"):
            for level in ("high", "medium", "low"):
                assert (mode, level) in DEFAULT_ORACLE_POLICY

    def test_scope_axis_takes_precedence(self):
        """3-tuple (mode, level, scope) overrides 2-tuple (mode, level)."""
        policy = {
            ("factual", "high"): 0,
            ("factual", "high", "auth"): 2,
        }
        inv = OracleIndependenceInvariant(policy=policy)
        assert inv.min_class_for("factual", "high") == 0
        assert inv.min_class_for("factual", "high", scope="auth") == 2

    def test_scope_falls_back_to_2tuple(self):
        """If 3-tuple not found, falls back to 2-tuple."""
        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        assert inv.min_class_for("factual", "high", scope="auth") == 1

    def test_scope_none_uses_2tuple(self):
        """scope=None always uses 2-tuple lookup."""
        policy = {
            ("factual", "high"): 0,
            ("factual", "high", "auth"): 2,
        }
        inv = OracleIndependenceInvariant(policy=policy)
        assert inv.min_class_for("factual", "high", scope=None) == 0


# ---------------------------------------------------------------------------
# Tests: Claim details surfacing (debuggability)
# ---------------------------------------------------------------------------

class TestClaimDetails:
    """Verify that meta.claim_details surfaces min_required/observed_class per claim."""

    def test_pass_shows_details(self, tmp_path):
        """Even when passing, each claim shows min=0 observed=0."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "t", b'{"ok":true}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.PASS
        details = result.meta["claim_details"]
        assert len(details) == 1
        assert details[0] == {
            "claim_id": "c1",
            "min_required": 0,
            "observed_class": 0,
            "satisfied": True,
        }

    def test_fail_shows_details(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "t", b'{}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("factual", "high"): 2}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        details = result.meta["claim_details"]
        assert len(details) == 1
        assert details[0]["min_required"] == 2
        assert details[0]["observed_class"] == 0
        assert details[0]["satisfied"] is False

    def test_mixed_claims_all_in_details(self, tmp_path):
        """All oracle-backed claims appear in details, pass or fail."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        b0 = _put_evidence(store, "r1", "local", b'{"a":1}',
                           evidence_kind="oracle:pytest_log", oracle_class=0)
        b1 = _put_evidence(store, "r1", "ci", b'{"b":2}',
                           evidence_kind="oracle:pytest_log", oracle_class=1)
        _put_claims_map(store, "r1", [
            {"id": "c1", "confidence": "high", "evidence_refs": [b0.ref]},
            {"id": "c2", "confidence": "high", "evidence_refs": [b1.ref]},
        ])

        policy = {("factual", "high"): 1}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        details = result.meta["claim_details"]
        assert len(details) == 2
        d_by_id = {d["claim_id"]: d for d in details}
        assert d_by_id["c1"]["satisfied"] is False
        assert d_by_id["c1"]["observed_class"] == 0
        assert d_by_id["c2"]["satisfied"] is True
        assert d_by_id["c2"]["observed_class"] == 1

    def test_no_oracle_claims_empty_details(self, tmp_path):
        """When no claims cite oracles, details list is empty."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "out", b"text",
                             evidence_kind="model:self_report")
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.meta.get("claim_details") == []

    def test_details_serializable(self, tmp_path):
        """claim_details round-trips through to_dict()."""
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "t", b'{}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        d = result.to_dict()
        # claim_details is in meta, which to_dict() includes
        assert "claim_details" in d["meta"]
        import json
        json.dumps(d)  # should not raise


# ---------------------------------------------------------------------------
# Tests: Integration with evidence_gate bridge output
# ---------------------------------------------------------------------------

class TestIntegrationShape:
    def test_invariant_id(self):
        inv = OracleIndependenceInvariant()
        assert inv.invariant_id == "oracle.independence_minimum"

    def test_result_serializable(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "t", b'{}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        inv = OracleIndependenceInvariant()
        result = inv.evaluate(_ctx(store, "r1"))
        d = result.to_dict()
        assert d["invariant_id"] == "oracle.independence_minimum"
        assert d["verdict"] == "pass"
        assert isinstance(d["meta"], dict)

    def test_fail_result_has_pointers(self, tmp_path):
        store = _make_store(tmp_path)
        _start_run(store, "r1")
        blob = _put_evidence(store, "r1", "t", b'{}',
                             evidence_kind="oracle:pytest_log", oracle_class=0)
        _put_claims_map(store, "r1", [{
            "id": "c1", "confidence": "high", "evidence_refs": [blob.ref],
        }])

        policy = {("factual", "high"): 2}
        inv = OracleIndependenceInvariant(policy=policy)
        result = inv.evaluate(_ctx(store, "r1"))
        assert result.verdict == Verdict.FAIL
        assert blob.ref in result.reasons[0].pointers

    def test_imported_from_invariants_package(self):
        """Verify invariant is accessible from the main package."""
        from receipt_kernel.invariants import OracleIndependenceInvariant as Imported
        assert Imported is OracleIndependenceInvariant
