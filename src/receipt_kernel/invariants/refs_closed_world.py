# SPDX-License-Identifier: Apache-2.0
"""Invariant: refs.closed_world

Every evidence_ref in claims_map must be present in some EVIDENCE_PUT
event in this run. Prevents "citation laundering" — pointing at blobs
the run didn't produce.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.invariants._helpers import (
    collect_run_blob_refs,
    get_run_mode,
    load_evidence_json,
)
from receipt_kernel.types import InvariantResult, Reason, Verdict


class RefsClosedWorldInvariant:
    """Verify claims only reference evidence produced by this run."""

    invariant_id = "refs.closed_world"

    def __init__(self, *, require_in_modes: tuple[str, ...] = ("factual", "mixed")):
        self._modes = require_in_modes

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        store = ctx.get("store")
        run_id = ctx.get("run_id")
        if store is None or not run_id:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(code="CONTEXT_MISSING", msg="store/run_id not provided")],
            )

        mode = get_run_mode(store, str(run_id))
        if mode is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(code="RUN_MODE_MISSING", msg="RUN_START.meta.mode is required")],
            )

        if mode not in self._modes:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "skipped": True},
            )

        claims_doc = load_evidence_json(store, str(run_id), "claims_map")
        if claims_doc is None:
            # Let claims.evidence_binding own this failure
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(code="CLAIMS_MAP_MISSING", msg="cannot verify closed-world without claims_map")],
                meta={"mode": mode},
            )

        claims = claims_doc.get("claims") or []
        claimed_refs: set[str] = set()
        for c in claims:
            if isinstance(c, dict):
                for r in c.get("evidence_refs") or []:
                    if isinstance(r, str) and r.startswith("blob://"):
                        claimed_refs.add(r)

        if not claimed_refs:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "refs_checked": 0},
            )

        # Collect all blob refs produced by this run's EVIDENCE_PUT events
        run_refs = collect_run_blob_refs(store, str(run_id))

        orphans = sorted(claimed_refs - run_refs)
        if orphans:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="REFS_OUTSIDE_RUN",
                    msg=f"claims reference {len(orphans)} blob(s) not produced by this run",
                    pointers=tuple(orphans),
                )],
                meta={"mode": mode, "orphans": orphans},
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
            reasons=[],
            meta={"mode": mode, "refs_checked": len(claimed_refs)},
        )
