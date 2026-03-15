# SPDX-License-Identifier: Apache-2.0
"""Invariant: output.bound_to_claims

The claims_map must bind to the actual output blob via output_ref.
Prevents divergence between what was evaluated and what the user saw.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.invariants._helpers import (
    get_evidence_blob_sha,
    get_run_mode,
    load_evidence_json,
)
from receipt_kernel.types import InvariantResult, Reason, Verdict


class OutputBoundToClaimsInvariant:
    """Verify claims_map references the actual final output blob."""

    invariant_id = "output.bound_to_claims"

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

        # Check that final_output evidence exists
        output_sha = get_evidence_blob_sha(store, str(run_id), "final_output")
        if output_sha is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="FINAL_OUTPUT_MISSING",
                    msg="final_output evidence blob required in factual/mixed mode",
                )],
                meta={"mode": mode},
            )

        # Check that claims_map references this output
        claims_doc = load_evidence_json(store, str(run_id), "claims_map")
        if claims_doc is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(code="CLAIMS_MAP_MISSING", msg="cannot verify output binding without claims_map")],
                meta={"mode": mode},
            )

        # claims_map must have output_ref or output_sha256
        claims_output_ref = claims_doc.get("output_ref")
        claims_output_sha = claims_doc.get("output_sha256")

        expected_ref = f"blob://sha256:{output_sha}"

        if claims_output_ref == expected_ref or claims_output_sha == output_sha:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                evidence_refs=[expected_ref],
                meta={"mode": mode},
            )

        if claims_output_ref is None and claims_output_sha is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="OUTPUT_NOT_BOUND",
                    msg="claims_map has no output_ref or output_sha256",
                )],
                meta={"mode": mode},
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.FAIL,
            reasons=[Reason(
                code="OUTPUT_MISMATCH",
                msg=(
                    f"claims_map output binding doesn't match final_output blob: "
                    f"expected sha={output_sha[:16]}..."
                ),
            )],
            meta={"mode": mode},
        )
