# SPDX-License-Identifier: Apache-2.0
"""Invariant: evaluation.completeness

Verifies:
1. At least one EVALUATION event exists
2. The evaluation is attested (has results with verdicts)
3. No silent downgrade: if evidence is incomplete, overall_verdict cannot be PASS
4. Required invariants were evaluated
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.types import InvariantResult, Reason, Verdict


class EvaluationCompletenessInvariant:
    """Verify that evaluations are attested and non-downgrading."""

    invariant_id = "evaluation.completeness"

    def __init__(
        self,
        required_evidence_keys: list[str] | None = None,
        required_invariants: tuple[str, ...] = (),
        verify_blobs: bool = False,
        require_receipt_completeness_in_results: bool = False,
    ):
        self.required_evidence_keys = required_evidence_keys or []
        self.required_invariants = required_invariants
        self.verify_blobs = verify_blobs
        self.require_receipt_completeness_in_results = require_receipt_completeness_in_results

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        """Evaluate evaluation completeness.

        ctx must contain:
        - store: SqliteReceiptStore
        - run_id: str
        """
        store = ctx["store"]
        run_id = ctx["run_id"]

        eval_events = store.get_events(run_id, event_type="EVALUATION")
        reasons: list[Reason] = []

        if not eval_events:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="NO_EVALUATION",
                    msg="No EVALUATION events found in run",
                )],
            )

        # Check the latest evaluation event
        latest = eval_events[-1]
        payload = latest.get("payload", {})
        results = payload.get("results", [])
        overall_verdict = payload.get("overall_verdict")
        evidence_complete = payload.get("evidence_complete", False)

        # Must have results
        if not results:
            reasons.append(Reason(
                code="EMPTY_RESULTS",
                msg="EVALUATION event has no results",
            ))

        # Must have overall_verdict
        if overall_verdict is None:
            reasons.append(Reason(
                code="NO_OVERALL_VERDICT",
                msg="EVALUATION event missing overall_verdict",
            ))

        # No silent downgrade: if evidence is incomplete, can't claim PASS
        if overall_verdict == "pass" and not evidence_complete:
            reasons.append(Reason(
                code="SILENT_DOWNGRADE",
                msg=(
                    "overall_verdict is 'pass' but evidence_complete is False. "
                    "Incomplete evidence cannot produce a PASS verdict."
                ),
            ))

        # Check required invariants were evaluated
        evaluated_ids = {r.get("invariant_id") for r in results}
        for req_inv in self.required_invariants:
            if req_inv not in evaluated_ids:
                reasons.append(Reason(
                    code="MISSING_INVARIANT",
                    msg=f"Required invariant {req_inv!r} not found in evaluation results",
                ))

        # Check for failed invariants that weren't reflected in overall
        if overall_verdict == "pass":
            for result in results:
                rv = result.get("verdict", "")
                if rv in ("fail", "unknown"):
                    reasons.append(Reason(
                        code="VERDICT_INCONSISTENCY",
                        msg=(
                            f"Invariant {result.get('invariant_id', '?')!r} "
                            f"has verdict={rv!r} but overall_verdict is 'pass'"
                        ),
                    ))

        if reasons:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=reasons,
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
            meta={
                "evaluation_count": len(eval_events),
                "invariants_evaluated": sorted(evaluated_ids - {None}),
            },
        )
