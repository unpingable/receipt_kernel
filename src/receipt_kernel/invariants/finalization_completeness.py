# SPDX-License-Identifier: Apache-2.0
"""Invariant: finalization.completeness

Verifies:
1. A RUN_FINALIZE event exists
2. The finalize event has an overall_verdict
3. If require_decision_ref: the finalize event references a DECISION or EVALUATION
4. No invisible endings: the finalize is the last event in the run
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.types import InvariantResult, Reason, Verdict


class FinalizationCompletenessInvariant:
    """Verify runs end cleanly with attested finalization."""

    invariant_id = "finalization.completeness"

    def __init__(
        self,
        require_decision_ref: bool = False,
        allow_warn_as_success: bool = True,
    ):
        self.require_decision_ref = require_decision_ref
        self.allow_warn_as_success = allow_warn_as_success

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        """Evaluate finalization completeness.

        ctx must contain:
        - store: SqliteReceiptStore
        - run_id: str
        """
        store = ctx["store"]
        run_id = ctx["run_id"]

        all_events = store.get_events(run_id)
        reasons: list[Reason] = []

        finalize_events = [
            e for e in all_events if e.get("event_type") == "RUN_FINALIZE"
        ]

        if not finalize_events:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="NO_FINALIZE",
                    msg="No RUN_FINALIZE event found in run",
                )],
            )

        finalize = finalize_events[-1]
        payload = finalize.get("payload", {})

        # Must have overall_verdict
        overall = payload.get("overall_verdict")
        if overall is None:
            reasons.append(Reason(
                code="NO_VERDICT",
                msg="RUN_FINALIZE event missing overall_verdict in payload",
            ))

        # Check decision reference
        if self.require_decision_ref:
            event_refs = finalize.get("refs", {}).get("events", [])
            if not event_refs:
                reasons.append(Reason(
                    code="NO_DECISION_REF",
                    msg="RUN_FINALIZE has no event references (expected DECISION or EVALUATION ref)",
                ))

        # Finalize must be the last event
        if all_events and all_events[-1].get("event_type") != "RUN_FINALIZE":
            reasons.append(Reason(
                code="NOT_LAST_EVENT",
                msg=(
                    f"RUN_FINALIZE is not the last event. "
                    f"Last event type: {all_events[-1].get('event_type')!r}"
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
            meta={"overall_verdict": overall},
        )
