# SPDX-License-Identifier: Apache-2.0
"""Invariants: run.single_finalize + run.stage_required_path

run.single_finalize:
  Exactly one RUN_FINALIZE per run. Zero = incomplete, >1 = corruption.

run.stage_required_path:
  Required stages appear in order. Doesn't require ALL transitions —
  just that the required stages are visited in sequence.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.types import InvariantResult, Reason, Verdict


class SingleFinalizeInvariant:
    """Verify exactly one RUN_FINALIZE event per run."""

    invariant_id = "run.single_finalize"

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        store = ctx["store"]
        run_id = ctx["run_id"]

        finalize_events = store.get_events(run_id, event_type="RUN_FINALIZE")
        count = len(finalize_events)

        if count == 0:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="NO_FINALIZE",
                    msg="Run has no RUN_FINALIZE event",
                )],
            )

        if count > 1:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="MULTIPLE_FINALIZE",
                    msg=f"Run has {count} RUN_FINALIZE events (expected exactly 1)",
                )],
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
        )


class StageRequiredPathInvariant:
    """Verify required stages appear in order."""

    invariant_id = "run.stage_required_path"

    def __init__(self, required_path: list[str]):
        self.required_path = required_path

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        store = ctx["store"]
        run_id = ctx["run_id"]

        all_events = store.get_events(run_id)
        reasons: list[Reason] = []

        # Extract the stage sequence from events (deduplicated, preserving order)
        visited: list[str] = []
        for ev in all_events:
            stage = ev.get("stage", "")
            if not visited or visited[-1] != stage:
                visited.append(stage)

        # Check that required stages appear in order
        path_idx = 0
        for stage in visited:
            if path_idx < len(self.required_path) and stage == self.required_path[path_idx]:
                path_idx += 1

        if path_idx < len(self.required_path):
            missing = self.required_path[path_idx:]
            reasons.append(Reason(
                code="MISSING_STAGES",
                msg=(
                    f"Required stages not visited (in order): {missing}. "
                    f"Visited: {visited}"
                ),
            ))

        if reasons:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=reasons,
                meta={"visited": visited, "required": self.required_path},
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
            meta={"visited": visited, "required": self.required_path},
        )
