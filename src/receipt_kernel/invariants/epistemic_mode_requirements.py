# SPDX-License-Identifier: Apache-2.0
"""Invariant: epistemic.mode_requirements

Certain run modes impose minimum evidence requirements.
If mode is missing → FAIL (you don't get to be vague and still claim success).
"""

from __future__ import annotations

from typing import Any, Mapping

from receipt_kernel.invariants._helpers import get_evidence_blob_sha, get_run_mode
from receipt_kernel.types import InvariantResult, Reason, Verdict


# Default requirements per mode.
# Factual/mixed must have claims_map. Creative is relaxed.
DEFAULT_MODE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "factual": ("claims_map",),
    "mixed": ("claims_map",),
    "creative": (),
}


class EpistemicModeRequirementsInvariant:
    """Verify mode-specific minimum evidence requirements are met."""

    invariant_id = "epistemic.mode_requirements"

    def __init__(
        self,
        *,
        requirements: Mapping[str, tuple[str, ...]] | None = None,
        allow_unknown_modes: bool = False,
    ):
        self._req = dict(requirements or DEFAULT_MODE_REQUIREMENTS)
        self._allow_unknown = allow_unknown_modes

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

        required = self._req.get(mode)
        if required is None:
            if self._allow_unknown:
                return InvariantResult(
                    invariant_id=self.invariant_id,
                    verdict=Verdict.WARN,
                    reasons=[Reason(code="RUN_MODE_UNKNOWN", msg=f"no requirements defined for mode: {mode}")],
                    meta={"mode": mode},
                )
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(code="RUN_MODE_UNKNOWN", msg=f"unsupported mode: {mode}")],
                meta={"mode": mode},
            )

        if not required:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "required": list(required)},
            )

        missing: list[str] = []
        for key in required:
            if get_evidence_blob_sha(store, str(run_id), key) is None:
                missing.append(key)

        if missing:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="MODE_REQUIREMENTS_MISSING",
                    msg=f"mode={mode} missing required evidence: {missing}",
                )],
                meta={"mode": mode, "missing": missing},
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
            reasons=[],
            meta={"mode": mode, "required": list(required)},
        )
