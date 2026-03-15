# SPDX-License-Identifier: Apache-2.0
"""Invariant: oracle.independence_minimum

Verifies that oracle evidence cited by claims meets a minimum independence
class for the run's mode.

Oracle independence classes:
  0 — local, same host (e.g., pytest on the dev machine)
  1 — same-org CI (e.g., GitHub Actions in the same repo)
  2 — cross-org CI (e.g., third-party CI service)
  3 — independent third-party verification

This invariant ships with all thresholds at class 0, so it's inert today.
When a project raises the bar (e.g., strict + security-sensitive → class 1),
claims backed only by class-0 oracles will fail this invariant.

Policy table
~~~~~~~~~~~~
The minimum class is looked up from a policy table. Keys support two forms:

  (mode, claim_level)         → min_class   # basic (2-axis)
  (mode, claim_level, scope)  → min_class   # extended (3-axis)

The 3-tuple form takes precedence when a claim carries a ``scope`` field.
This lets you express "auth files need class 1" without overriding the
global default for all high-confidence claims. The scope axis is plumbed
but not populated yet — claims don't carry scope today. When they do,
no invariant changes are needed.

Known simplifications
~~~~~~~~~~~~~~~~~~~~~
- **Max-class-over-all-oracles**: If a claim cites two oracle blobs, the
  *highest* class is used. This means a high-class but irrelevant oracle can
  satisfy a requirement intended for a different evidence type. A future
  refinement (``min_over_required_evidence_set``) would check per-evidence-kind
  requirements instead. For now, max-over-all is correct because each claim
  typically cites one oracle type.

- **No oracle-presence enforcement**: Claims without oracle evidence are
  silently skipped. This invariant assumes ``confidence.sanity`` enforces that
  HARD claims have strong (oracle-backed) evidence. If ``confidence.sanity``
  is disabled, HARD claims that omit oracle refs entirely will pass this
  invariant unchecked. Consider enabling both invariants together, or adding
  an optional strict toggle here later.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.invariants._helpers import (
    build_blob_class_map,
    build_blob_kind_map,
    get_run_mode,
    load_evidence_json,
)
from receipt_kernel.types import InvariantResult, Reason, Verdict


# Default policy: everything is class 0 (inert).
#
# Keys: 2-tuple (mode, claim_level) or 3-tuple (mode, claim_level, scope).
# "claim_level" matches the "confidence" field in the claims_map:
#   "high" = HARD claims, "medium" = MEDIUM, "low" = SOFT.
# "scope" is an optional file-class tag (e.g., "auth", "ci", "deps", "build").
#   When present, the 3-tuple is checked first; missing keys fall back to 2-tuple.
# Missing keys default to 0.
DEFAULT_ORACLE_POLICY: dict[tuple[str, ...], int] = {
    ("factual", "high"): 0,
    ("factual", "medium"): 0,
    ("factual", "low"): 0,
    ("mixed", "high"): 0,
    ("mixed", "medium"): 0,
    ("mixed", "low"): 0,
    ("exploratory", "high"): 0,
    ("exploratory", "medium"): 0,
    ("exploratory", "low"): 0,
}


class OracleIndependenceInvariant:
    """Verify oracle evidence meets minimum independence class.

    For each claim that cites oracle-backed evidence, checks that
    the oracle_class meets the minimum required by the policy table.

    Claims without oracle evidence are not checked by this invariant —
    that's confidence.sanity's job. See module docstring for known
    simplifications and the dependency on confidence.sanity.
    """

    invariant_id = "oracle.independence_minimum"

    def __init__(
        self,
        *,
        require_in_modes: tuple[str, ...] = ("factual", "mixed"),
        policy: dict[tuple[str, ...], int] | None = None,
    ):
        self._modes = require_in_modes
        self._policy = policy if policy is not None else dict(DEFAULT_ORACLE_POLICY)

    def min_class_for(self, mode: str, claim_level: str, scope: str | None = None) -> int:
        """Look up the minimum oracle class.

        Checks (mode, claim_level, scope) first if scope is provided,
        then falls back to (mode, claim_level), then 0.
        """
        if scope is not None:
            val = self._policy.get((mode, claim_level, scope))
            if val is not None:
                return val
        return self._policy.get((mode, claim_level), 0)

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
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(code="CLAIMS_MAP_MISSING", msg="cannot verify oracle independence without claims_map")],
                meta={"mode": mode},
            )

        claims = claims_doc.get("claims") or []
        if not claims:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "claim_count": 0},
            )

        # Build blob ref → oracle_class map
        blob_class_map = build_blob_class_map(store, str(run_id))

        reasons: list[Reason] = []
        checked = 0
        passed = 0
        claim_details: list[dict[str, Any]] = []

        for i, c in enumerate(claims):
            if not isinstance(c, dict):
                continue
            cid = c.get("id", f"idx:{i}")
            confidence = str(c.get("confidence", "")).lower()
            scope = c.get("scope")  # 3rd axis, not populated yet
            evrefs = c.get("evidence_refs") or []

            # Find oracle evidence among this claim's evidence refs
            oracle_refs = [
                ref for ref in evrefs
                if isinstance(ref, str) and ref in blob_class_map
            ]

            if not oracle_refs:
                # No oracle evidence cited — not our problem
                continue

            checked += 1
            min_required = self.min_class_for(mode, confidence, scope)

            # Max class over all cited oracles (see docstring: known simplification)
            max_class = max(blob_class_map[ref] for ref in oracle_refs)

            detail: dict[str, Any] = {
                "claim_id": cid,
                "min_required": min_required,
                "observed_class": max_class,
                "satisfied": max_class >= min_required,
            }
            claim_details.append(detail)

            if max_class < min_required:
                reasons.append(Reason(
                    code="ORACLE_CLASS_BELOW_MINIMUM",
                    msg=(
                        f"claim {cid}: oracle class {max_class} < required {min_required} "
                        f"for ({mode}, {confidence})"
                    ),
                    pointers=tuple(oracle_refs),
                ))
            else:
                passed += 1

        if reasons:
            verdict = Verdict.FAIL
        else:
            verdict = Verdict.PASS

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=verdict,
            reasons=reasons,
            meta={
                "mode": mode,
                "claims_with_oracle": checked,
                "claims_passing": passed,
                "claim_details": claim_details,
            },
        )
