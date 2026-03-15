# SPDX-License-Identifier: Apache-2.0
"""Invariant: tools.trace_consistency

If claims reference tool_call_ids, the tool_trace evidence must exist
and contain matching entries. Catches "phantom tooling" structurally.

Also verifies tool output binding: if trace entries have output_ref or
output_sha256, those outputs must exist as blobs AND be in this run's
closed-world evidence set.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.invariants._helpers import (
    collect_run_blob_refs,
    get_run_mode,
    load_evidence_json,
    parse_blob_ref,
)
from receipt_kernel.types import InvariantResult, Reason, Verdict


class ToolTraceConsistencyInvariant:
    """Verify tool-derived claims match actual tool trace entries."""

    invariant_id = "tools.trace_consistency"

    def __init__(self, *, enforce_in_modes: tuple[str, ...] = ("factual", "mixed")):
        self._modes = enforce_in_modes

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

        # Load claims_map to find tool_call_ids
        claims_doc = load_evidence_json(store, str(run_id), "claims_map")
        if claims_doc is None:
            # Let claims.evidence_binding own this failure
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(code="CLAIMS_MAP_MISSING", msg="cannot verify tool refs without claims_map")],
                meta={"mode": mode},
            )

        claims = claims_doc.get("claims") or []
        required_ids: set[str] = set()
        for c in claims:
            if isinstance(c, dict):
                tids = c.get("tool_call_ids")
                if isinstance(tids, list):
                    for tid in tids:
                        if isinstance(tid, str) and tid:
                            required_ids.add(tid)

        if not required_ids:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "tool_ids_checked": 0},
            )

        # Load tool_trace
        trace_doc = load_evidence_json(store, str(run_id), "tool_trace")
        if trace_doc is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="TOOL_TRACE_MISSING",
                    msg="tool_trace required when claims reference tool_call_ids",
                )],
                meta={"mode": mode, "required_ids": sorted(required_ids)},
            )

        calls = trace_doc.get("calls")
        if not isinstance(calls, list):
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(code="TOOL_TRACE_MALFORMED", msg="tool_trace.calls must be a list")],
                meta={"mode": mode},
            )

        # Build call index
        call_by_id: dict[str, dict[str, Any]] = {}
        for call in calls:
            if isinstance(call, dict) and isinstance(call.get("id"), str):
                call_by_id[call["id"]] = call

        reasons: list[Reason] = []

        # Phase 1: verify call IDs exist
        missing_ids = sorted(required_ids - set(call_by_id.keys()))
        if missing_ids:
            reasons.append(Reason(
                code="TOOL_CALL_MISSING",
                msg=f"claims reference tool_call_ids missing from trace: {missing_ids}",
            ))

        # Phase 2: verify tool output binding (closed-world)
        # Only check calls that are actually referenced by claims
        run_refs = collect_run_blob_refs(store, str(run_id))

        for tid in sorted(required_ids & set(call_by_id.keys())):
            call = call_by_id[tid]
            output_ref = call.get("output_ref")
            output_sha = call.get("output_sha256")

            if output_ref is not None:
                # Output ref must be in this run's closed-world set
                if output_ref not in run_refs:
                    reasons.append(Reason(
                        code="TOOL_OUTPUT_NOT_IN_RUN",
                        msg=f"tool {tid}: output_ref not produced by this run",
                        pointers=(output_ref,),
                    ))
                else:
                    # Also verify blob is retrievable
                    sha = parse_blob_ref(output_ref)
                    if sha is not None and not store.has_blob(sha):
                        reasons.append(Reason(
                            code="TOOL_OUTPUT_MISSING",
                            msg=f"tool {tid}: output blob not in store",
                            pointers=(output_ref,),
                        ))
            elif output_sha is not None:
                # Resolve sha to ref and check
                resolved_ref = f"blob://sha256:{output_sha}"
                if resolved_ref not in run_refs:
                    reasons.append(Reason(
                        code="TOOL_OUTPUT_NOT_IN_RUN",
                        msg=f"tool {tid}: output_sha256 blob not produced by this run",
                        pointers=(resolved_ref,),
                    ))
                elif not store.has_blob(output_sha):
                    reasons.append(Reason(
                        code="TOOL_OUTPUT_MISSING",
                        msg=f"tool {tid}: output blob not in store",
                        pointers=(resolved_ref,),
                    ))
            else:
                # No output binding — severity depends on mode
                if mode == "factual":
                    reasons.append(Reason(
                        code="TOOL_OUTPUT_UNBOUND",
                        msg=f"tool {tid}: no output_ref or output_sha256 in trace entry",
                    ))
                else:
                    # mixed mode: warn instead of fail
                    reasons.append(Reason(
                        code="TOOL_OUTPUT_UNBOUND_WARN",
                        msg=f"tool {tid}: no output binding (warn in {mode} mode)",
                    ))

        # Determine verdict
        fail_codes = {"TOOL_CALL_MISSING", "TOOL_OUTPUT_MISSING", "TOOL_OUTPUT_NOT_IN_RUN", "TOOL_OUTPUT_UNBOUND"}
        warn_codes = {"TOOL_OUTPUT_UNBOUND_WARN"}

        has_fail = any(r.code in fail_codes for r in reasons)
        has_warn = any(r.code in warn_codes for r in reasons)

        if has_fail:
            verdict = Verdict.FAIL
        elif has_warn:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=verdict,
            reasons=reasons,
            meta={"mode": mode, "tool_ids_checked": len(required_ids)},
        )
