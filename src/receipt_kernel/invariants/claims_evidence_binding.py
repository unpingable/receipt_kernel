# SPDX-License-Identifier: Apache-2.0
"""Invariant: claims.evidence_binding

Every factual claim must point to evidence refs (blobs) that exist in the store.
In factual/mixed mode, claims_map is mandatory.
Claims with zero evidence_refs → FAIL.
Claims referencing missing blobs → FAIL.
"""

from __future__ import annotations

import json
from typing import Any

from receipt_kernel.invariants._helpers import (
    get_evidence_blob_sha,
    get_run_mode,
    load_evidence_json,
    parse_blob_ref,
)
from receipt_kernel.types import InvariantResult, Reason, Verdict


class ClaimsEvidenceBindingInvariant:
    """Verify every factual claim is bound to retrievable evidence."""

    invariant_id = "claims.evidence_binding"

    def __init__(self, *, require_in_modes: tuple[str, ...] = ("factual", "mixed")):
        self._require_in_modes = require_in_modes

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

        if mode not in self._require_in_modes:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.PASS,
                reasons=[],
                meta={"mode": mode, "skipped": True},
            )

        # Load claims_map
        doc = load_evidence_json(store, str(run_id), "claims_map")
        if doc is None:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(
                    code="CLAIMS_MAP_MISSING",
                    msg="claims_map evidence required in factual/mixed mode",
                )],
                meta={"mode": mode},
            )

        claims = doc.get("claims")
        if not isinstance(claims, list):
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=[Reason(code="CLAIMS_MAP_MALFORMED", msg="claims_map.claims must be a list")],
                meta={"mode": mode},
            )

        reasons: list[Reason] = []
        evidence_refs: list[str] = []

        for i, c in enumerate(claims):
            if not isinstance(c, dict):
                reasons.append(Reason(code="CLAIM_MALFORMED", msg=f"claim[{i}] not an object"))
                continue

            cid = c.get("id", f"idx:{i}")
            evrefs = c.get("evidence_refs")

            if not isinstance(evrefs, list) or not evrefs:
                reasons.append(Reason(
                    code="CLAIM_UNBOUND",
                    msg=f"claim {cid} has no evidence_refs",
                ))
                continue

            for r in evrefs:
                if not isinstance(r, str):
                    reasons.append(Reason(code="EVIDENCE_REF_BAD", msg=f"claim {cid}: non-string ref"))
                    continue
                evidence_refs.append(r)

                # Check blob existence
                sha = parse_blob_ref(r)
                if sha is not None and not store.has_blob(sha):
                    reasons.append(Reason(
                        code="EVIDENCE_REF_MISSING",
                        msg=f"claim {cid}: blob {r} not in store",
                        pointers=(r,),
                    ))

        fail_codes = {"CLAIM_UNBOUND", "EVIDENCE_REF_MISSING", "CLAIMS_MAP_MALFORMED", "CLAIM_MALFORMED"}
        verdict = (
            Verdict.FAIL if any(r.code in fail_codes for r in reasons)
            else Verdict.WARN if reasons
            else Verdict.PASS
        )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=verdict,
            reasons=reasons,
            evidence_refs=sorted(set(evidence_refs)),
            meta={"mode": mode, "claim_count": len(claims)},
        )
