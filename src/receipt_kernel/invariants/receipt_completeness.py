# SPDX-License-Identifier: Apache-2.0
"""Invariant: receipt.completeness

Verifies that all required evidence keys are present in EVIDENCE_PUT events
and that the corresponding blobs are retrievable.
"""

from __future__ import annotations

from typing import Any

from receipt_kernel.types import InvariantResult, Reason, Verdict


class ReceiptCompletenessInvariant:
    """Verify required evidence is present and retrievable."""

    invariant_id = "receipt.completeness"

    def __init__(
        self,
        required_keys: list[str] | None = None,
        verify_blobs: bool = True,
    ):
        self.required_keys = required_keys or []
        self.verify_blobs = verify_blobs

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        """Evaluate receipt completeness.

        ctx must contain:
        - store: SqliteReceiptStore
        - run_id: str
        """
        store = ctx["store"]
        run_id = ctx["run_id"]

        evidence_events = store.get_events(run_id, event_type="EVIDENCE_PUT")
        reasons: list[Reason] = []
        evidence_refs: list[str] = []

        # Collect all evidence keys
        found_keys: dict[str, str] = {}  # key -> blob sha256
        for ev in evidence_events:
            payload = ev.get("payload", {})
            key = payload.get("key", "")
            evidence = payload.get("evidence", {})
            sha = evidence.get("sha256", "")
            if key:
                found_keys[key] = sha
                blob_refs = ev.get("refs", {}).get("blobs", [])
                evidence_refs.extend(blob_refs)

        # Check required keys
        for rk in self.required_keys:
            if rk not in found_keys:
                reasons.append(Reason(
                    code="MISSING_KEY",
                    msg=f"Required evidence key {rk!r} not found in EVIDENCE_PUT events",
                ))

        # Verify blobs are retrievable
        if self.verify_blobs:
            for key, sha in found_keys.items():
                if sha and not store.has_blob(sha):
                    reasons.append(Reason(
                        code="BLOB_NOT_FOUND",
                        msg=f"Blob for evidence key {key!r} (sha256={sha[:16]}...) not found in store",
                        pointers=(f"blob://sha256:{sha}",),
                    ))
                elif sha and not store.blob_is_live(sha):
                    # Blob exists but data has been expired — this is WARN, not FAIL
                    reasons.append(Reason(
                        code="BLOB_EXPIRED",
                        msg=f"Blob for evidence key {key!r} exists but data has been expired",
                        pointers=(f"blob://sha256:{sha}",),
                    ))

        # Determine verdict
        has_missing = any(r.code == "MISSING_KEY" for r in reasons)
        has_not_found = any(r.code == "BLOB_NOT_FOUND" for r in reasons)
        has_expired = any(r.code == "BLOB_EXPIRED" for r in reasons)

        if has_missing or has_not_found:
            verdict = Verdict.FAIL
        elif has_expired:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=verdict,
            reasons=reasons,
            evidence_refs=evidence_refs,
            meta={"found_keys": list(found_keys.keys())},
        )
