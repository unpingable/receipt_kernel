# SPDX-License-Identifier: Apache-2.0
"""Invariant: ledger.chain_valid

Verifies the hash chain integrity of a run's event ledger:
1. Sequence numbers are contiguous (1, 2, 3, ...)
2. prev_event_hash links correctly to the previous event
3. event_hash matches the canonical JSON of the envelope (minus event_hash)
"""

from __future__ import annotations

import json
from typing import Any

from receipt_kernel.envelope import canonical_json, compute_hash
from receipt_kernel.types import InvariantResult, Reason, Verdict


class LedgerChainValidInvariant:
    """Verify hash chain integrity for a run."""

    invariant_id = "ledger.chain_valid"

    def evaluate(self, ctx: dict[str, Any]) -> InvariantResult:
        """Evaluate chain validity.

        ctx must contain:
        - store: SqliteReceiptStore
        - run_id: str
        """
        store = ctx["store"]
        run_id = ctx["run_id"]

        store._ensure_conn()
        rows = store._conn.execute(
            "SELECT seq, envelope_json, event_hash, prev_event_hash "
            "FROM events WHERE run_id = ? ORDER BY seq ASC",
            (run_id,),
        ).fetchall()

        if not rows:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.UNKNOWN,
                reasons=[Reason(
                    code="NO_EVENTS",
                    msg=f"No events found for run_id={run_id}",
                )],
            )

        reasons: list[Reason] = []
        prev_hash: str | None = None
        expected_seq = 1

        for seq, env_json, stored_hash, stored_prev in rows:
            seq = int(seq)
            ref = f"event://{run_id}/{seq}"

            # Check contiguous sequence
            if seq != expected_seq:
                reasons.append(Reason(
                    code="SEQ_GAP",
                    msg=f"Expected seq={expected_seq}, got seq={seq}",
                    pointers=(ref,),
                ))

            # Check prev_event_hash linkage
            if stored_prev != prev_hash:
                reasons.append(Reason(
                    code="PREV_HASH_MISMATCH",
                    msg=(
                        f"seq={seq}: prev_event_hash={stored_prev!r} "
                        f"but expected {prev_hash!r}"
                    ),
                    pointers=(ref,),
                ))

            # Verify event_hash
            env = json.loads(env_json)
            env_no_hash = dict(env)
            env_no_hash.pop("event_hash", None)
            computed = compute_hash(canonical_json(env_no_hash))

            if stored_hash != computed:
                reasons.append(Reason(
                    code="EVENT_HASH_MISMATCH",
                    msg=(
                        f"seq={seq}: event_hash={stored_hash!r} "
                        f"but computed {computed!r}"
                    ),
                    pointers=(ref,),
                ))

            prev_hash = computed
            expected_seq = seq + 1

        if reasons:
            return InvariantResult(
                invariant_id=self.invariant_id,
                verdict=Verdict.FAIL,
                reasons=reasons,
            )

        return InvariantResult(
            invariant_id=self.invariant_id,
            verdict=Verdict.PASS,
            meta={"event_count": len(rows)},
        )
