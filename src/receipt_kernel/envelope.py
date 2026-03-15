# SPDX-License-Identifier: Apache-2.0
"""Event envelope: hash-chained, append-only event records.

Every event in a run shares this stable schema. The envelope is the unit
of trust — if the hash chain is intact, the narrative is tamper-evident.

Design:
- event_hash = sha256(canonical_json(envelope_without_event_hash))
- prev_event_hash links to the previous event in the same run (null for first)
- seq is monotonic and contiguous per run (1-indexed)
- ts is ISO 8601 UTC
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from receipt_kernel.types import EVENT_SCHEMA_VERSION, VALID_EVENT_TYPES


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization for hashing.

    Sorted keys, compact separators, ASCII-safe, no NaN/Infinity.
    Do not change these parameters without bumping EVENT_SCHEMA_VERSION.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def compute_hash(data: bytes) -> str:
    """SHA-256 hex digest with prefix."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def compute_hash_raw(data: bytes) -> str:
    """SHA-256 hex digest without prefix (for blob addressing)."""
    return hashlib.sha256(data).hexdigest()


def make_envelope(
    *,
    event_type: str,
    stage: str,
    policy_id: str,
    policy_version: str,
    stage_graph_id: str,
    actor_kind: str,
    actor_id: str,
    payload: dict[str, Any],
    blob_refs: list[str] | None = None,
    event_refs: list[str] | None = None,
    run_id: str = "",  # filled by store on append
    seq: int = 0,  # filled by store on append
    prev_event_hash: str | None = None,  # filled by store on append
    ts: str | None = None,
) -> dict[str, Any]:
    """Build an event envelope (without final hash — store computes that).

    The store fills in run_id, seq, prev_event_hash, and computes event_hash
    when appending. Callers provide the content; the store provides the chain.
    """
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(
            f"Unknown event_type {event_type!r}. "
            f"Valid types: {sorted(VALID_EVENT_TYPES)}"
        )

    timestamp = ts or datetime.now(timezone.utc).isoformat()

    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "run_id": run_id,
        "seq": seq,
        "ts": timestamp,
        "event_type": event_type,
        "stage": stage,
        "policy": {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "stage_graph_id": stage_graph_id,
        },
        "actor": {
            "kind": actor_kind,
            "id": actor_id,
        },
        "prev_event_hash": prev_event_hash,
        "event_hash": None,  # computed by store
        "payload": payload,
        "refs": {
            "blobs": list(blob_refs or []),
            "events": list(event_refs or []),
        },
    }


def seal_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Compute and set event_hash on an envelope.

    The hash covers all fields except event_hash itself.
    Returns a new dict with event_hash set.
    """
    env = dict(envelope)
    env.pop("event_hash", None)
    h = compute_hash(canonical_json(env))
    env["event_hash"] = h
    return env


def verify_envelope_hash(envelope: dict[str, Any]) -> bool:
    """Verify that an envelope's event_hash matches its content."""
    stored_hash = envelope.get("event_hash")
    if not stored_hash:
        return False
    env = dict(envelope)
    env.pop("event_hash", None)
    computed = compute_hash(canonical_json(env))
    return stored_hash == computed
