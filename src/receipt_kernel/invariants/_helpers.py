# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for hallucination invariants.

These extract structured data from the event ledger using the store's
public API. No direct SQL — everything goes through store methods.
"""

from __future__ import annotations

import json
from typing import Any


def parse_blob_ref(ref: str) -> str | None:
    """Extract sha256 from a blob://sha256:<hex> reference."""
    prefix = "blob://sha256:"
    if isinstance(ref, str) and ref.startswith(prefix):
        return ref[len(prefix):]
    return None


def get_run_mode(store: Any, run_id: str) -> str | None:
    """Get run mode from RUN_START.payload.meta.mode."""
    events = store.get_events(run_id, event_type="RUN_START")
    if not events:
        return None
    meta = (events[0].get("payload") or {}).get("meta") or {}
    mode = meta.get("mode")
    return str(mode).lower() if isinstance(mode, str) else None


def find_evidence_by_key(store: Any, run_id: str, key: str) -> dict[str, Any] | None:
    """Find the latest EVIDENCE_PUT with the given key.

    Returns the evidence dict from the payload, or None.
    """
    events = store.get_events(run_id, event_type="EVIDENCE_PUT")
    for ev in reversed(events):
        payload = ev.get("payload") or {}
        if payload.get("key") == key:
            return payload.get("evidence") or {}
    return None


def get_evidence_blob_sha(store: Any, run_id: str, key: str) -> str | None:
    """Get the sha256 of the latest EVIDENCE_PUT blob for a key."""
    ev = find_evidence_by_key(store, run_id, key)
    if ev is None:
        return None
    return ev.get("sha256")


def load_evidence_json(store: Any, run_id: str, key: str) -> dict[str, Any] | None:
    """Load and parse a JSON evidence blob by key.

    Returns parsed dict, or None if missing/unreadable.
    """
    sha = get_evidence_blob_sha(store, run_id, key)
    if sha is None:
        return None
    raw = store.get_blob(sha)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def build_blob_kind_map(store: Any, run_id: str) -> dict[str, str]:
    """Build a mapping from blob ref → evidence_kind for a run.

    Scans all EVIDENCE_PUT events and extracts meta.evidence_kind.
    Returns {blob_ref: evidence_kind} for all blobs with a kind tag.
    """
    events = store.get_events(run_id, event_type="EVIDENCE_PUT")
    result: dict[str, str] = {}
    for ev in events:
        payload = ev.get("payload") or {}
        evidence = payload.get("evidence") or {}
        ref = evidence.get("ref")
        meta = payload.get("meta") or {}
        kind = meta.get("evidence_kind")
        if isinstance(ref, str) and isinstance(kind, str):
            result[ref] = kind
    return result


def build_blob_class_map(store: Any, run_id: str) -> dict[str, int]:
    """Build a mapping from blob ref → oracle_class for a run.

    Scans all EVIDENCE_PUT events and extracts meta.oracle_class.
    Returns {blob_ref: oracle_class} for all blobs with oracle_class.
    Blobs without oracle_class are excluded (they are not oracle evidence).
    """
    events = store.get_events(run_id, event_type="EVIDENCE_PUT")
    result: dict[str, int] = {}
    for ev in events:
        payload = ev.get("payload") or {}
        evidence = payload.get("evidence") or {}
        ref = evidence.get("ref")
        meta = payload.get("meta") or {}
        oracle_class = meta.get("oracle_class")
        if isinstance(ref, str) and isinstance(oracle_class, int):
            result[ref] = oracle_class
    return result


def collect_run_blob_refs(store: Any, run_id: str) -> set[str]:
    """Collect all blob refs produced by EVIDENCE_PUT events in a run.

    Returns set of blob://sha256:... strings.
    """
    events = store.get_events(run_id, event_type="EVIDENCE_PUT")
    refs: set[str] = set()
    for ev in events:
        # From refs.blobs in the envelope
        for r in (ev.get("refs") or {}).get("blobs") or []:
            if isinstance(r, str):
                refs.add(r)
        # From payload.evidence.ref
        evidence = (ev.get("payload") or {}).get("evidence") or {}
        ref = evidence.get("ref")
        if isinstance(ref, str):
            refs.add(ref)
    return refs
