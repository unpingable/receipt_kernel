# receipt-kernel

Append-only, hash-chained run ledger with invariant evaluation.

Zero dependencies. Stdlib only. Python 3.10+.

## What it does

- **Run ledger**: append-only, hash-chained event store (SQLite, WAL mode)
- **Stage machine**: explicit stage graph with hard-fail on illegal transitions
- **Evidence store**: content-addressed blobs with pre-write redaction and retention policies
- **Invariant evaluation**: PASS / WARN / FAIL / UNKNOWN — no silent downgrade

## What it doesn't do

No daemons, schedulers, reconciliation loops, plugins, auth, tenancy, or LLM abstractions.
It records what happened, proves the chain is intact, and evaluates invariants. That's it.

## Install

```bash
pip install receipt-kernel
```

## Quick start

```python
from receipt_kernel import Verdict, BlobRef, RetentionPolicy
from receipt_kernel.store_sqlite import SqliteReceiptStore
from receipt_kernel.stages import DEFAULT_STAGE_GRAPH
from receipt_kernel.envelope import make_envelope, seal_envelope

# Create a store
store = SqliteReceiptStore(":memory:", stage_graph=DEFAULT_STAGE_GRAPH)

# Start a run
run_id = "run-001"
store.ensure_run(run_id, policy_id="default", policy_version="1.0")

# Append events through the stage graph
env = make_envelope(
    run_id=run_id,
    event_type="RUN_START",
    stage="START",
    actor={"kind": "system", "id": "test"},
    policy={"policy_id": "default", "policy_version": "1.0", "stage_graph_id": "default"},
    payload={"task": "example"},
)
sealed = seal_envelope(env, prev_hash=None)
store.append_event(sealed)
```

## Invariants

Six constitutional invariants ship with the kernel:

| Invariant | What it checks |
|-----------|---------------|
| `ledger_chain_valid` | Hash chain integrity (seq contiguity, prev_hash, event_hash) |
| `receipt_completeness` | Required evidence keys present, blobs retrievable |
| `evaluation_completeness` | Attested evaluation, no silent downgrade |
| `finalization_completeness` | Clean endings, decision ref, last event |
| `run_shape.single_finalize` | Exactly one RUN_FINALIZE per run |
| `run_shape.stage_required_path` | Required stages appear in order |

All invariants return `InvariantResult` with a `Verdict`. Any UNKNOWN or FAIL in required invariants poisons overall success.

## Verdicts

```python
from receipt_kernel import Verdict

Verdict.PASS     # verified and satisfied
Verdict.WARN     # verified but degraded
Verdict.FAIL     # verified and violated
Verdict.UNKNOWN  # cannot verify (missing evidence, read failure)
```

UNKNOWN is a failure, not a shrug.

## Evidence

Evidence is stored as content-addressed blobs (`blob://sha256:<hex>`).

Two evidence classes:
- **public**: retained longer, safe for logging
- **sealed**: aggressively expired, encrypted-at-rest when applicable

An optional redaction hook runs before persistence (13 built-in secret patterns).

## License

Apache-2.0
