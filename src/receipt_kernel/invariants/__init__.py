# SPDX-License-Identifier: Apache-2.0
"""Constitutional invariants for the receipt kernel.

Invariants in three groups:

Structural (ledger integrity):
- ledger.chain_valid — hash chain verification
- receipt.completeness — evidence keys present, blobs retrievable
- evaluation.completeness — attested evaluation, no silent downgrade
- finalization.completeness — clean endings, decision ref required
- run.single_finalize — exactly one RUN_FINALIZE per run
- run.stage_required_path — required stages appear in order

Hallucination (claims ↔ evidence binding):
- claims.evidence_binding — factual claims must have evidence refs
- tools.trace_consistency — tool-derived claims must match trace entries
- epistemic.mode_requirements — mode-specific minimum evidence
- refs.closed_world — evidence refs must come from this run's ledger
- output.bound_to_claims — claims_map must bind to final output blob
- confidence.sanity — confidence levels must match evidence strength

Oracle (evidence provenance):
- oracle.independence_minimum — oracle evidence meets minimum class for mode
"""

from receipt_kernel.invariants.claims_evidence_binding import ClaimsEvidenceBindingInvariant
from receipt_kernel.invariants.confidence_sanity import ConfidenceSanityInvariant
from receipt_kernel.invariants.epistemic_mode_requirements import EpistemicModeRequirementsInvariant
from receipt_kernel.invariants.evaluation_completeness import EvaluationCompletenessInvariant
from receipt_kernel.invariants.finalization_completeness import FinalizationCompletenessInvariant
from receipt_kernel.invariants.ledger_chain_valid import LedgerChainValidInvariant
from receipt_kernel.invariants.oracle_independence import OracleIndependenceInvariant
from receipt_kernel.invariants.output_bound_to_claims import OutputBoundToClaimsInvariant
from receipt_kernel.invariants.receipt_completeness import ReceiptCompletenessInvariant
from receipt_kernel.invariants.refs_closed_world import RefsClosedWorldInvariant
from receipt_kernel.invariants.run_shape import SingleFinalizeInvariant, StageRequiredPathInvariant
from receipt_kernel.invariants.tool_trace_consistency import ToolTraceConsistencyInvariant

__all__ = [
    # Structural
    "LedgerChainValidInvariant",
    "ReceiptCompletenessInvariant",
    "EvaluationCompletenessInvariant",
    "FinalizationCompletenessInvariant",
    "SingleFinalizeInvariant",
    "StageRequiredPathInvariant",
    # Hallucination
    "ClaimsEvidenceBindingInvariant",
    "ToolTraceConsistencyInvariant",
    "EpistemicModeRequirementsInvariant",
    "RefsClosedWorldInvariant",
    "OutputBoundToClaimsInvariant",
    "ConfidenceSanityInvariant",
    # Oracle
    "OracleIndependenceInvariant",
]
