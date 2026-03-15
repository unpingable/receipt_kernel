# SPDX-License-Identifier: Apache-2.0
"""StageGraph: explicit stage machine with hard-fail on illegal transitions.

Stages are not advisory. An illegal transition is a bug, not a warning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StageGraph:
    """Defines legal stage transitions for a run.

    Transitions not in the graph are hard errors.
    """

    graph_id: str
    transitions: dict[str, list[str]]  # stage -> list of legal next stages
    initial_stage: str
    terminal_stages: frozenset[str]

    def validate_transition(self, from_stage: str, to_stage: str) -> None:
        """Raise ValueError if transition is illegal."""
        if from_stage not in self.transitions:
            raise ValueError(
                f"Unknown stage {from_stage!r} in graph {self.graph_id!r}. "
                f"Known stages: {sorted(self.transitions.keys())}"
            )
        allowed = self.transitions[from_stage]
        if to_stage not in allowed:
            raise ValueError(
                f"Illegal transition {from_stage!r} -> {to_stage!r} "
                f"in graph {self.graph_id!r}. "
                f"Allowed from {from_stage!r}: {allowed}"
            )

    def is_terminal(self, stage: str) -> bool:
        return stage in self.terminal_stages

    def all_stages(self) -> frozenset[str]:
        stages = set(self.transitions.keys())
        for targets in self.transitions.values():
            stages.update(targets)
        return frozenset(stages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "transitions": {k: list(v) for k, v in self.transitions.items()},
            "initial_stage": self.initial_stage,
            "terminal_stages": sorted(self.terminal_stages),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageGraph:
        return cls(
            graph_id=data["graph_id"],
            transitions={k: list(v) for k, v in data["transitions"].items()},
            initial_stage=data["initial_stage"],
            terminal_stages=frozenset(data["terminal_stages"]),
        )


# =============================================================================
# Built-in graphs
# =============================================================================


DEFAULT_STAGE_GRAPH = StageGraph(
    graph_id="v1_default",
    transitions={
        "START": ["COLLECT"],
        "COLLECT": ["EVALUATE"],
        "EVALUATE": ["DECIDE"],
        "DECIDE": ["FINALIZE", "REMEDIATE"],
        "REMEDIATE": ["COLLECT"],  # retry loop
        "FINALIZE": [],  # terminal
    },
    initial_stage="START",
    terminal_stages=frozenset({"FINALIZE"}),
)


MINIMAL_STAGE_GRAPH = StageGraph(
    graph_id="v1_minimal",
    transitions={
        "START": ["FINALIZE"],
        "FINALIZE": [],
    },
    initial_stage="START",
    terminal_stages=frozenset({"FINALIZE"}),
)
