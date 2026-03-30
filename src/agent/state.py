from __future__ import annotations

from src.agent.schemas import InvestigationState, SubjectNormalized


def build_investigation_state(subjects: list[SubjectNormalized]) -> InvestigationState:
    return InvestigationState(subjects=subjects)