from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SubjectType(str, Enum):
    PERSON = "person"
    COMPANY = "company"
    DOMAIN = "domain"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionType(str, Enum):
    DETECT_SUBJECTS = "detect_subjects"
    PLAN_INVESTIGATION = "plan_investigation"
    SEARCH_WEB = "search_web"
    SEARCH_NEWS = "search_news"
    DNS_LOOKUP = "dns_lookup"
    WHOIS_LOOKUP = "whois_lookup"
    FETCH_WEBSITE = "fetch_website"
    FETCH_ROBOTS_TXT = "fetch_robots_txt"
    FETCH_SECURITY_TXT = "fetch_security_txt"
    FETCH_TLS_CERTIFICATE = "fetch_tls_certificate"
    ANALYZE_EVIDENCE = "analyze_evidence"
    GENERATE_ATTACK_HYPOTHESES = "generate_attack_hypotheses"
    FINALIZE_REPORT = "finalize_report"


class AttackVectorType(str, Enum):
    SOCIAL_ENGINEERING = "social_engineering"
    BRAND_IMPERSONATION = "brand_impersonation"
    CREDENTIAL_ATTACK = "credential_attack"
    SUPPLY_CHAIN = "supply_chain"
    PUBLIC_EXPOSURE = "public_exposure"
    INFRASTRUCTURE_TARGETING = "infrastructure_targeting"
    THIRD_PARTY_RISK = "third_party_risk"
    KNOWN_VULNERABILITY_ASSOCIATION = "known_vulnerability_association"
    OTHER = "other"


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class SubjectInput(StrictBaseModel):
    id: str | None = None
    type: SubjectType | None = None
    value: str = Field(min_length=1)


class SubjectNormalized(StrictBaseModel):
    id: str
    original_value: str
    detected_type: SubjectType
    normalized_value: str
    confidence: ConfidenceLevel
    reason: str


class SubjectsEnvelope(StrictBaseModel):
    subjects: list[SubjectInput]


class DetectSubjectsResponse(StrictBaseModel):
    subjects: list[SubjectNormalized]


class InvestigationGoal(StrictBaseModel):
    subject_id: str
    priority: int = Field(ge=1, le=5)
    goal: str


class InvestigationPlan(StrictBaseModel):
    summary: str
    goals: list[InvestigationGoal]
    initial_actions: list[str]
    notes: list[str] = Field(default_factory=list)


class NextActionDecision(StrictBaseModel):
    action: ActionType
    subject_id: str | None = None
    reason: str
    query: str | None = None
    expected_output: str | None = None


class EvidenceObservation(StrictBaseModel):
    observation: str
    confidence: ConfidenceLevel
    relevance: str


class AnalyzeEvidenceResponse(StrictBaseModel):
    description: str
    extracted_observations: list[EvidenceObservation]
    reliability_note: str


class EvidenceItem(StrictBaseModel):
    id: str
    subject_ids: list[str]
    source_type: str
    query_or_action: str
    description: str
    raw_result: dict[str, Any] | list[Any] | str | None = None
    extracted_observations: list[EvidenceObservation] = Field(default_factory=list)
    reliability_note: str


class EvidenceBatchSummary(StrictBaseModel):
    batch_id: str
    evidence_refs: list[str]
    factual_summary: list[str] = Field(default_factory=list)
    security_implications: list[str] = Field(default_factory=list)
    notable_entities: list[str] = Field(default_factory=list)
    source_quality_notes: list[str] = Field(default_factory=list)


class InvestigationLead(StrictBaseModel):
    id: str
    title: str
    subject_ids: list[str]
    lead_type: str
    summary: str
    evidence_refs: list[str]
    confidence: ConfidenceLevel
    operator_hint: str = ""
    grounded_facts: list[str] = Field(default_factory=list)
    concrete_pretexts: list[str] = Field(default_factory=list)
    defensive_actions: list[str] = Field(default_factory=list)
    why_it_matters: str = ""
    suggested_follow_up_queries: list[str] = Field(default_factory=list)


class AttackHypothesis(StrictBaseModel):
    id: str
    title: str
    summary: str
    type: AttackVectorType
    confidence: ConfidenceLevel
    target_subject_ids: list[str]
    evidence_refs: list[str]
    grounded_facts: list[str] = Field(default_factory=list)
    concrete_pretexts: list[str] = Field(default_factory=list)
    defensive_actions: list[str] = Field(default_factory=list)
    why_it_matters: str
    why_selected: str


class ExecutiveSummaryResponse(StrictBaseModel):
    executive_summary: str


class AttackVectorRefinementResponse(StrictBaseModel):
    attack_vector: AttackHypothesis


class ReportWrapUpResponse(StrictBaseModel):
    rationale: str
    recommended_next_steps: list[str] = Field(default_factory=list)

class ReportSynthesis(StrictBaseModel):
    executive_summary: str
    top_3_selected_attack_vectors: list[AttackHypothesis] = Field(
        min_length=0,
        max_length=3,
    )
    rationale: str
    recommended_next_steps: list[str] = Field(default_factory=list)

class SourceUsed(StrictBaseModel):
    id: str
    source_type: str
    description: str
    subject_ids: list[str] = Field(default_factory=list)


class InvestigationReport(StrictBaseModel):
    subjects: list[SubjectNormalized]
    executive_summary: str
    top_3_selected_attack_vectors: list[AttackHypothesis] = Field(
        min_length=0,
        max_length=3,
    )
    sources_used: list[SourceUsed]
    risk_signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rationale: str
    recommended_next_steps: list[str] = Field(default_factory=list)


class SubjectInvestigationState(StrictBaseModel):
    subject: SubjectNormalized
    findings: list[str] = Field(default_factory=list)
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    completed: bool = False


class InvestigationState(StrictBaseModel):
    subjects: list[SubjectNormalized]
    steps_taken: int = 0
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    intermediate_hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    selected_attack_vectors: list[AttackHypothesis] = Field(default_factory=list)
    investigation_leads: list[InvestigationLead] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rationale_notes: list[str] = Field(default_factory=list)
    status: str = "running"