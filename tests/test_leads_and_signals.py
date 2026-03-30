from src.agent.loop import build_investigation_leads, derive_risk_signals
from src.agent.schemas import EvidenceItem, EvidenceObservation, InvestigationState, SubjectNormalized


def make_subject(subject_id: str, subject_type: str, value: str) -> SubjectNormalized:
    return SubjectNormalized(
        id=subject_id,
        original_value=value,
        detected_type=subject_type,
        normalized_value=value,
        confidence="high",
        reason="test fixture",
    )


def make_evidence(evidence_id: str, subject_ids: list[str], observations: list[str]) -> EvidenceItem:
    return EvidenceItem(
        id=evidence_id,
        subject_ids=subject_ids,
        source_type="search_web",
        query_or_action="fixture",
        description="fixture description",
        raw_result=None,
        extracted_observations=[
            EvidenceObservation(
                observation=item,
                confidence="high",
                relevance="fixture relevance",
            )
            for item in observations
        ],
        reliability_note="fixture note",
    )


def test_build_investigation_leads_company_only():
    company = make_subject("subj_1", "company", "Meta")

    state = InvestigationState(
        subjects=[company],
        evidence_items=[
            make_evidence(
                "ev1",
                ["subj_1"],
                [
                    "Meta has a public developer portal with Graph API documentation.",
                    "Meta maintains named partner integrations with Microsoft Teams and Workplace.",
                    "Meta publishes careers pages and partner program references.",
                ],
            )
        ],
    )

    leads = build_investigation_leads(state)

    assert len(leads) >= 1
    assert any(lead.lead_type in {"supply_chain", "social_engineering", "third_party_risk"} for lead in leads)


def test_derive_risk_signals_detects_provider_and_developer_surface():
    company = make_subject("subj_1", "company", "ExampleCo")
    domain = make_subject("subj_2", "domain", "example.com")

    state = InvestigationState(
        subjects=[company, domain],
        evidence_items=[
            make_evidence(
                "ev1",
                ["subj_1", "subj_2"],
                [
                    "A deprecated legacy API reference is still public.",
                    "The site uses WordPress and WP Engine.",
                    "DNS and provider relationships include GoDaddy, Route 53, and Cloudflare.",
                    "Public partner and integration documentation is available.",
                ],
            )
        ],
    )

    signals = derive_risk_signals(state)

    assert any("deprecated" in signal.lower() for signal in signals)
    assert any("wordpress" in signal.lower() or "cms" in signal.lower() for signal in signals)
    assert any("provider" in signal.lower() for signal in signals)
