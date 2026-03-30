from src.agent.loop import _parse_attack_vector_text, _parse_batch_summary_text


def test_parse_batch_summary_text():
    text = """
BATCH_ID: batch_1
EVIDENCE_REFS: ev1, ev2

FACTUAL_SUMMARY:
- Fact one
- Fact two

SECURITY_IMPLICATIONS:
- Implication one

NOTABLE_ENTITIES:
- Cloudflare
- Route 53

SOURCE_QUALITY_NOTES:
- Official documentation present
""".strip()

    parsed = _parse_batch_summary_text(text)

    assert parsed.batch_id == "batch_1"
    assert parsed.evidence_refs == ["ev1", "ev2"]
    assert parsed.factual_summary == ["Fact one", "Fact two"]
    assert parsed.security_implications == ["Implication one"]
    assert parsed.notable_entities == ["Cloudflare", "Route 53"]
    assert parsed.source_quality_notes == ["Official documentation present"]


def test_parse_attack_vector_text():
    text = """
TITLE: Provider-themed admin deception
SUMMARY: Public provider context supports believable admin-targeting lures.
TYPE: third_party_risk
CONFIDENCE: high
TARGET_SUBJECT_IDS: subj_1, subj_2
EVIDENCE_REFS: ev4, ev6

GROUNDED_FACTS:
- GoDaddy is the registrar.
- Route 53 is used for DNS.

CONCRETE_PRETEXTS:
- Fake registrar renewal notice.
- DNS anomaly verification request.

DEFENSIVE_ACTIONS:
- Enforce hardware MFA on registrar and DNS admin consoles.
- Require out-of-band approval for DNS changes.

WHY_IT_MATTERS:
The provider context makes admin-targeting phishing more believable.

WHY_SELECTED:
It is directly grounded in public registrar and DNS evidence.
""".strip()

    parsed = _parse_attack_vector_text(text, vector_id="av_1")

    assert parsed.id == "av_1"
    assert parsed.title == "Provider-themed admin deception"
    assert parsed.type == "third_party_risk"
    assert parsed.confidence == "high"
    assert parsed.target_subject_ids == ["subj_1", "subj_2"]
    assert parsed.evidence_refs == ["ev4", "ev6"]
    assert parsed.grounded_facts == ["GoDaddy is the registrar.", "Route 53 is used for DNS."]
    assert parsed.concrete_pretexts[0] == "Fake registrar renewal notice."
    assert parsed.defensive_actions[0].startswith("Enforce hardware MFA")
