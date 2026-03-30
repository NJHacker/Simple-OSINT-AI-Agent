from src.agent.reporter import render_markdown_report
from src.agent.schemas import AttackHypothesis, InvestigationReport, SourceUsed, SubjectNormalized


def test_render_markdown_report_includes_sections():
    report = InvestigationReport(
        subjects=[
            SubjectNormalized(
                id="subj_1",
                original_value="ExampleCo",
                detected_type="company",
                normalized_value="ExampleCo",
                confidence="high",
                reason="fixture",
            )
        ],
        executive_summary="Example summary.",
        top_3_selected_attack_vectors=[
            AttackHypothesis(
                id="av_1",
                title="Example vector",
                summary="Example vector summary.",
                type="social_engineering",
                confidence="medium",
                target_subject_ids=["subj_1"],
                evidence_refs=["ev1"],
                grounded_facts=["Fact one"],
                concrete_pretexts=["Pretext one"],
                defensive_actions=["Action one"],
                why_it_matters="It matters because it is plausible.",
                why_selected="It was selected due to strong evidence.",
            )
        ],
        sources_used=[
            SourceUsed(
                id="ev1",
                source_type="search_web",
                description="Example source",
                subject_ids=["subj_1"],
            )
        ],
        risk_signals=["Risk signal one"],
        limitations=[],
        rationale="Example rationale.",
        recommended_next_steps=["Next step one"],
    )

    markdown = render_markdown_report(report)

    assert "# Investigation Report" in markdown
    assert "## Executive Summary" in markdown
    assert "## Top 3 Selected Attack Vectors" in markdown
    assert "Example vector" in markdown
    assert "Concrete pretexts:" in markdown
    assert "Defensive actions:" in markdown
