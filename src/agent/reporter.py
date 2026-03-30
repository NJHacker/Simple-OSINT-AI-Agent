from __future__ import annotations

from src.agent.schemas import InvestigationReport


def render_markdown_report(report: InvestigationReport) -> str:
    lines: list[str] = []

    lines.append("# Investigation Report")
    lines.append("")

    lines.append("## Subjects")
    for subject in report.subjects:
        lines.append(
            f"- **{subject.id}** | type: `{subject.detected_type}` | value: `{subject.normalized_value}`"
        )
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(report.executive_summary)
    lines.append("")

    lines.append("## Top 3 Selected Attack Vectors")
    if report.top_3_selected_attack_vectors:
        for vector in report.top_3_selected_attack_vectors:
            lines.append(f"### {vector.title}")
            lines.append(f"- Type: `{vector.type}`")
            lines.append(f"- Confidence: `{vector.confidence}`")
            lines.append(f"- Target subjects: {', '.join(vector.target_subject_ids)}")
            lines.append(f"- Evidence refs: {', '.join(vector.evidence_refs)}")
            lines.append(f"- Summary: {vector.summary}")
            lines.append(f"- Why it matters: {vector.why_it_matters}")
            lines.append(f"- Why selected: {vector.why_selected}")

            if vector.grounded_facts:
                lines.append("- Grounded facts:")
                for item in vector.grounded_facts:
                    lines.append(f"  - {item}")

            if vector.concrete_pretexts:
                lines.append("- Concrete pretexts:")
                for item in vector.concrete_pretexts:
                    lines.append(f"  - {item}")

            if vector.defensive_actions:
                lines.append("- Defensive actions:")
                for item in vector.defensive_actions:
                    lines.append(f"  - {item}")

            lines.append("")
    else:
        lines.append("- No attack vectors were selected.")
        lines.append("")

    lines.append("## Sources Used")
    if report.sources_used:
        for source in report.sources_used:
            lines.append(
                f"- **{source.id}** | `{source.source_type}` | subjects: {', '.join(source.subject_ids)} | {source.description}"
            )
    else:
        lines.append("- No sources recorded.")
    lines.append("")

    lines.append("## Risk Signals")
    if report.risk_signals:
        for item in report.risk_signals:
            lines.append(f"- {item}")
    else:
        lines.append("- None recorded.")
    lines.append("")

    lines.append("## Rationale")
    lines.append(report.rationale)
    lines.append("")

    lines.append("## Recommended Next Steps")
    if report.recommended_next_steps:
        for item in report.recommended_next_steps:
            lines.append(f"- {item}")
    else:
        lines.append("- None.")
    lines.append("")

    return "\n".join(lines)