from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.agent.query_builder import build_seed_queries
from src.agent.schemas import (
    AnalyzeEvidenceResponse,
    AttackHypothesis,
    DetectSubjectsResponse,
    EvidenceBatchSummary,
    EvidenceItem,
    ExecutiveSummaryResponse,
    InvestigationLead,
    InvestigationPlan,
    InvestigationReport,
    InvestigationState,
    NextActionDecision,
    ReportWrapUpResponse,
    SourceUsed,
    SubjectNormalized,
    SubjectsEnvelope,
)
from src.agent.state import build_investigation_state
from src.llm.claude_client import ClaudeClient
from src.tools.registry import execute_action
from src.utils.config import Settings
from src.utils.prompts import load_prompt

logger = logging.getLogger("simple_ai_agent.loop")

DETECT_SUBJECTS_SYSTEM_PROMPT = """
You classify investigation subjects for a passive OSINT agent.

Rules:
- Allowed subject types: person, company, domain.
- Return valid JSON only.
- Do not add commentary outside JSON.
- Preserve the original value.
- Normalize domains to lowercase.
- For company/person names, keep normalization conservative.
- If user provided a type, verify it and correct it only if clearly wrong.
- Confidence must be one of: low, medium, high.
""".strip()

PLAN_INVESTIGATION_SYSTEM_PROMPT = """
You are planning a passive OSINT investigation for a small proof of concept.

Rules:
- Return valid JSON only.
- Be concise.
- Use only tools that are actually supported by this POC.
- Supported tools are: search_web, search_news, dns_lookup, whois_lookup, fetch_website, fetch_robots_txt, fetch_security_txt, fetch_tls_certificate.
- Do not suggest external services, websites, APIs, or tools that are not implemented.
- Do not claim confirmed vulnerabilities.
- Focus on realistic public-information collection that can later support attack-vector hypotheses.
- Stay within passive investigation only.
""".strip()

CHOOSE_NEXT_ACTION_SYSTEM_PROMPT = """
You are selecting the next action for a passive OSINT investigation agent.

Rules:
- Return valid JSON only.
- Use only these actions: search_web, search_news, dns_lookup, whois_lookup, fetch_website, fetch_robots_txt, fetch_security_txt, fetch_tls_certificate, generate_attack_hypotheses, finalize_report
- Prefer short, practical actions that improve attack-vector analysis.
- dns_lookup, whois_lookup, fetch_robots_txt, fetch_security_txt, and fetch_tls_certificate should only be used for domain subjects.
- fetch_website should only be used for company or domain subjects.
- Prefer actions that add new evidence rather than repeating the same source.
- finalize_report should be chosen only when enough useful evidence has been collected.
- Do not claim confirmed vulnerabilities.
""".strip()

ANALYZE_EVIDENCE_SYSTEM_PROMPT = """
You are analyzing raw tool output from a passive OSINT investigation.

Rules:
- Return valid JSON only.
- Extract only observations that are supported by the tool output.
- Separate facts from assumptions.
- Keep observations concise and practical.
- Preserve concrete proper nouns where present.
- Do not claim confirmed vulnerabilities or exploitation.
""".strip()

SUMMARIZE_EVIDENCE_BATCH_SYSTEM_PROMPT = """
You are summarizing a small evidence batch for later final-report synthesis.

Rules:
- Return plain tagged text only.
- Use only the provided evidence.
- Preserve concrete names, products, vendors, places, and events when present.
- Focus on concise facts and security implications.
- Do not claim confirmed vulnerabilities.
""".strip()

REFINE_ATTACK_VECTOR_SYSTEM_PROMPT = """
You are refining one attack vector for a passive OSINT investigation.

Rules:
- Return plain tagged text only.
- Use only the provided lead, relevant evidence summaries, and risk signals.
- Be specific and practical.
- Distinguish clearly between targeting the company through provider-themed social engineering and compromising the provider itself.
- Do not imply that compromise of major providers like AWS or GoDaddy is itself a likely attack path unless the evidence directly supports that conclusion.
- Focus on credible scenarios such as phishing admins, change-approval deception, support impersonation, or provider-themed workflow abuse.
- Attack vectors are hypotheses, not confirmed vulnerabilities.
""".strip()

WRITE_EXECUTIVE_SUMMARY_SYSTEM_PROMPT = """
You are writing a concise executive summary for a passive OSINT investigation.

Rules:
- Return valid JSON only.
- Use only the provided subjects, refined attack vectors, and risk signals.
- Be concrete and practical.
- Do not mention counts.
""".strip()

WRITE_REPORT_WRAPUP_SYSTEM_PROMPT = """
You are writing the rationale and next steps for a passive OSINT investigation report.

Rules:
- Return valid JSON only.
- Use only the provided attack vectors and risk signals.
- Be concise and action-oriented.
""".strip()


def _strip_code_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z0-9_+-]*\n?", "", stripped)
        stripped = re.sub(r"\n?```$", "", stripped)
    return stripped.strip()


def _extract_tag_value(text: str, tag: str) -> str:
    pattern = rf"^{re.escape(tag)}:\s*(.*)$"
    for line in text.splitlines():
        match = re.match(pattern, line.strip())
        if match:
            return match.group(1).strip()
    return ""


def _extract_tagged_block(text: str, tag: str, stop_tags: list[str]) -> str:
    lines = text.splitlines()
    start_index = None

    for index, line in enumerate(lines):
        if line.strip() == f"{tag}:":
            start_index = index + 1
            break

    if start_index is None:
        return ""

    collected = []
    stop_set = {f"{item}:" for item in stop_tags}

    for line in lines[start_index:]:
        if line.strip() in stop_set:
            break
        collected.append(line)

    return "\n".join(collected).strip()


def _parse_bullet_block(block: str) -> list[str]:
    items = []

    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- "):
            items.append(line[2:].strip())
        else:
            items.append(line)

    return [item for item in items if item]


def _parse_csv_field(value: str) -> list[str]:
    if not value.strip():
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def detect_subjects(
    llm_client: ClaudeClient,
    subjects_envelope: SubjectsEnvelope,
) -> list[SubjectNormalized]:
    user_prompt = load_prompt(
        "detect_subjects.txt",
        subjects_json=json.dumps(
            subjects_envelope.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
        ),
    )

    response = llm_client.generate_json(
        system_prompt=DETECT_SUBJECTS_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=DetectSubjectsResponse,
        max_tokens=llm_client.settings.action_max_tokens,
    )
    return response.subjects


def build_fallback_plan(subjects: list[SubjectNormalized]) -> InvestigationPlan:
    goals = []
    initial_actions = []
    notes = [
        "Passive OSINT only.",
        "Attack vectors are hypotheses, not validated vulnerabilities.",
    ]

    for index, subject in enumerate(subjects[:3], start=1):
        if subject.detected_type == "company":
            goal_text = "Collect public company context, partner surface, and external relationships."
            initial_actions.extend(
                [
                    f"search_web on {subject.id}",
                    f"search_news on {subject.id}",
                    f"fetch_website on {subject.id}",
                ]
            )
        elif subject.detected_type == "domain":
            goal_text = "Collect passive domain registration, DNS, web, and certificate information."
            initial_actions.extend(
                [
                    f"whois_lookup on {subject.id}",
                    f"dns_lookup on {subject.id}",
                    f"fetch_website on {subject.id}",
                    f"fetch_tls_certificate on {subject.id}",
                ]
            )
        else:
            goal_text = "Collect public professional context, affiliations, and public persona indicators."
            initial_actions.extend(
                [
                    f"search_web on {subject.id}",
                    f"search_news on {subject.id}",
                ]
            )

        goals.append(
            {
                "subject_id": subject.id,
                "priority": index,
                "goal": goal_text,
            }
        )

    deduped_actions: list[str] = []
    for action in initial_actions:
        if action not in deduped_actions:
            deduped_actions.append(action)

    return InvestigationPlan(
        summary="Initial passive OSINT plan built for the provided subjects.",
        goals=goals,
        initial_actions=deduped_actions[:6],
        notes=notes,
    )


def plan_investigation(
    llm_client: ClaudeClient,
    subjects: list[SubjectNormalized],
) -> InvestigationPlan:
    user_prompt = load_prompt(
        "plan_investigation.txt",
        subjects_json=json.dumps(
            [subject.model_dump(mode="json") for subject in subjects],
            indent=2,
            ensure_ascii=False,
        ),
    )

    try:
        return llm_client.generate_json(
            system_prompt=PLAN_INVESTIGATION_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            response_model=InvestigationPlan,
            max_tokens=llm_client.settings.action_max_tokens,
        )
    except Exception as exc:
        logger.warning("LLM planning failed, using fallback plan: %s", exc)
        return build_fallback_plan(subjects)


def _build_compact_state(state: InvestigationState) -> dict:
    compact_evidence = []

    for item in state.evidence_items:
        compact_evidence.append(
            {
                "id": item.id,
                "subject_ids": item.subject_ids,
                "source_type": item.source_type,
                "query_or_action": item.query_or_action,
                "description": item.description,
                "observations": [obs.observation for obs in item.extracted_observations],
                "reliability_note": item.reliability_note,
            }
        )

    return {
        "subjects": [subject.model_dump(mode="json") for subject in state.subjects],
        "steps_taken": state.steps_taken,
        "evidence_items": compact_evidence,
        "investigation_leads": [lead.model_dump(mode="json") for lead in state.investigation_leads],
        "limitations": state.limitations,
        "status": state.status,
    }


def choose_next_action(
    llm_client: ClaudeClient,
    state: InvestigationState,
    plan: InvestigationPlan,
) -> NextActionDecision:
    user_prompt = load_prompt(
        "choose_next_action.txt",
        state_json=json.dumps(_build_compact_state(state), indent=2, ensure_ascii=False),
        plan_json=json.dumps(plan.model_dump(mode="json"), indent=2, ensure_ascii=False),
    )

    return llm_client.generate_json(
        system_prompt=CHOOSE_NEXT_ACTION_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=NextActionDecision,
        max_tokens=llm_client.settings.action_max_tokens,
    )


def analyze_evidence(
    llm_client: ClaudeClient,
    decision: NextActionDecision,
    tool_result: dict,
) -> AnalyzeEvidenceResponse:
    user_prompt = load_prompt(
        "analyze_observation.txt",
        decision_json=json.dumps(decision.model_dump(mode="json"), indent=2, ensure_ascii=False),
        tool_result_json=json.dumps(tool_result, indent=2, ensure_ascii=False),
    )

    return llm_client.generate_json(
        system_prompt=ANALYZE_EVIDENCE_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=AnalyzeEvidenceResponse,
        max_tokens=llm_client.settings.action_max_tokens,
    )


def _find_subject(subjects: list[SubjectNormalized], subject_id: str | None) -> SubjectNormalized:
    if not subject_id:
        raise ValueError("subject_id is required for executable actions")

    for subject in subjects:
        if subject.id == subject_id:
            return subject

    raise ValueError(f"Unknown subject_id: {subject_id}")


def _build_evidence_item(
    state: InvestigationState,
    decision: NextActionDecision,
    analysis: AnalyzeEvidenceResponse,
    tool_result: dict,
) -> EvidenceItem:
    evidence_id = f"ev{len(state.evidence_items) + 1}"
    query_or_action = decision.query if decision.query else decision.action

    return EvidenceItem(
        id=evidence_id,
        subject_ids=[decision.subject_id] if decision.subject_id else [],
        source_type=decision.action,
        query_or_action=query_or_action,
        description=analysis.description,
        raw_result=tool_result,
        extracted_observations=analysis.extracted_observations,
        reliability_note=analysis.reliability_note,
    )


def _fallback_analysis(decision: NextActionDecision, tool_result: dict) -> AnalyzeEvidenceResponse:
    description = f"Collected data from {decision.action}."
    observations = []

    if isinstance(tool_result, dict) and "results" in tool_result:
        results = tool_result.get("results", [])
        if not results:
            description = f"{decision.action} returned no results."
        else:
            first = results[0]
            title = first.get("title") or "First result"
            snippet = first.get("snippet") or ""
            observations.append(
                {
                    "observation": f"{title}: {snippet[:180]}".strip(),
                    "confidence": "medium",
                    "relevance": "May provide an initial clue for manual follow-up.",
                }
            )

    return AnalyzeEvidenceResponse(
        description=description,
        extracted_observations=observations,
        reliability_note="Deterministic fallback due to LLM analysis failure.",
    )


def _seed_task_worker(
    settings: Settings,
    subject: SubjectNormalized,
    decision: NextActionDecision,
) -> tuple[NextActionDecision, AnalyzeEvidenceResponse, dict]:
    worker_client = ClaudeClient(settings)
    tool_result = execute_action(
        decision=decision,
        subject_value=subject.normalized_value,
        subject_type=subject.detected_type,
        settings=settings,
    )

    try:
        analysis = analyze_evidence(worker_client, decision, tool_result)
    except Exception as exc:
        logger.warning("Seed analysis failed for %s: %s", decision.query or decision.action, exc)
        analysis = _fallback_analysis(decision, tool_result)

    return decision, analysis, tool_result


def _execute_seed_queries(
    settings: Settings,
    state: InvestigationState,
) -> InvestigationState:
    tasks: list[tuple[int, SubjectNormalized, NextActionDecision]] = []
    seed_budget = max(settings.max_agent_steps - 2, 1)

    for subject in state.subjects:
        for seed in build_seed_queries(subject):
            if len(tasks) >= seed_budget:
                break

            tasks.append(
                (
                    len(tasks),
                    subject,
                    NextActionDecision(
                        action=seed["action"],
                        subject_id=subject.id,
                        reason="Deterministic seed collection for early evidence gathering.",
                        query=seed["query"],
                        expected_output="Initial high-signal OSINT evidence.",
                    ),
                )
            )

        if len(tasks) >= seed_budget:
            break

    if not tasks:
        return state

    max_workers = min(3, len(tasks))
    results: list[tuple[int, NextActionDecision, AnalyzeEvidenceResponse, dict]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_seed_task_worker, settings, subject, decision): (index, decision)
            for index, subject, decision in tasks
        }

        for future in as_completed(future_map):
            index, decision = future_map[future]
            try:
                resolved_decision, analysis, tool_result = future.result()
                results.append((index, resolved_decision, analysis, tool_result))
            except Exception as exc:
                logger.warning("Seed task failed for %s: %s", decision.query or decision.action, exc)

    for _, decision, analysis, tool_result in sorted(results, key=lambda item: item[0]):
        evidence_item = _build_evidence_item(state, decision, analysis, tool_result)
        state.evidence_items.append(evidence_item)
        state.steps_taken += 1

        logger.info(
            "Seed evidence added | id=%s | action=%s | query=%s",
            evidence_item.id,
            decision.action,
            decision.query,
        )

    return state


def run_initial_phase(
    llm_client: ClaudeClient,
    subjects_envelope: SubjectsEnvelope,
) -> tuple[InvestigationState, InvestigationPlan]:
    detected_subjects = detect_subjects(llm_client, subjects_envelope)
    state = build_investigation_state(detected_subjects)
    plan = plan_investigation(llm_client, detected_subjects)
    return state, plan


def run_collection_phase(
    llm_client: ClaudeClient,
    settings: Settings,
    state: InvestigationState,
    plan: InvestigationPlan,
) -> InvestigationState:
    state = _execute_seed_queries(settings, state)

    while state.steps_taken < settings.max_agent_steps:
        decision = choose_next_action(llm_client, state, plan)

        logger.info(
            "Step %s | action=%s | subject_id=%s | query=%s",
            state.steps_taken + 1,
            decision.action,
            decision.subject_id,
            decision.query,
        )

        if decision.action in {"finalize_report", "generate_attack_hypotheses"}:
            state.status = "collection_complete"
            break

        subject = _find_subject(state.subjects, decision.subject_id)
        tool_result = execute_action(
            decision=decision,
            subject_value=subject.normalized_value,
            subject_type=subject.detected_type,
            settings=settings,
        )

        try:
            analysis = analyze_evidence(llm_client, decision, tool_result)
        except Exception as exc:
            logger.warning("Analysis failed for %s, using fallback: %s", decision.query or decision.action, exc)
            analysis = _fallback_analysis(decision, tool_result)

        evidence_item = _build_evidence_item(state, decision, analysis, tool_result)
        state.evidence_items.append(evidence_item)
        state.steps_taken += 1

        logger.info(
            "Evidence added | id=%s | observations=%s",
            evidence_item.id,
            len(evidence_item.extracted_observations),
        )

    if state.steps_taken >= settings.max_agent_steps:
        state.status = "collection_complete"

    return state


def _subject_id_by_type(state: InvestigationState, subject_type: str) -> str | None:
    for subject in state.subjects:
        if subject.detected_type == subject_type:
            return subject.id
    return None


def _subject_value_by_type(state: InvestigationState, subject_type: str) -> str | None:
    for subject in state.subjects:
        if subject.detected_type == subject_type:
            return subject.normalized_value
    return None


def _joined_item_text(item: EvidenceItem) -> str:
    parts = [item.description, item.reliability_note]
    parts.extend(obs.observation for obs in item.extracted_observations)
    return " ".join(part for part in parts if part).lower()


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []

    for item in items:
        normalized = item.strip()
        if not normalized:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    return result


def _collect_facts(
    state: InvestigationState,
    *,
    subject_ids: set[str],
    keywords: list[str],
    limit: int = 4,
) -> tuple[list[str], list[str]]:
    facts: list[str] = []
    refs: list[str] = []

    for item in state.evidence_items:
        if not set(item.subject_ids).intersection(subject_ids):
            continue

        matched = False
        for obs in item.extracted_observations:
            text = obs.observation.lower()
            if any(keyword in text for keyword in keywords):
                facts.append(obs.observation)
                matched = True

        if matched:
            refs.append(item.id)

    return _dedupe_keep_order(facts)[:limit], _dedupe_keep_order(refs)


def derive_risk_signals(state: InvestigationState) -> list[str]:
    all_text = " ".join(_joined_item_text(item) for item in state.evidence_items)

    signals: list[str] = []

    if any(token in all_text for token in ["deprecated", "sandbox", "legacy api", "developer portal"]):
        signals.append(
            "Public developer references include deprecated, sandbox, or legacy-style material that should be reviewed for stale guidance, confusing migrations, or lower-trust entry points."
        )

    if any(token in all_text for token in ["wordpress", "wp engine", "wp-admin", "admin-ajax"]):
        signals.append(
            "The public web presence appears to expose CMS or marketing-stack indicators that may justify review of plugin governance, admin workflows, and publicly reachable helper endpoints."
        )

    vendor_hits = []
    for vendor in ["godaddy", "route 53", "cloudflare", "cisco ironport", "iphmx", "zapier", "zoom", "adobe", "anthropic"]:
        if vendor in all_text:
            vendor_hits.append(vendor)

    if vendor_hits:
        signals.append(
            f"Publicly visible provider dependencies such as {', '.join(vendor_hits[:5])} can support believable provider-themed phishing or admin-workflow deception targeting the company's own staff; this does not imply a likely compromise of those providers themselves."
        )

    if any(token in all_text for token in ["linkedin", "conference", "speaker", "interview", "education", "new york", "investor"]):
        signals.append(
            "The public executive footprint contains enough professional, event, and background detail to support tailored executive social-engineering pretexts."
        )

    if any(token in all_text for token in ["partner", "integration", "api", "keylink", "agent", "developer"]):
        signals.append(
            "Public references to integrations, partner relationships, APIs, and named platform components indicate trust-boundary and onboarding themes worth testing in tabletop or phishing simulations."
        )

    return _dedupe_keep_order(signals)[:5]


def build_investigation_leads(state: InvestigationState) -> list[InvestigationLead]:
    leads: list[InvestigationLead] = []

    company_id = _subject_id_by_type(state, "company")
    domain_id = _subject_id_by_type(state, "domain")
    person_id = _subject_id_by_type(state, "person")
    person_value = _subject_value_by_type(state, "person")
    company_value = _subject_value_by_type(state, "company")
    domain_value = _subject_value_by_type(state, "domain")

    if person_id:
        facts, refs = _collect_facts(
            state,
            subject_ids={person_id},
            keywords=["linkedin", "conference", "speaker", "interview", "education", "new york", "investor", "background"],
        )

        if facts:
            leads.append(
                InvestigationLead(
                    id="lead_1",
                    title="Executive public-persona social engineering lead",
                    subject_ids=[sid for sid in [person_id, company_id] if sid],
                    lead_type="social_engineering",
                    summary="The public executive footprint appears rich enough to support tailored executive phishing or impersonation scenarios.",
                    evidence_refs=refs,
                    confidence="high",
                    operator_hint="Focus on concrete executive-oriented pretexts grounded in discovered events, profiles, education, investing activity, or public appearances. Prefer specific lures over generic networking language.",
                    grounded_facts=facts,
                    suggested_follow_up_queries=[
                        f'"{person_value}" conference' if person_value else "",
                        f'"{person_value}" interview' if person_value else "",
                        f'"{person_value}" investor' if person_value else "",
                    ],
                )
            )

    third_party_keywords = ["godaddy", "route 53", "cloudflare", "cisco ironport", "iphmx", "zapier", "zoom", "adobe", "anthropic"]
    third_party_subject_ids = {sid for sid in [company_id, domain_id] if sid}
    if third_party_subject_ids:
        facts, refs = _collect_facts(
            state,
            subject_ids=third_party_subject_ids,
            keywords=third_party_keywords,
        )

        if facts:
            title_target = company_value or domain_value or "the target organization"

            leads.append(
                InvestigationLead(
                    id="lead_2",
                    title="Provider-themed admin deception against registrar, DNS, and SaaS workflows",
                    subject_ids=list(third_party_subject_ids),
                    lead_type="third_party_risk",
                    summary=f"Visible registrar, DNS, CDN, and SaaS relationships for {title_target} could enable believable provider-themed lures against the company's own admins or operators.",
                    evidence_refs=refs,
                    confidence="high",
                    operator_hint="Do not frame this as compromising AWS, GoDaddy, Cloudflare, or another provider directly. Frame it as deception or phishing against the company's own staff who manage registrar, DNS, email, CDN, or SaaS workflows.",
                    grounded_facts=facts,
                    suggested_follow_up_queries=[
                        f"site:{domain_value} cloudflare" if domain_value else "",
                        f"site:{domain_value} zapier" if domain_value else "",
                        f"site:{domain_value} zoom" if domain_value else "",
                    ],
                )
            )

    platform_keywords = ["api", "developer", "partner", "integration", "keylink", "agent", "deprecated", "sandbox", "policy engine"]
    platform_subject_ids = {sid for sid in [company_id, domain_id] if sid}
    if platform_subject_ids:
        facts, refs = _collect_facts(
            state,
            subject_ids=platform_subject_ids,
            keywords=platform_keywords,
        )

        if facts:
            leads.append(
                InvestigationLead(
                    id="lead_3",
                    title="API, developer, and partner-surface follow-up lead",
                    subject_ids=list(platform_subject_ids),
                    lead_type="supply_chain",
                    summary="Public API, developer, and integration references provide enough language and context for realistic partner- or platform-themed pretexts.",
                    evidence_refs=refs,
                    confidence="medium",
                    operator_hint="Focus on named APIs, developer portals, sandbox/deprecated references, partner onboarding, integration validation, or named platform components. Keep the scenario tied to the company's own workflows and trust boundaries.",
                    grounded_facts=facts,
                    suggested_follow_up_queries=[
                        f"site:{domain_value} api" if domain_value else "",
                        f"site:{domain_value} developer" if domain_value else "",
                        f'"{company_value}" partner integration' if company_value else "",
                    ],
                )
            )
    hiring_keywords = ["careers", "job", "hiring", "greenhouse", "recruit", "role", "opening"]
    if company_id:
        facts, refs = _collect_facts(
            state,
            subject_ids={company_id},
            keywords=hiring_keywords,
        )

        if facts:
            leads.append(
                InvestigationLead(
                    id=f"lead_{len(leads) + 1}",
                    title="Hiring and recruiter-themed deception lead",
                    subject_ids=[company_id],
                    lead_type="social_engineering",
                    summary="Public hiring and recruiting references can support recruiter-, candidate-, or role-themed social engineering against internal staff.",
                    evidence_refs=refs,
                    confidence="medium",
                    operator_hint="Focus on named roles, hiring flows, ATS providers, recruiter communication, or role-specific business context.",
                    grounded_facts=facts,
                    suggested_follow_up_queries=[
                        f'"{company_value}" careers' if company_value else "",
                        f'"{company_value}" greenhouse' if company_value else "",
                        f'"{company_value}" hiring role' if company_value else "",
                    ],
                )
            )

    compliance_keywords = ["regulatory", "policy", "investor", "press", "compliance", "legal", "announcement"]
    if company_id:
        facts, refs = _collect_facts(
            state,
            subject_ids={company_id},
            keywords=compliance_keywords,
        )

        if facts:
            leads.append(
                InvestigationLead(
                    id=f"lead_{len(leads) + 1}",
                    title="Compliance, policy, or partner-communication deception lead",
                    subject_ids=[company_id],
                    lead_type="third_party_risk",
                    summary="Public policy, compliance, investor, or partner communication themes can support realistic deception against corporate, legal, or partner-facing staff.",
                    evidence_refs=refs,
                    confidence="medium",
                    operator_hint="Focus on compliance review, policy update, legal notice, investor communication, or public announcement follow-up themes grounded in the evidence.",
                    grounded_facts=facts,
                    suggested_follow_up_queries=[
                        f'"{company_value}" compliance' if company_value else "",
                        f'"{company_value}" investor relations' if company_value else "",
                        f'"{company_value}" policy announcement' if company_value else "",
                    ],
                )
            )

    for lead in leads:
        lead.suggested_follow_up_queries = [q for q in lead.suggested_follow_up_queries if q]

    return leads[:5]


def _chunk_list(items: list[EvidenceItem], size: int) -> list[list[EvidenceItem]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _fallback_batch_summary(batch_id: str, batch: list[EvidenceItem]) -> EvidenceBatchSummary:
    facts = []
    quality_notes = []

    for item in batch:
        facts.extend(obs.observation for obs in item.extracted_observations[:2])
        if item.reliability_note:
            quality_notes.append(item.reliability_note)

    return EvidenceBatchSummary(
        batch_id=batch_id,
        evidence_refs=[item.id for item in batch],
        factual_summary=_dedupe_keep_order(facts)[:4],
        security_implications=[],
        notable_entities=[],
        source_quality_notes=_dedupe_keep_order(quality_notes)[:2],
    )


def _parse_batch_summary_text(text: str) -> EvidenceBatchSummary:
    clean = _strip_code_fences(text)

    return EvidenceBatchSummary(
        batch_id=_extract_tag_value(clean, "BATCH_ID"),
        evidence_refs=_parse_csv_field(_extract_tag_value(clean, "EVIDENCE_REFS")),
        factual_summary=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "FACTUAL_SUMMARY",
                ["SECURITY_IMPLICATIONS", "NOTABLE_ENTITIES", "SOURCE_QUALITY_NOTES"],
            )
        ),
        security_implications=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "SECURITY_IMPLICATIONS",
                ["NOTABLE_ENTITIES", "SOURCE_QUALITY_NOTES"],
            )
        ),
        notable_entities=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "NOTABLE_ENTITIES",
                ["SOURCE_QUALITY_NOTES"],
            )
        ),
        source_quality_notes=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "SOURCE_QUALITY_NOTES",
                [],
            )
        ),
    )


def _summarize_batch_worker(
    settings: Settings,
    batch_id: str,
    batch: list[EvidenceItem],
) -> EvidenceBatchSummary:
    worker_client = ClaudeClient(settings)
    compact_batch = []

    for item in batch:
        compact_batch.append(
            {
                "id": item.id,
                "subject_ids": item.subject_ids,
                "source_type": item.source_type,
                "query_or_action": item.query_or_action,
                "description": item.description,
                "observations": [obs.observation for obs in item.extracted_observations],
                "reliability_note": item.reliability_note,
            }
        )

    user_prompt = load_prompt(
        "summarize_evidence_batch.txt",
        batch_id=batch_id,
        batch_json=json.dumps(compact_batch, indent=2, ensure_ascii=False),
    )

    try:
        raw_text = worker_client.generate_text(
            system_prompt=SUMMARIZE_EVIDENCE_BATCH_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=settings.action_max_tokens,
        )
        return _parse_batch_summary_text(raw_text)
    except Exception as exc:
        logger.warning("Evidence batch summary failed for %s: %s", batch_id, exc)
        return _fallback_batch_summary(batch_id, batch)


def summarize_evidence_batches(
    settings: Settings,
    state: InvestigationState,
) -> list[EvidenceBatchSummary]:
    batches = _chunk_list(state.evidence_items, 3)
    if not batches:
        return []

    max_workers = min(3, len(batches))
    results: list[tuple[int, EvidenceBatchSummary]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_summarize_batch_worker, settings, f"batch_{index + 1}", batch): index
            for index, batch in enumerate(batches)
        }

        for future in as_completed(future_map):
            index = future_map[future]
            summary = future.result()
            results.append((index, summary))

    return [summary for _, summary in sorted(results, key=lambda item: item[0])]


def _build_sources_used(state: InvestigationState) -> list[SourceUsed]:
    return [
        SourceUsed(
            id=item.id,
            source_type=item.source_type,
            description=item.description,
            subject_ids=item.subject_ids,
        )
        for item in state.evidence_items
    ]


def _lead_to_attack_vector(lead: InvestigationLead, index: int) -> AttackHypothesis:
    valid_types = {
        "social_engineering",
        "brand_impersonation",
        "credential_attack",
        "supply_chain",
        "public_exposure",
        "infrastructure_targeting",
        "third_party_risk",
        "known_vulnerability_association",
    }
    vector_type = lead.lead_type if lead.lead_type in valid_types else "other"

    return AttackHypothesis(
        id=f"av_{index}",
        title=lead.title,
        summary=lead.summary,
        type=vector_type,
        confidence=lead.confidence,
        target_subject_ids=lead.subject_ids,
        evidence_refs=lead.evidence_refs,
        grounded_facts=lead.grounded_facts,
        concrete_pretexts=[],
        defensive_actions=[],
        why_it_matters=lead.why_it_matters or lead.summary,
        why_selected="Derived from deterministic lead because LLM refinement failed.",
    )


def _relevant_batch_summaries_for_lead(
    lead: InvestigationLead,
    batch_summaries: list[EvidenceBatchSummary],
) -> list[EvidenceBatchSummary]:
    lead_refs = set(lead.evidence_refs)
    return [
        batch
        for batch in batch_summaries
        if lead_refs.intersection(batch.evidence_refs)
    ]


def _parse_attack_vector_text(
    text: str,
    *,
    vector_id: str,
) -> AttackHypothesis:
    clean = _strip_code_fences(text)

    vector_type = _extract_tag_value(clean, "TYPE") or "other"
    confidence = _extract_tag_value(clean, "CONFIDENCE") or "medium"

    why_it_matters = _extract_tagged_block(
        clean,
        "WHY_IT_MATTERS",
        ["WHY_SELECTED"],
    )
    why_selected = _extract_tagged_block(
        clean,
        "WHY_SELECTED",
        [],
    )

    parsed = AttackHypothesis(
        id=vector_id,
        title=_extract_tag_value(clean, "TITLE"),
        summary=_extract_tag_value(clean, "SUMMARY"),
        type=vector_type,
        confidence=confidence,
        target_subject_ids=_parse_csv_field(_extract_tag_value(clean, "TARGET_SUBJECT_IDS")),
        evidence_refs=_parse_csv_field(_extract_tag_value(clean, "EVIDENCE_REFS")),
        grounded_facts=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "GROUNDED_FACTS",
                ["CONCRETE_PRETEXTS", "DEFENSIVE_ACTIONS", "WHY_IT_MATTERS", "WHY_SELECTED"],
            )
        ),
        concrete_pretexts=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "CONCRETE_PRETEXTS",
                ["DEFENSIVE_ACTIONS", "WHY_IT_MATTERS", "WHY_SELECTED"],
            )
        ),
        defensive_actions=_parse_bullet_block(
            _extract_tagged_block(
                clean,
                "DEFENSIVE_ACTIONS",
                ["WHY_IT_MATTERS", "WHY_SELECTED"],
            )
        ),
        why_it_matters=why_it_matters.strip(),
        why_selected=why_selected.strip(),
    )

    if not parsed.title or not parsed.summary:
        raise ValueError("Parsed attack vector is missing title or summary")

    return parsed


def refine_attack_vector(
    llm_client: ClaudeClient,
    lead: InvestigationLead,
    batch_summaries: list[EvidenceBatchSummary],
    risk_signals: list[str],
    vector_id: str,
) -> AttackHypothesis:
    relevant_batches = _relevant_batch_summaries_for_lead(lead, batch_summaries)

    user_prompt = load_prompt(
        "refine_attack_vector.txt",
        lead_json=json.dumps(lead.model_dump(mode="json"), indent=2, ensure_ascii=False),
        batch_summaries_json=json.dumps(
            [batch.model_dump(mode="json") for batch in relevant_batches],
            indent=2,
            ensure_ascii=False,
        ),
        risk_signals_json=json.dumps(risk_signals, indent=2, ensure_ascii=False),
    )

    try:
        raw_text = llm_client.generate_text(
            system_prompt=REFINE_ATTACK_VECTOR_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=llm_client.settings.report_max_tokens,
        )
        return _parse_attack_vector_text(raw_text, vector_id=vector_id)
    except Exception as exc:
        logger.warning("Attack vector refinement failed for %s, using fallback: %s", lead.id, exc)
        fallback = _lead_to_attack_vector(lead, int(vector_id.split("_")[-1]))
        if fallback.type == "third_party_risk":
            fallback.summary = (
                "Public registrar, DNS, CDN, mail, and SaaS relationships support believable provider-themed lures against the company's own admins or operators, without implying likely compromise of those providers themselves."
            )
            fallback.why_it_matters = (
                "Visible provider relationships help attackers craft credible support, re-authentication, billing, or change-approval lures aimed at the company staff responsible for these services."
            )
            fallback.why_selected = (
                "Prioritized because the public provider footprint supports realistic provider-themed deception against the company’s own workflows without assuming compromise of AWS, GoDaddy, or other providers."
            )
        return fallback


def write_executive_summary(
    llm_client: ClaudeClient,
    subjects: list[SubjectNormalized],
    attack_vectors: list[AttackHypothesis],
    risk_signals: list[str],
) -> str:
    user_prompt = load_prompt(
        "write_executive_summary.txt",
        subjects_json=json.dumps([subject.model_dump(mode="json") for subject in subjects], indent=2, ensure_ascii=False),
        attack_vectors_json=json.dumps([vector.model_dump(mode="json") for vector in attack_vectors], indent=2, ensure_ascii=False),
        risk_signals_json=json.dumps(risk_signals, indent=2, ensure_ascii=False),
    )

    response = llm_client.generate_json(
        system_prompt=WRITE_EXECUTIVE_SUMMARY_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=ExecutiveSummaryResponse,
        max_tokens=llm_client.settings.action_max_tokens,
    )
    return response.executive_summary


def write_report_wrapup(
    llm_client: ClaudeClient,
    attack_vectors: list[AttackHypothesis],
    risk_signals: list[str],
) -> ReportWrapUpResponse:
    user_prompt = load_prompt(
        "write_report_wrapup.txt",
        attack_vectors_json=json.dumps([vector.model_dump(mode="json") for vector in attack_vectors], indent=2, ensure_ascii=False),
        risk_signals_json=json.dumps(risk_signals, indent=2, ensure_ascii=False),
    )

    return llm_client.generate_json(
        system_prompt=WRITE_REPORT_WRAPUP_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=ReportWrapUpResponse,
        max_tokens=llm_client.settings.action_max_tokens,
    )


def generate_report(
    llm_client: ClaudeClient,
    settings: Settings,
    state: InvestigationState,
) -> InvestigationReport:
    state.investigation_leads = build_investigation_leads(state)
    risk_signals = derive_risk_signals(state)
    batch_summaries = summarize_evidence_batches(settings, state)
    sources_used = _build_sources_used(state)

    refined_vectors: list[AttackHypothesis] = []
    limitations: list[str] = []

    for index, lead in enumerate(state.investigation_leads[:3], start=1):
        refined_vectors.append(
            refine_attack_vector(
                llm_client=llm_client,
                lead=lead,
                batch_summaries=batch_summaries,
                risk_signals=risk_signals,
                vector_id=f"av_{index}",
            )
        )

    try:
        executive_summary = write_executive_summary(
            llm_client=llm_client,
            subjects=state.subjects,
            attack_vectors=refined_vectors,
            risk_signals=risk_signals,
        )
    except Exception as exc:
        logger.warning("Executive summary generation failed, using fallback: %s", exc)
        executive_summary = (
            "This passive OSINT investigation identified prioritized attack surfaces around executive impersonation, "
            "provider-themed admin deception, and partner/developer-facing workflows. The strongest findings are grounded "
            "in the public executive footprint, visible registrar/DNS/CDN relationships, and public developer or partner content."
        )
        limitations.append("Executive summary fell back to deterministic mode due to LLM output failure.")

    try:
        wrapup = write_report_wrapup(
            llm_client=llm_client,
            attack_vectors=refined_vectors,
            risk_signals=risk_signals,
        )
        rationale = wrapup.rationale
        recommended_next_steps = wrapup.recommended_next_steps
    except Exception as exc:
        logger.warning("Report wrap-up generation failed, using fallback: %s", exc)
        rationale = (
            "The prioritized vectors were selected because they are grounded in public evidence and map to realistic "
            "social-engineering or trust-boundary abuse scenarios rather than speculative provider compromise."
        )
        recommended_next_steps = [
            item
            for vector in refined_vectors
            for item in vector.defensive_actions[:2]
        ][:5]
        limitations.append("Report rationale/next steps fell back to deterministic mode due to LLM output failure.")

    return InvestigationReport(
        subjects=state.subjects,
        executive_summary=executive_summary,
        top_3_selected_attack_vectors=refined_vectors,
        sources_used=sources_used,
        risk_signals=risk_signals,
        limitations=limitations,
        rationale=rationale,
        recommended_next_steps=recommended_next_steps,
    )