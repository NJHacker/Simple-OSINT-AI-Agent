from __future__ import annotations

from src.agent.schemas import SubjectNormalized


def build_seed_queries(subject: SubjectNormalized) -> list[dict]:
    value = subject.normalized_value

    if subject.detected_type == "person":
        return [
            {"action": "search_web", "query": f'"{value}" LinkedIn OR biography OR profile'},
            {"action": "search_web", "query": f'"{value}" interview OR podcast OR conference'},
            {"action": "search_web", "query": f'"{value}" education OR background OR experience'},
            {"action": "search_web", "query": f'"{value}" investor OR advisor OR board'},
            {"action": "search_news", "query": f'"{value}"'},
        ]

    if subject.detected_type == "company":
        return [
            {"action": "search_web", "query": f'"{value}" official site leadership careers'},
            {"action": "search_web", "query": f'"{value}" integrations partners infrastructure'},
            {"action": "search_web", "query": f'"{value}" API docs developers'},
            {"action": "search_web", "query": f'"{value}" security architecture blog'},
            {"action": "search_news", "query": f'"{value}" incident breach regulatory funding'},
        ]

    if subject.detected_type == "domain":
        return [
            {"action": "whois_lookup", "query": None},
            {"action": "dns_lookup", "query": None},
            {"action": "fetch_website", "query": None},
            {"action": "fetch_robots_txt", "query": None},
            {"action": "fetch_security_txt", "query": None},
            {"action": "fetch_tls_certificate", "query": None},
        ]

    return []