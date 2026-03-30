from __future__ import annotations

from src.agent.schemas import ActionType, NextActionDecision, SubjectType
from src.tools.dns_lookup import dns_lookup
from src.tools.fetch_web import fetch_robots_txt, fetch_security_txt, fetch_url
from src.tools.tls_lookup import fetch_tls_certificate
from src.tools.web_search import search_news, search_web
from src.tools.whois_lookup import whois_lookup
from src.utils.config import Settings


def execute_action(
    decision: NextActionDecision,
    subject_value: str,
    subject_type: str,
    settings: Settings,
) -> dict:
    if decision.action == ActionType.SEARCH_WEB:
        if not decision.query:
            raise ValueError("search_web requires query")
        return search_web(decision.query, settings.search_backend)

    if decision.action == ActionType.SEARCH_NEWS:
        if not decision.query:
            raise ValueError("search_news requires query")
        return search_news(decision.query, settings.search_backend)

    if decision.action == ActionType.DNS_LOOKUP:
        if subject_type != SubjectType.DOMAIN.value:
            return {"error": "dns_lookup is only valid for domain subjects"}
        return dns_lookup(subject_value)

    if decision.action == ActionType.WHOIS_LOOKUP:
        if subject_type != SubjectType.DOMAIN.value:
            return {"error": "whois_lookup is only valid for domain subjects"}
        return whois_lookup(subject_value)

    if decision.action == "fetch_website":
        url = subject_value if subject_value.startswith("http") else f"https://{subject_value}"
        return fetch_url(url)

    if decision.action == "fetch_robots_txt":
        if subject_type != SubjectType.DOMAIN.value:
            return {"error": "fetch_robots_txt is only valid for domain subjects"}
        return fetch_robots_txt(subject_value)

    if decision.action == "fetch_security_txt":
        if subject_type != SubjectType.DOMAIN.value:
            return {"error": "fetch_security_txt is only valid for domain subjects"}
        return fetch_security_txt(subject_value)

    if decision.action == "fetch_tls_certificate":
        if subject_type != SubjectType.DOMAIN.value:
            return {"error": "fetch_tls_certificate is only valid for domain subjects"}
        return fetch_tls_certificate(subject_value)

    raise ValueError(f"Unsupported executable action: {decision.action}")