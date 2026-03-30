from __future__ import annotations

import whois


def whois_lookup(domain: str) -> dict:
    try:
        result = whois.whois(domain)
    except Exception as exc:
        return {
            "domain": domain,
            "error": str(exc),
        }

    return {
        "domain": domain,
        "registrar": str(result.registrar) if result.registrar else None,
        "creation_date": str(result.creation_date) if result.creation_date else None,
        "expiration_date": str(result.expiration_date) if result.expiration_date else None,
        "name_servers": result.name_servers if result.name_servers else [],
        "emails": result.emails if result.emails else [],
    }