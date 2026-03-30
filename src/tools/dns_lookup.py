from __future__ import annotations

import dns.resolver


def _truncate(value: str, limit: int = 160) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _redact_txt(value: str) -> str:
    value = value.strip('"')

    if "=" in value and len(value) > 60:
        key, _, _ = value.partition("=")
        return f"{key}=<redacted>"

    return _truncate(value)


def dns_lookup(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4

    results: dict[str, list[str] | str] = {"domain": domain}

    for record_type in ("A", "MX", "NS"):
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in list(answers)[:5]]
        except Exception as exc:
            results[record_type] = [f"lookup_failed: {exc}"]

    try:
        answers = resolver.resolve(domain, "TXT")
        txt_records: list[str] = []

        for answer in list(answers)[:8]:
            value = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in answer.strings
            )
            txt_records.append(_redact_txt(value))

        results["TXT"] = txt_records
    except Exception as exc:
        results["TXT"] = [f"lookup_failed: {exc}"]

    return results