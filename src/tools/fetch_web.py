from __future__ import annotations

import requests
from bs4 import BeautifulSoup


DEFAULT_HEADERS = {
    "User-Agent": "Simple_AI_Agent_Demo/1.0"
}


def fetch_url(url: str, timeout: int = 8) -> dict:
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    content_type = response.headers.get("Content-Type", "")
    text = response.text[:20000]

    result = {
        "url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "content_type": content_type,
    }

    if "text/html" in content_type:
        soup = BeautifulSoup(text, "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""
        meta_description = ""

        meta_tag = soup.find("meta", attrs={"name": "description"})
        if meta_tag and meta_tag.get("content"):
            meta_description = meta_tag["content"][:500]

        result["title"] = title
        result["meta_description"] = meta_description
        result["text_preview"] = soup.get_text(" ", strip=True)[:1500]
    else:
        result["text_preview"] = text[:1500]

    return result


def fetch_robots_txt(domain: str) -> dict:
    return fetch_url(f"https://{domain}/robots.txt")


def fetch_security_txt(domain: str) -> dict:
    primary = fetch_url(f"https://{domain}/.well-known/security.txt")
    if primary.get("status_code") == 200:
        return primary
    return fetch_url(f"https://{domain}/security.txt")