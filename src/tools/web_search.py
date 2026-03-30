from __future__ import annotations

from ddgs import DDGS
from ddgs.exceptions import DDGSException

from src.tools.mock_search import run_mock_search


def _normalize_results(results: list[dict], source_type: str) -> dict:
    normalized = []

    for item in results:
        normalized.append(
            {
                "title": item.get("title") or "",
                "snippet": item.get("body") or item.get("snippet") or "",
                "url": item.get("href") or item.get("url") or "",
                "source_type": source_type,
            }
        )

    return {"results": normalized}


def search_web(query: str, backend: str) -> dict:
    if backend == "mock":
        return run_mock_search(query)

    if backend == "ddgs":
        try:
            results = list(DDGS().text(query, max_results=5))
            return {
                "query": query,
                "backend": "ddgs",
                **_normalize_results(results, "web_search"),
            }
        except DDGSException:
            return {
                "query": query,
                "backend": "ddgs",
                "results": [],
                "warning": "No web results found",
            }
        except Exception as exc:
            return {
                "query": query,
                "backend": "ddgs",
                "results": [],
                "error": str(exc),
            }

    raise ValueError(f"Unsupported search backend: {backend}")


def search_news(query: str, backend: str) -> dict:
    if backend == "mock":
        return run_mock_search(query)

    if backend == "ddgs":
        try:
            results = list(DDGS().news(query, max_results=5))
            return {
                "query": query,
                "backend": "ddgs",
                **_normalize_results(results, "news_search"),
            }
        except DDGSException:
            try:
                fallback_results = list(DDGS().text(f"{query} news", max_results=5))
                return {
                    "query": query,
                    "backend": "ddgs_text_fallback",
                    **_normalize_results(fallback_results, "news_search"),
                }
            except Exception:
                return {
                    "query": query,
                    "backend": "ddgs",
                    "results": [],
                    "warning": "No news results found",
                }
        except Exception as exc:
            return {
                "query": query,
                "backend": "ddgs",
                "results": [],
                "error": str(exc),
            }

    raise ValueError(f"Unsupported search backend: {backend}")