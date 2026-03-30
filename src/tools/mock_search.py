from __future__ import annotations


def run_mock_search(query: str) -> dict:
    query_lower = query.lower()

    if "fireblocks" in query_lower and "news" not in query_lower:
        return {
            "query": query,
            "results": [
                {
                    "title": "Fireblocks Official Website",
                    "snippet": "Fireblocks provides digital asset infrastructure for institutions and enterprises.",
                    "url": "https://www.fireblocks.com",
                },
                {
                    "title": "Fireblocks Careers",
                    "snippet": "Job listings reference engineering, cloud, security, product, and enterprise infrastructure roles.",
                    "url": "https://www.fireblocks.com/careers",
                },
                {
                    "title": "Fireblocks Leadership",
                    "snippet": "Public executive and leadership information is available, including CEO and co-founders.",
                    "url": "https://www.fireblocks.com/company",
                },
                {
                    "title": "Fireblocks Developer and Platform Content",
                    "snippet": "Public-facing platform, API, and developer-related content may reveal product surface and ecosystem integration points.",
                    "url": "https://www.fireblocks.com/platforms",
                },
            ],
        }

    if "fireblocks" in query_lower and "news" in query_lower:
        return {
            "query": query,
            "results": [
                {
                    "title": "Fireblocks announces partnership expansion",
                    "snippet": "Public coverage discusses ecosystem relationships, integrations, and institutional partnerships.",
                    "url": "https://www.example.com/fireblocks-partnerships",
                },
                {
                    "title": "Fireblocks funding and growth coverage",
                    "snippet": "Public reporting discusses company growth, customer base, and market positioning.",
                    "url": "https://www.example.com/fireblocks-growth",
                },
            ],
        }

    if "michael shaulov" in query_lower:
        return {
            "query": query,
            "results": [
                {
                    "title": "Michael Shaulov Profile",
                    "snippet": "Michael Shaulov is publicly associated with Fireblocks leadership.",
                    "url": "https://www.example.com/michael-shaulov-profile",
                },
                {
                    "title": "Interview with Michael Shaulov",
                    "snippet": "Public speaking and media presence may provide context for social engineering hypotheses.",
                    "url": "https://www.example.com/michael-shaulov-interview",
                },
            ],
        }

    if "fireblocks.com" in query_lower:
        return {
            "query": query,
            "results": [
                {
                    "title": "fireblocks.com",
                    "snippet": "Corporate domain associated with Fireblocks public web presence.",
                    "url": "https://www.fireblocks.com",
                }
            ],
        }

    return {
        "query": query,
        "results": [
            {
                "title": "Generic Search Result",
                "snippet": "No specific mock result matched this query.",
                "url": "https://www.example.com",
            }
        ],
    }