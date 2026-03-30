# Simple_AI_Agent_Demo

A passive OSINT investigation agent powered by the Claude API.

The agent accepts one or more investigation subjects (`person`, `company`, `domain`), autonomously gathers public information with a small toolset, and produces a structured report in JSON and Markdown.

## Scope

This proof of concept is intentionally limited to **passive** investigation only. It does **not** perform active scanning, intrusive collection, login attempts, or any direct interaction with target-controlled systems beyond standard unauthenticated public HTTP fetches and public record retrieval.

Supported subjects:
- person
- company
- domain

Supported tool categories in the current POC:
- web search / news search
- DNS lookup
- WHOIS lookup
- website fetch
- `robots.txt`
- `security.txt`
- TLS certificate metadata

## High-Level Flow

1. Normalize and classify input subjects with Claude.
2. Build an initial investigation plan.
3. Run deterministic seed collection for each subject.
4. Continue collection via an agent loop powered by Claude.
5. Summarize evidence in small batches.
6. Generate deterministic grounded leads.
7. Refine the top attack vectors with Claude.
8. Generate a final structured report in:
   - `investigation_report.json`
   - `investigation_report.md`

## Repository Structure

```text
Simple_AI_Agent_Demo/
├── README.md
├── architecture.md
├── requirements.txt
├── .env.example
├── main.py
├── demo_subjects/
├── reports/
└── src/
    ├── agent/
    ├── llm/
    ├── prompts/
    ├── tools/
    └── utils/
```

## Environment Setup

### 1. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

- PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

- Bash:

```bash
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a local `.env` file in the project root.

Example:

```env
ANTHROPIC_API_KEY=your_key_here
ANTHROPIC_MODEL=claude-sonnet-4-6
SEARCH_BACKEND=ddgs
MAX_AGENT_STEPS=15
OUTPUT_DIR=reports
ACTION_MAX_TOKENS=1000
REPORT_MAX_TOKENS=1500
TEMPERATURE=0.0
```

Notes:
- `.env` should **not** be committed.
- `.env.example` should remain a template only.
- `SEARCH_BACKEND=ddgs` enables web/news search without separate API keys.

## Running the Agent

### Dry run

Validates config and input only:

```bash
python main.py --input demo_subjects/multi_subject_input.json --dry-run
```

### Full run

```bash
python main.py --input demo_subjects/multi_subject_input.json
```

Each run creates a timestamped output folder under `reports/`.

Example outputs:
- `initial_state.json`
- `initial_plan.json`
- `evidence_collection_state.json`
- `investigation_report.json`
- `investigation_report.md`
- `agent_debug.log`

## Input Format

Example input:

```json
{
  "subjects": [
    { "value": "Fireblocks" },
    { "value": "fireblocks.com" },
    { "value": "Michael Shaulov" }
  ]
}
```

`type` is optional. If omitted, Claude classifies the subject.

## Output Format

The final report contains:
- normalized subjects
- executive summary
- up to 3 selected attack vectors
- sources used
- risk signals
- rationale
- recommended next steps

Important: the agent selects **up to three** attack vectors. If the evidence supports only one or two high-confidence vectors, the report intentionally returns fewer than three rather than fabricating weak findings.

## Design Decisions

### Why passive-only?
This assignment was implemented as an OSINT-style autonomous investigator. Passive collection keeps the POC safe, reproducible, and easy to demonstrate without target authorization.

### Why deterministic leads + LLM refinement?
A purely LLM-driven report was more brittle and harder to ground. The current design uses deterministic lead extraction from evidence, then lets Claude refine and synthesize the results. This preserves traceability while still benefiting from model reasoning.

### Why batch summaries?
Large single-shot structured outputs were less reliable. Evidence is first summarized in small batches, then reused for later synthesis.

## Limitations

- Search quality depends on public availability and the `ddgs` backend.
- The agent is strongest on passive social-engineering and trust-boundary style findings.
- It does not validate exploitable vulnerabilities.
- It may return fewer than 3 attack vectors when evidence is insufficient.
- Company-only investigations are weaker unless the public web surface reveals enough partner, hiring, legal, PR, or developer context.

## Suggested Demo Inputs

Examples to test:
- company only
- company + domain
- company + person
- company + domain + person
- multiple people associated with one company

## Running Tests

```bash
pytest -q
```

The included tests focus on parser correctness, report rendering, and deterministic lead/risk-signal behavior.

## Submission Notes

This repository is structured to match the assignment deliverables:
- working code
- README
- architecture document
- optional demo artifacts
