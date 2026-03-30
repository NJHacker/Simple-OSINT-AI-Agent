# Simple_AI_Agent_Demo — Architecture Document

## Page 1 — Current System Design

### Objective

The goal of this proof of concept is to implement an autonomous AI investigation agent that accepts one or more public subjects (person, company, domain), collects passive OSINT, and generates a structured investigation report.

The current system is designed around three constraints:
1. Claude must power the reasoning loop.
2. The agent must be autonomous.
3. The output must be a clean, structured report.

### Design Principles

- **Passive only**: no intrusive scanning or authenticated access.
- **Grounded outputs**: final attack vectors should be tied to collected evidence.
- **Practical reporting**: prioritize realistic attack hypotheses over speculative claims.
- **Small-step LLM usage**: avoid one large brittle generation step when smaller steps provide more stability.

### System Components

```text
User Input
   ↓
Input Loader
   ↓
Subject Detection / Normalization (Claude)
   ↓
Initial Investigation Plan (Claude)
   ↓
Deterministic Seed Collection
   ↓
Agent Loop
   ├─ Next Action Selection (Claude)
   ├─ Tool Execution (Python)
   ├─ Observation Extraction (Claude)
   └─ State Update
   ↓
Evidence Batching
   ↓
Batch Summaries (Claude)
   ↓
Deterministic Lead Generation
   ↓
Attack Vector Refinement (Claude)
   ↓
Executive Summary / Wrap-up (Claude)
   ↓
Final JSON + Markdown Report
```

### Main Modules

#### 1. `main.py`
Entry point. Responsible for:
- loading config
- loading input JSON
- creating a timestamped run directory
- orchestrating the full run
- writing output artifacts

#### 2. `src/llm/claude_client.py`
Thin wrapper over the Anthropic SDK. It exposes:
- `generate_text(...)`
- `generate_json(...)`

It also logs response size, duration, and stop reason for debugging.

#### 3. `src/agent/loop.py`
Core orchestration layer. It contains:
- subject detection
- planning
- collection loop
- evidence batching
- lead generation
- final report assembly

This file is the main agent runtime.

#### 4. `src/tools/`
Implements the passive collection layer:
- search (`ddgs` backend)
- DNS
- WHOIS
- homepage fetch
- `robots.txt`
- `security.txt`
- TLS metadata

The tools are intentionally small and replaceable.

#### 5. `src/prompts/`
Prompt templates for:
- subject classification
- planning
- action choice
- evidence analysis
- batch summarization
- attack-vector refinement
- executive summary
- report wrap-up

Prompt content is kept separate from code to make tuning easier.

### Agent Loop Behavior

The system uses a hybrid approach:

#### Deterministic pieces
- seed collection
- evidence storage
- lead family detection
- risk signal derivation
- final report assembly

#### LLM-driven pieces
- subject classification
- planning
- next-action selection
- evidence analysis
- batch summarization
- attack-vector refinement
- final summary and rationale

This hybrid design was chosen because a fully LLM-driven report was more brittle and less grounded, while a fully deterministic pipeline produced repetitive and generic narrative output.

### Why Batches Were Introduced

Early versions attempted to send too much evidence to the model in one call. That caused formatting failures and unstable structured output generation. The current design reduces that risk by:
- summarizing evidence in small groups
- refining attack vectors one at a time
- generating executive summary and wrap-up separately

This reduces prompt size and keeps later synthesis focused.

### Output Model

The final report contains:
- subjects
- executive summary
- up to 3 attack vectors
- sources used
- risk signals
- rationale
- recommended next steps

The agent intentionally returns **up to 3** attack vectors, not always exactly 3. This is meant to preserve quality: if only one or two attack hypotheses are sufficiently grounded, the tool should not invent weak findings to reach a fixed count.

### Current Strengths

- Good fit for passive OSINT enrichment
- Stronger than a simple prompt wrapper because it preserves state
- Produces grounded attack hypotheses rather than raw search summaries
- Handles person/company/domain jointly
- Works with minimal external setup beyond Claude and open web retrieval

### Current Limitations

- Search quality depends on public web indexing and the lightweight backend
- Passive collection favors social engineering / trust-boundary hypotheses more than technical exploit validation
- Company-only inputs can be weaker if no public domain or strong partner/developer context is present
- Some report sections remain sensitive to output-format stability

---

## Page 2 — Future Development & Vision

### Near-Term Improvements

#### 1. Official-domain resolution for company-only inputs
Today, company-only input can be weaker because domain-specific tools are not always usable. A natural next step is to add a small domain-resolution stage:
- identify the canonical company domain
- validate it from the search results
- automatically attach it as an investigation subject

This would make company-only investigations much stronger.

#### 2. Better source quality scoring
Right now, the system stores evidence descriptions and reliability notes, but source quality is still relatively coarse. A better version would score sources by:
- official site vs third-party site
- first-party documentation vs aggregator
- recency
- consistency across multiple sources

That score could directly influence attack-vector confidence.

#### 3. Structured outputs via Anthropic schema enforcement
The current implementation improved stability by splitting tasks into smaller calls, but some sections still depend on format discipline from the model. A future version should use Claude structured output/schema enforcement where practical, especially for:
- next action selection
- evidence analysis
- executive summary / wrap-up

#### 4. Better company-only lead families
Future versions should add more evidence-driven lead families for company-only input, for example:
- hiring / recruiter-themed deception
- compliance / legal / PR workflow deception
- investor or earnings-call themed deception
- public support / abuse contact quality issues

### Advanced Future Vision

#### 1. Human-in-the-loop mode
The current POC is autonomous. A future version should support a dual mode:
- autonomous mode for passive investigation
- analyst-review mode for suspicious or high-risk findings

This is especially useful before any intrusive follow-up or manual escalation.

#### 2. Entity graph and relationship memory
Instead of a flat evidence store, the system could persist a graph of:
- people
- companies
- domains
- partners
- products
- conferences
- providers

That would make it easier to identify indirect paths such as:
- executive ↔ conference ↔ vendor
- company ↔ developer portal ↔ partner
- domain ↔ provider ↔ workflow owner

#### 3. Continuous investigations / watch mode
The same architecture could support recurring investigations:
- re-checking a company weekly
- watching for new partners or conferences
- monitoring docs migrations or infrastructure changes

#### 4. Broader tool layer
Possible future tool additions:
- official search APIs
- certificate transparency
- public GitHub collection
- public job-posting enrichment
- controlled reputation sources

The important design point is that the current tool registry already makes these additions straightforward.

### Testing Strategy

The current repo should include lightweight automated tests around the most failure-prone deterministic logic:
- tagged-text parsing
- report rendering
- risk signal derivation
- lead generation behavior

A larger future test strategy would include:

#### Unit tests
- parser correctness
- tool wrappers
- config loading
- report rendering

#### Integration tests
- a small mocked end-to-end investigation
- company-only input
- company + domain
- company + person
- multiple-people scenario

#### Evaluation tests
- does the agent produce at least one grounded vector?
- are vectors traceable to evidence refs?
- does the report avoid claiming confirmed compromise when only passive evidence exists?

### Why This Design Is Reasonable for the Assignment

The assignment requested:
- an autonomous investigation loop
- Claude as backbone
- a structured report
- code + README + architecture document

This implementation addresses all of those requirements while staying within the expected ~4 hour scope by choosing a pragmatic hybrid architecture: LLM reasoning for dynamic decisions and refinement, deterministic code for state, tools, grounding, and output assembly.

That makes the system realistic enough to demonstrate value, while still being small enough to explain clearly in a technical interview.
