# TraceDNA — Current Project Status Audit Master Prompt for Codex

You are auditing the **current implementation state** of the TraceDNA repository.

Your job is **not to improve the project yet** and **not to assume that planned features are implemented**.

You must inspect the actual repository and produce a single Markdown file:

```text
TRACEDNA_CURRENT_STATUS.md
```

This document will be given to another technical reviewer, so it must accurately describe **what is actually implemented right now**, what is partial, what is missing, and what the current code really does.

---

# 1. Core Rule

Base the report only on evidence from the current repository:

- source code,
- tests,
- configuration,
- database models,
- API routes,
- frontend components,
- demo fixtures,
- scripts,
- README,
- runtime behaviour if you can run the project.

Do **not** mark a feature as implemented just because:

- it appears in a README,
- it appears in a design/specification file,
- a TODO mentions it,
- a frontend label exists,
- a mock fixture contains the value,
- an unused function exists.

A feature counts as implemented only if the real code path works or is clearly wired end-to-end.

---

# 2. Inspect the Whole Repository First

Before writing the report:

1. Inspect the repository structure.
2. Identify backend and frontend entry points.
3. Identify:
   - API routes,
   - services,
   - data models,
   - analysis modules,
   - tests,
   - demo fixtures,
   - configuration,
   - scripts.
4. Run relevant tests if possible.
5. Start or exercise the backend if practical.
6. Inspect frontend calls to confirm what data is actually displayed.
7. Trace major features from:
   - input
   - processing
   - storage
   - API
   - UI

Do not rely only on filenames.

---

# 3. Required Output Format

Create:

```text
TRACEDNA_CURRENT_STATUS.md
```

Use the following structure exactly.

---

# TraceDNA — Current Implementation Status

## 1. Executive Summary

Give a short technical summary of the current project.

Include:

- what TraceDNA currently does,
- what the strongest working feature is,
- how complete the prototype is,
- whether the main demo flow works,
- the biggest missing or incomplete area.

Also give an overall prototype completeness estimate:

```text
Prototype completeness: XX%
```

This percentage is only a rough engineering estimate.

Explain briefly how you arrived at it.

---

## 2. Current Architecture

Describe the architecture that actually exists.

Include:

- frontend framework,
- backend framework,
- database/storage,
- main analysis pipeline,
- important libraries,
- whether external APIs are used,
- whether the prototype works offline.

Add a simple ASCII pipeline based on the real implementation.

Example format:

```text
.eml upload
   ↓
...
```

Do not copy planned architecture unless it exists.

---

## 3. Repository Structure

Give the important folders/files and what they currently do.

Do not list every file.

Focus on:

- backend entry point,
- frontend entry point,
- analysis services,
- tests,
- demo data,
- configuration.

---

## 4. End-to-End Analysis Flow

Trace one uploaded `.eml` through the current system.

Explain:

1. upload,
2. evidence preservation,
3. parsing,
4. threat scoring,
5. authentication analysis,
6. mail path analysis,
7. campaign analysis,
8. claims/evidence,
9. frontend display.

For every stage, explain what the current code actually does.

---

# 5. Feature Status Matrix

Use this status system:

```text
✅ IMPLEMENTED
🟡 PARTIALLY IMPLEMENTED
🟠 PRESENT BUT NOT REALLY WIRED / MOCKED
❌ NOT IMPLEMENTED
❓ CANNOT CONFIRM
```

Create a table:

| Feature | Status | What currently works | Important limitations | Code location |
|---|---|---|---|---|

Audit at least all of the following.

### Input / Evidence
- Raw `.eml` upload
- Original email preservation
- SHA-256 hashing
- Evidence integrity verification
- Attachment metadata extraction
- Attachment SHA-256

### Parsing
- From
- To
- Reply-To
- Return-Path
- Message-ID
- Date
- Received headers
- Authentication-Results
- Received-SPF
- DKIM-Signature
- ARC headers
- Plain-text body
- HTML body
- URL extraction

### Threat Detection / Risk
- Overall risk score
- Risk contribution breakdown
- Credential-phishing detection
- BEC/payment-diversion detection
- Urgency/secrecy detection
- Reply-To mismatch
- Return-Path mismatch
- Lookalike-domain detection
- Suspicious URL analysis

### Email Authentication
Audit SPF, DKIM and DMARC **separately**.

For each, explicitly answer:

- Is it parsed?
- Is the result displayed?
- Is it used in risk scoring?
- Is alignment checked?
- Is it receiver-observed only?
- Is any live/cryptographic re-verification performed?

Required rows:

- SPF parsing
- SPF scoring/use
- SPF live verification
- DKIM parsing
- DKIM scoring/use
- DKIM cryptographic verification
- DMARC parsing
- DMARC scoring/use
- DMARC alignment analysis
- ARC support

### Trust-Aware Mail Path
- Received-header parsing
- Trusted root configuration
- Trusted boundary detection
- Continuity checking
- Timestamp plausibility
- Hostname/IP consistency
- Reverse-DNS
- Public/private IP analysis
- Hop trust score
- Trusted / uncertain / untrusted classification
- Earliest trustworthy observable infrastructure
- Forged/untrusted hop rejection
- Counterfactual simulator

Be very explicit about what the trust engine really checks.

Do not infer checks from names.

Inspect the actual code.

### Infrastructure Enrichment
- IP extraction
- ASN enrichment
- Provider enrichment
- Country/city enrichment
- RDAP
- DNS lookup
- reverse DNS
- GeoIP
- fixture/mock enrichment
- live enrichment

Clearly distinguish:

```text
real live lookup
vs
offline fixture/demo data
```

### Infrastructure DNA
Audit separately:

- Network DNA
- Domain DNA
- URL grammar
- Query-key/path normalisation
- HTML skeleton
- Message-ID pattern
- Reply-To pattern
- Return-Path pattern
- Mail-header fingerprint
- Content similarity
- TF-IDF
- Embeddings
- Temporal similarity
- Certificate fingerprinting
- Domain/IP rotation detection

For each, state exactly what is implemented.

### Similarity / Campaign Correlation
- Pairwise email similarity
- Weighted DNA similarity
- Similarity contribution breakdown
- High-signal feature bonuses
- Campaign similarity bands
- Campaign clustering
- Historical campaign matching
- Conservative/no-match behaviour
- Campaign graph
- Campaign mutation timeline
- Persistent-vs-rotated trait detection
- Campaign prototype/fingerprint

### Evidence / Explainability
- Evidence IDs
- Claim objects
- Claim → evidence links
- Contradicting evidence
- Confidence score
- Confidence band
- Heuristic confidence labelling
- Evidence drawer/UI
- Report generation

### Frontend
- Upload UI
- Case list
- Risk card
- Why-flagged panel
- Authentication panel
- Trust-aware mail path UI
- Campaign DNA UI
- Campaign graph
- Mutation timeline
- Claims → evidence UI
- Integrity status
- Demo-reset/load feature

### Optional AI
- LLM usage
- AI explanation
- AI investigation agent
- deterministic fallback
- whether core functionality depends on external AI

---

# 6. SPF / DKIM / DMARC — Exact Current State

Create a dedicated section because this is important for presentations.

Use this exact format:

## SPF

```text
Parsing:
Displayed:
Used in scoring:
Alignment checked:
Live verification:
Implementation file(s):
Current limitations:
```

## DKIM

```text
Parsing:
Displayed:
Used in scoring:
Cryptographic verification:
Implementation file(s):
Current limitations:
```

## DMARC

```text
Parsing:
Displayed:
Used in scoring:
Alignment checked:
Implementation file(s):
Current limitations:
```

## ARC

```text
Parsing:
Used:
Implementation file(s):
Current limitations:
```

Do not group these together.

---

# 7. Trust-Aware Mail Path — Exact Algorithm

Explain the actual current algorithm in simple technical steps.

For example:

```text
1. ...
2. ...
3. ...
```

Then give the exact signals it uses.

Use a table:

| Signal | Implemented? | How it affects trust |
|---|---|---|

Audit:

- configured trusted root,
- parseable peer IP,
- hostname consistency,
- next-hop continuity,
- timestamp ordering,
- reverse DNS,
- private/public address logic,
- authentication relation,
- malformed header handling.

Then explicitly answer:

### What does `TRUSTED · BOUNDARY` mean in the current code?

### What causes `CONTINUITY_BREAK`?

### What causes `TRUST_ROOT_NOT_CONFIGURED`?

### Can the current implementation detect a deliberately forged lower `Received:` header?

### Does it *prove* a hop is forged, or only mark it unsupported/untrusted?

### Does the system ever call an IP the physical attacker location?

---

# 8. Infrastructure DNA — Exact Algorithm

Explain exactly what the current implementation means by:

```text
Infrastructure DNA
```

List all feature groups actually used.

Then provide the current similarity formula or logic.

If weights exist, include them exactly.

Example:

```text
network = ...
domain = ...
web = ...
mail = ...
content = ...
temporal = ...
```

Explain:

- how URL grammar is calculated,
- how HTML skeleton is calculated,
- how Message-ID patterns are calculated,
- how text/content similarity works,
- whether TF-IDF is used,
- whether embeddings are used,
- how changed domains/IPs are treated,
- what thresholds define HIGH/REVIEW/LOW.

If the UI shows:

```text
✓ URL grammar
✓ HTML skeleton
✓ Message-ID pattern
✕ domain rotated
✕ source IP rotated
```

explain the exact backend conditions that cause each badge.

---

# 9. Campaign Matching — Exact Current Behaviour

Explain:

- how historical cases are compared,
- how campaign similarity is calculated,
- how a campaign is assigned,
- how "No confident historical match" is produced,
- current thresholds,
- whether campaign clustering exists,
- whether seeded Campaign Alpha/Beta fixtures exist,
- whether the unseen mutation demo works.

If possible, run the demo fixtures and report results.

Use a table like:

| Test email | Expected | Actual | Similarity | Result |
|---|---|---|---:|---|

Include:

- Alpha historical samples
- unseen Alpha mutation
- Beta
- benign urgent invoice

If these fixtures do not exist, say so.

---

# 10. Current UI — What Each Visible Section Actually Means

Explain the current UI labels in plain English.

At minimum:

- risk level,
- risk score,
- why flagged,
- evidence integrity,
- trust-aware mail path,
- trusted boundary,
- untrusted hop,
- earliest trustworthy observable infrastructure,
- campaign DNA,
- no confident historical match,
- URL grammar badge,
- HTML skeleton badge,
- Message-ID pattern badge,
- domain rotated,
- source IP rotated,
- claims → evidence,
- heuristic evidence confidence.

This section should be suitable for someone preparing a hackathon presentation.

---

# 11. Demo Data vs Real Analysis

Create a table:

| Capability | Real parsed data | Offline fixture/mock | Live external lookup |
|---|---:|---:|---:|

Cover:

- email headers,
- SPF,
- DKIM,
- DMARC,
- IP,
- ASN,
- provider,
- geolocation,
- domain data,
- campaign data,
- certificates,
- threat intelligence.

This is extremely important.

Do not let demo fixtures be mistaken for real threat-intelligence lookups.

---

# 12. Tests and Validation

Report:

- number/type of tests,
- which major components have tests,
- test command,
- pass/fail status,
- any failing tests,
- important untested features.

If possible, run them.

Include exact results.

Also state whether there is an end-to-end test for:

```text
upload unseen Alpha
→ reject forged/untrusted header
→ identify trust boundary
→ match Campaign Alpha
→ produce claims/evidence
```

---

# 13. What Is Safe to Claim to Hackathon Judges

Create three subsections.

## Fully Safe Claims

Only features clearly demonstrated by current code.

Example format:

- **Feature:** ...
  - Safe explanation: ...

## Claims That Need Careful Wording

Features that exist but could be overstated.

Example:

```text
Do not say:
"We found the attacker."

Say:
"We identified the earliest trustworthy observable sending infrastructure."
```

## Claims We Should NOT Make Yet

Anything unimplemented, mocked, or unsupported.

Include things like:

- physical attacker attribution,
- counterfactual simulator if absent,
- live DKIM verification if absent,
- "no existing tool does this",
- enterprise-scale throughput unless tested.

---

# 14. Biggest Gaps Before Demo

Give the top 5 missing/improvable things in priority order.

For each:

```text
Problem:
Why it matters:
Estimated effort:
Recommended action:
```

Focus on changes that can realistically improve the hackathon presentation.

---

# 15. Recommended Final Feature List

Produce a concise bullet list of features that can accurately be presented to judges **based on the current repository**.

Each bullet should have:

```text
Feature name — one-sentence plain-English explanation.
```

Do not include unimplemented features.

---

# 16. Recommended 60-Second Explanation

Write a short presentation script explaining what the current prototype actually does.

It must match the implementation.

Do not mention planned features as completed.

---

# 17. Recommended 3-Minute Technical Explanation

Write a slightly deeper judge-facing explanation covering:

1. email ingestion,
2. risk/authentication,
3. trust-aware mail path,
4. Infrastructure DNA,
5. campaign matching,
6. evidence explainability.

Again, only describe features that truly exist.

---

# 18. Current Limitations

Be explicit.

Include technical limitations such as:

- heuristic scores,
- fixture enrichment,
- missing live lookup,
- missing SPF/DKIM re-verification,
- trust-root dependency,
- synthetic campaign dataset,
- thresholds not statistically calibrated,
- no physical attacker attribution,
- incomplete frontend features,
- small evaluation set.

Only include limitations that apply to this repository.

---

# 19. Final Engineering Verdict

Give:

```text
Current prototype readiness: X/10
Hackathon demo readiness: X/10
Technical defensibility: X/10
Implementation completeness: X/10
```

Then answer:

### What is the single strongest feature currently implemented?

### What is the single weakest point judges may attack?

### What one change would most improve the project before judging?

---

# 20. Evidence Appendix

For every major feature marked `✅ IMPLEMENTED`, provide at least one code reference.

Format:

```text
Feature:
Files:
- backend/...
- frontend/...
Important functions/classes:
- ...
```

Do not paste huge code blocks.

The goal is to make the audit verifiable.

---

# Final Instructions

- Be brutally accurate.
- Do not praise the project unnecessarily.
- Do not infer implementation from design documents.
- Distinguish frontend display from actual backend logic.
- Distinguish fixture/demo enrichment from real external intelligence.
- Distinguish parsed receiver-observed SPF/DKIM/DMARC results from active verification.
- Distinguish heuristic similarity from calibrated probability.
- Distinguish infrastructure location from physical attacker location.
- If something cannot be confirmed, mark it `❓ CANNOT CONFIRM`.
- If code exists but is unused, mark it `🟠 PRESENT BUT NOT REALLY WIRED / MOCKED`.
- Run the relevant tests and demo flow where practical.
- Include errors or failures rather than hiding them.
- Do not modify the application unless required only to run/read it.
- The primary deliverable is the audit file, not code changes.

At the end, ensure this file exists:

```text
TRACEDNA_CURRENT_STATUS.md
```

Then respond to me only with:

1. the path to `TRACEDNA_CURRENT_STATUS.md`,
2. a 3–5 line summary of the audit,
3. any command that failed and prevented full verification.
