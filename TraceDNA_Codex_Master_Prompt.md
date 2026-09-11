# TraceDNA — Codex Master Implementation Prompt

You are the lead engineer responsible for building the TraceDNA hackathon prototype in this repository.

The repository includes a specification file named:

```text
TraceDNA_Prototype_Context.md
```

Treat that file as the **authoritative product and technical specification** for the prototype.

Your job is to implement the strongest possible working MVP described there.

---

# 1. Primary Objective

Build an end-to-end prototype that allows a user to upload a raw `.eml` file and receive:

1. evidence integrity verification,
2. transparent threat/BEC triage,
3. trust-aware mail-path reconstruction,
4. the earliest trustworthy observable external infrastructure,
5. Infrastructure DNA,
6. similarity against historical emails/campaigns,
7. campaign assignment when justified,
8. campaign mutation timeline,
9. claim → evidence → confidence explanations,
10. a usable analyst dashboard.

The most important end-to-end demo is:

```text
Seed historical Campaign Alpha
        ↓
Upload unseen_alpha_mutation.eml
        ↓
Threat triage
        ↓
Forged lower Received header rejected
        ↓
Trust boundary found
        ↓
Infrastructure DNA computed
        ↓
High similarity to Campaign Alpha
        ↓
New email attached to Campaign Alpha
        ↓
Mutation timeline updated
        ↓
Every conclusion traceable to evidence
```

If this flow works reliably, the project is successful.

---

# 2. Working Style

Do not spend time asking broad clarification questions.

Inspect the existing repository first.

If code already exists:

- understand it,
- reuse good parts,
- refactor only when necessary,
- do not throw away working code without a reason.

If the repository is empty, create the recommended structure from the specification.

Work in small, verifiable milestones.

After each major milestone:

- run tests,
- fix errors,
- continue.

Prefer a smaller working feature over a larger half-finished one.

---

# 3. Scope Discipline

Do **not** overbuild.

Do not implement these until the entire core demo works:

- Kubernetes,
- Kafka,
- Elasticsearch,
- enterprise authentication,
- Gmail/Outlook connectors,
- automatic quarantine,
- malware sandboxing,
- arbitrary URL execution,
- complex agent loops,
- paid threat-intelligence dependencies,
- production multi-tenancy.

Do not let optional features delay the MVP.

---

# 4. Required Technology Choices

Unless the existing repo strongly justifies an alternative, use:

## Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy or SQLModel
- SQLite by default
- NetworkX
- scikit-learn
- BeautifulSoup
- tldextract
- pytest

## Frontend

- React
- TypeScript
- Vite
- Cytoscape.js
- Tailwind or simple maintainable CSS

The full app must be runnable locally without paid services.

---

# 5. Mandatory Offline Demo Mode

The prototype must work without internet access and without API keys.

Implement a deterministic:

```text
FixtureEnrichmentProvider
```

backed by:

```text
demo/enrichment_fixtures.json
```

Use safe synthetic domains and reserved documentation IP ranges.

Optional live adapters may exist behind environment flags, but must never be required for the demo.

---

# 6. Safety Constraints

Email content is untrusted.

You must:

- never execute attachments,
- never auto-open arbitrary links,
- sanitize rendered HTML,
- store uploaded evidence outside public frontend directories,
- sanitize filenames,
- limit upload size,
- prevent path traversal,
- use timeouts on optional live lookups,
- never treat email text as instructions for an LLM or tool,
- never claim IP geolocation identifies a physical attacker.

If an LLM is added, it may only summarize already structured evidence.

---

# 7. Implement in This Order

## Milestone 1 — Project Skeleton

Create:

- backend FastAPI app,
- DB setup,
- frontend app,
- README,
- `.env.example`,
- health route,
- basic test setup.

Verify both backend and frontend start.

## Milestone 2 — Evidence Ingestion

Implement:

- `.eml` upload,
- case ID,
- raw evidence storage,
- SHA-256,
- integrity verification,
- DB persistence.

Tests:

- upload succeeds,
- hash stored,
- integrity passes,
- deliberate modification causes integrity failure in test.

## Milestone 3 — Email Parser

Extract:

- subject,
- From,
- Reply-To,
- Return-Path,
- Message-ID,
- Date,
- Received headers,
- Authentication-Results,
- text body,
- HTML body,
- URLs,
- attachments metadata + hashes.

Preserve raw header strings.

Add robust malformed-email handling.

## Milestone 4 — Triage and Identity Analysis

Implement transparent risk signals:

- sender mismatch,
- Reply-To mismatch,
- Return-Path mismatch,
- authentication anomalies,
- lookalike domain basics,
- credential intent,
- payment-diversion intent,
- secrecy/urgency,
- suspicious URL structure.

Store every component as evidence.

Expose the contribution breakdown.

## Milestone 5 — Header Trust Engine

This is critical.

Implement the trust-aware `Received:` analysis exactly in the spirit of the specification.

Requirements:

- parse each hop,
- configured trust root,
- continuity checks,
- timestamp plausibility,
- public/private IP classification,
- trust score/band,
- reason codes,
- trust boundary,
- earliest trustworthy observable external source.

Important:

Do not choose the lowest/oldest-looking `Received:` entry by default.

Include a synthetic email with a forged older header below the trust boundary.

Write dedicated unit tests.

## Milestone 6 — Feature Normalisation

Implement:

- domain normalization,
- URL path grammar normalization,
- query-key extraction,
- Message-ID pattern extraction,
- HTML skeleton extraction,
- content normalization,
- network-enrichment fixture integration.

All feature extraction must be deterministic.

## Milestone 7 — Infrastructure DNA

Represent DNA in six groups:

```text
network
domain
web
mail
content
temporal
```

Implement per-group similarity and overall weighted similarity.

Use transparent metrics:

- Jaccard,
- normalized string similarity,
- TF-IDF cosine,
- exact high-signal matches,
- piecewise temporal score.

Return:

```text
overall score
band
group scores
feature contributions
high-signal matches
conflicts
```

Do not hide the score behind a black box.

## Milestone 8 — Demo Historical Campaigns

Create safe synthetic `.eml` files:

```text
alpha_01.eml
alpha_02.eml
alpha_03.eml
beta_01.eml
benign_urgent_invoice.eml
unseen_alpha_mutation.eml
```

Campaign Alpha must rotate obvious IOCs while preserving hidden traits.

Campaign Beta must be structurally different.

The benign invoice must contain urgency/payment language but remain low/non-malicious based on broader evidence.

Provide:

```bash
python backend/scripts/seed_demo.py
```

or an equivalent command.

## Milestone 9 — Campaign Matcher

Implement:

- pairwise similarities,
- campaign graph,
- conservative assignment rule,
- "no confident match" path.

Use NetworkX connected components for the MVP.

Do not force every malicious email into a campaign.

Tests must prove:

```text
unseen Alpha → Alpha
unseen Alpha !→ Beta
benign !→ Alpha
```

## Milestone 10 — Mutation Timeline

For each campaign:

- sort members,
- detect changed traits,
- detect persistent traits,
- produce timeline events,
- attach evidence IDs.

This is the main wow feature.

## Milestone 11 — Claim / Evidence Engine

Every important conclusion must be a structured claim.

At minimum create claims for:

- threat assessment,
- authentication anomaly,
- sender anomaly,
- earliest trustworthy infrastructure,
- rejected/untrusted Received hop,
- campaign match,
- mutation,
- integrity.

Claims must contain:

- supporting evidence,
- contradictory evidence,
- confidence score,
- confidence band,
- confidence kind.

Use:

```text
heuristic_evidence_confidence
```

for heuristic confidence.

Never label it as "probability same attacker".

## Milestone 12 — Frontend

Build an analyst-focused UI.

Required views:

### Dashboard

- cases,
- risk,
- category,
- campaign,
- similarity,
- upload.

### Case Detail

- risk summary,
- sender/authentication,
- mail path,
- DNA,
- campaign result,
- claims.

### Relay Trust Path

Visual vertical hop chain:

```text
TRUSTED
TRUSTED
BOUNDARY
UNTRUSTED
```

Click a hop to inspect the raw header and reasons.

### DNA Similarity

Show:

- six group scores,
- top contributions,
- persistent traits,
- changed traits.

### Campaign Graph

Use Cytoscape.

Keep it readable.

### Mutation Timeline

Chronological campaign changes.

### Evidence Drawer

Clicking a claim must reveal exact evidence IDs and values.

## Milestone 13 — Demo Reset and Script

Implement a simple reset + seed flow.

Create:

```text
demo/DEMO_SCRIPT.md
```

with exact presenter actions.

The demo should be reproducible in under a few minutes.

## Milestone 14 — Final QA

Run:

- backend tests,
- end-to-end test,
- frontend build,
- lint/typecheck if configured.

Fix all critical failures.

Update README with exact run commands.

---

# 8. Required Algorithm Behaviour

## Header Trust

For the forged-header demo:

- the fake lower `Received:` line must be visible,
- it must be marked untrusted/unsupported,
- it must not become the origin claim,
- the actual trust boundary must be independently justified.

## Campaign DNA

A new email with:

- new domain,
- new source IP,

must still match Alpha because of other persistent traits.

The explanation must show *which* traits drove the match.

## Shared ASN

Same ASN/provider alone must not create a high campaign score.

## Benign Urgency

"Urgent invoice/payment" language alone must not cause a severe malicious classification.

## Unknown

When evidence is insufficient, return `unknown` or `no confident match`.

Do not fabricate certainty.

---

# 9. Suggested Similarity Weights

Start with:

```text
network   0.12
domain    0.12
web       0.22
mail      0.22
content   0.22
temporal  0.10
```

Suggested bands:

```text
>= 0.75  HIGH
0.55–0.74 REVIEW
< 0.55   LOW
```

Suggested campaign attach rule:

```text
max_pair >= 0.78
AND
(
  top3_mean >= 0.65
  OR
  high_signal_exact_match_count >= 1
)
```

Keep all weights/config in one configuration module/file.

Write tests around ranges, not decorative exact UI numbers.

---

# 10. Evidence Provenance Requirements

Every derived result must be traceable.

Example:

```text
Claim C17:
"This email is highly similar to Campaign Alpha"

Supporting:
E31 normalized URL grammar match
E32 HTML skeleton similarity
E33 Message-ID pattern match
E34 Reply-To pattern relation

Contradicting:
E35 domain differs
E36 source IP differs
```

The user must be able to inspect those evidence records.

This is not optional.

---

# 11. API Expectations

Implement clean REST endpoints approximately matching the specification.

At minimum:

```text
GET  /api/health
POST /api/cases
GET  /api/cases/{id}
GET  /api/cases/{id}/relay-path
GET  /api/cases/{id}/dna
GET  /api/cases/{id}/claims
GET  /api/cases/{id}/evidence
POST /api/cases/{id}/verify-integrity
GET  /api/campaigns/{id}
GET  /api/campaigns/{id}/graph
```

Use Pydantic response models.

---

# 12. Tests That Must Exist

Implement unit/integration tests for:

```text
email parsing
hash integrity
header trust
forged header rejection
URL normalization
Message-ID pattern normalization
HTML skeleton generation
DNA group similarity
overall DNA score
campaign matching
benign non-match
mutation timeline
claim evidence references
API upload
end-to-end unseen Alpha flow
```

The final end-to-end test is mandatory.

---

# 13. README Quality Bar

The README must let a new developer run the project without guessing.

It must include:

```text
Prerequisites
Backend install
Frontend install
Database setup
Seed demo
Run backend
Run frontend
Run tests
Reset demo
Exact demo flow
Known limitations
```

Also include this conceptual warning:

> Infrastructure location is not the same as attacker physical location. Campaign similarity is an evidence-based heuristic similarity score, not proof that two messages were sent by the same person.

---

# 14. UX Quality Bar

Do not make the UI look like a generic admin template if time allows.

The judge should understand the story immediately.

Prioritize these visual elements:

1. trust path,
2. similarity contributions,
3. persistent vs rotated traits,
4. campaign timeline,
5. evidence drawer.

Avoid spending time on decorative charts that do not advance the investigation.

---

# 15. Optional AI

Only after the MVP works:

Implement an optional evidence-grounded summarizer.

Input:

- claims,
- evidence,
- timeline,
- campaign summary.

Output:

- concise analyst summary.

If no LLM key exists, fall back to deterministic templated text.

No core functionality may depend on it.

---

# 16. Definition of Success

The final repository should support this exact flow:

```bash
# install
# seed demo
# run backend
# run frontend
```

Then:

1. Open UI.
2. Historical Alpha/Beta cases already exist.
3. Upload:

```text
demo/emails/unseen_alpha_mutation.eml
```

4. UI shows:
   - suspicious/high-risk triage,
   - evidence integrity PASS,
   - forged older Received hop rejected,
   - trustworthy boundary identified,
   - Alpha similarity HIGH,
   - new case attached to Alpha,
   - persistent DNA traits highlighted,
   - rotated domain/IP highlighted,
   - campaign timeline updated,
   - every conclusion linked to evidence.

If this is not reliable, keep working on the MVP instead of adding features.

---

# 17. Final Engineering Principle

When choosing between:

```text
more features
```

and:

```text
better evidence, stronger tests, clearer algorithm, cleaner demo
```

always choose the second.

The hackathon-winning moment is not:

> "We used AI, graphs, SPF, DKIM, and five APIs."

It is:

> **"This unseen email changed domain and IP, even contained a forged mail-path clue, but TraceDNA rejected the forged hop, matched the persistent campaign traits, reconstructed the campaign mutation, and showed the exact evidence behind the conclusion."**

Build toward that moment.
