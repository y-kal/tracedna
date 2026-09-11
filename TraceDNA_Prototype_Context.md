# TraceDNA — Complete Prototype Context and Implementation Specification

> **Project working name:** TraceDNA  
> **Subtitle:** Evidence-Grounded Email Campaign Reconstruction and Trust-Aware Origin Intelligence  
> **Primary goal:** Build a convincing hackathon prototype that does not merely classify an email as malicious, but reconstructs the trustworthy evidence trail behind it, fingerprints persistent campaign infrastructure traits, correlates a new email with historical attacks even after domain/IP rotation, and explains every conclusion through evidence.

---

# 0. Executive Summary

TraceDNA is an email threat investigation prototype focused on **Business Email Compromise (BEC), phishing, impersonation, and related email campaigns**.

Most basic email-security demos do this:

```text
Email
  ↓
Classifier / LLM
  ↓
Phishing: 96%
```

TraceDNA should instead do this:

```text
Raw .eml
   ↓
Evidence preservation
   ↓
Header + identity + URL + content triage
   ↓
Trust-aware mail path reconstruction
   ↓
IOC and infrastructure extraction
   ↓
Infrastructure DNA fingerprint
   ↓
Historical campaign similarity
   ↓
Campaign mutation timeline
   ↓
Claim → Evidence → Confidence
   ↓
Analyst dashboard + forensic report
```

The strongest hackathon differentiation is the combination of:

1. **Trust-Aware Mail Path Reconstruction**
   - Do not blindly trust the oldest/earliest-looking `Received:` header.
   - Determine the earliest **independently observable** infrastructure from the trusted portion of the relay chain.
   - Treat older sender-supplied or discontinuous headers as potentially spoofed.
   - Explain *why* each hop is trusted, uncertain, or rejected.

2. **Infrastructure DNA**
   - Represent a campaign using persistent traits across network, domain, URL/web, mail-header, content-template, and temporal features.
   - Compare new emails against historical campaigns even when obvious IOCs such as domain and IP have changed.
   - Produce an explainable similarity score with per-feature contributions.

3. **Campaign DNA Mutation Tracker**
   - Show how a campaign changed over time:
     - domain rotated,
     - IP changed,
     - provider changed,
     - URL pattern retained,
     - template retained,
     - message-ID pattern retained,
     - Reply-To reused,
     - certificate or other infrastructure trait reused where data exists.
   - Highlight which DNA traits survived each mutation.

4. **Evidence Provenance**
   - Every important conclusion must be represented as:
     - **Claim**
     - **Supporting evidence**
     - **Contradicting evidence**
     - **Confidence**
   - Never allow an LLM to invent forensic facts.
   - The raw `.eml` must be hashed and preserved unchanged.

This prototype is **not** intended to replace Microsoft Defender, Proofpoint, Mimecast, VirusTotal, or an enterprise SOC platform. The goal is to demonstrate a technically defensible investigation capability with a memorable live demo.

---

# 1. Core Product Thesis

The product thesis is:

> **Most tools tell you that an email is malicious. TraceDNA shows which campaign it is probably part of, how that campaign changed infrastructure to evade simple IOC matching, what the earliest trustworthy observable sending infrastructure is, and exactly which evidence supports each conclusion.**

The system should answer five questions:

1. **Is the email suspicious?**
2. **Why is it suspicious?**
3. **What is the earliest trustworthy observable sending infrastructure?**
4. **Does it resemble a previously observed campaign despite changed domains/IPs?**
5. **What evidence supports or contradicts each conclusion?**

The prototype should make these answers visual and inspectable.

---

# 2. Scope Priorities

## 2.1 Must-Build MVP

The prototype is only considered complete if these work end to end:

1. Raw `.eml` upload.
2. SHA-256 evidence hashing.
3. Email parsing:
   - headers,
   - body text,
   - HTML,
   - URLs,
   - attachments metadata,
   - Message-ID,
   - From,
   - Reply-To,
   - Return-Path,
   - Received chain,
   - Authentication-Results where present.
4. Transparent threat/BEC triage.
5. Trust-aware `Received:` chain analysis.
6. Extraction of observable infrastructure:
   - domains,
   - IPs,
   - URLs,
   - Reply-To,
   - Message-ID pattern,
   - attachment hashes.
7. Infrastructure DNA feature generation.
8. Pairwise email similarity.
9. Campaign clustering / campaign matching.
10. Campaign mutation timeline.
11. Evidence provenance:
    - evidence items,
    - claims,
    - confidence,
    - explanations.
12. Analyst dashboard.
13. Seeded demo dataset.
14. End-to-end tests.
15. One-click or simple command to run the full prototype locally.

## 2.2 Nice-to-Have

Only build these after the MVP is stable:

- Live RDAP lookup.
- Live DNS lookup.
- GeoIP lookup.
- VirusTotal / AbuseIPDB adapters.
- Transformer embeddings.
- PDF export.
- LLM report generation.
- Background task queue.
- PostgreSQL production profile.

## 2.3 Explicitly Out of Scope for the Hackathon

Do **not** spend prototype time on:

- malware detonation/sandboxing,
- executing attachments,
- Gmail/Outlook integration,
- automatic quarantine,
- SIEM/SOAR integration,
- Kubernetes,
- Elasticsearch/OpenSearch,
- distributed Kafka architecture,
- enterprise RBAC,
- complex multi-tenant design,
- mobile app,
- exact human attacker geolocation,
- production legal chain-of-custody claims,
- claiming that IP geolocation identifies a physical attacker.

---

# 3. Target User

Primary user:

- SOC analyst,
- incident responder,
- cybersecurity investigator,
- fraud-response analyst,
- institutional security team.

Typical interaction:

1. Analyst receives a suspicious email.
2. Analyst exports/downloads the raw message as `.eml`.
3. Analyst uploads it to TraceDNA.
4. TraceDNA:
   - preserves evidence,
   - triages the email,
   - reconstructs the trustworthy mail path,
   - extracts indicators,
   - compares the email to prior incidents,
   - identifies likely campaign relationships,
   - builds a timeline,
   - provides evidence-backed conclusions.
5. Analyst can inspect *why* a conclusion was reached.

---

# 4. Strongest Demo Narrative

The live demo is the centre of the product.

Seed the system with three historical malicious emails belonging to the same campaign, but make them look superficially unrelated.

Example:

```text
Email A
Domain: payroll-secure.example
IP: 192.0.2.10
URL pattern: /auth/session/<token>
Message-ID pattern: <digits>.<hex>@mailer-node
Template: "validate payroll profile"

Email B
Domain: office-auth.example
IP: 198.51.100.22
URL pattern: /auth/session/<token>
Message-ID pattern: <digits>.<hex>@mailer-node
Template: structurally similar
Different visible sender

Email C
Domain: microsoft-check.example
IP: 203.0.113.31
URL pattern: /auth/session/<token>
Message-ID pattern: <digits>.<hex>@mailer-node
Same/near-same HTML skeleton
```

Then upload a fourth **unseen** `.eml`.

The new email should:

- use a new domain,
- use a new IP,
- contain a forged lower `Received:` header pointing somewhere innocent,
- retain several hidden campaign traits:
  - similar HTML/template structure,
  - same URL path grammar,
  - same Message-ID structure,
  - related Reply-To pattern,
  - similar sending-time window,
  - optionally a reused certificate fingerprint from fixture enrichment.

The demo should reveal information in this order:

### Reveal 1 — Threat Triage

```text
HIGH RISK
Likely category: Business Email Compromise / Credential Phishing
```

This is expected and should not be treated as the wow moment.

### Reveal 2 — Trust-Aware Mail Path

Show a relay chain.

Example:

```text
[TRUSTED ROOT]
recipient-gateway.example
        ↓
[TRUSTED]
mx.provider.example
        ↓
[BOUNDARY]
203.0.113.77
Earliest independently observed external source
        ↓
[UNTRUSTED / SENDER-SUPPLIED]
1.2.3.4
Forged lower Received header
```

The UI must explain why the forged hop was excluded.

### Reveal 3 — Infrastructure DNA

```text
Campaign Alpha similarity: 0.86 — HIGH

Contributions:
+ URL path grammar similarity          0.18
+ HTML/template similarity             0.15
+ Message-ID pattern similarity        0.14
+ Reply-To pattern similarity          0.12
+ Mail header fingerprint similarity   0.10
+ Temporal proximity                   0.07
+ Network/provider relation            0.06
+ Domain lexical relation              0.04
```

The exact numbers may differ, but contributions must be generated by the algorithm, not hard-coded into the UI.

### Reveal 4 — Campaign Mutation Timeline

```text
Day 1   Campaign Alpha first observed
Day 3   Domain A active
Day 6   IP changed
Day 7   Domain B appeared
Day 10  Domain C appeared
Today   New email matched to Campaign Alpha

Persistent traits:
✓ URL grammar retained
✓ HTML skeleton retained
✓ Message-ID pattern retained
✓ Reply-To pattern retained

Rotated traits:
✗ Domain changed
✗ IP changed
```

### Reveal 5 — Evidence

Click:

```text
VIEW EVIDENCE
```

Every conclusion expands into the exact parsed source fields and derived evidence that support it.

This final evidence view is essential.

---

# 5. Technical Architecture

Use a deliberately simple architecture for hackathon reliability.

```text
┌────────────────────────────────────────────┐
│ React / TypeScript Frontend                │
│ - Upload                                   │
│ - Case summary                             │
│ - Relay path                               │
│ - Campaign graph                           │
│ - Mutation timeline                        │
│ - Evidence drawer                          │
└─────────────────────┬──────────────────────┘
                      │ HTTP / JSON
                      ▼
┌────────────────────────────────────────────┐
│ FastAPI Backend                            │
│                                            │
│  Ingestion Service                         │
│       ↓                                    │
│  Email Parser                              │
│       ↓                                    │
│  Threat Triage                             │
│       ↓                                    │
│  Header Trust Engine                       │
│       ↓                                    │
│  IOC / Feature Extractors                  │
│       ↓                                    │
│  Infrastructure DNA Engine                 │
│       ↓                                    │
│  Campaign Matcher / Graph                  │
│       ↓                                    │
│  Mutation Timeline                         │
│       ↓                                    │
│  Claim + Evidence Engine                   │
│                                            │
│  SQLite default / PostgreSQL optional      │
└────────────────────────────────────────────┘
```

## Recommended stack

### Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy or SQLModel
- SQLite by default
- PostgreSQL optional via environment variable
- NetworkX
- scikit-learn
- `email` standard library
- `beautifulsoup4`
- `tldextract`
- `python-multipart`
- `dnspython` optional
- `httpx` for optional enrichment
- `uvicorn`

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS or simple CSS modules
- Cytoscape.js for relationship graph
- Recharts or lightweight charting for score components if desired

### Testing

- pytest
- FastAPI TestClient / httpx
- frontend smoke test if practical
- deterministic fixture data

---

# 6. Repository Layout

Recommended structure:

```text
tracedna/
├── README.md
├── .env.example
├── docker-compose.yml              # optional, keep simple
├── Makefile                        # or task commands
│
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models/
│   │   │   ├── case.py
│   │   │   ├── email_record.py
│   │   │   ├── evidence.py
│   │   │   ├── claim.py
│   │   │   ├── campaign.py
│   │   │   └── analysis.py
│   │   ├── schemas/
│   │   │   ├── cases.py
│   │   │   ├── analysis.py
│   │   │   └── graph.py
│   │   ├── services/
│   │   │   ├── ingestion.py
│   │   │   ├── email_parser.py
│   │   │   ├── auth_parser.py
│   │   │   ├── triage.py
│   │   │   ├── header_trust.py
│   │   │   ├── indicator_extractor.py
│   │   │   ├── feature_extractor.py
│   │   │   ├── dna_similarity.py
│   │   │   ├── campaign_matcher.py
│   │   │   ├── timeline.py
│   │   │   ├── evidence_engine.py
│   │   │   ├── report.py
│   │   │   └── enrichment/
│   │   │       ├── base.py
│   │   │       ├── fixture_provider.py
│   │   │       ├── rdap_provider.py
│   │   │       └── geoip_provider.py
│   │   ├── api/
│   │   │   ├── cases.py
│   │   │   ├── campaigns.py
│   │   │   └── health.py
│   │   └── utils/
│   │       ├── hashing.py
│   │       ├── normalization.py
│   │       └── time.py
│   ├── tests/
│   │   ├── fixtures/
│   │   ├── test_parser.py
│   │   ├── test_header_trust.py
│   │   ├── test_dna_similarity.py
│   │   ├── test_campaign_matcher.py
│   │   └── test_end_to_end.py
│   └── scripts/
│       ├── seed_demo.py
│       └── analyse_fixture.py
│
├── frontend/
│   ├── package.json
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   │   ├── UploadPanel.tsx
│   │   │   ├── RiskSummary.tsx
│   │   │   ├── RelayTrustPath.tsx
│   │   │   ├── DnaSimilarityPanel.tsx
│   │   │   ├── CampaignGraph.tsx
│   │   │   ├── MutationTimeline.tsx
│   │   │   ├── EvidenceDrawer.tsx
│   │   │   └── ClaimCard.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── CaseDetail.tsx
│   │   │   └── CampaignDetail.tsx
│   │   ├── types/
│   │   └── main.tsx
│   └── ...
│
└── demo/
    ├── emails/
    │   ├── alpha_01.eml
    │   ├── alpha_02.eml
    │   ├── alpha_03.eml
    │   ├── beta_01.eml
    │   ├── benign_urgent_invoice.eml
    │   └── unseen_alpha_mutation.eml
    ├── enrichment_fixtures.json
    └── DEMO_SCRIPT.md
```

---

# 7. Data Model

The database must preserve enough structure for explainability.

## 7.1 Case

```text
Case
- id
- created_at
- source_filename
- raw_sha256
- analysis_version
- status
- final_risk_score
- final_category
- matched_campaign_id nullable
```

## 7.2 EmailRecord

```text
EmailRecord
- id
- case_id
- message_id
- subject
- from_name
- from_address
- from_domain
- reply_to
- reply_to_domain
- return_path
- return_path_domain
- sent_at
- body_text
- body_html
- raw_headers_json
- parsed_headers_json
```

Do not silently modify or normalize away the original raw values. Store normalized values separately where necessary.

## 7.3 Indicator

```text
Indicator
- id
- case_id
- type
  - domain
  - ip
  - url
  - email
  - attachment_sha256
  - message_id_pattern
  - hostname
  - asn
  - provider
- raw_value
- normalized_value
- source_field
- first_seen
- enrichment_json
```

## 7.4 EvidenceItem

```text
EvidenceItem
- id
- case_id
- evidence_type
- source_component
- source_field
- raw_value
- normalized_value
- derived_value
- extractor_version
- created_at
- evidence_hash
- metadata_json
```

Example:

```json
{
  "id": "E-103",
  "evidence_type": "header_trust",
  "source_component": "header_trust_engine",
  "source_field": "Received[3]",
  "raw_value": "Received: from ...",
  "derived_value": "untrusted",
  "metadata": {
    "reason_codes": [
      "OLDER_THAN_TRUST_BOUNDARY",
      "NOT_INDEPENDENTLY_OBSERVED"
    ]
  }
}
```

## 7.5 Claim

```text
Claim
- id
- case_id
- claim_type
- statement
- confidence_score
- confidence_band
- confidence_kind
- explanation
- supporting_evidence_ids
- contradicting_evidence_ids
```

`confidence_kind` must distinguish:

```text
heuristic_evidence_confidence
```

from a calibrated statistical probability.

Do not display a heuristic score as if it were a scientifically calibrated probability.

## 7.6 InfrastructureDNA

Store a structured fingerprint:

```json
{
  "network": {...},
  "domain": {...},
  "web": {...},
  "mail": {...},
  "content": {...},
  "temporal": {...}
}
```

Also store:

- feature extractor version,
- normalized feature vector if used,
- sparse token sets,
- embedding/model version where applicable.

## 7.7 Campaign

```text
Campaign
- id
- name
- created_at
- first_seen
- last_seen
- risk_summary
- dna_prototype_json
- member_count
```

## 7.8 CampaignMembership

```text
CampaignMembership
- campaign_id
- case_id
- similarity_score
- similarity_band
- matched_at
- contribution_breakdown_json
- decision_reason
```

---

# 8. Raw Evidence Preservation

When a file is uploaded:

1. Read raw bytes.
2. Compute SHA-256 immediately.
3. Save raw file unchanged in an evidence directory, e.g.:

```text
data/evidence/<case_id>/original.eml
```

4. Record:
   - original filename,
   - content length,
   - SHA-256,
   - ingestion timestamp,
   - analysis version.

Do not mutate the saved evidence.

All derived analysis is stored separately.

A simple verification endpoint should re-hash the file and confirm:

```text
Evidence integrity: PASS
```

or:

```text
Evidence integrity: FAIL
```

This is not a legal chain-of-custody certification. The UI must say:

> Prototype evidence-integrity verification.

---

# 9. Email Parsing

Use Python's standard `email` package with an appropriate policy.

Extract:

- Subject
- From
- To
- Cc if present
- Reply-To
- Return-Path
- Message-ID
- Date
- Received headers
- Authentication-Results
- Received-SPF
- DKIM-Signature
- ARC-* headers where present
- body text
- body HTML
- URLs in:
  - plain text,
  - HTML href attributes,
  - HTML form actions where applicable
- attachment:
  - filename,
  - declared MIME,
  - detected/observed byte type if practical,
  - size,
  - SHA-256,
  - embedded URLs only if easy and safe.

Never execute attachments.

Use defensive parsing because malformed emails are common.

---

# 10. Threat / BEC Triage

Triage is intentionally secondary to the campaign investigation.

The MVP should use a transparent hybrid:

1. deterministic rules,
2. structured feature score,
3. optional lightweight text model.

## 10.1 Example Risk Signals

High-value signals:

```text
DMARC fail / misalignment
Reply-To domain mismatch
From vs Return-Path mismatch
lookalike sender domain
credential request
payment diversion request
bank account change request
gift card request
secret/confidential urgency
suspicious/deceptive URL
known malicious IOC fixture hit
```

Lower-value contextual signals:

```text
urgency
authority language
very recent domain fixture
IP reputation fixture
unusual Message-ID domain
```

## 10.2 Example Transparent Risk Score

Illustrative weights:

```text
DMARC/alignment serious anomaly      +18
Reply-To mismatch                    +12
Return-Path mismatch                 +8
lookalike domain                     +15
credential request                   +15
payment diversion / bank change      +18
secrecy / "do not call"              +8
strong urgency                       +6
suspicious URL structure             +10
threat-intel fixture hit              +12
```

Cap at 100.

The score must expose its component contributions.

The exact weight table must live in configuration, not in UI code.

## 10.3 Categories

At minimum:

```text
clean_or_low_risk
suspicious
credential_phishing
business_email_compromise
brand_impersonation
```

The category can be rule-composed.

An optional text classifier may refine category but must not override hard forensic facts.

---

# 11. Authentication Analysis

Parse and display existing:

- SPF result
- DKIM result
- DMARC result
- ARC information where available

Do not assume the prototype can perfectly re-verify historical DKIM from current DNS.

For MVP:

1. Parse `Authentication-Results`.
2. Extract:
   - SPF result and authenticated domain,
   - DKIM result and signing domain,
   - DMARC result and visible From domain relationship.
3. Detect alignment anomalies.
4. Clearly distinguish:
   - **observed receiver authentication result**
   - **live re-check result** if a live lookup adapter is implemented.

Never collapse those into one field.

---

# 12. Trust-Aware Mail Path Reconstruction

This is one of the two core technical differentiators.

## 12.1 Important Email Semantics

Each receiving mail server normally **prepends** its own `Received:` header.

Therefore, in a raw mailbox copy:

- topmost `Received:` entries are typically the most recent,
- older-looking entries appear lower,
- but malicious senders can insert fake `Received:` lines before submitting the message.

Therefore:

> The system must not blindly treat the lowest/oldest-looking `Received:` header as authoritative.

## 12.2 Trust Root

The prototype needs a trust configuration.

Example:

```yaml
trusted_gateways:
  - recipient-gateway.example
  - "*.google.com"
  - "*.outlook.com"

trusted_ip_ranges:
  - "203.0.113.0/28"
```

For the seeded demo, use explicit known trusted gateway patterns.

For arbitrary uploads, if no organisational trust root is available:

- mark trust as `unknown`,
- still parse the chain,
- do not overclaim.

## 12.3 Core Algorithm

Represent parsed hops in header order from newest to oldest.

Each hop should include:

```text
index
raw_header
from_host
from_ip
by_host
by_ip if available
timestamp
public/private classification
syntax quality
```

Algorithm:

1. Identify whether the topmost hop was inserted by a configured trusted gateway.
2. If not, set trust confidence low/unknown and avoid claiming a hard boundary.
3. Starting from the trusted top hop, traverse downward.
4. For each next hop, determine whether the currently trusted receiver independently observed the claimed peer.
5. Validate continuity using available signals:
   - receiver hostname consistency,
   - previous/next peer relationship,
   - public/private IP sanity,
   - timestamp ordering tolerance,
   - syntactic consistency,
   - configured trusted relay match,
   - obvious impossible transitions.
6. Continue while evidence supports continuity.
7. The **earliest independently observed external source** is the source peer of the lowest still-trusted Received hop.
8. Any older headers below the trust boundary are marked:
   - untrusted,
   - sender supplied,
   - or unknown.
9. Create an evidence-backed claim.

Example claim:

```text
Claim:
203.0.113.77 is the earliest independently observed external sending infrastructure.

Confidence:
HIGH heuristic evidence confidence

Supporting evidence:
E12 — Received header inserted by configured trusted gateway
E13 — chain continuity preserved
E14 — timestamp ordering plausible

Contradicting/uncertain evidence:
E18 — older sender-supplied Received line claims 1.2.3.4
```

## 12.4 Hop Trust Score

A simple heuristic score may be used internally.

Illustrative components:

```text
+30 inserted by configured trusted gateway
+20 continuity with trusted downstream hop
+10 parseable public peer IP
+10 plausible timestamp ordering
+10 hostname/IP consistency
+10 reverse relation / fixture consistency if available
+10 authenticated infrastructure relation if available

-30 continuity break
-25 older than established trust boundary
-20 impossible/private-public transition without explanation
-20 severe timestamp anomaly
-20 malformed/unparseable hop
```

Convert score to bands:

```text
>= 70  TRUSTED
40-69  UNCERTAIN
< 40   UNTRUSTED
```

These thresholds are heuristic and must be labelled as such.

## 12.5 Counterfactual Header Tampering Demo

Include a demo button or prebuilt fixture that shows:

```text
Naive oldest-header extraction:
1.2.3.4

TraceDNA trust-aware boundary:
203.0.113.77

Reason:
1.2.3.4 appears only in a header below the independently observed trust boundary.
```

This is a critical demo feature.

---

# 13. Indicator Extraction and Normalisation

Extract:

- sender domain,
- Reply-To domain,
- Return-Path domain,
- Message-ID domain,
- Message-ID local-part pattern,
- Received hostnames,
- Received IPs,
- URLs,
- URL hostnames,
- registrable domains,
- attachment hashes,
- optional X-Mailer/User-Agent header,
- content text,
- HTML skeleton.

Normalize carefully.

## 13.1 Domain Normalisation

- lower-case,
- Unicode/punycode handling,
- registrable domain via `tldextract`,
- tokenise labels,
- derive lexical fingerprint:
  - strip digits to `<D>`,
  - split hyphenated tokens,
  - character n-grams if used.

Example:

```text
secure-login-493.example
→ tokens: ["secure", "login", "<D>"]
```

## 13.2 URL Normalisation

For similarity:

- lowercase host,
- remove scheme,
- remove fragment,
- normalize path parameters,
- replace long numeric/hex tokens,
- sort or set query parameter keys,
- do not preserve secrets.

Example:

```text
https://a.example/auth/session/9af83d?uid=381&token=abc
```

becomes:

```text
host=a.example
path=/auth/session/<HEX>
query_keys={uid,token}
```

## 13.3 Message-ID Pattern

Example:

```text
<1720550283.8f73ac@mail-node-03>
```

derive a pattern such as:

```text
<DIGITS>.<HEX>@mail-node-<DIGITS>
```

This can be surprisingly useful in controlled campaign fixtures.

## 13.4 HTML Skeleton

For HTML body:

- parse with BeautifulSoup,
- remove text values,
- preserve tags,
- preserve form/action/link structural features,
- normalize random IDs/classes where possible.

Example structural representation:

```text
html>body>table>tr>td>a
html>body>form>input:text
html>body>form>input:password
```

Use this for template similarity.

---

# 14. Infrastructure DNA

This is the central campaign-correlation concept.

The DNA must be **structured and explainable**, not a vague embedding.

Create six feature groups.

## 14.1 Network DNA

Possible features:

```text
source IP
/24 or /48 network prefix
ASN
hosting provider
network type
reverse-DNS suffix
nameserver/provider relation
```

For the offline demo, enrichment can come from deterministic fixture data.

Important:

> Same ASN or same large cloud provider is weak evidence.

Network similarity must never dominate on its own.

## 14.2 Domain DNA

Features:

```text
registrable domain tokens
subdomain pattern
hyphen/digit pattern
TLD
punycode flag
lookalike relation
registrar fixture
nameserver suffixes
domain-age band fixture
```

## 14.3 Web / URL DNA

Features:

```text
normalized URL path grammar
query key set
path token set
credential-form presence
redirect pattern fixture
HTML link structure
```

## 14.4 Mail DNA

Features:

```text
Reply-To pattern
Return-Path pattern
Message-ID pattern
Message-ID domain
X-Mailer/User-Agent
Received hostname patterns
HELO/EHLO-like hostname if parsable
authentication-domain patterns
```

## 14.5 Content DNA

Use template-oriented similarity, not raw semantic "same topic".

Features:

```text
normalized text TF-IDF
HTML skeleton TF-IDF/Jaccard
key phrase structure
CTA pattern
credential/payment intent
```

A transformer embedding is optional.

Default implementation should work offline using scikit-learn TF-IDF.

## 14.6 Temporal DNA

Features:

```text
send hour bucket
day spacing
campaign burst proximity
domain first-seen relation fixture
```

Temporal evidence should be weak-to-medium, never decisive alone.

---

# 15. DNA Similarity Algorithm

The algorithm must return:

```text
overall_similarity
similarity_band
per_group_scores
per_feature contributions
high_signal exact matches
conflicts
```

## 15.1 Group Weights

Recommended starting weights:

```text
network   0.12
domain    0.12
web       0.22
mail      0.22
content   0.22
temporal  0.10
----------------
total     1.00
```

The reasoning:

- same network/provider is easy to collide on,
- domain changes are expected,
- web/mail/content persistence is more useful for mutation tracking,
- temporal relation supports but should not dominate.

Weights must be configurable.

## 15.2 Example Feature Similarities

Use transparent metrics:

### Sets
Use Jaccard:

```text
J(A,B) = |A ∩ B| / |A ∪ B|
```

Use for:

- URL path tokens,
- query keys,
- nameserver suffixes,
- tag structures,
- header pattern sets.

### Strings / Patterns

Use:

- normalized Levenshtein ratio,
- character n-gram cosine similarity,
- exact match for high-signal fingerprints.

### Content

Default:

- TF-IDF cosine similarity on normalized text,
- TF-IDF/Jaccard on HTML skeleton.

### Temporal

Simple piecewise score:

```text
<= 1 day    1.0
<= 3 days   0.8
<= 7 days   0.6
<= 14 days  0.4
<= 30 days  0.2
else        0.0
```

Do not use temporal proximity as strong proof.

## 15.3 High-Signal Bonuses

Some exact matches may justify extra confidence.

Example bonuses:

```text
same attachment SHA-256         +0.20
same Reply-To exact             +0.10
same certificate fingerprint    +0.12  # if available
same uncommon Message-ID pattern +0.08
```

Cap total similarity at 1.0.

Only apply bonuses when the feature is genuinely present.

## 15.4 Weak-Signal Downweighting

Examples:

```text
same major cloud ASN            low contribution
same Cloudflare/AWS/Azure       very low contribution
same common TLD                 near-zero contribution
same language                   near-zero contribution
generic urgency                 near-zero campaign contribution
```

The algorithm should allow a `common_infrastructure` list to reduce common-provider weight.

## 15.5 Similarity Bands

Recommended:

```text
>= 0.75  HIGH campaign similarity
0.55-0.74 REVIEW / POSSIBLE
< 0.55  LOW / UNRELATED
```

These are prototype heuristics, not calibrated probabilities.

The UI must use words like:

```text
Similarity: 0.86 — HIGH
```

not:

```text
86% probability same attacker
```

---

# 16. Campaign Matching

For a new case:

1. Compute DNA against each previous case.
2. Compute strongest matches per campaign.
3. Calculate:
   - max pairwise similarity,
   - mean of top 3 similarities,
   - number of high-signal shared features.
4. Assign to a campaign only under conservative conditions.

Suggested rule:

```text
Attach to existing campaign if:

max_pair >= 0.78

AND

(
  top3_mean >= 0.65
  OR
  at least one high-signal exact match exists
)
```

If no campaign qualifies:

```text
No confident historical campaign match.
```

Do not force every malicious email into a campaign.

---

# 17. Campaign Clustering for Seeded History

For historical demo data:

1. Build an email-to-email similarity graph.
2. Add an edge if similarity >= configurable threshold, e.g. `0.68`.
3. Store edge weight = similarity.
4. Use NetworkX connected components for the MVP.

This is intentionally simple and transparent.

Later, community-detection algorithms can be added, but not required.

Graph node types in the UI may include:

```text
email
campaign
domain
ip
url_pattern
reply_to
attachment_hash
message_id_pattern
```

Avoid an unreadable "everything graph".

The default graph should emphasize the evidence relevant to the selected campaign.

---

# 18. Campaign DNA Prototype

A campaign prototype can be computed from member emails.

Store:

- most frequent structural URL patterns,
- most frequent Message-ID patterns,
- recurring Reply-To domains/addresses,
- high-similarity HTML skeleton clusters,
- recurring text-template tokens,
- associated IPs/ASNs/providers,
- observed domains,
- first/last seen.

Do not average meaningless categorical fields blindly.

The campaign prototype is a summary used for display and optional fast pre-filtering.

Final attachment should still be supported by pairwise evidence.

---

# 19. Campaign Mutation Tracker

The mutation tracker should answer:

> What changed, and what persisted?

For all members in a campaign, sort by `sent_at` or `first_seen`.

Between consecutive events, detect:

```text
domain_changed
source_ip_changed
asn_changed
provider_changed
reply_to_changed
message_id_pattern_changed
url_pattern_persisted
html_template_persisted
attachment_hash_reused
certificate_reused
```

Output timeline entries.

Example:

```json
{
  "timestamp": "2026-09-03T10:00:00Z",
  "event_type": "infrastructure_mutation",
  "summary": "Campaign moved to a new domain and IP while retaining URL and HTML patterns.",
  "changed": [
    "domain",
    "source_ip"
  ],
  "persisted": [
    "url_path_grammar",
    "html_skeleton",
    "message_id_pattern"
  ],
  "evidence_ids": ["E31", "E32", "E33", "E34"]
}
```

The frontend should visually distinguish:

- **rotated traits**
- **persistent traits**

This is the primary campaign wow feature.

---

# 20. Evidence and Claim Engine

Every important analyst-visible conclusion must become a `Claim`.

Required claim types:

```text
threat_assessment
sender_identity_anomaly
authentication_anomaly
earliest_trustworthy_infrastructure
header_tampering_or_untrusted_hop
campaign_match
campaign_mutation
infrastructure_location
evidence_integrity
```

Example:

```json
{
  "claim_type": "campaign_match",
  "statement": "This email is highly similar to Campaign Alpha.",
  "confidence_score": 0.86,
  "confidence_band": "high",
  "confidence_kind": "heuristic_evidence_confidence",
  "supporting_evidence_ids": [
    "E-URL-12",
    "E-HTML-04",
    "E-MSGID-03",
    "E-REPLY-07"
  ],
  "contradicting_evidence_ids": [
    "E-IP-DIFF-02",
    "E-DOMAIN-DIFF-03"
  ]
}
```

The UI must show contradictions too.

This is important because the project should appear analytical, not overconfident.

---

# 21. Geolocation and Infrastructure Enrichment

For the MVP, use an adapter interface.

```python
class EnrichmentProvider:
    def enrich_ip(ip: str) -> IPEnrichment: ...
    def enrich_domain(domain: str) -> DomainEnrichment: ...
```

Implement first:

```text
FixtureEnrichmentProvider
```

that loads deterministic demo metadata from:

```text
demo/enrichment_fixtures.json
```

Optional:

- RDAP live provider,
- GeoIP provider.

UI language must say:

```text
Likely infrastructure location
```

Never:

```text
Attacker location
```

If source is demo fixture, label:

```text
DEMO ENRICHMENT
```

If live GeoIP exists:

```text
Infrastructure geolocation only; does not identify a human attacker.
```

---

# 22. Optional AI / LLM Layer

The prototype must work without an LLM.

If an LLM is added, it is **only an explanation/report layer**.

Input to the LLM:

```json
{
  "claims": [...],
  "evidence": [...],
  "campaign_summary": {...},
  "timeline": [...]
}
```

Never send the LLM the task:

> "Decide whether this is phishing from the raw email."

The LLM may:

- summarize existing structured findings,
- answer analyst questions using evidence IDs,
- generate a concise report.

Every sentence in an AI report should ideally cite evidence IDs.

If no API key is available, use deterministic templated explanations.

No part of the core demo should fail because an external LLM is unavailable.

---

# 23. API Design

Recommended endpoints.

## Health

```http
GET /api/health
```

## Upload and analyse

```http
POST /api/cases
Content-Type: multipart/form-data
file=<eml>
```

Response:

```json
{
  "case_id": "CASE-...",
  "status": "analysed"
}
```

## Get case

```http
GET /api/cases/{case_id}
```

Returns:

- metadata,
- risk,
- parsed sender/auth info,
- campaign result,
- top claims.

## Relay path

```http
GET /api/cases/{case_id}/relay-path
```

Returns hops with:

```text
index
from_host
from_ip
by_host
timestamp
trust_score
trust_band
reason_codes
is_trust_boundary
```

## DNA

```http
GET /api/cases/{case_id}/dna
```

## Campaign match

```http
GET /api/cases/{case_id}/campaign-match
```

## Evidence

```http
GET /api/cases/{case_id}/evidence
```

## Claims

```http
GET /api/cases/{case_id}/claims
```

## Campaign details

```http
GET /api/campaigns/{campaign_id}
```

Returns:

- members,
- graph,
- prototype,
- timeline,
- mutation summary.

## Campaign graph

```http
GET /api/campaigns/{campaign_id}/graph
```

Cytoscape-friendly JSON.

## Verify evidence integrity

```http
POST /api/cases/{case_id}/verify-integrity
```

---

# 24. Frontend UX

The UI should feel like an analyst product.

Do not create a chatbot-first experience.

## Screen 1 — Dashboard

Show:

```text
Case
Risk
Category
Campaign
Campaign similarity
Status
```

Provide:

```text
Upload .eml
Load demo scenario
```

## Screen 2 — Case Detail

Top section:

```text
HIGH RISK
Business Email Compromise
Risk score: 84/100
Campaign Alpha similarity: 0.86 HIGH
Evidence integrity: PASS
```

Then tabs/panels:

1. **Why flagged**
2. **Mail path**
3. **Campaign DNA**
4. **Related campaign**
5. **Evidence**

## Screen 3 — Mail Path

Render vertical path.

Colours may be chosen by frontend defaults, but semantically distinguish:

```text
trusted
uncertain
untrusted
trust boundary
```

Each hop should be clickable.

Clicking a hop shows:

- raw `Received:` header,
- parsed values,
- trust score,
- reason codes.

## Screen 4 — Campaign DNA

Show six group scores:

```text
Network
Domain
Web
Mail
Content
Temporal
```

Then show top positive matches and conflicts.

Example:

```text
Persistent
✓ URL grammar
✓ HTML template
✓ Message-ID pattern

Changed
✗ domain
✗ source IP
```

## Screen 5 — Campaign Graph

Use Cytoscape.js.

Do not display hundreds of nodes.

For demo, show:

```text
selected email
related emails
campaign
domains
IPs
URL pattern
Reply-To
```

## Screen 6 — Mutation Timeline

Chronological campaign evolution.

Every event should link back to evidence/cases.

## Screen 7 — Evidence Drawer

For a selected claim:

```text
Claim:
Likely part of Campaign Alpha

Supporting evidence:
E12 URL grammar similarity
E18 HTML structure similarity
E21 Message-ID pattern

Conflicting evidence:
E25 new domain
E26 new source IP
```

This drawer is essential.

---

# 25. Demo Dataset Specification

The repository must include safe synthetic data.

Use:

- `.example` domains,
- reserved documentation IP ranges:
  - `192.0.2.0/24`
  - `198.51.100.0/24`
  - `203.0.113.0/24`

Do not include live credential-phishing infrastructure.

## Campaign Alpha

Three historical emails plus one unseen mutation.

Persistent traits:

```text
URL path grammar:
  /auth/session/<token>

HTML skeleton:
  similar login form layout

Message-ID pattern:
  <DIGITS>.<HEX>@mailer-node-<DIGITS>

Reply-To pattern:
  accounts-<digits>@mailbox.example

Timing:
  morning bursts, close dates
```

Rotated traits:

```text
domain
source IP
sender display name
visible brand
```

## Campaign Beta

Different:

```text
URL:
  /invoice/view/<digits>

HTML:
  attachment/payment theme

Message-ID pattern:
  <UUID>@billing-gw

Reply-To:
  finance-desk@example
```

It must not be confused with Campaign Alpha.

## Benign Control

Create:

```text
benign_urgent_invoice.eml
```

It may contain words like:

- urgent,
- invoice,
- payment,

but should have:

- coherent sender identity,
- no deceptive URL,
- no Reply-To mismatch,
- no suspicious campaign DNA match,
- plausible authentication fixture.

This tests that text urgency alone does not trigger a severe malicious verdict.

## Forged Header Case

`unseen_alpha_mutation.eml` should contain an older, fake `Received:` line below the trust boundary.

The trust engine should explicitly reject or downgrade it.

---

# 26. Seeded Enrichment Fixture

Example:

```json
{
  "203.0.113.77": {
    "asn": "AS64500",
    "provider": "Example VPS Alpha",
    "country": "DE",
    "city": "Frankfurt",
    "network_type": "hosting",
    "source": "demo_fixture"
  }
}
```

Use fictional documentation ASNs / clearly demo-labelled values where practical.

The demo must not falsely imply that reserved IP ranges have real geolocation.

---

# 27. Acceptance Tests

The project is not complete until these pass.

## 27.1 Parsing

Given `alpha_01.eml`:

- From parsed correctly.
- Reply-To parsed correctly.
- Message-ID parsed.
- Received headers preserved in order.
- URLs extracted.
- raw file hash stored.

## 27.2 Integrity

After upload:

```text
verify-integrity → PASS
```

After deliberately modifying the saved raw evidence in a test:

```text
verify-integrity → FAIL
```

## 27.3 Header Trust

Given `unseen_alpha_mutation.eml`:

- configured recipient gateway is trusted root,
- trust traversal identifies an external boundary,
- forged older header is not treated as origin,
- claim references the exact evidence item(s).

## 27.4 DNA Similarity

Expected:

```text
unseen_alpha_mutation vs alpha historical:
HIGH

unseen_alpha_mutation vs beta:
LOW

benign urgent invoice vs alpha:
LOW
```

Do not assert exact scores unless tests are based on deterministic current weights.

Use acceptable ranges.

Example:

```text
alpha match >= 0.75
beta match < 0.55
benign match < 0.55
```

## 27.5 Campaign Matching

The unseen Alpha mutation should attach to Campaign Alpha.

The benign control should not attach to a malicious campaign.

## 27.6 Mutation Timeline

Campaign Alpha timeline should show:

- domain changes,
- IP changes,
- retained URL grammar,
- retained HTML/template trait,
- retained Message-ID pattern.

## 27.7 Evidence

Every high-level claim must contain at least one evidence reference.

A campaign match must also show contradictory/changed traits where they exist.

## 27.8 API

All core API routes should have tests.

## 27.9 End-to-End

One test/script should:

1. reset DB,
2. seed historical campaigns,
3. upload unseen email,
4. analyse it,
5. assert Campaign Alpha match,
6. assert forged hop not selected,
7. verify evidence integrity.

---

# 28. Evaluation Metrics

For the hackathon prototype, report only what can actually be measured.

## Detection

On synthetic/demo test set:

- precision,
- recall,
- F1,
- false positives.

## Campaign matching

- correct campaign assignment rate,
- false campaign assignment rate,
- similarity margin between correct and nearest wrong campaign.

## Header trust

Use curated test emails with:

- clean chain,
- forged lower header,
- missing trusted root,
- timestamp anomaly.

Report:

- trust-boundary correctness on this fixture set.

## Explainability

Check:

- percentage of high-level claims with evidence references,
- number of unsupported claims should be zero in deterministic report mode.

## Systems

Optional:

- median analysis latency on local demo,
- p95 latency for a small batch,
- do not make enterprise-scale claims.

---

# 29. Security Requirements

1. Never execute attachments.
2. Never automatically visit arbitrary URLs during the core analysis.
3. Live enrichment must be opt-in.
4. Set request size limits.
5. Sanitize filenames.
6. Store uploads outside public frontend directory.
7. Escape/render email HTML safely.
8. Do not render raw email HTML directly without sanitisation.
9. Do not expose secrets in logs.
10. Include `.env.example`.
11. Use timeouts for live HTTP/DNS lookups.
12. Treat all email content as untrusted data.
13. If an LLM exists, email content must never be interpreted as tool instructions.
14. LLM tool calls must be server-defined and evidence-scoped.

---

# 30. Error Handling

The system should fail honestly.

Examples:

```text
Trusted recipient gateway not configured.
Relay chain parsed, but trustworthy origin boundary cannot be established confidently.
```

```text
No campaign similarity exceeds the review threshold.
No historical campaign match assigned.
```

```text
Live RDAP unavailable.
Using locally available evidence only.
```

```text
DKIM re-verification unavailable.
Displaying receiver-observed Authentication-Results instead.
```

A graceful "unknown" is better than invented certainty.

---

# 31. Configuration

Use a config file or environment-driven settings.

Example:

```yaml
analysis_version: "0.1.0"

risk_weights:
  dmarc_anomaly: 18
  reply_to_mismatch: 12
  return_path_mismatch: 8
  lookalike_domain: 15
  credential_request: 15
  payment_diversion: 18
  secrecy: 8
  urgency: 6
  suspicious_url: 10
  threat_intel_hit: 12

dna_weights:
  network: 0.12
  domain: 0.12
  web: 0.22
  mail: 0.22
  content: 0.22
  temporal: 0.10

campaign_thresholds:
  high: 0.75
  review: 0.55
  attach_max_pair: 0.78
  attach_top3_mean: 0.65

header_trust:
  trusted_threshold: 70
  uncertain_threshold: 40
```

Do not hard-code values throughout the codebase.

---

# 32. Implementation Order

Codex should build in this order.

## Phase 1 — Backend Skeleton

- FastAPI app
- DB
- health endpoint
- core models
- upload endpoint
- raw evidence storage
- SHA-256

## Phase 2 — Parser

- `.eml` parser
- body/HTML
- headers
- URLs
- attachments hashes
- tests

## Phase 3 — Transparent Triage

- sender/auth mismatches
- text intent rules
- lookalike basics
- risk score
- evidence generation

## Phase 4 — Header Trust Engine

- Received parser
- trust configuration
- hop scoring
- trust boundary
- forged-header fixture
- tests

## Phase 5 — DNA Feature Extraction

- domain normalization
- URL grammar
- Message-ID pattern
- HTML skeleton
- TF-IDF features
- network fixture enrichment

## Phase 6 — Similarity and Campaigns

- pairwise DNA score
- per-feature contributions
- seeded campaigns
- matching logic
- NetworkX graph
- tests

## Phase 7 — Mutation Timeline

- compare ordered campaign cases
- changed vs persistent traits
- timeline API
- tests

## Phase 8 — Claims and Evidence

- claim generation
- contradictions
- evidence drawer data
- integrity verification

## Phase 9 — Frontend

- upload
- dashboard
- case detail
- mail path
- DNA breakdown
- graph
- timeline
- evidence drawer

## Phase 10 — Demo Polish

- one-command seeding
- demo reset
- sample files
- DEMO_SCRIPT.md
- screenshots optional
- final README

Do not begin optional LLM/live enrichment work until Phase 10 core flow works.

---

# 33. Definition of Done

The prototype is done when a fresh developer can:

```bash
git clone ...
cd tracedna
```

and then follow a short README to:

1. install backend dependencies,
2. install frontend dependencies,
3. seed demo data,
4. run backend,
5. run frontend,
6. open the app,
7. upload `demo/emails/unseen_alpha_mutation.eml`,
8. observe:
   - high threat risk,
   - forged header rejected,
   - earliest trustworthy infrastructure identified,
   - high Campaign Alpha similarity,
   - new email attached to Campaign Alpha,
   - mutation timeline updated,
   - claim/evidence view,
   - evidence-integrity PASS.

If this flow is not reliable, the prototype is not ready.

---

# 34. README Requirements

The README should contain:

1. What TraceDNA does.
2. What makes it different.
3. Architecture.
4. Local setup.
5. Demo commands.
6. Demo scenario.
7. Core algorithms.
8. Known limitations.
9. Safety notes.
10. No false claims:
   - infrastructure location ≠ attacker location,
   - similarity ≠ same human attacker,
   - heuristic confidence ≠ calibrated probability.
11. Test commands.
12. Optional integration instructions.

---

# 35. Product Messaging

Use this one-line pitch:

> **TraceDNA doesn't just flag malicious email — it reconstructs the trustworthy mail path, fingerprints persistent campaign traits, and shows how an attacker changed infrastructure while preserving the evidence linking related attacks.**

Longer pitch:

> **TraceDNA is an evidence-grounded email investigation platform that analyses raw email, rejects untrustworthy relay claims, fingerprints persistent infrastructure and behavioural traits, correlates new attacks with historical campaigns despite domain/IP rotation, reconstructs how the campaign mutated over time, and ties every conclusion back to inspectable evidence.**

---

# 36. What Must Not Be Claimed

Never claim:

- "We identify the attacker."
- "This IP is the hacker's location."
- "86% probability this is the same criminal."
- "Legally admissible chain of custody."
- "Enterprise-scale 100k email throughput" unless actually load-tested.
- "Zero-day phishing detection" unless genuinely evaluated.
- "AI found the attacker."
- "Novel because we use a graph."
- "Novel because we use an LLM."
- "Novel because we check SPF/DKIM/DMARC."

Safer language:

- earliest trustworthy observable infrastructure,
- likely campaign relationship,
- infrastructure location,
- heuristic evidence confidence,
- explainable similarity,
- evidence-grounded investigation,
- prototype integrity verification.

---

# 37. Judge Questions the Prototype Must Survive

## "Why not just VirusTotal?"

Answer:

> VirusTotal is useful for IOC enrichment. TraceDNA's core value is trust-aware email-path reconstruction plus transparent cross-email campaign fingerprinting and mutation tracking. External threat-intelligence lookups are supporting evidence, not the product.

## "Why not Microsoft Defender?"

Answer:

> Mature commercial systems perform campaign correlation. The prototype focuses on making the underlying evidence relationship explicit and demonstrable: which mail-path hops are trusted, which traits survived IOC rotation, how similarity is calculated, what changed over time, and what contradicts the campaign hypothesis.

## "Is the graph the innovation?"

Answer:

> No. The graph is a visualisation. The core technical work is trust-aware origin-boundary analysis, structured Infrastructure DNA similarity, and mutation tracking with evidence provenance.

## "Where does 86% come from?"

Answer:

> It is a transparent heuristic similarity score built from documented feature groups and per-feature contributions. It is not presented as a calibrated probability of attacker identity.

## "Can a shared ASN create false matches?"

Answer:

> Yes, which is why common network infrastructure is deliberately low-weight. More discriminative mail, URL, template, and exact high-signal traits carry more weight.

## "What if you cannot determine the origin?"

Answer:

> The system reports that the trustworthy origin boundary cannot be established confidently. It is designed to fail honestly rather than invent certainty.

## "What role does AI play?"

Answer:

> Core forensic extraction and campaign scoring are deterministic and inspectable. An optional AI layer can summarize structured evidence but cannot create unsupported facts.

---

# 38. Hackathon Presentation Structure

Recommended 5–7 minute demo/pitch:

## 0:00–0:30 — Problem

> Existing alerts often stop at "malicious". Analysts still need to understand how the message arrived and whether it is related to previous attacks.

## 0:30–1:00 — Key Insight

> Attackers rotate domains and IPs, but they frequently retain less obvious operational traits.

## 1:00–1:30 — Architecture

Show only:

```text
Email
→ Trust-aware path
→ Infrastructure DNA
→ Campaign timeline
→ Evidence
```

Do not show a 30-box architecture diagram.

## 1:30–4:30 — Live Demo

Perform the complete demo narrative from Section 4.

## 4:30–5:30 — Technical Explanation

Explain:

- trust boundary,
- DNA score,
- mutation tracker,
- evidence claims.

## 5:30–6:00 — Limitations

Explicitly state:

- no physical attacker geolocation,
- heuristic similarity,
- offline enrichment fixtures for reliable demo,
- optional live adapters.

## 6:00–6:30 — Final Line

> "Most tools tell you the email is malicious. TraceDNA shows the campaign behind it, the infrastructure traits the attacker failed to change, and the exact evidence that proves the relationship."

---

# 39. Suggested Future Work

Only mention after MVP:

- calibrated campaign probability model,
- graph neural network or metric learning,
- certificate transparency integration,
- passive DNS,
- STIX/TAXII export,
- SOC integration,
- organisation-specific trust-root learning,
- streaming ingestion,
- distributed workers,
- analyst feedback loop,
- active learning,
- better anomaly detection,
- safe detonation service,
- richer LLM evidence assistant.

Do not implement these prematurely.

---

# 40. Final Priority Order

If development time becomes limited, protect these in this order:

1. **Working raw `.eml` ingestion**
2. **Evidence hashing**
3. **Trust-aware `Received:` analysis**
4. **Infrastructure DNA extraction**
5. **Campaign similarity with explainable contributions**
6. **Seeded historical campaigns**
7. **Unseen-email campaign match**
8. **Mutation timeline**
9. **Evidence/claim view**
10. **Polished frontend**
11. Optional enrichment
12. Optional LLM

The single most important demo outcome is:

> **An unseen email with a different domain and IP is correctly linked to the historical campaign because persistent campaign traits remain, while a forged lower `Received:` header is rejected as untrusted — and the UI shows exactly why.**

That is the prototype TraceDNA should be built around.
