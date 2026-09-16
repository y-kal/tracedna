# TraceDNA — Current Implementation Status

## 1. Executive Summary

TraceDNA is an offline-first FastAPI/SQLite and React prototype that accepts a raw `.eml`, stores a copy, records a SHA-256 hash, parses common mail fields and bodies, applies deterministic phishing/BEC heuristics, scores `Received:` hops against a hard-coded recipient gateway, and compares the parsed email with seeded synthetic campaign members.

The strongest working feature is the deterministic trust-path demonstration: the unseen Alpha mutation is parsed with a trusted first gateway hop, an older lower `Received:` line is downgraded as untrusted, and `203.0.113.77` is selected as the earliest trustworthy observable infrastructure. Raw upload, storage, parsing, triage, campaign matching, claims/evidence generation, and the main UI data path are present.

The prototype is not a complete implementation of the architecture described in the planning documents. Authentication is receiver-observed string matching rather than active SPF/DKIM/DMARC verification; enrichment fixtures are not wired into analysis; the frontend hard-codes some labels and does not display campaign graphs or timelines; and there is no live lookup, report generator, AI layer, attachment execution, or calibrated model.

Prototype completeness: 58%

This is a rough engineering estimate based on the core upload-to-explanation path being present, while substantial planned areas—especially trust validation depth, enrichment, campaign visualization, and active authentication verification—are absent or only represented by UI/specification language.

The main seeded demo flow works at the direct analysis level and the frontend production build succeeds. The repository test suite is not green: 2 tests pass and 1 fails because the expected Alpha URL-grammar match is not produced for the first historical Alpha sample.

## 2. Current Architecture

- Frontend: React 18/TypeScript-style JSX compiled by Vite. The UI is a single component in `frontend/src/main.tsx` with CSS in `frontend/src/style.css`.
- Backend: FastAPI with synchronous SQLite access and one main module, `backend/app/main.py`.
- Storage: SQLite tables `cases` and `campaigns`; uploaded raw evidence is written below `data/evidence/<case-id>/original.eml`.
- Parsing: Python standard-library `email` parsing plus BeautifulSoup for HTML structure/text.
- Analysis: deterministic rule-based triage, a small `Received:` trust heuristic, feature extraction, weighted Jaccard/exact-match similarity, and JSON claims/evidence.
- External APIs: none. The code does not call DNS, RDAP, GeoIP, URL reputation, certificate, LLM, or threat-intelligence services.
- Offline operation: yes for the implemented path. The only network-like frontend dependency is a Google Fonts CSS import; core backend analysis is offline.

Actual pipeline:

```text
.eml upload
   ↓
size/extension check
   ↓
raw file written + SHA-256 recorded
   ↓
email parser: headers, bodies, URLs, attachments, Received hops
   ↓
triage rules + receiver-observed auth string check
   ↓
Received-hop trust heuristic
   ↓
Infrastructure DNA feature extraction
   ↓
max pairwise similarity against seeded campaign members
   ↓
SQLite case JSON + claims/evidence JSON
   ↓
React risk, path, campaign, and claims panels
```

## 3. Repository Structure

| Path | Current role |
|---|---|
| `backend/app/main.py` | FastAPI app, SQLite schema/access, parser, triage, trust path, similarity, claims, campaign routes. |
| `backend/tests/test_core.py` | Three unit-level tests for forged `Received:`, Alpha similarity, and benign urgency. |
| `backend/scripts/seed_demo.py` | Clears the two SQLite tables and seeds Alpha/Beta historical cases plus the benign control. |
| `backend/requirements.txt` | FastAPI, Uvicorn, multipart upload, BeautifulSoup, NetworkX, pytest, httpx. NetworkX is declared but unused in the application. |
| `frontend/src/main.tsx` | Single-page upload, case list, detail panels, and direct `fetch` calls to backend routes. |
| `frontend/src/style.css` | Visual styling and responsive layout. |
| `demo/emails/` | Six synthetic `.eml` files: three Alpha members, one Beta member, one benign control, and an unseen Alpha mutation. |
| `demo/enrichment_fixtures.json` | Two static IP enrichment records. No code path loads this file. |
| `data/tracedna.sqlite3` | Current local database containing seeded demo rows plus a locally stored uploaded email. |
| `data/evidence/` | Current persisted upload evidence directory. |
| `README.md`, `demo/DEMO_SCRIPT.md` | Run/demo documentation; useful context but not proof of additional implementation. |
| `TraceDNA_Prototype_Context.md`, `TraceDNA_Codex_Master_Prompt.md` | Design/master-prompt material, not implementation. |

## 4. End-to-End Analysis Flow

1. **Upload.** `POST /api/cases` accepts one multipart file, requires a filename ending in `.eml`, reads it into memory, and rejects files over 10 MB. There is no MIME/content validation beyond the extension.

2. **Evidence preservation.** The raw bytes are written to `data/evidence/<case-id>/original.eml`. A SHA-256 is stored in the `cases` table. `POST /api/cases/{id}/verify-integrity` re-reads that path and compares the digest. The UI does not call this endpoint; its visible `PASS` is hard-coded.

3. **Parsing.** `parse_eml` uses `BytesParser(policy=policy.default)`. It extracts subject, From, To only indirectly through the full header dictionary, Reply-To, Return-Path, Message-ID, Date, all `Received` values, all `Authentication-Results`, plain text, HTML, URL records, path grammars, query keys, HTML skeleton, Message-ID pattern, and attachment filename/MIME/size/SHA-256. It does not separately parse SPF, DKIM, DMARC, or ARC fields.

4. **Threat scoring.** `triage` adds fixed points for Reply-To mismatch, Return-Path mismatch, the literal substring `dmarc=fail`, credential language, payment language, urgency/secrecy language, and URL paths beginning `/auth`. Score is capped at 100. `credential_request` forces category `credential_phishing`; payment language only becomes `business_email_compromise` at score 45 or above. The unseen Alpha fixture scores 55/MEDIUM/credential_phishing, not HIGH.

5. **Authentication analysis.** The implementation joins `Authentication-Results` strings and only checks whether `dmarc=fail` occurs. SPF/DKIM pass/fail values are not separately extracted, displayed, aligned, or scored. No cryptographic or DNS verification is performed.

6. **Mail path.** `parse_received` uses one IPv4-oriented regular expression. `trust_path` checks the first hop's `by_host` against two hard-coded recipient gateways or the `.recipient.example` suffix, adds fixed trust points for a configured root, a parseable peer IPv4, and a simple prior-host/next-by-host equality. It chooses the first trusted root-side hop as boundary and uses its peer IP/host as `origin`; older unsupported hops are downgraded.

7. **Campaign analysis.** On upload, every seeded campaign is scanned. The maximum email-to-member score is used, and the best campaign is returned only when the score is at least `0.55`. A matched upload is appended to that campaign's JSON member list. No clustering algorithm or learned campaign prototype exists.

8. **Claims/evidence.** The upload path creates evidence records for the raw hash, each triage signal, and each relay hop. It creates a heuristic threat claim, an origin claim when an origin exists, and a campaign-match claim when a campaign is assigned. Evidence links are IDs in the claim object, but campaign similarity feature evidence is not separately materialized.

9. **Frontend display.** The React app fetches case list, case detail, claims, evidence, and relay path. It displays risk, signals, a hard-coded integrity PASS, relay path, origin, campaign name/similarity, hard-coded DNA chips, and claims. It does not fetch or render the campaign graph, campaign timeline, integrity verification result, raw evidence, authentication details, attachment details, or parsed URLs.

## 5. Feature Status Matrix

| Feature | Status | What currently works | Important limitations | Code location |
|---|---|---|---|---|
| Raw `.eml` upload | ✅ IMPLEMENTED | Multipart upload, `.eml` suffix check, 10 MB limit | Extension is trusted; no content/MIME validation | `backend/app/main.py:215-229` |
| Original email preservation | ✅ IMPLEMENTED | Raw bytes saved outside frontend public files | Seeded cases point to demo files; no retention policy | `backend/app/main.py:220-221` |
| SHA-256 hashing | ✅ IMPLEMENTED | Hash stored with case and evidence claim | No hash algorithm/version metadata beyond field name | `backend/app/main.py:30,188,221` |
| Evidence integrity verification | ✅ IMPLEMENTED | Re-hashes saved raw file and returns expected/actual/intact | UI does not call it; only file-path integrity is checked | `backend/app/main.py:253-257` |
| Attachment metadata extraction | ✅ IMPLEMENTED | Filename, MIME, byte size, SHA-256 | No attachment content analysis or UI | `backend/app/main.py:74-78` |
| Attachment SHA-256 | ✅ IMPLEMENTED | Hash computed for decoded attachment bytes | Only stored inside parsed case JSON | `backend/app/main.py:76-78` |
| From / To / Reply-To / Return-Path | ✅ IMPLEMENTED | Core fields extracted; To remains available in raw header map | No normalized recipient model | `backend/app/main.py:80-90` |
| Message-ID / Date | ✅ IMPLEMENTED | Extracted and stored | Date is not parsed into a timestamp for validation | `backend/app/main.py:87-90` |
| Received headers | ✅ IMPLEMENTED | All `Received` values sent through a narrow parser | IPv4-focused regex; malformed/IPv6 cases lose structure | `backend/app/main.py:52-62,93` |
| Authentication-Results | ✅ IMPLEMENTED | Raw values collected | Not parsed into a structured SPF/DKIM/DMARC result | `backend/app/main.py:94` |
| Received-SPF / DKIM-Signature / ARC headers | 🟡 PARTIALLY IMPLEMENTED | They remain in the generic email headers | No dedicated parsing or downstream use | `backend/app/main.py:101` |
| Plain-text / HTML body | ✅ IMPLEMENTED | Both body forms collected | No body normalization beyond simple tokenization | `backend/app/main.py:67-79` |
| URL extraction | ✅ IMPLEMENTED | HTTP(S) URLs and host/path/query keys extracted | No URL fetch, reputation, domain registration, or safe canonicalization | `backend/app/main.py:40-50` |
| Overall risk score | ✅ IMPLEMENTED | Fixed-point score capped at 100 | Heuristic, not calibrated | `backend/app/main.py:108-129` |
| Risk contribution breakdown | ✅ IMPLEMENTED | Signal names, points, and details returned/displayed | Only active rules appear; no negative/contradicting factors | `backend/app/main.py:111-124` |
| Credential-phishing detection | ✅ IMPLEMENTED | Keyword/form-language heuristics and `/auth` URL rule | Broad keyword matching; no classifier or URL inspection | `backend/app/main.py:116-128` |
| BEC/payment-diversion detection | 🟡 PARTIALLY IMPLEMENTED | Payment words can produce BEC category at score ≥45 | No sender impersonation/business-context model; fixture benign payment language stays clean/low | `backend/app/main.py:117-128` |
| Urgency/secrecy detection | ✅ IMPLEMENTED | Fixed six-point keyword rule | Generic terms can create false positives | `backend/app/main.py:123` |
| Reply-To mismatch | ✅ IMPLEMENTED | Compares registrable-ish last two domain labels | Simplistic domain extraction; no alignment policy | `backend/app/main.py:26-29,112` |
| Return-Path mismatch | ✅ IMPLEMENTED | Same comparison against visible sender domain | No address normalization beyond string/domain split | `backend/app/main.py:113` |
| Lookalike-domain detection | ❌ NOT IMPLEMENTED | None | No edit distance, brand list, IDN, or lookalike rule | No implementation found |
| Suspicious URL analysis | 🟡 PARTIALLY IMPLEMENTED | `/auth` path prefix contributes 10 points; grammar extracted | No domain reputation, redirect, certificate, or safe browsing lookup | `backend/app/main.py:49,124` |
| SPF parsing / scoring / live verification | ❌ NOT IMPLEMENTED | Raw auth text is retained; no SPF-specific behavior | See dedicated SPF section | `backend/app/main.py:94,119` |
| DKIM parsing / scoring / cryptographic verification | ❌ NOT IMPLEMENTED | Generic header retention only | No signature verification or key lookup | `backend/app/main.py:101` |
| DMARC parsing | 🟡 PARTIALLY IMPLEMENTED | Literal `dmarc=fail` search in Authentication-Results | No structured result, policy, or alignment parse | `backend/app/main.py:118-120` |
| DMARC scoring/use | ✅ IMPLEMENTED | Literal fail adds 18 points | Only fail substring is used; pass/none/alignment absent | `backend/app/main.py:119-120` |
| DMARC alignment | ❌ NOT IMPLEMENTED | None | No SPF/DKIM identifier alignment | No implementation found |
| ARC support | ❌ NOT IMPLEMENTED | None beyond generic header retention | ARC chain is neither parsed nor used | No implementation found |
| Received parsing | ✅ IMPLEMENTED | Basic `from (...) by ...; timestamp` records | No robust RFC grammar | `backend/app/main.py:52-62` |
| Trusted root configuration | ✅ IMPLEMENTED | Two hard-coded gateways plus suffix rule | Not externalized/configurable at runtime | `backend/app/main.py:32,133` |
| Trusted boundary detection | ✅ IMPLEMENTED | First root-side hop is marked boundary | Boundary is simplistic and often first hop by construction | `backend/app/main.py:151-156` |
| Continuity checking | ✅ IMPLEMENTED | Compares previous `from_host` to current `by_host` | Does not validate all hop directions or timestamps | `backend/app/main.py:142-146` |
| Timestamp plausibility | ❌ NOT IMPLEMENTED | Timestamp text is retained | No parsing or ordering check | `backend/app/main.py:62,93` |
| Hostname/IP consistency | 🟡 PARTIALLY IMPLEMENTED | IPv4 can be extracted from parentheses/leading token | No DNS resolution or hostname verification | `backend/app/main.py:57-60` |
| Reverse-DNS / public-private IP logic | ❌ NOT IMPLEMENTED | None | No reverse lookup or `ipaddress` use in execution | `backend/app/main.py` imports are unused |
| Hop trust score/band | ✅ IMPLEMENTED | Fixed scores and TRUSTED/UNCERTAIN/UNTRUSTED bands | Scores are not calibrated and omit many signals | `backend/app/main.py:136-150` |
| Earliest trustworthy infrastructure | ✅ IMPLEMENTED | Boundary peer IP/host exposed as `origin` | “Earliest” means earliest observable after the hard-coded boundary, not physical origin | `backend/app/main.py:154-156` |
| Forged/untrusted hop rejection | 🟡 PARTIALLY IMPLEMENTED | Older continuity-break hop gets UNTRUSTED | It is retained and labelled; no cryptographic proof/rejection of header authenticity | `backend/app/main.py:147-150` |
| Counterfactual simulator | ❌ NOT IMPLEMENTED | None | No route or simulation logic | No implementation found |
| IP extraction | ✅ IMPLEMENTED | IPv4 extraction from `Received` text | IPv6 and broader RFC cases absent | `backend/app/main.py:57-60` |
| ASN/provider/country/city enrichment | ❌ NOT IMPLEMENTED | Fixture file exists | No loader or API call; values never reach analysis/UI | `demo/enrichment_fixtures.json` only |
| RDAP / DNS / reverse DNS / GeoIP | ❌ NOT IMPLEMENTED | None | No live adapters | No implementation found |
| Fixture/mock enrichment | 🟠 PRESENT BUT NOT REALLY WIRED / MOCKED | Static JSON contains two records | Not loaded by backend | `demo/enrichment_fixtures.json` |
| Network DNA | 🟡 PARTIALLY IMPLEMENTED | Exact origin equality is one weighted network group | No ASN/provider/network enrichment | `backend/app/main.py:164-171` |
| Domain DNA | 🟡 PARTIALLY IMPLEMENTED | From/Reply-To domain set Jaccard | No lookalike or domain-history features | `backend/app/main.py:166` |
| URL grammar/query normalization | ✅ IMPLEMENTED | Lowercase path, digit and long-hex substitutions; query-key sets | Normalization is weak: short alphanumeric tokens do not normalize, causing the failing test | `backend/app/main.py:40-50` |
| HTML skeleton | ✅ IMPLEMENTED | Tag-name sequence after removing text | Simple structural string, not a robust DOM fingerprint | `backend/app/main.py:51-55` |
| Message-ID pattern | ✅ IMPLEMENTED | Digits/long hex/local host digit substitutions | Heuristic regex can over/under-normalize | `backend/app/main.py:33-38` |
| Reply-To / Return-Path pattern | 🟡 PARTIALLY IMPLEMENTED | Domains participate in similarity | No independent address-pattern feature | `backend/app/main.py:166,168` |
| Mail-header fingerprint | ❌ NOT IMPLEMENTED | Generic headers are stored | No fingerprint is computed; header serialization has a bug that iterates strings character-by-character | `backend/app/main.py:101` |
| Content similarity | 🟡 PARTIALLY IMPLEMENTED | Body-token Jaccard plus exact HTML skeleton | Plain-text token similarity is empty for HTML-only fixtures; no TF-IDF or embeddings | `backend/app/main.py:169` |
| TF-IDF / embeddings | ❌ NOT IMPLEMENTED | None | No vector model or sklearn usage | No implementation found |
| Temporal similarity | 🟠 PRESENT BUT NOT REALLY WIRED / MOCKED | Constant `0.6` value contributes 0.06 | It does not inspect dates or temporal distance | `backend/app/main.py:170` |
| Certificate fingerprinting / domain-IP rotation | ❌ NOT IMPLEMENTED | UI says domain/source IP rotated based on hard-coded display | No certificates, DNS history, or rotation detector | `frontend/src/main.tsx:12`; `backend/app/main.py:178,273` |
| Pairwise / weighted DNA similarity | ✅ IMPLEMENTED | Six groups, exact high-signal bonuses, weighted total | Deterministic heuristic with fixed constant temporal component | `backend/app/main.py:163-178` |
| Similarity breakdown | ✅ IMPLEMENTED | Groups/contributions/conflicts returned by similarity | Frontend does not render the backend breakdown | `backend/app/main.py:172-178` |
| High-signal bonuses | ✅ IMPLEMENTED | +0.08 Message-ID, +0.05 URL grammar; HTML is match-only | Bonuses are not separately represented as evidence objects | `backend/app/main.py:173-178` |
| Campaign bands / assignment | ✅ IMPLEMENTED | HIGH ≥.75, REVIEW ≥.55, LOW otherwise; campaign threshold .55 | Max-member score only; no margin or conservative second-best check | `backend/app/main.py:177,200-207` |
| Campaign clustering | ❌ NOT IMPLEMENTED | None | NetworkX is unused | `backend/requirements.txt` |
| Historical matching / no-match behavior | ✅ IMPLEMENTED | Seeded campaigns scanned; no match below .55 | Stored match can be stale; matching after upload can include the newly appended case | `backend/app/main.py:200-207,222-228` |
| Campaign graph | 🟡 PARTIALLY IMPLEMENTED | API returns a star graph from campaign to member emails | Frontend never fetches/renders it; no email-to-email weighted graph | `backend/app/main.py:263-267` |
| Mutation timeline | 🟡 PARTIALLY IMPLEMENTED | API compares adjacent members for changed/persisted labels | Frontend never fetches/renders it; no evidence links | `backend/app/main.py:269-275` |
| Persistent-vs-rotated traits | ✅ IMPLEMENTED | Adjacent domain/origin changes and three persisted pattern comparisons | Only a small set of fields; UI chips are hard-coded | `backend/app/main.py:273-274`, `frontend/src/main.tsx:12` |
| Campaign prototype/fingerprint | ❌ NOT IMPLEMENTED | None | No aggregate prototype object | No implementation found |
| Evidence IDs / claim objects | ✅ IMPLEMENTED | UUID-like IDs and claim JSON | IDs are generated only on upload; seeded cases have no claims/evidence | `backend/app/main.py:184-195` |
| Claim → evidence links | ✅ IMPLEMENTED | Supporting ID arrays returned/displayed | Campaign claim points to general triage evidence, not feature-specific similarity evidence | `backend/app/main.py:191-194` |
| Contradicting evidence | 🟡 PARTIALLY IMPLEMENTED | Empty arrays are present | No contradicting evidence is generated | `backend/app/main.py:191-194` |
| Confidence score/band | ✅ IMPLEMENTED | Threat score-derived, fixed origin `.82`, similarity-derived campaign confidence | Heuristic labels are not calibrated probabilities | `backend/app/main.py:191-194` |
| Evidence drawer/UI | 🟡 PARTIALLY IMPLEMENTED | HTML `<details>` claims panel shows IDs | Evidence objects themselves are fetched but unused in rendering | `frontend/src/main.tsx:7-12` |
| Report generation | ❌ NOT IMPLEMENTED | None | No export/report route or UI | No implementation found |
| Upload UI / case list / risk card / why-flagged | ✅ IMPLEMENTED | Working React controls and fetches | Error handling is minimal | `frontend/src/main.tsx:8-12` |
| Authentication panel | ❌ NOT IMPLEMENTED | Authentication can influence score invisibly | No SPF/DKIM/DMARC panel | No implementation found |
| Trust-aware path UI | ✅ IMPLEMENTED | Renders returned hops, bands, reasons, boundary, origin | Does not explain all missing signals | `frontend/src/main.tsx:12` |
| Campaign DNA UI | 🟡 PARTIALLY IMPLEMENTED | Campaign name, similarity, text, chips | Chips are static and shown independent of backend match details | `frontend/src/main.tsx:12` |
| Demo reset/load | 🟡 PARTIALLY IMPLEMENTED | Manual seed script documented | No UI reset/load button | `backend/scripts/seed_demo.py`, `frontend/src/main.tsx` |
| Optional AI / deterministic fallback | 🟠 PRESENT BUT NOT REALLY WIRED / MOCKED | Deterministic core exists | No LLM or AI explanation layer exists | No implementation found |

## 6. SPF / DKIM / DMARC — Exact Current State

## SPF

```text
Parsing: No SPF-specific parsing. Authentication-Results strings are retained as raw strings.
Displayed: No. The frontend has no authentication panel.
Used in scoring: No. `spf=...` does not affect triage.
Alignment checked: No.
Live verification: No DNS or SPF evaluator is called.
Implementation file(s): backend/app/main.py, parse_eml and triage.
Current limitations: A receiver-observed SPF result, including Received-SPF, is not structured or independently verified.
```

## DKIM

```text
Parsing: No. DKIM-Signature is only retained in the generic header map.
Displayed: No.
Used in scoring: No.
Cryptographic verification: No.
Implementation file(s): backend/app/main.py, generic header collection in parse_eml.
Current limitations: No signature canonicalization, body hash check, public-key lookup, or result/alignment model.
```

## DMARC

```text
Parsing: Partial only. The code searches the joined Authentication-Results text for the literal substring `dmarc=fail`.
Displayed: Not as an authentication result; its effect appears only as a Why flagged signal.
Used in scoring: Yes. Literal `dmarc=fail` adds 18 points.
Alignment checked: No.
Implementation file(s): backend/app/main.py, triage.
Current limitations: No policy parsing, pass/none handling, SPF/DKIM identifier alignment, or independent verification.
```

## ARC

```text
Parsing: No dedicated ARC parsing.
Used: No.
Implementation file(s): None; generic email headers are retained by parse_eml.
Current limitations: ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results do not influence trust or risk.
```

## 7. Trust-Aware Mail Path — Exact Algorithm

The actual algorithm is:

```text
1. Parse each Received value with one regex into from_host, from_ip, by_host, and timestamp text.
2. Treat the first parsed hop as root-side trusted when its by_host is one of two hard-coded gateways or ends with `.recipient.example`.
3. For hop 0, add 50 for a configured root and 20 for a parseable peer IPv4.
4. For later hops, add 35 when the previous hop's from_host equals this hop's by_host; otherwise add CONTINUITY_BREAK.
5. If an older hop is reached after a configured root and its score is below 40, add OLDER_THAN_TRUST_BOUNDARY and SENDER_SUPPLIED_OR_UNSUPPORTED and set score to 20.
6. Classify score ≥70 as TRUSTED, ≥40 as UNCERTAIN, otherwise UNTRUSTED.
7. Mark the first selected root-side hop as the boundary and expose its peer IP or host as origin.
```

| Signal | Implemented? | How it affects trust |
|---|---|---|
| Configured trusted root | Yes | +50 on hop 0 when `by_host` matches hard-coded gateway rules. |
| Parseable peer IP | Yes, IPv4 only | +20 in the code's eligible hops. |
| Hostname consistency | Partial | Host text is compared for continuity; no DNS consistency check. |
| Next-hop continuity | Yes, narrow | Prior `from_host == current by_host` adds 35. |
| Timestamp ordering | No | Timestamp is only stored as text. |
| Reverse DNS | No | No lookup. |
| Private/public address logic | No | No address classification. |
| Authentication relation | No | SPF/DKIM/DMARC does not alter hop trust. |
| Malformed header handling | Partial | Non-matching headers become records with null fields; they are not rejected or richly diagnosed. |

### What does `TRUSTED · BOUNDARY` mean in the current code?

It means the hop is the first parsed `Received` entry whose receiving host matches the configured recipient gateway rule. In the common fixture it also has a parseable peer IPv4 and therefore scores 70. It does not mean the header is cryptographically authentic or that the sending host is proven trustworthy.

### What causes `CONTINUITY_BREAK`?

For a hop after index 0, either the previous hop has no `from_host`, the current hop has no `by_host`, or the two strings differ case-insensitively.

### What causes `TRUST_ROOT_NOT_CONFIGURED`?

The first parsed hop exists but its `by_host` is neither one of `recipient-gateway.example` / `mx.recipient.example` nor a host ending in `.recipient.example`.

### Can the current implementation detect a deliberately forged lower `Received:` header?

It can mark a lower header unsupported/untrusted when the parsed chain produces a continuity break below a configured root. The unseen Alpha fixture demonstrates this with `1.2.3.4` and `forged.example`. It cannot prove that the header was deliberately forged.

### Does it prove a hop is forged, or only mark it unsupported/untrusted?

Only the latter. The code retains the header and labels it `UNTRUSTED`; it does not authenticate header insertion or reject the raw bytes.

### Does the system ever call an IP the physical attacker location?

No. It calls the selected value the “earliest trustworthy observable external infrastructure.” No geolocation is executed and no physical-person attribution is implemented.

## 8. Infrastructure DNA — Exact Algorithm

In current code, “Infrastructure DNA” means six deterministic similarity groups:

```text
network  = Jaccard({origin})
domain   = Jaccard({from_domain, reply_to_domain})
web      = 0.65 * Jaccard(url_grammars) + 0.35 * Jaccard(query_keys)
mail     = 0.55 * exact(message_pattern) + 0.45 * Jaccard(reply_to_domain)
content  = 0.55 * Jaccard(body_text_tokens) + 0.45 * exact(html_skeleton)
temporal = constant 0.6
```

Weights are exactly:

```text
network=.12, domain=.12, web=.22, mail=.22, content=.22, temporal=.10
```

The weighted group values are summed and capped at 1.0. Exact high-signal bonuses are `+0.08` for equal Message-ID pattern and `+0.05` when any URL path grammar intersects. Bands are `HIGH` at ≥0.75, `REVIEW` at ≥0.55, and `LOW` below 0.55.

- URL grammar: URL paths are lowercased; digit runs become `<DIGITS>` and hexadecimal-looking runs of at least eight characters become `<HEX>`. Query keys are sorted and de-duplicated. Short alphanumeric tokens such as `abc123` are not normalized as one token, which is why `alpha_01` versus the unseen mutation has no URL high-signal match and causes the failing test.
- HTML skeleton: BeautifulSoup text nodes are blanked and remaining tag names are joined with `>`; `html`, `head`, `meta`, and `title` are omitted.
- Message-ID pattern: local-part digit runs and hex runs of at least six characters are replaced; digits in the host are replaced.
- Text/content: only token-set Jaccard over `body_text` plus exact HTML skeleton. HTML-only samples get no useful plain-text token score.
- TF-IDF: not used.
- Embeddings: not used.
- Changed domains/IPs: domain and `origin` mismatches are added to `conflicts`; they are not automatically fatal. They reduce the relevant Jaccard group, while persistent structural features can keep the score high.

The UI badges do not come from individual backend badge conditions. The frontend always renders `✓ URL grammar`, `✓ HTML skeleton`, `✓ Message-ID pattern`, `✕ domain rotated`, and `✕ source IP rotated` for every selected case, whether the corresponding backend comparison supports them or not.

## 9. Campaign Matching — Exact Current Behaviour

Historical comparison iterates every row in `campaigns`, computes similarity against each stored member, keeps each campaign's maximum member score, selects the globally highest campaign, and returns no match unless that score is at least `0.55`. There is no margin against the second-best campaign, clustering, graph-based assignment, or statistical calibration. A matched uploaded case is appended to the selected campaign.

The seeded script creates three Alpha historical samples, one Beta sample, and one benign control. The unseen mutation is deliberately excluded from seeding.

| Test email | Expected | Actual direct analysis | Similarity / result |
|---|---|---|---:|
| `alpha_01.eml` | Alpha historical sample | Seeded as Alpha member | Not a new match test |
| `alpha_02.eml` | Alpha historical sample | Seeded as Alpha member | Not a new match test |
| `alpha_03.eml` | Alpha historical sample | Seeded as Alpha member | Not a new match test |
| `unseen_alpha_mutation.eml` vs Alpha 01 | Alpha, high | HIGH | 0.777; Message-ID and HTML matches, source IP conflict; URL grammar does not match because short `abc123` is not normalized |
| `unseen_alpha_mutation.eml` vs Alpha 02 | Alpha, high | HIGH | 0.777; Message-ID and HTML matches, source IP conflict |
| `unseen_alpha_mutation.eml` vs Alpha 03 | Alpha, high | HIGH | 0.970; Message-ID, URL grammar, and HTML matches; source IP conflict |
| `unseen_alpha_mutation.eml` vs Beta | No Beta match | LOW | 0.258 |
| `benign_urgent_invoice.eml` | Benign control | LOW / `clean_or_low_risk`, score 24 | It has no campaign match against the seeded data |

The repository's own tests report `2 passed, 1 failed`: the failing assertion expects `url_path_grammar` for the Alpha mutation versus Alpha 01, but the current normalizer returns only `message_id_pattern` and `html_skeleton` for that pair. The unseen mutation still clears the campaign threshold because Alpha 03 scores 0.97.

The campaign API exposes a simple star graph (campaign node connected to member email nodes) and an adjacent-member mutation timeline. The React UI does not call either API, so the documented mutation-demo view is not actually visible in the current frontend.

## 10. Current UI — What Each Visible Section Actually Means

- **Risk level / risk score:** fixed keyword-rule output. The score is not a probability and is labelled heuristic in the UI.
- **Why flagged:** only the positive triage rules that fired, with fixed points.
- **Evidence integrity:** a hard-coded `PASS` label saying SHA-256 was preserved. It is not the result of calling `/verify-integrity`.
- **Trust-aware mail path:** the parsed `Received` records and backend trust bands/reason codes.
- **Trusted boundary:** the first root-side hop selected by the hard-coded gateway rule, not an authenticated boundary.
- **Untrusted hop:** a hop whose current heuristic score is below 40, often due to continuity break; not a proven forgery.
- **Earliest trustworthy observable infrastructure:** the boundary hop's peer IP or hostname, not a physical attacker location.
- **Campaign DNA:** stored campaign assignment and similarity claim when present, plus static explanatory text.
- **No confident historical match:** rendered when the stored case has no campaign assignment; backend uses a 0.55 threshold.
- **URL grammar / HTML skeleton / Message-ID pattern badges:** static frontend chips; they are not conditionally populated from the similarity breakdown.
- **Domain rotated / source IP rotated:** static changed chips; backend does compare these fields in timeline/conflicts, but the current selected-case chips do not reflect result-specific conditions.
- **Claims → evidence:** expandable claim objects with heuristic confidence and supporting/contradicting ID lists. Evidence objects are fetched into state but not rendered as a detailed drawer.
- **Heuristic evidence confidence:** a string label in generated claims, not a calibrated confidence model.

## 11. Demo Data vs Real Analysis

| Capability | Real parsed data | Offline fixture/mock | Live external lookup |
|---|---:|---:|---:|
| Email headers | Yes | Synthetic `.eml` inputs | No |
| SPF | Raw Authentication-Results text only | Synthetic values in demo headers | No |
| DKIM | Generic header retention only | Real-looking header may exist in stored uploaded email, but unused | No |
| DMARC | Literal `dmarc=fail` search | Synthetic demo header values | No |
| IP | IPv4 text from Received headers | Reserved documentation IPs | No |
| ASN/provider | No | JSON fixture exists but is not loaded | No |
| Geolocation | No | JSON fixture exists but is not loaded | No |
| Domain data | Basic domain string extraction | `.example` synthetic domains | No DNS/RDAP |
| Campaign data | SQLite comparison logic | Seeded Alpha/Beta JSON members | No |
| Certificates | No | No fixture | No |
| Threat intelligence | No | No fixture used | No |

The project is safe to describe as offline-first for its actual implemented analysis. It is not accurate to describe the current enrichment fixture as live infrastructure intelligence.

## 12. Tests and Validation

The backend test command is `./.venv/bin/pytest -q` (equivalent to the documented `pytest -q` when the virtual environment is active). Current result:

```text
1 failed, 2 passed
```

Passing coverage:

- forged lower `Received:` header is not selected as origin and is marked UNTRUSTED;
- benign urgent invoice remains below score 60.

Failing coverage:

- Alpha trait test expects URL grammar match for the unseen mutation against `alpha_01`; actual score is 0.777 but `url_path_grammar` is absent because `/auth/session/abc123` and `/auth/session/112233` normalize differently.

`npm run build` in `frontend` passes with Vite. No browser-level or backend HTTP end-to-end test is present. There is no test that exercises upload → evidence write → API response → frontend rendering. There is no end-to-end assertion for the complete requested sequence:

```text
upload unseen Alpha
→ reject forged/untrusted header
→ identify trust boundary
→ match Campaign Alpha
→ produce claims/evidence
```

The direct Python analysis path demonstrates the first four concepts, but the repository does not test them through the HTTP/UI path.

## 13. What Is Safe to Claim to Hackathon Judges

## Fully Safe Claims

- **Offline raw-email triage:** TraceDNA accepts `.eml` files and deterministically flags selected credential/payment/urgency signals.
- **Evidence preservation:** The upload path stores original bytes and records a SHA-256 that can be rechecked by an API endpoint.
- **Trust-aware observable path:** The prototype applies a configured recipient-gateway boundary and can downgrade an older continuity-breaking `Received` line.
- **Explainable heuristic similarity:** Campaign scoring exposes weighted feature groups, conflicts, bands, and high-signal matches in backend JSON.
- **Synthetic mutation demo:** The unseen Alpha mutation matches seeded Alpha more strongly than Beta and retains HTML/Message-ID traits despite origin conflict.
- **Claims with evidence IDs:** Uploaded cases receive threat, origin, and optional campaign claims linked to generated evidence IDs.

## Claims That Need Careful Wording

- Do not say “we found the attacker.” Say “we identified the earliest trustworthy observable infrastructure represented by the parsed headers.”
- Do not say “we verified SPF/DKIM/DMARC.” Say “we retain receiver-observed authentication text and use a literal DMARC-fail heuristic.”
- Do not say “the system proved a forged header.” Say “the system marked a lower hop unsupported/untrusted because it broke the configured continuity heuristic.”
- Do not say “AI found the campaign.” Say “a deterministic weighted heuristic matched the email to seeded synthetic campaign data.”
- Do not say “live threat intelligence.” Say “offline synthetic demo data; no live enrichment is wired.”
- Do not present the static DNA chips as per-email measured results.

## Claims We Should NOT Make Yet

- Physical attacker attribution or attacker geolocation.
- Live SPF, DKIM, DMARC, ARC validation.
- DNS/RDAP/GeoIP/ASN/provider or certificate intelligence.
- A complete campaign graph/mutation timeline in the current visible UI.
- Calibrated probabilities, enterprise-scale performance, or production forensic reliability.
- “No existing tool does this.”
- An implemented counterfactual simulator.

## 14. Biggest Gaps Before Demo

1. **Problem:** The visible integrity PASS is not connected to the verification route.
   - **Why it matters:** Judges can reasonably ask whether the displayed result was actually checked.
   - **Estimated effort:** Small.
   - **Recommended action:** Call `/verify-integrity`, display its result, and add a tamper test.

2. **Problem:** Authentication is mostly absent and no authentication panel exists.
   - **Why it matters:** SPF/DKIM/DMARC are likely judge questions, and the UI currently cannot distinguish receiver-observed text from verification.
   - **Estimated effort:** Medium for structured parsing/display; large for cryptographic verification.
   - **Recommended action:** At minimum parse and display SPF/DKIM/DMARC/ARC observations with an explicit “not independently verified” label.

3. **Problem:** DNA badges are hard-coded and the Alpha URL grammar test fails.
   - **Why it matters:** The strongest campaign story is not fully backed by per-case UI or green tests.
   - **Estimated effort:** Small to medium.
   - **Recommended action:** Return feature-match booleans from the backend, render them conditionally, and normalize short dynamic URL tokens consistently.

4. **Problem:** Campaign graph and mutation timeline APIs are not surfaced in the frontend.
   - **Why it matters:** The documented demo promises a mutation timeline/graph that a judge cannot see.
   - **Estimated effort:** Medium.
   - **Recommended action:** Render the existing timeline first; add the graph only if time permits.

5. **Problem:** Enrichment fixture and evidence detail are not wired.
   - **Why it matters:** The prototype can be mistaken for live intelligence, while claims do not expose feature-level similarity evidence.
   - **Estimated effort:** Medium.
   - **Recommended action:** Either remove/label the fixture clearly or load it into a visibly marked offline-enrichment panel; add evidence records for similarity features.

## 15. Recommended Final Feature List

- Raw `.eml` evidence capture — Stores the original upload and records a SHA-256 digest.
- Deterministic phishing/BEC triage — Scores selected credential, payment, authentication-URL, mismatch, and urgency signals.
- Trust-aware `Received:` path — Uses a configured gateway boundary and continuity heuristic to label hops.
- Earliest trustworthy observable infrastructure — Reports the boundary peer IP/host without claiming physical attribution.
- Explainable Infrastructure DNA — Compares origin, domains, URL paths/query keys, mail patterns, HTML skeleton, content, and a weak temporal component.
- Historical campaign matching — Assigns a seeded campaign when the maximum heuristic score reaches the review threshold.
- Mutation comparison API — Reports selected changed and persisted traits between adjacent campaign members.
- Claims and evidence IDs — Links generated threat/origin/campaign claims to stored hash, triage, and header-trust evidence records.
- Offline demo operation — Core backend analysis requires no external intelligence or AI service.

## 16. Recommended 60-Second Explanation

“TraceDNA starts with the raw email, preserves the original bytes, and records a hash so the evidence can be checked later. It parses the sender, reply path, URLs, body structure, and `Received` headers. A transparent ruleset explains why the message is suspicious. For the mail path, it treats our configured recipient gateway as the trusted observation boundary and downgrades older headers that break continuity, so we report the earliest trustworthy infrastructure we can observe rather than claiming to locate an attacker. We then compare persistent traits—such as HTML structure, Message-ID shape, and URL path grammar—with seeded historical messages. In the demo, a new Alpha mutation changes its domain and IP but still matches the Alpha campaign more strongly than Beta. The result is returned as heuristic claims linked to inspectable evidence IDs.”

## 17. Recommended 3-Minute Technical Explanation

1. **Ingestion:** FastAPI accepts an `.eml`, limits size, writes the raw bytes under a case directory, and stores the SHA-256 and analysis JSON in SQLite.
2. **Risk/authentication:** The standard email parser extracts fields and bodies. Fixed rules score Reply-To/Return-Path mismatch, receiver-observed `dmarc=fail`, credential/payment/urgency language, and `/auth` URLs. SPF and DKIM are not actively verified; the current implementation must be described as receiver-observed heuristic analysis.
3. **Trust-aware path:** Each `Received` line is parsed into sender host/IP, receiving host, and timestamp text. The first hop is trusted only when its receiving host matches the hard-coded recipient gateway rule. Subsequent continuity is checked with a simple host equality test. A continuity-breaking older hop is labelled unsupported/untrusted, and the selected boundary peer becomes the earliest trustworthy observable infrastructure.
4. **Infrastructure DNA:** Similarity is a weighted sum of network, domain, web, mail, content, and constant temporal groups. URL grammar, HTML skeleton, and Message-ID patterns are normalized heuristically; exact Message-ID and URL matches receive small bonuses. The result is HIGH/REVIEW/LOW, not a probability.
5. **Campaign matching:** Seeded Alpha and Beta members are compared pairwise. The maximum member score per campaign is used, and assignment requires at least 0.55. The unseen Alpha mutation reaches 0.97 against Alpha 03 and 0.258 against Beta.
6. **Explainability:** Uploaded cases receive evidence records for the raw hash, triage signals, and relay hops. Claims carry supporting evidence IDs and heuristic confidence labels. The current UI renders the claims and path, but not the existing campaign graph/timeline APIs or detailed evidence objects.

## 18. Current Limitations

- Risk and similarity scores are hand-authored heuristics, not calibrated probabilities.
- SPF, DKIM, DMARC alignment, ARC, and cryptographic re-verification are absent.
- The trust engine depends on a hard-coded trusted root and narrow IPv4/hostname parsing.
- Timestamp plausibility, reverse DNS, public/private IP logic, DNS, RDAP, ASN, provider, GeoIP, and certificate data are absent.
- The enrichment JSON is unused offline fixture material, not a live lookup.
- The campaign dataset is synthetic and very small.
- URL normalization is inconsistent for short alphanumeric tokens; one repository test currently fails.
- Similarity temporal evidence is a constant, not a date-derived feature.
- Campaign assignment uses a maximum pairwise score without margin, clustering, or a campaign prototype.
- Campaign graph and timeline are API-only and absent from the visible UI.
- Evidence integrity is exposed as a hard-coded UI PASS rather than a verification result.
- Claims do not contain feature-level similarity evidence, and contradicting evidence arrays are always empty.
- No attachment content analysis, report export, counterfactual simulator, AI investigator, or live threat-intelligence integration exists.
- There is no browser/e2e validation of the complete demo flow.

## 19. Final Engineering Verdict

```text
Current prototype readiness: 6/10
Hackathon demo readiness: 6/10
Technical defensibility: 5/10
Implementation completeness: 5/10
```

### What is the single strongest feature currently implemented?

The deterministic trust-boundary demonstration: the code can retain the raw path, mark the lower continuity-breaking fixture hop UNTRUSTED, and report a boundary-derived observable infrastructure value with reason codes.

### What is the single weakest point judges may attack?

The gap between presentation language and implemented authentication/enrichment: SPF/DKIM/DMARC are not actively verified, and the apparent infrastructure-intelligence layer is not wired to the enrichment fixture or live services.

### What one change would most improve the project before judging?

Wire the visible demo to backend-derived results: real integrity verification, structured authentication observations, and conditional DNA badges/timeline. This would make the existing core evidence demonstrably consistent end to end without requiring a new intelligence service.

## 20. Evidence Appendix

Feature: raw upload and evidence preservation

Files:

- `backend/app/main.py:215-229`

Important functions/classes:

- `upload`
- `sha`
- SQLite `cases` table creation in `db`

Feature: parsing and attachment hashing

Files:

- `backend/app/main.py:33-101`

Important functions/classes:

- `url_features`
- `message_pattern`
- `html_skeleton`
- `parse_received`
- `parse_eml`

Feature: triage/risk scoring

Files:

- `backend/app/main.py:108-129`

Important functions/classes:

- `triage`

Feature: trust-aware mail path

Files:

- `backend/app/main.py:32,52-62,131-157`
- `backend/tests/test_core.py:8-11`

Important functions/classes:

- `TRUSTED_GATEWAYS`
- `parse_received`
- `trust_path`

Feature: Infrastructure DNA similarity

Files:

- `backend/app/main.py:159-178`
- `backend/tests/test_core.py:13-18`

Important functions/classes:

- `jaccard`
- `similarity`
- `DNA_WEIGHTS`

Feature: campaigns and mutation timeline

Files:

- `backend/app/main.py:200-207,258-275`
- `backend/scripts/seed_demo.py:7-19`
- `demo/emails/alpha_01.eml`
- `demo/emails/alpha_02.eml`
- `demo/emails/alpha_03.eml`
- `demo/emails/unseen_alpha_mutation.eml`

Important functions/classes:

- `match_campaign`
- `campaign`
- `graph`
- `timeline`
- `seed`

Feature: claims and evidence

Files:

- `backend/app/main.py:184-195,246-257`
- `frontend/src/main.tsx:7-12`

Important functions/classes:

- `evidence_claims`
- `claims`
- `evidence`
- `verify`

Feature: frontend display

Files:

- `frontend/src/main.tsx:5-14`
- `frontend/src/style.css`

Important functions/classes:

- `App`
- `Panel`
- direct `fetch` calls for cases, claims, evidence, and relay path

Feature: offline synthetic enrichment material

Files:

- `demo/enrichment_fixtures.json`
- `README.md:42`

Important functions/classes:

- No loader or enrichment function exists; the file is not wired into `backend/app/main.py`.

Feature: validation

Files:

- `backend/tests/test_core.py`
- `frontend/package.json`

Important functions/classes:

- `test_forged_received_header_is_not_origin`
- `test_alpha_traits_match_and_domain_ip_can_rotate`
- `test_benign_urgency_is_not_severe`
- Vite `build` script

