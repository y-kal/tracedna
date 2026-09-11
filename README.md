# TraceDNA

TraceDNA is an offline-first email investigation prototype. It preserves and hashes raw `.eml` evidence, performs transparent BEC/phishing triage, reconstructs a trust-aware mail path, extracts Infrastructure DNA, and explains historical campaign matches through claims and evidence.

The demo uses only synthetic `.example` domains and reserved documentation IP ranges. Infrastructure location is not attacker location; campaign similarity is an evidence-based heuristic, not proof of the same human attacker.

## Run locally

Prerequisite: Python 3.12+, Node 18+.

```bash
python -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
python backend/scripts/seed_demo.py
uvicorn app.main:app --app-dir backend --reload
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL and upload `demo/emails/unseen_alpha_mutation.eml`.

## Demo flow

The seeded Alpha emails rotate domains and source IPs but retain URL grammar, HTML skeleton, Message-ID structure, and Reply-To pattern. The unseen mutation also contains an older forged `Received:` line. TraceDNA should identify the configured recipient gateway, mark the forged hop untrusted, and show a high Alpha similarity with changed and persistent traits.

Reset and reseed with `python backend/scripts/seed_demo.py`.

## API and tests

Core routes include `/api/health`, `/api/cases`, `/api/cases/{id}/relay-path`, `/api/cases/{id}/dna`, `/api/cases/{id}/claims`, `/api/cases/{id}/evidence`, `/api/cases/{id}/verify-integrity`, and campaign detail/graph routes.

```bash
pytest -q
```

The enrichment fixture is deterministic and no live DNS, URL fetching, LLM, or attachment execution is used.
