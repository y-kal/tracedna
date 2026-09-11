# TraceDNA demo

```bash
python backend/scripts/seed_demo.py
uvicorn app.main:app --app-dir backend --reload
```

Open the frontend, upload `demo/emails/unseen_alpha_mutation.eml`, and show the high-risk triage, rejected forged Received hop, Alpha similarity, persistent traits, mutation timeline, and evidence claims.
