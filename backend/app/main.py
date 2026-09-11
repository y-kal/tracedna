from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
EVIDENCE = DATA / "evidence"
DB_PATH = DATA / "tracedna.sqlite3"
EVIDENCE.mkdir(parents=True, exist_ok=True)

DNA_WEIGHTS = {"network": .12, "domain": .12, "web": .22, "mail": .22, "content": .22, "temporal": .10}
TRUSTED_GATEWAYS = {"recipient-gateway.example", "mx.recipient.example"}

def db():
    DATA.mkdir(exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, filename TEXT, raw_sha256 TEXT, raw_path TEXT, analysis TEXT, created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS campaigns (id TEXT PRIMARY KEY, name TEXT, members TEXT, created_at TEXT)")
    c.commit()
    return c

def now(): return datetime.now(timezone.utc).isoformat()
def sha(b): return hashlib.sha256(b).hexdigest()
def tokens(s): return set(re.findall(r"[a-z0-9]+", (s or "").lower()))

def domain_parts(value):
    host = (value or "").lower().strip().strip("<>").split("@")[-1].split(":")[0]
    bits = host.split(".")
    return host, ".".join(bits[-2:]) if len(bits) >= 2 else host

def url_features(text):
    urls = re.findall(r"https?://[^\s<>\"]+", text or "")
    out, grammars, queries = [], [], []
    for raw in urls:
        p = urlparse(raw.rstrip(".,)")); host = p.hostname or ""
        path = re.sub(r"[0-9a-f]{8,}", "<HEX>", p.path.lower())
        path = re.sub(r"\d+", "<DIGITS>", path)
        q = sorted(parse_qs(p.query).keys())
        grammars.append(path or "/"); queries.extend(q)
        out.append({"raw": raw, "host": host.lower(), "path_grammar": path or "/", "query_keys": q})
    return out, grammars, sorted(set(queries))

def message_pattern(mid):
    local, _, host = (mid or "").strip("<>").partition("@")
    local = re.sub(r"\b\d+\b", "<DIGITS>", local)
    local = re.sub(r"\b[0-9a-f]{6,}\b", "<HEX>", local, flags=re.I)
    host = re.sub(r"\d+", "<DIGITS>", host.lower())
    return f"{local}@{host}" if host else local

def html_skeleton(source):
    if not source: return ""
    soup = BeautifulSoup(source, "html.parser")
    for node in soup.find_all(string=True): node.replace_with("")
    return ">".join(x.name for x in soup.find_all() if x.name not in {"html", "head", "meta", "title"})

def parse_received(raw):
    m = re.search(r"from\s+([^\s(]+)(?:\s+\(([^)]*)\))?\s+by\s+([^;\s]+).*?(?:;\s*(.*))?$", raw, re.I)
    if not m: return {"raw": raw, "from_host": None, "from_ip": None, "by_host": None, "timestamp": None}
    inside = m.group(2) or ""
    ipm = re.search(r"(?:\[)?((?:\d{1,3}\.){3}\d{1,3})(?:\])?", inside) or re.search(r"(?:\[)?((?:\d{1,3}\.){3}\d{1,3})(?:\])?", m.group(1))
    # The parenthesized hostname is the useful continuity identity; the leading
    # token is often only the peer's address.
    from_host = (re.match(r"([^\s\[]+)", inside).group(1) if inside else m.group(1))
    return {"raw": raw, "from_host": from_host, "from_ip": ipm.group(1) if ipm else None, "by_host": m.group(3), "timestamp": m.group(4)}

def parse_eml(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text, html_body, attachments = [], "", []
    for part in msg.walk():
        if part.is_multipart(): continue
        ctype = part.get_content_type()
        try: content = part.get_content()
        except Exception: content = ""
        if part.get_filename():
            b = part.get_payload(decode=True) or b""
            attachments.append({"filename": Path(part.get_filename()).name, "mime": ctype, "size": len(b), "sha256": sha(b)})
        elif ctype == "text/plain": text.append(str(content))
        elif ctype == "text/html": html_body += str(content)
    from_addr = msg.get("From", "")
    reply = msg.get("Reply-To", "")
    ret = msg.get("Return-Path", "")
    urls, grammars, query_keys = url_features("\n".join(text) + "\n" + html_body)
    received = [parse_received(x) for x in msg.get_all("Received", [])]
    auth = msg.get_all("Authentication-Results", [])
    sender_domain = domain_parts(from_addr)[1]
    return {"subject": str(msg.get("Subject", "")), "from": str(from_addr), "from_domain": sender_domain,
            "reply_to": str(reply), "reply_to_domain": domain_parts(reply)[1], "return_path": str(ret),
            "return_path_domain": domain_parts(ret)[1], "message_id": str(msg.get("Message-ID", "")),
            "date": str(msg.get("Date", "")), "body_text": "\n".join(text), "body_html": html_body,
            "received": received, "auth": auth, "urls": urls, "attachments": attachments,
            "url_grammars": grammars, "query_keys": query_keys, "html_skeleton": html_skeleton(html_body),
            "message_pattern": message_pattern(str(msg.get("Message-ID", ""))),
            "headers": {k: [str(v) for v in vals] for k, vals in msg.items()}}

def triage(p):
    body = (p["body_text"] + " " + BeautifulSoup(p["body_html"], "html.parser").get_text(" ")).lower()
    signals = []
    def add(name, points, detail): signals.append({"name": name, "points": points, "detail": detail})
    if p["reply_to_domain"] and p["reply_to_domain"] != p["from_domain"]: add("reply_to_mismatch", 12, "Reply-To domain differs from visible sender")
    if p["return_path_domain"] and p["return_path_domain"] != p["from_domain"]: add("return_path_mismatch", 8, "Return-Path domain differs from visible sender")
    auth = " ".join(p["auth"]).lower()
    if "dmarc=fail" in auth: add("dmarc_anomaly", 18, "Receiver-observed DMARC failure")
    if any(x in body for x in ["password", "sign in", "verify your account", "credential"]): add("credential_request", 15, "Credential-oriented language")
    if any(x in body for x in ["bank account", "payment", "wire", "gift card"]): add("payment_intent", 18, "Payment or diversion language")
    if any(x in body for x in ["urgent", "immediately", "confidential", "do not call"]): add("urgency_or_secrecy", 6, "Urgency or secrecy language")
    if any(u["path_grammar"].startswith("/auth") for u in p["urls"]): add("suspicious_url", 10, "Authentication URL structure")
    score = min(100, sum(x["points"] for x in signals))
    category = "clean_or_low_risk" if score < 25 else "suspicious"
    if any(x["name"] == "credential_request" for x in signals): category = "credential_phishing"
    if any(x["name"] == "payment_intent" for x in signals) and score >= 45: category = "business_email_compromise"
    return {"score": score, "band": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW", "category": category, "signals": signals}

def trust_path(p):
    hops = p["received"]; result = []; boundary = None
    root_trusted = bool(hops and (hops[0].get("by_host") in TRUSTED_GATEWAYS or (hops[0].get("by_host") or "").endswith(".recipient.example")))
    for i, h in enumerate(hops):
        reasons = []
        score = 0
        if i == 0 and root_trusted: score += 50; reasons.append("CONFIGURED_TRUST_ROOT")
        elif i == 0: reasons.append("TRUST_ROOT_NOT_CONFIGURED")
        if i == 0 or i < len(hops) - 1:
            if h.get("from_ip"):
                score += 20; reasons.append("PARSEABLE_PEER_IP")
        if i > 0:
            previous = hops[i-1]
            if previous.get("from_host") and h.get("by_host") and previous["from_host"].lower() == h["by_host"].lower():
                score += 35; reasons.append("CHAIN_CONTINUITY")
            else: reasons.append("CONTINUITY_BREAK")
        if i > 0 and root_trusted and boundary is None and score < 40:
            reasons += ["OLDER_THAN_TRUST_BOUNDARY", "SENDER_SUPPLIED_OR_UNSUPPORTED"]; score = 20
        band = "TRUSTED" if score >= 70 else "UNCERTAIN" if score >= 40 else "UNTRUSTED"
        result.append({**h, "index": i, "trust_score": score, "trust_band": band, "reason_codes": reasons, "is_trust_boundary": False})
        if root_trusted and boundary is None and (i == 0 or score >= 40): boundary = i
    if boundary is not None and result:
        result[boundary]["is_trust_boundary"] = True
    origin = None
    if boundary is not None:
        origin = result[boundary].get("from_ip") or result[boundary].get("from_host")
    return result, origin, root_trusted

def jaccard(a, b):
    a, b = set(a or []), set(b or [])
    return 1.0 if not a and not b else len(a & b) / len(a | b) if a | b else 0.0

def similarity(a, b):
    groups = {
        "network": jaccard([a.get("origin")], [b.get("origin")]),
        "domain": jaccard([a.get("from_domain"), a.get("reply_to_domain")], [b.get("from_domain"), b.get("reply_to_domain")]),
        "web": (.65*jaccard(a.get("url_grammars"), b.get("url_grammars")) + .35*jaccard(a.get("query_keys"), b.get("query_keys"))),
        "mail": (.55*(a.get("message_pattern")==b.get("message_pattern")) + .45*jaccard([a.get("reply_to_domain")], [b.get("reply_to_domain")])),
        "content": (.55*jaccard(tokens(a.get("body_text")), tokens(b.get("body_text"))) + .45*(a.get("html_skeleton")==b.get("html_skeleton"))),
        "temporal": 0.6,
    }
    contributions = {k: round(v*DNA_WEIGHTS[k], 4) for k, v in groups.items()}
    exact = []
    if a.get("message_pattern") and a.get("message_pattern") == b.get("message_pattern"): exact.append("message_id_pattern")
    if a.get("url_grammars") and set(a.get("url_grammars")) & set(b.get("url_grammars")): exact.append("url_path_grammar")
    if a.get("html_skeleton") and a.get("html_skeleton") == b.get("html_skeleton"): exact.append("html_skeleton")
    score = min(1.0, sum(contributions.values()) + (0.08 if "message_id_pattern" in exact else 0) + (0.05 if "url_path_grammar" in exact else 0))
    return {"overall": round(score, 4), "band": "HIGH" if score >= .75 else "REVIEW" if score >= .55 else "LOW", "groups": {k: round(v, 4) for k,v in groups.items()}, "contributions": contributions, "high_signal_matches": exact, "conflicts": [x for x in ["domain" if a.get("from_domain") != b.get("from_domain") else None, "source_ip" if a.get("origin") != b.get("origin") else None] if x]}

def analyse(raw):
    p = parse_eml(raw); tri = triage(p); hops, origin, root = trust_path(p); p["origin"] = origin
    return {"parsed": p, "triage": tri, "relay_path": hops, "origin": origin, "trust_root_configured": root}

def evidence_claims(analysis, sha256, campaign=None, match=None):
    p, t = analysis["parsed"], analysis["triage"]; ev = []
    def add(typ, field, raw, derived):
        eid = "E-" + uuid.uuid4().hex[:8].upper(); ev.append({"id": eid, "evidence_type": typ, "source_field": field, "raw_value": raw, "derived_value": derived}); return eid
    ids = [add("integrity", "raw_sha256", sha256, "hash recorded")]
    for s in t["signals"]: ids.append(add("triage_signal", s["name"], s["detail"], s["points"]))
    for h in analysis["relay_path"]: add("header_trust", f"Received[{h['index']}]", h["raw"], {"band": h["trust_band"], "reasons": h["reason_codes"]})
    claims = [{"id": "C-"+uuid.uuid4().hex[:8].upper(), "claim_type": "threat_assessment", "statement": f"Email assessed as {t['category']} with {t['band']} risk.", "confidence_score": t["score"]/100, "confidence_band": t["band"].lower(), "confidence_kind": "heuristic_evidence_confidence", "supporting_evidence_ids": ids[1:], "contradicting_evidence_ids": []}]
    if analysis["origin"]: claims.append({"id":"C-"+uuid.uuid4().hex[:8].upper(), "claim_type":"earliest_trustworthy_infrastructure", "statement":f"{analysis['origin']} is the earliest independently observed external infrastructure.", "confidence_score":.82, "confidence_band":"high", "confidence_kind":"heuristic_evidence_confidence", "supporting_evidence_ids":ids[:1], "contradicting_evidence_ids":[]})
    if campaign and match:
        claims.append({"id":"C-"+uuid.uuid4().hex[:8].upper(), "claim_type":"campaign_match", "statement":f"This email is {match['band'].lower()}ly similar to {campaign['name']}.", "confidence_score":match["overall"], "confidence_band":match["band"].lower(), "confidence_kind":"heuristic_evidence_confidence", "supporting_evidence_ids":ids[1:], "contradicting_evidence_ids":[]})
    return ev, claims

def load_cases(c):
    return [json.loads(r["analysis"]) | {"id": r["id"], "filename": r["filename"], "raw_sha256": r["raw_sha256"]} for r in c.execute("SELECT * FROM cases ORDER BY created_at").fetchall()]

def match_campaign(c, analysis):
    best = None
    for camp in c.execute("SELECT * FROM campaigns").fetchall():
        members = json.loads(camp["members"]); scores = [similarity(analysis["parsed"], x["parsed"]) for x in members]
        if scores:
            m = max(scores, key=lambda x:x["overall"])
            if best is None or m["overall"] > best["match"]["overall"]: best = {"id":camp["id"], "name":camp["name"], "match":m, "members":members}
    return best if best and best["match"]["overall"] >= .55 else None

app = FastAPI(title="TraceDNA", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health(): return {"status":"ok", "service":"tracedna"}

@app.post("/api/cases")
async def upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"): raise HTTPException(400, "Only .eml files are accepted")
    raw = await file.read()
    if len(raw) > 10*1024*1024: raise HTTPException(413, "File too large")
    cid = "CASE-" + uuid.uuid4().hex[:10].upper(); path = EVIDENCE / cid / "original.eml"; path.parent.mkdir(parents=True); path.write_bytes(raw)
    analysis = analyse(raw); c = db(); c.execute("INSERT INTO cases VALUES (?,?,?,?,?,?)", (cid, Path(file.filename).name, sha(raw), str(path), json.dumps(analysis), now())); c.commit()
    match = match_campaign(c, analysis); campaign = {"id":match["id"],"name":match["name"]} if match else None
    ev, claims = evidence_claims(analysis, sha(raw), campaign, match["match"] if match else None); analysis["evidence"] = ev; analysis["claims"] = claims; analysis["campaign"] = campaign
    c.execute("UPDATE cases SET analysis=? WHERE id=?", (json.dumps(analysis), cid))
    if match:
        members = json.loads(c.execute("SELECT members FROM campaigns WHERE id=?", (match["id"],)).fetchone()[0])
        members.append(analysis | {"id": cid, "filename": Path(file.filename).name})
        c.execute("UPDATE campaigns SET members=? WHERE id=?", (json.dumps(members), match["id"]))
    c.commit(); return {"case_id":cid, "status":"analysed"}

def get_case(cid):
    c=db(); r=c.execute("SELECT * FROM cases WHERE id=?",(cid,)).fetchone()
    if not r: raise HTTPException(404,"Case not found")
    return json.loads(r["analysis"]) | {"id":cid,"filename":r["filename"],"raw_sha256":r["raw_sha256"]}

@app.get("/api/cases")
def cases():
    c=db(); return [{"id":r["id"],"filename":r["filename"],"raw_sha256":r["raw_sha256"], **{k:v for k,v in [("risk",json.loads(r["analysis"])["triage"])]}} for r in c.execute("SELECT * FROM cases ORDER BY created_at DESC")]
@app.get("/api/cases/{cid}")
def case(cid): return get_case(cid)
@app.get("/api/cases/{cid}/relay-path")
def relay(cid): return get_case(cid)["relay_path"]
@app.get("/api/cases/{cid}/dna")
def dna(cid):
    x=get_case(cid); c=db(); best=match_campaign(c,x); return {"case_id":cid,"match":best["match"] if best else None,"campaign": {"id":best["id"],"name":best["name"]} if best else None}
@app.get("/api/cases/{cid}/claims")
def claims(cid): return get_case(cid).get("claims",[])
@app.get("/api/cases/{cid}/evidence")
def evidence(cid): return get_case(cid).get("evidence",[])
@app.get("/api/cases/{cid}/campaign-match")
def campaign_match(cid):
    x=get_case(cid); return x.get("campaign") or {"status":"no_confident_match"}
@app.post("/api/cases/{cid}/verify-integrity")
def verify(cid):
    c=db(); r=c.execute("SELECT raw_path,raw_sha256 FROM cases WHERE id=?",(cid,)).fetchone()
    if not r: raise HTTPException(404,"Case not found")
    actual=sha(Path(r["raw_path"]).read_bytes()); return {"case_id":cid,"intact":actual==r["raw_sha256"],"expected":r["raw_sha256"],"actual":actual}
@app.get("/api/campaigns/{camp_id}")
def campaign(camp_id):
    c=db(); r=c.execute("SELECT * FROM campaigns WHERE id=?",(camp_id,)).fetchone()
    if not r: raise HTTPException(404,"Campaign not found")
    members=json.loads(r["members"]); return {"id":camp_id,"name":r["name"],"members":[{"id":x.get("id"),"filename":x.get("filename"),"date":x["parsed"].get("date")} for x in members],"timeline":timeline(members)}
@app.get("/api/campaigns/{camp_id}/graph")
def graph(camp_id):
    x=campaign(camp_id); nodes=[{"data":{"id":camp_id,"label":x["name"],"type":"campaign"}}]; edges=[]
    for m in x["members"]: nodes.append({"data":{"id":m["id"],"label":m["filename"],"type":"email"}}); edges.append({"data":{"source":camp_id,"target":m["id"]}})
    return {"nodes":nodes,"edges":edges}

def timeline(members):
    ordered=sorted(members,key=lambda x:x["parsed"].get("date", "")); out=[]
    for prev, cur in zip(ordered, ordered[1:]):
        changed=[]; persisted=[]
        for key,label in [("from_domain","domain"),("origin","source_ip")]: (changed if prev["parsed"].get(key)!=cur["parsed"].get(key) else persisted).append(label)
        for key,label in [("url_grammars","url_path_grammar"),("html_skeleton","html_skeleton"),("message_pattern","message_id_pattern")]: (persisted if prev["parsed"].get(key)==cur["parsed"].get(key) else changed).append(label)
        out.append({"timestamp":cur["parsed"].get("date"),"summary":"Campaign changed infrastructure while retaining selected traits.","changed":changed,"persisted":persisted})
    return out
