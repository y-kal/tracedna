import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import db, analyse, now

ROOT=Path(__file__).resolve().parents[2]
def seed():
    c=db()
    c.execute("DELETE FROM campaigns"); c.execute("DELETE FROM cases")
    alpha=[]; beta=[]
    for path in sorted((ROOT/'demo/emails').glob('*.eml')):
        if path.name == 'unseen_alpha_mutation.eml': continue
        raw=path.read_bytes(); analysis=analyse(raw); cid='CASE-DEMO-'+path.stem.upper()
        c.execute("INSERT INTO cases VALUES (?,?,?,?,?,?)",(cid,path.name,__import__('hashlib').sha256(raw).hexdigest(),str(path),json.dumps(analysis),now()))
        if path.name.startswith('beta_'): beta.append(analysis | {'id':cid,'filename':path.name})
        elif path.name.startswith('alpha_'): alpha.append(analysis | {'id':cid,'filename':path.name})
    c.execute("INSERT INTO campaigns VALUES (?,?,?,?)",('CAMP-ALPHA','Campaign Alpha',json.dumps(alpha),now()))
    c.execute("INSERT INTO campaigns VALUES (?,?,?,?)",('CAMP-BETA','Campaign Beta',json.dumps(beta),now()))
    c.commit(); print('Seeded Campaign Alpha, Campaign Beta, and a benign control.')
if __name__=='__main__': seed()
