from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import analyse, similarity

ROOT = Path(__file__).resolve().parents[2]

def test_forged_received_header_is_not_origin():
    a = analyse((ROOT/'demo/emails/unseen_alpha_mutation.eml').read_bytes())
    assert a['origin'] == '203.0.113.77'
    assert any(h['trust_band'] == 'UNTRUSTED' and h['from_ip'] == '1.2.3.4' for h in a['relay_path'])

def test_alpha_traits_match_and_domain_ip_can_rotate():
    new = analyse((ROOT/'demo/emails/unseen_alpha_mutation.eml').read_bytes())['parsed']
    old = analyse((ROOT/'demo/emails/alpha_01.eml').read_bytes())['parsed']
    score = similarity(new, old)
    assert score['overall'] >= .55
    assert 'url_path_grammar' in score['high_signal_matches']

def test_benign_urgency_is_not_severe():
    a = analyse((ROOT/'demo/emails/benign_urgent_invoice.eml').read_bytes())
    assert a['triage']['score'] < 60
