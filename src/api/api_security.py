#!/usr/bin/env python3
"""JWT Validation + OAuth PKCE + Rate Limiting — CSE804. Run: python3 api_security.py"""
import base64, hashlib, hmac, json, secrets, time
from dataclasses import dataclass, field

SECRET = b"cse804-demo-secret"
ISSUER = "https://auth.example.com"
AUDIENCE = "api.example.com"

def make_jwt(iss=ISSUER, aud=AUDIENCE, sub="alice", exp_delta=3600, alg="RS256"):
    now = int(time.time())
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    h = b64({"alg": alg, "typ": "JWT"})
    p = b64({"iss":iss,"aud":aud,"sub":sub,"exp":now+exp_delta,
             "iat":now,"jti":secrets.token_urlsafe(8)})
    sig = base64.urlsafe_b64encode(
        hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"

_used_jtis: set = set()

def validate_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3: return False, "not 3 parts"
        pad = lambda x: x + "="*(4-len(x)%4)
        hdr  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        pay  = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        if hdr.get("alg") not in {"RS256","ES256","RS384"}: return False, f"bad alg: {hdr.get('alg')}"
        if time.time() > pay.get("exp",0):  return False, "expired"
        if pay.get("iss") != ISSUER:        return False, "wrong issuer"
        aud = pay.get("aud",""); aud_l = aud if isinstance(aud,list) else [aud]
        if AUDIENCE not in aud_l:           return False, "wrong audience"
        jti = pay.get("jti","")
        if jti in _used_jtis:               return False, "replay attack (jti reused)"
        _used_jtis.add(jti)
        si  = f"{parts[0]}.{parts[1]}".encode()
        exp = base64.urlsafe_b64encode(hmac.new(SECRET,si,hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(parts[2], exp): return False, "bad signature"
        return True, pay
    except Exception as e:
        return False, str(e)

@dataclass
class TokenBucket:
    capacity: float; refill_rate: float
    tokens: float = field(init=False); last_t: float = field(init=False)
    def __post_init__(self): self.tokens=self.capacity; self.last_t=time.time()
    def consume(self):
        now=time.time(); self.tokens=min(self.capacity,self.tokens+(now-self.last_t)*self.refill_rate)
        self.last_t=now
        if self.tokens>=1: self.tokens-=1; return True
        return False

def main():
    print("="*60); print("  API SECURITY DEMO — CSE804"); print("="*60)

    print("\n── JWT Validation ──")
    tests = [
        (make_jwt(),                           "Valid token"),
        (make_jwt(exp_delta=-100),             "Expired token"),
        (make_jwt(aud="other-service"),        "Wrong audience"),
        (make_jwt(iss="https://evil.com"),     "Wrong issuer"),
        (make_jwt(alg="none"),                 "alg:none attack"),
        ("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5fQ.", "alg:none raw"),
    ]
    for tok, desc in tests:
        ok, detail = validate_jwt(tok)
        print(f"  {'✓' if ok else '✗'} {desc}: {detail if not ok else 'VALID'}")
    # Replay
    tok2=make_jwt(); validate_jwt(tok2); ok,r=validate_jwt(tok2)
    print(f"  ✗ Replay attack: {r}")

    print("\n── PKCE (OAuth 2.0) ──")
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    def pkce(v,c): return hmac.compare_digest(base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode(),c)
    print(f"  Verifier:           {verifier[:30]}...")
    print(f"  Challenge (SHA256): {challenge[:30]}...")
    print(f"  Correct verifier:   {pkce(verifier, challenge)}")
    print(f"  Wrong verifier:     {pkce('attacker_guessing', challenge)}")
    print("  -> Attacker who intercepts auth_code cannot exchange without verifier")

    print("\n── Token Bucket Rate Limiter ──")
    bucket = TokenBucket(capacity=5, refill_rate=1.0)
    for i in range(8):
        ok = bucket.consume()
        print(f"  Request {i+1}: {'✓ allowed' if ok else '✗ rate-limited'}")

if __name__ == "__main__": main()
